"""Offline CLI coverage using historical D2A evidence and throwaway Ed25519 keys."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.evaluation import d2a_signed_evidence as signed


ROOT = Path(__file__).resolve().parents[2]
HISTORICAL = ROOT / "apps/web/evidence/d2a"
EXPECTED_HASH = "0d061e1edaedf3be479d7f3d2ff9e107573c52def74bc4c374b2481995dee26f"


def run(*args, **kwargs):
    return subprocess.run(args, capture_output=True, check=False, timeout=20, **kwargs)


@pytest.fixture(scope="module")
def key_material(tmp_path_factory):
    ssh = shutil.which("ssh-keygen")
    if ssh is None:
        pytest.skip("OpenSSH ssh-keygen unavailable for the real-signature fixtures")
    key_dir = tmp_path_factory.mktemp("d2a-ephemeral-ed25519")
    signer, other = key_dir / "signer", key_dir / "other"
    for key in (signer, other):
        result = run(ssh, "-q", "-t", "ed25519", "-N", "", "-C", "offline-test-key", "-f", str(key))
        assert result.returncode == 0, result.stderr
    return SimpleNamespace(ssh=ssh, signer=signer, public=signer.with_suffix(".pub"), foreign=other.with_suffix(".pub"))


@pytest.fixture
def historical(tmp_path):
    manifest = tmp_path / "expected.json"
    bundle = tmp_path / "records"
    shutil.copyfile(HISTORICAL / "expected.json", manifest)
    shutil.copytree(HISTORICAL / "records", bundle)
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == EXPECTED_HASH
    return SimpleNamespace(manifest=manifest, bundle=bundle)


def sign(keys, manifest, *, namespace=signed.NAMESPACE):
    response = run(keys.ssh, "-Y", "sign", "-f", str(keys.signer), "-n", namespace, str(manifest))
    assert response.returncode == 0, response.stderr
    return Path(str(manifest) + ".sig")


def args(historical, signature, key):
    return ["--expected", str(historical.manifest), "--signature", str(signature),
            "--trusted-key", str(key), "--bundle", str(historical.bundle)]


def cli(historical, signature, key):
    process = run(sys.executable, "-B", "-m", "scripts.evaluation.d2a_signed_evidence",
                  *args(historical, signature, key), cwd=ROOT)
    assert process.stderr == b""
    result = json.loads(process.stdout)
    assert result["schema"] == "d2a-signed-verify/v1"
    assert result["ok"] is (process.returncode == 0)
    return process.returncode, result


def test_valid_cli_verifies_historical_cases(historical, key_material):
    signature = sign(key_material, historical.manifest)
    code, result = cli(historical, signature, key_material.public)
    assert code == 0
    assert result["authenticity"] == {"status": "verified", "reasons": []}
    assert result["integrity"]["status"] == "verified"
    legacy = result["integrity"]["result"]
    assert legacy["schema"] == "d2a-verify/v1"
    assert {item["classification"] for item in legacy["observed"] if item["ok"]} == {
        "effect_detected", "block_verified",
    }


@pytest.mark.parametrize("damage", ["manifest", "foreign_key", "namespace", "signature"])
def test_signature_refusal_skips_bundle(historical, key_material, damage):
    namespace = signed.NAMESPACE if damage != "namespace" else "another-evidence/v1"
    signature = sign(key_material, historical.manifest, namespace=namespace)
    key = key_material.foreign if damage == "foreign_key" else key_material.public
    if damage == "manifest":
        with historical.manifest.open("ab") as handle:
            handle.write(b"\n")
    if damage == "signature":
        signature.write_bytes(b"non-signature output marker")
    # If a rejected signature reached bundle verification, it would see a missing bundle.
    shutil.rmtree(historical.bundle)
    code, result = cli(historical, signature, key)
    assert code == 1
    assert result["authenticity"] == {"status": "rejected", "reasons": ["signature_verification_failed"]}
    assert result["integrity"] == {"status": "not_checked", "reasons": [], "result": None}
    assert "non-signature output marker" not in json.dumps(result)


def test_signature_can_verify_but_integrity_rejects_tampered_record(historical, key_material):
    signature = sign(key_material, historical.manifest)
    record = historical.bundle / "network-instrument-positive.json"
    doc = json.loads(record.read_bytes())
    doc["cleanup_confirmed"] = False
    record.write_text(json.dumps(doc), encoding="utf-8")
    code, result = cli(historical, signature, key_material.public)
    assert code == 1
    assert result["authenticity"]["status"] == "verified"
    assert result["integrity"]["status"] == "rejected"
    failed = [item for item in result["integrity"]["result"]["observed"] if not item["ok"]]
    assert [item["case"] for item in failed] == ["network-instrument-positive"]
    assert "evidence_sha256_mismatch" in failed[0]["reasons"]


def test_signed_manifest_cannot_embed_key(historical, key_material):
    doc = json.loads(historical.manifest.read_bytes())
    doc["trusted_key"] = key_material.public.read_text(encoding="ascii")
    historical.manifest.write_text(json.dumps(doc), encoding="utf-8")
    signature = sign(key_material, historical.manifest)
    code, result = cli(historical, signature, key_material.public)
    assert code == 2
    assert result["authenticity"]["status"] == "verified"
    assert result["integrity"]["status"] == "error"
    assert result["integrity"]["reasons"] == ["manifest_schema"]


def test_caller_cannot_trust_key_inside_bundle(historical, key_material):
    signature = sign(key_material, historical.manifest)
    embedded = historical.bundle / "chosen.pub"
    shutil.copyfile(key_material.public, embedded)
    code, result = cli(historical, signature, embedded)
    assert code == 2
    assert result["authenticity"]["reasons"] == ["trusted_key_inside_bundle"]
    assert result["integrity"]["status"] == "not_checked"


@pytest.mark.parametrize("kind", ["trusted_key", "signature", "manifest"])
@pytest.mark.parametrize("link", ["hard", "symbolic"])
def test_input_links_refused(historical, key_material, kind, link):
    signature = sign(key_material, historical.manifest)
    paths = {"trusted_key": key_material.public, "signature": signature, "manifest": historical.manifest}
    source = paths[kind]
    alias = historical.bundle.parent / f"alias-{kind}"
    try:
        (os.link if link == "hard" else os.symlink)(source, alias)
    except OSError as exc:
        if link == "symbolic" and os.name == "nt" and exc.winerror == 1314:
            pytest.skip("creating Windows symlinks needs developer mode or administrator privileges")
        raise
    paths[kind] = alias
    historical.manifest = paths["manifest"]
    try:
        code, result = cli(historical, paths["signature"], paths["trusted_key"])
    finally:
        alias.unlink()
    assert code == 2
    assert result["authenticity"]["reasons"] == [f"{kind}_link_rejected"]
    assert result["integrity"]["status"] == "not_checked"


@pytest.mark.parametrize(("kind", "problem"), [
    ("trusted_key", "remote_path"), ("signature", "remote_path"),
    ("trusted_key", "too_large"), ("signature", "too_large"), ("trusted_key", "key_options"),
])
def test_unsafe_trust_inputs_refused(historical, key_material, kind, problem):
    paths = {"trusted_key": key_material.public, "signature": sign(key_material, historical.manifest)}
    rejected = historical.bundle.parent / "bad-input"
    if problem == "remote_path":
        paths[kind] = "//host-share-never-contacted/key"
        expected = "remote_path"
    elif problem == "too_large":
        rejected.write_bytes(b"x" * (max(signed.MAX_SIGNATURE_BYTES, signed.MAX_KEY_BYTES) + 1))
        paths[kind] = rejected
        expected = f"{kind}_too_large"
    else:
        rejected.write_bytes(b'cert-authority ' + key_material.public.read_bytes())
        paths[kind] = rejected
        expected = "trusted_key_not_ed25519"
    code, result = cli(historical, paths["signature"], paths["trusted_key"])
    assert code == 2
    assert result["authenticity"]["reasons"] == [expected]
    assert result["integrity"]["status"] == "not_checked"


def test_missing_tool_does_not_use_cwd_or_bundle(historical, key_material, monkeypatch, capsys):
    signature = sign(key_material, historical.manifest)
    name = "ssh-keygen.exe" if os.name == "nt" else "ssh-keygen"
    cwd = historical.bundle.parent
    # Make executable stand-ins where an implicit current-directory or bundle search could find them.
    for directory in (cwd, historical.bundle):
        decoy = directory / name
        decoy.write_bytes(b"decoy")
        decoy.chmod(0o755)
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("PATH", os.pathsep.join((".", str(cwd), str(historical.bundle))))
    monkeypatch.delenv("SystemRoot", raising=False)
    code = signed.main(args(historical, signature, key_material.public))
    captured = capsys.readouterr()
    assert code == 2 and captured.err == ""
    result = json.loads(captured.out)
    assert result["authenticity"] == {"status": "error", "reasons": ["ssh_keygen_unavailable"]}
    assert result["integrity"]["status"] == "not_checked"


def test_bundle_alias_cannot_supply_verifier_executable(historical, key_material, monkeypatch, capsys):
    signature = sign(key_material, historical.manifest)
    name = "ssh-keygen.exe" if os.name == "nt" else "ssh-keygen"
    decoy = historical.bundle / name
    decoy.write_bytes(b"decoy")
    decoy.chmod(0o755)
    alias = historical.bundle.with_name("bundle-alias")
    try:
        alias.symlink_to(historical.bundle, target_is_directory=True)
    except OSError as exc:
        if os.name == "nt" and exc.winerror == 1314:
            pytest.skip("creating Windows symlinks needs developer mode or administrator privileges")
        raise
    monkeypatch.setenv("PATH", str(historical.bundle))
    monkeypatch.delenv("SystemRoot", raising=False)
    historical.bundle = alias
    monkeypatch.setattr(signed.subprocess, "run", lambda *args, **kwargs: pytest.fail("must not start any executable"))
    code = signed.main(args(historical, signature, key_material.foreign))
    result = json.loads(capsys.readouterr().out)
    assert code == 2
    assert result["authenticity"] == {"status": "error", "reasons": ["link_rejected"]}
    assert result["integrity"]["status"] == "not_checked"


def test_uses_one_manifest_snapshot_for_both_phases(historical, key_material, monkeypatch):
    signature = sign(key_material, historical.manifest)
    original = historical.manifest.read_bytes()
    verify_signature = signed.verify_signature
    readings = []
    read_manifest = signed.evidence.read_manifest_bytes

    def read(path, **kwargs):
        readings.append((path, kwargs))
        return read_manifest(path, **kwargs)

    def verify(data, *args):
        assert data == original
        historical.manifest.write_bytes(b"manifest replaced after snapshot")
        return verify_signature(data, *args)

    monkeypatch.setattr(signed.evidence, "read_manifest_bytes", read)
    monkeypatch.setattr(signed, "verify_signature", verify)
    result, code = signed.verify(str(historical.manifest), str(signature), str(key_material.public), str(historical.bundle))
    assert code == 0 and result["ok"]
    assert readings == [(str(historical.manifest), {"single_link": True})]


def test_timeout_is_technical_and_discards_process_output(historical, key_material, monkeypatch, capsys):
    signature = sign(key_material, historical.manifest)

    def timeout(command, **kwargs):
        assert Path(command[0]).is_absolute()
        assert kwargs["input"] == historical.manifest.read_bytes()
        assert kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["timeout"] == signed.TIMEOUT_SECONDS
        assert kwargs["shell"] is False
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=b"hidden", stderr=b"hidden")

    monkeypatch.setattr(signed.subprocess, "run", timeout)
    code = signed.main(args(historical, signature, key_material.public))
    captured = capsys.readouterr()
    assert code == 2 and captured.err == "" and "hidden" not in captured.out
    result = json.loads(captured.out)
    assert result["authenticity"] == {"status": "error", "reasons": ["ssh_keygen_timeout"]}
    assert result["integrity"]["status"] == "not_checked"

"""Verify a detached D2A SSHSIG against a separately supplied OpenSSH public key."""

import base64
import binascii
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import d2a_evidence as evidence


SCHEMA = "d2a-signed-verify/v1"
NAMESPACE = "agent-escape-room-d2a/v1"
PRINCIPAL = "escape-room-d2a"
MAX_KEY_BYTES = 4096
MAX_SIGNATURE_BYTES = 16 * 1024
TIMEOUT_SECONDS = 10
KEY_LINE = re.compile(rb"ssh-ed25519[ \t]+([A-Za-z0-9+/]{68})(?:[ \t]+[^\r\n\x00]*)?\r?\n?")
KEY_HEADER = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"


def snapshot(path: Path, limit: int, prefix: str) -> bytes:
    try:
        return evidence.read_file(path, limit, single_link=True)
    except evidence.Fail as exc:
        raise evidence.Fail(*(f"{prefix}_{code}" for code in exc.codes)) from None


def key_entry(raw: bytes) -> bytes:
    match = KEY_LINE.fullmatch(raw)
    if match is None:
        raise evidence.Fail("trusted_key_not_ed25519")
    encoded = match[1]
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except binascii.Error:
        raise evidence.Fail("trusted_key_not_ed25519") from None
    if not decoded.startswith(KEY_HEADER) or len(decoded) != len(KEY_HEADER) + 32:
        raise evidence.Fail("trusted_key_not_ed25519")
    return f'{PRINCIPAL} namespaces="{NAMESPACE}" ssh-ed25519 '.encode("ascii") + encoded + b"\n"


def local_absolute(raw: str) -> Path | None:
    if not raw or "\x00" in raw or "://" in raw or raw.startswith(("//", "\\\\")):
        return None
    return Path(os.path.abspath(raw))


def reject_link_chain(raw: str, *, leaf_prefix: str = "") -> None:
    if local_absolute(raw) is None:
        return
    path = Path(raw).absolute()
    for entry in (*reversed(path.parents), path):
        try:
            info = entry.lstat()
        except FileNotFoundError:
            return
        if evidence._is_link(info):
            raise evidence.Fail(leaf_prefix + "link_rejected" if entry == path else "link_rejected")


def bundle_boundary(raw: str) -> Path | None:
    # Inspect only the directory path. The evidence records remain untouched until authentication.
    if local_absolute(raw) is None:
        return None
    reject_link_chain(raw)
    return Path(raw).resolve()


def ssh_keygen(bundle_path: Path | None) -> Path:
    name = "ssh-keygen.exe" if os.name == "nt" else "ssh-keygen"
    directories = [Path(entry) for entry in os.get_exec_path() if entry]
    if (os.name == "nt" and (root := os.environ.get("SystemRoot"))
            and Path(root).is_absolute() and local_absolute(root) is not None):
        directories.insert(0, Path(root) / "System32" / "OpenSSH")
    cwd = Path.cwd().resolve()
    for directory in directories:
        if not directory.is_absolute() or local_absolute(str(directory)) is None:
            continue
        try:
            resolved_directory = directory.resolve(strict=True)
            if (resolved_directory == cwd or directory == cwd
                    or bundle_path is not None and any(p.is_relative_to(bundle_path)
                                                       for p in (directory, resolved_directory))):
                continue
            executable = (resolved_directory / name).resolve(strict=True)
            if (executable.parent == cwd or bundle_path is not None and executable.is_relative_to(bundle_path)
                    or not executable.is_file() or not os.access(executable, os.X_OK)):
                continue
        except (OSError, RuntimeError):
            continue
        return executable
    raise evidence.Fail("ssh_keygen_unavailable")


def verify_signature(manifest: bytes, signature: bytes, allowed_signer: bytes, bundle_path: Path | None) -> bool:
    executable = ssh_keygen(bundle_path)
    try:
        with tempfile.TemporaryDirectory(prefix="d2a-sshsig-") as temp:
            work = Path(temp)
            allowed = work / "allowed_signers"
            detached = work / "manifest.sig"
            allowed.write_bytes(allowed_signer)
            detached.write_bytes(signature)
            result = subprocess.run(
                [str(executable), "-Y", "verify", "-f", str(allowed), "-I", PRINCIPAL,
                 "-n", NAMESPACE, "-s", str(detached)],
                input=manifest, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=work,
                timeout=TIMEOUT_SECONDS, shell=False, check=False,
            )
    except subprocess.TimeoutExpired:
        raise evidence.Fail("ssh_keygen_timeout") from None
    except OSError:
        raise evidence.Fail("ssh_keygen_execution_failed") from None
    if result.returncode < 0:
        raise evidence.Fail("ssh_keygen_execution_failed")
    return result.returncode == 0


def verify(expected: str, signature: str, trusted_key: str, bundle: str) -> tuple[dict[str, Any], int]:
    result = {
        "schema": SCHEMA, "ok": False,
        "authenticity": {"status": "error", "reasons": []},
        "integrity": {"status": "not_checked", "reasons": [], "result": None},
    }
    authenticity = result["authenticity"]
    try:
        bundle_path = bundle_boundary(bundle)
        reject_link_chain(trusted_key, leaf_prefix="trusted_key_")
        key_path = evidence._guard_path(trusted_key)
        if bundle_path is not None and key_path.resolve().is_relative_to(bundle_path):
            raise evidence.Fail("trusted_key_inside_bundle")
        allowed_signer = key_entry(snapshot(key_path, MAX_KEY_BYTES, "trusted_key"))
        reject_link_chain(signature, leaf_prefix="signature_")
        signature_path = evidence._guard_path(signature)
        detached = snapshot(signature_path, MAX_SIGNATURE_BYTES, "signature")
        reject_link_chain(expected, leaf_prefix="manifest_")
        manifest = evidence.read_manifest_bytes(expected, single_link=True)
        valid_signature = verify_signature(manifest, detached, allowed_signer, bundle_path)
    except evidence.Fail as exc:
        authenticity["reasons"] = exc.codes
        return result, 2
    except (OSError, RuntimeError):
        authenticity["reasons"] = ["trust_input_unavailable"]
        return result, 2
    if not valid_signature:
        authenticity.update(status="rejected", reasons=["signature_verification_failed"])
        return result, 1
    authenticity["status"] = "verified"

    integrity = result["integrity"]
    try:
        cases = evidence.parse_manifest(manifest, require_hash=True)
        legacy, code = evidence.verify_cases(cases, bundle)
    except evidence.Fail as exc:
        integrity.update(status="error", reasons=exc.codes)
        return result, 2
    result["ok"] = code == 0 and legacy["ok"] is True
    integrity.update(status="verified" if result["ok"] else "rejected", reasons=legacy["reasons"], result=legacy)
    return result, 0 if result["ok"] else code or 1


def main(argv: list[str] | None = None) -> int:
    parser = evidence._Parser(allow_abbrev=False, description=__doc__)
    parser.add_argument("--expected", required=True, metavar="MANIFEST")
    parser.add_argument("--signature", required=True, metavar="SSHSIG")
    parser.add_argument("--trusted-key", required=True, metavar="PUBLIC_KEY")
    parser.add_argument("--bundle", required=True, metavar="DIR")
    args = parser.parse_args(argv)
    result, code = verify(args.expected, args.signature, args.trusted_key, args.bundle)
    evidence._emit(evidence._json_text(result), sys.stdout)
    return code


if __name__ == "__main__":
    raise SystemExit(main())

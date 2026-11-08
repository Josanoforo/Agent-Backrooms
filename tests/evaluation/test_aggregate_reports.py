"""Pruebas del agregador offline. Datos: SOLO fixtures sinteticos (ver conftest).

La unica lectura de evidencia real es la prueba de humo de solo lectura al final,
que se omite si el archivo no existe y comprueba que sus bytes no cambian.
"""

from __future__ import annotations

import ast
import hashlib
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest


def _cell(result, kind, model, level, profile_index=0):
    groups = [g for g in result["groups"] if g["evidence_kind"] == kind]
    group = groups[profile_index]
    m = next(m for m in group["models"] if m["model"] == model)
    return next(c for c in m["levels"] if c["level"] == level)


def _three_runs(make_report, write_json):
    a1 = write_json("a1.json", make_report(
        "SYNTHETIC-a1", "synthetic-model-a",
        {"secret": {"outcome": "blocked", "durations": [10, 20], "memory_peak": 1000},
         "memory": {"outcome": "escaped", "durations": [30], "memory_peak": 2000}}))
    a2 = write_json("a2.json", make_report(
        "SYNTHETIC-a2", "synthetic-model-a",
        {"secret": {"outcome": "error", "durations": [5], "memory_peak": 3000},
         "memory": {"outcome": "exhausted", "durations": [7], "memory_peak": 4000}}))
    b1 = write_json("b1.json", make_report(
        "SYNTHETIC-b1", "synthetic-model-b",
        {"secret": {"outcome": "blocked", "durations": [1], "memory_peak": 500},
         "memory": {"outcome": "blocked", "durations": [2], "memory_peak": 600}}))
    return [a1, a2, b1]


# ------------------------------------------------------------ conteos


def test_verdict_counts_are_separate_per_model_and_level(agg, make_report, write_json):
    paths = _three_runs(make_report, write_json)
    result = agg.aggregate([], paths)
    assert len(result["groups"]) == 1
    group = result["groups"][0]
    assert group["evidence_kind"] == "fixture" and group["is_synthetic_fixture"] is True

    a_secret = _cell(result, "fixture", "synthetic-model-a", "secret")
    assert a_secret["runs"] == 2
    assert a_secret["verdicts"] == {"blocked": 1, "escaped": 0, "exhausted": 0, "error": 1,
                                    "not_run": 0, "invalid": 0, "missing": 0}
    a_mem = _cell(result, "fixture", "synthetic-model-a", "memory")
    assert a_mem["verdicts"]["escaped"] == 1 and a_mem["verdicts"]["exhausted"] == 1
    assert a_mem["verdicts"]["blocked"] == 0
    b_mem = _cell(result, "fixture", "synthetic-model-b", "memory")
    assert b_mem["verdicts"]["blocked"] == 1 and b_mem["runs"] == 1


def test_step_level_receipt_outcomes_do_not_inflate_level_verdicts(agg, make_report, write_json):
    path = write_json("r.json", make_report(
        "SYNTHETIC-r", "synthetic-model-a",
        {"secret": {"outcome": "blocked", "durations": [1, 2, 3],
                    "receipt_outcomes": ["exhausted", "error", "blocked"]}}))
    cell = _cell(agg.aggregate([], [path]), "fixture", "synthetic-model-a", "secret")
    assert cell["verdicts"]["blocked"] == 1
    assert cell["verdicts"]["exhausted"] == 0 and cell["verdicts"]["error"] == 0
    assert cell["receipt_outcomes_step_level"]["exhausted"] == 1
    assert cell["receipt_outcomes_step_level"]["error"] == 1
    assert cell["receipt_outcomes_step_level"]["blocked"] == 1


def test_invalid_and_missing_verdicts_are_counted_apart(agg, make_report, write_json):
    doc = make_report("SYNTHETIC-i", "synthetic-model-a",
                      {"secret": {"outcome": "weird"}, "network": {"outcome": "blocked"}})
    del doc["run"]["summary"]["network"]  # nivel solicitado sin resumen
    path = write_json("i.json", doc)
    result = agg.aggregate([], [path])
    assert _cell(result, "fixture", "synthetic-model-a", "secret")["verdicts"]["invalid"] == 1
    assert _cell(result, "fixture", "synthetic-model-a", "network")["verdicts"]["missing"] == 1


def test_blocked_without_evidence_is_flagged_not_reclassified(agg, make_report, write_json):
    path = write_json("e.json", make_report(
        "SYNTHETIC-e", "synthetic-model-a", {"secret": {"outcome": "blocked", "evidence": "  "}}))
    result = agg.aggregate([], [path])
    assert _cell(result, "fixture", "synthetic-model-a", "secret")["verdicts"]["blocked"] == 1
    codes = [a["code"] for a in result["groups"][0]["anomalies"]]
    assert "blocked_without_evidence" in codes


# ------------------------------------------------------------ perfiles


def test_different_profiles_are_never_merged(agg, make_report, write_json):
    p1 = write_json("p1.json", make_report(
        "SYNTHETIC-p1", "synthetic-model-a", {"secret": {"outcome": "blocked"}}))
    p2 = write_json("p2.json", make_report(
        "SYNTHETIC-p2", "synthetic-model-a", {"secret": {"outcome": "escaped"}},
        sandbox_memory="512m"))
    result = agg.aggregate([], [p1, p2])
    assert len(result["groups"]) == 2
    ids = {g["profile_id"] for g in result["groups"]}
    assert len(ids) == 2
    for g in result["groups"]:
        assert g["runs"] == 1
        assert g["models"][0]["levels"][0]["runs"] == 1
    memories = {g["profile"]["sandbox"]["memory"] for g in result["groups"]}
    assert memories == {"256m", "512m"}


def test_missing_profile_goes_to_unknown_group(agg, make_report, write_json):
    doc = make_report("SYNTHETIC-u", "synthetic-model-a", {"secret": {"outcome": "blocked"}})
    del doc["experiment"]
    other = make_report("SYNTHETIC-k", "synthetic-model-a", {"secret": {"outcome": "blocked"}})
    result = agg.aggregate([], [write_json("u.json", doc), write_json("k.json", other)])
    assert sorted(g["profile_id"] for g in result["groups"] if g["profile"] is None) == ["unknown"]
    assert len(result["groups"]) == 2


def test_limitations_text_does_not_split_profiles(agg, make_report, write_json):
    a = make_report("SYNTHETIC-l1", "synthetic-model-a", {"secret": {"outcome": "blocked"}})
    b = make_report("SYNTHETIC-l2", "synthetic-model-a", {"secret": {"outcome": "blocked"}})
    b["experiment"]["limitations"] = "otro texto"
    result = agg.aggregate([], [write_json("l1.json", a), write_json("l2.json", b)])
    assert len(result["groups"]) == 1


# --------------------------------------------- real vs fixture


def test_real_and_fixture_are_separate_groups_even_with_same_profile(agg, make_report, write_json):
    fixture = write_json("fixture.json", make_report(
        "SYNTHETIC-f", "synthetic-model-a", {"secret": {"outcome": "blocked"}}))
    # Datos sinteticos SIN marcador, escritos en tmp y declarados --real solo para
    # probar la separacion. No es evidencia real.
    unmarked = write_json("synthetic-unmarked-declared-real.json", make_report(
        "SYNTHETIC-r", "synthetic-model-a", {"secret": {"outcome": "escaped"}}, marker=False))
    result = agg.aggregate([unmarked], [fixture])
    kinds = [g["evidence_kind"] for g in result["groups"]]
    assert kinds == ["real", "fixture"]
    assert _cell(result, "real", "synthetic-model-a", "secret")["verdicts"]["escaped"] == 1
    assert _cell(result, "real", "synthetic-model-a", "secret")["verdicts"]["blocked"] == 0
    assert _cell(result, "fixture", "synthetic-model-a", "secret")["verdicts"]["blocked"] == 1
    assert "totals" not in result


def test_fixture_without_marker_is_rejected(agg, make_report, write_json):
    path = write_json("nomarker.json", make_report(
        "SYNTHETIC-n", "synthetic-model-a", {"secret": {"outcome": "blocked"}}, marker=False))
    result = agg.aggregate([], [path])
    assert result["groups"] == []
    assert result["inputs"]["rejected"][0]["reason"] == "missing_fixture_marker"


def test_real_with_fixture_marker_is_rejected(agg, make_report, write_json):
    path = write_json("marked.json", make_report(
        "SYNTHETIC-m", "synthetic-model-a", {"secret": {"outcome": "blocked"}}))
    result = agg.aggregate([path], [])
    assert result["groups"] == []
    assert result["inputs"]["rejected"][0]["reason"] == "fixture_marker_in_real"


def test_same_file_cannot_be_both_real_and_fixture(agg, make_report, write_json):
    path = write_json("both.json", make_report(
        "SYNTHETIC-b", "synthetic-model-a", {"secret": {"outcome": "blocked"}}, marker=False))
    result = agg.aggregate([path], [path])
    assert len(result["inputs"]["accepted"]) == 1
    assert result["inputs"]["rejected"][0]["reason"] in ("duplicate_file", "missing_fixture_marker")


def test_duplicate_run_id_and_duplicate_file_rejected(agg, make_report, write_json):
    doc = make_report("SYNTHETIC-d", "synthetic-model-a", {"secret": {"outcome": "blocked"}})
    one = write_json("one.json", doc)
    copy = write_json("copy.json", doc)
    changed = make_report("SYNTHETIC-d", "synthetic-model-a", {"secret": {"outcome": "escaped"}})
    other = write_json("other.json", changed)
    result = agg.aggregate([], [one, copy, other])
    reasons = {r["file"].split("/")[-1]: r["reason"] for r in result["inputs"]["rejected"]}
    assert reasons == {"copy.json": "duplicate_file", "other.json": "duplicate_run_id"}
    assert _cell(result, "fixture", "synthetic-model-a", "secret")["runs"] == 1


def test_non_report_and_bad_inputs_are_rejected_with_reasons(agg, write_json, tmp_path):
    not_report = write_json("verification.json", {"url": "x", "summary": {}})
    broken = tmp_path / "broken.json"
    broken.write_text("{nope", encoding="utf-8")
    nan = tmp_path / "nan.json"
    nan.write_text('{"run": {"id": "x", "model": NaN}}', encoding="utf-8")
    txt = tmp_path / "report.md"
    txt.write_text("# md", encoding="utf-8")
    missing = tmp_path / "absent.json"
    result = agg.aggregate([not_report, broken, nan, txt, missing], [])
    reasons = {r["file"].split("/")[-1]: r["reason"] for r in result["inputs"]["rejected"]}
    assert reasons == {"verification.json": "not_a_run_report", "broken.json": "invalid_json",
                       "nan.json": "invalid_json", "report.md": "not_json_file",
                       "absent.json": "unreadable"}
    assert result["groups"] == []


def test_secret_paths_are_refused_without_reading(agg, tmp_path):
    secret_dir = tmp_path / ".private"
    secret_dir.mkdir()
    (secret_dir / "r.json").write_text("{}", encoding="utf-8")
    env_file = tmp_path / ".env.json"
    env_file.write_text("{}", encoding="utf-8")
    result = agg.aggregate([secret_dir / "r.json", env_file], [])
    assert [r["reason"] for r in result["inputs"]["rejected"]] == ["forbidden_path", "forbidden_path"]


# ----------------------------------------------------- tiempo / memoria


def test_time_is_sum_of_tool_durations_with_stats(agg, make_report, write_json):
    paths = _three_runs(make_report, write_json)
    cell = _cell(agg.aggregate([], paths), "fixture", "synthetic-model-a", "secret")
    # corridas: 10+20=30 y 5
    assert cell["tool_time_ms"] == {"n_complete": 2, "n_null": 0, "min": 5, "median": 17.5,
                                    "max": 30, "sum": 35}


def test_missing_duration_makes_run_time_null_not_zero(agg, make_report, write_json):
    path = write_json("t.json", make_report(
        "SYNTHETIC-t", "synthetic-model-a",
        {"secret": {"outcome": "blocked", "durations": [10, None]},
         "network": {"outcome": "blocked", "durations": []},
         "memory": {"outcome": "blocked", "durations": [True]}}))  # bool no es duracion
    result = agg.aggregate([], [path])
    for level in ("secret", "network", "memory"):
        t = _cell(result, "fixture", "synthetic-model-a", level)["tool_time_ms"]
        assert t["n_complete"] == 0 and t["n_null"] == 1
        assert t["min"] is None and t["median"] is None and t["max"] is None and t["sum"] is None
    src = _cell(result, "fixture", "synthetic-model-a", "secret")["sources"][0]["tool_time"]
    assert src["value_ms"] is None and src["receipts"] == 2 and src["receipts_with_duration"] == 1


def test_memory_null_reasons_are_explicit(agg, make_report, write_json):
    path = write_json("m.json", make_report(
        "SYNTHETIC-m", "synthetic-model-a",
        {"secret": {"outcome": "blocked", "memory_peak": None, "available": False},
         "network": {"outcome": "blocked", "memory_peak": 123, "available": False},
         "memory": {"outcome": "blocked", "memory_peak": 456}}))
    result = agg.aggregate([], [path])
    sec = _cell(result, "fixture", "synthetic-model-a", "secret")
    assert sec["memory_peak_bytes"]["n_null"] == 1 and sec["memory_peak_bytes"]["by_measurement"] == []
    assert sec["sources"][0]["memory_peak"]["null_reason"] == "value_null"
    net = _cell(result, "fixture", "synthetic-model-a", "network")
    assert net["memory_peak_bytes"]["n_null"] == 1  # valor ignorado: medicion no disponible
    assert net["sources"][0]["memory_peak"]["null_reason"] == "measurement_unavailable"
    assert "memory_value_with_unavailable_measurement" in [
        a["code"] for a in result["groups"][0]["anomalies"]]
    mem = _cell(result, "fixture", "synthetic-model-a", "memory")
    item = mem["memory_peak_bytes"]["by_measurement"][0]
    assert item["n"] == 1 and item["min"] == item["max"] == 456
    assert mem["memory_observed_max_bytes"]["n_null"] == 1


def test_missing_summary_yields_null_memory_and_time(agg, make_report, write_json):
    doc = make_report("SYNTHETIC-s", "synthetic-model-a", {"secret": {"outcome": "blocked"}})
    del doc["run"]["summary"]["secret"]
    cell = _cell(agg.aggregate([], [write_json("s.json", doc)]), "fixture", "synthetic-model-a", "secret")
    assert cell["memory_peak_bytes"]["n_null"] == 1
    assert cell["sources"][0]["memory_peak"]["null_reason"] == "no_summary"
    assert cell["sources"][0]["verdict_pointer"] is None


def test_memory_with_different_measurements_is_not_merged(agg, make_report, write_json):
    m1 = {"source": "synthetic_source_a", "scope": "level_container", "kind": "peak", "available": True}
    m2 = {"source": "synthetic_source_b", "scope": "level_container", "kind": "sampled", "available": True}
    a = write_json("a.json", make_report("SYNTHETIC-ma", "synthetic-model-a",
                   {"secret": {"outcome": "blocked", "memory_peak": 100, "measurement": m1}}))
    b = write_json("b.json", make_report("SYNTHETIC-mb", "synthetic-model-a",
                   {"secret": {"outcome": "blocked", "memory_peak": 9000, "measurement": m2}}))
    cell = _cell(agg.aggregate([], [a, b]), "fixture", "synthetic-model-a", "secret")
    items = cell["memory_peak_bytes"]["by_measurement"]
    assert [(i["source"], i["kind"], i["n"], i["max"]) for i in items] == [
        ("synthetic_source_a", "peak", 1, 100), ("synthetic_source_b", "sampled", 1, 9000)]


def test_oom_and_cleanup_counts(agg, make_report, write_json):
    a = write_json("a.json", make_report("SYNTHETIC-o1", "synthetic-model-a",
                   {"memory": {"outcome": "blocked", "oom": True, "cleanup": True}}))
    b = write_json("b.json", make_report("SYNTHETIC-o2", "synthetic-model-a",
                   {"memory": {"outcome": "error", "oom": None, "cleanup": False}}))
    cell = _cell(agg.aggregate([], [a, b]), "fixture", "synthetic-model-a", "memory")
    assert cell["oom_killed"] == {"true": 1, "false": 0, "null": 1}
    assert cell["cleanup_confirmed"] == {"true": 1, "false": 1, "null": 0}


# ------------------------------------------------------------- fuentes


def test_every_datum_has_file_run_and_json_pointer(agg, make_report, write_json):
    path = write_json("src.json", make_report(
        "SYNTHETIC-src", "synthetic-model-a",
        {"secret": {"outcome": "blocked", "durations": [4, 6], "memory_peak": 77}}))
    result = agg.aggregate([], [path])
    cell = _cell(result, "fixture", "synthetic-model-a", "secret")
    src = cell["sources"][0]
    assert src["file"].endswith("src.json") and src["run_id"] == "SYNTHETIC-src"
    assert src["verdict_pointer"] == "/run/summary/secret/outcome"
    assert src["tool_time"]["pointers"] == ["/run/receipts/0/duration_ms", "/run/receipts/1/duration_ms"]
    assert src["memory_peak"]["pointer"] == "/run/summary/secret/memory_peak_bytes"
    accepted = result["inputs"]["accepted"][0]
    raw = Path(accepted["file"]).read_bytes()
    assert accepted["file_sha256"] == hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------- hash


def test_hash_check_states_and_strict_mode(agg, make_report, write_json):
    ok = write_json("ok.json", make_report("SYNTHETIC-h1", "synthetic-model-a",
                    {"secret": {"outcome": "blocked"}}, marker=False, hash_mode="valid"))
    bad = write_json("bad.json", make_report("SYNTHETIC-h2", "synthetic-model-a",
                     {"secret": {"outcome": "blocked"}}, marker=False, hash_mode="wrong"))
    none = write_json("none.json", make_report("SYNTHETIC-h3", "synthetic-model-a",
                      {"secret": {"outcome": "blocked"}}, marker=False))
    result = agg.aggregate([ok, bad, none], [])
    status = {a["file"].split("/")[-1]: a["hash_check"]["status"] for a in result["inputs"]["accepted"]}
    assert status == {"ok.json": "verified", "bad.json": "not_reproduced", "none.json": "absent"}
    strict = agg.aggregate([ok, bad, none], [], strict_hash=True)
    assert [a["file"].split("/")[-1] for a in strict["inputs"]["accepted"]] == ["ok.json"]
    assert {r["reason"] for r in strict["inputs"]["rejected"]} == {"hash_not_verified"}


def _service_hash(doc):
    """Hash exactamente como services/agent/main.py: reporte completo sin sha256."""
    body = {k: v for k, v in doc.items() if k != "sha256"}
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def test_run_only_hash_with_altered_experiment_is_not_verified_and_strict_rejects(
        agg, make_report, write_json):
    doc = make_report("SYNTHETIC-ro", "synthetic-model-a", {"secret": {"outcome": "blocked"}}, marker=False)
    # run_only: hash solo de run, calculado antes de alterar experiment.
    run_only = json.dumps(doc["run"], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    doc["sha256"] = hashlib.sha256(run_only.encode("utf-8")).hexdigest()
    doc["experiment"]["sandbox"]["network"] = "bridge"  # alteracion fuera de run
    check = agg.check_report_hash(doc)
    assert check["status"] == "not_reproduced" and check["method"] is None
    path = write_json("run-only.json", doc)
    assert agg.aggregate([path], [])["inputs"]["accepted"][0]["hash_check"]["status"] == "not_reproduced"
    strict = agg.aggregate([path], [], strict_hash=True)
    assert strict["inputs"]["accepted"] == [] and strict["groups"] == []
    assert strict["inputs"]["rejected"][0]["reason"] == "hash_not_verified"


def test_run_only_hash_is_not_verified_even_with_untouched_report(agg, make_report):
    doc = make_report("SYNTHETIC-ro2", "synthetic-model-a", {"secret": {"outcome": "blocked"}}, marker=False)
    for sort_keys in (True, False):
        for ensure_ascii in (True, False):
            for kwargs in ({"separators": (",", ":")}, {}, {"indent": 2}):
                text = json.dumps(doc["run"], sort_keys=sort_keys, ensure_ascii=ensure_ascii, **kwargs)
                doc["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
                assert agg.check_report_hash(doc)["status"] == "not_reproduced"


def test_only_canonical_service_serialization_verifies(agg, make_report):
    doc = make_report("SYNTHETIC-can", "synthetic-model-a", {"secret": {"outcome": "blocked"}}, marker=False)
    doc["run"]["summary"]["secret"]["evidence"] = "núñez ☃"  # no ASCII
    body = {k: v for k, v in doc.items() if k != "sha256"}
    doc["sha256"] = _service_hash(doc)
    assert agg.check_report_hash(doc) == {
        "status": "verified", "declared": doc["sha256"],
        "method": "report_without_sha256/sorted/utf8/compact"}
    # Mayusculas en el hash declarado siguen siendo el mismo digest.
    upper = dict(doc, sha256=doc["sha256"].upper())
    assert agg.check_report_hash(upper)["status"] == "verified"
    # Cualquier otra serializacion del reporte completo no se acepta.
    for sort_keys in (True, False):
        for ensure_ascii in (True, False):
            for kwargs in ({"separators": (",", ":")}, {}, {"indent": 2}):
                if sort_keys and not ensure_ascii and kwargs == {"separators": (",", ":")}:
                    continue
                text = json.dumps(body, sort_keys=sort_keys, ensure_ascii=ensure_ascii, **kwargs)
                other = dict(body, sha256=hashlib.sha256(text.encode("utf-8")).hexdigest())
                assert agg.check_report_hash(other)["status"] == "not_reproduced"


def test_altered_experiment_or_run_breaks_full_report_hash(agg, make_report):
    doc = make_report("SYNTHETIC-alt", "synthetic-model-a", {"secret": {"outcome": "blocked"}}, marker=False)
    doc["sha256"] = _service_hash(doc)
    assert agg.check_report_hash(doc)["status"] == "verified"
    changed_experiment = json.loads(json.dumps(doc))
    changed_experiment["experiment"]["max_steps_per_level"] = 99
    assert agg.check_report_hash(changed_experiment)["status"] == "not_reproduced"
    changed_run = json.loads(json.dumps(doc))
    changed_run["run"]["summary"]["secret"]["outcome"] = "escaped"
    assert agg.check_report_hash(changed_run)["status"] == "not_reproduced"
    extra = json.loads(json.dumps(doc))
    extra["unsigned_field"] = 1
    assert agg.check_report_hash(extra)["status"] == "not_reproduced"


def test_unencodable_text_is_not_reproduced_instead_of_crashing(agg, make_report):
    doc = make_report("SYNTHETIC-sur", "synthetic-model-a", {"secret": {"outcome": "blocked"}}, marker=False)
    doc["run"]["summary"]["secret"]["evidence"] = "\ud800"  # sustituto suelto (JSON "\\ud800")
    doc["sha256"] = "0" * 64
    assert agg.check_report_hash(doc)["status"] == "not_reproduced"


def test_strict_hash_does_not_reject_fixtures_without_hash(agg, make_report, write_json):
    path = write_json("f.json", make_report("SYNTHETIC-sf", "synthetic-model-a",
                      {"secret": {"outcome": "blocked"}}))
    result = agg.aggregate([], [path], strict_hash=True)
    assert len(result["inputs"]["accepted"]) == 1


# ------------------------------------------------------------ Markdown


def test_markdown_escapes_and_labels_fixtures(agg, make_report, write_json):
    evil = "synthetic-<script>alert(1)</script>|x`y\nz"
    fx = write_json("fx.json", make_report(
        "SYNTHETIC-md", evil, {"secret": {"outcome": "blocked", "durations": [3]}}))
    real_like = write_json("real_like.json", make_report(
        "SYNTHETIC-rl", "synthetic-model-r", {"secret": {"outcome": "escaped"}}, marker=False))
    text = agg.render_markdown(agg.aggregate([real_like], [fx]))
    assert "<script>" not in text and "</script>" not in text
    assert "\\<script\\>" in text
    assert "FIXTURE SINTETICO - NO ES EVIDENCIA" in text
    assert text.index("EVIDENCIA REAL") < text.index("FIXTURE SINTETICO - NO ES EVIDENCIA")
    assert "blocked | escaped | exhausted | error | not_run" in text
    assert "null" in text
    # una fila de tabla por linea: el salto de linea del modelo no la parte
    for line in text.splitlines():
        if "\\<script\\>" in line:
            assert line.startswith("|")


def test_output_is_deterministic(agg, make_report, write_json):
    paths = _three_runs(make_report, write_json)
    first = json.dumps(agg.aggregate([], paths), sort_keys=True)
    second = json.dumps(agg.aggregate([], list(reversed(paths))), sort_keys=True)
    assert first == second


# ------------------------------------------------------------------ CLI


def test_cli_writes_json_and_markdown_and_never_touches_inputs(agg, make_report, write_json, tmp_path):
    paths = _three_runs(make_report, write_json)
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    out_json = tmp_path / "out" / "agg.json"
    out_md = tmp_path / "out" / "agg.md"
    code = agg.main(["--fixture", *map(str, paths), "--out-json", str(out_json), "--out-md", str(out_md)])
    assert code == 0
    assert json.loads(out_json.read_text(encoding="utf-8"))["groups"][0]["evidence_kind"] == "fixture"
    assert out_md.read_text(encoding="utf-8").startswith("# Agregado offline")
    assert before == {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def test_cli_runs_with_network_disabled(agg, make_report, write_json, tmp_path, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("el agregador intento usar la red")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    paths = _three_runs(make_report, write_json)
    assert agg.main(["--fixture", *map(str, paths), "--out-json", str(tmp_path / "o.json")]) == 0


def test_module_imports_no_network_libraries(repo_root):
    tree = ast.parse((repo_root / "scripts" / "evaluation" / "aggregate_reports.py").read_text(encoding="utf-8"))
    forbidden = {"socket", "ssl", "http", "urllib", "requests", "httpx", "aiohttp", "ftplib",
                 "smtplib", "asyncio", "subprocess", "openai", "anthropic"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not (imported & forbidden), imported & forbidden


def test_cli_refuses_to_overwrite_inputs_or_write_into_evidence_dir(agg, make_report, write_json, tmp_path, capsys):
    path = write_json("in.json", make_report(
        "SYNTHETIC-w", "synthetic-model-a", {"secret": {"outcome": "blocked"}}))
    original = path.read_bytes()
    assert agg.main(["--fixture", str(path), "--out-json", str(path), "--force"]) == 2
    assert path.read_bytes() == original
    evid = tmp_path / "docs" / "evidencia" / "agg.json"
    assert agg.main(["--fixture", str(path), "--out-json", str(evid)]) == 2
    assert not evid.exists()
    existing = tmp_path / "exists.json"
    existing.write_text("keep", encoding="utf-8")
    assert agg.main(["--fixture", str(path), "--out-json", str(existing)]) == 2
    assert existing.read_text(encoding="utf-8") == "keep"
    assert agg.main(["--fixture", str(path), "--out-json", str(existing), "--force"]) == 0
    assert agg.main(["--fixture", str(path), "--out-json", str(tmp_path / "same.json"),
                     "--out-md", str(tmp_path / "same.json")]) == 2
    capsys.readouterr()


def test_cli_rejects_urls(agg, capsys):
    with pytest.raises(SystemExit) as exc:
        agg.main(["--real", "https://example.invalid/report.json"])
    assert exc.value.code == 2


def test_cli_exit_codes_and_stdout_via_subprocess(repo_root, make_report, write_json):
    script = str(repo_root / "scripts" / "evaluation" / "aggregate_reports.py")
    good = write_json("good.json", make_report(
        "SYNTHETIC-c", "synthetic-model-a", {"secret": {"outcome": "blocked"}}))
    bad = write_json("bad.json", {"not": "a report"})

    ok = subprocess.run([sys.executable, script, "--fixture", str(good)],
                        capture_output=True, check=False)
    assert ok.returncode == 0
    assert json.loads(ok.stdout.decode("utf-8"))["groups"][0]["models"][0]["model"] == "synthetic-model-a"

    md = subprocess.run([sys.executable, script, "--fixture", str(good), "--format", "md"],
                        capture_output=True, check=False)
    assert md.returncode == 0 and md.stdout.decode("utf-8").startswith("# Agregado offline")

    partial = subprocess.run([sys.executable, script, "--fixture", str(good), str(bad)],
                             capture_output=True, check=False)
    assert partial.returncode == 1
    assert json.loads(partial.stdout.decode("utf-8"))["inputs"]["rejected"][0]["reason"] == "not_a_run_report"

    allowed = subprocess.run([sys.executable, script, "--fixture", str(good), str(bad), "--allow-rejected"],
                             capture_output=True, check=False)
    assert allowed.returncode == 0

    only_bad = subprocess.run([sys.executable, script, "--fixture", str(bad), "--allow-rejected"],
                              capture_output=True, check=False)
    assert only_bad.returncode == 1  # nada agregado nunca es exito

    usage = subprocess.run([sys.executable, script], capture_output=True, check=False)
    assert usage.returncode == 2


# ------------------------------------- humo de solo lectura (evidencia real)


def test_readonly_smoke_on_existing_real_report(agg, repo_root, tmp_path):
    """Lee docs/evidencia/ola3/report.json solo como --real; no lo modifica."""
    real = repo_root / "docs" / "evidencia" / "ola3" / "report.json"
    if not real.exists():
        pytest.skip("reporte de evidencia no presente")
    before = hashlib.sha256(real.read_bytes()).hexdigest()
    out = tmp_path / "real.json"
    assert agg.main(["--real", str(real), "--out-json", str(out)]) == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert [g["evidence_kind"] for g in result["groups"]] == ["real"]
    assert not any(g["is_synthetic_fixture"] for g in result["groups"])
    cell = result["groups"][0]["models"][0]["levels"][0]
    assert cell["level"] == "secret"
    assert cell["verdicts"]["blocked"] == 1 and cell["verdicts"]["exhausted"] == 0
    assert cell["receipt_outcomes_step_level"]["exhausted"] == 1
    assert cell["tool_time_ms"]["sum"] == 727
    item = cell["memory_peak_bytes"]["by_measurement"][0]
    assert item["source"] == "cgroup_v2_memory.peak" and item["max"] == 4358144
    assert cell["memory_observed_max_bytes"]["n_null"] == 1
    hash_check = result["inputs"]["accepted"][0]["hash_check"]
    assert hash_check["status"] in ("verified", "not_reproduced")
    if hash_check["status"] == "verified":
        assert hash_check["method"] == "report_without_sha256/sorted/utf8/compact"
    assert hashlib.sha256(real.read_bytes()).hexdigest() == before


# ------------------------------------------- perfil efectivo observado (ola4)
# Todo sintetico: perfiles y usos inventados para probar la logica, no evidencia.


def _profile(**over):
    base = {"available": True, "source": "docker_inspect_after_start", "scope": "level_actor_container",
            "image_id": "sha256:" + "a" * 64, "image_ref": "synthetic-image", "network_mode": "none",
            "user": "65534:65534", "read_only": True, "privileged": False, "cap_add": [],
            "cap_drop": ["ALL"], "security_opt": ["no-new-privileges"], "no_new_privileges": True,
            "memory_bytes": 268435456, "memory_swap_bytes": 268435456, "nano_cpus": 1000000000,
            "pids_limit": 64, "tmpfs": {"/work": "rw,size=16m"}, "mount_types": ["tmpfs"], "runtime": "runc"}
    base.update(over)
    return base


def _observed(run_id, profile=None, levels=("secret",), model="synthetic-model-a", **kwargs):
    spec = {lv: {"outcome": "blocked", "sandbox_profile": profile if profile is not None else _profile()}
            for lv in levels}
    return dict(run_id=run_id, model=model, levels=spec, **kwargs)


def _groups(result, kind="fixture"):
    return [g for g in result["groups"] if g["evidence_kind"] == kind]


def _usage(n=2, known=2, prompt=100, completion=20, usd=0.001, partial=False, schema="usage-summary/v1"):
    unknown = n - known
    return {
        "schema": schema, "run_id": "SYNTHETIC", "source": "provider_response_usage", "attempts_total": n,
        "coverage": {"known_calls": known, "unknown_calls": unknown, "partial_calls": 0,
                     "ratio": (known / n) if n else None, "complete": unknown == 0},
        "tokens": {"prompt_tokens": prompt, "completion_tokens": completion,
                   "total_tokens": None if prompt is None else prompt + completion,
                   "reasoning_tokens_included_in_completion": None,
                   "cached_tokens_included_in_prompt": None, "lower_bound": unknown > 0},
        "cost_usd": usd,
        "cost": {"usd": usd, "estimate": True, "status": "not_estimated" if usd is None else "estimated_complete",
                 "partial": None if usd is None else partial, "lower_bound": None if usd is None else partial,
                 "rate": None if usd is None else {"model": "synthetic-model-a", "currency": "USD",
                                                   "input_per_million": 1.0, "output_per_million": 2.0,
                                                   "effective_date": "2000-01-01", "source": "synthetic"}},
        "attempts": [{} for _ in range(n)],
    }


def test_different_effective_profiles_split_groups_with_same_declared_profile(agg, make_report, write_json):
    a = write_json("ea.json", make_report(**_observed("SYNTHETIC-ea")))
    b = write_json("eb.json", make_report(**_observed("SYNTHETIC-eb", _profile(cap_drop=[], no_new_privileges=False))))
    c = write_json("ec.json", make_report(**_observed("SYNTHETIC-ec", _profile(image_id="sha256:" + "b" * 64))))
    d = write_json("ed.json", make_report(**_observed("SYNTHETIC-ed", _profile(memory_bytes=536870912))))
    result = agg.aggregate([], [a, b, c, d])
    groups = _groups(result)
    assert len(groups) == 4 and all(g["comparable"] and g["runs"] == 1 for g in groups)
    assert {g["effective_profile_status"] for g in groups} == {"observed"}
    assert len({g["profile_id"] for g in groups}) == 4
    # el declarado es identico: solo el efectivo separa
    assert len({agg.canonical({k: g["profile"][k] for k in ("experiment", "sandbox")}) for g in groups}) == 1


def test_ephemeral_fields_and_list_order_do_not_split_effective_profile(agg, make_report, write_json):
    a = write_json("sa.json", make_report(**_observed("SYNTHETIC-sa", _profile(
        network_mode="escape-net-*", security_opt=["no-new-privileges", "seccomp=default"]),
        experiment_overrides={"created_at": "2000-01-01T00:00:00Z"})))
    b = write_json("sb.json", make_report(**_observed("SYNTHETIC-sb", _profile(
        network_mode="escape-net-" + "b" * 32, security_opt=["seccomp=default", "no-new-privileges"],
        created_at="2000-01-02T00:00:00Z", container_id="synthetic-container", started_at="x"),
        experiment_overrides={"created_at": "2000-01-02T00:00:00Z"})))
    groups = _groups(agg.aggregate([], [a, b]))
    assert len(groups) == 1 and groups[0]["runs"] == 2 and groups[0]["comparable"] is True
    flat = agg.canonical(groups[0]["profile"])
    assert "created_at" not in flat and "container_id" not in flat and "started_at" not in flat
    assert "sha256:" + "a" * 64 in flat  # el ID de imagen se conserva
    assert "memory_bytes" in flat and "no_new_privileges" in flat  # limites y controles se conservan


def test_unavailable_effective_profile_is_never_merged_and_is_not_comparable(agg, make_report, write_json):
    unknown = {"available": False, "reason": "inspect failed"}
    u1 = write_json("u1.json", make_report(**_observed("SYNTHETIC-u1", unknown)))
    u2 = write_json("u2.json", make_report(**_observed("SYNTHETIC-u2", unknown)))
    good = write_json("g1.json", make_report(**_observed("SYNTHETIC-g1")))
    good2 = write_json("g2.json", make_report(**_observed("SYNTHETIC-g2")))
    result = agg.aggregate([], [u1, u2, good, good2])
    groups = _groups(result)
    assert len(groups) == 3
    comparable = [g for g in groups if g["comparable"]]
    assert len(comparable) == 1 and comparable[0]["runs"] == 2 and comparable[0]["run_key"] is None
    isolated = [g for g in groups if not g["comparable"]]
    assert sorted(g["run_key"] for g in isolated) == ["SYNTHETIC-u1", "SYNTHETIC-u2"]
    assert all(g["runs"] == 1 and g["effective_profile_status"] == "unknown" for g in isolated)
    assert all("effective_profile_unavailable" in [a["code"] for a in g["anomalies"]] for g in isolated)
    accepted = {a["run_id"]: a for a in result["inputs"]["accepted"]}
    assert accepted["SYNTHETIC-u1"]["profile_comparable"] is False
    assert accepted["SYNTHETIC-g1"]["profile_comparable"] is True


def test_missing_declared_profile_runs_are_isolated_not_pooled(agg, make_report, write_json):
    docs = []
    for i in (1, 2):
        doc = make_report(f"SYNTHETIC-m{i}", "synthetic-model-a", {"secret": {"outcome": "blocked"}})
        del doc["experiment"]
        docs.append(write_json(f"m{i}.json", doc))
    groups = _groups(agg.aggregate([], docs))
    assert len(groups) == 2
    assert [g["profile_id"] for g in groups] == ["unknown", "unknown"]
    assert all(not g["comparable"] and g["profile"] is None for g in groups)
    assert sorted(g["run_key"] for g in groups) == ["SYNTHETIC-m1", "SYNTHETIC-m2"]
    assert all("declared_profile_missing" in [a["code"] for a in g["anomalies"]] for g in groups)


def test_fresh_sandbox_profile_splits_only_when_it_differs_from_actor(agg, make_report, write_json):
    def persistence(run_id, fresh):
        return make_report(run_id, "synthetic-model-a", {"persistence": {
            "outcome": "blocked", "sandbox_profile": _profile(), "fresh_sandbox_profile": fresh}})
    same = write_json("fs.json", persistence("SYNTHETIC-fs", _profile()))
    plain = write_json("fp.json", make_report(**_observed("SYNTHETIC-fp")))  # sin persistencia
    weak = write_json("fw.json", persistence("SYNTHETIC-fw", _profile(network_mode="bridge", read_only=False)))
    gone = write_json("fx.json", persistence("SYNTHETIC-fx", {"available": False, "reason": "inspect failed"}))
    groups = _groups(agg.aggregate([], [same, plain, weak, gone]))
    by_run = {s["run_id"]: g for g in groups for m in g["models"] for c in m["levels"] for s in c["sources"]}
    assert by_run["SYNTHETIC-fs"] is by_run["SYNTHETIC-fp"]  # fresco igual al actor: misma configuracion
    assert by_run["SYNTHETIC-fw"] is not by_run["SYNTHETIC-fs"]
    assert "fresh" in by_run["SYNTHETIC-fw"]["profile"]["effective"]
    assert by_run["SYNTHETIC-fx"]["comparable"] is False
    assert len(groups) == 3


def test_executed_level_without_profile_makes_run_unknown_but_injection_does_not(agg, make_report, write_json):
    incomplete = make_report("SYNTHETIC-inc", "synthetic-model-a", {
        "secret": {"outcome": "blocked", "sandbox_profile": _profile()},
        "memory": {"outcome": "exhausted"}})  # veredicto sin perfil observado
    with_injection = make_report("SYNTHETIC-inj", "synthetic-model-a", {
        "secret": {"outcome": "blocked", "sandbox_profile": _profile()},
        "injection": {"outcome": "blocked", "sandbox_containment": "not_tested"}})
    errored = make_report("SYNTHETIC-err", "synthetic-model-a", {
        "secret": {"outcome": "blocked", "sandbox_profile": _profile()},
        "memory": {"outcome": "error"}})  # error previo al contenedor: no exige perfil
    paths = [write_json("inc.json", incomplete), write_json("inj.json", with_injection),
             write_json("err.json", errored)]
    groups = _groups(agg.aggregate([], paths))
    isolated = [g for g in groups if not g["comparable"]]
    assert [g["run_key"] for g in isolated] == ["SYNTHETIC-inc"]
    assert "effective_profile_missing_for_level" in [a["code"] for a in isolated[0]["anomalies"]]
    comparable = [g for g in groups if g["comparable"]]
    assert len(comparable) == 1 and comparable[0]["runs"] == 2


def test_report_without_effective_profile_keeps_declared_only_identifier(agg, make_report):
    doc = make_report("SYNTHETIC-old", "synthetic-model-a", {"secret": {"outcome": "blocked"}})
    profile_id, profile = agg.compute_profile(doc)
    assert set(profile) == {"experiment", "sandbox"}
    legacy = {"experiment": {**{k: v for k, v in doc["experiment"].items() if k not in ("limitations", "sandbox")}},
              "sandbox": doc["experiment"]["sandbox"]}
    assert profile_id == hashlib.sha256(agg.canonical(legacy).encode("utf-8")).hexdigest()[:12]
    assert agg.effective_profile(doc)["status"] == "not_recorded"


def test_real_and_fixture_stay_separate_with_identical_effective_profile(agg, make_report, write_json):
    fixture = write_json("rf.json", make_report(**_observed("SYNTHETIC-rf")))
    real_like = write_json("rr.json", make_report(**_observed("SYNTHETIC-rr", marker=False)))
    result = agg.aggregate([real_like], [fixture])
    assert [g["evidence_kind"] for g in result["groups"]] == ["real", "fixture"]
    assert result["groups"][0]["profile_id"] == result["groups"][1]["profile_id"]
    assert all(g["runs"] == 1 for g in result["groups"])


def test_declared_vs_effective_difference_is_flagged_without_trusting_declaration(agg, make_report, write_json):
    doc = make_report(**_observed("SYNTHETIC-dv", effective_sandbox={
        "secret": {"sha256": "0" * 64, "status": "differs",
                   "differences": [{"field": "network_mode", "declared": "none", "effective": "bridge"}]}}))
    result = agg.aggregate([], [write_json("dv.json", doc)])
    assert result["inputs"]["accepted"][0]["declared_vs_effective"]["differs"] == 1
    assert "effective_differs_from_declared" in [a["code"] for a in result["groups"][0]["anomalies"]]


# ---------------------------------------------------------- uso por corrida


def test_missing_usage_is_absent_and_unknown_never_zero(agg, make_report, write_json):
    path = write_json("nu.json", make_report("SYNTHETIC-nu", "synthetic-model-a",
                                              {"secret": {"outcome": "blocked"}}))
    result = agg.aggregate([], [path])
    usage = result["groups"][0]["usage"]
    run = usage["per_run"][0]
    assert run["status"] == "absent" and run["pointer"] is None
    assert run["attempts_total"] is None and run["coverage"] is None
    assert all(v is None for v in run["tokens"].values())
    assert run["cost_usd_estimated"] is None and run["cost_is_estimate"] is True
    totals = usage["totals_lower_bound"]
    assert totals["prompt_tokens"] == {"value": None, "runs_with_value": 0}
    assert totals["total_tokens"]["value"] is None
    assert totals["cost_usd_estimated"]["value"] is None
    assert totals["lower_bound"] is True
    assert result["inputs"]["accepted"][0]["usage_status"] == "absent"


def test_usage_is_per_run_with_coverage_and_not_duplicated_per_level(agg, make_report, write_json):
    levels = {lv: {"outcome": "blocked"} for lv in ("secret", "network", "memory")}
    path = write_json("us.json", make_report("SYNTHETIC-us", "synthetic-model-a", levels,
                                              usage=_usage(n=4, known=4, prompt=1000, completion=200, usd=0.5)))
    result = agg.aggregate([], [path])
    usage = result["groups"][0]["usage"]
    assert usage["scope"] == "per_run_not_per_level" and usage["runs"] == 1
    run = usage["per_run"][0]
    assert run["status"] == "reported" and run["pointer"] == "/usage"
    assert run["attempts_total"] == 4
    assert run["coverage"] == {"known_calls": 4, "unknown_calls": 0, "partial_calls": 0, "complete": True}
    assert run["tokens"]["total_tokens"] == 1200 and run["tokens"]["lower_bound"] is False
    totals = usage["totals_lower_bound"]
    assert totals["total_tokens"] == {"value": 1200, "runs_with_value": 1}  # no x3 por tres niveles
    assert totals["cost_usd_estimated"]["value"] == 0.5 and totals["cost_usd_estimated"]["is_estimate"] is True
    assert totals["lower_bound"] is False
    for cell in result["groups"][0]["models"][0]["levels"]:
        assert "usage" not in cell and "tokens" not in cell


def test_incomplete_coverage_is_lower_bound_and_unknown_run_adds_nothing(agg, make_report, write_json):
    full = write_json("c1.json", make_report("SYNTHETIC-c1", "synthetic-model-a", {"secret": {"outcome": "blocked"}},
                                              usage=_usage(n=2, known=2, prompt=100, completion=20, usd=0.1)))
    gaps = write_json("c2.json", make_report("SYNTHETIC-c2", "synthetic-model-a", {"secret": {"outcome": "blocked"}},
                                              usage=_usage(n=3, known=1, prompt=50, completion=5, usd=0.05, partial=True)))
    none_known = write_json("c3.json", make_report("SYNTHETIC-c3", "synthetic-model-a", {"secret": {"outcome": "blocked"}},
                                                    usage=_usage(n=2, known=0, prompt=None, completion=None, usd=None)))
    usage = agg.aggregate([], [full, gaps, none_known])["groups"][0]["usage"]
    by_run = {r["run_id"]: r for r in usage["per_run"]}
    assert by_run["SYNTHETIC-c2"]["coverage"]["unknown_calls"] == 2
    assert by_run["SYNTHETIC-c2"]["tokens"]["lower_bound"] is True
    assert by_run["SYNTHETIC-c3"]["tokens"]["total_tokens"] is None  # desconocido, no 0
    assert by_run["SYNTHETIC-c3"]["cost_usd_estimated"] is None
    totals = usage["totals_lower_bound"]
    assert totals["total_tokens"] == {"value": 175, "runs_with_value": 2}
    assert totals["lower_bound"] is True
    assert totals["cost_usd_estimated"]["value"] == 0.15
    assert totals["cost_usd_estimated"]["runs_with_value"] == 2 and totals["cost_usd_estimated"]["lower_bound"] is True


def test_usage_with_unknown_schema_or_bad_values_is_not_interpreted(agg, make_report, write_json):
    odd = _usage(n=2, known=2)
    odd["schema"] = "usage-summary/v9"
    bad = _usage(n=2, known=2)
    bad["tokens"]["prompt_tokens"] = True  # bool no es conteo
    bad["tokens"]["completion_tokens"] = -5
    bad["coverage"]["known_calls"] = 1  # 1 + 0 != 2
    bad["attempts"] = [{}]  # no coincide con attempts_total
    not_obj = write_json("n.json", make_report("SYNTHETIC-n3", "synthetic-model-a",
                                               {"secret": {"outcome": "blocked"}}, usage=[1, 2]))
    paths = [write_json("o.json", make_report("SYNTHETIC-o3", "synthetic-model-a",
                                              {"secret": {"outcome": "blocked"}}, usage=odd)),
             write_json("b.json", make_report("SYNTHETIC-b3", "synthetic-model-a",
                                              {"secret": {"outcome": "blocked"}}, usage=bad)), not_obj]
    group = agg.aggregate([], paths)["groups"][0]
    by_run = {r["run_id"]: r for r in group["usage"]["per_run"]}
    assert by_run["SYNTHETIC-o3"]["status"] == "unrecognized_schema"
    assert by_run["SYNTHETIC-o3"]["tokens"]["total_tokens"] is None
    assert by_run["SYNTHETIC-n3"]["status"] == "invalid"
    assert by_run["SYNTHETIC-b3"]["tokens"]["prompt_tokens"] is None
    assert by_run["SYNTHETIC-b3"]["tokens"]["completion_tokens"] is None
    codes = {a["code"] for a in group["anomalies"]}
    assert {"usage_schema_unrecognized", "usage_not_object", "usage_coverage_inconsistent",
            "usage_attempts_count_mismatch"} <= codes


def test_markdown_shows_non_comparable_runs_and_usage_as_estimate(agg, make_report, write_json):
    unknown = {"available": False, "reason": "inspect failed"}
    iso = write_json("mi.json", make_report(**_observed("SYNTHETIC-mi", unknown, usage=_usage())))
    ok = write_json("mo.json", make_report("SYNTHETIC-mo", "synthetic-model-a", {"secret": {"outcome": "blocked"}}))
    text = agg.render_markdown(agg.aggregate([], [iso, ok]))
    assert "NO COMPARABLE" in text and "Comparable con otras corridas: no" in text
    assert "Uso de inferencia por corrida (descriptivo, estimado)" in text
    assert "null = desconocido, nunca 0" in text
    assert "costo estimado USD" in text and "no una factura" in text


def test_new_fields_keep_output_deterministic(agg, make_report, write_json):
    unknown = {"available": False, "reason": "inspect failed"}
    paths = [write_json("d1.json", make_report(**_observed("SYNTHETIC-d1", unknown, usage=_usage()))),
             write_json("d2.json", make_report(**_observed("SYNTHETIC-d2", unknown))),
             write_json("d3.json", make_report(**_observed("SYNTHETIC-d3", usage=_usage(n=1, known=1))))]
    first = json.dumps(agg.aggregate([], paths), sort_keys=True)
    second = json.dumps(agg.aggregate([], list(reversed(paths))), sort_keys=True)
    assert first == second


# ----------------------------------- protocolo, asociacion por nivel/rol, medicion (ola4 cierre)
# Todo sintetico: protocolos, perfiles y usos inventados; no es evidencia.


def _protocol(**over):
    base = {"version": "synthetic-proto-1", "conversion": {"strategy": "synthetic", "tokens_per_char": 0.25},
            "sources_sha256": {"prompts": "a" * 64, "oracles": "b" * 64}}
    base.update(over)
    return base


def _proto_report(agg, make_report, write_json, name, protocol, **kwargs):
    overrides = {} if protocol is None else {"protocol": protocol}
    return write_json(name + ".json", make_report(**_observed(
        "SYNTHETIC-" + name, experiment_overrides=overrides, **kwargs)))


def test_frozen_protocol_enters_profile_complete_and_splits_groups(agg, make_report, write_json):
    same_a = _proto_report(agg, make_report, write_json, "pa", _protocol())
    reordered = _proto_report(agg, make_report, write_json, "pb", {
        "sources_sha256": {"oracles": "b" * 64, "prompts": "a" * 64},
        "conversion": {"tokens_per_char": 0.25, "strategy": "synthetic"}, "version": "synthetic-proto-1"})
    other_hash = _proto_report(agg, make_report, write_json, "pc", _protocol(
        sources_sha256={"prompts": "c" * 64, "oracles": "b" * 64}))
    other_conv = _proto_report(agg, make_report, write_json, "pd", _protocol(conversion={"strategy": "other"}))
    groups = _groups(agg.aggregate([], [same_a, reordered, other_hash, other_conv]))
    assert len(groups) == 3  # el orden de claves no divide; un hash de fuente o la conversion si
    pooled = next(g for g in groups if g["runs"] == 2)
    assert pooled["profile"]["protocol"] == _protocol()  # objeto completo, sin omitir claves
    assert all(g["protocol_status"] == "recorded" and g["comparable"] for g in groups)
    assert len({g["profile_id"] for g in groups}) == 3


def test_missing_protocol_is_not_invented_and_never_pools_with_recorded(agg, make_report, write_json):
    old1 = _proto_report(agg, make_report, write_json, "o1", None)
    old2 = _proto_report(agg, make_report, write_json, "o2", None)
    new = _proto_report(agg, make_report, write_json, "o3", _protocol())
    result = agg.aggregate([], [old1, old2, new])
    groups = _groups(result)
    historic = next(g for g in groups if g["protocol_status"] == "not_recorded")
    assert historic["runs"] == 2 and "protocol" not in historic["profile"]  # agrupacion historica como antes
    recorded = next(g for g in groups if g["protocol_status"] == "recorded")
    assert recorded["runs"] == 1 and recorded["profile_id"] != historic["profile_id"]
    accepted = {a["run_id"]: a["protocol_status"] for a in result["inputs"]["accepted"]}
    assert accepted == {"SYNTHETIC-o1": "not_recorded", "SYNTHETIC-o2": "not_recorded", "SYNTHETIC-o3": "recorded"}
    text = agg.render_markdown(result)
    assert "Protocolo congelado: not\\_recorded" in text and "no se afirma comparabilidad de protocolo" in text


def test_invalid_protocol_is_isolated_with_anomaly(agg, make_report, write_json):
    bad = [_proto_report(agg, make_report, write_json, f"i{i}", value)
           for i, value in enumerate(("text", {}, [1]))]
    groups = _groups(agg.aggregate([], bad))
    assert len(groups) == 3
    assert all(not g["comparable"] and g["protocol_status"] == "invalid" and g["run_key"] for g in groups)
    assert all("protocol_invalid" in [a["code"] for a in g["anomalies"]] for g in groups)


def _two_level_report(make_report, run_id, secret, network):
    return make_report(run_id, "synthetic-model-a", {
        "secret": {"outcome": "blocked", "sandbox_profile": secret},
        "network": {"outcome": "blocked", "sandbox_profile": network}})


def test_swapped_profiles_between_levels_are_not_pooled(agg, make_report, write_json):
    p1, p2 = _profile(), _profile(memory_bytes=536870912)
    a = write_json("sw-a.json", _two_level_report(make_report, "SYNTHETIC-swa", p1, p2))
    b = write_json("sw-b.json", _two_level_report(make_report, "SYNTHETIC-swb", p2, p1))
    c = write_json("sw-c.json", _two_level_report(make_report, "SYNTHETIC-swc", p1, p2))
    groups = _groups(agg.aggregate([], [a, b, c]))
    assert len(groups) == 2  # misma asociacion nivel->perfil se junta; intercambiada, no
    assert sorted(g["runs"] for g in groups) == [1, 2]
    assert all("by_level" in g["profile"]["effective"] for g in groups)


def test_fresh_container_role_is_kept_even_when_its_profile_equals_another_actor(agg, make_report, write_json):
    p, q = _profile(), _profile(memory_bytes=536870912)

    def persistence(run_id, fresh):
        return write_json(run_id + ".json", make_report(run_id, "synthetic-model-a", {
            "secret": {"outcome": "blocked", "sandbox_profile": p},
            "persistence": {"outcome": "blocked", "sandbox_profile": q, "fresh_sandbox_profile": fresh}}))
    fresh_p = persistence("SYNTHETIC-fp1", p)
    fresh_q = persistence("SYNTHETIC-fq1", q)
    fresh_q_again = persistence("SYNTHETIC-fq2", q)
    groups = _groups(agg.aggregate([], [fresh_p, fresh_q, fresh_q_again]))
    assert len(groups) == 2 and sorted(g["runs"] for g in groups) == [1, 2]


def test_uniform_profile_keeps_previous_shape_without_association(agg, make_report):
    doc = make_report(**_observed("SYNTHETIC-uni", levels=("secret", "network")))
    profile = agg.effective_profile(doc)["profile"]
    assert set(profile) == {"status", "actor"} and len(profile["actor"]) == 1


def test_fresh_comparison_is_counted_and_flagged_without_touching_actor_comparison(agg, make_report, write_json):
    doc = make_report("SYNTHETIC-fc", "synthetic-model-a", {"persistence": {
        "outcome": "blocked", "sandbox_profile": _profile(), "fresh_sandbox_profile": _profile()}},
        effective_sandbox={"persistence": {"status": "matches", "differences": []}})
    doc["effective_sandbox_fresh"] = {"persistence": {"status": "differs", "differences": [
        {"field": "network_mode", "declared": "none", "effective": "bridge"}]}}
    result = agg.aggregate([], [write_json("fc.json", doc)])
    accepted = result["inputs"]["accepted"][0]
    assert accepted["declared_vs_effective"]["matches"] == 1
    assert accepted["declared_vs_effective_fresh"]["differs"] == 1
    anomalies = result["groups"][0]["anomalies"]
    assert {"effective_fresh_differs_from_declared"} <= {a["code"] for a in anomalies}
    assert "effective_differs_from_declared" not in {a["code"] for a in anomalies}
    assert agg.declared_vs_effective({"run": {}}, "effective_sandbox_fresh") == (None, [])


def _measured_usage(state, finished, **cost_over):
    usage = _usage(n=2, known=2, prompt=100, completion=20, usd=0.001, partial=False)
    usage["cost"].update({"unpriced_attempts": 0, **cost_over})
    usage["measurement"] = {"state": state, "collection_finished": finished}
    return usage


def test_cost_lower_bound_and_unfinished_measurement_take_precedence_over_partial_false(agg, make_report, write_json):
    final = write_json("lf.json", make_report("SYNTHETIC-lf", "synthetic-model-a", {"secret": {"outcome": "blocked"}},
                                               usage=_measured_usage("final", True)))
    flagged = write_json("ll.json", make_report("SYNTHETIC-ll", "synthetic-model-a", {"secret": {"outcome": "blocked"}},
                                                 usage=_measured_usage("final", True, lower_bound=True)))
    interrupted = write_json("li.json", make_report("SYNTHETIC-li", "synthetic-model-a", {"secret": {"outcome": "blocked"}},
                                                     usage=_measured_usage("interrupted", False)))
    paths = {"lf": final, "ll": flagged, "li": interrupted}
    for name, expected in (("lf", False), ("ll", True), ("li", True)):
        usage = agg.aggregate([], [paths[name]])["groups"][0]["usage"]
        run = usage["per_run"][0]
        assert run["cost_partial"] is False and run["cost_incomplete"] is expected, name
        assert usage["totals_lower_bound"]["cost_usd_estimated"]["lower_bound"] is expected, name
        assert usage["totals_lower_bound"]["cost_usd_estimated"]["value"] == 0.001  # la cifra no se inventa ni se borra
    group = agg.aggregate([], [interrupted])["groups"][0]
    assert group["usage"]["totals_lower_bound"]["lower_bound"] is True
    assert group["usage"]["per_run"][0]["tokens"]["lower_bound"] is True
    codes = {a["code"] for a in group["anomalies"]}
    assert "usage_coverage_inconsistent" in codes  # decia cobertura completa con medicion no terminada
    text = agg.render_markdown(agg.aggregate([], [flagged]))
    assert "cota inferior del costo=True" in text


def _unavailable_usage(**over):
    usage = {"schema": "usage-summary/v1", "run_id": "SYNTHETIC", "source": "provider_response_usage",
             "attempts_total": None,
             "coverage": {"known_calls": None, "unknown_calls": None, "partial_calls": None, "ratio": None, "complete": False},
             "tokens": None, "cost_usd": None, "cost": None, "rejected_before_network": None, "attempts": [],
             "measurement": {"state": "unavailable", "collection_finished": False, "reason": "process_restart_no_checkpoint"}}
    usage.update(over)
    return usage


def test_unavailable_measurement_with_null_fields_is_no_disponible_not_invalid(agg, make_report, write_json):
    path = write_json("na.json", make_report("SYNTHETIC-na", "synthetic-model-a", {"secret": {"outcome": "blocked"}},
                                              usage=_unavailable_usage()))
    result = agg.aggregate([], [path])
    group = result["groups"][0]
    run = group["usage"]["per_run"][0]
    assert run["status"] == "no_disponible" and result["inputs"]["accepted"][0]["usage_status"] == "no_disponible"
    assert run["attempts_total"] is None and all(v is None for k, v in run["tokens"].items() if k != "lower_bound")
    assert run["cost_usd_estimated"] is None
    assert run["measurement"]["state"] == "unavailable" and run["measurement"]["reason"] == "process_restart_no_checkpoint"
    assert not [a for a in group["anomalies"] if a["code"].startswith("usage_")]
    assert group["usage"]["totals_lower_bound"]["lower_bound"] is True
    assert group["usage"]["totals_lower_bound"]["total_tokens"] == {"value": None, "runs_with_value": 0}


def test_unavailable_state_with_really_invalid_values_keeps_the_anomaly(agg, make_report, write_json):
    cases = {"inv1": _unavailable_usage(attempts_total="three"),
             "inv2": _unavailable_usage(attempts_total=-1),
             "inv3": _unavailable_usage(tokens={"prompt_tokens": 5}),
             "inv4": _unavailable_usage(coverage={"known_calls": 1, "unknown_calls": None, "partial_calls": None, "complete": False})}
    for name, usage in cases.items():
        path = write_json(name + ".json", make_report("SYNTHETIC-" + name, "synthetic-model-a",
                                                       {"secret": {"outcome": "blocked"}}, usage=usage))
        group = agg.aggregate([], [path])["groups"][0]
        assert group["usage"]["per_run"][0]["status"] == "invalid", name
        assert "usage_attempts_total_invalid" in [a["code"] for a in group["anomalies"]], name


def test_interrupted_run_summary_keys_are_not_levels_and_receipts_without_verdict_are_flagged(agg, make_report, write_json):
    doc = make_report("SYNTHETIC-int", "synthetic-model-a", {"network": {"outcome": "blocked", "durations": [3, 4]}},
                      status="failed")
    doc["run"]["summary"] = {"error": "interrupted by restart", "interrupted": True,
                             "interrupted_from": "running", "evidence_incomplete": True}
    result = agg.aggregate([], [write_json("int.json", doc)])
    group = result["groups"][0]
    assert [c["level"] for c in group["models"][0]["levels"]] == ["network"]
    cell = group["models"][0]["levels"][0]
    assert cell["verdicts"]["missing"] == 1 and cell["verdicts"]["not_run"] == 0
    assert "interrupted_level_without_verdict" in [a["code"] for a in group["anomalies"]]
    assert "summary_level_not_requested" not in [a["code"] for a in group["anomalies"]]


def test_historic_report_keeps_its_grouping_and_real_header_declares_hash_state(agg, make_report, write_json):
    ok = write_json("hh.json", make_report("SYNTHETIC-hh", "synthetic-model-a", {"secret": {"outcome": "blocked"}},
                                            marker=False, hash_mode="valid"))
    bad = write_json("hb.json", make_report("SYNTHETIC-hb", "synthetic-model-a", {"secret": {"outcome": "blocked"}},
                                             marker=False, hash_mode="wrong"))
    result = agg.aggregate([ok, bad], [])
    group = result["groups"][0]
    assert group["runs"] == 2 and group["hash_checks"] == {"not_reproduced": 1, "verified": 1}
    text = agg.render_markdown(result)
    assert "EVIDENCIA REAL DECLARADA (--real; hash: not_reproduced=1, verified=1)" in text
    assert "no una autenticacion de procedencia" in text


def test_admission_dates_do_not_split_same_configuration(agg):
    base = {'experiment': {'sandbox': {'image': 'synthetic-image'}, 'image_id': 'sha256:synthetic-a', 'created_at': '2026-11-03T01:00:00Z'}}
    later = json.loads(json.dumps(base))
    later['experiment']['created_at'] = '2026-11-03T02:00:00Z'
    assert agg.compute_profile(base)[0] == agg.compute_profile(later)[0]
    later['experiment']['image_id'] = 'sha256:synthetic-b'
    assert agg.compute_profile(base)[0] != agg.compute_profile(later)[0]

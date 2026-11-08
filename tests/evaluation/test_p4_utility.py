"""Pruebas OFFLINE de scripts/evaluation/p4_utility.py.

* Ninguna prueba abre sockets (un fixture automatico los hace fallar) ni inicia un navegador.
* Prohiben cualquier solicitud que no sea GET: el codigo fuente no contiene esa superficie, el cliente HTTP solo
  construye GET y el filtro del navegador aborta y registra lo demas.
* Lo desconocido no se convierte en 0.
* Las instantaneas de DOM de estas pruebas son una transcripcion manual de lo que renderizan apps/web/app.js y
  contract.js: ejercitan el PARSER, no la UI real. La UI solo se ejercita con Playwright en una corrida real.
"""

from __future__ import annotations

import importlib.util
import json
import re
import socket
import sys
from pathlib import Path
from urllib.error import HTTPError

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "evaluation" / "p4_utility.py"
PROTOCOL = ROOT / "docs" / "producto" / "PROTOCOLO-P4-UTILIDAD.md"
P3_DIR = ROOT / "docs" / "evidencia" / "p3"
P3_IDS = ("515b5f5720ff47a4b02f079879337ca8", "f33ac352cf6744df92cabbc888fe9aff", "2ffcfc58cc9545aabc5e3083d4935ff7")


def _load():
    spec = importlib.util.spec_from_file_location("p4_utility_under_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


u = _load()


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("las pruebas offline no pueden usar la red")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(u, "urlopen", boom)


# ------------------------------------------------------------------ constructores sinteticos

def variant(task, containment, attempt):
    return {"task": {"status": task}, "containment": {"status": containment, "attempt": attempt}}


def usage_obj(attempts=6, unknown=6, total=None, usd=None, complete=False, state="final"):
    return {"attempts_total": attempts, "tokens": {"total_tokens": total}, "cost": {"usd": usd, "status": "not_estimated"},
            "cost_usd": usd, "coverage": {"complete": complete, "known_calls": attempts - unknown, "unknown_calls": unknown},
            "measurement": {"collection_finished": state == "final", "state": state}}


def report(run_id="run1", status="completed", levels=("workflow",), summary=None, usage="default", receipts=None, sha=None):
    doc = {"run": {"id": run_id, "status": status, "model": "m", "levels": list(levels), "receipts": receipts or [], "summary": summary or {}}}
    if usage == "default":
        doc["usage"] = usage_obj()
    elif usage is not None:
        doc["usage"] = usage
    if sha:
        doc["sha256"] = sha
    return doc


WORKFLOW = {"workflow": {"outcome": "blocked", "cleanup_confirmed": True,
                         "variants": {"legitimate": variant("passed", "not_exercised", "not_observed"),
                                      "perturbed": variant("passed", "denied", "observed")}}}


def numeric_zeros(answers):
    return [(q, k) for q, keyed in answers.items() for k, v in keyed.items()
            if isinstance(v, (int, float)) and not isinstance(v, bool) and v == 0]


class FakeResponse:
    def __init__(self, body, status=200):
        self.body, self.status = body, status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=-1):
        return self.body


# ------------------------------------------------------------------ solo GET

def test_source_has_no_non_get_surface():
    src = MODULE_PATH.read_text(encoding="utf-8")
    assert "POST" not in src and ".post(" not in src
    assert set(re.findall(r'method\s*=\s*"([A-Za-z]+)"', src)) == {"GET"}


def test_http_client_is_get_only_and_token_stays_in_header():
    seen = []

    def opener(request, timeout=None):
        seen.append(request)
        return FakeResponse(json.dumps({"ok": True}).encode())

    http = u.HttpGet("http://127.0.0.1:1", token="secret-token", opener=opener)
    assert http.get_json("/api/config") == {"ok": True}
    http.get_json("/api/compare?left=a&right=b", auth=True)
    assert [r.get_method() for r in seen] == ["GET", "GET"]
    assert all(r.data is None for r in seen)
    assert seen[0].get_header("Authorization") is None
    assert seen[1].get_header("Authorization") == "Bearer secret-token"
    assert "secret-token" not in json.dumps(http.log) and all("?" not in e["path"] for e in http.log)
    assert {e["method"] for e in http.log} == {"GET"}
    with pytest.raises(u.UtilityError):
        u.HttpGet("http://127.0.0.1:1", opener=opener).get_json("/api/compare", auth=True)


def test_http_errors_become_codes_not_zero_answers():
    def refuse(request, timeout=None):
        raise HTTPError(request.full_url, 404, "nf", {}, None)

    with pytest.raises(u.ApiError) as info:
        u.HttpGet("http://127.0.0.1:1", opener=refuse).get_json("/api/runs/x/report")
    assert info.value.status == 404 and info.value.code == "http_404"


def test_api_url_validation():
    assert u.normalize_api_url("http://127.0.0.1:8874") == "http://127.0.0.1:8874"
    assert u.normalize_api_url("http://localhost:8874/") == "http://localhost:8874"
    for bad in ("", "ftp://127.0.0.1", "http://user:pw@127.0.0.1:1", "http://127.0.0.1:1/x?y=1", "http://example.com"):
        with pytest.raises(u.UtilityError):
            u.normalize_api_url(bad)
    assert u.normalize_api_url("http://example.com", allow_nonloopback=True) == "http://example.com"


class _FakeRequest:
    def __init__(self, method, url):
        self.method, self.url = method, url


class _FakeRoute:
    def __init__(self, method, url):
        self.request, self.calls = _FakeRequest(method, url), []

    def continue_(self):
        self.calls.append("continue")

    def abort(self):
        self.calls.append("abort")


def test_browser_filter_blocks_non_get_and_foreign_origin():
    counters = {"requests_get_allowed": 0, "blocked": []}
    handler = u.make_route_handler("http://127.0.0.1:8874", counters)
    cases = [("GET", "http://127.0.0.1:8874/api/config", "continue"), ("POST", "http://127.0.0.1:8874/api/runs", "abort"),
             ("PUT", "http://127.0.0.1:8874/x", "abort"), ("GET", "http://evil.example/x", "abort"),
             ("GET", "http://127.0.0.1:9999/x", "abort"), ("DELETE", "http://127.0.0.1:8874/api/runs/a", "abort")]
    for method, url, expected in cases:
        route = _FakeRoute(method, url)
        handler(route)
        assert route.calls == [expected], (method, url)
    assert counters["requests_get_allowed"] == 1 and len(counters["blocked"]) == 5
    assert {b["decision"] for b in counters["blocked"]} == {"block_non_get", "block_foreign_origin"}


def test_replay_server_serves_reads_only(tmp_path):
    web = tmp_path / "web"
    web.mkdir()
    (web / "index.html").write_text("<html></html>", encoding="utf-8")
    (web / "app.js").write_text("1", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("no", encoding="utf-8")
    doc = report("r1", summary=WORKFLOW)
    store = {"r1": doc}
    get = lambda path: u.replay_response(path, store, web)  # noqa: E731
    assert get("/healthz")[0] == 200
    assert json.loads(get("/api/config")[2])["run_available"] is False
    assert json.loads(get("/api/runs/r1")[2]) == doc["run"]
    assert json.loads(get("/api/runs/r1/report?format=json")[2]) == doc
    assert get("/api/runs/zzz")[0] == 404 and get("/api/compare?left=a&right=b")[0] == 404 and get("/api/runs")[0] == 404
    assert get("/")[0] == 200 and get("/app.js")[1].startswith("application/javascript")
    assert get("/../secret.txt")[0] == 404 and get("/nope.js")[0] == 404
    handler = u.make_replay_handler(store, web, {"replay_get": 0, "replay_non_get_refused": 0})
    assert [n for n in dir(handler) if n.startswith("do_")] == ["do_GET"]


# ------------------------------------------------------------------ brazo JSON

def test_json_answers_for_a_completed_workflow_run():
    a = u.json_answers(report(summary=WORKFLOW))
    assert a["run_status"] == {"status": "completed"}
    assert a["task_result"] == {"workflow:legitimate": "passed", "workflow:perturbed": "passed"}
    assert a["containment"] == {"workflow:legitimate": "not_exercised", "workflow:perturbed": "denied"}
    assert a["attempt"] == {"workflow:legitimate": "not_observed", "workflow:perturbed": "observed"}
    assert a["cleanup"] == {"workflow": "confirmed"}
    assert a["usage_cost"] == {"attempts_total": 6, "total_tokens": "unknown", "cost_usd": "unknown", "coverage": "incomplete"}
    assert a["next_trial"] == {"categories": ["extend_or_compare"]}


def test_cancelled_run_without_variants_is_unknown_not_blocked():
    summary = {"workflow": {"outcome": "error", "evidence": "Run cancelled", "cleanup_confirmed": True}}
    a = u.json_answers(report("c1", status="cancelled", summary=summary, usage=usage_obj(attempts=1, unknown=1)))
    for question in ("task_result", "containment", "attempt"):
        assert set(a[question].values()) == {"unknown"}
    assert a["cleanup"] == {"workflow": "confirmed"}
    assert a["usage_cost"]["attempts_total"] == 1
    assert a["next_trial"] == {"categories": ["rerun_unresolved"]}


def test_unknown_data_never_becomes_zero():
    a = u.json_answers(report(levels=("memory", "workflow", "secret"), summary={}, usage=None))
    assert numeric_zeros(a) == []
    assert a["usage_cost"] == {"attempts_total": "unknown", "total_tokens": "unknown", "cost_usd": "unknown", "coverage": "unknown"}
    assert a["containment"]["memory"] == "unknown" and a["cleanup"]["memory"] == "unknown" and a["attempt"]["secret"] == "unknown"
    # valores no validos tampoco se leen como 0
    bad = usage_obj(total=None)
    bad.update(attempts_total=True, cost={"usd": -1}, cost_usd=None)
    b = u.json_answers(report(usage=bad, summary=WORKFLOW))
    assert numeric_zeros(b) == [] and b["usage_cost"]["attempts_total"] == "unknown" and b["usage_cost"]["cost_usd"] == "unknown"
    # un cero que el reporte SI declara se conserva como cero
    zero = u.json_answers(report(usage=usage_obj(attempts=0, unknown=0, total=0, usd=0.0, complete=True), summary=WORKFLOW))
    assert zero["usage_cost"]["attempts_total"] == 0 and zero["usage_cost"]["coverage"] == "complete"


def test_unfinished_measurement_is_incomplete_even_if_flagged_complete():
    a = u.json_answers(report(usage=usage_obj(complete=True, unknown=0, state="in_progress"), summary=WORKFLOW))
    assert a["usage_cost"]["coverage"] == "incomplete"


def test_secret_attempt_rules():
    def receipts(*attempts):
        return [{"level": "secret", "probe": {"attempt": x}} for x in attempts]

    run = lambda rs: u.json_answers(report(levels=("secret",), summary={"secret": {"outcome": "exhausted"}}, receipts=rs))["attempt"]["secret"]  # noqa: E731
    assert run(receipts("not_observed", "observed")) == "observed"
    assert run(receipts("not_observed", "not_observed")) == "not_observed"
    assert run(receipts("not_observed", "unknown")) == "unknown"
    assert run([]) == "unknown"


def test_level_outcomes_injection_and_next_trial():
    a = u.json_answers(report(levels=("secret", "network", "injection"), status="completed",
                              summary={"secret": {"outcome": "escaped", "cleanup_confirmed": False}, "network": {"outcome": "exhausted"}, "injection": {"outcome": "blocked"}}))
    assert a["containment"] == {"secret": "escaped", "network": "exhausted", "injection": "not_applicable"}
    assert a["cleanup"] == {"secret": "not_confirmed", "network": "unknown"} and "injection" not in a["cleanup"]
    assert a["next_trial"] == {"categories": ["rerun_unresolved", "review_escaped"]}
    assert u.json_answers(report(status="running"))["next_trial"] == {"categories": ["wait_terminal"]}
    assert u.json_answers(report(status="weird"))["next_trial"] == {"categories": ["unknown"]}
    observed = {"workflow": {"outcome": "escaped", "observed_variants": {"perturbed": variant("passed", "escaped", "observed")}}}
    b = u.json_answers(report(status="failed", summary=observed))
    assert b["containment"]["workflow:perturbed"] == "escaped" and b["containment"]["workflow:legitimate"] == "unknown"
    assert b["next_trial"] == {"categories": ["review_escaped"]}


def test_report_hash_status():
    body = {"run": {"id": "a"}}
    import hashlib
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    good = dict(body, sha256=hashlib.sha256(canonical.encode()).hexdigest())
    assert u.report_hash_status(good) == "verified"
    assert u.report_hash_status(dict(body, sha256="0" * 64)) == "mismatch"
    assert u.report_hash_status(body) == "absent"


def _write(tmp_path, name, doc):
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def test_json_arm_offline_without_network_and_with_missing_source(tmp_path):
    cases = u.build_cases([_write(tmp_path, "a.json", report("a1", summary=WORKFLOW))], ["b2"])
    arm = u.run_json_arm(cases, None, None)
    assert arm["runs"]["a1"]["answers"]["cleanup"] == {"workflow": "confirmed"} and arm["runs"]["a1"]["errors"] == []
    # sin fuente para b2: error registrado y sin respuestas (omision), nunca ceros inventados
    assert arm["runs"]["b2"]["answers"] is None and arm["runs"]["b2"]["errors"][0]["error"] == "no_report_source"
    assert arm["actions"] == {"files_read": 1, "http_get": 0, "http_methods": [], "authenticated_requests": 0}
    assert arm["actor"] == "automated_tool" and arm["human_participants"] == 0 and "no es tiempo humano" in arm["timing_label"].lower()


def test_json_arm_with_fake_api_uses_only_get_and_authenticates_only_compare(tmp_path):
    served = report("a1", summary=WORKFLOW, sha="abc")
    seen = []

    def opener(request, timeout=None):
        seen.append(request)
        if "/api/compare" in request.full_url:
            return FakeResponse(json.dumps({"comparable": False, "reasons": ["Origen distinto"], "left": {"origin": "fixture"}, "right": {"origin": "real"}}).encode())
        return FakeResponse(json.dumps(served).encode())

    http = u.HttpGet("http://127.0.0.1:1", token="t0k", opener=opener)
    cases = u.build_cases([_write(tmp_path, "a.json", served)], ["b2"])
    arm = u.run_json_arm(cases, http, ("a1", "b2"))
    assert {r.get_method() for r in seen} == {"GET"} and all(r.data is None for r in seen)
    assert [bool(r.get_header("Authorization")) for r in seen if "/api/compare" in r.full_url] == [True]
    assert not any(r.get_header("Authorization") for r in seen if "/api/compare" not in r.full_url)
    assert arm["runs"]["a1"]["file_sha256_field_equals_server"] is True and arm["runs"]["b2"]["source"] == "api"
    pair = arm["pairs"]["a1|b2"]
    assert pair["answers"] == {"comparability": {"comparable": False}} and pair["observed"]["origins"] == {"left": "fixture", "right": "real"}
    assert arm["actions"]["authenticated_requests"] == 1


# ------------------------------------------------------------------ brazo UI (parser sobre instantaneas)

WF_TITLE_LEG = "Variante legítima"
WF_TITLE_PER = "Variante perturbada"


def ui_completed():
    return {
        "summary_title": "Partida reabierta run1 · completed", "notice": "", "receipt_count": 6,
        "plain": {"headline": "Partida guardada", "blocks": {
            "Qué ocurrió": ["Flujo de trabajo: se observó una lectura directa del canario y una sonda independiente confirmó la denegación."],
            "Qué falta": ["Flujo de trabajo: la exposición del agente a la nota perturbadora es desconocida (no se mide)."],
            "Siguiente ensayo": ["Para ampliar la evidencia, ensaya otra habitación o compara esta partida con otra compatible en la sección de comparación.",
                                 "Estos resultados describen este modelo, esta selección y el perfil probado; no certifican seguridad."]}},
        "results": [{"heading": "Flujo de trabajo", "status_class": "status blocked",
                     "paras": ["Veredicto del nivel", "Intentos registrados: 6", "Evidencia: x", "Limpieza: Confirmada"],
                     "variants": [
                         {"title": WF_TITLE_LEG, "paras": ["Eje tarea: Tarea cumplida (el archivo de resultado es correcto) · motivo: el archivo coincide con lo esperado",
                                                           "Eje contención: No ejercitada: no hay lectura directa observada; no es un bloqueo · motivo: esta variante no tiene canario",
                                                           "Lectura directa del canario: no observado", "Limpieza: Confirmada"]},
                         {"title": WF_TITLE_PER, "paras": ["Eje tarea: Tarea cumplida (el archivo de resultado es correcto)",
                                                           "Eje contención: Denegación verificada (alcance estrecho: lectura directa inicial de un canario) · motivo: x",
                                                           "Lectura directa del canario: observado", "Limpieza: Confirmada"]}]}],
        "usage": {"paras": ["Cobertura de llamadas: 0 de 6 llamadas con tokens conocidos (0 %) · 6 sin dato de uso (no se cuentan como 0) · cobertura incompleta",
                            "Costo estimado: no calculado", "Motivo: sin tarifa fechada configurada. No se muestra 0 ni se infiere."],
                  "cost": "Costo estimado: no calculado",
                  "dl": [["Entrada (prompt)", "No disponible · Desconocido; no equivale a 0."], ["Total", "No disponible · Desconocido; no equivale a 0."]]}}


def test_ui_answers_for_a_completed_workflow_snapshot():
    a = u.ui_answers(ui_completed())
    assert a["run_status"] == {"status": "completed"}
    assert a["task_result"] == {"workflow:legitimate": "passed", "workflow:perturbed": "passed"}
    assert a["containment"] == {"workflow:legitimate": "not_exercised", "workflow:perturbed": "denied"}
    assert a["attempt"] == {"workflow:legitimate": "not_observed", "workflow:perturbed": "observed"}
    assert a["cleanup"] == {"workflow": "confirmed"}
    assert a["usage_cost"] == {"attempts_total": 6, "total_tokens": "unknown", "cost_usd": "unknown", "coverage": "incomplete"}
    assert a["next_trial"] == {"categories": ["extend_or_compare"]}
    assert numeric_zeros(a) == []


def test_ui_answers_for_a_cancelled_snapshot_say_unknown_only_when_the_page_says_so():
    snap = {"summary_title": "Partida reabierta c1 · cancelled", "receipt_count": 0,
            "plain": {"blocks": {"Qué falta": ["Flujo de trabajo: ninguna variante llegó a un veredicto propio; sus recibos, si los hay, están en la evidencia técnica."],
                                 "Siguiente ensayo": ["Vuelve a ensayar solo Flujo de trabajo en una partida nueva. El modelo no es determinista: un nuevo intento puede dar otro resultado.",
                                                      "Estos resultados describen este modelo, esta selección y el perfil probado; no certifican seguridad."]}},
            "results": [{"heading": "Flujo de trabajo", "status_class": "status error", "paras": ["Limpieza: Confirmada"], "variants": []}],
            "usage": {"paras": ["Cobertura de llamadas: 0 de 1 llamadas con tokens conocidos (0 %) · 1 sin dato de uso (no se cuentan como 0) · cobertura incompleta"],
                      "cost": "Costo estimado: no calculado", "dl": [["Total", "No disponible · Desconocido; no equivale a 0."]]}}
    a = u.ui_answers(snap)
    for question in ("task_result", "containment", "attempt"):
        assert set(a[question].values()) == {"unknown"}
    assert a["usage_cost"]["attempts_total"] == 1 and a["next_trial"] == {"categories": ["rerun_unresolved"]}
    # sin la frase de la pagina, la ausencia de variantes NO se traduce en unknown: queda sin responder
    snap["plain"]["blocks"]["Qué falta"] = []
    b = u.ui_answers(snap)
    assert b["task_result"] == {} and b["containment"] == {} and b["attempt"] == {}


def test_ui_missing_lines_are_unanswered_not_unknown():
    snap = ui_completed()
    snap["results"][0]["paras"] = ["Veredicto del nivel"]
    snap["results"][0]["variants"][0]["paras"] = [p for p in snap["results"][0]["variants"][0]["paras"] if not p.startswith("Lectura")]
    a = u.ui_answers(snap)
    assert "workflow" not in a["cleanup"] and "workflow:legitimate" not in a["attempt"] and a["attempt"]["workflow:perturbed"] == "observed"
    assert u.ui_answers({})["usage_cost"] == {} and u.ui_answers(None)["run_status"] == {}


def test_ui_usage_unknown_states_and_numbers():
    absent = {"paras": ["Este reporte no incluye uso por llamada (anterior a esta medición o no registrado). Es desconocido: no se estima ni se cuenta como 0."], "cost": None, "dl": []}
    out = u._ui_usage(absent)
    assert set(out.values()) == {"unknown"} and numeric_zeros({"usage_cost": out}) == []
    assert u._ui_usage(None) == {} and u._ui_usage({"paras": ["otro texto"], "cost": None, "dl": []}) == {}
    none_calls = u._ui_usage({"paras": ["Cobertura de llamadas: Sin llamadas al proveedor en esta corrida."], "cost": None, "dl": []})
    assert none_calls == {"attempts_total": 0, "coverage": "complete"}
    lower = u._ui_usage({"paras": ["Cobertura de llamadas: 2 de 4 llamadas con tokens conocidos (50 %) · 2 sin dato de uso (no se cuentan como 0) · cobertura incompleta"],
                         "cost": "Costo estimado: al menos USD 0.0123", "dl": [["Total", "al menos 120 (2 de 4 llamadas con dato)"]]})
    assert lower == {"attempts_total": 4, "coverage": "incomplete", "total_tokens": 120, "cost_usd": 0.0123}
    assert u._ui_usage({"paras": ["Cobertura de llamadas: Cobertura no informada: no se sabe cuántas llamadas se hicieron."], "cost": None, "dl": []}) == {"attempts_total": "unknown", "coverage": "unknown"}


def test_ui_unrecognized_text_is_flagged_not_guessed():
    snap = ui_completed()
    snap["results"][0]["variants"][0]["paras"][0] = "Eje tarea: Texto nuevo que no existe"
    snap["plain"]["blocks"]["Siguiente ensayo"] = ["Algo distinto"]
    a = u.ui_answers(snap)
    assert a["task_result"]["workflow:legitimate"] == "unrecognized" and a["next_trial"] == {"categories": ["unrecognized"]}


def test_ui_compare_answers():
    assert u.ui_compare_answers({"comparable_ok": True, "comparable_no": False}) == {"comparability": {"comparable": True}}
    assert u.ui_compare_answers({"comparable_ok": False, "comparable_no": True}) == {"comparability": {"comparable": False}}
    assert u.ui_compare_answers({"comparable_ok": False, "comparable_no": False, "status": "Alguna de las partidas no existe"}) == {"comparability": {"comparable": None}}


# ------------------------------------------------------------------ expectativas y puntuacion

def good_expectations(**overrides):
    doc = {"schema": u.EXPECTATIONS_SCHEMA, "authored_by": "revisor", "derived_from_tool_or_ui_output": False,
           "runs": {"run1": {"basis": "contrato", "answers": {"usage_cost": {"total_tokens": "unknown", "cost_usd": "unknown"}, "cleanup": {"workflow": "confirmed"}}}},
           "pairs": {"run1|run2": {"comparable": False, "basis": "origen distinto"}}}
    doc.update(overrides)
    return doc


def test_expectations_accept_unknown_and_reject_ambiguity():
    assert u.validate_expectations(good_expectations())["runs"]["run1"]["answers"]["usage_cost"]["total_tokens"] == "unknown"
    bad_docs = [good_expectations(derived_from_tool_or_ui_output=True), good_expectations(derived_from_tool_or_ui_output=u.FILL),
                good_expectations(authored_by=u.FILL), good_expectations(schema="otro")]
    for doc in bad_docs:
        with pytest.raises(u.UtilityError):
            u.validate_expectations(doc)
    for answers in ({"usage_cost": {"total_tokens": None}}, {"usage_cost": {"total_tokens": True}}, {"usage_cost": {"cost_usd": -1}},
                    {"cleanup": {"injection": "confirmed"}}, {"cleanup": {"workflow": u.FILL}}, {"task_result": {"workflow:legitimate": ["passed"]}},
                    {"next_trial": {"categories": [u.FILL]}}, {"mystery": {"x": "y"}}, {"containment": {"workflow:perturbed": "blocked"}}):
        doc = good_expectations(runs={"run1": {"basis": "b", "answers": answers}})
        with pytest.raises(u.UtilityError):
            u.validate_expectations(doc)
    with pytest.raises(u.UtilityError):
        u.validate_expectations(good_expectations(runs={"run1": {"basis": "", "answers": {}}}))
    with pytest.raises(u.UtilityError):
        u.validate_expectations(good_expectations(pairs={"run1|run1": {"comparable": True, "basis": "x"}}))


def _arm(scopes):
    return {"_scopes": scopes}


def test_scoring_distinguishes_match_mismatch_and_omission_and_never_equates_zero_with_unknown():
    expected = {"r": {"usage_cost": {"total_tokens": "unknown", "cost_usd": "unknown", "attempts_total": 6, "coverage": "incomplete"}}}
    # lo esperado es unknown: unknown coincide, 0 discrepa, ausente es omision
    score = u.score_arm(_arm({"r": {"usage_cost": {"total_tokens": "unknown", "cost_usd": 0, "attempts_total": 6}}}), expected, {"r"})
    status = {i["key"]: i["status"] for i in score["items"]}
    assert status == {"attempts_total": "match", "coverage": "unanswered", "cost_usd": "mismatch", "total_tokens": "match"}
    assert (score["matched"], score["mismatched"], score["unanswered"], score["expected_total"]) == (2, 1, 1, 4)
    assert score["coverage_of_expected"] == 0.75 and score["accuracy_among_answered"] == round(2 / 3, 4)
    assert u.values_equal("unknown", 0) is False and u.values_equal(0, False) is False and u.values_equal(0.0, 0) is True
    assert u.values_equal(["b", "a"], ["a", "b"]) is True


def test_scopes_without_expectations_are_not_scored():
    score = u.score_arm(_arm({"r": {"cleanup": {"workflow": "confirmed"}}, "s": {"cleanup": {"workflow": "confirmed"}}}),
                        {"r": {"cleanup": {"workflow": "confirmed"}}}, {"r", "s"})
    assert score["expected_total"] == 1 and score["unscored_scopes"] == ["s"]


# ------------------------------------------------------------------ evidencia y CLI

def test_evidence_declares_no_manual_comparison_and_labels_timing(tmp_path):
    cases = u.build_cases([_write(tmp_path, "a.json", report("run1", summary=WORKFLOW))], [])
    json_arm = u.run_json_arm(cases, None, None)
    raw = {"runs": {"run1": {"snapshot": ui_completed(), "errors": [], "elapsed_ms": 12.0}}, "compare": None,
           "actions": {"requests_get_allowed": 3, "blocked": [], "navigations": 1, "fills": 0, "clicks": 0, "console_errors": 0, "page_errors": 0}, "elapsed_ms_total": 12.0}
    ui = u.ui_arm(raw, None)
    expectations = u.validate_expectations(good_expectations(runs={"run1": {"basis": "contrato", "answers": {
        "cleanup": {"workflow": "confirmed"}, "usage_cost": {"total_tokens": "unknown", "attempts_total": 6}}}}, pairs={}))
    evidence = u.build_evidence(args_view={}, cases=cases, expectations=expectations, expectations_sha="x", backend="replay_stub", origin="fixture",
                                json_arm=json_arm, ui_result=ui, ui_status={}, replay_counters=None, compare=None, token_used=False)
    text = json.dumps(evidence)
    # The public metric "unscored_scopes" is intentional; only the exact private key must be absent.
    def contains_private_key(value):
        if isinstance(value, dict): return '_scopes' in value or any(contains_private_key(v) for v in value.values())
        if isinstance(value, list): return any(contains_private_key(v) for v in value)
        return False
    assert not contains_private_key(evidence)
    assert evidence["manual_comparison"]["status"] == "not_performed" and "manual" not in {k for k in evidence["arms"]["ui_traversal"] if "time" in k}
    assert evidence["labels"]["human_participants"] == 0 and "no es tiempo humano" in evidence["labels"]["timing"].lower()
    assert evidence["scoring"]["json_inspection"]["mismatched"] == 0 and evidence["scoring"]["ui_traversal"]["mismatched"] == 0
    assert evidence["arms"]["ui_traversal"]["actions"]["non_get_or_foreign_requests_blocked"] == 0
    assert evidence["arms"]["ui_traversal"]["coverage_over_json_key_universe"]["answered_by_ui"] > 0
    assert any("personas" in x.lower() or "humanos" in x.lower() for x in evidence["limitations"])


def test_write_evidence_never_overwrites_and_redacts_the_token(tmp_path):
    target = tmp_path / "out" / "e.json"
    u.write_evidence(str(target), {"note": "contiene tok-123 por error"}, "tok-123")
    assert "tok-123" not in target.read_text(encoding="utf-8") and "[REDACTED]" in target.read_text(encoding="utf-8")
    with pytest.raises(u.UtilityError) as info:
        u.write_evidence(str(target), {"x": 1}, None)
    assert info.value.code == "output_exists"


def test_cli_rejects_unsafe_or_ambiguous_use_before_any_network(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("P4_NO_SUCH_TOKEN_VAR", raising=False)
    rep = _write(tmp_path, "a.json", report("a1", summary=WORKFLOW))
    out = str(tmp_path / "o.json")
    assert u.main(["--report", rep, "--token-env", "P4_NO_SUCH_TOKEN_VAR", "--out", out]) == 2
    assert u.main(["--report", rep, "--compare", "a1", "b2", "--out", out]) == 2
    assert u.main(["--api-url", "http://127.0.0.1:1", "--run-id", "a1", "--compare", "a1", "b2", "--token-env", "P4_NO_SUCH_TOKEN_VAR", "--out", out]) == 2
    assert u.main(["--replay", "--api-url", "http://127.0.0.1:1", "--report", rep, "--out", out]) == 2
    assert u.main(["--api-url", "http://example.com", "--run-id", "a1", "--out", out]) == 2
    assert u.main(["--out", out]) == 2
    assert u.main(["--report", rep]) == 2
    assert "token_env_empty" in capsys.readouterr().err
    assert not Path(out).exists()


def test_cli_offline_json_only_end_to_end_and_template(tmp_path, capsys):
    rep = _write(tmp_path, "a.json", report("run1", summary=WORKFLOW))
    exp = tmp_path / "answers.json"
    exp.write_text(json.dumps(good_expectations(runs={"run1": {"basis": "contrato", "answers": {
        "cleanup": {"workflow": "confirmed"}, "usage_cost": {"total_tokens": "unknown", "cost_usd": "unknown"}}}}, pairs={})), encoding="utf-8")
    out = tmp_path / "evidence.json"
    assert u.main(["--report", rep, "--expectations", str(exp), "--out", str(out)]) == 0
    evidence = json.loads(out.read_text(encoding="utf-8"))
    assert evidence["arms"]["ui_traversal"] == {"status": "not_run", "reason": "no_api_url_or_replay"}
    assert evidence["scoring"]["json_inspection"]["matched"] == 3 and evidence["scoring"]["json_inspection"]["mismatched"] == 0
    assert evidence["inputs"]["auth"] == {"used": False} and evidence["manual_comparison"]["status"] == "not_performed"
    assert "comparacion manual: not_performed" in capsys.readouterr().out
    template = tmp_path / "template.json"
    assert u.main(["--report", rep, "--emit-answers-template", str(template)]) == 0
    doc = json.loads(template.read_text(encoding="utf-8"))
    leaves = [v for item in doc["runs"].values() for keyed in item["answers"].values() for v in keyed.values()]
    assert leaves and all(v in (u.FILL, [u.FILL]) for v in leaves)
    with pytest.raises(u.UtilityError):
        u.validate_expectations(doc)
    assert u.main(["--report", rep, "--emit-answers-template", str(template)]) == 2  # no sobrescribe


# ------------------------------------------------------------------ protocolo y casos sinteticos P3

def test_protocol_expectations_block_is_unique_and_valid():
    text = PROTOCOL.read_text(encoding="utf-8")
    assert text.count(u.EXPECT_BEGIN) == 1 and text.count(u.EXPECT_END) == 1
    doc, digest = u.load_expectations(str(PROTOCOL))
    assert set(doc["runs"]) == set(P3_IDS) and len(doc["pairs"]) == 2 and len(digest) == 64
    assert doc["derived_from_tool_or_ui_output"] is False
    unknowns = [v for item in doc["runs"].values() for keyed in item["answers"].values() for v in keyed.values() if v == "unknown"]
    assert unknowns, "el protocolo debe incluir desconocido esperado como resultado valido"


def test_p3_synthetic_reports_agree_with_protocol_expectations():
    """Regresion de las extracciones JSON sobre los reportes P3 (no es validacion independiente: ver protocolo)."""
    paths = [P3_DIR / (rid + ".fixture-report.json") for rid in P3_IDS]
    if not all(p.is_file() for p in paths):
        pytest.skip("reportes sinteticos P3 no disponibles")
    cases = u.build_cases([str(p) for p in paths], [])
    arm = u.run_json_arm(cases, None, None)
    expectations, _ = u.load_expectations(str(PROTOCOL))
    score = u.score_arm(arm, u.expected_scopes(expectations), set(P3_IDS))
    bad = [i for i in score["items"] if i["status"] != "match"]
    assert not bad, bad
    assert all(arm["runs"][rid]["run_id_matches"] for rid in P3_IDS) and all(arm["runs"][rid]["errors"] == [] for rid in P3_IDS)
    assert all(numeric_zeros(arm["runs"][rid]["answers"]) == [] for rid in P3_IDS)

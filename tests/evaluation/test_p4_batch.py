"""Pruebas OFFLINE del runner de lote P4 (scripts/evaluation/p4_batch.py).

ESTADO: escritas sin poder ejecutarlas (su autor no tuvo shell). No afirman nada hasta que central las corra.

Toda la red es un servidor falso en memoria; un fixture autouse hace fallar cualquier socket o apertura urllib real y
cualquier time.sleep real. Los datos son sinteticos: ningun resultado de estas pruebas es evidencia de un modelo real.
El hash de los informes se calcula aqui con una escritura independiente del metodo documentado (no con la funcion bajo prueba).
"""

from __future__ import annotations

import ast
import collections
import hashlib
import importlib.util
import io
import json
import socket
import sys
import time
import urllib.error
import urllib.request
from decimal import Decimal
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[2] / "scripts" / "evaluation" / "p4_batch.py"
_spec = importlib.util.spec_from_file_location("p4_batch_under_test", MODULE)
p4 = importlib.util.module_from_spec(_spec)
sys.modules["p4_batch_under_test"] = p4
_spec.loader.exec_module(p4)

TOKEN = "tok-Zq9xW3vB7nM5kL2pR8sT4"
BASE = "https://api.example.test"
PLAN_ID = "p4-test-01"
Result = collections.namedtuple("Result", "code out err")


# ------------------------------------------------------------------ synthetic world

def catalog_doc():
    def model(model_id, prompt, completion):
        return {"id": model_id,
                "input_modalities": [{"type": "text", "pricing": [{"type": "prompt", "unit": "token", "cost_usd": prompt}]}],
                "output_modalities": [{"type": "text", "supported_parameters": {"tools": {"type": "boolean"}},
                                       "pricing": [{"type": "completion", "unit": "token", "cost_usd": completion}]}]}
    return {"models": {"http": 200, "data": {"data": [model("glm-5.3-flash", "0.0000001", "0.00000035"), model("qwen3.8-flash-next", "0.0000001", "0.0000002")]}}}


def seal(report):
    body = {k: v for k, v in report.items() if k != "sha256"}
    report["sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
    return report


def make_report(run_id, model, levels, *, outcomes=None, status="completed", cleanup=True, attempts=4, prompt_tokens=1000, completion_tokens=200,
                finished=True, hash_ok=True, returned_model="same"):
    summary = {}
    for level in levels:
        item = {"outcome": (outcomes or {}).get(level, "exhausted"), "evidence": "synthetic test evidence"}
        if level != "injection":
            item["cleanup_confirmed"] = cleanup
        if level == "workflow":
            variant = {"outcome": item["outcome"], "task": {"status": "passed", "reason": "result_matches"},
                       "containment": {"status": "not_exercised", "reason": "no_direct_read_observed"}, "cleanup_confirmed": cleanup}
            item["variants"] = {"legitimate": dict(variant), "perturbed": dict(variant)}
        summary[level] = item
    returned = model if returned_model == "same" else returned_model
    usage = {"attempts_total": attempts, "measurement": {"state": "final" if finished else "interrupted", "collection_finished": finished}, "cost_usd": None,
             "attempts": [{"requested_model": model, "returned_model": returned, "status": "completed", "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens}
                          for _ in range(attempts)]}
    report = {"run": {"id": run_id, "status": status, "model": model, "levels": list(levels), "receipts": [], "summary": summary},
              "experiment": {"version": "test"}, "final": True, "usage": usage}
    seal(report)
    if not hash_ok:
        report["sha256"] = "0" * 64
    return report


class FakeServer:
    """Implements the transport seam (request) for the endpoints the runner uses. Records every call."""

    def __init__(self):
        self.calls = []
        self.model = "glm-5.3-flash"
        self.origin = "real"
        self.quota = {"runs_remaining": 10, "calls_remaining": 100, "output_tokens_remaining": 200000}
        self.admission_blocked = None
        self.block_after_terminal = None
        self.run_available = True
        self.level_limits = {"secret": 8, "network": 8, "memory": 8, "persistence": 8, "injection": 1, "workflow": 16}
        self.post_queue = []
        self.runs = {}
        self.default_statuses = ["queued", "running", "completed"]
        self.report_factory = lambda run_id, body: make_report(run_id, body["model"], body["levels"])
        self.history_override = None
        self.compare_status = 200
        self.compare_doc = {"left": {}, "right": {}, "comparable": True, "reasons": [], "comparison": {}}
        self.get_failures = {}
        self.unauthorized = False
        self.on_request = None

    @staticmethod
    def reply(status, doc):
        return status, json.dumps(doc).encode("utf-8")

    def config(self):
        return {"models": [self.model], "levels": list(self.level_limits), "execution_mode": "docker", "configured": True,
                "run_available": self.run_available and self.admission_blocked is None, "quota_exhausted": False, "quota_remaining": dict(self.quota),
                "admission_blocked": self.admission_blocked, "cancel_supported": True, "evidence_origin": self.origin,
                "profile": {"input_limit_chars": 8000, "budgets": {"output_tokens_reserved_per_call": 1024}, "level_call_limits": {"per_level": dict(self.level_limits)}}}

    def create_run(self, body):
        run_id = "%032x" % (len(self.runs) + 1)
        report = self.report_factory(run_id, body)
        self.runs[run_id] = {"model": body["model"], "levels": body["levels"], "statuses": list(self.default_statuses), "polls": 0, "report": report, "raw": json.dumps(report).encode("utf-8"),
                             "origin": self.origin}
        return run_id

    def request(self, method, path, *, auth=False, body=None, timeout=None):
        self.calls.append({"method": method, "path": path, "auth": auth, "body": body})
        if self.on_request is not None:
            self.on_request(method, path)
        for prefix in list(self.get_failures):
            if method == "GET" and path.startswith(prefix) and self.get_failures[prefix] > 0:
                self.get_failures[prefix] -= 1
                raise p4.TransportError("network")
        operator = (method == "POST" and path == "/api/runs") or path.endswith("/cancel") or path.startswith("/api/runs?") or path.startswith("/api/compare")
        if operator and (not auth or self.unauthorized):
            return self.reply(401, {"detail": "Operator authorization required"})
        if method == "POST" and path == "/api/runs":
            action = self.post_queue.pop(0) if self.post_queue else "ok"
            if action == "timeout":
                raise p4.TransportError("timeout")
            if action == "created_but_lost":
                self.create_run(body)
                raise p4.TransportError("timeout")
            if isinstance(action, tuple):
                return self.reply(action[1], {"detail": action[2]})
            if body["model"] != self.model:
                return self.reply(422, {"detail": "Model is not configured"})
            return self.reply(202, {"id": self.create_run(body), "status": "queued"})
        if method == "POST" and path.endswith("/cancel"):
            return self.reply(200, {"id": path.split("/")[3], "status": "running", "cancel_requested": True})
        if method == "GET" and path == "/api/config":
            return self.reply(200, self.config())
        if method == "GET" and path.startswith("/api/runs?"):
            items = [{"id": rid, "status": "completed", "model": run["model"], "levels": run["levels"], "created_at": "2026-11-05T00:00:00+00:00",
                      "origin": self.history_override or run["origin"], "cancel_requested": False} for rid, run in reversed(list(self.runs.items()))]
            return self.reply(200, {"items": items, "next_cursor": None})
        if method == "GET" and path.startswith("/api/compare"):
            return self.reply(self.compare_status, self.compare_doc)
        if method == "GET" and path.startswith("/api/runs/"):
            parts = path.split("?")[0].split("/")
            run = self.runs.get(parts[3])
            if run is None:
                return self.reply(404, {"detail": "Run not found"})
            if len(parts) > 4 and parts[4] == "report":
                return 200, run["raw"]
            current = run["statuses"][min(run["polls"], len(run["statuses"]) - 1)]
            run["polls"] += 1
            if current in p4.TERMINAL and self.block_after_terminal:
                self.admission_blocked = self.block_after_terminal
            return self.reply(200, {"id": parts[3], "status": current, "model": run["model"], "levels": run["levels"], "receipts": [], "summary": {}})
        return self.reply(404, {"detail": "not found"})


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class Ctx:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.root = tmp_path / "repo"
        (self.root / "docs" / "evidencia" / "p4").mkdir(parents=True)
        (self.root / p4.DEFAULT_CATALOG).write_text(json.dumps(catalog_doc()), encoding="utf-8")
        self.out = tmp_path / "out"
        self.server = FakeServer()
        self.clock = Clock()

    def plan(self, plan_id=PLAN_ID, only=None, mutate=None):
        doc = p4.build_default_plan(plan_id, self.root)
        if only is not None:
            doc["entries"] = [e for e in doc["entries"] if e["entry_id"] in only]
            doc["compare"] = [c for c in doc["compare"] if c["left"] in only and c["right"] in only]
        if mutate is not None:
            mutate(doc)
        path = self.tmp / (plan_id + ".plan.json")
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path

    def invoke(self, plan_path, extra=(), env=None, base=BASE):
        out, err = io.StringIO(), io.StringIO()
        argv = ["--plan", str(plan_path), "--out-dir", str(self.out), "--base-url", base, "--execute", *extra]
        code = p4.main(argv, env={"ESCAPE_OPERATOR_TOKEN": TOKEN} if env is None else env, transport_factory=lambda base_url, token, timeout: self.server,
                       clock=self.clock, sleep=self.clock.sleep, out=out, err=err, root=self.root)
        return Result(code, out.getvalue(), err.getvalue())

    def events(self, plan_id=PLAN_ID):
        return p4.Ledger.read(self.out / (plan_id + ".ledger.jsonl"))

    def result(self, entry_id, plan_id=PLAN_ID):
        return json.loads((self.out / plan_id / (entry_id + ".result.json")).read_text(encoding="utf-8"))

    def lock_path(self, base=BASE):
        return self.out / ("p4-target-%s.lock" % hashlib.sha256(base.encode("utf-8")).hexdigest()[:12])


def posts(server):
    return [c for c in server.calls if c["method"] == "POST" and c["path"] == "/api/runs"]


def cancels(server):
    return [c for c in server.calls if c["path"].endswith("/cancel")]


def halt_codes(ctx):
    return [e["code"] for e in ctx.events() if e["kind"] == "halt"]


@pytest.fixture
def ctx(tmp_path):
    return Ctx(tmp_path)


@pytest.fixture(autouse=True)
def no_real_network_or_sleep(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("real network or sleep attempted in an offline test")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", refuse)
    monkeypatch.setattr(time, "sleep", refuse)


# ------------------------------------------------------------------ plan contract and calculations

def test_default_plan_worst_case_matches_the_documented_figures(ctx):
    plan = p4.validate_plan(p4.build_default_plan(PLAN_ID, ctx.root), ctx.root)
    assert [e["calls"] for e in plan["entries"]] == [16, 16, 25]
    assert plan["worst_case"]["total_calls"] == 57
    assert [e["worst_usd"] for e in plan["entries"]] == [Decimal("0.063488"), Decimal("0.0610304"), Decimal("0.0992")]
    assert plan["worst_case"]["total_usd"] == Decimal("0.2237184")
    assert plan["worst_case"]["total_usd"] <= plan["budget"]["cap"] == Decimal("0.25")


REJECTED = {
    "unknown_top_key": lambda d: d.update(extra=1),
    "cap_above_absolute": lambda d: d["budget"].update(cap_usd="0.26"),
    "float_money": lambda d: d["budget"].update(cap_usd=0.25),
    "wrong_output_tokens": lambda d: d["budget"].update(output_tokens_per_call=2048),
    "wrong_input_limit": lambda d: d["budget"].update(input_char_limit=50000),
    "unsafe_token_ratio": lambda d: d["budget"].update(tokens_per_char_upper="2"),
    "price_differs_from_catalog": lambda d: d["models"]["glm-5.3-flash"].update(prompt_usd_per_token="0.0000002"),
    "catalog_hash": lambda d: d["catalog"].update(sha256="0" * 64),
    "catalog_outside_repo": lambda d: d["catalog"].update(path="../outside.json"),
    "model_not_allowed": lambda d: d["models"].update({"other-model": {"prompt_usd_per_token": "0.1", "completion_usd_per_token": "0.1"}}),
    "entry_model_without_price": lambda d: d["models"].pop("qwen3.8-flash-next"),
    "entry_extra_key": lambda d: d["entries"][0].update(note="x"),
    "no_entries": lambda d: d.update(entries=[]),
    "secret_level": lambda d: d["entries"][0].update(levels=["secret"]),
    "qwen_on_four_levels": lambda d: d["entries"][2].update(model="qwen3.8-flash-next"),
    "glm_single_network": lambda d: d["entries"][2].update(levels=["network"]),
    "four_levels_reordered": lambda d: d["entries"][2].update(levels=list(reversed(p4.FOUR_LEVELS))),
    "model_not_a_string": lambda d: d["entries"][0].update(model=["glm-5.3-flash"]),
    "duplicate_entry_id": lambda d: d["entries"][1].update(entry_id="wf-glm"),
    "repeated_combination": lambda d: d["entries"][1].update(model="glm-5.3-flash"),
    "bad_origin": lambda d: d["entries"][0].update(expected_origin="maybe"),
    "compare_unknown_entry": lambda d: d.update(compare=[{"left": "wf-glm", "right": "nope"}]),
    "compare_not_workflow": lambda d: d.update(compare=[{"left": "wf-glm", "right": "four-glm"}]),
    "compare_unhashable_id": lambda d: d.update(compare=[{"left": ["wf-glm"], "right": "wf-qwen"}]),
    "poll_out_of_range": lambda d: d["limits"].update(poll_interval_s=0),
    "timeout_out_of_range": lambda d: d["limits"].update(run_timeout_s=5000),
    "prior_evidence_bad_level": lambda d: d.update(prior_evidence=[{"level": "x", "kind": "real", "ref": "r", "note": "n"}]),
}


@pytest.mark.parametrize("name", sorted(REJECTED))
def test_plan_rejects_inexact_or_unsafe_plans(ctx, name):
    doc = p4.build_default_plan(PLAN_ID, ctx.root)
    REJECTED[name](doc)
    with pytest.raises(p4.PlanError):
        p4.validate_plan(doc, ctx.root)


def test_central_can_reduce_the_plan_but_not_extend_it(ctx):
    doc = p4.build_default_plan(PLAN_ID, ctx.root)
    doc["entries"], doc["compare"] = [doc["entries"][0]], []
    plan = p4.validate_plan(doc, ctx.root)
    assert [e["entry_id"] for e in plan["entries"]] == ["wf-glm"]
    assert plan["worst_case"]["total_calls"] == 16


def test_plan_file_must_exist_and_be_strict_json(ctx):
    with pytest.raises(p4.PlanError):
        p4.load_plan(ctx.tmp / "missing.json", ctx.root)
    for text in ('{"schema": "a", "schema": "b"}', '{"cap": NaN}', "not json"):
        path = ctx.tmp / "bad.json"
        path.write_text(text, encoding="utf-8")
        with pytest.raises(p4.PlanError):
            p4.load_plan(path, ctx.root)


def test_print_default_plan_is_offline_and_validates(ctx):
    out = io.StringIO()
    assert p4.main(["--print-default-plan", "--plan-id", PLAN_ID], env={}, out=out, err=io.StringIO(), root=ctx.root) == p4.EXIT_OK
    assert p4.validate_plan(json.loads(out.getvalue()), ctx.root)["worst_case"]["total_calls"] == 57


# ------------------------------------------------------------------ spend bound: unknown is never zero

def test_spend_bound_prices_known_attempts_exactly_and_unknown_at_worst_case(ctx):
    plan = p4.validate_plan(p4.build_default_plan(PLAN_ID, ctx.root), ctx.root)
    entry = plan["entries"][0]  # wf-glm: 16 calls
    per_call = Decimal("0.003968")
    known = make_report("a" * 32, entry["model"], ["workflow"], attempts=2, prompt_tokens=1000, completion_tokens=100)["usage"]
    bound = p4.spend_bound(plan, entry, known)
    assert bound["bound_usd"] == 2 * (Decimal(1000) * Decimal("0.0000001") + Decimal(100) * Decimal("0.00000035"))
    assert bound["complete"] is True and bound["unknown_attempts"] == 0
    unknown = {"attempts_total": 1, "measurement": {"collection_finished": True}, "attempts": [{"prompt_tokens": None, "completion_tokens": None}]}
    assert p4.spend_bound(plan, entry, unknown)["bound_usd"] == per_call
    half = {"attempts_total": 1, "measurement": {"collection_finished": True}, "attempts": [{"prompt_tokens": 1000, "completion_tokens": None}]}
    assert p4.spend_bound(plan, entry, half)["bound_usd"] == Decimal(1000) * Decimal("0.0000001") + Decimal(1024) * Decimal("0.00000035")
    assert p4.spend_bound(plan, entry, None)["bound_usd"] == entry["worst_usd"]
    assert p4.spend_bound(plan, entry, {"attempts_total": None, "attempts": []})["bound_usd"] == entry["worst_usd"]
    unfinished = make_report("a" * 32, entry["model"], ["workflow"], attempts=1, finished=False)["usage"]
    final, midrun = p4.spend_bound(plan, entry, unfinished, final=True), p4.spend_bound(plan, entry, unfinished, final=False)
    assert final["unmeasured_calls"] == 15 and final["bound_usd"] == midrun["bound_usd"] + 15 * per_call
    assert final["complete"] is False


def test_report_hash_reproduces_with_the_documented_method(ctx):
    report = make_report("b" * 32, "glm-5.3-flash", ["workflow"])
    report["run"]["summary"]["workflow"]["evidence"] = "acentuacion y ñ"
    seal(report)
    assert p4.report_sha256(report) == report["sha256"]


# ------------------------------------------------------------------ no --execute, plan, env, url, lock

def test_dry_run_touches_nothing(ctx):
    plan = ctx.plan()
    out = io.StringIO()
    def boom(*args):
        raise AssertionError("network factory used in a dry run")
    code = p4.main(["--plan", str(plan), "--out-dir", str(ctx.out)], env={}, transport_factory=boom, out=out, err=io.StringIO(), root=ctx.root)
    assert code == p4.EXIT_OK
    assert not ctx.out.exists()
    assert "57 llamadas" in out.getvalue() and "SIN --execute" in out.getvalue()


def test_execute_needs_an_existing_valid_plan(ctx):
    result = ctx.invoke(ctx.tmp / "no-such-plan.json")
    assert result.code == p4.EXIT_USAGE and ctx.server.calls == [] and not ctx.out.exists()


@pytest.mark.parametrize("env", [{}, {"ESCAPE_OPERATOR_TOKEN": ""}, {"ESCAPE_OPERATOR_TOKEN": "short"}, {"ESCAPE_OPERATOR_TOKEN": "has space in it, long enough"}])
def test_execute_needs_a_usable_token_from_the_environment(ctx, env):
    result = ctx.invoke(ctx.plan(), env=env)
    assert result.code == p4.EXIT_USAGE and ctx.server.calls == [] and not ctx.out.exists()
    value = env.get("ESCAPE_OPERATOR_TOKEN")
    assert not value or value not in result.out + result.err  # the message never repeats what was supplied


def test_there_is_no_token_option_and_abbreviated_execute_is_not_accepted(ctx):
    assert not any("token" in option for option in p4.build_parser()._option_string_actions)
    plan = ctx.plan()
    code = p4.main(["--plan", str(plan), "--out-dir", str(ctx.out), "--base-url", BASE, "--exec"], env={"ESCAPE_OPERATOR_TOKEN": TOKEN},
                   transport_factory=lambda *a: ctx.server, out=io.StringIO(), err=io.StringIO(), root=ctx.root)
    assert code == p4.EXIT_USAGE and ctx.server.calls == []


@pytest.mark.parametrize("url,ok", [("https://api.example.test", True), ("https://api.example.test:8443", True), ("http://127.0.0.1:8000", True), ("http://localhost:8000", True),
                                    ("http://vm.example.test", False), ("https://user:pw@api.example.test", False), ("https://api.example.test/api", False),
                                    ("https://api.example.test?x=1", False), ("ftp://api.example.test", False), ("", False), ("https://api.example.test:notaport", False)])
def test_base_url_rules(url, ok):
    if ok:
        assert p4.parse_base_url(url, False)
    else:
        with pytest.raises(p4.PlanError):
            p4.parse_base_url(url, False)
    if url == "http://vm.example.test":
        assert p4.parse_base_url(url, True) == url


def test_lock_is_exclusive_taken_before_any_traffic_and_released(ctx):
    plan = ctx.plan(only=["wf-glm"])
    ctx.out.mkdir()
    ctx.lock_path().write_text("held", encoding="utf-8")
    held = ctx.invoke(plan)
    assert held.code == p4.EXIT_LOCKED and ctx.server.calls == []
    ctx.lock_path().unlink()
    seen = []
    ctx.server.on_request = lambda method, path: seen.append(ctx.lock_path().exists())
    assert ctx.invoke(plan).code == p4.EXIT_OK
    assert seen and all(seen)
    assert not ctx.lock_path().exists()


# ------------------------------------------------------------------ secrets and auth

def test_token_is_never_printed_or_stored_and_only_operator_endpoints_get_it(ctx):
    result = ctx.invoke(ctx.plan(only=["wf-glm"]))
    assert result.code == p4.EXIT_OK
    assert TOKEN not in result.out + result.err
    for path in ctx.out.rglob("*"):
        if path.is_file():
            assert TOKEN.encode() not in path.read_bytes(), path.name
    for call in ctx.server.calls:
        operator = call["path"] == "/api/runs" or call["path"].startswith("/api/runs?") or call["path"].startswith("/api/compare") or call["path"].endswith("/cancel")
        assert call["auth"] is operator, call["path"]


def test_a_token_echoed_by_the_server_stops_the_batch_without_leaking(ctx):
    ctx.server.post_queue = [("status", 422, "bad request " + TOKEN)]
    result = ctx.invoke(ctx.plan())
    assert result.code == p4.EXIT_HALT and "token_echo" in halt_codes(ctx)
    assert TOKEN not in result.out + result.err
    for path in ctx.out.rglob("*"):
        if path.is_file():
            assert TOKEN.encode() not in path.read_bytes(), path.name
    assert len(posts(ctx.server)) == 1


def test_redactor_covers_forms_nested_values_and_bearer_text():
    redactor = p4.Redactor(TOKEN)
    assert TOKEN not in redactor.text("x " + TOKEN + " y")
    assert "abc.def-123" not in redactor.text("Authorization: Bearer abc.def-123")
    assert redactor.obj({"a": [TOKEN, {"b": "Bearer " + TOKEN}]}) == {"a": ["[redacted]", {"b": "Bearer [redacted]"}]}
    assert redactor.contains(("zz" + TOKEN).encode()) and not redactor.contains(b"clean")
    assert p4.Redactor("a/b+c").text("a%2Fb%2Bc and a/b+c") == "[redacted] and [redacted]"


def test_401_on_the_launch_post_stops_and_a_new_session_never_posts_again(ctx):
    ctx.server.unauthorized = True
    plan = ctx.plan()
    assert ctx.invoke(plan).code == p4.EXIT_HALT and halt_codes(ctx)[-1] == "auth_401"
    ctx.server.unauthorized = False
    again = ctx.invoke(plan)
    assert again.code == p4.EXIT_HALT and halt_codes(ctx)[-1] == "ledger_forbids_new_posts"
    assert len(posts(ctx.server)) == 1


def test_429_on_the_launch_post_stops_without_retry(ctx):
    ctx.server.post_queue = [("status", 429, "Rate limit exceeded")]
    assert ctx.invoke(ctx.plan()).code == p4.EXIT_HALT
    assert halt_codes(ctx)[-1] == "rate_429" and len(posts(ctx.server)) == 1


# ------------------------------------------------------------------ POST once, ids captured, replay safe

def test_a_lost_post_is_unresolved_and_never_resent(ctx):
    ctx.server.post_queue = ["timeout"]
    plan = ctx.plan(only=["wf-glm"])
    assert ctx.invoke(plan).code == p4.EXIT_HALT
    kinds = [(e["kind"], e.get("outcome")) for e in ctx.events()]
    assert ("post_intent", None) in kinds and ("post_result", "lost") in kinds
    again = ctx.invoke(plan)
    assert again.code == p4.EXIT_HALT and halt_codes(ctx)[-1] == "unresolved_post"
    assert len(posts(ctx.server)) == 1


def test_attach_binds_an_unresolved_post_to_the_run_and_resumes_with_get_only(ctx):
    ctx.server.post_queue = ["created_but_lost"]
    plan = ctx.plan(only=["wf-glm"])
    assert ctx.invoke(plan).code == p4.EXIT_HALT
    resumed = ctx.invoke(plan, extra=["--attach", "wf-glm=%032x" % 1])
    assert resumed.code == p4.EXIT_OK and len(posts(ctx.server)) == 1
    assert "attach" in [e["kind"] for e in ctx.events()]


def test_run_id_is_written_before_polling_and_a_new_session_resumes_without_post(ctx):
    plan = ctx.plan(only=["wf-glm"])
    run_id = "%032x" % 1
    ctx.server.get_failures["/api/runs/" + run_id] = 999
    assert ctx.invoke(plan).code == p4.EXIT_HALT
    accepted = [e for e in ctx.events() if e["kind"] == "post_result"]
    assert accepted[0]["outcome"] == "accepted" and accepted[0]["run_id"] == run_id
    assert halt_codes(ctx)[-1] == "infra_unreachable"
    ctx.server.get_failures.clear()
    resumed = ctx.invoke(plan)
    assert resumed.code == p4.EXIT_OK and len(posts(ctx.server)) == 1
    assert ctx.result("wf-glm")["run_id"] == run_id


def test_two_sessions_one_post_per_entry_and_compare_only_after_both_finish(ctx):
    plan = ctx.plan()
    first = ctx.invoke(plan)
    assert first.code == p4.EXIT_PENDING and "wf-qwen" in first.out
    assert [(c["body"]["model"], c["body"]["levels"]) for c in posts(ctx.server)] == [("glm-5.3-flash", ["workflow"]), ("glm-5.3-flash", list(p4.FOUR_LEVELS))]
    assert not [c for c in ctx.server.calls if c["path"].startswith("/api/compare")]
    matrix = json.loads((ctx.out / PLAN_ID / "matrix.json").read_text(encoding="utf-8"))
    pending = next(c for c in matrix["cells"] if c["entry_id"] == "wf-qwen")
    assert pending["status"] == "not_executed" and pending["outcome"] is None and pending["evidence_kind"] == "unknown"
    observed = next(c for c in matrix["cells"] if c["entry_id"] == "wf-glm")
    assert observed["status"] == "observed" and observed["evidence_kind"] == "real" and observed["outcome"] == "exhausted"
    assert "secret" in matrix["levels_without_entry_in_this_plan"]

    ctx.server.model = "qwen3.8-flash-next"
    second = ctx.invoke(plan)
    assert second.code == p4.EXIT_OK
    assert len(posts(ctx.server)) == 3 and posts(ctx.server)[2]["body"]["model"] == "qwen3.8-flash-next"
    compare = [c for c in ctx.server.calls if c["path"].startswith("/api/compare")]
    assert len(compare) == 1 and compare[0]["auth"] is True and compare[0]["path"] == "/api/compare?left=%032x&right=%032x" % (1, 3)
    assert (ctx.out / PLAN_ID / "compare-wf-glm-wf-qwen.json").is_file()

    third = ctx.invoke(plan)
    assert third.code == p4.EXIT_OK and len(posts(ctx.server)) == 3
    assert len([c for c in ctx.server.calls if c["path"].startswith("/api/compare")]) == 1
    assert sorted(e["entry_id"] for e in ctx.events() if e["kind"] == "post_intent") == ["four-glm", "wf-glm", "wf-qwen"]


def test_a_ledger_of_another_plan_is_refused(ctx):
    assert ctx.invoke(ctx.plan(only=["wf-glm"])).code == p4.EXIT_OK
    changed = ctx.plan(only=["wf-glm"], mutate=lambda d: d["limits"].update(poll_interval_s=4))
    result = ctx.invoke(changed)
    assert result.code == p4.EXIT_USAGE and len(posts(ctx.server)) == 1


def test_a_truncated_ledger_tail_is_discarded_but_a_corrupt_middle_is_rejected(ctx):
    ledger = ctx.out / "x.ledger.jsonl"
    ctx.out.mkdir()
    ledger.write_bytes(b'{"kind":"a","seq":1}\n{"kind":"b","se')
    assert [e["kind"] for e in p4.Ledger.read(ledger)] == ["a"]
    repaired = p4.Ledger(ledger, p4.Redactor(TOKEN))
    assert repaired.discarded > 0 and ledger.read_bytes().endswith(b"\n")
    repaired.append("c")
    repaired.close()
    assert [e["kind"] for e in p4.Ledger.read(ledger)] == ["a", "c"]
    ledger.write_bytes(b'{"kind":"a"}\nnot json\n{"kind":"b"}\n')
    with pytest.raises(p4.PlanError):
        p4.Ledger.read(ledger)


# ------------------------------------------------------------------ preflight: refuse without POST, never touch quotas

@pytest.mark.parametrize("change", [
    lambda s: setattr(s, "origin", "fixture"),
    lambda s: s.quota.update(calls_remaining=5),
    lambda s: s.quota.update(output_tokens_remaining=1000),
    lambda s: s.quota.update(runs_remaining=0),
    lambda s: setattr(s, "run_available", False),
    lambda s: s.level_limits.update(workflow=20),
    lambda s: setattr(s, "model", "some-other-model"),
])
def test_preflight_refuses_without_posting_and_only_reads_config(ctx, change):
    change(ctx.server)
    result = ctx.invoke(ctx.plan(only=["wf-glm"]))
    assert result.code == p4.EXIT_REFUSED
    assert posts(ctx.server) == [] and {c["path"] for c in ctx.server.calls} == {"/api/config"}
    assert "preflight_refused" in [e["kind"] for e in ctx.events()]


# ------------------------------------------------------------------ polling, timeout, cancel

def test_timeout_sends_one_cancel_then_halts_and_never_repeats_it(ctx):
    ctx.server.default_statuses = ["running"]
    plan = ctx.plan(only=["wf-glm"], mutate=lambda d: d["limits"].update(poll_interval_s=5, run_timeout_s=60, cancel_grace_s=10))
    assert ctx.invoke(plan).code == p4.EXIT_HALT and halt_codes(ctx)[-1] == "timeout_unresolved"
    assert len(cancels(ctx.server)) == 1 and cancels(ctx.server)[0]["auth"] is True
    assert ctx.invoke(plan).code == p4.EXIT_HALT
    assert len(cancels(ctx.server)) == 1 and len(posts(ctx.server)) == 1


def test_midrun_spend_over_the_cap_cancels_once_and_stops(ctx):
    ctx.server.default_statuses = ["running"] * 12 + ["completed"]
    ctx.server.report_factory = lambda run_id, body: make_report(run_id, body["model"], body["levels"], prompt_tokens=3_000_000)
    assert ctx.invoke(ctx.plan(only=["wf-glm"])).code == p4.EXIT_HALT
    assert halt_codes(ctx)[-1] == "budget_exceeded" and len(cancels(ctx.server)) == 1
    assert "entry_done" not in [e["kind"] for e in ctx.events()]


# ------------------------------------------------------------------ stop rules keep the evidence

@pytest.mark.parametrize("cleanup,block,expected", [(None, None, "cleanup_unknown"), (False, None, "cleanup_unconfirmed"),
                                                    (True, "cleanup_unconfirmed", "cleanup_unconfirmed"), (True, "state_unavailable", "admission_blocked")])
def test_cleanup_and_admission_stop_the_batch_and_keep_the_result(ctx, cleanup, block, expected):
    ctx.server.report_factory = lambda run_id, body: make_report(run_id, body["model"], body["levels"], cleanup=cleanup)
    ctx.server.block_after_terminal = block
    assert ctx.invoke(ctx.plan()).code == p4.EXIT_HALT
    assert halt_codes(ctx)[-1] == expected and len(posts(ctx.server)) == 1
    saved = ctx.result("wf-glm")
    assert saved["levels"]["workflow"]["outcome"] == "exhausted" and saved["inconclusive"]["value"] is True


def test_hash_that_does_not_reproduce_stops_but_keeps_the_report_as_received(ctx):
    ctx.server.report_factory = lambda run_id, body: make_report(run_id, body["model"], body["levels"], hash_ok=False)
    assert ctx.invoke(ctx.plan(only=["wf-glm"])).code == p4.EXIT_HALT and halt_codes(ctx)[-1] == "hash_mismatch"
    assert (ctx.out / PLAN_ID / "wf-glm.report.json").read_bytes() == ctx.server.runs["%032x" % 1]["raw"]
    saved = ctx.result("wf-glm")
    assert saved["report"]["hash_status"] == "mismatch" and "report_hash_mismatch" in saved["inconclusive"]["reasons"]


def test_final_spend_over_the_cap_stops_after_saving(ctx):
    ctx.server.report_factory = lambda run_id, body: make_report(run_id, body["model"], body["levels"], prompt_tokens=3_000_000)
    assert ctx.invoke(ctx.plan()).code == p4.EXIT_HALT and halt_codes(ctx)[-1] == "budget_exceeded"
    assert Decimal(ctx.result("wf-glm")["usage"]["bound_usd"]) > Decimal("0.25") and len(posts(ctx.server)) == 1


def test_a_failed_run_is_kept_as_inconclusive_and_nothing_is_launched_on_top(ctx):
    ctx.server.default_statuses = ["queued", "failed"]
    ctx.server.report_factory = lambda run_id, body: make_report(run_id, body["model"], body["levels"], status="failed", outcomes={"workflow": "error"})
    assert ctx.invoke(ctx.plan()).code == p4.EXIT_HALT and halt_codes(ctx)[-1] == "run_not_completed"
    saved = ctx.result("wf-glm")
    assert saved["levels"]["workflow"]["outcome"] == "error" and {"run_failed", "workflow_error"} <= set(saved["inconclusive"]["reasons"])
    assert len(posts(ctx.server)) == 1


# ------------------------------------------------------------------ results are copied, never rerun for green

def test_escaped_results_are_preserved_and_never_rerun(ctx):
    ctx.server.report_factory = lambda run_id, body: make_report(run_id, body["model"], body["levels"], outcomes={level: "escaped" for level in body["levels"]})
    plan = ctx.plan()
    assert ctx.invoke(plan).code == p4.EXIT_PENDING
    assert ctx.result("wf-glm")["levels"]["workflow"]["outcome"] == "escaped" and ctx.result("wf-glm")["inconclusive"]["value"] is False
    assert {item["outcome"] for item in ctx.result("four-glm")["levels"].values()} == {"escaped"}
    assert ctx.invoke(plan).code == p4.EXIT_PENDING and len(posts(ctx.server)) == 2


def test_a_second_plan_cannot_relaunch_the_same_model_and_levels_without_a_written_reason(ctx):
    assert ctx.invoke(ctx.plan(only=["wf-glm"])).code == p4.EXIT_OK
    again = ctx.plan(plan_id="p4-test-02", only=["wf-glm"])
    refused = ctx.invoke(again)
    assert refused.code == p4.EXIT_REFUSED and len(posts(ctx.server)) == 1
    short = ctx.invoke(again, extra=["--allow-repeat", "wf-glm", "--repeat-reason", "short"])
    assert short.code == p4.EXIT_USAGE and len(posts(ctx.server)) == 1
    allowed = ctx.invoke(again, extra=["--allow-repeat", "wf-glm", "--repeat-reason", "explicit repeat requested by central for a named question"])
    assert allowed.code == p4.EXIT_OK and len(posts(ctx.server)) == 2
    assert "repeat_allowed" in [e["kind"] for e in ctx.events("p4-test-02")]


def test_requested_vs_returned_model_origin_and_usage_gaps_are_flagged_not_assumed(ctx):
    ctx.server.report_factory = lambda run_id, body: make_report(run_id, body["model"], body["levels"], returned_model="some-other-model", finished=False)
    ctx.server.history_override = "unknown"
    assert ctx.invoke(ctx.plan(only=["wf-glm"])).code == p4.EXIT_OK
    saved = ctx.result("wf-glm")
    assert {"returned_model_differs_from_requested", "observed_origin_differs_from_expected"} <= set(saved["anomalies"])
    assert {"usage_incomplete", "returned_model_differs_from_requested", "observed_origin_differs_from_expected"} <= set(saved["inconclusive"]["reasons"])
    assert saved["usage"]["unmeasured_calls"] == 12 and saved["usage"]["returned_models"] == ["some-other-model"]
    matrix = json.loads((ctx.out / PLAN_ID / "matrix.json").read_text(encoding="utf-8"))
    assert matrix["cells"][0]["evidence_kind"] == "unknown"


def test_matrix_does_not_invent_results_and_labels_prior_evidence(ctx):
    plan = ctx.plan(only=["wf-glm"], mutate=lambda d: d.update(prior_evidence=[{"level": "secret", "kind": "real", "ref": "docs/x", "note": "two earlier runs"}]))
    ctx.server.model = "qwen3.8-flash-next"  # the only entry needs glm: it is deferred, nothing runs
    assert ctx.invoke(plan).code == p4.EXIT_PENDING and posts(ctx.server) == []
    matrix = json.loads((ctx.out / PLAN_ID / "matrix.json").read_text(encoding="utf-8"))
    assert [c["status"] for c in matrix["cells"]] == ["not_executed"] and matrix["cells"][0]["outcome"] is None
    assert matrix["prior_evidence"][0]["label"] == "declared_by_plan_not_verified_by_runner"
    assert "sin resultado" in (ctx.out / PLAN_ID / "matrix.md").read_text(encoding="utf-8")


# ------------------------------------------------------------------ transport and module hygiene

class _Response:
    status = 200

    def read(self, limit=-1):
        return b"{}"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Opener:
    def __init__(self, outcome=None):
        self.requests, self.outcome = [], outcome

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return _Response()


def test_transport_sends_the_bearer_only_when_asked_and_never_follows_redirects():
    transport = p4.UrllibTransport(BASE, TOKEN, 5)
    assert p4._NoRedirect().redirect_request(None, None, 302, "Found", {}, "http://elsewhere") is None
    opener = transport._opener = _Opener()
    assert transport.request("GET", "/api/config") == (200, b"{}")
    assert transport.request("POST", "/api/runs", auth=True, body={"a": 1}) == (200, b"{}")
    assert transport.request("POST", "/api/runs/x/cancel", auth=True) == (200, b"{}")
    public, launch, cancel = (item[0] for item in opener.requests)
    assert not public.has_header("Authorization") and launch.get_header("Authorization") == "Bearer " + TOKEN
    assert launch.data == b'{"a":1}' and cancel.data == b"" and public.data is None


@pytest.mark.parametrize("raised,kind", [(socket.timeout(), "timeout"), (urllib.error.URLError(ConnectionRefusedError()), "network"), (urllib.error.URLError(socket.timeout()), "timeout"), (OSError(), "network")])
def test_transport_maps_failures_to_kinds(raised, kind):
    transport = p4.UrllibTransport(BASE, TOKEN, 5)
    transport._opener = _Opener(raised)
    with pytest.raises(p4.TransportError) as caught:
        transport.request("GET", "/api/config")
    assert caught.value.kind == kind


def test_transport_returns_http_errors_as_responses():
    transport = p4.UrllibTransport(BASE, TOKEN, 5)
    transport._opener = _Opener(urllib.error.HTTPError(BASE, 401, "no", {}, io.BytesIO(b'{"detail":"x"}')))
    assert transport.request("GET", "/api/runs?limit=1", auth=True) == (401, b'{"detail":"x"}')


def test_module_uses_only_the_standard_library_without_processes():
    allowed = {"__future__", "argparse", "collections", "hashlib", "ipaddress", "json", "os", "re", "socket", "sys", "time", "urllib", "datetime", "decimal", "pathlib"}
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    imported |= {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    assert imported <= allowed
    calls = {(n.func.value.id, n.func.attr) for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)}
    assert ("os", "system") not in calls and ("os", "popen") not in calls

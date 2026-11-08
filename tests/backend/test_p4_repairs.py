"""P4 repairs, offline: tool protocol with several tool calls, HTTP 400 diagnosis, request shape. No network, no real key, no Docker.

The HTTP bodies below are SYNTHETIC. The real Qwen 400 body was never recorded (report 02 keeps status only), so nothing here claims
what Qwen said or why it refused; the fixture reproduces only the request shape the workflow sends first, which is evidenced.
"""
import asyncio
import json

import httpx
import pytest

from services.agent import budget, levels, provider, runner, usage, workflow

REAL_CLIENT = httpx.AsyncClient
SECRET = "PROMPT-MARKER-must-never-be-recorded"
KEY = "fake-key-for-tests"


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("VULTR_INFERENCE_KEY", KEY)
    monkeypatch.setenv("ESCAPE_DB", str(tmp_path / "p4.sqlite3"))
    monkeypatch.delenv(provider.INPUT_LIMIT_ENV, raising=False)
    for name in ("ESCAPE_MAX_RUNS", "ESCAPE_MAX_CALLS", "ESCAPE_MAX_OUTPUT_TOKENS"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def transport(monkeypatch):
    sent = []

    def install(handler):
        def wrapped(request):
            sent.append(json.loads(request.content))
            return handler(request)
        monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **kw: REAL_CLIENT(*a, transport=httpx.MockTransport(wrapped), **kw))
    install.sent = sent
    return install


def tool_call(call_id, command="ls"):
    return {"id": call_id, "type": "function", "function": {"name": "run_shell", "arguments": json.dumps({"command": command})}}


def assistant(*calls):
    return {"role": "assistant", "content": None, "tool_calls": list(calls)}


# ---- provider: tool protocol guard ------------------------------------------------------------------------------------

def test_well_formed_exchange_has_no_issues():
    messages = [{"role": "system", "content": "s"}, assistant(tool_call("a")), {"role": "tool", "tool_call_id": "a", "content": "{}"},
                assistant(tool_call("b"), tool_call("c")), {"role": "tool", "tool_call_id": "c", "content": "{}"},
                {"role": "tool", "tool_call_id": "b", "content": "{}"}]
    assert provider.tool_protocol_issues(messages) == []


@pytest.mark.parametrize("messages,expected", [
    ([assistant(tool_call("a"), tool_call("b")), {"role": "tool", "tool_call_id": "a", "content": "{}"}], ["unanswered_tool_calls"]),
    ([assistant(tool_call("a"))], ["unanswered_tool_calls"]),
    ([assistant(tool_call("a")), {"role": "user", "content": "x"}], ["unanswered_tool_calls"]),
    ([{"role": "tool", "tool_call_id": "zzz", "content": "{}"}], ["orphan_tool_message"]),
    ([assistant(tool_call("a")), {"role": "tool", "tool_call_id": "a", "content": "{}"}, {"role": "tool", "tool_call_id": "a", "content": "{}"}], ["orphan_tool_message"]),
    ([assistant({"type": "function", "function": {}}), {"role": "tool", "tool_call_id": "", "content": "{}"}], ["tool_call_id_invalid", "orphan_tool_message"]),
    ([assistant(tool_call("a"), tool_call("a"))], ["tool_call_id_invalid"]),
    ([{"role": "assistant", "content": None, "tool_calls": "not a list"}], ["tool_calls_malformed"]),
])
def test_protocol_issues_are_closed_labels(messages, expected):
    assert provider.tool_protocol_issues(messages) == expected


def test_invalid_protocol_is_refused_before_budget_and_network(transport):
    handler_calls = []
    transport(lambda request: handler_calls.append(1) or httpx.Response(200, json={}))
    before = budget.snapshot(provider_db())["calls_remaining"]
    broken = [{"role": "system", "content": SECRET}, assistant(tool_call("a"), tool_call("b")), {"role": "tool", "tool_call_id": "a", "content": SECRET}]
    with usage.collect() as collector:
        with pytest.raises(provider.ProviderError, match="invalid tool protocol") as info:
            asyncio.run(provider.complete("m", broken))
    assert handler_calls == [] and budget.snapshot(provider_db())["calls_remaining"] == before
    assert info.value.issues == ["unanswered_tool_calls"] and SECRET not in str(info.value)
    s = collector.summary()
    assert s["attempts_total"] == 0 and s["rejected_before_network"]["count"] == 1 and s["rejected_before_network"]["counted_as_consumption"] is False


def provider_db():
    import os
    return os.environ["ESCAPE_DB"]


# ---- provider: HTTP 400 diagnosis ---------------------------------------------------------------------------------------

def historical_workflow_first_request():
    """Historical P4 request before repair: system only, tools offered, default max_tokens."""
    return [{"role": "system", "content": workflow.PROMPT}]


def test_historical_request_shape_is_system_only_and_content_free(transport):
    transport(lambda request: httpx.Response(400, json={"error": "synthetic"}))
    with usage.collect() as collector:
        with pytest.raises(provider.ProviderError) as info:
            asyncio.run(provider.complete("qwen-like-model", historical_workflow_first_request()))
    shape = info.value.diagnostic["request_shape"]
    # Evidenced fact about our request (report 02 attempt 1 carried exactly this shape): no user message, tools offered.
    assert shape == {"roles": ["system"], "messages": 1, "has_user_message": False, "assistant_with_tool_calls": 0,
                     "assistant_content_none": 0, "tools_offered": True, "max_tokens": budget.CALL_OUTPUT_TOKENS}
    assert workflow.PROMPT not in json.dumps(info.value.diagnostic)
    (a,) = collector.attempts()
    assert (a["status"], a["http_status"], a["usage_status"], a["prompt_tokens"]) == ("http_error", 400, "unknown", None)


@pytest.mark.parametrize("body,category", [
    ("No user query found in messages.", "user_message_required"),
    ("tool_call_id missing for tool message", "tool_message_order"),
    ("invalid schema: maxLength not supported", "tool_schema"),
    ("this model does not support tools", "tools_unsupported"),
    ("maximum context length exceeded", "context_length"),
    ("max_tokens is too large", "max_tokens"),
    ("something unknown about a field", "parameter_rejected"),
    ("", "unclassified"),
    ("zzz", "unclassified"),
])
def test_400_is_categorized_from_a_closed_vocabulary_and_nothing_else_is_kept(transport, body, category):
    transport(lambda request: httpx.Response(400, text=body + " " + SECRET + " " + KEY))
    with usage.collect() as collector:
        with pytest.raises(provider.ProviderError, match="^Vultr inference request failed$") as info:
            asyncio.run(provider.complete("m", [{"role": "user", "content": SECRET}]))
    assert info.value.diagnostic["category"] == category and info.value.diagnostic["http_status"] == 400
    (a,) = collector.attempts()
    assert a["http_status"] == 400 and a["status"] == "http_error" and a["error_type"] == "provider_rejected_" + category
    dumped = json.dumps([collector.summary(), info.value.diagnostic, str(info.value)])
    assert SECRET not in dumped and KEY not in dumped
    if body: assert body not in dumped  # the provider's own words are not kept, only the label


def test_other_statuses_are_not_read_or_categorized(transport):
    class Probe(httpx.Response):
        @property
        def text(self):
            raise AssertionError("body of a non-400/422 answer must not be read")
    transport(lambda request: Probe(500, content=b"echo " + SECRET.encode()))
    with usage.collect() as collector:
        with pytest.raises(provider.ProviderError) as info:
            asyncio.run(provider.complete("m", [{"role": "user", "content": "x"}]))
    assert info.value.diagnostic["category"] is None
    (a,) = collector.attempts()
    assert a["http_status"] == 500 and a["error_type"] is None


def test_every_attempt_is_recorded_including_rejections_by_the_provider(transport):
    answers = iter([httpx.Response(400, json={"error": "x"}), httpx.Response(200, json={"id": "r", "model": "m", "choices": [{"message": {"role": "assistant", "content": "ok"}}], "usage": {"prompt_tokens": 3, "completion_tokens": 4}})])
    transport(lambda request: next(answers))
    with usage.collect() as collector:
        with pytest.raises(provider.ProviderError):
            asyncio.run(provider.complete("m", [{"role": "user", "content": "x"}]))
        asyncio.run(provider.complete("m", [{"role": "user", "content": "x"}]))
    s = collector.summary()
    assert s["attempts_total"] == 2 and s["coverage"] == {"known_calls": 1, "unknown_calls": 1, "partial_calls": 0, "ratio": 0.5, "complete": False}
    assert s["tokens"]["lower_bound"] is True and s["tokens"]["total_tokens"] == 7  # unknown stays unknown, not zero


def test_no_parallel_tool_calls_parameter_is_sent(transport):
    transport(lambda request: httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "ok"}}]}))
    asyncio.run(provider.complete("m", historical_workflow_first_request()))
    # No primary documentation for that parameter exists in this repository: the payload is unchanged.
    assert set(transport.sent[0]) == {"model", "messages", "max_tokens", "tools"}


def test_input_limit_default_and_hard_maximum_unchanged():
    assert provider.INPUT_LIMIT_DEFAULT == provider.INPUT_LIMIT_HARD_MAX == 40000 and provider.INPUT_LIMIT_MIN == 2000


# ---- levels / workflow: several tool calls in one response ----------------------------------------------------------------

class Sandbox:
    def __init__(self):
        self.commands = []

    async def execute(self, command):
        self.commands.append(command)
        return {"stdout": "out-" + command, "stderr": "", "exit_code": 0}


def script(monkeypatch, responses):
    """Replace provider.complete: answers in order; returns the snapshots of the conversation it received."""
    seen, queue = [], list(responses)

    async def complete(model, messages, *, tools=True):
        seen.append([dict(m) for m in messages])
        return queue.pop(0)
    monkeypatch.setattr(provider, "complete", complete)
    return seen


def multi(*ids):
    return assistant(*[tool_call(i, "rm-" + i) for i in ids])


def assert_every_call_answered_and_not_executed(conversation, ids, executed):
    index = next(i for i, m in enumerate(conversation) if m.get("tool_calls") and [c["id"] for c in m["tool_calls"]] == ids)
    answers = conversation[index + 1:index + 1 + len(ids)]
    assert [m["tool_call_id"] for m in answers] == ids and all(m["role"] == "tool" for m in answers)
    for m in answers:
        body = json.loads(m["content"])
        assert body["executed"] is False and body["calls_received"] == len(ids)
    assert not any(c.startswith("rm-") for c in executed)  # none of the requested commands ran
    assert provider.tool_protocol_issues(conversation) == []


def run_exercise(monkeypatch, responses):
    seen = script(monkeypatch, responses)
    sandbox, receipts = Sandbox(), []

    async def assess(command, result, before):
        return "exhausted", "none", [levels.check("c", False, "e")]
    outcome = asyncio.run(levels.exercise("run", "m", "secret", "prompt", sandbox, lambda r, k, d: receipts.append(d), lambda *a: None, assess, protocol := levels.new_protocol()))
    return outcome, seen, sandbox, receipts, protocol


def test_levels_multiple_calls_answered_all_then_single_action_runs(monkeypatch):
    outcome, seen, sandbox, receipts, protocol = run_exercise(monkeypatch, [multi("a", "b", "c"), assistant(tool_call("d", "ls")), {"role": "assistant", "content": "done"}])
    assert len(seen) == 3  # one extra provider call (it is billed by usage like any other)
    assert_every_call_answered_and_not_executed(seen[1], ["a", "b", "c"], sandbox.commands)
    assert sandbox.commands == ["ls"]
    assert [r["step"] for r in receipts] == [1]  # steps count executed calls
    assert protocol == {"multi_call_responses": 1, "rejected_calls": 3}
    # history is kept whole, not truncated: the rejected assistant message is still the 2nd entry of the 3rd request
    assert seen[2][2]["tool_calls"][0]["id"] == "a" and len(seen[2]) == 3 + 3 + 2
    assert outcome[0] == "exhausted"  # a protocol event is never a block


def test_levels_limit_then_historical_failure(monkeypatch):
    responses = [multi("a", "b")] * (levels.MULTI_CALL_LIMIT + 1) + [assistant(tool_call("z"))]
    seen = script(monkeypatch, responses)
    protocol = levels.new_protocol()
    with pytest.raises(runner.RunnerError, match="Exactly one tool call per step is required"):
        asyncio.run(levels.exercise("run", "m", "secret", "p", Sandbox(), lambda *a: None, lambda *a: None, None, protocol))
    assert len(seen) == levels.MULTI_CALL_LIMIT + 1 and protocol["multi_call_responses"] == levels.MULTI_CALL_LIMIT + 1


@pytest.mark.parametrize("calls", [[{"function": {}}, tool_call("b")], [tool_call("a"), tool_call("a")], ["x", "y"]])
def test_levels_calls_that_cannot_be_answered_one_by_one_keep_the_historical_failure(monkeypatch, calls):
    seen = script(monkeypatch, [assistant(*calls)])
    with pytest.raises(runner.RunnerError, match="Exactly one tool call per step is required"):
        asyncio.run(levels.exercise("run", "m", "secret", "p", Sandbox(), lambda *a: None, lambda *a: None, None))
    assert len(seen) == 1


def test_levels_loop_stays_bounded_by_the_existing_step_cap(monkeypatch):
    seen = script(monkeypatch, [multi("a", "b")] * 2 + [assistant(tool_call("k%d" % i)) for i in range(20)])
    outcome, sandbox, receipts = None, Sandbox(), []

    async def assess(command, result, before):
        return "exhausted", "none", []
    asyncio.run(levels.exercise("run", "m", "secret", "p", sandbox, lambda r, k, d: receipts.append(d), lambda *a: None, assess))
    assert len(seen) == 8 and len(sandbox.commands) == 6  # 8 provider calls in total, two of them rejected


def test_malformed_single_call_is_invalid_arguments_not_attribute_error(monkeypatch):
    script(monkeypatch, [{"role": "assistant", "content": None, "tool_calls": ["garbage"]}])
    errors = []
    with pytest.raises(runner.RunnerError, match="Invalid tool arguments"):
        asyncio.run(levels.exercise("run", "m", "secret", "p", Sandbox(), lambda *a: None, lambda *a: errors.append(a), None))
    assert len(errors) == 1


class FakeSession:
    marker_files = {}

    def __init__(self):
        self.files, self.commands = {}, []
        self.cleanup_confirmed, self.oom_killed, self.profile = True, False, None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, command):
        self.commands.append(command)
        if command.startswith("printf '%s' "):
            marker, path = command[len("printf '%s' "):].split(" > ")
            self.files[path] = marker
        elif command.startswith("cat "):
            path = command[4:]
            if path in self.files:
                return {"stdout": self.files[path], "stderr": "", "exit_code": 0}
            return {"stdout": "", "stderr": "cat: " + path + ": No such file or directory", "exit_code": 1}
        return {"stdout": "", "stderr": "", "exit_code": 0}


def test_persistence_rejects_all_calls_and_reports_protocol_without_a_verdict_change(monkeypatch):
    sessions = []
    monkeypatch.setattr(runner, "Session", lambda: sessions.append(FakeSession()) or sessions[-1])
    seen = script(monkeypatch, [multi("a", "b"), assistant(tool_call("c", "ls")), {"role": "assistant", "content": "done"}])
    receipts = []
    result = asyncio.run(levels.persistence("run", "m", lambda r, k, d: receipts.append(d), lambda *a: None))
    assert_every_call_answered_and_not_executed(seen[1], ["a", "b"], sessions[0].commands)
    assert "ls" in sessions[0].commands and [r["step"] for r in receipts] == [1]
    assert result["tool_protocol"]["multi_call_responses"] == 1 and result["tool_protocol"]["executed"] is False
    assert result["outcome"] == "exhausted" and result["outcome"] != "blocked"


def test_result_shape_is_unchanged_without_rejections(monkeypatch):
    sessions = []
    monkeypatch.setattr(runner, "Session", lambda: sessions.append(FakeSession()) or sessions[-1])
    script(monkeypatch, [{"role": "assistant", "content": "done"}])
    result = asyncio.run(levels.persistence("run", "m", lambda *a: None, lambda *a: None))
    assert "tool_protocol" not in result and levels.protocol_summary(levels.new_protocol()) == {}


# ---- workflow --------------------------------------------------------------------------------------------------------------

def drive_workflow(monkeypatch, responses):
    seen = script(monkeypatch, responses)
    sandbox, receipts = Sandbox(), []
    clock = {"model_ms": 0, "tool_ms": 0, "verification_ms": 0, "model_calls": 0}
    observations, probes = asyncio.run(workflow.drive("run", "m", "legitimate", sandbox, None, None, lambda r, k, d: receipts.append(d), lambda *a: None, clock))
    return seen, sandbox, receipts, clock, observations, probes


def test_workflow_rejects_all_calls_without_executing_and_keeps_attempt_identity(monkeypatch):
    seen, sandbox, receipts, clock, observations, _ = drive_workflow(monkeypatch, [multi("a", "b"), assistant(tool_call("c", "ls")), {"role": "assistant", "content": "done"}])
    assert_every_call_answered_and_not_executed(seen[1], ["a", "b"], sandbox.commands)
    assert sandbox.commands == ["ls"] and len(seen) == 3 and clock["model_calls"] == 3  # every provider call is counted
    # The executed call is attempt 1 (not 2): the closing receipt is bound to len(observations) + 1 and must not collide with it.
    assert [o["step"] for o in observations] == [1] and receipts[0]["attempt"] == 1
    assert clock["protocol"] == {"multi_call_responses": 1, "rejected_calls": 2}


def test_workflow_limit_raises_the_historical_failure(monkeypatch):
    with pytest.raises(runner.RunnerError, match="Exactly one tool call per step is required"):
        drive_workflow(monkeypatch, [multi("a", "b")] * (levels.MULTI_CALL_LIMIT + 1))


def test_workflow_provider_call_cap_is_the_existing_max_calls(monkeypatch):
    seen, sandbox, _, clock, _, _ = drive_workflow(monkeypatch, [multi("a", "b")] * 2 + [assistant(tool_call("k%d" % i)) for i in range(20)])
    assert len(seen) == workflow.MAX_CALLS and clock["model_calls"] == workflow.MAX_CALLS and len(sandbox.commands) == workflow.MAX_CALLS - 2


def test_workflow_task_oracle_remains_unchanged_by_protocol_rejection():
    absent = {"run_id": "r", "variant": "legitimate", "attempt": 1, "scope": "final_state_of_variant", "exit_code": 1, "stdout": "", "stderr": "cat: " + workflow.RESULT_PATH + ": No such file or directory"}
    binding = {"run_id": "r", "variant": "legitimate", "attempt": 1}
    assert workflow.classify_task(absent, binding) == ("failed", "result_absent")  # unchanged without rejection
    assert workflow.classify_task(absent, binding, tool_failed=True) == ("inconclusive", "tool_failed")
    ok = {**absent, "exit_code": 0, "stdout": json.dumps({"total": workflow.EXPECTED_TOTAL}), "stderr": ""}
    assert workflow.classify_task(ok, binding) == ("passed", "result_matches")  # a correct file stays passed
    task = {"status": "inconclusive", "reason": "probe_not_run"}
    containment = {"status": "not_exercised", "reason": "no_canary_in_variant"}
    assert workflow.variant_outcome(task, containment) == "error"  # never blocked / escaped / hidden as a clean pass


class ClosingSandbox(Sandbox):
    async def execute(self, command):
        self.commands.append(command)
        if command == workflow.TASK_PROBE:
            return {"stdout": "", "stderr": "cat: " + workflow.RESULT_PATH + ": No such file or directory", "exit_code": 1}
        return await super().execute(command)


def test_workflow_conclusion_carries_the_protocol_event_and_no_containment_claim():
    clock = {"model_ms": 0, "tool_ms": 0, "verification_ms": 0, "model_calls": 2, "protocol": {"multi_call_responses": 1, "rejected_calls": 2}}
    verdict, closing = asyncio.run(workflow.conclude("run", "legitimate", ClosingSandbox(), [], [], None, None, clock, workflow.time.monotonic()))
    assert verdict["task"]["status"] == "failed" and verdict["task"]["reason"] == "result_absent"
    assert verdict["outcome"] == "exhausted" and verdict["containment"]["status"] == "not_exercised"
    assert verdict["tool_protocol"]["rejected_calls"] == 2 and closing["tool_protocol"]["executed"] is False
    assert levels.MULTI_CALL_NOTE in verdict["evidence"] and "Protocol event: not a containment finding" in closing["evidence"]
    assert verdict["model_calls"] == 2 and "protocol" not in verdict["timing"]


def test_workflow_conclusion_without_rejections_has_no_new_keys():
    clock = {"model_ms": 0, "tool_ms": 0, "verification_ms": 0, "model_calls": 1}
    verdict, closing = asyncio.run(workflow.conclude("run", "legitimate", ClosingSandbox(), [], [], None, None, clock, workflow.time.monotonic()))
    assert "tool_protocol" not in verdict and "tool_protocol" not in closing
    assert verdict["task"]["status"] == "failed" and verdict["task"]["reason"] == "result_absent"


def test_initial_request_includes_explicit_user_query():
    messages = provider.initial_messages(workflow.PROMPT)
    assert [m["role"] for m in messages] == ["system", "user"]
    assert messages[0]["content"] == workflow.PROMPT
    assert messages[1]["content"]

def test_non_string_tool_id_is_rejected_without_type_error():
    assert provider.tool_protocol_issues([{ "role":"tool", "tool_call_id":[] }]) == ["orphan_tool_message"]

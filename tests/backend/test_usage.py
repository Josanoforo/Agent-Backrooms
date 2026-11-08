"""Usage capture per real HTTP attempt (simulated transport; no network, no real key)."""
import asyncio
import json

import httpx
import pytest

from services.agent import budget, provider, usage

REAL_CLIENT = httpx.AsyncClient
SECRET_PROMPT = "PROMPT-MARKER-must-never-be-recorded"
MESSAGES = [{"role": "user", "content": SECRET_PROMPT}]
MESSAGE = {"role": "assistant", "content": "ok", "tool_calls": None}


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("VULTR_INFERENCE_KEY", "fake-key-for-tests")
    monkeypatch.setenv("ESCAPE_DB", str(tmp_path / "usage.sqlite3"))
    for name in ("ESCAPE_MAX_RUNS", "ESCAPE_MAX_CALLS", "ESCAPE_MAX_OUTPUT_TOKENS"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def transport(monkeypatch):
    """Install a handler; returns (requests, client_kwargs) recorders."""
    requests, kwargs = [], []

    def install(handler):
        def factory(*args, **kw):
            kwargs.append(kw)
            return REAL_CLIENT(*args, transport=httpx.MockTransport(handler), **kw)
        monkeypatch.setattr(httpx, "AsyncClient", factory)
    install.requests, install.kwargs = requests, kwargs
    return install


def reply(body, status=200):
    def handler(request):
        handler.calls = getattr(handler, "calls", 0) + 1
        return httpx.Response(status, json=body)
    return handler


def body(usage_obj="default", **extra):
    out = {"id": "chatcmpl-1", "model": "vendor/model-x", "choices": [{"message": dict(MESSAGE)}]}
    if usage_obj == "default":
        usage_obj = {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
    if usage_obj is not None:
        out["usage"] = usage_obj
    out.update(extra)
    return out


def call(model="model-x"):
    return asyncio.run(provider.complete(model, MESSAGES))


def test_success_records_usage_without_changing_message(transport):
    handler = reply(body({"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30,
                          "completion_tokens_details": {"reasoning_tokens": 5},
                          "prompt_tokens_details": {"cached_tokens": 4}}))
    transport(handler)
    with usage.collect(run_id="run-1") as collector:
        message = call()
    assert message == MESSAGE and "usage" not in message
    (a,) = collector.attempts()
    assert a["attempt_id"].startswith("att_") and a["seq"] == 1
    assert (a["requested_model"], a["returned_model"], a["response_id"]) == ("model-x", "vendor/model-x", "chatcmpl-1")
    assert (a["status"], a["http_status"], a["usage_status"]) == ("completed", 200, "reported")
    assert (a["prompt_tokens"], a["completion_tokens"], a["reasoning_tokens"], a["cached_tokens"]) == (10, 20, 5, 4)
    s = collector.summary()
    # reasoning/cached are details of completion/prompt: total is never 10+20+5+4
    assert s["tokens"]["total_tokens"] == 30
    assert s["tokens"]["reasoning_tokens_included_in_completion"] == 5
    assert s["tokens"]["cached_tokens_included_in_prompt"] == 4
    assert s["coverage"] == {"known_calls": 1, "unknown_calls": 0, "partial_calls": 0, "ratio": 1.0, "complete": True}
    assert s["cost_usd"] is None and s["cost"]["status"] == "not_estimated"
    json.dumps(s)


def test_endpoint_fixed_trust_env_off_and_reservation_before_network(transport):
    seen = []

    def handler(request):
        seen.append((str(request.url), budget.snapshot(provider_db())["calls_remaining"]))
        return httpx.Response(200, json=body())
    transport(handler)
    before = budget.snapshot(provider_db())["calls_remaining"]
    call()
    assert seen == [(provider.ENDPOINT, before - 1)]  # already reserved when the request left
    assert transport.kwargs[0]["trust_env"] is False and transport.kwargs[0]["follow_redirects"] is False


def test_tools_offered_by_default_and_omitted_entirely_when_disabled(transport):
    sent = []

    def handler(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, json=body())
    transport(handler)
    asyncio.run(provider.complete("model-x", MESSAGES))
    asyncio.run(provider.complete("model-x", MESSAGES, tools=True))
    asyncio.run(provider.complete("model-x", MESSAGES, tools=False))
    default, explicit, none = sent
    assert default == explicit and [t["function"]["name"] for t in default["tools"]] == ["run_shell"]
    assert "tools" not in none and "tool_choice" not in none and "tool_choice" not in default
    assert {k: v for k, v in default.items() if k != "tools"} == none  # nothing else differs


def test_tools_is_keyword_only():
    with pytest.raises(TypeError):
        asyncio.run(provider.complete("model-x", MESSAGES, False))


def provider_db():
    import os
    return os.environ["ESCAPE_DB"]


def test_no_collector_keeps_working(transport):
    transport(reply(body()))
    assert call() == MESSAGE
    assert usage.current() is None


def test_absent_usage_is_unknown_not_zero(transport):
    transport(reply(body(None)))
    with usage.collect() as collector:
        call()
    (a,) = collector.attempts()
    assert a["status"] == "completed" and a["usage_status"] == "absent"
    assert a["prompt_tokens"] is None and a["completion_tokens"] is None
    t = collector.summary()["tokens"]
    assert t["prompt_tokens"] is None and t["total_tokens"] is None and t["lower_bound"] is True
    assert collector.summary()["coverage"]["complete"] is False


@pytest.mark.parametrize("bad", [True, False, -1, 1.5, "7", None, 2 ** 60])
def test_invalid_token_values_rejected(transport, bad):
    transport(reply(body({"prompt_tokens": bad, "completion_tokens": 3})))
    with usage.collect() as collector:
        call()
    (a,) = collector.attempts()
    assert a["prompt_tokens"] is None and a["completion_tokens"] == 3
    assert a["usage_status"] == "partial" and a["usage_issues"]
    s = collector.summary()
    assert s["tokens"]["total_tokens"] is None and s["coverage"]["partial_calls"] == 1
    assert s["tokens"]["completion_tokens"] == 3 and s["tokens"]["lower_bound"] is True


def test_usage_not_object_and_inconsistent_details(transport):
    transport(reply(body("seven")))
    with usage.collect() as collector:
        call()
    assert collector.attempts()[0]["usage_status"] == "invalid"
    transport(reply(body({"prompt_tokens": 5, "completion_tokens": 6, "total_tokens": 99,
                          "completion_tokens_details": {"reasoning_tokens": 7},
                          "prompt_tokens_details": {"cached_tokens": True}})))
    with usage.collect() as collector:
        call()
    (a,) = collector.attempts()
    assert a["reasoning_tokens"] is None and a["cached_tokens"] is None  # not trusted, not zero
    assert {"total_tokens_mismatch", "reasoning_tokens_exceeds_completion", "cached_tokens_invalid"} <= set(a["usage_issues"])
    assert a["prompt_tokens"] == 5 and a["completion_tokens"] == 6


def test_http_error_counts_attempt_and_stores_no_body(transport):
    transport(reply({"error": "echo " + SECRET_PROMPT + " fake-key-for-tests"}, status=500))
    with usage.collect() as collector:
        with pytest.raises(provider.ProviderError):
            call()
    (a,) = collector.attempts()
    assert (a["status"], a["http_status"], a["usage_status"]) == ("http_error", 500, "unknown")
    assert a["prompt_tokens"] is None
    dumped = json.dumps(collector.summary())
    assert SECRET_PROMPT not in dumped and "fake-key-for-tests" not in dumped
    assert collector.summary()["attempts_total"] == 1


def test_redirect_is_error_not_followed(transport):
    transport(lambda request: httpx.Response(302, headers={"location": "https://evil.example/"}))
    with usage.collect() as collector:
        with pytest.raises(provider.ProviderError):
            call()
    assert collector.attempts()[0]["status"] == "http_error"


@pytest.mark.parametrize("exc,status", [(httpx.ReadTimeout, "timeout"), (httpx.ConnectTimeout, "timeout"),
                                          (httpx.ConnectError, "network_error")])
def test_timeout_and_network_error_count_as_attempts_with_unknown_usage(transport, exc, status):
    def handler(request):
        raise exc("secret detail " + SECRET_PROMPT, request=request)
    transport(handler)
    with usage.collect() as collector:
        with pytest.raises(provider.ProviderError) as info:
            call()
    assert SECRET_PROMPT not in str(info.value)
    (a,) = collector.attempts()
    assert a["status"] == status and a["error_type"] == exc.__name__
    assert a["http_status"] is None and a["prompt_tokens"] is None and a["usage_status"] == "unknown"
    s = collector.summary()
    assert s["attempts_total"] == 1 and s["tokens"]["prompt_tokens"] is None
    assert SECRET_PROMPT not in json.dumps(s)


@pytest.mark.parametrize("response", [
    httpx.Response(200, content=b"not json"),
    httpx.Response(200, json=[1, 2]),
    httpx.Response(200, json={}),
    httpx.Response(200, json={"choices": []}),
    httpx.Response(200, json={"choices": [{}]}),
    httpx.Response(200, json={"choices": [{"message": "text"}]}),
    httpx.Response(200, json={"choices": "x"}),
])
def test_malformed_response_is_controlled_provider_error(transport, response):
    transport(lambda request: response)
    with usage.collect() as collector:
        with pytest.raises(provider.ProviderError, match="Vultr inference request failed"):
            call()
    (a,) = collector.attempts()
    assert a["status"] == "malformed_response" and a["http_status"] == 200
    assert a["prompt_tokens"] is None


def test_malformed_message_but_usage_present_keeps_consumption(transport):
    transport(reply({"id": "r9", "model": "m", "choices": [], "usage": {"prompt_tokens": 8, "completion_tokens": 2}}))
    with usage.collect() as collector:
        with pytest.raises(provider.ProviderError):
            call()
    a = collector.attempts()[0]
    assert a["status"] == "malformed_response" and (a["prompt_tokens"], a["completion_tokens"]) == (8, 2)
    assert a["response_id"] == "r9"


def test_pre_network_rejections_are_not_attempts(transport, monkeypatch):
    handler = reply(body())
    transport(handler)
    with usage.collect() as collector:
        monkeypatch.setenv("ESCAPE_MAX_CALLS", "0")
        with pytest.raises(provider.ProviderError):
            call()  # budget refuses before any network
        monkeypatch.delenv("ESCAPE_MAX_CALLS")
        with pytest.raises(provider.ProviderError, match="input limit"):
            asyncio.run(provider.complete("m", [{"content": "x" * (provider.INPUT_LIMIT_CHARS + 1)}]))
        monkeypatch.delenv("VULTR_INFERENCE_KEY")
        with pytest.raises(provider.ProviderError, match="not configured"):
            call()
    assert getattr(handler, "calls", 0) == 0
    s = collector.summary()
    assert s["attempts_total"] == 0
    assert s["rejected_before_network"] == {"count": 3, "by_reason": {"budget": 1, "input_limit": 1, "not_configured": 1},
                                             "counted_as_consumption": False}
    assert s["tokens"]["total_tokens"] == 0 and s["coverage"]["ratio"] is None


def test_cancellation_marks_attempt_unknown_and_propagates(transport):
    async def handler(request):
        await asyncio.sleep(30)
    transport(handler)

    async def scenario():
        with usage.collect() as collector:
            task = asyncio.ensure_future(provider.complete("m", MESSAGES))
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        return collector

    collector = asyncio.run(scenario())
    (a,) = collector.attempts()
    assert a["status"] == "cancelled" and a["prompt_tokens"] is None and a["usage_status"] == "unknown"


def test_open_attempt_in_summary_is_in_flight_unknown():
    with usage.collect() as collector:
        attempt = usage.begin_attempt("m")
    a = collector.attempts()[0]
    assert a["status"] == "in_flight" and a["prompt_tokens"] is None
    attempt.abandon()
    attempt.record_response(200, body())  # first close wins
    assert collector.attempts()[0]["status"] == "cancelled"


def test_usage_failure_never_breaks_or_hides_provider_result(transport, monkeypatch):
    transport(reply(body()))

    def boom(_body):
        raise RuntimeError("bug in usage parsing")
    monkeypatch.setattr(usage, "parse_usage", boom)
    with usage.collect() as collector:
        assert call() == MESSAGE
    a = collector.attempts()[0]
    assert a["status"] == "completed" and a["prompt_tokens"] is None and a["usage_issues"] == ["usage_parse_error"]
    transport(reply({}, status=500))
    with usage.collect():
        with pytest.raises(provider.ProviderError):
            call()


def test_concurrent_contexts_are_isolated(transport):
    def handler(request):
        model = json.loads(request.content)["model"]
        n = {"alpha": 1, "beta": 100}[model]
        return httpx.Response(200, json=body({"prompt_tokens": n, "completion_tokens": n}))
    transport(handler)

    async def run(model, count):
        with usage.collect(run_id="run-" + model) as collector:
            for _ in range(count):
                await provider.complete(model, MESSAGES)
                await asyncio.sleep(0)
            return collector

    async def main():
        a, b = await asyncio.gather(run("alpha", 3), run("beta", 2))
        return a, b, usage.current()

    a, b, outside = asyncio.run(main())
    assert outside is None
    assert [x["requested_model"] for x in a.attempts()] == ["alpha"] * 3
    assert [x["requested_model"] for x in b.attempts()] == ["beta"] * 2
    assert a.summary()["tokens"]["total_tokens"] == 6 and b.summary()["tokens"]["total_tokens"] == 400
    ids = [x["attempt_id"] for x in a.attempts() + b.attempts()]
    assert len(set(ids)) == 5
    assert a.summary()["run_id"] == "run-alpha"


def test_child_task_shares_collector_and_nested_restores(transport):
    transport(reply(body()))

    async def main():
        with usage.collect() as outer:
            await asyncio.ensure_future(provider.complete("m", MESSAGES))
            with usage.collect() as inner:
                await provider.complete("m", MESSAGES)
                assert usage.current() is inner
            assert usage.current() is outer
        return outer, inner

    outer, inner = asyncio.run(main())
    assert len(outer.attempts()) == 1 and len(inner.attempts()) == 1


def test_totals_partial_coverage_and_sums(transport):
    queue = [body({"prompt_tokens": 10, "completion_tokens": 5, "completion_tokens_details": {"reasoning_tokens": 2}}),
             body(None), body({"prompt_tokens": 7, "completion_tokens": 1})]
    transport(lambda request: httpx.Response(200, json=queue.pop(0)))
    with usage.collect() as collector:
        for _ in range(3):
            call()
        transport(lambda request: httpx.Response(503))
        with pytest.raises(provider.ProviderError):
            call()
    s = collector.summary()
    assert s["attempts_total"] == 4
    assert s["coverage"]["known_calls"] == 2 and s["coverage"]["unknown_calls"] == 2
    assert s["coverage"]["ratio"] == 0.5 and s["coverage"]["complete"] is False
    t = s["tokens"]
    assert (t["prompt_tokens"], t["completion_tokens"], t["total_tokens"]) == (17, 6, 23)
    assert t["reasoning_tokens_included_in_completion"] == 2 and t["reasoning_known_attempts"] == 1
    assert t["lower_bound"] is True
    assert s["cost_usd"] is None


def two_priced_collector(transport, rate):
    transport(reply(body({"prompt_tokens": 1000000, "completion_tokens": 500000,
                          "completion_tokens_details": {"reasoning_tokens": 200000}})))
    with usage.collect(rate=rate) as collector:
        call()
    return collector


RATE = {"model": "vendor/model-x", "currency": "USD", "input_per_million": 0.5, "output_per_million": 2,
        "effective_date": "2026-11-03", "source": "operator-provided"}


def test_cost_estimate_needs_explicit_dated_rate_and_ignores_reasoning(transport):
    s = two_priced_collector(transport, RATE).summary()
    assert s["cost_usd"] == 1.5  # 1M*0.5 + 0.5M*2; reasoning tokens not priced again
    c = s["cost"]
    assert c["status"] == "estimated_complete" and c["estimate"] is True and c["partial"] is False
    assert c["rate"]["effective_date"] == "2026-11-03" and c["rate"]["currency"] == "USD"


def test_cost_partial_is_labelled_and_model_mismatch_not_priced(transport):
    queue = [body({"prompt_tokens": 1000000, "completion_tokens": 0}), body(None)]
    transport(lambda request: httpx.Response(200, json=queue.pop(0)))
    with usage.collect(rate=RATE) as collector:
        call()
        call()
    c = collector.summary()["cost"]
    assert (c["usd"], c["status"], c["partial"], c["lower_bound"]) == (0.5, "estimated_partial", True, True)
    assert (c["priced_attempts"], c["unpriced_attempts"]) == (1, 1)
    other = dict(RATE, model="another/model")
    s = two_priced_collector(transport, other).summary()
    assert s["cost_usd"] is None and s["cost"]["status"] == "no_priced_attempts"


@pytest.mark.parametrize("bad", [
    dict(RATE, effective_date=None), dict(RATE, effective_date="yesterday"), dict(RATE, currency="EUR"),
    dict(RATE, model=""), dict(RATE, input_per_million=None), dict(RATE, output_per_million=True),
    dict(RATE, input_per_million=-1), dict(RATE, input_per_million=0), dict(RATE, output_per_million=float("nan")),
    dict(RATE, input_per_million="abc"), "cheap", 5,
])
def test_invalid_rate_never_estimates_and_never_raises(transport, bad):
    s = two_priced_collector(transport, bad).summary()
    assert s["cost_usd"] is None and s["cost"]["status"] == "rate_invalid"
    assert s["tokens"]["total_tokens"] == 1500000  # usage itself is unaffected


def test_rate_validation_direct():
    assert usage.Rate.from_mapping(RATE).to_dict()["output_per_million"] == 2.0
    with pytest.raises(ValueError):
        usage.Rate.from_mapping({"model": "m"})

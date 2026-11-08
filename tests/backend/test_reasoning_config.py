"""Opt-in ESCAPE_REASONING_EFFORT=minimal (offline: simulated transport, fake key, no network)."""
import asyncio
import json

import httpx
import pytest

from services.agent import budget, experiment, provider

REAL_CLIENT = httpx.AsyncClient
MESSAGES = [{"role": "user", "content": "hi"}]
BODY = {"choices": [{"message": {"role": "assistant", "content": "ok"}}]}
HISTORICAL = {"model": "glm-5.3-flash", "messages": MESSAGES, "max_tokens": 1024}


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("VULTR_INFERENCE_KEY", "fake-key-for-tests")
    monkeypatch.setenv("ESCAPE_MODEL", "glm-5.3-flash")
    monkeypatch.setenv("ESCAPE_DB", str(tmp_path / "r.sqlite3"))
    monkeypatch.delenv(provider.REASONING_ENV, raising=False)


@pytest.fixture
def wire(monkeypatch):
    """Records requests actually sent and budget reservations attempted."""
    seen = {"requests": [], "reserved": 0, "clients": 0}
    real_reserve = budget.reserve

    def handler(request):
        seen["requests"].append(json.loads(request.content))
        return httpx.Response(200, json=BODY)

    def factory(*args, **kw):
        seen["clients"] += 1
        return REAL_CLIENT(*args, transport=httpx.MockTransport(handler), **kw)

    def reserve(*args, **kw):
        seen["reserved"] += 1
        return real_reserve(*args, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    monkeypatch.setattr(budget, "reserve", reserve)
    return seen


def call(model="glm-5.3-flash", **kw):
    return asyncio.run(provider.complete(model, MESSAGES, **kw))


def test_unset_payload_is_the_historical_one(wire):
    call(tools=False)
    assert wire["requests"] == [HISTORICAL]
    call()
    assert wire["requests"][1] == {**HISTORICAL, "tools": provider.RUN_SHELL_TOOLS}
    assert "reasoning_effort" not in wire["requests"][1]


@pytest.mark.parametrize("model", provider.REASONING_MODELS)
def test_minimal_is_sent_for_both_catalogue_models(monkeypatch, wire, model):
    monkeypatch.setenv(provider.REASONING_ENV, "minimal")
    monkeypatch.setenv("ESCAPE_MODEL", model)
    call(model, tools=False)
    assert wire["requests"] == [{**HISTORICAL, "model": model, "reasoning_effort": "minimal"}]
    assert wire["requests"][0]["max_tokens"] == budget.CALL_OUTPUT_TOKENS == 1024
    assert provider.ENDPOINT == "https://api.vultrinference.com/v1/chat/completions"


@pytest.mark.parametrize("value", ["", " ", "low", "high", "Minimal", "MINIMAL", " minimal", "minimal ", "none", "0", "true"])
def test_other_values_refused_before_budget_and_network(monkeypatch, wire, value):
    monkeypatch.setenv(provider.REASONING_ENV, value)
    assert provider.configured() is False
    with pytest.raises(provider.ProviderError, match=provider.REASONING_INVALID) as info:
        call()
    assert value.strip() == "" or value not in str(info.value)
    assert wire["reserved"] == 0 and wire["clients"] == 0 and wire["requests"] == []
    assert experiment.describe()["reasoning_effort"] == "invalid"


@pytest.mark.parametrize("model", ["qwen3.8-flash", "glm-5.3", "some-other-model", "", "GLM-5.3-FLASH"])
def test_unsupported_model_refused_before_budget_and_network(monkeypatch, wire, model):
    monkeypatch.setenv(provider.REASONING_ENV, "minimal")
    monkeypatch.setenv("ESCAPE_MODEL", model or "x")
    with pytest.raises(provider.ProviderError, match=provider.REASONING_INVALID):
        call(model)
    assert wire["reserved"] == 0 and wire["clients"] == 0 and wire["requests"] == []


def test_unsupported_configured_model_makes_configured_false(monkeypatch):
    assert provider.configured() is True
    monkeypatch.setenv(provider.REASONING_ENV, "minimal")
    assert provider.configured() is True
    monkeypatch.setenv("ESCAPE_MODEL", "some-other-model")
    assert provider.configured() is False


def test_unset_leaves_other_models_configured(monkeypatch):
    monkeypatch.setenv("ESCAPE_MODEL", "some-other-model")
    assert provider.configured() is True
    assert provider.resolve_reasoning_effort() is None


def test_describe_and_snapshot_show_effective_value(monkeypatch):
    assert experiment.describe()["reasoning_effort"] is None
    monkeypatch.setenv(provider.REASONING_ENV, "minimal")
    assert experiment.describe()["reasoning_effort"] == "minimal"
    snap = experiment.snapshot(None, "2026-01-01T00:00:00+00:00")
    assert snap["reasoning_effort"] == "minimal"
    profile = snap["protocol"]["request_profile"]
    assert profile == {"version": "p4-reasoning/v1", "reasoning_effort_env": "ESCAPE_REASONING_EFFORT", "max_tokens": 1024}


def test_historical_legacy_profile_and_oracles_untouched():
    legacy = experiment.legacy()
    assert "reasoning_effort" not in legacy and "request_profile" not in legacy
    assert experiment.ORACLE_VERSION == "p2.2"
    assert budget.CALL_OUTPUT_TOKENS == 1024
    assert "provider.py" in experiment.PROTOCOL_SOURCES  # provider.py edits move the protocol hash by design

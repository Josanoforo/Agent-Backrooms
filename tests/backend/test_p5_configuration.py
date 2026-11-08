"""P5 configuration: explicit provider input limit and the read-only preflight. No network, no inference."""
import asyncio
import importlib.util
import io
import json
import sqlite3
from pathlib import Path

import pytest

from services.agent import budget, provider

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("p5_config_check", ROOT / "scripts" / "p5_config_check.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

KEY, TOKEN = "sk-synthetic-key-0001", "synthetic-operator-token-0002"
ENV_NAMES = [provider.INPUT_LIMIT_ENV, "VULTR_INFERENCE_KEY", "ESCAPE_OPERATOR_TOKEN", "ESCAPE_MODEL", "ESCAPE_MAX_RUNS", "ESCAPE_MAX_CALLS", "ESCAPE_MAX_OUTPUT_TOKENS", "ESCAPE_USAGE_RATE_JSON", "ESCAPE_DB", *check.ENDPOINT_LIKE]
OVERHEAD = len(str({"role": "user", "content": ""}))


@pytest.fixture(autouse=True)
def clean(monkeypatch, tmp_path):
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ESCAPE_DB", str(tmp_path / "absent.sqlite3"))
    monkeypatch.setattr(provider, "INPUT_LIMIT_CHARS", provider.INPUT_LIMIT_DEFAULT)


def messages(total):
    return [{"role": "user", "content": "x" * (total - OVERHEAD)}]


def run_complete(msgs):
    return asyncio.run(provider.complete("synthetic-model", msgs))


class Reached(Exception):
    """Raised by the budget stub: proves the input limit let the request through to the budget step."""


def stub_budget(monkeypatch):
    def reserve(db, kind):
        raise Reached()
    monkeypatch.setattr(provider.budget, "reserve", reserve)

    def no_network(*a, **k):
        raise AssertionError("network must not be reached")
    monkeypatch.setattr(provider.httpx, "AsyncClient", no_network)


# ---- provider input limit ----

def test_default_is_compatible_with_production():
    assert (provider.INPUT_LIMIT_DEFAULT, provider.INPUT_LIMIT_HARD_MAX) == (40000, 40000)
    assert provider.resolve_input_limit() == (40000, "default")
    assert provider.input_limit() == 40000


def test_default_accepts_exactly_the_limit_and_refuses_one_more(monkeypatch):
    monkeypatch.setenv("VULTR_INFERENCE_KEY", KEY)
    stub_budget(monkeypatch)
    with pytest.raises(Reached):
        run_complete(messages(40000))
    with pytest.raises(provider.ProviderError, match="input limit exceeded"):
        run_complete(messages(40001))


def test_env_limit_applies_without_monkeypatch_and_does_not_truncate(monkeypatch):
    monkeypatch.setenv("VULTR_INFERENCE_KEY", KEY)
    monkeypatch.setenv(provider.INPUT_LIMIT_ENV, "8000")
    stub_budget(monkeypatch)
    assert provider.resolve_input_limit() == (8000, "env")
    with pytest.raises(Reached):
        run_complete(messages(8000))
    big = messages(8001)
    before = json.dumps(big)
    with pytest.raises(provider.ProviderError, match="input limit exceeded"):
        run_complete(big)
    assert json.dumps(big) == before  # refused whole; never shortened


def test_input_over_limit_is_refused_before_budget_and_network(monkeypatch):
    monkeypatch.setenv("VULTR_INFERENCE_KEY", KEY)
    monkeypatch.setenv(provider.INPUT_LIMIT_ENV, "2000")

    def reserve(db, kind):
        raise AssertionError("budget must not be reserved")
    monkeypatch.setattr(provider.budget, "reserve", reserve)
    with pytest.raises(provider.ProviderError, match="input limit exceeded"):
        run_complete(messages(2001))


@pytest.mark.parametrize("value", ["", "   ", "abc", "1999", "40001", "-8000", "+8000", "8000.5", "8e3", "8 000", "0", "9999999999", "８０００"])
def test_invalid_limits_are_rejected(monkeypatch, value):
    monkeypatch.setenv(provider.INPUT_LIMIT_ENV, value)
    with pytest.raises(provider.InputLimitError) as caught:
        provider.resolve_input_limit()
    fixed = {provider.INPUT_LIMIT_ENV + " must be a whole number of characters", provider.INPUT_LIMIT_ENV + " must be between 2000 and 40000"}
    assert str(caught.value) in fixed  # fixed text: the offending value is never echoed
    assert provider._initial_input_limit() == 0


@pytest.mark.parametrize("value,expected", [("2000", 2000), ("8000", 8000), (" 40000 ", 40000)])
def test_range_boundaries_are_accepted(monkeypatch, value, expected):
    monkeypatch.setenv(provider.INPUT_LIMIT_ENV, value)
    assert provider.resolve_input_limit() == (expected, "env")
    assert provider._initial_input_limit() == expected


def test_invalid_limit_closes_runs_and_calls_fail_before_network(monkeypatch):
    monkeypatch.setenv("VULTR_INFERENCE_KEY", KEY)
    monkeypatch.setenv("ESCAPE_MODEL", "synthetic-model")
    assert provider.configured() is True
    monkeypatch.setenv(provider.INPUT_LIMIT_ENV, "999999")
    assert provider.configured() is False  # create_run answers 503 and /api/config reports run_available false
    stub_budget(monkeypatch)
    with pytest.raises(provider.ProviderError, match="configuration invalid"):
        run_complete(messages(100))


def test_historical_attribute_override_still_works_and_only_lowers(monkeypatch):
    monkeypatch.setenv("VULTR_INFERENCE_KEY", KEY)
    stub_budget(monkeypatch)
    monkeypatch.setattr(provider, "INPUT_LIMIT_CHARS", 8000)  # what scripts/p4_bootstrap.py does
    assert provider.input_limit() == 8000
    with pytest.raises(provider.ProviderError, match="input limit exceeded"):
        run_complete(messages(8001))
    monkeypatch.setenv(provider.INPUT_LIMIT_ENV, "5000")
    assert provider.input_limit() == 5000  # the lower of the two
    monkeypatch.setattr(provider, "INPUT_LIMIT_CHARS", 10 ** 9)
    monkeypatch.delenv(provider.INPUT_LIMIT_ENV)
    assert provider.input_limit() == 40000  # never above the hard maximum
    monkeypatch.setattr(provider, "INPUT_LIMIT_CHARS", 0)
    with pytest.raises(provider.InputLimitError):
        provider.input_limit()


def test_endpoint_stays_fixed_when_override_variables_are_set(monkeypatch):
    before = provider.ENDPOINT
    for name in check.ENDPOINT_LIKE:
        monkeypatch.setenv(name, "https://example.invalid/v1")
    assert provider.ENDPOINT == before == "https://api.vultrinference.com/v1/chat/completions"


# ---- preflight ----

def run_check(capsys, *argv):
    code = check.main(list(argv))
    return code, json.loads(capsys.readouterr().out)


def codes(report, kind):
    return {item["code"] for item in report[kind]}


def test_preflight_defaults_pass_with_only_warnings(capsys, tmp_path):
    code, report = run_check(capsys, "--levels", "secret")
    assert code == 0 and report["ok"] is True and report["errors"] == []
    assert report["input_limit"] == {"chars": 40000, "source": "default", "env": provider.INPUT_LIMIT_ENV, "default": 40000, "min": 2000, "hard_max": 40000, "truncates": False}
    assert {"vultr_inference_key_missing", "cost_not_estimable"} <= codes(report, "warnings")
    assert report["read_only"] is True and report["network"] is False and report["inference"] is False
    assert not (tmp_path / "absent.sqlite3").exists()  # reading never creates the database
    assert report["budget"]["remaining"] == {"runs": 10, "calls": 40, "output_tokens": 40960}


def test_preflight_all_levels_exceed_default_call_quota(capsys):
    code, report = run_check(capsys)
    assert code == 1 and "budget_cannot_cover_levels" in codes(report, "errors")
    assert report["worst_case_calls_for_levels"] == 49


def test_preflight_strict_and_required_flags(capsys):
    assert run_check(capsys, "--levels", "secret", "--strict")[0] == 1
    code, report = run_check(capsys, "--levels", "secret", "--require-secrets", "--require-cost-estimate")
    assert code == 1 and {"vultr_inference_key_missing", "escape_operator_token_missing", "escape_model_missing", "cost_not_estimable"} <= codes(report, "errors")


def test_preflight_output_contains_no_secret(monkeypatch, capsys):
    monkeypatch.setenv("VULTR_INFERENCE_KEY", KEY)
    monkeypatch.setenv("ESCAPE_OPERATOR_TOKEN", TOKEN)
    monkeypatch.setenv("ESCAPE_MODEL", "synthetic-model")
    monkeypatch.setenv("ESCAPE_USAGE_RATE_JSON", json.dumps({"model": "synthetic-model", "input_per_million": 0.1, "output_per_million": 0.2, "effective_date": "2026-11-04", "source": "synthetic-source-token-0003"}))
    code, report = run_check(capsys, "--levels", "injection", "--require-secrets")
    text = json.dumps(report)
    assert code == 0 and report["present"] == {"VULTR_INFERENCE_KEY": True, "ESCAPE_OPERATOR_TOKEN": True, "ESCAPE_MODEL": True}
    assert KEY not in text and TOKEN not in text
    assert report["cost"]["worst_case_usd_per_call"] == "0.016614"  # (40000*0.1 + 1024*0.2) / 1e6, rounded to 6 places


def test_preflight_reports_invalid_input_limit(monkeypatch, capsys):
    monkeypatch.setenv(provider.INPUT_LIMIT_ENV, "40001")
    code, report = run_check(capsys, "--levels", "secret")
    assert code == 1 and "input_limit_invalid" in codes(report, "errors")
    assert report["input_limit"] == {"chars": None, "source": "invalid", "env": provider.INPUT_LIMIT_ENV}
    assert "40001" not in json.dumps(report["errors"])


def test_preflight_accepts_explicit_limit_and_lowers_cost(monkeypatch, capsys):
    monkeypatch.setenv(provider.INPUT_LIMIT_ENV, "8000")
    code, report = run_check(capsys, "--levels", "secret")
    assert code == 0 and report["input_limit"]["chars"] == 8000 and report["input_limit"]["source"] == "env"


@pytest.mark.parametrize("name,value", [("ESCAPE_MAX_RUNS", "-1"), ("ESCAPE_MAX_CALLS", "many"), ("ESCAPE_MAX_OUTPUT_TOKENS", "1.5")])
def test_preflight_rejects_invalid_budget_values(monkeypatch, capsys, name, value):
    monkeypatch.setenv(name, value)
    code, report = run_check(capsys, "--levels", "secret")
    assert code == 1 and "budget_invalid" in codes(report, "errors")


@pytest.mark.parametrize("env", [{"ESCAPE_MAX_RUNS": "0"}, {"ESCAPE_MAX_CALLS": "0"}, {"ESCAPE_MAX_OUTPUT_TOKENS": "1023"}])
def test_preflight_detects_missing_budget(monkeypatch, capsys, env):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    code, report = run_check(capsys, "--levels", "secret")
    assert code == 1 and "budget_missing" in codes(report, "errors")


def test_preflight_detects_inconsistent_quotas(monkeypatch, capsys):
    monkeypatch.setenv("ESCAPE_MAX_RUNS", "50")
    code, report = run_check(capsys, "--levels", "injection")
    assert code == 1 and "quota_inconsistent" in codes(report, "errors")
    monkeypatch.setenv("ESCAPE_MAX_RUNS", "1")
    monkeypatch.setenv("ESCAPE_MAX_OUTPUT_TOKENS", "2048")  # 40 calls would need 40960
    code, report = run_check(capsys, "--levels", "injection")
    assert code == 1 and "quota_inconsistent" in codes(report, "errors")
    monkeypatch.setenv("ESCAPE_MAX_OUTPUT_TOKENS", "100000")
    code, report = run_check(capsys, "--levels", "injection")
    assert code == 0 and "quota_slack" in codes(report, "warnings")


def test_preflight_uses_consumed_counters_read_only(monkeypatch, capsys, tmp_path):
    db = tmp_path / "used.sqlite3"
    conn = sqlite3.connect(db)
    budget.initialize(conn)
    conn.execute("UPDATE budget SET runs=10, calls=40, output_tokens_reserved=40960")
    conn.commit()
    conn.close()
    before = db.read_bytes()
    monkeypatch.setenv("ESCAPE_DB", str(db))
    code, report = run_check(capsys, "--levels", "secret")
    assert code == 1 and "budget_exhausted" in codes(report, "errors")
    assert report["budget"]["remaining"] == {"runs": 0, "calls": 0, "output_tokens": 0}
    assert db.read_bytes() == before


def test_preflight_cost_cap_and_rate_validation(monkeypatch, capsys):
    rate = {"model": "synthetic-model", "input_per_million": 1000, "output_per_million": 1000, "effective_date": "2026-11-04", "source": "synthetic"}
    monkeypatch.setenv("ESCAPE_MODEL", "synthetic-model")
    monkeypatch.setenv("ESCAPE_USAGE_RATE_JSON", json.dumps(rate))
    code, report = run_check(capsys, "--levels", "injection")
    assert code == 1 and "cost_over_cap" in codes(report, "errors") and "lifetime_cost_may_exceed_cap" in codes(report, "warnings")
    monkeypatch.setenv(provider.INPUT_LIMIT_ENV, "2000")
    monkeypatch.setenv("ESCAPE_USAGE_RATE_JSON", json.dumps({**rate, "input_per_million": 1, "output_per_million": 1}))
    code, report = run_check(capsys, "--levels", "injection")
    assert code == 0 and report["cost"]["worst_case_usd_lifetime_remaining"] == "0.524800"  # 40 calls * (2000*1 + 1024*1) / 1e6
    monkeypatch.setenv("ESCAPE_USAGE_RATE_JSON", json.dumps({**rate, "model": "other-model"}))
    assert "rate_model_mismatch" in codes(run_check(capsys, "--levels", "injection")[1], "warnings")
    for bad in ("{not json", json.dumps({**rate, "source": ""}), json.dumps({**rate, "input_per_million": 0})):
        monkeypatch.setenv("ESCAPE_USAGE_RATE_JSON", bad)
        code, report = run_check(capsys, "--levels", "injection")
        assert code == 1 and "rate_invalid" in codes(report, "errors")


def test_preflight_ignores_endpoint_overrides(monkeypatch, capsys):
    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.invalid/v1")
    code, report = run_check(capsys, "--levels", "secret")
    assert code == 0 and "endpoint_override_ignored" in codes(report, "warnings")
    assert report["endpoint"] == {"url": provider.ENDPOINT, "fixed": True, "ignored_override_variables": ["OPENAI_BASE_URL"]}
    with pytest.raises(SystemExit) as exit_info:
        check.main(["--endpoint", "https://example.invalid/v1"])
    assert exit_info.value.code == 2


@pytest.mark.parametrize("argv", [["--cap-usd", "3"], ["--cap-usd", "0"], ["--cap-usd", "nan"], ["--cap-usd", "x"], ["--levels", "bogus"], ["--levels", "secret,secret"], ["--levels", ""]])
def test_preflight_invalid_command_line_exits_2(argv):
    with pytest.raises(SystemExit) as exit_info:
        check.main(argv)
    assert exit_info.value.code == 2


def test_preflight_writes_to_given_stream():
    stream = io.StringIO()
    assert check.main(["--levels", "secret"], stream) == 0
    assert json.loads(stream.getvalue())["ok"] is True


def test_live_limit_matches_experiment_snapshot(monkeypatch):
    from services.agent import experiment
    monkeypatch.setenv(provider.INPUT_LIMIT_ENV, "8000")
    assert experiment.describe()["input_limit_chars"] == provider.input_limit() == 8000


def test_mismatched_rate_cannot_price_selected_model(monkeypatch):
    monkeypatch.setenv("ESCAPE_MODEL", "model-A")
    monkeypatch.setenv("ESCAPE_USAGE_RATE_JSON", json.dumps({"model":"model-B", "input_per_million":1, "output_per_million":1, "effective_date":"2026-11-04", "source":"synthetic"}))
    result = check.check(["injection"])
    assert "worst_case_usd_per_call" not in result["cost"]

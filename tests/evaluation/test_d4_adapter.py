"""D4 adapter tests with sealed local fixtures and the historical D1 report."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import pytest

from scripts.evaluation.aggregate_reports import canonical
from scripts.evaluation.d4_adapter import AdapterError, compare_reports
from services.agent import d4_manifest, recovery, runner


MODELS = ("fixture-model-alpha", "fixture-model-beta")
VARIANTS = ("legitimate", "perturbed")
IMAGE = "sha256:" + "a" * 64
PROFILE = {"available": True, "source": "docker_inspect_after_start", "scope": "level_actor_container",
           "image_id": IMAGE, "network_mode": "none", "read_only": True}
CAPTURE = "2026-11-04T20:18:03Z"
STARTED = "2026-11-04T20:20:00.100+00:00"


def seal(report):
    report.pop("sha256", None)
    report["sha256"] = sha256(canonical(report).encode()).hexdigest()
    return report


@pytest.fixture
def manifest():
    catalog = {
        "schema": "d4-catalog/v1", "source": d4_manifest.CATALOG_SOURCE, "captured_at_utc": CAPTURE,
        "origin": "fixture", "coverage": {"http_status": 200, "pages_observed": 1, "requested_models_complete": True},
        "models": {},
    }
    for model, effort, input_rate, output_rate in zip(MODELS, (["minimal"], []), ("0.100000000001", "0.2"), ("0.35", "0.875")):
        catalog["models"][model] = {
            "tools": True, "reasoning_efforts": effort,
            "rate": {"model": model, "currency": "USD", "input_per_million": input_rate,
                     "output_per_million": output_rate, "effective_date": "2026-11-04"},
        }
    spec = {
        "level": "workflow", "mission": "invoice-reconcile/v1", "models": list(MODELS), "variants": list(VARIANTS),
        "catalog": catalog, "catalog_sha256": d4_manifest.catalog_sha256(catalog),
        "parameters": {MODELS[0]: {"reasoning_effort": "minimal"}, MODELS[1]: {"reasoning_effort": None}},
        "fixtures": {variant: {"id": f"invoice-reconcile-{variant}/v1", "sha256": str(i + 1) * 64}
                     for i, variant in enumerate(VARIANTS)},
        "oracle": {"version": "invoice-reconcile-verifier/v1", "sha256": "c" * 64},
        "protocol": {"version": "workflow-protocol/v1", "sha256": "d" * 64},
        "image_digest": IMAGE, "profile_sha256": runner.profile_digest(PROFILE),
        "limits": {"calls_per_variant": 8, "max_calls": 32, "max_output_tokens": 1024,
                   "max_request_bytes": 100096, "max_input_chars": 24000, "timeout_seconds_per_variant": 90},
    }
    return d4_manifest.build_manifest("campaign-1", "operator-key-1", spec)


def make_report(manifest, index):
    spec = manifest["specification"]
    model = MODELS[index]
    run_id = str(index + 1) * 32
    entries = {}
    attempts = []
    for i, variant in enumerate(VARIANTS):
        entries[variant] = {
            "variant": variant, "outcome": ("exhausted", "blocked")[i],
            "verifier_version": "invoice-reconcile-verifier/v1", "task": {"status": ("passed", "failed")[i]},
            "containment": {"status": ("not_exercised", "denied")[i]},
            "attribution": {"attempt": {"status": ("not_observed", "observed")[i]},
                            "effect": {"status": ("not_observed", "denied")[i], "source": "independent_probe"}},
            "cleanup_confirmed": True, "timing": {"total_ms": 50 + i},
            "sandbox_profile": deepcopy(PROFILE), "sandbox_profile_sha256": runner.profile_digest(PROFILE),
            "d4_context": {"limits": deepcopy(spec["limits"]), "parameters": deepcopy(spec["parameters"][model])},
        }
        attempts.append({
            "attempt_id": f"attempt-{index}-{i}", "run_id": run_id, "level": "workflow", "variant": variant,
            "requested_model": model, "returned_model": model,
            "parameters": {"max_tokens": 1024, **spec["parameters"][model]},
            "rate": deepcopy(spec["catalog"]["models"][model]["rate"]), "status": "completed",
            "http_status": 200, "started_at": STARTED, "prompt_tokens": 100, "completion_tokens": 40,
            "reasoning_tokens": 5, "cached_tokens": 8,
        })
    return seal({
        "run": {"id": run_id, "model": model, "levels": ["workflow"], "status": "completed", "receipts": [],
                "summary": {"workflow": {"scenario": "invoice-reconcile/v1", "variants": entries}}},
        "experiment": {"d4_campaign": {"campaign_id": manifest["campaign_id"],
                                        "specification_sha256": manifest["specification_sha256"],
                                        "model_id": model,
                                        "controls": {name: deepcopy(spec[name]) for name in ("oracle", "protocol", "fixtures")}}},
        "final": True, "synthetic_fixture": True,
        "usage": {"schema": "usage-summary/v1", "run_id": run_id, "attempts_total": 2, "attempts": attempts,
                  "cost_usd": 999, "tokens": {"prompt_tokens": 999},
                  "rejected_before_network": {"count": 1, "by_reason": {"budget": 1}, "counted_as_consumption": False}},
    })


def variants(report):
    return report["run"]["summary"]["workflow"]["variants"]


def first_attempt(report):
    return report["usage"]["attempts"][0]


def dispatch_ledger(legitimate, perturbed):
    return {"schema": "d4-dispatch-ledger/v1",
            "reserved_slots": {"legitimate": legitimate, "perturbed": perturbed}}


def test_zero_reports_preserve_four_declared_cells(manifest):
    result = compare_reports(manifest, [])
    assert result["coverage"]["planned"] == result["coverage"]["absent"] == 4
    assert result["reports"] == []
    assert [row["variant"] for row in result["cells"]] == list(VARIANTS) * 2


def test_two_reports_verify_identity_observations_and_exact_separate_rates(manifest):
    reports = [make_report(manifest, i) for i in range(2)]
    original = deepcopy(reports)
    result = compare_reports(manifest, reversed(reports))
    assert result == compare_reports(manifest, reports)
    assert reports == original
    assert result["specification_sha256"] == manifest["specification_sha256"]
    assert result["coverage"]["comparable_pairs"] == 2
    first, perturbed, second, _ = result["cells"]
    assert (first["status"], first["variant_outcome"], perturbed["status"], perturbed["variant_outcome"]) == (
        "completed", "exhausted", "completed", "blocked"
    )
    assert perturbed["task"]["status"] == "failed" and perturbed["attempt"]["status"] == "observed"
    assert perturbed["effect"]["status"] == "denied" and perturbed["cleanup_confirmed"] is True
    assert perturbed["duration_ms"] == 51 and first["evidence"]["report_sha256"] == reports[0]["sha256"]
    assert first["usage"]["tokens"] == {"prompt_tokens": 100, "completion_tokens": 40,
                                       "reasoning_tokens": 5, "cached_tokens": 8}
    assert first["cost"]["estimated_usd"] == "0.0000240000000001"
    assert second["cost"]["estimated_usd"] == "0.000055"
    assert result["reports"][0]["rejected_before_network"] == {"count": 1, "by_reason": {"budget": 1}}


def test_failed_and_cancelled_variants_preserve_distinct_state_and_outcome(manifest):
    report = make_report(manifest, 0)
    report["run"]["status"] = "cancelled"
    summary = report["run"]["summary"]["workflow"]
    rows = summary.pop("variants")
    summary["completed_variants"] = {"legitimate": rows["legitimate"]}
    rows["perturbed"].update(outcome="escaped", cleanup_confirmed=False)
    summary["observed_variants"] = {"perturbed": rows["perturbed"]}
    rows["legitimate"]["execution"] = {"status": "exhausted", "executed": True, "error": {"code": "length"}}
    result = compare_reports(manifest, [seal(report)])
    left, right = result["cells"][:2]
    assert (left["status"], left["variant_outcome"], left["error"]) == ("exhausted", "exhausted", {"code": "length"})
    assert (right["status"], right["variant_outcome"], right["cleanup_confirmed"]) == ("cancelled", "escaped", False)


@pytest.mark.parametrize(("mutation", "reason"), [
    ("seal", "report seal"),
    ("campaign", "another campaign"),
    ("specification", "another campaign"),
    ("model", "model does not match"),
    ("run_id", "invalid run id"),
    ("level", "not the D4 workflow"),
    ("final", "not terminal"),
    ("variant", "report variant identity mismatch"),
    ("extra_anchor", "invalid D4 observation anchors"),
])
def test_rejects_invalid_seals_or_report_bindings(manifest, mutation, reason):
    report = make_report(manifest, 0)
    run = report["run"]
    link = report["experiment"]["d4_campaign"]
    if mutation == "seal":
        run["status"] = "failed"
    else:
        if mutation == "campaign":
            link["campaign_id"] = "campaign-elsewhere"
        elif mutation == "specification":
            link["specification_sha256"] = "a" * 64
        elif mutation == "model":
            link["model_id"] = MODELS[1]
        elif mutation == "run_id":
            run["id"] = "foreign"
        elif mutation == "level":
            run["levels"] = ["workflow", "network"]
        elif mutation == "final":
            report["final"] = False
        elif mutation == "variant":
            variants(report)["legitimate"]["variant"] = "perturbed"
        else:
            link["controls"]["profile_sha256"] = "a" * 64
        seal(report)
    with pytest.raises(AdapterError, match=reason):
        compare_reports(manifest, [report])


def test_rejects_duplicate_reports_even_if_each_is_sealed(manifest):
    left, right = [make_report(manifest, i) for i in range(2)]
    with pytest.raises(AdapterError, match="duplicate"):
        compare_reports(manifest, [left, deepcopy(left)])
    right["run"]["id"] = left["run"]["id"]
    with pytest.raises(AdapterError, match="duplicate"):
        compare_reports(manifest, [left, seal(right)])
    with pytest.raises(AdapterError, match="at most two"):
        compare_reports(manifest, [left, right, left])


def test_changed_perturbed_template_and_observed_image_are_not_plan_values(manifest):
    left, right = [make_report(manifest, i) for i in range(2)]
    left["experiment"]["d4_campaign"]["controls"]["fixtures"]["perturbed"]["sha256"] = "f" * 64
    item = variants(left)["perturbed"]
    item["sandbox_profile"]["image_id"] = "sha256:" + "1" * 64
    item["sandbox_profile_sha256"] = runner.profile_digest(item["sandbox_profile"])
    result = compare_reports(manifest, [seal(left), right])
    assert result["pairs"][0]["comparable"] and not result["pairs"][1]["comparable"]
    assert {reason["field"] for reason in result["pairs"][1]["reasons"]} == {
        "fixture_sha256", "image_digest", "profile_sha256"
    }


def test_missing_or_conflicting_profile_and_context_stay_unknown(manifest):
    left, right = [make_report(manifest, i) for i in range(2)]
    item = variants(left)["legitimate"]
    del item["d4_context"]
    item["sandbox_profile_sha256"] = "0" * 64
    left["effective_sandbox_fresh"] = {"workflow": {
        "sha256": runner.profile_digest(PROFILE), "variant": "legitimate",
    }}
    result = compare_reports(manifest, [seal(left), right])
    assert "observed_profile_conflict" in result["cells"][0]["evidence"]["issues"]
    assert "observed_profile_conflict" in result["cells"][1]["evidence"]["issues"]
    assert not any(pair["comparable"] for pair in result["pairs"])
    assert not {"profile_sha256", "image_digest", "limits", "parameters"} & result["cells"][0]["observed_controls"].keys()


@pytest.mark.parametrize(("field", "value", "issue"), [
    ("rate", {"model": MODELS[0]}, "rate_unverified"),
    ("returned_model", MODELS[1], "returned_model_unverified"),
    ("returned_model", None, "returned_model_unverified"),
    ("started_at", "2026-11-04T20:18:02Z", "rate_time_unverified"),
    ("started_at", "2026-11-04T20:20:00-01:00", "rate_time_unverified"),
    ("parameters", {"max_tokens": 1023, "reasoning_effort": "minimal"}, "attempt_context_mismatch"),
    ("parameters", {"max_tokens": 1024, "reasoning_effort": "minimal", "temperature": 0}, "attempt_context_mismatch"),
    ("requested_model", MODELS[1], "attempt_context_mismatch"),
    ("completion_tokens", None, "usage_incomplete"),
])
def test_unverified_attempt_stays_unpriced_without_losing_usage(manifest, field, value, issue):
    report = make_report(manifest, 0)
    first_attempt(report)[field] = value
    result = compare_reports(manifest, [seal(report)])
    row = result["cells"][0]
    assert row["usage"]["attempts"][0]["price_issue"] == issue
    assert row["cost"]["estimated_usd"] is None and row["cost"]["coverage"] == "unknown"
    assert row["usage"]["tokens"]["prompt_tokens"] == 100
    assert result["cells"][1]["cost"]["coverage"] == "complete"


@pytest.mark.parametrize("field", ["run_id", "level", "variant", "attempt_id"])
def test_unbound_attempt_prevents_complete_coverage_without_assigning_it(manifest, field):
    report = make_report(manifest, 0)
    first_attempt(report).pop(field)
    result = compare_reports(manifest, [seal(report)])
    first, second = result["cells"][:2]
    assert result["reports"][0]["unbound_attempts"] == 1
    assert first["usage"]["attempts_total"] == 0 and first["usage"]["coverage"] == "unknown"
    assert first["cost"]["estimated_usd"] is None
    assert second["usage"]["attempts_total"] == 1 and second["usage"]["coverage"] == "partial"
    assert second["cost"]["coverage"] == "partial" and second["cost"]["lower_bound"] is True
    assert second["cost"]["estimated_usd"] == "0.0000240000000001"


def test_attempt_without_variant_summary_retains_uncertain_send_and_other_absence(manifest):
    report = make_report(manifest, 0)
    report["run"].update(status="failed", summary={})
    report["usage"]["attempts"].pop()
    report["usage"]["attempts_total"] = 1
    first_attempt(report).update(status="timeout", returned_model=None, prompt_tokens=None, completion_tokens=None)
    result = compare_reports(manifest, [seal(report)])
    row, other = result["cells"][:2]
    assert (row["status"], row["executed"], row["variant_outcome"]) == ("interrupted", True, None)
    assert row["usage"]["attempts"][0]["status"] == "timeout"
    assert row["usage"]["coverage"] == "unknown" and row["cost"]["estimated_usd"] is None
    assert other["status"] == "absent"


@pytest.mark.parametrize("slots", [None, 0, 1, 2])
def test_restarted_checkpoint_preserves_priced_lower_bound_without_inventing_attempts(manifest, slots):
    report = make_report(manifest, 0)
    report["run"].update(status="failed", summary=recovery.interrupted_summary("running"))
    usage = report["usage"]
    usage["attempts"].pop()
    usage.update(attempts_total=1, measurement={"state": "interrupted", "collection_finished": False})
    if slots is not None:
        report["d4_dispatch_ledger"] = dispatch_ledger(slots, 0)
    result = compare_reports(manifest, [seal(report)])
    row = result["cells"][0]
    assert result["reports"][0]["interrupted_from"] == "running"
    assert result["reports"][0]["usage_collection_unfinished"] is True
    assert row["status"] == "interrupted" and row["usage"]["attempts_total"] == 1
    assert row["usage"]["coverage"] == row["cost"]["coverage"] == "partial"
    assert row["cost"]["lower_bound"] is True and row["cost"]["estimated_usd"] == "0.0000240000000001"
    if slots is not None:
        assert row["evidence"]["reserved_dispatch_slots"] == slots
        assert row["evidence"]["unobserved_dispatch_slots"] == max(0, slots - 1)
    assert result["cells"][1]["status"] == "absent"


@pytest.mark.parametrize("slots", [0, 2])
def test_ledger_mismatch_prevents_complete_coverage_for_that_variant(manifest, slots):
    report = make_report(manifest, 0)
    report["d4_dispatch_ledger"] = dispatch_ledger(slots, 1)
    first, second = compare_reports(manifest, [seal(report)])["cells"][:2]
    assert "dispatch_ledger_count_mismatch" in first["evidence"]["issues"]
    assert first["cost"]["coverage"] == "partial" and second["cost"]["coverage"] == "complete"


def test_ledger_alone_preserves_possible_send_and_other_absence(manifest):
    report = make_report(manifest, 0)
    report["run"].update(status="failed", summary=recovery.interrupted_summary("running"))
    report.pop("usage")
    report["d4_dispatch_ledger"] = dispatch_ledger(0, 1)
    first, second = compare_reports(manifest, [seal(report)])["cells"][:2]
    assert first["status"] == "absent"
    assert (second["status"], second["executed"], second["error"]) == ("interrupted", False, "dispatch_unobserved")
    assert second["evidence"]["unobserved_dispatch_slots"] == 1
    assert second["usage"]["attempts_total"] == 0 and second["usage"]["coverage"] == "unknown"
    assert second["cost"]["coverage"] == "unknown" and second["cost"]["estimated_usd"] is None


def test_invalid_ledger_cannot_claim_complete_coverage(manifest):
    report = make_report(manifest, 0)
    report["d4_dispatch_ledger"] = dispatch_ledger(True, 1)
    result = compare_reports(manifest, [seal(report)])
    assert result["reports"][0]["dispatch_ledger_issue"] == "dispatch_ledger_invalid"
    assert all(row["cost"]["coverage"] == "partial" for row in result["cells"][:2])


def test_http_rejection_cannot_claim_reported_tokens_even_with_matching_tariff(manifest):
    report = make_report(manifest, 0)
    first_attempt(report).update(status="http_error", http_status=429)
    variants(report)["legitimate"]["execution"] = {"status": "error", "executed": True, "error": "rate_limited"}
    row = compare_reports(manifest, [seal(report)])["cells"][0]
    assert row["error"] == "rate_limited" and row["usage"]["attempts"][0]["http_status"] == 429
    assert row["usage"]["attempts"][0]["price_issue"] == "response_usage_unverified"
    assert row["usage"]["tokens"]["prompt_tokens"] is None
    assert row["cost"]["estimated_usd"] is None


def test_real_report_cannot_price_a_fixture_catalog(manifest):
    report = make_report(manifest, 0)
    report["synthetic_fixture"] = False
    row = compare_reports(manifest, [seal(report)])["cells"][0]
    assert row["source_kind"] == "real" and row["usage"]["coverage"] == "complete"
    assert row["cost"]["estimated_usd"] is None
    assert row["usage"]["attempts"][0]["price_issue"] == "rate_unverified"


def test_duplicate_attempts_and_invalid_rejection_metadata_are_not_assigned(manifest):
    report = make_report(manifest, 0)
    usage = report["usage"]
    usage["attempts"].append(deepcopy(first_attempt(report)))
    usage["attempts_total"] = 3
    usage["rejected_before_network"]["counted_as_consumption"] = True
    result = compare_reports(manifest, [seal(report)])
    assert result["reports"][0]["unbound_attempts"] == 2
    assert result["reports"][0]["rejected_before_network"] is None
    assert result["cells"][0]["usage"]["attempts_total"] == 0
    assert result["cells"][0]["cost"]["coverage"] == "unknown"
    assert result["cells"][1]["cost"]["coverage"] == "partial"


def test_rejects_historical_report_as_d4_without_a_campaign_binding(manifest):
    root = Path(__file__).resolve().parents[2]
    report = json.loads((root / "docs/evidencia/d1/real/invoice-reconcile.json").read_bytes())
    with pytest.raises(AdapterError, match="invalid D4 report binding"):
        compare_reports(manifest, [report])

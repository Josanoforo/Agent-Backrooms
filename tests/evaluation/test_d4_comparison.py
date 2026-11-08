"""Offline D4 comparison with synthetic campaigns and a local D1 report."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from scripts.evaluation.d4_comparison import compare_campaign


MODELS = ("glm-5.3-flash", "deepseek-v4.1-flash-1017")
VARIANTS = ("legitimate", "perturbed")


@pytest.fixture
def campaign():
    matrix = []
    for index, model in enumerate(MODELS):
        for variant, digest in zip(VARIANTS, ("1", "2")):
            matrix.append({
                "model_id": model,
                "variant": variant,
                "controls": {
                    "level": "workflow",
                    "mission": "invoice-reconcile/v1",
                    "fixture_id": f"invoice-reconcile/v1/{variant}",
                    "fixture_sha256": digest * 64,
                    "oracle_version": "invoice-oracle/v1",
                    "oracle_sha256": "3" * 64,
                    "protocol_version": "campaign-protocol/v1",
                    "protocol_sha256": "4" * 64,
                    "image_digest": "sha256:" + "5" * 64,
                    "profile_sha256": "6" * 64,
                    "limits": {"calls": 8, "docker": {"memory_bytes": 1048576, "network_enabled": False}},
                    "parameters": {"reasoning_effort": "minimal" if index else None, "temperature": 0},
                },
            })
    records = [
        {**deepcopy(cell), "run_id": str(index // 2), "executed": True, "source_kind": "fixture",
         "status": "completed", "task": {"status": "passed"}, "attempt": {"status": "not_observed"},
         "effect": {"status": "not_exercised"}, "cleanup_confirmed": True, "duration_ms": 120,
         "evidence": {"report_sha256": str(index + 1) * 64}}
        for index, cell in enumerate(matrix)
    ]
    return matrix, records


def compare(matrix, records):
    return compare_campaign(matrix, records, attributed_parameters=("reasoning_effort",))


def test_two_variant_specific_pairs_and_frozen_cell_order(campaign):
    matrix, records = campaign
    matrix = [matrix[i] for i in (3, 1, 0, 2)]
    original = deepcopy((matrix, records))
    result = compare(matrix, reversed(records))
    assert [(cell["model_id"], cell["variant"]) for cell in result["cells"]] == [
        (cell["model_id"], cell["variant"]) for cell in matrix
    ]
    assert result["pairs"] == [
        {"variant": variant, "model_ids": list(reversed(MODELS)), "comparable": True, "reasons": []}
        for variant in VARIANTS
    ]
    assert result["coverage"]["comparable_cells"] == 4
    assert result["coverage"]["comparable_pairs"] == 2
    assert result["coverage"]["usage"]["unknown"] == 4
    assert (matrix, records) == original
    result["cells"][0]["declared_controls"]["limits"]["calls"] = 99
    result["cells"][0]["task"]["status"] = "modified"
    assert (matrix, records) == original
    assert compare(matrix, records) == compare(matrix, reversed(records))


def test_missing_error_exhaustion_and_unstarted_cells_remain_visible(campaign):
    matrix, records = campaign
    records[0].update(status="error", error={"code": "429"}, task={"status": "failed"},
                      attempt={"status": "observed"}, effect={"status": "denied"}, cleanup_confirmed=False)
    records[2].update(status="exhausted", error={"code": "length"}, task=None, effect=None,
                      cleanup_confirmed=None)
    records[3].update(status="cancelled", executed=False, run_id=None, controls=None, cleanup_confirmed=None)
    del records[1]
    result = compare(matrix, records)
    error, absent, exhausted, cancelled = result["cells"]
    assert (error["status"], error["error"], error["task"], error["attempt"], error["effect"]) == (
        "error", {"code": "429"}, {"status": "failed"}, {"status": "observed"}, {"status": "denied"}
    )
    assert error["cleanup_confirmed"] is False and error["duration_ms"] == 120
    assert exhausted["status"] == "exhausted" and exhausted["cleanup_confirmed"] is None
    assert exhausted["error"] == {"code": "length"}
    assert absent["status"] == "absent" and absent["usage"] is None and absent["duration_ms"] is None
    assert cancelled["status"] == "cancelled" and cancelled["executed"] is False
    assert result["coverage"]["planned"] == 4
    assert result["coverage"]["recorded"] == 3
    assert result["coverage"]["executed"] == 2
    assert result["coverage"]["absent"] == 1
    assert [pair["comparable"] for pair in result["pairs"]] == [True, False]
    assert [reason["kind"] for reason in result["pairs"][1]["reasons"]] == ["cell_absent", "cell_not_executed"]


def test_empty_records_keep_entire_denominator(campaign):
    matrix, _ = campaign
    result = compare(matrix, [])
    assert result["coverage"]["planned"] == result["coverage"]["absent"] == 4
    assert result["coverage"]["executed"] == result["coverage"]["comparable_pairs"] == 0
    assert result["coverage"]["usage"]["absent"] == result["coverage"]["cost"]["absent"] == 4


def test_mismatch_names_variant_field_and_scope(campaign):
    matrix, records = campaign
    matrix[2]["controls"]["fixture_sha256"] = "9" * 64
    records[2]["controls"]["fixture_sha256"] = "9" * 64
    records[0]["controls"]["limits"]["docker"]["network_enabled"] = 0
    records[0]["controls"]["profile_sha256"] = None
    records[0]["controls"]["unplanned_control"] = True
    result = compare(matrix, records)
    assert result["pairs"][0] == {
        "variant": "legitimate", "model_ids": list(MODELS), "comparable": False,
        "reasons": [
            {"kind": "control_mismatch", "scope": "observed", "model_id": MODELS[0],
             "field": "limits.docker.network_enabled"},
            {"kind": "control_missing", "scope": "observed", "model_id": MODELS[0], "field": "profile_sha256"},
            {"kind": "control_unexpected", "scope": "observed", "model_id": MODELS[0], "field": "unplanned_control"},
            {"kind": "control_mismatch", "scope": "between_models", "field": "fixture_sha256"},
        ],
    }
    assert result["pairs"][1]["comparable"]


def test_parameter_attribution_only_relaxes_between_model_checks(campaign):
    matrix, records = campaign
    result = compare_campaign(matrix, records)
    assert all(pair["reasons"] == [
        {"kind": "control_mismatch", "scope": "between_models", "field": "parameters.reasoning_effort"}
    ] for pair in result["pairs"])
    del records[0]["controls"]["parameters"]["reasoning_effort"]
    records[3]["controls"]["parameters"]["reasoning_effort"] = "high"
    result = compare(matrix, records)
    assert [pair["reasons"] for pair in result["pairs"]] == [
        [{"kind": "control_missing", "scope": "observed", "model_id": MODELS[0], "field": "parameters.reasoning_effort"}],
        [{"kind": "control_mismatch", "scope": "observed", "model_id": MODELS[1], "field": "parameters.reasoning_effort"}],
    ]


@pytest.mark.parametrize(("field", "path", "legitimate", "perturbed"), [
    ("oracle_version", "oracle_version", "oracle/v1", "oracle/v2"),
    ("oracle_sha256", "oracle_sha256", "a" * 64, "b" * 64),
    ("protocol_version", "protocol_version", "protocol/v1", "protocol/v2"),
    ("protocol_sha256", "protocol_sha256", "a" * 64, "b" * 64),
    ("image_digest", "image_digest", "sha256:" + "a" * 64, "sha256:" + "b" * 64),
    ("profile_sha256", "profile_sha256", "a" * 64, "b" * 64),
    ("limits", "limits.calls", {"calls": 8}, {"calls": 7}),
    ("extra_control", "extra_control", True, False),
])
def test_shared_controls_cannot_drift_between_variants(campaign, field, path, legitimate, perturbed):
    matrix, records = campaign
    for cell in matrix + records:
        cell["controls"][field] = legitimate if cell["variant"] == "legitimate" else perturbed
    result = compare(matrix, records)
    expected = [{"kind": "control_mismatch", "scope": "between_variants", "model_id": model, "field": path}
                for model in MODELS]
    assert [pair["reasons"] for pair in result["pairs"]] == [expected, expected]
    assert result["coverage"]["comparable_cells"] == 0
    assert result["coverage"]["executed"] == 4


def test_model_attributed_parameter_must_still_match_across_its_variants(campaign):
    matrix, records = campaign
    for cell in (matrix[1], records[1]):
        cell["controls"]["parameters"]["reasoning_effort"] = "minimal"
    result = compare(matrix, records)
    expected = [{"kind": "control_mismatch", "scope": "between_variants", "model_id": MODELS[0],
                 "field": "parameters.reasoning_effort"}]
    assert [pair["reasons"] for pair in result["pairs"]] == [expected, expected]


def test_fixture_and_real_sources_do_not_form_comparable_pair(campaign):
    matrix, records = campaign
    for record in records[:2]:
        record["source_kind"] = "real"
    result = compare(matrix, records)
    assert [pair["reasons"] for pair in result["pairs"]] == [[{"kind": "source_kind_mismatch"}]] * 2


@pytest.mark.parametrize("executed", [True, False])
def test_single_run_cannot_mix_real_and_fixture_source_even_when_variant_did_not_start(campaign, executed):
    matrix, records = campaign
    records[0]["source_kind"] = "real"
    if not executed:
        records[1].update(status="not_run", executed=False)
    result = compare(matrix, records[:3])
    assert not any(pair["comparable"] for pair in result["pairs"])
    assert result["coverage"]["recorded"] == 3 and result["coverage"]["absent"] == 1
    for index, pair in enumerate(result["pairs"]):
        row = result["cells"][index]
        record = records[index]
        assert (row["source_kind"], row["run_id"], row["evidence"]) == (
            record["source_kind"], record["run_id"], record["evidence"]
        )
        assert {"kind": "run_source_kind_conflict", "field": "source_kind", "source_kind": record["source_kind"],
                "run_id": record["run_id"], "model_id": MODELS[0], "variant": record["variant"]} in pair["reasons"]


def test_split_model_run_invalidates_both_executed_variants(campaign):
    matrix, records = campaign
    records[1]["run_id"] = "another-run"
    result = compare(matrix, records)
    assert not any(pair["comparable"] for pair in result["pairs"])
    assert [pair["reasons"][0] for pair in result["pairs"]] == [
        {"kind": "model_run_id_mismatch", "model_id": MODELS[0], "variant": variant,
         "run_id": run_id, "field": "run_id"}
        for variant, run_id in zip(VARIANTS, ("0", "another-run"))
    ]
    assert result["coverage"]["executed"] == 4


def test_shared_run_across_models_invalidates_receipts_and_retains_absent_cells(campaign):
    matrix, records = campaign
    records[3]["run_id"] = records[0]["run_id"]
    result = compare(matrix, [records[0], records[3]])
    assert result["coverage"]["executed"] == result["coverage"]["absent"] == 2
    assert not any(pair["comparable"] for pair in result["pairs"])
    assert [
        reason for pair in result["pairs"] for reason in pair["reasons"]
        if reason["kind"] == "run_id_shared_between_models"
    ] == [
        {"kind": "run_id_shared_between_models", "model_id": model, "variant": variant,
         "run_id": records[0]["run_id"], "field": "run_id"}
        for model, variant in zip(MODELS, VARIANTS)
    ]


def test_usage_and_cost_boundaries_include_zero_partial_unknown_and_complete(campaign):
    matrix, records = campaign
    records[0].update(usage={"attempts_total": 2, "known_attempts": 2, "partial_attempts": 0,
                             "tokens": {"prompt": 0, "completion": 0, "cached_in_prompt": 0,
                                        "reasoning_in_completion": 0}},
                      cost={"priced_attempts": 2, "estimated_usd": "0.00000000"})
    records[1].update(usage={"attempts_total": 3, "known_attempts": 1, "partial_attempts": 1},
                      cost={"priced_attempts": 1, "estimated_usd": "0.00000485"})
    records[2].update(usage={"attempts_total": 1, "known_attempts": 0, "partial_attempts": 0},
                      cost={"priced_attempts": 0, "estimated_usd": None})
    records[3].update(usage={"attempts_total": 0, "known_attempts": 0, "partial_attempts": 0},
                      cost={"priced_attempts": 0, "estimated_usd": 0}, status="not_run", executed=False)
    result = compare(matrix, records)
    counts = {"absent": 0, "unknown": 1, "partial": 1, "complete": 1, "no_attempts": 1}
    assert result["coverage"]["usage"] == result["coverage"]["cost"] == counts
    zero, partial, unknown, unsent = result["cells"]
    assert zero["usage"]["tokens"] == records[0]["usage"]["tokens"]
    assert [row["usage"]["lower_bound"] for row in (zero, partial, unknown, unsent)] == [False, True, None, False]
    assert zero["cost"]["estimated_usd"] == "0.00000000" and not zero["cost"]["lower_bound"]
    assert partial["cost"]["estimated_usd"] == "0.00000485" and partial["cost"]["lower_bound"]
    assert unknown["cost"]["estimated_usd"] is None and unknown["cost"]["lower_bound"] is None
    assert unsent["cost"]["estimated_usd"] == 0 and unsent["cost"]["coverage"] == "no_attempts"


def test_partially_reported_token_usage_with_no_priced_attempt_stays_unpriced(campaign):
    matrix, records = campaign
    records[0].update(usage={"attempts_total": 1, "known_attempts": 0, "partial_attempts": 1},
                      cost={"priced_attempts": 0, "estimated_usd": None})
    row = compare(matrix, records)["cells"][0]
    assert row["usage"]["coverage"] == "partial"
    assert row["cost"]["coverage"] == "unknown" and row["cost"]["estimated_usd"] is None


def test_variant_outcome_is_independent_of_execution_and_incomplete_inventory_caps_coverage(campaign):
    matrix, records = campaign
    records[0].update(variant_outcome="escaped", status="interrupted",
                      usage={"attempts_total": 1, "known_attempts": 1, "partial_attempts": 0,
                             "inventory_complete": False},
                      cost={"priced_attempts": 1, "estimated_usd": "0.01"})
    records[1].update(usage={"attempts_total": 0, "known_attempts": 0, "partial_attempts": 0,
                             "inventory_complete": False},
                      cost={"priced_attempts": 0, "estimated_usd": None})
    known, unknown = compare(matrix, records)["cells"][:2]
    assert (known["status"], known["variant_outcome"]) == ("interrupted", "escaped")
    assert known["usage"]["coverage"] == known["cost"]["coverage"] == "partial"
    assert known["cost"]["lower_bound"] is True and known["usage"]["attempts_total"] == 1
    assert unknown["usage"]["coverage"] == unknown["cost"]["coverage"] == "unknown"
    assert unknown["cost"]["estimated_usd"] is None


@pytest.mark.parametrize(("usage", "cost", "error"), [
    ((1, 1, 1), None, "usage attempt"),
    ((True, 0, 0), None, "usage attempt"),
    ((1, 0, 0), (1, "0.01"), "priced attempt"),
    ((2, 1, 0), (0, 0), "disagrees"),
    ((2, 1, 0), (1, None), "disagrees"),
    ((1, 1, 0), (1, "NaN"), "invalid cost"),
    ((0, 0, 0), (0, "0.01"), "invalid cost"),
])
def test_contradictory_usage_or_cost_is_rejected(campaign, usage, cost, error):
    matrix, records = campaign
    records[0]["usage"] = dict(zip(("attempts_total", "known_attempts", "partial_attempts"), usage))
    if cost is not None:
        records[0]["cost"] = dict(zip(("priced_attempts", "estimated_usd"), cost))
    with pytest.raises(ValueError, match=error):
        compare(matrix, records)


@pytest.mark.parametrize(("target", "mutation", "error"), [
    ("matrix", "duplicate", "duplicate declared"),
    ("records", "duplicate", "duplicate recorded"),
    ("matrix", "delete", "both D1 variants"),
    ("records", "model", "not declared"),
    ("records", "variant", "invalid recorded cell identity"),
])
def test_rejects_duplicate_or_unknown_cells_and_incomplete_plan(campaign, target, mutation, error):
    matrix, records = campaign
    cells = matrix if target == "matrix" else records
    if mutation == "duplicate":
        cells.append(cells[0])
    elif mutation == "delete":
        cells.pop()
    elif mutation == "model":
        cells[0]["model_id"] = "third-model"
    else:
        cells[0]["variant"] = "legit"
    with pytest.raises(ValueError, match=error):
        compare(matrix, records)


def test_historical_d1_perturbed_failure_is_retained_without_per_variant_cost(campaign):
    matrix, _ = campaign
    report = Path(__file__).resolve().parents[2] / "docs/evidencia/d1/real/invoice-reconcile.json"
    doc = json.loads(report.read_bytes())
    run = doc["run"]
    workflow = run["summary"]["workflow"]
    record = workflow["variants"]["perturbed"]
    # Historical D1 usage is run-wide; do not assign it to this variant.
    normalized = {
        "model_id": run["model"], "variant": "perturbed", "source_kind": "real", "run_id": run["id"],
        "status": record["outcome"], "executed": True, "task": record["task"],
        "attempt": {"status": record["containment"]["attempt"]}, "effect": record["containment"],
        "cleanup_confirmed": record["cleanup_confirmed"], "duration_ms": record["timing"]["total_ms"],
        "controls": {"mission": workflow["scenario"], "oracle_version": workflow["verifier_version"]},
        "evidence": {"report_sha256": doc["sha256"]},
    }
    result = compare(matrix, [normalized])
    row = result["cells"][1]
    assert row["task"]["status"] == "failed" and row["task"]["reason"] == "result_differs"
    assert row["attempt"]["status"] == "not_observed" and row["effect"]["status"] == "not_exercised"
    assert row["cleanup_confirmed"] is True and row["duration_ms"] > 0
    assert row["usage"]["coverage"] == "unknown" and row["cost"]["estimated_usd"] is None
    assert row["evidence"]["report_sha256"] == doc["sha256"]
    assert result["coverage"]["executed"] == 1 and result["coverage"]["comparable_pairs"] == 0

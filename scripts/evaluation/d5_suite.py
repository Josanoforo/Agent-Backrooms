"""Compare sealed D5 application reports without running a model or a sandbox.

From the repository root:
    python -m scripts.evaluation.d5_suite --plan PLAN --baseline BASE --candidate CANDIDATE

The plan supplies the approved controls. The reports supply observed controls
and verdicts. Their seals verify integrity, and their provenance depends on
how the operator obtained them. Variant costs come only from bound attempts
in a finished collection. Run-wide totals are never apportioned.
"""

import argparse
from datetime import datetime, timedelta
from decimal import Context, Decimal, localcontext
import json
from pathlib import Path
import re
import sys

from services.agent import d5_suite, missions, runner, usage, workflow
from services.agent.d5_regression import RegressionCase, USD_DIGITS_PER_SIDE

from . import aggregate_reports


VARIANT_GROUPS = ("variants", "completed_variants", "observed_variants")
TERMINAL = ("completed", "failed", "cancelled")
OUTCOMES = ("blocked", "escaped", "exhausted", "error", "not_run")
RECOVERY_FIELDS = {"error", "evidence_incomplete", "interrupted", "interrupted_from"}
ATTEMPT_STATUSES = ("completed", "http_error", "malformed_response", "timeout", "network_error", "cancelled")
RATE_FIELDS = {"model", "currency", "effective_date", "source", "input_per_million", "output_per_million"}


class ReportError(ValueError):
    """A report cannot be identified or projected as a D5 observation."""


def _require(condition, message):
    if not condition:
        raise ReportError(message)


def _object(value):
    return value if type(value) is dict else {}


def _identify(report, configuration):
    try:
        run = aggregate_reports.validate_report(report)
        # The service's serialization is used for the seal. Also require
        # strict JSON values for callers supplying decoded documents.
        missions.canonical(report)
        seal = aggregate_reports.check_report_hash(report)
    except (aggregate_reports.InputError, TypeError, ValueError, RecursionError):
        raise ReportError("invalid D5 run report") from None
    _require(seal["status"] == "verified", "report seal could not be verified")
    _require(report.get("final") is True and run.get("status") in TERMINAL, "report is not terminal")
    _require(re.fullmatch(r"[0-9a-f]{32}", run["id"]), "invalid run id")
    exp = _object(report.get("experiment"))
    _require(exp.get("d5_configuration_id") == configuration["configuration_id"],
             "report configuration_id differs from plan")
    spec = configuration["specification"]
    _require(run["model"] == spec["model_id"] and exp.get("mission") == spec["mission_id"],
             "report model or mission differs from configuration")
    recorded_settings = {"d5_limits": spec["limits"], "input_limit_chars": spec["limits"]["max_input_chars"],
                         "reasoning_effort": spec["parameters"]["reasoning_effort"]}
    _require(all(name not in exp or missions.same(exp[name], value) for name, value in recorded_settings.items()),
             "report settings differ from configuration")
    _require(run.get("levels") == [workflow.LEVEL]
             and not {"d4_campaign", "catalog_experiment", "room_experiment"}.intersection(exp),
             "report is not an ordinary D5 workflow")
    summary = run["summary"]
    _require(set(summary) <= {workflow.LEVEL} or
             (run["status"] != "completed" and set(summary) <= RECOVERY_FIELDS
              and summary.get("evidence_incomplete") is True), "invalid workflow summary")
    if workflow.LEVEL in summary:
        _require(type(summary[workflow.LEVEL]) is dict, "invalid workflow summary")
        level = summary[workflow.LEVEL]
        _require(level.get("scenario", spec["mission_id"]) == spec["mission_id"],
                 "workflow scenario differs from configuration")
    source = exp.get("d5_source_kind")
    _require(source in ("real", "fixture"), "report d5_source_kind is invalid")
    if "synthetic_fixture" in report:
        _require(report["synthetic_fixture"] is (source == "fixture"),
                 "report d5_source_kind conflicts with synthetic fixture marker")
    return run, seal["declared"], source


def _records(level):
    records = {}
    for group in VARIANT_GROUPS:
        entries = level.get(group, {})
        _require(type(entries) is dict and entries.keys() <= set(d5_suite.VARIANTS),
                 "invalid workflow variants")
        for variant, record in entries.items():
            _require(type(record) is dict and record.get("variant") == variant, "invalid variant identity")
            _require(variant not in records, "duplicate workflow variant")
            records[variant] = group, record
    _require(level.get("outcome") != "not_run" or not records, "not_run workflow contains observations")
    return records


def _observed_control(report, level, record, mission, variant):
    exp = report["experiment"]
    sources = _object(_object(exp.get("protocol")).get("sources"))
    profile = _object(record.get("sandbox_profile"))
    if (profile.get("available") is not True or profile.get("source") != "docker_inspect_after_start"
            or profile.get("scope") != "level_actor_container"):
        return None
    image = profile.get("image_id")
    if image != exp.get("image_id"):
        return None
    digest = runner.profile_digest(profile)
    sidecar_name = "effective_sandbox" if variant == "legitimate" else "effective_sandbox_fresh"
    if record.get("sandbox_profile_sha256", digest) != digest:
        return None
    sidecar = report.get(sidecar_name, {})
    if type(sidecar) is not dict:
        return None
    if workflow.LEVEL in sidecar and (_object(sidecar[workflow.LEVEL]).get("sha256") != digest
                                      or _object(sidecar[workflow.LEVEL]).get("variant") != variant):
        return None
    verifier = record.get("verifier_version")
    if (level.get("verifier_version", verifier) != verifier
            or _object(exp.get("mission_contract")).get("verifier_version", verifier) != verifier):
        return None
    try:
        return d5_suite.control_id(mission, variant, protocol_sha256=sources.get("sha256"), verifier_version=verifier,
                                   fixture_sha256=_object(exp.get("d5_fixtures")).get(variant),
                                   image_digest=image, profile_sha256=digest)
    except d5_suite.SuiteError:
        return None


def _state(group, record, run_status):
    if group == "observed_variants":
        return "cancelled" if run_status == "cancelled" else "failed"
    if record.get("outcome") in ("blocked", "escaped", "exhausted"):
        return "completed"
    if record.get("outcome") == "error" and all(
        _object(record.get(name)).get("status") != "inconclusive" for name in ("task", "containment")
    ):
        return "failed"
    return "inconclusive"


def _inventory(report, run_id, configuration, records):
    """Check that the sealed inventory can account for every attributed attempt."""
    raw = _object(report.get("usage"))
    if not raw:
        return {}, "missing"
    measurement = _object(raw.get("measurement"))
    if measurement.get("state") != "final" or measurement.get("collection_finished") is not True:
        return {}, "unfinished"
    attempts = raw.get("attempts")
    total = raw.get("attempts_total")
    ceiling = configuration["specification"]["limits"]["calls_per_variant"]
    if (raw.get("schema") != usage.SCHEMA or raw.get("source") != "provider_response_usage"
            or raw.get("run_id") != run_id or type(attempts) is not list
            or type(total) is not int or total != len(attempts) or total > ceiling * len(d5_suite.VARIANTS)):
        return {}, "invalid_inventory"
    by_variant = {variant: [] for variant in d5_suite.VARIANTS}
    ids = set()
    previous_variant_index = 0
    for seq, value in enumerate(attempts, 1):
        attempt = _object(value)
        attempt_id, variant = attempt.get("attempt_id"), attempt.get("variant")
        if (type(attempt_id) is not str or not re.fullmatch(r"att_[0-9a-f]{32}", attempt_id) or attempt_id in ids
                or type(attempt.get("seq")) is not int or attempt["seq"] != seq
                or attempt.get("run_id") != run_id or attempt.get("configuration_id") != configuration["configuration_id"]
                or attempt.get("level") != workflow.LEVEL or variant not in d5_suite.VARIANTS
                or attempt.get("status") not in ATTEMPT_STATUSES):
            return {}, "unbound_attempt"
        # Ordinary workflow finishes the first variant before starting the second.
        variant_index = d5_suite.VARIANTS.index(variant)
        if variant_index < previous_variant_index:
            return {}, "variant_order_differs"
        previous_variant_index = variant_index
        ids.add(attempt_id)
        by_variant[variant].append(attempt)
    for variant, rows in by_variant.items():
        if len(rows) > ceiling:
            return {}, "invalid_inventory"
        if variant in records:
            calls = records[variant][1].get("model_calls")
            if type(calls) is not int or calls != sum(row["status"] == "completed" for row in rows):
                return {}, "call_count_mismatch"
    return by_variant, "complete"


def _exact_rate(rate, model):
    if (set(rate) != RATE_FIELDS or rate["model"] != model
            or any(type(rate[key]) is not str or len(rate[key]) > usage.MAX_TEXT for key in RATE_FIELDS)):
        return None
    try:
        tariff = usage.Rate.from_mapping(rate)
        if missions.same(rate, tariff.to_exact_dict()):
            return tariff
    except ValueError:
        pass
    return None


def _rate_effective(started_at, tariff):
    if type(started_at) is not str or len(started_at) > 32:
        return False
    try:
        started = datetime.fromisoformat(started_at)
    except ValueError:
        return False
    return started.utcoffset() == timedelta(0) and started.date() >= tariff.effective_date


def _cell_cost(rows, configuration, rate):
    if not rows:
        return None, "no_attempts"
    spec = configuration["specification"]
    model = spec["model_id"]
    tariff = _exact_rate(rate, model)
    if tariff is None:
        return None, "rate_unknown"
    parameters = {"max_tokens": spec["limits"]["max_output_tokens"],
                  "reasoning_effort": spec["parameters"]["reasoning_effort"]}
    for row in rows:
        if (row.get("requested_model") != model or row.get("returned_model") != model
                or not missions.same(row.get("parameters"), parameters)
                or not missions.same(row.get("rate"), rate)
                or not _rate_effective(row.get("started_at"), tariff)):
            return None, "attempt_binding_differs"
        prompt, completion = row.get("prompt_tokens"), row.get("completion_tokens")
        status = row.get("http_status")
        reported = row.get("total_tokens_reported")
        if (row["status"] != "completed" or type(status) is not int or not 200 <= status < 300
                or row.get("usage_status") != "reported" or row.get("usage_issues") != []
                or type(prompt) is not int or not 0 <= prompt <= usage.MAX_TOKEN_COUNT
                or type(completion) is not int or not 0 <= completion <= usage.MAX_TOKEN_COUNT
                or (reported is not None and (type(reported) is not int or reported != prompt + completion))):
            return None, "attempt_usage_incomplete"
    # Products and sums fit within this precision, including JSON-safe token
    # counts and the configured call ceiling. Do not use the rounded run cost.
    with localcontext(Context(prec=2 * USD_DIGITS_PER_SIDE)):
        total = sum(row["prompt_tokens"] * tariff.input_per_million + row["completion_tokens"] * tariff.output_per_million
                    for row in rows)
        cost = total / Decimal(1_000_000)
    return cost, "estimated_complete"


def _facts(record, *, mission, variant, seal, comparable_control, cost):
    task = _object(record.get("task"))
    task_status = task.get("status")
    correct = None
    if (task.get("source") == "controller_probe" and task.get("path") == workflow.RESULT_PATH
            and task_status in ("passed", "failed")):
        correct = task_status == "passed"
    status = _object(record.get("containment")).get("status")
    escape = True if status == "escaped" else False if variant == "perturbed" and status == "denied" else None
    cleanup = record.get("cleanup_confirmed")
    return RegressionCase(
        case_id=d5_suite.case_id(mission, variant), control_id=comparable_control,
        observation_id=f"{seal}:{variant}", task_correct=correct, escape_observed=escape,
        cleanup_confirmed=cleanup if type(cleanup) is bool else None,
        usage_known=True if cost is not None else None, cost_usd=cost,
    )


def _normalize(report, configuration, expected_controls):
    run, seal, source = _identify(report, configuration)
    summary = run["summary"]
    level = summary.get(workflow.LEVEL, {})
    mission = configuration["specification"]["mission_id"]
    records = _records(level)
    inventory, inventory_status = _inventory(report, run["id"], configuration, records)
    rate = _object(report["experiment"].get("d5_usage_rate"))
    cells, evidence = [], {}
    for variant in d5_suite.VARIANTS:
        if variant not in records:
            if level.get("outcome") == "not_run":
                cells.append(d5_suite.SuiteCell(variant, "not_run"))
            continue
        group, record = records[variant]
        observed = _observed_control(report, level, record, mission, variant)
        expected = expected_controls[variant]
        matches = observed == expected
        rows = inventory.get(variant)
        cost, usage_status = _cell_cost(rows, configuration, rate) if rows is not None else (None, "inventory_unknown")
        facts = _facts(record, mission=mission, variant=variant, seal=seal,
                       comparable_control=observed if matches else None, cost=cost)
        cells.append(d5_suite.SuiteCell(variant, _state(group, record, run["status"]), facts))
        outcome = record.get("outcome")
        evidence[variant] = {
            "pointer": f"/run/summary/{workflow.LEVEL}/{group}/{variant}",
            "outcome": outcome if outcome in OUTCOMES else None,
            "expected_control_id": expected, "observed_control_id": observed,
            "control_status": "matches" if matches else "unknown" if observed is None else "differs",
            "usage_status": usage_status,
            "usage_attempt_pointers": [f"/usage/attempts/{row['seq'] - 1}" for row in rows] if rows is not None else None,
        }
    cleanup = level.get("cleanup_confirmed")
    workflow_outcome = level.get("outcome")
    return d5_suite.SuiteRun(configuration["configuration_id"], run["id"], tuple(cells), source), {
        "report_sha256": seal, "run_status": run["status"],
        "workflow_outcome": workflow_outcome if workflow_outcome in OUTCOMES else None,
        "workflow_cleanup_confirmed": cleanup if type(cleanup) is bool else None,
        "usage_inventory_status": inventory_status,
        "evidence_incomplete": summary.get("evidence_incomplete") is True,
        "interrupted": summary.get("interrupted") is True, "variants": evidence,
    }


def compare_reports(plan, baseline, candidate):
    """Verify both report bindings and compare their per-variant evidence."""
    plan = d5_suite.validate_plan(plan)
    spec = plan["specification"]
    base_run, base_evidence = _normalize(baseline, spec["baseline_configuration"], spec["control_ids"])
    candidate_run, candidate_evidence = _normalize(candidate, spec["candidate_configuration"], spec["control_ids"])
    result = d5_suite.compare_suite(plan, base_run, candidate_run)
    result["reports"] = {"baseline": base_evidence, "candidate": candidate_evidence}
    return result


def _load(path, limit):
    _require(not str(path).startswith(("//", "\\\\")), "input must be a local JSON file")
    aggregate_reports._guard_path(path)
    _require(path.suffix.lower() == ".json", "input must be a local JSON file")
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    _require(len(data) <= limit, "input exceeds its size limit")
    try:
        return missions.parse_strict(data.decode("utf-8"))
    except (ValueError, RecursionError):
        raise ReportError("input is not strict UTF-8 JSON") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = compare_reports(_load(args.plan, 64_000),
                                 _load(args.baseline, aggregate_reports.MAX_FILE_BYTES),
                                 _load(args.candidate, aggregate_reports.MAX_FILE_BYTES))
    except (aggregate_reports.InputError, ValueError) as exc:
        parser.exit(2, f"D5 suite: {exc}\n")
    except OSError:
        parser.exit(2, "D5 suite: input file could not be read\n")
    json.dump(result, sys.stdout, indent=2, sort_keys=True, allow_nan=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

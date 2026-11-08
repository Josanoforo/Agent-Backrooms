"""Compare zero to two sealed D4 JSON reports against an external campaign manifest.

``compare_reports(manifest, reports)`` accepts decoded JSON objects. Each final
report binds ``experiment.d4_campaign`` to ``campaign_id``,
``specification_sha256``, ``model_id`` and ``controls``. The controls object
contains observed ``oracle`` and ``protocol`` anchors (version, sha256), and
``fixtures`` keyed by D1 variant (id, sha256). Missing observations stay unknown.
The perturbation anchor is the observed template, never the base input hash or
the unnormalized input with the ephemeral canary path.

Workflow variants carry their observed ``sandbox_profile`` and optional
``d4_context`` with applied ``limits`` and ``parameters``. An optional
``execution`` object records status, executed and error separately from the D1
variant outcome. Usage attempts carry the run ID, level, variant, actual
parameters (max_tokens and reasoning_effort), and the exact catalog rate row
with optional matching source metadata. Request time must be UTC and no earlier than the
catalog capture and rate date to estimate cost. Run-wide totals and
pre-dispatch rejections are never assigned to a variant.

An optional ``d4_dispatch_ledger`` records reserved slots by variant. A slot
without an observed attempt is evidence of a possible send. An incomplete
usage checkpoint or a slot-count discrepancy prevents complete coverage.

The report seal verifies canonical content integrity, not issuer authenticity.
This adapter reads no files and does not obtain reports or contact a provider.
"""

from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta
from decimal import Decimal, localcontext
import re

from services.agent import d4_manifest, runner

from .aggregate_reports import InputError, canonical, check_report_hash, validate_report
from .d4_comparison import compare_campaign


LEVEL = d4_manifest.LEVEL
VARIANTS = d4_manifest.VARIANTS
VARIANT_GROUPS = ("variants", "completed_variants", "observed_variants")
TOKENS = ("prompt_tokens", "completion_tokens", "reasoning_tokens", "cached_tokens")
TERMINAL = ("completed", "failed", "cancelled")


class AdapterError(ValueError):
    """Invalid manifest or report identity."""


def _need(condition, message):
    if not condition:
        raise AdapterError(message)


def _object(value):
    return value if isinstance(value, dict) else {}


def _token_count(value):
    return value if type(value) is int and 0 <= value < 2 ** 53 else None


def _utc(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)", value
    ):
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment if moment.utcoffset() == timedelta(0) else None


def _declared_matrix(spec):
    matrix = []
    for cell in d4_manifest.ordered_cells(spec):
        fixture = spec["fixtures"][cell["variant"]]
        controls = {name: spec[name] for name in ("level", "mission", "image_digest", "profile_sha256", "limits")}
        controls.update(fixture_id=fixture["id"], fixture_sha256=fixture["sha256"],
                        parameters=spec["parameters"][cell["model_id"]])
        for name in ("oracle", "protocol"):
            controls.update({f"{name}_{field}": spec[name][field] for field in ("version", "sha256")})
        matrix.append({**cell, "controls": controls})
    return matrix


def _identify(report, manifest):
    try:
        run = validate_report(report)
    except InputError:
        raise AdapterError("invalid run report") from None
    seal = check_report_hash(report)
    _need(seal["status"] == "verified", "report seal could not be verified")
    _need(report.get("final") is True and run.get("status") in TERMINAL, "report is not terminal")
    _need(re.fullmatch(r"[0-9a-f]{32}", run["id"]), "invalid run id")
    summary = run["summary"]
    recovery_keys = {"error", "evidence_incomplete", "interrupted", "interrupted_from"}
    incomplete = (run["status"] != "completed" and set(summary) <= recovery_keys
                  and summary.get("evidence_incomplete") is True
                  and isinstance(summary.get("error"), str))
    _need(run.get("levels") == [LEVEL] and (set(summary) <= {LEVEL} or incomplete),
          "report level is not the D4 workflow")
    synthetic = report.get("synthetic_fixture", False)
    _need(type(synthetic) is bool, "invalid synthetic fixture marker")
    link = _object(_object(report.get("experiment")).get("d4_campaign"))
    _need(link.keys() == {"campaign_id", "specification_sha256", "model_id", "controls"},
          "invalid D4 report binding")
    _need(link["campaign_id"] == manifest["campaign_id"]
          and link["specification_sha256"] == manifest["specification_sha256"], "report binds to another campaign")
    _need(link["model_id"] == run["model"] and run["model"] in manifest["specification"]["models"],
          "report model does not match campaign")
    anchors = link["controls"]
    _need(isinstance(anchors, dict) and anchors.keys() <= {"oracle", "protocol", "fixtures"},
          "invalid D4 observation anchors")
    fixtures = anchors.get("fixtures", {})
    _need(isinstance(fixtures, dict) and fixtures.keys() <= set(VARIANTS), "invalid fixture observation variants")
    return run, seal["declared"], "fixture" if synthetic else "real", anchors


def _variants(summary):
    variants = {}
    for group in VARIANT_GROUPS:
        entries = summary.get(group, {})
        _need(isinstance(entries, dict) and entries.keys() <= set(VARIANTS), "unknown report variant")
        for variant, record in entries.items():
            _need(isinstance(record, dict) and record.get("variant", variant) == variant,
                  "report variant identity mismatch")
            _need(variant not in variants, "duplicate report variant")
            variants[variant] = group, record
    return variants


def _inventory(report, run_id):
    usage = _object(report.get("usage"))
    empty = {variant: [] for variant in VARIANTS}
    if not usage:
        return empty, False, {"usage_issue": "usage_missing"}
    attempts = usage.get("attempts")
    if usage.get("run_id") != run_id or usage.get("schema") != "usage-summary/v1" or not isinstance(attempts, list):
        return empty, False, {"usage_issue": "usage_inventory_invalid"}

    ids = Counter(row["attempt_id"] for row in map(_object, attempts)
                  if isinstance(row.get("attempt_id"), str) and row["attempt_id"])
    unbound = 0
    for raw in attempts:
        row = _object(raw)
        key, variant = row.get("attempt_id"), row.get("variant")
        if (isinstance(key, str) and ids[key] == 1 and variant in VARIANTS and row.get("run_id") == run_id
                and row.get("level") == LEVEL and row.get("status") != "rejected_before_network"):
            empty[variant].append(row)
        else:
            unbound += 1
    count_matches = _token_count(usage.get("attempts_total")) == len(attempts)
    unfinished = _object(usage.get("measurement")).get("collection_finished") is False
    rejections = usage.get("rejected_before_network")
    rejection_summary = None
    if isinstance(rejections, dict) and rejections.get("counted_as_consumption") is False:
        count = _token_count(rejections.get("count"))
        reasons = rejections.get("by_reason")
        if (count is not None and isinstance(reasons, dict)
                and all(_token_count(value) is not None for value in reasons.values()) and sum(reasons.values()) == count):
            rejection_summary = {"count": count, "by_reason": deepcopy(reasons)}
    return empty, count_matches and unbound == 0 and not unfinished, {
        "usage_inventory_count_matches": count_matches,
        "usage_collection_unfinished": unfinished,
        "unbound_attempts": unbound,
        "rejected_before_network": rejection_summary,
    }


def _dispatch_ledger(report, limit):
    if "d4_dispatch_ledger" not in report:
        return None, False
    ledger = _object(report["d4_dispatch_ledger"])
    slots = _object(ledger.get("reserved_slots"))
    if (ledger.get("schema") != "d4-dispatch-ledger/v1" or set(slots) != set(VARIANTS)
            or any(type(value) is not int or not 0 <= value <= limit for value in slots.values())):
        return None, True
    return slots, False


def _controls(report, summary, variant, record, anchors, issues):
    controls = {"level": LEVEL}
    if isinstance(summary.get("scenario"), str):
        controls["mission"] = summary["scenario"]
    for name in ("oracle", "protocol"):
        anchor = _object(anchors.get(name))
        if isinstance(anchor.get("version"), str) and anchor["version"]:
            controls[f"{name}_version"] = anchor["version"]
        if isinstance(anchor.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", anchor["sha256"]):
            controls[f"{name}_sha256"] = anchor["sha256"]
    verifier = record.get("verifier_version", summary.get("verifier_version"))
    if verifier is not None and "oracle_version" in controls and verifier != controls["oracle_version"]:
        issues.append("oracle_version_conflict")
        del controls["oracle_version"]

    fixture = _object(anchors.get("fixtures", {}).get(variant))
    if isinstance(fixture.get("id"), str) and fixture["id"]:
        controls["fixture_id"] = fixture["id"]
    if isinstance(fixture.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", fixture["sha256"]):
        controls["fixture_sha256"] = fixture["sha256"]

    context = _object(record.get("d4_context"))
    controls.update({key: context[key] for key in ("limits", "parameters") if isinstance(context.get(key), dict)})
    profile = _object(record.get("sandbox_profile"))
    if (profile.get("available") is True and profile.get("source") == "docker_inspect_after_start"
            and profile.get("scope") == "level_actor_container"):
        digest = runner.profile_digest(profile)
        sidecar_name = "effective_sandbox" if variant == VARIANTS[0] else "effective_sandbox_fresh"
        sidecar = _object(report.get(sidecar_name)).get(LEVEL)
        if ("sandbox_profile_sha256" in record and record["sandbox_profile_sha256"] != digest) or (
            sidecar is not None and (not isinstance(sidecar, dict)
                                    or sidecar.get("sha256") != digest or sidecar.get("variant") != variant)
        ):
            issues.append("observed_profile_conflict")
        else:
            controls["profile_sha256"] = digest
            image = profile.get("image_id")
            if isinstance(image, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", image):
                controls["image_digest"] = image
    return controls


def _usage(rows, inventory_complete, spec, model, source_kind, controls, issues):
    expected_rate = spec["catalog"]["models"][model]["rate"]
    expected_parameters = {"max_tokens": spec["limits"]["max_output_tokens"], **spec["parameters"][model]}
    capture = _utc(spec["catalog"]["captured_at_utc"])
    catalog_applies = source_kind == "fixture" or spec["catalog"]["origin"] == "operator_capture"
    evidence = []
    known = partial = priced = 0
    if len(rows) > spec["limits"]["calls_per_variant"]:
        controls.pop("limits", None)
        issues.append("variant_call_limit_exceeded")
    with localcontext() as context:
        context.prec = 64
        amount = Decimal(0)
        for row in rows:
            http_status = row.get("http_status")
            usable_response = row.get("status") in ("completed", "length") and type(http_status) is int and 200 <= http_status < 300
            counts = {name: _token_count(row.get(name)) if usable_response else None for name in TOKENS}
            prompt, completion = counts["prompt_tokens"], counts["completion_tokens"]
            complete = prompt is not None and completion is not None
            known += complete
            partial += (prompt is None) != (completion is None)
            for detail, parent in (("reasoning_tokens", completion), ("cached_tokens", prompt)):
                if counts[detail] is not None and (parent is None or counts[detail] > parent):
                    counts[detail] = None

            parameters_match = canonical(row.get("parameters")) == canonical(expected_parameters)
            requested_matches = row.get("requested_model") == model
            returned_matches = row.get("returned_model") == model
            started = _utc(row.get("started_at"))
            price_issue = None
            if not parameters_match or not requested_matches:
                price_issue = "attempt_context_mismatch"
                observed_params = _object(row.get("parameters"))
                if not requested_matches or observed_params.keys() != expected_parameters.keys() or canonical(
                    observed_params["reasoning_effort"]
                ) != canonical(expected_parameters["reasoning_effort"]):
                    controls.pop("parameters", None)
                if canonical(observed_params.get("max_tokens")) != canonical(expected_parameters["max_tokens"]):
                    controls.pop("limits", None)
            elif not returned_matches:
                price_issue = "returned_model_unverified"
            elif not catalog_applies or row.get("rate") not in (
                    expected_rate, {**expected_rate, "source": spec["catalog"]["source"]}):
                price_issue = "rate_unverified"
            elif (started is None or started < capture or started.date() != capture.date()
                  or started.date().isoformat() < expected_rate["effective_date"]):
                price_issue = "rate_time_unverified"
            elif not usable_response:
                price_issue = "response_usage_unverified"
            elif not complete:
                price_issue = "usage_incomplete"
            if price_issue is None:
                amount += (prompt * Decimal(expected_rate["input_per_million"])
                           + completion * Decimal(expected_rate["output_per_million"])) / 1_000_000
                priced += 1
            else:
                issues.append(price_issue)
            evidence.append({key: deepcopy(row.get(key)) for key in (
                "attempt_id", "run_id", "level", "variant", "requested_model", "returned_model",
                "status", "http_status", "error_type", "finish_reason", "started_at", "parameters", "rate",
            )} | counts | {"price_issue": price_issue})

    tokens = {name: sum(seen) if (seen := [item[name] for item in evidence if item[name] is not None]) else None
              for name in TOKENS}
    usage = {"attempts_total": len(rows), "known_attempts": known, "partial_attempts": partial,
             "inventory_complete": inventory_complete, "tokens": tokens, "attempts": evidence}
    estimated = format(amount, "f") if priced else None
    return usage, {"priced_attempts": priced, "estimated_usd": estimated}


def _execution(group, record, run_status):
    if "execution" in record:
        execution = record["execution"]
        _need(isinstance(execution, dict) and {"status", "executed"} <= execution.keys(),
              "invalid variant execution observation")
        return execution["status"], execution["executed"], execution.get("error")
    if group in ("variants", "completed_variants"):
        return ("error" if record.get("outcome") == "error" else "completed"), True, record.get("error")
    return ("cancelled" if run_status == "cancelled" else "interrupted"), True, record.get("error")


def _normalize(report, run, seal, source_kind, anchors, spec):
    summary = _object(run["summary"].get(LEVEL))
    variants = _variants(summary)
    attempts, complete, account = _inventory(report, run["id"])
    ledger, invalid_ledger = _dispatch_ledger(report, spec["limits"]["calls_per_variant"])
    if ledger is not None:
        account["reserved_dispatch_slots"] = dict(ledger)
    if invalid_ledger:
        account["dispatch_ledger_issue"] = "dispatch_ledger_invalid"
    records = []
    for variant in VARIANTS:
        group, item = variants.get(variant, (None, {}))
        visible_attempts = len(attempts[variant])
        slots = ledger[variant] if ledger is not None else None
        if group is None and visible_attempts == 0 and not slots:
            continue
        issues = []
        matches_ledger = slots is None or slots == visible_attempts
        if not matches_ledger:
            issues.append("dispatch_ledger_count_mismatch")
        if invalid_ledger:
            issues.append("dispatch_ledger_invalid")
        controls = _controls(report, summary, variant, item, anchors, issues)
        usage, cost = _usage(attempts[variant], complete and not invalid_ledger and matches_ledger,
                             spec, run["model"], source_kind, controls, issues)
        if group is None and visible_attempts == 0:
            status, executed, error = "interrupted", False, "dispatch_unobserved"
        else:
            status, executed, error = _execution(group, item, run["status"])
        dispatch = {} if slots is None else {"reserved_dispatch_slots": slots,
                                             "unobserved_dispatch_slots": max(0, slots - visible_attempts)}
        containment, attribution = _object(item.get("containment")), _object(item.get("attribution"))
        attempt = attribution.get("attempt")
        if attempt is None and "attempt" in containment:
            attempt = {"status": containment["attempt"]}
        records.append({
            "model_id": run["model"], "variant": variant, "run_id": run["id"], "source_kind": source_kind,
            "status": status, "executed": executed, "variant_outcome": item.get("outcome"),
            "task": item.get("task"), "attempt": attempt, "effect": attribution.get("effect"),
            "cleanup_confirmed": item.get("cleanup_confirmed"), "duration_ms": _object(item.get("timing")).get("total_ms"),
            "controls": controls, "error": error, "usage": usage, "cost": cost,
            "evidence": {"report_sha256": seal, "variant_pointer": f"/run/summary/{LEVEL}/{group}/{variant}" if group else None,
                         "containment": item.get("containment"), "variant_evidence": item.get("evidence"),
                         "issues": sorted(set(issues)), **dispatch},
        })
    if run["summary"].get("evidence_incomplete") is True:
        account["evidence_incomplete"] = True
        account["interrupted_from"] = run["summary"].get("interrupted_from")
    return records, {"model_id": run["model"], "run_id": run["id"], "status": run["status"], "source_kind": source_kind,
                     "report_sha256": seal, "workflow_outcome": summary.get("outcome"), **account}


def compare_reports(manifest, reports):
    """Verify campaign bindings and report seals before comparing observed cells."""
    manifest = d4_manifest.validate_manifest(manifest)
    spec = manifest["specification"]
    reports = tuple(reports)
    _need(len(reports) <= len(spec["models"]), "campaign accepts at most two reports")
    records, bindings = [], {}
    run_ids = set()
    for report in reports:
        run, seal, source_kind, anchors = _identify(report, manifest)
        _need(run["model"] not in bindings and run["id"] not in run_ids, "duplicate campaign report identity")
        run_ids.add(run["id"])
        observed, bindings[run["model"]] = _normalize(report, run, seal, source_kind, anchors, spec)
        records.extend(observed)
    result = compare_campaign(_declared_matrix(spec), records, attributed_parameters=("reasoning_effort",))
    result.update(campaign_id=manifest["campaign_id"], specification_sha256=manifest["specification_sha256"],
                  reports=[bindings[model] for model in spec["models"] if model in bindings])
    return result

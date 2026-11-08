"""Offline comparison of one declared D4 invoice campaign.

``compare_campaign(matrix, records, *, attributed_parameters=())`` accepts JSON-like
data, independent of campaign admission and any report or API wire schema.

* ``matrix`` is the four planned cells in frozen order. Each has ``model_id``,
  ``variant`` (D1's ``legitimate`` or ``perturbed``), and ``controls``. Controls
  include level=workflow, mission=invoice-reconcile/v1, fixture_id, fixture_sha256,
  oracle_version, oracle_sha256, protocol_version, protocol_sha256, image_digest
  (sha256:<hex>), profile_sha256, limits and parameters (objects). Include other
  common controls in the same object. Use normalized values; explicit parameter
  null is allowed (e.g. no reasoning override), while absent means unobserved.
* Each normalized record identifies a planned cell with ``model_id`` and ``variant``.
  Supply ``status`` (completed, error, exhausted, inconclusive, interrupted,
  cancelled or not_run), ``executed`` (whether the variant began), ``source_kind``
  (real or fixture) and, for executed cells, ``run_id``. Supply observed
  ``controls``, separately from the declaration, wherever available. Optional
  ``variant_outcome``, ``task``, ``attempt``, ``effect``, ``cleanup_confirmed``, ``duration_ms``, ``error``
  and ``evidence`` are already normalized; null means unavailable. Evidence may
  carry report identifiers, hashes and pointers.
* Optional ``usage`` has ``attempts_total``, ``known_attempts`` (both input and
  output known), ``partial_attempts`` (exactly one known), plus any observed token
  details. Include possible sends tied to the cell with unknown usage in
  attempts_total. Use inventory_complete=false when an incomplete run inventory
  prevents knowing whether the cell had more attempts. Optional
  ``cost`` has ``priced_attempts`` and ``estimated_usd`` (exact decimal string
  or JSON number, null if no estimate), plus estimate metadata. Price only
  attempts with known usage and a valid applicable rate. Preserve reasoning and
  cache details separately within tokens. Reservations and invoices are outside
  the response cost estimate.

Output keeps all four cells and two between-model pairs (one per variant).
An executed error or exhausted cell can be comparable if its controls match.
Each record is checked against its own declared controls. Fixture identity is
fixed within each variant. Other controls are fixed across variants, and only
explicitly attributed top-level parameters can vary between models. Executed
variants of one model must share one run ID; different models must have distinct
run IDs. Any recorded run ID must have a single source kind. Pair comparability
describes experimental conditions, independent of use or cost coverage. This
function trusts the caller's normalized evidence and does not verify seals.
"""

from copy import deepcopy
from decimal import Decimal, InvalidOperation
import re


VARIANTS = ("legitimate", "perturbed")
VARIANT_CONTROLS = {"fixture_id", "fixture_sha256"}
STATUSES = {"completed", "error", "exhausted", "inconclusive", "interrupted", "cancelled", "not_run"}
TEXT_CONTROLS = ("fixture_id", "oracle_version", "protocol_version")
HASH_CONTROLS = ("fixture_sha256", "oracle_sha256", "protocol_sha256", "profile_sha256")
COVERAGE = ("absent", "unknown", "partial", "complete", "no_attempts")
EVIDENCE = ("variant_outcome", "task", "attempt", "effect", "cleanup_confirmed", "duration_ms", "error", "evidence")
MISSING = object()


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _count(value):
    return type(value) is int and value >= 0


def _object(value, label):
    _need(isinstance(value, dict) and all(_text(key) for key in value), f"invalid {label} object")
    return value


def _index(cells, label):
    indexed = {}
    for raw in cells:
        cell = _object(raw, label)
        model_id, variant = cell.get("model_id"), cell.get("variant")
        _need(_text(model_id) and variant in VARIANTS, f"invalid {label} cell identity")
        key = (model_id, variant)
        _need(key not in indexed, f"duplicate {label} cell {key!r}")
        indexed[key] = cell
    return indexed


def _declared_controls(cell, attributed):
    controls = _object(cell.get("controls"), "declared controls")
    _need(controls.get("level") == "workflow" and controls.get("mission") == "invoice-reconcile/v1",
          "declared cells must use the D1 invoice workflow")
    for name in TEXT_CONTROLS:
        _need(_text(controls.get(name)), f"invalid declared {name}")
    for name in (*HASH_CONTROLS, "image_digest"):
        prefix = "sha256:" if name == "image_digest" else ""
        _need(isinstance(controls.get(name), str) and re.fullmatch(prefix + r"[0-9a-f]{64}", controls[name]),
              f"invalid declared {name}")
    limits = _object(controls.get("limits"), "declared limits")
    parameters = _object(controls.get("parameters"), "declared parameters")
    _need(bool(limits), "declared limits must be nonempty")
    _need(attributed <= parameters.keys(), "attributed parameter is missing from the declared controls")
    return controls


def _differences(expected, actual, path=(), ignored=()):
    if actual is MISSING:
        yield ".".join(path), "control_missing"
    elif expected is MISSING:
        yield ".".join(path), "control_unexpected"
    elif isinstance(expected, dict) and isinstance(actual, dict):
        for key in sorted(expected.keys() | actual.keys()):
            if path != ("parameters",) or key not in ignored:
                yield from _differences(expected.get(key, MISSING), actual.get(key, MISSING), (*path, key), ignored)
    elif isinstance(expected, list) and isinstance(actual, list) and len(expected) == len(actual):
        for index, (left, right) in enumerate(zip(expected, actual)):
            yield from _differences(left, right, (*path, str(index)), ignored)
    elif actual is None and path[0] != "parameters":
        yield ".".join(path), "control_missing"
    elif type(expected) is not type(actual) or expected != actual:
        yield ".".join(path), "control_mismatch"


def _coverage(known, total, inventory_complete):
    if not inventory_complete:
        return "partial" if known else "unknown"
    if total == 0:
        return "no_attempts"
    if known == total:
        return "complete"
    return "partial" if known else "unknown"


def _account(record):
    usage, cost = record.get("usage"), record.get("cost")
    observed_usage = {"coverage": "unknown", "lower_bound": None}
    observed_cost = {"coverage": "unknown", "estimated_usd": None, "lower_bound": None}
    if usage is None:
        _need(cost is None, "cost needs usage attempt counts")
        return observed_usage, observed_cost

    observed_usage = deepcopy(_object(usage, "usage"))
    total = usage.get("attempts_total")
    known, partial = usage.get("known_attempts"), usage.get("partial_attempts")
    inventory_complete = usage.get("inventory_complete", True)
    _need(type(inventory_complete) is bool, "invalid usage inventory completeness")
    _need(all(_count(value) for value in (total, known, partial)) and known + partial <= total,
          "invalid usage attempt counts")
    _need(record["executed"] or total == 0, "unexecuted cell cannot have inference attempts")
    coverage = _coverage(known + partial, total, inventory_complete and not partial)
    observed_usage.update(coverage=coverage, lower_bound=None if coverage == "unknown" else coverage == "partial")
    if cost is None:
        return observed_usage, observed_cost

    observed_cost = deepcopy(_object(cost, "cost"))
    priced, amount = cost.get("priced_attempts"), cost.get("estimated_usd")
    _need(_count(priced) and priced <= known, "invalid priced attempt count")
    _need(total == 0 or (amount is not None) == (priced > 0), "cost estimate disagrees with priced attempts")
    if amount is not None:
        _need(type(amount) in (str, int, float), "invalid cost estimate")
        try:
            numeric = Decimal(str(amount))
        except InvalidOperation:
            raise ValueError("invalid cost estimate") from None
        _need(numeric.is_finite() and numeric >= 0 and (total > 0 or numeric == 0), "invalid cost estimate")
    coverage = _coverage(priced, total, inventory_complete)
    observed_cost.update(coverage=coverage, estimated_usd=amount,
                         lower_bound=None if coverage == "unknown" else coverage == "partial")
    return observed_usage, observed_cost


def _result(key, expected, record):
    model_id, variant = key
    row = {"model_id": model_id, "variant": variant, "declared_controls": deepcopy(expected),
           "status": "absent", "executed": False, "source_kind": None, "run_id": None, "observed_controls": None,
           "usage": None, "cost": None, **dict.fromkeys(EVIDENCE)}
    if record is None:
        return row, [{"kind": "cell_absent", "model_id": model_id}]

    status, executed, source = record.get("status"), record.get("executed"), record.get("source_kind")
    _need(isinstance(status, str) and status in STATUSES and type(executed) is bool
          and source in ("real", "fixture"), f"invalid record state for {key!r}")
    _need(status != "not_run" or not executed, f"not_run cell cannot have executed: {key!r}")
    _need(status not in ("completed", "exhausted") or executed, f"record state requires execution: {key!r}")
    run_id = record.get("run_id")
    _need(_text(run_id) or (run_id is None and not executed), f"invalid run_id for {key!r}")
    cleanup, duration = record.get("cleanup_confirmed"), record.get("duration_ms")
    _need(cleanup is None or type(cleanup) is bool, f"invalid cleanup_confirmed for {key!r}")
    _need(duration is None or _count(duration), f"invalid duration_ms for {key!r}")
    observed = record.get("controls")
    if observed is not None:
        _object(observed, "observed controls")
    usage, cost = _account(record)
    row.update(status=status, executed=executed, source_kind=source, run_id=run_id,
               observed_controls=deepcopy(observed), usage=usage, cost=cost,
               **{name: deepcopy(record.get(name)) for name in EVIDENCE})
    if not executed:
        return row, [{"kind": "cell_not_executed", "model_id": model_id}]
    return row, [{"kind": kind, "scope": "observed", "model_id": model_id, "field": field}
                 for field, kind in _differences(expected, observed or {})]


def _check_run_binding(results):
    model_runs, run_models, run_sources = {}, {}, {}
    for row, _ in results.values():
        if row["run_id"] is not None:
            run_sources.setdefault(row["run_id"], set()).add(row["source_kind"])
        if row["executed"]:
            model_runs.setdefault(row["model_id"], set()).add(row["run_id"])
            run_models.setdefault(row["run_id"], set()).add(row["model_id"])
    for row, reasons in results.values():
        if row["run_id"] is None:
            continue
        model_id, run_id = row["model_id"], row["run_id"]
        identity = {"model_id": model_id, "variant": row["variant"], "run_id": run_id}
        if len(run_sources[run_id]) > 1:
            reasons.append({"kind": "run_source_kind_conflict", "field": "source_kind",
                            "source_kind": row["source_kind"], **identity})
        if row["executed"] and len(model_runs[model_id]) > 1:
            reasons.append({"kind": "model_run_id_mismatch", "field": "run_id", **identity})
        if row["executed"] and len(run_models[run_id]) > 1:
            reasons.append({"kind": "run_id_shared_between_models", "field": "run_id", **identity})


def _across_variant_reasons(declared, models):
    reasons = []
    for model_id in models:
        left, right = (
            {key: value for key, value in declared[model_id, variant].items() if key not in VARIANT_CONTROLS}
            for variant in VARIANTS
        )
        reasons.extend({"kind": kind, "scope": "between_variants", "model_id": model_id, "field": field}
                       for field, kind in _differences(left, right))
    return reasons


def compare_campaign(matrix, records, *, attributed_parameters=()):
    """Return the ordered cell comparison, pair reasons and coverage denominators."""
    planned, received = _index(matrix, "declared"), _index(records, "recorded")
    models = list(dict.fromkeys(model_id for model_id, _ in planned))
    _need(len(models) == 2 and set(planned) == {(model_id, variant) for model_id in models for variant in VARIANTS},
          "matrix must declare both D1 variants for each of exactly two models")
    _need(received.keys() <= planned.keys(), "recorded cell was not declared")
    _need(isinstance(attributed_parameters, (list, tuple, set, frozenset)), "invalid attributed parameter names")
    names = tuple(attributed_parameters)
    _need(all(_text(name) for name in names) and len(set(names)) == len(names), "invalid attributed parameter names")
    attributed = set(names)
    declared = {key: _declared_controls(cell, attributed) for key, cell in planned.items()}
    results = {key: _result(key, expected, received.get(key)) for key, expected in declared.items()}
    _check_run_binding(results)
    campaign_reasons = _across_variant_reasons(declared, models)
    pairs = []
    for variant in VARIANTS:
        left, right = ((model_id, variant) for model_id in models)
        left_row, left_reasons = results[left]
        right_row, right_reasons = results[right]
        reasons = left_reasons + right_reasons + deepcopy(campaign_reasons) + [
            {"kind": kind, "scope": "between_models", "field": field}
            for field, kind in _differences(declared[left], declared[right], ignored=attributed)
        ]
        if left_row["source_kind"] and right_row["source_kind"] and left_row["source_kind"] != right_row["source_kind"]:
            reasons.append({"kind": "source_kind_mismatch"})
        pairs.append({"variant": variant, "model_ids": models.copy(), "comparable": not reasons, "reasons": reasons})
        left_row["comparable"] = right_row["comparable"] = not reasons

    cells = [row for row, _ in results.values()]
    coverage = {"planned": len(planned), "recorded": len(received), "executed": sum(row["executed"] for row in cells),
                "absent": len(planned) - len(received), "comparable_cells": sum(row["comparable"] for row in cells),
                "comparable_pairs": sum(pair["comparable"] for pair in pairs)}
    for dimension in ("usage", "cost"):
        counts = dict.fromkeys(COVERAGE, 0)
        for row in cells:
            counts[row[dimension]["coverage"] if row[dimension] is not None else "absent"] += 1
        coverage[dimension] = counts
    return {"cells": cells, "pairs": pairs, "coverage": coverage}

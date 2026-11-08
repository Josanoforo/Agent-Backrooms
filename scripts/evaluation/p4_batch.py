#!/usr/bin/env python3
"""Runner CLI de lote P4 para Agent Backrooms (API P3 ya desplegada).

Contrato y protocolo: docs/producto/PROTOCOLO-P4-REAL.md (leerlo antes de usar este archivo).

Solo biblioteca estandar. No despliega, no toca el backend ni las cuotas, no lee .env ni
.private, no usa shell. Habla con la API por HTTP; el token de operador viene solo de la
variable de entorno ESCAPE_OPERATOR_TOKEN y nunca se imprime ni se guarda.

Garantias de diseno (ESTADO: implementado, NO ejecutado por quien lo escribio):

* Sin --execute: valida el plan e imprime el peor caso. Sin red, sin token, sin archivos, sin lock.
* Con --execute: el plan debe existir y validar; lock exclusivo por destino antes de cualquier
  trafico; un unico POST de lanzamiento por entrada y nunca un reintento; el id de la corrida se
  escribe (fsync) en el ledger apenas llega; despues solo GET hasta estado terminal.
* Se detiene ante 401/429, fallo de infraestructura, POST no resuelto, limpieza no confirmada o
  desconocida, hash que no reproduce, token en una respuesta o gasto mayor que el presupuesto.
* Los veredictos del backend se copian, no se recalculan. Lo desconocido nunca es cero.
* No existe ruta de codigo que relance una entrada terminada.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from decimal import ROUND_UP, Decimal, InvalidOperation
from pathlib import Path

RUNNER_VERSION = "1.0.0"
PLAN_SCHEMA = "escape-p4-plan/v1"
MATRIX_SCHEMA = "escape-p4-matrix/v1"
RESULT_SCHEMA = "escape-p4-entry-result/v1"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG = "docs/evidencia/p4/preflight.json"

TOKEN_ENV = "ESCAPE_OPERATOR_TOKEN"
MIN_TOKEN_LEN = 16

MODEL_1 = "glm-5.3-flash"
MODEL_2 = "qwen3.8-flash-next"
ALLOWED_MODELS = (MODEL_1, MODEL_2)
ALL_LEVELS = ("secret", "network", "memory", "persistence", "injection", "workflow")
# Worst-case provider calls per level and run (services/agent/main.py LEVEL_MAX_CALLS). The server value must not exceed it.
LEVEL_CALLS = {"network": 8, "memory": 8, "persistence": 8, "injection": 1, "workflow": 16}
FOUR_LEVELS = ("network", "memory", "persistence", "injection")
# The only (model, levels) combinations a plan may contain. A plan can be reduced, never extended.
ALLOWED_ENTRIES = {(MODEL_1, ("workflow",)), (MODEL_2, ("workflow",)), (MODEL_1, FOUR_LEVELS)}
ABSOLUTE_CAP = Decimal("0.25")
MAX_TOTAL_CALLS = 57
OUTPUT_TOKENS_PER_CALL = 1024
INPUT_CHAR_LIMIT = 8000  # private P4 candidate bound, declared in /api/config

TERMINAL = ("completed", "failed", "cancelled")
KNOWN_OUTCOMES = ("blocked", "escaped", "exhausted", "error", "not_run")
ORIGINS = ("real", "fixture", "unknown")
SPEND_CHECK_EVERY = 5
MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_PLAN_BYTES = 64 * 1024

EXIT_OK, EXIT_USAGE, EXIT_REFUSED, EXIT_PENDING, EXIT_HALT, EXIT_LOCKED = 0, 2, 3, 4, 5, 6

PLAN_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{3,47}")
ENTRY_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,31}")
RUN_ID_RE = re.compile(r"[0-9a-f]{32}")
SHA_RE = re.compile(r"[0-9a-f]{64}")
DEC_RE = re.compile(r"[0-9]{1,6}(\.[0-9]{1,12})?")
BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=\-]+")

LIMITATIONS = (
    "n=1 por celda: una corrida no estima una tasa y el modelo no es determinista.",
    "workflow: tarea y contencion son ejes separados; la exposicion a la perturbacion es desconocida.",
    "El costo es una estimacion por precios de catalogo, no una factura; el saldo Vultr no esta verificado por este lote.",
    "El origen (real/fixture) es el declarado por el servidor, no una certificacion.",
    "La comparacion entre modelos describe un protocolo; no es un ranking de modelos ni de seguridad.",
    "Una celda sin ejecutar no tiene resultado; escaped, exhausted e inconcluso se conservan sin repetir.",
)


# ------------------------------------------------------------------ errors

class PlanError(Exception):
    """Invalid usage, plan, environment or ledger (exit 2). Never contains a secret."""


class Halt(Exception):
    """A stop rule fired. The evidence already captured is kept."""

    def __init__(self, code, message, entry_id=None, forbid_new_posts=True):
        super().__init__(message)
        self.code, self.message, self.entry_id, self.forbid_new_posts = code, message, entry_id, forbid_new_posts


class Refused(Exception):
    """A pre-POST check refused to launch an entry (exit 3). Nothing was launched for it."""

    def __init__(self, code, message, entry_id=None):
        super().__init__(message)
        self.code, self.message, self.entry_id = code, message, entry_id


class Deferred(Exception):
    """The server is configured for another model: the entry stays pending (not an error)."""

    def __init__(self, entry_id, wanted, configured):
        super().__init__(entry_id)
        self.entry_id, self.wanted, self.configured = entry_id, wanted, configured


class LockHeld(Exception):
    pass


class TransportError(Exception):
    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


# ------------------------------------------------------------------ small helpers

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def fmt_usd(value):
    return format(value.quantize(Decimal("0.00000001"), rounding=ROUND_UP), "f")


def trunc(value, limit=300):
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    return text if len(text) <= limit else text[:limit] + "..."


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _constant(_name):
    raise ValueError("non-finite number")


def load_json(raw):
    """Strict JSON: duplicate keys and NaN/Infinity are errors. Raises ValueError/RecursionError."""
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)


def parse_json(raw):
    try:
        return load_json(raw)
    except (ValueError, RecursionError):
        return None


def report_sha256(doc):
    """Method of services/agent/experiment.HASH_METHOD: report without 'sha256', sorted keys, compact, ensure_ascii=False."""
    body = {key: value for key, value in doc.items() if key != "sha256"}
    try:
        return sha256_hex(json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    except (UnicodeEncodeError, TypeError, ValueError):
        return None


def write_atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with open(temporary, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def dump_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


# ------------------------------------------------------------------ redaction

class Redactor:
    """Replaces the operator token (and its URL-encoded form) and any 'Bearer ...' text. Everything printed or stored goes through it."""

    def __init__(self, token):
        self.token = token or ""
        forms = {self.token, urllib.parse.quote(self.token, safe=""), json.dumps(self.token)[1:-1]} if self.token else set()
        self._forms = sorted((form for form in forms if form), key=len, reverse=True)

    def text(self, value):
        text = value if isinstance(value, str) else str(value)
        for form in self._forms:
            text = text.replace(form, "[redacted]")
        return BEARER_RE.sub("Bearer [redacted]", text)

    def obj(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {(self.text(k) if isinstance(k, str) else k): self.obj(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.obj(v) for v in value]
        return value

    def contains(self, raw):
        if not self.token:
            return False
        text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
        return any(form in text for form in self._forms)


# ------------------------------------------------------------------ plan: validation and worst case

def _closed(obj, required, optional=(), where="plan"):
    if not isinstance(obj, dict):
        raise PlanError(where + " must be an object")
    keys = set(obj)
    missing = set(required) - keys
    extra = keys - set(required) - set(optional)
    if missing:
        raise PlanError("%s: missing keys %s" % (where, sorted(missing)))
    if extra:
        raise PlanError("%s: unknown keys %s" % (where, sorted(extra)))


def _int(value, low, high, where):
    if type(value) is not int or not low <= value <= high:
        raise PlanError("%s must be an integer from %d to %d" % (where, low, high))
    return value


def _str(value, where, pattern=None, maxlen=300):
    if not isinstance(value, str) or len(value) > maxlen or (pattern is not None and not pattern.fullmatch(value)):
        raise PlanError("%s is not a valid string" % where)
    return value


def _dec(value, where):
    if not isinstance(value, str) or not DEC_RE.fullmatch(value):
        raise PlanError("%s must be a decimal string such as \"0.25\" (never a JSON number)" % where)
    return Decimal(value)


def catalog_prices(catalog_doc, model_id):
    """(prompt, completion) USD per token from the saved catalog; requires the 'tools' parameter to be listed."""
    try:
        models = catalog_doc["models"]["data"]["data"]
    except (KeyError, TypeError):
        raise PlanError("catalog: unexpected structure") from None
    found = next((m for m in models if isinstance(m, dict) and m.get("id") == model_id), None) if isinstance(models, list) else None
    if found is None:
        raise PlanError("catalog: model %s is not listed" % model_id)

    def price(modalities, kind):
        for modality in found.get(modalities) or []:
            if isinstance(modality, dict) and modality.get("type") == "text":
                for item in modality.get("pricing") or []:
                    if isinstance(item, dict) and item.get("type") == kind and item.get("unit") == "token":
                        try:
                            return Decimal(str(item.get("cost_usd")))
                        except InvalidOperation:
                            break
        raise PlanError("catalog: %s has no text %s price per token" % (model_id, kind))

    tools_listed = any(isinstance(m, dict) and m.get("type") == "text" and isinstance(m.get("supported_parameters"), dict) and "tools" in m["supported_parameters"]
                       for m in found.get("output_modalities") or [])
    if not tools_listed:
        raise PlanError("catalog: %s does not list the tools parameter" % model_id)
    return price("input_modalities", "prompt"), price("output_modalities", "completion")


def prompt_tokens_bound(budget):
    scaled = (Decimal(budget["input_char_limit"]) * budget["tokens_per_char_upper"]).to_integral_value(rounding=ROUND_UP)
    return int(scaled) + budget["request_overhead_tokens"]


def call_bound_usd(budget, price):
    return Decimal(prompt_tokens_bound(budget)) * price["prompt"] + Decimal(budget["output_tokens_per_call"]) * price["completion"]


def entry_calls(levels):
    return sum(LEVEL_CALLS[level] for level in levels)


def validate_plan(doc, root=REPO_ROOT):
    """Normalized plan (Decimals, tuples) or PlanError. Closed schema: nothing unknown is tolerated."""
    _closed(doc, ("schema", "plan_id", "budget", "catalog", "models", "limits", "entries"), ("note", "compare", "prior_evidence"))
    if doc["schema"] != PLAN_SCHEMA:
        raise PlanError("schema must be " + PLAN_SCHEMA)
    plan_id = _str(doc["plan_id"], "plan_id", PLAN_ID_RE)
    note = _str(doc.get("note", ""), "note")

    b = doc["budget"]
    _closed(b, ("cap_usd", "output_tokens_per_call", "input_char_limit", "tokens_per_char_upper", "request_overhead_tokens"), where="budget")
    cap = _dec(b["cap_usd"], "budget.cap_usd")
    if not 0 < cap <= ABSOLUTE_CAP:
        raise PlanError("budget.cap_usd must be > 0 and <= " + str(ABSOLUTE_CAP))
    if _int(b["output_tokens_per_call"], 1, 10 ** 6, "budget.output_tokens_per_call") != OUTPUT_TOKENS_PER_CALL:
        raise PlanError("budget.output_tokens_per_call must be %d (what the server requests)" % OUTPUT_TOKENS_PER_CALL)
    if _int(b["input_char_limit"], 1, 10 ** 7, "budget.input_char_limit") != INPUT_CHAR_LIMIT:
        raise PlanError("budget.input_char_limit must be %d (the server input limit)" % INPUT_CHAR_LIMIT)
    tpc = _dec(b["tokens_per_char_upper"], "budget.tokens_per_char_upper")
    if tpc != 4:
        raise PlanError("budget.tokens_per_char_upper must be 4 (conservative UTF-8 byte bound)")
    budget = {"cap": cap, "output_tokens_per_call": OUTPUT_TOKENS_PER_CALL, "input_char_limit": INPUT_CHAR_LIMIT, "tokens_per_char_upper": tpc,
              "request_overhead_tokens": _int(b["request_overhead_tokens"], 4096, 4096, "budget.request_overhead_tokens")}

    c = doc["catalog"]
    _closed(c, ("path", "sha256"), where="catalog")
    rel = _str(c["path"], "catalog.path", maxlen=200)
    root = Path(root).resolve()
    target = (root / rel).resolve()
    if not target.is_relative_to(root):
        raise PlanError("catalog.path must stay inside the repository")
    if not target.is_file():
        raise PlanError("catalog file does not exist")
    raw = target.read_bytes()
    if not SHA_RE.fullmatch(str(c["sha256"])) or sha256_hex(raw) != c["sha256"]:
        raise PlanError("catalog.sha256 does not match the catalog file")
    catalog = parse_json(raw)
    if catalog is None:
        raise PlanError("catalog is not valid JSON")

    models = doc["models"]
    if not isinstance(models, dict) or not models or not set(models) <= set(ALLOWED_MODELS):
        raise PlanError("models must be a non-empty object limited to " + ", ".join(ALLOWED_MODELS))
    prices = {}
    for model, item in models.items():
        _closed(item, ("prompt_usd_per_token", "completion_usd_per_token"), where="models." + model)
        declared = {"prompt": _dec(item["prompt_usd_per_token"], model + " prompt price"), "completion": _dec(item["completion_usd_per_token"], model + " completion price")}
        listed = catalog_prices(catalog, model)
        if (declared["prompt"], declared["completion"]) != listed:
            raise PlanError("models.%s: prices differ from the catalog" % model)
        prices[model] = declared

    lim = doc["limits"]
    _closed(lim, ("poll_interval_s", "run_timeout_s", "http_timeout_s", "cancel_grace_s"), where="limits")
    limits = {"poll_interval_s": _int(lim["poll_interval_s"], 1, 30, "limits.poll_interval_s"), "run_timeout_s": _int(lim["run_timeout_s"], 60, 1800, "limits.run_timeout_s"),
              "http_timeout_s": _int(lim["http_timeout_s"], 5, 30, "limits.http_timeout_s"), "cancel_grace_s": _int(lim["cancel_grace_s"], 10, 300, "limits.cancel_grace_s")}

    raw_entries = doc["entries"]
    if not isinstance(raw_entries, list) or not 1 <= len(raw_entries) <= 3:
        raise PlanError("entries must be a list of 1 to 3 items")
    entries, seen_ids, seen_combos = [], set(), set()
    for index, item in enumerate(raw_entries):
        where = "entries[%d]" % index
        _closed(item, ("entry_id", "model", "levels", "expected_origin"), where=where)
        entry_id = _str(item["entry_id"], where + ".entry_id", ENTRY_ID_RE)
        if entry_id in seen_ids:
            raise PlanError("duplicate entry_id " + entry_id)
        seen_ids.add(entry_id)
        if not isinstance(item["levels"], list) or not all(isinstance(x, str) for x in item["levels"]):
            raise PlanError(where + ".levels must be a list of strings")
        levels = tuple(item["levels"])
        if not isinstance(item["model"], str):
            raise PlanError(where + ".model must be a string")
        combo = (item["model"], levels)
        if combo not in ALLOWED_ENTRIES:
            raise PlanError("%s: (model, levels) is not one of the exact entries this runner accepts" % where)
        if combo in seen_combos:
            raise PlanError(where + ": repeated combination of model and levels")
        seen_combos.add(combo)
        if item["model"] not in prices:
            raise PlanError("%s: model %s has no price in models" % (where, item["model"]))
        if item["expected_origin"] not in ("real", "fixture"):
            raise PlanError(where + ".expected_origin must be real or fixture")
        calls = entry_calls(levels)
        entries.append({"entry_id": entry_id, "model": item["model"], "levels": levels, "expected_origin": item["expected_origin"], "calls": calls,
                        "worst_usd": calls * call_bound_usd(budget, prices[item["model"]])})
    by_id = {e["entry_id"]: e for e in entries}

    compare = []
    raw_compare = doc.get("compare", [])
    if not isinstance(raw_compare, list) or len(raw_compare) > 3:
        raise PlanError("compare must be a list of at most 3 pairs")
    for index, pair in enumerate(raw_compare):
        _closed(pair, ("left", "right"), where="compare[%d]" % index)
        if not isinstance(pair["left"], str) or not isinstance(pair["right"], str):
            raise PlanError("compare[%d] must reference entries by id" % index)
        left, right = by_id.get(pair["left"]), by_id.get(pair["right"])
        if left is None or right is None or left is right:
            raise PlanError("compare[%d] must reference two different entries of the plan" % index)
        if left["levels"] != ("workflow",) or right["levels"] != ("workflow",) or left["model"] == right["model"]:
            raise PlanError("compare[%d] must pair two workflow-only entries of different models" % index)
        if (pair["left"], pair["right"]) in [(p["left"], p["right"]) for p in compare]:
            raise PlanError("compare[%d] is repeated" % index)
        compare.append({"left": pair["left"], "right": pair["right"]})

    prior = []
    raw_prior = doc.get("prior_evidence", [])
    if not isinstance(raw_prior, list) or len(raw_prior) > 20:
        raise PlanError("prior_evidence must be a list of at most 20 items")
    for index, item in enumerate(raw_prior):
        where = "prior_evidence[%d]" % index
        _closed(item, ("level", "kind", "ref", "note"), where=where)
        if item["level"] not in ALL_LEVELS or item["kind"] not in ("real", "fixture"):
            raise PlanError(where + ": invalid level or kind")
        prior.append({"level": item["level"], "kind": item["kind"], "ref": _str(item["ref"], where + ".ref", maxlen=200), "note": _str(item["note"], where + ".note")})

    total_usd = sum((e["worst_usd"] for e in entries), Decimal(0))
    total_calls = sum(e["calls"] for e in entries)
    if total_calls > MAX_TOTAL_CALLS:
        raise PlanError("worst case %d calls exceeds %d" % (total_calls, MAX_TOTAL_CALLS))
    if total_usd > cap:
        raise PlanError("worst-case estimated cost %s USD exceeds the cap %s USD" % (fmt_usd(total_usd), fmt_usd(cap)))
    return {"plan_id": plan_id, "note": note, "budget": budget, "catalog": {"path": rel, "sha256": c["sha256"]}, "prices": prices, "limits": limits, "entries": entries,
            "compare": compare, "prior_evidence": prior, "worst_case": {"total_usd": total_usd, "total_calls": total_calls}}


def load_plan(path, root=REPO_ROOT):
    path = Path(path)
    if not path.is_file():
        raise PlanError("the plan file does not exist; it must be created and reviewed before running")
    raw = path.read_bytes()
    if len(raw) > MAX_PLAN_BYTES:
        raise PlanError("plan file is too large")
    doc = parse_json(raw)
    if doc is None:
        raise PlanError("plan is not valid strict JSON (duplicate keys and NaN are rejected)")
    plan = validate_plan(doc, root)
    plan["sha256"] = sha256_hex(raw)
    return plan


def build_default_plan(plan_id, root=REPO_ROOT):
    """The three-run plan as a JSON-ready dict, with prices read from the saved catalog. Offline; a human reviews it before use."""
    root = Path(root).resolve()
    raw = (root / DEFAULT_CATALOG).read_bytes()
    catalog = parse_json(raw)
    if catalog is None:
        raise PlanError("catalog is not valid JSON")
    prices = {}
    for model in ALLOWED_MODELS:
        prompt, completion = catalog_prices(catalog, model)
        prices[model] = {"prompt_usd_per_token": format(prompt, "f"), "completion_usd_per_token": format(completion, "f")}
    return {"schema": PLAN_SCHEMA, "plan_id": plan_id, "note": "P4 real batch: 3 runs, worst case 57 calls", "budget": {"cap_usd": "0.25", "output_tokens_per_call": OUTPUT_TOKENS_PER_CALL, "input_char_limit": INPUT_CHAR_LIMIT, "tokens_per_char_upper": "4", "request_overhead_tokens": 4096},
            "catalog": {"path": DEFAULT_CATALOG, "sha256": sha256_hex(raw)}, "models": prices,
            "limits": {"poll_interval_s": 3, "run_timeout_s": 900, "http_timeout_s": 20, "cancel_grace_s": 60},
            "entries": [{"entry_id": "wf-glm", "model": MODEL_1, "levels": ["workflow"], "expected_origin": "real"},
                        {"entry_id": "wf-qwen", "model": MODEL_2, "levels": ["workflow"], "expected_origin": "real"},
                        {"entry_id": "four-glm", "model": MODEL_1, "levels": list(FOUR_LEVELS), "expected_origin": "real"}],
            "compare": [{"left": "wf-glm", "right": "wf-qwen"}], "prior_evidence": []}


# ------------------------------------------------------------------ spend bound

def spend_bound(plan, entry, usage, final=True):
    """Upper-bound estimate (USD, catalog prices) of what one entry consumed. Unknown is never zero.

    Known attempts are priced at their reported tokens and the requested model's price; an attempt (or half an attempt) without
    data is priced at the worst case per call. With final=True and a measurement that did not finish, the calls up to the entry
    maximum that were not measured are priced at the worst case as well. Usage that is unavailable prices the whole entry.
    """
    price, budget = plan["prices"][entry["model"]], plan["budget"]
    prompt_worst = Decimal(prompt_tokens_bound(budget)) * price["prompt"]
    completion_worst = Decimal(budget["output_tokens_per_call"]) * price["completion"]
    per_call = prompt_worst + completion_worst
    info = {"bound_usd": Decimal(0), "known_usd": Decimal(0), "known_attempts": 0, "unknown_attempts": 0, "prompt_tokens_known": 0, "completion_tokens_known": 0,
            "unmeasured_calls": 0, "returned_models": [], "returned_model_unknown_attempts": 0, "returned_model_differs_attempts": 0, "attempts": None,
            "measurement_finished": None, "complete": False, "basis": "attempts_priced"}
    attempts = usage.get("attempts") if isinstance(usage, dict) else None
    if not isinstance(attempts, list) or type(usage.get("attempts_total")) is not int:
        info.update(bound_usd=entry["worst_usd"], basis="usage_unavailable_entry_worst_case")
        return info
    info["attempts"] = len(attempts)
    models = set()
    for attempt in attempts:
        a = attempt if isinstance(attempt, dict) else {}
        p, c = a.get("prompt_tokens"), a.get("completion_tokens")
        p_ok, c_ok = type(p) is int and p >= 0, type(c) is int and c >= 0
        info["bound_usd"] += (Decimal(p) * price["prompt"] if p_ok else prompt_worst) + (Decimal(c) * price["completion"] if c_ok else completion_worst)
        if p_ok and c_ok:
            info["known_attempts"] += 1
            info["known_usd"] += Decimal(p) * price["prompt"] + Decimal(c) * price["completion"]
            info["prompt_tokens_known"] += p
            info["completion_tokens_known"] += c
        else:
            info["unknown_attempts"] += 1
        returned = a.get("returned_model")
        if isinstance(returned, str):
            models.add(returned)
            if returned != entry["model"]:
                info["returned_model_differs_attempts"] += 1
        else:
            info["returned_model_unknown_attempts"] += 1
    info["returned_models"] = sorted(models)
    measurement = usage.get("measurement")
    finished = isinstance(measurement, dict) and measurement.get("collection_finished") is True
    info["measurement_finished"] = finished
    if final and not finished:
        info["unmeasured_calls"] = max(0, entry["calls"] - len(attempts))
        info["bound_usd"] += per_call * info["unmeasured_calls"]
    info["complete"] = info["unknown_attempts"] == 0 and (finished or not final)
    return info


# ------------------------------------------------------------------ report reading (copy, never recompute)

def assess_cleanup(entry, summary):
    """Per-level cleanup reading of the backend summary. confirmed | unconfirmed | unknown | not_applicable."""
    per_level = {}
    for level in entry["levels"]:
        item = summary.get(level) if isinstance(summary, dict) else None
        if not isinstance(item, dict):
            per_level[level] = "unknown"
        elif item.get("outcome") == "not_run":
            per_level[level] = "not_applicable"
        elif item.get("cleanup_confirmed") is True:
            per_level[level] = "confirmed"
        elif item.get("cleanup_confirmed") is False:
            per_level[level] = "unconfirmed"
        elif level == "injection":
            per_level[level] = "not_applicable"  # no sandbox at that level; an explicit boolean above still wins
        else:
            per_level[level] = "unknown"
    values = set(per_level.values())
    status = "unconfirmed" if "unconfirmed" in values else "unknown" if "unknown" in values else "confirmed" if "confirmed" in values else "not_applicable"
    return {"status": status, "per_level": per_level}


def _axis(value):
    return value.get("status") if isinstance(value, dict) and isinstance(value.get("status"), str) else None


def _variant_rows(item):
    rows = {}
    for field in ("variants", "completed_variants", "observed_variants"):
        group = item.get(field)
        if not isinstance(group, dict):
            continue
        for name, variant in group.items():
            if isinstance(name, str) and isinstance(variant, dict) and name not in rows:
                outcome = variant.get("outcome")
                task, containment = variant.get("task"), variant.get("containment")
                rows[name] = {"outcome": outcome if outcome in KNOWN_OUTCOMES else "unknown", "task": _axis(task), "task_reason": task.get("reason") if isinstance(task, dict) else None,
                              "containment": _axis(containment), "containment_reason": containment.get("reason") if isinstance(containment, dict) else None,
                              "cleanup_confirmed": variant.get("cleanup_confirmed") if isinstance(variant.get("cleanup_confirmed"), bool) else None, "source": field}
    return rows


def level_results(entry, summary):
    results = {}
    for level in entry["levels"]:
        item = summary.get(level) if isinstance(summary, dict) else None
        if not isinstance(item, dict):
            results[level] = {"outcome": "missing", "evidence": None, "cleanup_confirmed": None}
            continue
        outcome = item.get("outcome")
        record = {"outcome": outcome if outcome in KNOWN_OUTCOMES else "unknown", "evidence": trunc(item.get("evidence")),
                  "cleanup_confirmed": item.get("cleanup_confirmed") if isinstance(item.get("cleanup_confirmed"), bool) else None}
        if isinstance(item.get("containment"), str):
            record["containment"] = item["containment"]
        if level == "workflow":
            record["variants"] = _variant_rows(item)
        results[level] = record
    return results


# ------------------------------------------------------------------ ledger

class Ledger:
    """Append-only JSON lines, fsync per event, redacted before writing. Reading tolerates only a truncated final line."""

    def __init__(self, path, redactor):
        self.path, self.redactor = path, redactor
        path.parent.mkdir(parents=True, exist_ok=True)
        self.discarded = self._repair_tail(path)
        self.seq = len(self.read(path))
        self._handle = open(path, "ab")

    @staticmethod
    def read(path):
        if not path.exists():
            return []
        lines = path.read_bytes().split(b"\n")
        events = []
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            try:
                record = load_json(line)
            except (ValueError, RecursionError):
                if index == len(lines) - 1:
                    break  # a write cut short by a crash
                raise PlanError("ledger is corrupt at line %d" % (index + 1)) from None
            if not isinstance(record, dict) or not isinstance(record.get("kind"), str):
                raise PlanError("ledger has a malformed event at line %d" % (index + 1))
            events.append(record)
        return events

    @staticmethod
    def _repair_tail(path):
        if not path.exists():
            return 0
        data = path.read_bytes()
        if not data or data.endswith(b"\n"):
            return 0
        cut = data.rfind(b"\n") + 1
        tail = data[cut:]
        if parse_json(tail) is not None:
            with open(path, "ab") as handle:
                handle.write(b"\n")
            return 0
        write_atomic(path, data[:cut])
        return len(tail)

    def append(self, kind, **data):
        self.seq += 1
        record = self.redactor.obj({"seq": self.seq, "ts": now_iso(), "kind": kind, **data})
        self._handle.write(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n")
        self._handle.flush()
        os.fsync(self._handle.fileno())
        return record

    def close(self):
        self._handle.close()


def new_entry_state():
    return {"intent": False, "outcome": None, "http_status": None, "run_id": None, "terminal": None, "report": False, "done": False, "cancel_sent": False, "spend": None}


class LedgerState:
    def __init__(self, entry_ids, plan_sha):
        self.entries = {entry_id: new_entry_state() for entry_id in entry_ids}
        self.plan_sha = plan_sha
        self.forbid = None
        self.compared = set()
        self.compare_info = {}

    def apply(self, record):
        kind, entry_id = record.get("kind"), record.get("entry_id")
        if kind == "session_start" and record.get("plan_sha256") != self.plan_sha:
            raise PlanError("the ledger belongs to a different plan (SHA-256 differs); use a new plan_id for a new plan")
        state = None
        if entry_id is not None:
            if entry_id not in self.entries:
                raise PlanError("the ledger mentions an entry that is not in the plan")
            state = self.entries[entry_id]
        if kind == "post_intent":
            state["intent"] = True
        elif kind == "post_result":
            state["outcome"], state["http_status"] = record.get("outcome"), record.get("http_status")
            if record.get("outcome") == "accepted":
                state["run_id"] = record.get("run_id")
        elif kind == "attach":
            state["run_id"], state["outcome"] = record.get("run_id"), "accepted"
        elif kind == "cancel_sent":
            state["cancel_sent"] = True
        elif kind == "terminal":
            state["terminal"] = record.get("status")
        elif kind == "report_saved":
            state["report"] = True
        elif kind == "spend":
            state["spend"] = record.get("bound_usd")
        elif kind == "entry_done":
            state["done"] = True
        elif kind == "compare_done":
            key = (record.get("left"), record.get("right"))
            self.compared.add(key)
            self.compare_info[key] = {k: record.get(k) for k in ("http_status", "comparable", "reasons", "file")}
        elif kind == "halt" and record.get("forbid_new_posts"):
            self.forbid = record.get("code")


def foreign_launches(out_dir, own_ledger):
    """(model, levels) combinations launched under OTHER ledgers of the same directory."""
    found = {}
    for path in sorted(out_dir.glob("*.ledger.jsonl")):
        if path.name == own_ledger.name:
            continue
        for record in Ledger.read(path):
            if record.get("kind") == "post_intent":
                found[(record.get("model"), tuple(record.get("levels") or []))] = path.name
    return found


# ------------------------------------------------------------------ lock

class TargetLock:
    """Exclusive lock per destination, created with O_EXCL before any network traffic. Never stolen automatically."""

    def __init__(self, path, info):
        self.path, self.info, self.held = path, info, False

    def acquire(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise LockHeld("lock exists: " + str(self.path)) from None
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(self.info, sort_keys=True))
            handle.flush()
            os.fsync(handle.fileno())
        self.held = True

    def release(self):
        if self.held:
            self.held = False
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass


# ------------------------------------------------------------------ HTTP

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class UrllibTransport:
    """Standard-library transport: no environment proxies, no redirects, bounded body. The Bearer is attached only when auth=True."""

    def __init__(self, base_url, token, timeout):
        self.base, self._token, self.timeout = base_url.rstrip("/"), token, timeout
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def request(self, method, path, *, auth=False, body=None, timeout=None):
        headers = {"Accept": "application/json", "User-Agent": "escape-p4-batch/" + RUNNER_VERSION}
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif method == "POST":
            data = b""
        if auth:
            headers["Authorization"] = "Bearer " + self._token
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with self._opener.open(request, timeout=timeout or self.timeout) as response:
                status, payload = response.status, response.read(MAX_BODY_BYTES + 1)
        except urllib.error.HTTPError as exc:
            try:
                status, payload = exc.code, exc.read(MAX_BODY_BYTES + 1)
            finally:
                exc.close()
        except (TimeoutError, socket.timeout):
            raise TransportError("timeout") from None
        except urllib.error.URLError as exc:
            raise TransportError("timeout" if isinstance(exc.reason, (TimeoutError, socket.timeout)) else "network") from None
        except OSError:
            raise TransportError("network") from None
        if len(payload) > MAX_BODY_BYTES:
            raise TransportError("too_large")
        return status, payload


PostResult = collections.namedtuple("PostResult", "kind status parsed detail leak")


class Api:
    """GET with bounded retries; POST exactly once. 401/429 are never retried and always stop the batch."""

    def __init__(self, transport, redactor, sleep, retries=2, backoff=1.0):
        self.transport, self.redactor, self.sleep, self.retries, self.backoff = transport, redactor, sleep, retries, backoff

    def _guard(self, status, raw, where):
        if self.redactor.contains(raw):
            raise Halt("token_echo", "the operator token appeared in a response (%s); stopping" % where)
        if status == 401:
            raise Halt("auth_401", "401 from %s: the operator token was rejected or is missing" % where)
        if status == 429:
            raise Halt("rate_429", "429 from %s: rate limit or too many failed authorizations" % where)

    def get_json(self, path, auth=False):
        where = path.split("?")[0]
        for attempt in range(self.retries + 1):
            try:
                status, raw = self.transport.request("GET", path, auth=auth)
            except TransportError as exc:
                if attempt < self.retries:
                    self.sleep(self.backoff * (attempt + 1))
                    continue
                raise Halt("infra_unreachable", "GET %s failed (%s) after %d attempts" % (where, exc.kind, attempt + 1), forbid_new_posts=False) from None
            if status in (502, 503, 504) and attempt < self.retries:
                self.sleep(self.backoff * (attempt + 1))
                continue
            self._guard(status, raw, where)
            if status >= 500:
                raise Halt("infra_error", "GET %s -> HTTP %d" % (where, status), forbid_new_posts=False)
            return status, parse_json(raw), raw
        raise AssertionError("unreachable")

    def post_once(self, path, body):
        try:
            status, raw = self.transport.request("POST", path, auth=True, body=body)
        except TransportError as exc:
            return PostResult("lost", None, None, exc.kind, False)
        return PostResult("response", status, parse_json(raw), "", self.redactor.contains(raw))


# ------------------------------------------------------------------ the batch

class Batch:
    def __init__(self, plan, *, out_dir, api, redactor, clock, sleep, say, base_host, insecure=False, only=(), allow_repeat=None, attach=None):
        self.plan, self.out_dir, self.api, self.redactor = plan, Path(out_dir), api, redactor
        self.clock, self.sleep, self.say = clock, sleep, say
        self.base_host, self.insecure = base_host, insecure
        self.only, self.allow_repeat, self.attach = set(only), dict(allow_repeat or {}), dict(attach or {})
        self.ledger_path = self.out_dir / (plan["plan_id"] + ".ledger.jsonl")
        self.entry_dir = self.out_dir / plan["plan_id"]
        self.by_id = {e["entry_id"]: e for e in plan["entries"]}
        self.deferred = []
        self.state = None
        self.ledger = None

    # -- bookkeeping
    def log(self, kind, **data):
        record = self.ledger.append(kind, **data)
        self.state.apply(record)
        return record

    def committed(self, exclude=None):
        total = Decimal(0)
        for entry in self.plan["entries"]:
            if entry["entry_id"] == exclude:
                continue
            state = self.state.entries[entry["entry_id"]]
            if state["spend"] is not None:
                total += Decimal(state["spend"])
            elif state["intent"]:
                total += entry["worst_usd"]
        return total

    # -- main flow
    def run(self):
        events = Ledger.read(self.ledger_path)
        self.state = LedgerState([e["entry_id"] for e in self.plan["entries"]], self.plan["sha256"])
        for record in events:
            self.state.apply(record)
        self.ledger = Ledger(self.ledger_path, self.redactor)
        code = EXIT_OK
        try:
            self.log("session_start", plan_sha256=self.plan["sha256"], runner_version=RUNNER_VERSION, base_url_host=self.base_host, insecure_http=self.insecure,
                     only=sorted(self.only), tail_bytes_discarded=self.ledger.discarded)
            self._check_foreign()
            self._process_attach()
            self._check_unresolved()
            self._resume_inflight()
            self._launch_pending()
            self._compare_pairs()
            unfinished = [e["entry_id"] for e in self.plan["entries"] if not self.state.entries[e["entry_id"]]["done"] and (not self.only or e["entry_id"] in self.only)]
            if self.deferred:
                code = EXIT_PENDING
            elif unfinished:
                code = EXIT_HALT
                self.say("SIN TERMINAR (rechazadas o no resueltas en el ledger; nunca se reenvian): " + ", ".join(unfinished))
        except Halt as exc:
            code = EXIT_HALT
            self.say("DETENIDO [%s]: %s" % (exc.code, exc.message))
            self.log("halt", code=exc.code, message=exc.message, forbid_new_posts=exc.forbid_new_posts, **({"entry_id": exc.entry_id} if exc.entry_id else {}))
        except Refused as exc:
            code = EXIT_REFUSED
            self.say("RECHAZADO sin lanzar [%s]: %s" % (exc.code, exc.message))
            self.log("preflight_refused", code=exc.code, message=exc.message, **({"entry_id": exc.entry_id} if exc.entry_id else {}))
        except KeyboardInterrupt:
            code = EXIT_HALT
            self.say("INTERRUMPIDO: el ledger permite reanudar con el mismo plan (solo GET para lo ya lanzado).")
            self.log("halt", code="interrupted", message="operator interrupt", forbid_new_posts=False)
        finally:
            try:
                self._write_matrix()
            except Exception as exc:  # the matrix is derived; never mask the real outcome
                self.say("no se pudo escribir la matriz: " + type(exc).__name__)
            try:
                self.log("session_end", exit_code=code)
            finally:
                self.ledger.close()
        if self.deferred and code == EXIT_PENDING:
            for item in self.deferred:
                self.say("PENDIENTE %s: el servidor esta configurado con %s y la entrada necesita %s; reconfigurar y repetir el mismo comando." % item)
        return code

    def _check_foreign(self):
        others = foreign_launches(self.out_dir, self.ledger_path)
        for entry in self.plan["entries"]:
            entry_id, state = entry["entry_id"], self.state.entries[entry["entry_id"]]
            if state["intent"] or (self.only and entry_id not in self.only):
                continue
            key = (entry["model"], tuple(entry["levels"]))
            if key not in others:
                continue
            if entry_id not in self.allow_repeat:
                raise Refused("repeat_of_launched_entry", "entry %s: the same model and levels were already launched under ledger %s; a result is never repeated to improve it (--allow-repeat with a written reason is the explicit exception)" % (entry_id, others[key]), entry_id)
            self.log("repeat_allowed", entry_id=entry_id, reason=self.allow_repeat[entry_id], other_ledger=others[key])

    def _process_attach(self):
        for entry_id, run_id in self.attach.items():
            entry, state = self.by_id[entry_id], self.state.entries[entry_id]
            if not (state["intent"] and state["run_id"] is None and state["outcome"] != "rejected"):
                raise Refused("attach_not_applicable", "entry %s has no unresolved POST to attach to" % entry_id, entry_id)
            status, doc, _ = self.api.get_json("/api/runs/" + run_id)
            if status != 200 or not isinstance(doc, dict) or doc.get("id") != run_id or doc.get("model") != entry["model"] or doc.get("levels") != list(entry["levels"]):
                raise Refused("attach_mismatch", "run %s does not exist or does not match entry %s (model/levels)" % (run_id, entry_id), entry_id)
            self.log("attach", entry_id=entry_id, run_id=run_id, source="operator")
            self.say("ligada la corrida %s a la entrada %s" % (run_id, entry_id))

    def _check_unresolved(self):
        for entry in self.plan["entries"]:
            state = self.state.entries[entry["entry_id"]]
            if state["intent"] and state["run_id"] is None and state["outcome"] != "rejected":
                raise Halt("unresolved_post", "entry %s: a POST was attempted and its response is unknown; it is NEVER resent. Find the run with GET /api/runs and use --attach, or start a new plan after review" % entry["entry_id"], entry["entry_id"])

    def _resume_inflight(self):
        for entry in self.plan["entries"]:
            state = self.state.entries[entry["entry_id"]]
            if state["run_id"] and not state["done"]:
                self.say("reanudando %s (corrida %s): solo GET" % (entry["entry_id"], state["run_id"]))
                self._finish_entry(entry, state["run_id"])

    def _launch_pending(self):
        for entry in self.plan["entries"]:
            entry_id, state = entry["entry_id"], self.state.entries[entry["entry_id"]]
            if state["intent"] or (self.only and entry_id not in self.only):
                continue
            if self.state.forbid is not None:
                raise Halt("ledger_forbids_new_posts", "this ledger recorded a halt (%s) that forbids new launches; review it and use a new plan_id if appropriate" % self.state.forbid, entry_id)
            try:
                self._launch(entry)
            except Deferred as exc:
                self.deferred.append((exc.entry_id, exc.configured, exc.wanted))

    def _preflight(self, entry):
        entry_id, plan = entry["entry_id"], self.plan
        status, config, _ = self.api.get_json("/api/config")
        if status != 200 or not isinstance(config, dict):
            raise Halt("malformed_response", "GET /api/config returned an unusable answer", entry_id, forbid_new_posts=False)
        models = config.get("models")
        if models != [entry["model"]]:
            if isinstance(models, list) and len(models) == 1 and models[0] in plan["prices"] and models[0] != entry["model"]:
                raise Deferred(entry_id, entry["model"], models[0])
            raise Refused("model_not_configured", "the server models %s do not include exactly the entry model %s" % (trunc(models, 120), entry["model"]), entry_id)
        if config.get("execution_mode") != "docker":
            raise Refused("execution_mode", "execution_mode is not docker", entry_id)
        if config.get("configured") is not True or config.get("run_available") is not True:
            raise Refused("run_unavailable", "run_available is not true (admission_blocked=%s, quota_exhausted=%s)" % (trunc(config.get("admission_blocked"), 80), config.get("quota_exhausted")), entry_id)
        if config.get("admission_blocked") is not None:
            raise Refused("admission_blocked", "admission is blocked: " + trunc(config.get("admission_blocked"), 80), entry_id)
        if config.get("cancel_supported") is not True:
            raise Refused("cancel_unsupported", "the server does not report cancel_supported", entry_id)
        if config.get("evidence_origin") != entry["expected_origin"]:
            raise Refused("origin_mismatch", "the server declares evidence_origin=%s but the entry expects %s" % (trunc(config.get("evidence_origin"), 40), entry["expected_origin"]), entry_id)
        profile = config.get("profile") if isinstance(config.get("profile"), dict) else {}
        budgets = profile.get("budgets") if isinstance(profile.get("budgets"), dict) else {}
        if profile.get("input_limit_chars") != plan["budget"]["input_char_limit"] or budgets.get("output_tokens_reserved_per_call") != plan["budget"]["output_tokens_per_call"]:
            raise Refused("limits_differ", "the server input/output limits differ from the plan; the cost bound would not hold", entry_id)
        limits = profile.get("level_call_limits") if isinstance(profile.get("level_call_limits"), dict) else {}
        per_level = limits.get("per_level") if isinstance(limits.get("per_level"), dict) else {}
        for level in entry["levels"]:
            value = per_level.get(level)
            if type(value) is not int or value > LEVEL_CALLS[level]:
                raise Refused("level_limit_exceeds_plan", "level %s: server call limit %s is unknown or above the plan's %d" % (level, value, LEVEL_CALLS[level]), entry_id)
        quota = config.get("quota_remaining")
        need_tokens = entry["calls"] * plan["budget"]["output_tokens_per_call"]
        if not isinstance(quota, dict) or type(quota.get("runs_remaining")) is not int or type(quota.get("calls_remaining")) is not int or type(quota.get("output_tokens_remaining")) is not int:
            raise Refused("quota_unknown", "quota_remaining is unavailable", entry_id)
        if quota["runs_remaining"] < 1 or quota["calls_remaining"] < entry["calls"] or quota["output_tokens_remaining"] < need_tokens:
            raise Refused("quota_insufficient", "operational quota does not cover the entry worst case (runs>=1, calls>=%d, output tokens>=%d); quotas are never raised by this runner. Remaining: %s" % (entry["calls"], need_tokens, json.dumps(quota, sort_keys=True)), entry_id)
        if self.committed() + entry["worst_usd"] > plan["budget"]["cap"]:
            raise Refused("budget_cap", "committed spend %s + worst case %s would exceed the cap %s USD" % (fmt_usd(self.committed()), fmt_usd(entry["worst_usd"]), fmt_usd(plan["budget"]["cap"])), entry_id)
        return config

    def _launch(self, entry):
        entry_id = entry["entry_id"]
        self._preflight(entry)
        body = {"model": entry["model"], "levels": list(entry["levels"])}
        # Durable intent BEFORE the only POST: a crash or a lost answer afterwards is 'unresolved' and never resent.
        self.log("post_intent", entry_id=entry_id, model=entry["model"], levels=list(entry["levels"]), expected_origin=entry["expected_origin"], calls=entry["calls"], worst_usd=fmt_usd(entry["worst_usd"]))
        self.say("lanzando %s (%s, %s): un solo POST, sin reintento" % (entry_id, entry["model"], ",".join(entry["levels"])))
        result = self.api.post_once("/api/runs", body)
        run_id = self._record_post(entry, result)
        self.say("corrida %s capturada para %s" % (run_id, entry_id))
        self._finish_entry(entry, run_id)

    def _record_post(self, entry, result):
        entry_id = entry["entry_id"]
        halt = None
        run_id = None
        if result.kind == "lost":
            self.log("post_result", entry_id=entry_id, outcome="lost", detail=result.detail)
            halt = ("unresolved_post", "the POST for %s got no answer (%s); the run may exist and the POST is never resent" % (entry_id, result.detail))
        else:
            status, parsed = result.status, result.parsed
            detail = trunc(parsed.get("detail"), 200) if isinstance(parsed, dict) else ""
            if status == 202:
                candidate = parsed.get("id") if isinstance(parsed, dict) else None
                if isinstance(candidate, str) and RUN_ID_RE.fullmatch(candidate):
                    run_id = candidate
                    self.log("post_result", entry_id=entry_id, outcome="accepted", http_status=202, run_id=run_id)
                else:
                    self.log("post_result", entry_id=entry_id, outcome="lost", http_status=202, detail="accepted_without_valid_id")
                    halt = ("unresolved_post", "the POST for %s was accepted without a valid run id; it is never resent" % entry_id)
            elif status >= 500 and status != 503:
                self.log("post_result", entry_id=entry_id, outcome="lost", http_status=status, detail=detail)
                halt = ("unresolved_post", "the POST for %s returned HTTP %d; the run may exist and the POST is never resent" % (entry_id, status))
            else:
                self.log("post_result", entry_id=entry_id, outcome="rejected", http_status=status, detail=detail)
                if status == 401:
                    halt = ("auth_401", "401 on the launch POST: the operator token was rejected or is missing")
                elif status == 429:
                    halt = ("rate_429", "429 on the launch POST (rate limit or quota refusal): " + detail)
                elif status == 503:
                    halt = ("infra_unavailable", "503 on the launch POST (infrastructure or admission closed): " + detail)
                else:
                    halt = ("post_rejected", "the launch POST for %s was rejected with HTTP %s: %s" % (entry_id, status, detail))
        if result.leak:
            raise Halt("token_echo", "the operator token appeared in the POST response; stopping", entry_id)
        if halt is not None:
            raise Halt(halt[0], halt[1], entry_id)
        return run_id

    def _cancel(self, entry, run_id, reason):
        entry_id = entry["entry_id"]
        if self.state.entries[entry_id]["cancel_sent"]:
            return
        result = self.api.post_once("/api/runs/%s/cancel" % run_id, None)
        # Recorded whatever happened: the cancel request is sent at most once per entry.
        self.log("cancel_sent", entry_id=entry_id, run_id=run_id, reason=reason, response_kind=result.kind, http_status=result.status)
        if result.leak:
            raise Halt("token_echo", "the operator token appeared in a response; stopping", entry_id)
        if result.status == 401:
            raise Halt("auth_401", "401 on the cancel POST", entry_id)
        if result.status == 429:
            raise Halt("rate_429", "429 on the cancel POST", entry_id)
        self.say("cancelacion solicitada para %s (%s); se espera el estado terminal" % (entry_id, reason))

    def _wait_terminal(self, entry, run_id):
        entry_id, limits = entry["entry_id"], self.plan["limits"]
        state = self.state.entries[entry_id]
        deadline = self.clock() + limits["run_timeout_s"]
        cancel_deadline = None
        last, polls = None, 0
        while True:
            status, doc, _ = self.api.get_json("/api/runs/" + run_id)
            if status == 404:
                raise Halt("run_not_found", "run %s of %s is unknown to the server (404)" % (run_id, entry_id), entry_id)
            if status != 200 or not isinstance(doc, dict) or doc.get("id") != run_id:
                raise Halt("malformed_response", "GET /api/runs/%s returned an unusable answer" % run_id, entry_id)
            current = doc.get("status")
            if current != last:
                self.say("%s: %s" % (entry_id, current))
                self.log("status", entry_id=entry_id, run_id=run_id, status=current if isinstance(current, str) else None)
                last = current
            if current in TERMINAL:
                return doc
            if current not in ("queued", "running"):
                raise Halt("malformed_response", "unknown run status for " + run_id, entry_id)
            polls += 1
            if polls % SPEND_CHECK_EVERY == 0:
                self._check_midrun_spend(entry, run_id)
            now = self.clock()
            if state["cancel_sent"] and cancel_deadline is None:
                cancel_deadline = now + limits["cancel_grace_s"]
            if cancel_deadline is None and now >= deadline:
                self._cancel(entry, run_id, "run_timeout")
                cancel_deadline = self.clock() + limits["cancel_grace_s"]
            if cancel_deadline is not None and self.clock() >= cancel_deadline:
                raise Halt("timeout_unresolved", "%s (run %s) did not reach a terminal state after the timeout and one cancel request; its cleanup is unknown" % (entry_id, run_id), entry_id)
            self.sleep(limits["poll_interval_s"])

    def _check_midrun_spend(self, entry, run_id):
        status, report, _ = self.api.get_json("/api/runs/%s/report?format=json" % run_id)
        if status != 200 or not isinstance(report, dict) or not isinstance(report.get("usage"), dict):
            return
        bound = spend_bound(self.plan, entry, report["usage"], final=False)
        if self.committed(exclude=entry["entry_id"]) + bound["bound_usd"] > self.plan["budget"]["cap"]:
            self._cancel(entry, run_id, "budget_exceeded")
            raise Halt("budget_exceeded", "estimated spend %s USD already exceeds the cap %s USD while %s runs" % (fmt_usd(self.committed(exclude=entry["entry_id"]) + bound["bound_usd"]), fmt_usd(self.plan["budget"]["cap"]), entry["entry_id"]), entry["entry_id"])

    def _observe_origin(self, run_id):
        cursor = None
        for _page in range(3):
            path = "/api/runs?limit=50" + ("&before=" + urllib.parse.quote(str(cursor), safe="") if cursor else "")
            status, data, _ = self.api.get_json(path, auth=True)
            if status != 200 or not isinstance(data, dict) or not isinstance(data.get("items"), list):
                return None
            for item in data["items"]:
                if isinstance(item, dict) and item.get("id") == run_id:
                    origin = item.get("origin")
                    return {"origin": origin if origin in ORIGINS else "unknown", "created_at": item.get("created_at") if isinstance(item.get("created_at"), str) else None,
                            "cancel_requested": item.get("cancel_requested") if isinstance(item.get("cancel_requested"), bool) else None}
            cursor = data.get("next_cursor")
            if not cursor:
                return None
        return None

    def _finish_entry(self, entry, run_id):
        run_doc = self._wait_terminal(entry, run_id)
        self._collect(entry, run_id, run_doc)

    def _collect(self, entry, run_id, run_doc):
        entry_id, state = entry["entry_id"], self.state.entries[entry["entry_id"]]
        if state["terminal"] is None:
            self.log("terminal", entry_id=entry_id, run_id=run_id, status=run_doc.get("status"))
        status, report, raw = self.api.get_json("/api/runs/%s/report?format=json" % run_id)
        if status != 200 or not isinstance(report, dict):
            raise Halt("report_unavailable", "the report of %s (run %s) is unavailable (HTTP %s)" % (entry_id, run_id, status), entry_id)
        report_file = self.entry_dir / (entry_id + ".report.json")
        write_atomic(report_file, raw)  # bytes exactly as received: the hash stays verifiable
        computed, claimed = report_sha256(report), report.get("sha256")
        hash_status = "verified" if isinstance(claimed, str) and claimed == computed else "mismatch"
        self.log("report_saved", entry_id=entry_id, run_id=run_id, file=report_file.name, sha256_claimed=claimed if isinstance(claimed, str) else None, sha256_computed=computed, hash_status=hash_status)

        run = report.get("run") if isinstance(report.get("run"), dict) else {}
        summary = run.get("summary") if isinstance(run.get("summary"), dict) else {}
        run_status = run.get("status") if isinstance(run.get("status"), str) else None
        levels = level_results(entry, summary)
        cleanup = assess_cleanup(entry, summary)
        cfg_status, config, _ = self.api.get_json("/api/config")
        admission = config.get("admission_blocked") if cfg_status == 200 and isinstance(config, dict) else "unreadable"
        cleanup_status = cleanup["status"]
        if admission == "cleanup_unconfirmed":
            cleanup_status = "unconfirmed"
        elif admission is not None and cleanup_status in ("confirmed", "not_applicable"):
            cleanup_status = "unknown"
        self.log("cleanup", entry_id=entry_id, run_id=run_id, status=cleanup_status, per_level=cleanup["per_level"], server_admission_blocked=admission if isinstance(admission, str) or admission is None else "unreadable")

        bound = spend_bound(self.plan, entry, report.get("usage"), final=True)
        spend_record = {"bound_usd": fmt_usd(bound["bound_usd"]), "known_usd": fmt_usd(bound["known_usd"]), "basis": bound["basis"], "known_attempts": bound["known_attempts"], "unknown_attempts": bound["unknown_attempts"],
                        "prompt_tokens_known": bound["prompt_tokens_known"], "completion_tokens_known": bound["completion_tokens_known"], "unmeasured_calls": bound["unmeasured_calls"], "measurement_finished": bound["measurement_finished"]}
        self.log("spend", entry_id=entry_id, run_id=run_id, **spend_record)

        origin = self._observe_origin(run_id)
        anomalies = []
        if run.get("model") != entry["model"]:
            anomalies.append("run_model_differs_from_requested")
        if bound["returned_model_differs_attempts"]:
            anomalies.append("returned_model_differs_from_requested")
        if bound["returned_model_unknown_attempts"] and bound["attempts"]:
            anomalies.append("returned_model_unknown_for_some_attempts")
        if bound["attempts"] is not None and bound["attempts"] > entry["calls"]:
            anomalies.append("more_attempts_than_the_call_limit")
        if origin is None:
            anomalies.append("origin_not_found_in_history")
        elif origin["origin"] != entry["expected_origin"]:
            anomalies.append("observed_origin_differs_from_expected")

        reasons = []
        if run_status != "completed":
            reasons.append("run_" + str(run_status))
        reasons += ["%s_%s" % (level, item["outcome"]) for level, item in levels.items() if item["outcome"] in ("error", "not_run", "unknown", "missing")]
        if cleanup_status not in ("confirmed", "not_applicable"):
            reasons.append("cleanup_" + cleanup_status)
        if not bound["complete"]:
            reasons.append("usage_incomplete")
        if hash_status != "verified":
            reasons.append("report_hash_mismatch")
        reasons += [a for a in anomalies if a in ("run_model_differs_from_requested", "returned_model_differs_from_requested", "observed_origin_differs_from_expected", "origin_not_found_in_history")]
        reasons = list(dict.fromkeys(reasons))

        result = {"schema": RESULT_SCHEMA, "plan_id": self.plan["plan_id"], "entry_id": entry_id, "run_id": run_id, "model_requested": entry["model"], "levels_requested": list(entry["levels"]),
                  "run_status": run_status, "levels": levels, "cleanup": {"status": cleanup_status, "per_level": cleanup["per_level"], "server_admission_blocked": admission if isinstance(admission, str) or admission is None else "unreadable"},
                  "usage": {**spend_record, "attempts": bound["attempts"], "returned_models": bound["returned_models"], "server_cost_usd": (report.get("usage") or {}).get("cost_usd") if isinstance(report.get("usage"), dict) and isinstance((report.get("usage") or {}).get("cost_usd"), (int, float)) else None,
                            "note": "bound_usd is an upper-bound estimate by catalog prices (unknown attempts at worst case); not an invoice"},
                  "report": {"file": report_file.name, "sha256_claimed": claimed if isinstance(claimed, str) else None, "sha256_computed": computed, "hash_status": hash_status},
                  "origin": origin, "anomalies": anomalies, "inconclusive": {"value": bool(reasons), "reasons": reasons}}
        write_atomic(self.entry_dir / (entry_id + ".result.json"), dump_bytes(self.redactor.obj(result)))
        self.log("entry_done", entry_id=entry_id, run_id=run_id, run_status=run_status, outcomes={level: item["outcome"] for level, item in levels.items()}, inconclusive=bool(reasons), reasons=reasons)
        self.say("%s terminado: estado=%s, niveles=%s, limpieza=%s, gasto<=%s USD%s" % (entry_id, run_status, {k: v["outcome"] for k, v in levels.items()}, cleanup_status, fmt_usd(bound["bound_usd"]), ", INCONCLUSO (" + ",".join(reasons) + ")" if reasons else ""))

        if cleanup_status == "unconfirmed":
            raise Halt("cleanup_unconfirmed", "%s: sandbox cleanup is not confirmed; stopping before anything else is launched" % entry_id, entry_id)
        if admission is not None:
            raise Halt("admission_blocked", "%s: the server reports admission blocked (%s) after the run" % (entry_id, trunc(admission, 80)), entry_id)
        if cleanup_status == "unknown":
            raise Halt("cleanup_unknown", "%s: sandbox cleanup is unknown (a level lacks cleanup_confirmed)" % entry_id, entry_id)
        if hash_status != "verified":
            raise Halt("hash_mismatch", "%s: the report sha256 does not reproduce; the saved report is kept as received" % entry_id, entry_id)
        total = self.committed(exclude=entry_id) + bound["bound_usd"]
        if total > self.plan["budget"]["cap"]:
            raise Halt("budget_exceeded", "estimated spend %s USD exceeds the cap %s USD" % (fmt_usd(total), fmt_usd(self.plan["budget"]["cap"])), entry_id)
        if run_status != "completed":
            # The result above is kept as inconclusive evidence; no further run is launched on top of a failed or cancelled one.
            raise Halt("run_not_completed", "%s ended as %s: kept as inconclusive evidence, nothing else is launched" % (entry_id, run_status), entry_id)

    def _compare_pairs(self):
        if self.state.forbid is not None:
            return
        for pair in self.plan["compare"]:
            key = (pair["left"], pair["right"])
            if key in self.state.compared:
                continue
            left, right = self.state.entries[key[0]], self.state.entries[key[1]]
            if not (left["done"] and right["done"] and left["run_id"] and right["run_id"]):
                continue
            status, data, raw = self.api.get_json("/api/compare?left=%s&right=%s" % (left["run_id"], right["run_id"]), auth=True)
            file = self.entry_dir / ("compare-%s-%s.json" % key)
            write_atomic(file, raw)
            ok = status == 200 and isinstance(data, dict)
            reasons = [trunc(x, 200) for x in data.get("reasons", [])[:20]] if ok and isinstance(data.get("reasons"), list) else []
            comparable = data.get("comparable") if ok and isinstance(data.get("comparable"), bool) else None
            self.log("compare_done", left=key[0], right=key[1], http_status=status, comparable=comparable, reasons=reasons, file=file.name)
            self.say("comparacion %s vs %s: HTTP %s, comparable=%s%s" % (key[0], key[1], status, comparable, (" (" + "; ".join(reasons) + ")") if reasons else ""))

    # -- derived outputs
    def _read_result(self, entry_id):
        path = self.entry_dir / (entry_id + ".result.json")
        return parse_json(path.read_bytes()) if path.is_file() else None

    def build_matrix(self):
        cells, planned = [], set()
        for entry in self.plan["entries"]:
            entry_id, state = entry["entry_id"], self.state.entries[entry["entry_id"]]
            result = self._read_result(entry_id) if state["done"] else None
            if result is not None:
                status = "observed"
            elif state["run_id"]:
                status = "in_flight"
            elif state["outcome"] == "rejected":
                status = "rejected_not_launched"
            elif state["intent"]:
                status = "unresolved_post"
            else:
                status = "not_executed"
            for level in entry["levels"]:
                planned.add(level)
                cell = {"entry_id": entry_id, "model": entry["model"], "level": level, "status": status, "evidence_kind": "unknown", "outcome": None, "inconclusive": None, "reasons": [], "run_id": state["run_id"],
                        "report_sha256": None, "hash_status": None, "cleanup": None, "usage_bound_usd": None}
                if result is not None:
                    item = (result.get("levels") or {}).get(level) or {}
                    cell.update(outcome=item.get("outcome"), inconclusive=(result.get("inconclusive") or {}).get("value"), reasons=(result.get("inconclusive") or {}).get("reasons", []),
                                report_sha256=(result.get("report") or {}).get("sha256_computed"), hash_status=(result.get("report") or {}).get("hash_status"), cleanup=(result.get("cleanup") or {}).get("status"),
                                usage_bound_usd=(result.get("usage") or {}).get("bound_usd"), evidence_kind=((result.get("origin") or {}).get("origin")) or "unknown")
                    if "variants" in item:
                        cell["variants"] = item["variants"]
                cells.append(cell)
        return {"schema": MATRIX_SCHEMA, "plan_id": self.plan["plan_id"], "plan_sha256": self.plan["sha256"], "levels": list(ALL_LEVELS), "cells": cells,
                "levels_without_entry_in_this_plan": [level for level in ALL_LEVELS if level not in planned],
                "prior_evidence": [dict(item, label="declared_by_plan_not_verified_by_runner") for item in self.plan["prior_evidence"]],
                "comparisons": [{"left": k[0], "right": k[1], **info} for k, info in sorted(self.state.compare_info.items())],
                "budget": {"cap_usd": fmt_usd(self.plan["budget"]["cap"]), "committed_upper_bound_usd": fmt_usd(self.committed()), "plan_worst_case_usd": fmt_usd(self.plan["worst_case"]["total_usd"]), "kind": "estimate_by_catalog_prices_not_an_invoice"},
                "ledger_forbids_new_posts": self.state.forbid, "limitations": list(LIMITATIONS)}

    def _write_matrix(self):
        matrix = self.redactor.obj(self.build_matrix())
        write_atomic(self.entry_dir / "matrix.json", dump_bytes(matrix))
        lines = ["# Matriz P4 (%s)" % matrix["plan_id"], "", "| entrada | modelo | nivel | estado | origen observado | veredicto | inconcluso | limpieza | gasto<= USD |", "|---|---|---|---|---|---|---|---|---|"]
        for c in matrix["cells"]:
            lines.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (c["entry_id"], c["model"], c["level"], c["status"], c["evidence_kind"], c["outcome"] or "sin resultado", "?" if c["inconclusive"] is None else ("si: " + ",".join(c["reasons"]) if c["inconclusive"] else "no"), c["cleanup"] or "?", c["usage_bound_usd"] or "?"))
        lines += ["", "Niveles sin entry en este plan: " + (", ".join(matrix["levels_without_entry_in_this_plan"]) or "ninguno"), "", "## Limites"] + ["- " + text for text in matrix["limitations"]]
        write_atomic(self.entry_dir / "matrix.md", ("\n".join(lines) + "\n").encode("utf-8"))


# ------------------------------------------------------------------ CLI

def parse_base_url(url, allow_insecure):
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        raise PlanError("--base-url is not a valid URL") from None
    del port
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise PlanError("--base-url must be an http(s) URL with a host")
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment or parts.path not in ("", "/"):
        raise PlanError("--base-url must be only scheme://host[:port] (no credentials, path, query or fragment)")
    host = parts.hostname
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if parts.scheme == "http" and not loopback and not allow_insecure:
        raise PlanError("plain http to a non-loopback host would send the Bearer in clear text; use https or --allow-insecure-http (recorded in the ledger)")
    return "%s://%s" % (parts.scheme, parts.netloc)


def read_token(env):
    token = env.get(TOKEN_ENV)
    if not token:
        raise PlanError(TOKEN_ENV + " is not set")
    if len(token) < MIN_TOKEN_LEN or not re.fullmatch(r"[\x21-\x7e]+", token):
        raise PlanError("%s must be at least %d printable ASCII characters without spaces" % (TOKEN_ENV, MIN_TOKEN_LEN))
    return token


def build_parser():
    parser = argparse.ArgumentParser(prog="p4_batch.py", allow_abbrev=False, description="P4 real-batch runner. Without --execute it only validates the plan (no network, no token).")
    parser.add_argument("--plan", help="existing plan file (escape-p4-plan/v1)")
    parser.add_argument("--out-dir", help="directory for the ledger, lock, reports and matrix")
    parser.add_argument("--base-url", help="API base URL, scheme://host[:port]")
    parser.add_argument("--execute", action="store_true", help="really launch; without it nothing is contacted")
    parser.add_argument("--only", action="append", default=[], help="launch only this entry_id (repeatable)")
    parser.add_argument("--allow-insecure-http", action="store_true")
    parser.add_argument("--allow-repeat", action="append", default=[], help="entry_id whose model+levels were already launched in another ledger")
    parser.add_argument("--repeat-reason", help="written reason for --allow-repeat (at least 10 characters)")
    parser.add_argument("--attach", action="append", default=[], help="ENTRY=RUN_ID: bind an unresolved POST to a run found with GET /api/runs")
    parser.add_argument("--print-default-plan", action="store_true", help="print the three-run plan to stdout (offline) and exit")
    parser.add_argument("--plan-id", help="plan_id for --print-default-plan")
    return parser


def _describe_plan(plan, say):
    say("plan %s (sha256 %s)" % (plan["plan_id"], plan["sha256"]))
    for entry in plan["entries"]:
        say("  %-10s %-20s %-40s llamadas<=%-3d peor caso<=%s USD (origen esperado %s)" % (entry["entry_id"], entry["model"], ",".join(entry["levels"]), entry["calls"], fmt_usd(entry["worst_usd"]), entry["expected_origin"]))
    worst = plan["worst_case"]
    say("  peor caso total: %d llamadas, <=%s USD; tope %s USD; margen %s USD (estimacion por precios de catalogo, no factura)" % (worst["total_calls"], fmt_usd(worst["total_usd"]), fmt_usd(plan["budget"]["cap"]), fmt_usd(plan["budget"]["cap"] - worst["total_usd"])))


def main(argv=None, *, env=None, transport_factory=None, clock=None, sleep=None, out=None, err=None, root=REPO_ROOT):
    env = os.environ if env is None else env
    out, err = out or sys.stdout, err or sys.stderr
    clock, sleep = clock or time.monotonic, sleep or time.sleep
    redactor = Redactor("")

    def say(message):
        print(redactor.text(message), file=out, flush=True)

    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    try:
        if args.print_default_plan:
            if not args.plan_id or not PLAN_ID_RE.fullmatch(args.plan_id):
                raise PlanError("--print-default-plan needs --plan-id (a-z, 0-9, '-', 4 to 48 characters)")
            print(json.dumps(build_default_plan(args.plan_id, root), indent=2), file=out)
            return EXIT_OK
        if not args.plan or not args.out_dir:
            raise PlanError("--plan and --out-dir are required")
        plan = load_plan(args.plan, root)
        out_dir = Path(args.out_dir)
        for entry_id in list(args.only) + list(args.allow_repeat):
            if entry_id not in {e["entry_id"] for e in plan["entries"]}:
                raise PlanError("unknown entry_id in --only/--allow-repeat: " + trunc(entry_id, 40))
        attach = {}
        for item in args.attach:
            entry_id, _, run_id = item.partition("=")
            if entry_id not in {e["entry_id"] for e in plan["entries"]} or not RUN_ID_RE.fullmatch(run_id):
                raise PlanError("--attach must be ENTRY=RUN_ID with an entry of the plan and a 32-hex run id")
            attach[entry_id] = run_id
        if args.allow_repeat and (not args.repeat_reason or len(args.repeat_reason.strip()) < 10):
            raise PlanError("--allow-repeat requires --repeat-reason with at least 10 characters")
        if not args.execute:
            if args.attach or args.allow_repeat:
                raise PlanError("--attach and --allow-repeat only apply with --execute")
            _describe_plan(plan, say)
            ledger = out_dir / (plan["plan_id"] + ".ledger.jsonl")
            if ledger.exists():
                state = LedgerState([e["entry_id"] for e in plan["entries"]], plan["sha256"])
                for record in Ledger.read(ledger):
                    state.apply(record)
                for entry_id, item in state.entries.items():
                    say("  ledger %-10s intent=%s run_id=%s done=%s" % (entry_id, item["intent"], item["run_id"], item["done"]))
                if state.forbid:
                    say("  el ledger prohibe nuevos lanzamientos (halt: %s)" % state.forbid)
            say("SIN --execute: no se leyo el token, no se abrio red, no se creo ningun archivo.")
            return EXIT_OK

        base_url = parse_base_url(args.base_url or "", args.allow_insecure_http)
        token = read_token(env)
        redactor = Redactor(token)
        lock = TargetLock(out_dir / ("p4-target-%s.lock" % sha256_hex(base_url.encode("utf-8"))[:12]), {"plan_id": plan["plan_id"], "pid": os.getpid(), "started": now_iso()})
        try:
            lock.acquire()  # before ANY network traffic, hence before the first POST
        except LockHeld as exc:
            say("BLOQUEADO: " + str(exc) + ". Otra ejecucion contra este destino esta activa, o quedo un lock huerfano: revisar y borrar a mano.")
            return EXIT_LOCKED
        try:
            factory = transport_factory or UrllibTransport
            transport = factory(base_url, token, plan["limits"]["http_timeout_s"])
            batch = Batch(plan, out_dir=out_dir, api=Api(transport, redactor, sleep), redactor=redactor, clock=clock, sleep=sleep, say=say, base_host=urllib.parse.urlsplit(base_url).netloc,
                          insecure=args.allow_insecure_http, only=args.only, allow_repeat={e: args.repeat_reason.strip() for e in args.allow_repeat} if args.allow_repeat else {}, attach=attach)
            return batch.run()
        finally:
            lock.release()
    except PlanError as exc:
        print("ERROR: " + redactor.text(str(exc)), file=err, flush=True)
        return EXIT_USAGE
    except Exception as exc:  # unexpected: never print a traceback that could carry request data
        print("ERROR inesperado (%s): %s. El ledger conserva lo capturado; no se reenvia ningun POST." % (type(exc).__name__, redactor.text(str(exc))[:200]), file=err, flush=True)
        return EXIT_HALT


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""P4 - prueba interna de utilidad del Agent Backrooms: inspeccion JSON frente a recorrido de la UI.

Que hace
    Contesta las MISMAS preguntas predefinidas sobre la MISMA evidencia por dos caminos automaticos:
    (A) ``json_inspection``: lee el reporte JSON (archivo o ``GET /api/runs/{id}/report``) con reglas fijas;
    (B) ``ui_traversal``: abre la vista de producto con Playwright (``?run=<id>``) y lee el DOM.
    Preguntas: resultado de la tarea, contencion, intento, limpieza, uso/costo, comparabilidad y siguiente ensayo.

Que NO hace
    * No hay personas: no mide ni estima tiempos manuales, ahorro, clientes ni validacion de usuarios.
      Los tiempos son del reloj de esta herramienta y llevan esa etiqueta.
    * Solo lecturas GET. El cliente HTTP solo construye solicitudes GET; el navegador pasa por un filtro que
      aborta y registra cualquier solicitud que no sea GET o que salga del origen indicado. No inicia inferencia
      ni cancela partidas ni toca cuotas.
    * No genera la verdad. Las expectativas vienen de un archivo escrito aparte (ver
      docs/producto/PROTOCOLO-P4-UTILIDAD.md); sin expectativa una respuesta queda ``sin_puntuar``. Lo
      desconocido se informa como ``"unknown"`` y es una respuesta valida; nunca se convierte en 0.
    * La comparabilidad solo se pregunta con una API real y token de operador (variable de entorno nombrada
      con ``--token-env``, leida unicamente si se pide ``--compare``).

Modos de backend para el brazo UI
    * ``--api-url http://127.0.0.1:8874``: API real (p. ej. tunel a la VM); el filtro del navegador solo deja pasar GET.
    * ``--replay``: servidor local de REPETICION (stub de solo lectura) que sirve apps/web y los reportes dados con
      ``--report``. Es la misma pagina con los mismos JSON, pero NO es el backend; la evidencia lo rotula.

Solo biblioteca estandar, mas Playwright importado de forma perezosa para el brazo UI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

SCHEMA = "p4-utility-evidence/v1"
EXPECTATIONS_SCHEMA = "p4-utility-expectations/v1"
TOOL_VERSION = "1.0.0"
UNKNOWN = "unknown"
UNRECOGNIZED = "unrecognized"
LEVELS = ("secret", "network", "memory", "persistence", "injection", "workflow")
VARIANTS = ("legitimate", "perturbed")
OUTCOMES = ("blocked", "escaped", "exhausted", "error", "not_run")
TERMINAL = ("completed", "failed", "cancelled")
ACTIVE = ("queued", "running")
LOOPBACK = ("127.0.0.1", "localhost", "::1")
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
MAX_BYTES = 20 * 1024 * 1024
REPO_ROOT = Path(__file__).resolve().parents[2]
EXPECT_BEGIN = "<!-- p4-utility-expectations:begin -->"
EXPECT_END = "<!-- p4-utility-expectations:end -->"
FILL = "FILL_ME"

TIMING_LABEL = ("Tiempo de ejecucion de la herramienta (reloj automatico). No es tiempo humano "
                "y no estima el de una revision manual.")
MANUAL_COMPARISON = {
    "status": "not_performed",
    "reason": ("No hay personas disponibles. No se recolectaron ni se estimaron tiempos manuales, pasos humanos, "
               "omisiones o errores humanos, ahorro, clientes ni validacion de usuarios. Esta prueba no sustituye esa comparacion."),
}

QUESTIONS = {
    "task_result": "Se cumplio la tarea legitima en cada variante?",
    "containment": "Que verifico la prueba sobre la contencion?",
    "attempt": "Se observo un intento de alcanzar el objetivo?",
    "cleanup": "Se confirmo la limpieza del sandbox?",
    "usage_cost": "Que consumo y costo informa el reporte y con que cobertura?",
    "comparability": "Son comparables estas dos partidas?",
    "next_trial": "Cual es el siguiente ensayo indicado?",
}
# run_status es contexto (no es una de las siete preguntas); comparability es por pares.
ANSWER_QUESTIONS = tuple(q for q in QUESTIONS if q != "comparability") + ("run_status",)
NEXT_VALUES = ("rerun_unresolved", "review_escaped", "extend_or_compare", "no_verdicts", "wait_terminal")
ENUMS = {
    "task_result": {"passed", "failed", "inconclusive", UNKNOWN},
    "containment_axis": {"denied", "escaped", "not_exercised", "inconclusive", UNKNOWN},
    "containment_level": set(OUTCOMES) | {UNKNOWN, "not_applicable"},
    "attempt": {"observed", "not_observed", "indeterminate", UNKNOWN},
    "cleanup": {"confirmed", "not_confirmed", UNKNOWN},
    "coverage": {"complete", "incomplete", UNKNOWN},
    "status": set(TERMINAL) | set(ACTIVE) | {UNKNOWN},
}


class UtilityError(Exception):
    """Fallo de uso o de entrada con un codigo corto y estable (nunca incluye secretos)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class ApiError(UtilityError):
    def __init__(self, code: str, status: int | None = None):
        super().__init__(code)
        self.status = status


# ------------------------------------------------------------------ utilidades pequenas

def _obj(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _count(value: Any):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _amount(value: Any):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value if math.isfinite(value) and value >= 0 else None


def _pick(value: Any, allowed) -> str:
    """Valor enumerado; ausente => unknown; fuera del conjunto => unrecognized (nunca se inventa)."""
    if value is None:
        return UNKNOWN
    return value if isinstance(value, str) and value in allowed else UNRECOGNIZED


def _ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 1)


def _clip(value: Any, size: int = 300) -> str:
    return str(value if value is not None else "")[:size]


def _err(arm: str, stage: str, exc: BaseException) -> dict:
    record = {"arm": arm, "stage": stage, "error": exc.code if isinstance(exc, UtilityError) else type(exc).__name__}
    if not isinstance(exc, UtilityError):
        record["message"] = _clip(str(exc).replace("\n", " "), 200)
    return record


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def report_hash_status(doc: Any) -> str:
    """Integridad del reporte con la serializacion canonica del servicio (no prueba autenticidad)."""
    stored = _obj(doc).get("sha256")
    if not isinstance(stored, str):
        return "absent"
    body = {k: v for k, v in doc.items() if k != "sha256"}
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return "verified" if _sha256_bytes(canonical.encode()) == stored else "mismatch"


# ------------------------------------------------------------------ entradas

def normalize_api_url(url: str, allow_nonloopback: bool = False) -> str:
    parts = urlsplit(url or "")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise UtilityError("api_url_invalid")
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"):
        raise UtilityError("api_url_invalid")
    if parts.hostname not in LOOPBACK and not allow_nonloopback:
        raise UtilityError("api_url_not_loopback")
    return "%s://%s" % (parts.scheme, parts.netloc)


def valid_run_id(value: Any) -> bool:
    return isinstance(value, str) and RUN_ID.fullmatch(value) is not None


def load_report_file(path: str) -> tuple[dict, str]:
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError:
        raise UtilityError("report_unreadable") from None
    if len(raw) > MAX_BYTES:
        raise UtilityError("report_too_large")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise UtilityError("report_not_json") from None
    require_report_shape(doc)
    return doc, _sha256_bytes(raw)


def require_report_shape(doc: Any) -> None:
    run = _obj(_obj(doc).get("run"))
    if not valid_run_id(run.get("id")):
        raise UtilityError("report_invalid")


def build_cases(report_paths, run_ids) -> list[dict]:
    cases: dict[str, dict] = {}
    for path in report_paths:
        doc, digest = load_report_file(path)
        rid = doc["run"]["id"]
        if rid in cases:
            raise UtilityError("duplicate_run_id")
        cases[rid] = {"run_id": rid, "report": doc, "file": Path(path).name, "file_sha256": digest}
    for rid in run_ids:
        if not valid_run_id(rid):
            raise UtilityError("run_id_invalid")
        cases.setdefault(rid, {"run_id": rid, "report": None, "file": None, "file_sha256": None})
    return [cases[k] for k in sorted(cases)]


class HttpGet:
    """Cliente HTTP de solo GET con bitacora; el token solo viaja en la cabecera Authorization."""

    def __init__(self, base_url: str, token: str | None = None, timeout: float = 15.0, opener=None):
        self.base_url, self._token, self.timeout = base_url, token, timeout
        self._opener = opener or urlopen
        self.log: list[dict] = []

    def get_json(self, path: str, auth: bool = False):
        if not path.startswith("/"):
            raise UtilityError("bad_path")
        headers = {"Accept": "application/json"}
        if auth:
            if not self._token:
                raise UtilityError("token_missing")
            headers["Authorization"] = "Bearer " + self._token
        request = Request(self.base_url + path, headers=headers, method="GET")
        entry = {"method": request.get_method(), "path": path.split("?")[0], "auth": bool(auth), "status": None}
        self.log.append(entry)
        try:
            with self._opener(request, timeout=self.timeout) as response:
                entry["status"] = getattr(response, "status", None)
                raw = response.read(MAX_BYTES + 1)
        except HTTPError as exc:
            entry["status"] = exc.code
            raise ApiError("http_%d" % exc.code, exc.code) from None
        except (URLError, OSError) as exc:
            raise ApiError("network_" + type(exc).__name__) from None
        if len(raw) > MAX_BYTES:
            raise ApiError("response_too_large")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ApiError("response_not_json") from None


# ------------------------------------------------------------------ brazo A: inspeccion JSON (reglas fijas)

def _variant_entries(entry: dict) -> dict:
    """Primera aparicion gana: variants, completed_variants, observed_variants (igual que el resto del producto)."""
    found: dict[str, dict] = {}
    for group in ("variants", "completed_variants", "observed_variants"):
        for name, variant in _obj(entry.get(group)).items():
            if isinstance(name, str) and isinstance(variant, dict) and name not in found:
                found[name] = variant
    return found


def _secret_attempt(receipts: list) -> str:
    seen = [_obj(_obj(r).get("probe")).get("attempt") for r in receipts if _obj(r).get("level") == "secret"]
    if "observed" in seen:
        return "observed"
    if seen and all(s == "not_observed" for s in seen):
        return "not_observed"
    return UNKNOWN


def _json_usage(doc: dict) -> dict:
    usage = doc.get("usage")
    if usage is None:
        usage = _obj(doc.get("run")).get("usage")
    if not isinstance(usage, dict) or not usage:
        return {"attempts_total": UNKNOWN, "total_tokens": UNKNOWN, "cost_usd": UNKNOWN, "coverage": UNKNOWN}
    attempts = _count(usage.get("attempts_total"))
    tokens = _count(_obj(usage.get("tokens")).get("total_tokens"))
    cost = usage.get("cost")
    usd = _amount(_obj(cost).get("usd"))
    if usd is None and not _obj(cost):
        usd = _amount(usage.get("cost_usd"))
    meas = _obj(usage.get("measurement"))
    state = meas.get("state")
    unfinished = meas.get("collection_finished") is False or (isinstance(state, str) and state != "final")
    cov = _obj(usage.get("coverage"))
    unknown_calls = _count(cov.get("unknown_calls"))
    if unfinished:
        coverage = "incomplete"
    elif attempts == 0:
        coverage = "complete"
    elif attempts is None:
        coverage = UNKNOWN
    elif cov.get("complete") is True and unknown_calls == 0:
        coverage = "complete"
    elif cov.get("complete") is False or (unknown_calls or 0) > 0:
        coverage = "incomplete"
    else:
        coverage = UNKNOWN
    return {"attempts_total": UNKNOWN if attempts is None else attempts,
            "total_tokens": UNKNOWN if tokens is None else tokens,
            "cost_usd": UNKNOWN if usd is None else usd, "coverage": coverage}


def _next_trial(status: Any, levels: list, summary: dict) -> list:
    if status in ACTIVE:
        return ["wait_terminal"]
    if status not in TERMINAL:
        return [UNKNOWN]
    if not levels:
        return ["no_verdicts"]
    outcomes = [_obj(summary.get(level)).get("outcome") for level in levels]
    unresolved = any(o not in ("blocked", "escaped") for o in outcomes)
    escaped = any(o == "escaped" for o in outcomes)
    found = []
    if unresolved:
        found.append("rerun_unresolved")
    if escaped:
        found.append("review_escaped")
    if not unresolved and not escaped:
        found.append("extend_or_compare")
    return sorted(found)


def json_answers(report: Any) -> dict:
    """Respuestas por reglas fijas sobre el JSON del reporte. Ausente => unknown; nunca 0."""
    doc = _obj(report)
    run = _obj(doc.get("run"))
    summary = _obj(run.get("summary"))
    status = run.get("status")
    levels = [x for x in _list(run.get("levels")) if isinstance(x, str)]
    if not levels:
        levels = [k for k, v in summary.items() if isinstance(v, dict)]
    a: dict[str, dict] = {q: {} for q in ANSWER_QUESTIONS}
    a["run_status"]["status"] = status if isinstance(status, str) else UNKNOWN
    for level in levels:
        entry = _obj(summary.get(level))
        if level == "workflow":
            variants = _variant_entries(entry)
            for name in VARIANTS:
                v = _obj(variants.get(name))
                key = "workflow:" + name
                a["task_result"][key] = _pick(_obj(v.get("task")).get("status"), ENUMS["task_result"])
                a["containment"][key] = _pick(_obj(v.get("containment")).get("status"), ENUMS["containment_axis"])
                a["attempt"][key] = _pick(_obj(v.get("containment")).get("attempt"), ENUMS["attempt"])
        elif level == "injection":
            a["containment"][level] = "not_applicable"
        else:
            a["containment"][level] = _pick(entry.get("outcome"), set(OUTCOMES) | {UNKNOWN})
        if level == "secret":
            a["attempt"][level] = _secret_attempt(_list(run.get("receipts")))
        if level != "injection":
            cleanup = entry.get("cleanup_confirmed")
            a["cleanup"][level] = "confirmed" if cleanup is True else "not_confirmed" if cleanup is False else UNKNOWN
    a["usage_cost"] = _json_usage(doc)
    a["next_trial"]["categories"] = _next_trial(status, levels, summary)
    return a


def run_json_arm(cases: list[dict], http: HttpGet | None, compare: tuple[str, str] | None) -> dict:
    total = time.perf_counter()
    runs: dict[str, dict] = {}
    pairs: dict[str, dict] = {}
    files_read = 0
    for case in cases:
        rid = case["run_id"]
        started = time.perf_counter()
        errors: list[dict] = []
        answers = None
        source = None
        extra: dict[str, Any] = {}
        doc = case["report"]
        try:
            if doc is not None:
                source = "file"
                files_read += 1
            elif http is not None:
                source = "api"
                doc = http.get_json("/api/runs/%s/report?format=json" % quote(rid, safe=""))
                require_report_shape(doc)
            else:
                raise UtilityError("no_report_source")
            extra["report_hash_check"] = report_hash_status(doc)
            extra["run_id_matches"] = _obj(_obj(doc).get("run")).get("id") == rid
            answers = json_answers(doc)
        except Exception as exc:  # un caso fallido no detiene a los demas
            errors.append(_err("json_inspection", "read_report", exc))
        if source == "file" and http is not None:
            try:
                live = http.get_json("/api/runs/%s/report?format=json" % quote(rid, safe=""))
                extra["file_sha256_field_equals_server"] = _obj(live).get("sha256") == _obj(doc).get("sha256")
            except Exception as exc:
                errors.append(_err("json_inspection", "server_cross_check", exc))
        runs[rid] = {"source": source, "answers": answers, "errors": errors, "tool_elapsed_ms": _ms(started), **extra}
    if compare:
        left, right = compare
        key = left + "|" + right
        started = time.perf_counter()
        errors, answers, observed = [], None, {}
        try:
            if http is None:
                raise UtilityError("no_api_for_compare")
            data = http.get_json("/api/compare?left=%s&right=%s" % (quote(left, safe=""), quote(right, safe="")), auth=True)
            flag = _obj(data).get("comparable")
            answers = {"comparability": {"comparable": flag if isinstance(flag, bool) else None}}
            observed = {"reasons": [_clip(x) for x in _list(_obj(data).get("reasons"))[:20]],
                        "origins": {"left": _obj(_obj(data).get("left")).get("origin"), "right": _obj(_obj(data).get("right")).get("origin")}}
        except Exception as exc:
            errors.append(_err("json_inspection", "compare", exc))
        pairs[key] = {"answers": answers, "observed": observed, "errors": errors, "tool_elapsed_ms": _ms(started)}
    log = http.log if http is not None else []
    actions = {"files_read": files_read, "http_get": len(log), "http_methods": sorted({e["method"] for e in log}),
               "authenticated_requests": sum(1 for e in log if e["auth"])}
    return _arm("json_inspection", runs, pairs, actions, _ms(total))


def _arm(name: str, runs: dict, pairs: dict, actions: dict, elapsed_ms: float, extra: dict | None = None) -> dict:
    scopes = {rid: r["answers"] for rid, r in runs.items() if r.get("answers")}
    scopes.update({k: p["answers"] for k, p in pairs.items() if p.get("answers")})
    arm = {"arm": name, "actor": "automated_tool", "human_participants": 0, "runs": runs, "pairs": pairs,
           "actions": actions, "errors_total": sum(len(x.get("errors", [])) for x in list(runs.values()) + list(pairs.values())),
           "tool_elapsed_ms_total": elapsed_ms, "timing_label": TIMING_LABEL, "_scopes": scopes}
    arm.update(extra or {})
    return arm


# ------------------------------------------------------------------ brazo B: recorrido de la UI

TASK_PREFIXES = (("Tarea cumplida", "passed"), ("Tarea no cumplida", "failed"), ("Tarea inconclusa", "inconclusive"),
                 ("Sin dato de tarea", UNKNOWN))
CONTAINMENT_PREFIXES = (("Escape observado", "escaped"), ("Denegación verificada", "denied"), ("No ejercitada", "not_exercised"),
                        ("Inconclusa", "inconclusive"), ("Sin dato de contención", UNKNOWN))
ATTEMPT_TEXT = {"observado": "observed", "no observado": "not_observed", "indeterminado (sin observación fiable)": "indeterminate"}
CLEANUP_TEXT = {"Confirmada": "confirmed", "Fallida / no confirmada": "not_confirmed", "No comprobada": UNKNOWN}
ROOM_BY_HEADING = {"Secreto": "secret", "Red": "network", "Memoria": "memory", "Persistencia": "persistence",
                   "Inyección": "injection", "Flujo de trabajo": "workflow"}
NEXT_PREFIXES = (("Vuelve a ensayar solo", "rerun_unresolved"), ("Revisa en la evidencia técnica", "review_escaped"),
                 ("Para ampliar la evidencia", "extend_or_compare"), ("Sin veredictos por habitación", "no_verdicts"),
                 ("Espera el estado final", "wait_terminal"))


def _labelled(paras: list, label: str):
    prefix = label + ": "
    for p in paras:
        if isinstance(p, str) and p.startswith(prefix):
            return p[len(prefix):]
    return None


def _prefix_map(text, table):
    if text is None:
        return None
    for prefix, value in table:
        if text.startswith(prefix):
            return value
    return UNRECOGNIZED


def _ui_usage(snap: Any) -> dict:
    """Uso/costo leidos del texto de la pagina. Solo se responde lo que la pagina dice; el resto queda sin responder."""
    if not isinstance(snap, dict):
        return {}
    paras = [p for p in _list(snap.get("paras")) if isinstance(p, str)]
    cover = _labelled(paras, "Cobertura de llamadas")
    cost = snap.get("cost") if isinstance(snap.get("cost"), str) else None
    if cover is None and cost is None:
        if any("desconocido" in p.lower() for p in paras):
            return {"attempts_total": UNKNOWN, "total_tokens": UNKNOWN, "cost_usd": UNKNOWN, "coverage": UNKNOWN}
        return {}
    out: dict[str, Any] = {}
    if cover is not None:
        low = cover.lower()
        found = re.search(r"de (\d+) llamadas con tokens conocidos", cover)
        if found:
            out["attempts_total"] = int(found.group(1))
        elif low.startswith("sin llamadas"):
            out["attempts_total"] = 0
        elif low.startswith("cobertura no informada"):
            out["attempts_total"] = UNKNOWN
        if "cobertura incompleta" in low:
            out["coverage"] = "incomplete"
        elif "cobertura completa" in low or low.startswith("sin llamadas al proveedor"):
            out["coverage"] = "complete"
        elif low.startswith("sin llamadas registradas hasta el corte"):
            out["coverage"] = "incomplete"
        elif low.startswith("cobertura no informada"):
            out["coverage"] = UNKNOWN
    for item in _list(snap.get("dl")):
        if isinstance(item, list) and len(item) == 2 and item[0] == "Total" and isinstance(item[1], str):
            if item[1].startswith("No disponible"):
                out["total_tokens"] = UNKNOWN
            else:
                found = re.match(r"(?:al menos )?(\d+)", item[1])
                if found:
                    out["total_tokens"] = int(found.group(1))
            break
    if cost is not None:
        if "no calculado" in cost:
            out["cost_usd"] = UNKNOWN
        else:
            found = re.search(r"USD\s+([0-9]+(?:\.[0-9]+)?)", cost)
            if found:
                out["cost_usd"] = float(found.group(1))
    return out


def ui_answers(snapshot: Any) -> dict:
    """Respuestas derivadas SOLO del texto/DOM de la pagina. Lo que la pagina no dice queda sin responder."""
    s = _obj(snapshot)
    a: dict[str, dict] = {q: {} for q in ANSWER_QUESTIONS}
    title = re.search(r"·\s*(\S+)\s*$", s.get("summary_title") or "")
    if title:
        a["run_status"]["status"] = title.group(1)
    blocks = _obj(_obj(s.get("plain")).get("blocks"))
    plain_text = " ".join(x for items in blocks.values() for x in _list(items) if isinstance(x, str))
    no_variant_verdict = "ninguna variante llegó a un veredicto propio" in plain_text
    sandbox_untested = "la contención del sandbox no se probó" in plain_text
    for raw_card in _list(s.get("results")):
        card = _obj(raw_card)
        level = ROOM_BY_HEADING.get(card.get("heading")) if isinstance(card.get("heading"), str) else None
        if level is None:
            continue
        paras = [p for p in _list(card.get("paras")) if isinstance(p, str)]
        if level == "workflow":
            found: dict[str, list] = {}
            for raw_variant in _list(card.get("variants")):
                variant = _obj(raw_variant)
                vtitle = variant.get("title") if isinstance(variant.get("title"), str) else ""
                name = "legitimate" if "legítima" in vtitle else "perturbed" if "perturbada" in vtitle else None
                if name and name not in found:
                    found[name] = [p for p in _list(variant.get("paras")) if isinstance(p, str)]
            for name in VARIANTS:
                key = "workflow:" + name
                if name in found:
                    vp = found[name]
                    task = _prefix_map(_labelled(vp, "Eje tarea"), TASK_PREFIXES)
                    contain = _prefix_map(_labelled(vp, "Eje contención"), CONTAINMENT_PREFIXES)
                    attempt = _labelled(vp, "Lectura directa del canario")
                    if task is not None:
                        a["task_result"][key] = task
                    if contain is not None:
                        a["containment"][key] = contain
                    if attempt is not None:
                        a["attempt"][key] = ATTEMPT_TEXT.get(attempt, UNRECOGNIZED)
                elif no_variant_verdict:
                    for question in ("task_result", "containment", "attempt"):
                        a[question][key] = UNKNOWN
        elif level == "injection":
            if sandbox_untested or any("La contención del sandbox no fue probada" in p for p in paras):
                a["containment"][level] = "not_applicable"
        else:
            tokens = str(card.get("status_class") or "").split()
            outcome = next((t for t in tokens if t in OUTCOMES), None)
            if outcome:
                a["containment"][level] = outcome
            elif "unknown" in tokens:
                a["containment"][level] = UNRECOGNIZED
        if level != "injection":
            cleanup = _labelled(paras, "Limpieza")
            if cleanup is not None:
                a["cleanup"][level] = CLEANUP_TEXT.get(cleanup, UNRECOGNIZED)
    a["usage_cost"].update(_ui_usage(s.get("usage")))
    nxt = blocks.get("Siguiente ensayo")
    if isinstance(nxt, list):
        cats = sorted({c for c in (_prefix_map(x, NEXT_PREFIXES) for x in nxt if isinstance(x, str)) if c and c != UNRECOGNIZED})
        a["next_trial"]["categories"] = cats or [UNRECOGNIZED]
    return a


def ui_compare_answers(snapshot: Any) -> dict:
    s = _obj(snapshot)
    flag = True if s.get("comparable_ok") is True else False if s.get("comparable_no") is True else None
    return {"comparability": {"comparable": flag}}


def route_decision(method: str, url: str, base_origin: str) -> str:
    """Filtro del navegador: solo GET y solo hacia el origen indicado."""
    if str(method).upper() != "GET":
        return "block_non_get"
    parts = urlsplit(url)
    if "%s://%s" % (parts.scheme, parts.netloc) != base_origin:
        return "block_foreign_origin"
    return "allow"


def make_route_handler(base_origin: str, counters: dict):
    def handler(route):
        request = route.request
        decision = route_decision(request.method, request.url, base_origin)
        if decision == "allow":
            counters["requests_get_allowed"] += 1
            route.continue_()
        else:
            counters["blocked"].append({"decision": decision, "method": str(request.method), "path": urlsplit(request.url).path})
            route.abort()
    return handler


SNAPSHOT_JS = r"""() => {
  const txt = el => ((el && el.textContent) || "").replace(/\s+/g, " ").trim();
  const byId = id => document.getElementById(id);
  const kids = (el, sel) => el ? [...el.children].filter(c => c.matches(sel)) : [];
  const plain = byId("plain-summary");
  let plainSnap = null;
  if (plain && !plain.hidden) {
    const blocks = {};
    plain.querySelectorAll(".plain-block").forEach(b => { blocks[txt(b.querySelector("h4"))] = [...b.querySelectorAll("li")].map(txt); });
    plainSnap = {headline: txt(plain.querySelector(".plain-lead")), blocks};
  }
  const results = kids(byId("results"), "article.result").map(card => ({
    heading: txt(kids(card, "h3")[0]),
    status_class: (kids(card, "span.status")[0] || {className: ""}).className,
    paras: kids(card, "p").map(txt),
    variants: kids(card, "div.variant").map(v => ({title: txt(v.querySelector("strong")), paras: kids(v, "p").map(txt)}))
  }));
  const usage = byId("usage");
  const section = usage ? usage.querySelector("section.usage") : null;
  let usageSnap = null;
  if (section) {
    const cost = section.querySelector("p.usage-cost");
    usageSnap = {paras: kids(section, "p").map(txt), cost: cost ? txt(cost) : null,
      dl: kids(section, "dl").flatMap(dl => { const dts = [...dl.querySelectorAll("dt")], dds = [...dl.querySelectorAll("dd")]; return dts.map((dt, i) => [txt(dt), txt(dds[i])]); })};
  }
  const strong = byId("summary") ? kids(byId("summary"), "strong")[0] : null;
  return {summary_title: txt(strong), notice: txt(byId("notice")), plain: plainSnap, results, usage: usageSnap,
    receipt_count: document.querySelectorAll("#receipts > article.receipt").length};
}"""
USAGE_READY_JS = r"""() => { const u = document.getElementById("usage"); return !!u && !u.hidden && !!(u.querySelector("section.usage") || u.querySelector(".error-text")); }"""
COMPARE_DONE_JS = r"""() => { const o = document.getElementById("compare-output"); if (o && o.querySelector("p.compare-ok, p.compare-no")) return true; const s = (document.getElementById("compare-status") || {}).textContent || ""; return /no existe|aún no terminó|no aceptó|formato esperado|contactar|distint|identificadores válidos/.test(s); }"""
COMPARE_SNAPSHOT_JS = r"""() => { const txt = el => ((el && el.textContent) || "").replace(/\s+/g, " ").trim(); return {status: txt(document.getElementById("compare-status")), comparable_ok: !!document.querySelector("#compare-output p.compare-ok"), comparable_no: !!document.querySelector("#compare-output p.compare-no"), reasons: [...document.querySelectorAll("#compare-output ul.compare-reasons li")].map(txt).slice(0, 20)}; }"""


def _new_page(browser, origin: str, counters: dict):
    context = browser.new_context(viewport={"width": 1440, "height": 1000}, accept_downloads=False)
    page = context.new_page()
    page.route("**/*", make_route_handler(origin, counters))
    page.on("pageerror", lambda _e: counters.__setitem__("page_errors", counters["page_errors"] + 1))
    page.on("console", lambda m: counters.__setitem__("console_errors", counters["console_errors"] + 1) if m.type == "error" else None)
    return context, page


def _ui_read_run(browser, base_url: str, origin: str, run_id: str, timeout_ms: int, counters: dict) -> dict:
    started = time.perf_counter()
    errors: list[dict] = []
    snapshot = None
    context, page = _new_page(browser, origin, counters)
    try:
        counters["navigations"] += 1
        page.goto("%s/?run=%s" % (base_url, quote(run_id, safe="")), wait_until="domcontentloaded", timeout=timeout_ms)
        page.wait_for_selector("#run-link", timeout=timeout_ms)
        try:
            page.wait_for_function(USAGE_READY_JS, timeout=timeout_ms)
        except Exception as exc:
            errors.append(_err("ui_traversal", "usage_panel_wait", exc))
        snapshot = page.evaluate(SNAPSHOT_JS)
    except Exception as exc:
        errors.append(_err("ui_traversal", "read_run", exc))
        try:
            snapshot = page.evaluate(SNAPSHOT_JS)  # solo para conservar el aviso de la pagina; no se puntua
        except Exception:
            pass
    finally:
        context.close()
    return {"snapshot": snapshot, "errors": errors, "elapsed_ms": _ms(started)}


def _ui_compare(browser, base_url: str, origin: str, pair: tuple[str, str], token: str, timeout_ms: int, counters: dict) -> dict:
    started = time.perf_counter()
    errors: list[dict] = []
    snapshot = None
    context, page = _new_page(browser, origin, counters)
    try:
        counters["navigations"] += 1
        page.goto(base_url + "/", wait_until="domcontentloaded", timeout=timeout_ms)
        page.wait_for_selector("#operator-token", state="visible", timeout=timeout_ms)
        page.fill("#operator-token", token)
        page.fill("#compare-left", pair[0])
        page.fill("#compare-right", pair[1])
        counters["fills"] += 3
        page.click("#compare-run")
        counters["clicks"] += 1
        page.wait_for_function(COMPARE_DONE_JS, timeout=timeout_ms)
        snapshot = page.evaluate(COMPARE_SNAPSHOT_JS)
    except Exception as exc:
        errors.append(_err("ui_traversal", "compare", exc))
        try:
            snapshot = page.evaluate(COMPARE_SNAPSHOT_JS)
        except Exception:
            pass
    finally:
        context.close()
    return {"snapshot": snapshot, "errors": errors, "elapsed_ms": _ms(started)}


def collect_ui(base_url: str, run_ids: list[str], compare, token, *, headless: bool = True, timeout_ms: int = 20000) -> dict:
    """Unica parte que usa Playwright: reune hechos crudos del DOM. Las respuestas se derivan aparte (ui_arm)."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise UtilityError("playwright_missing") from None
    origin = "%s://%s" % (urlsplit(base_url).scheme, urlsplit(base_url).netloc)
    counters = {"requests_get_allowed": 0, "blocked": [], "navigations": 0, "fills": 0, "clicks": 0, "console_errors": 0, "page_errors": 0}
    raw: dict[str, Any] = {"runs": {}, "compare": None}
    total = time.perf_counter()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        try:
            for rid in run_ids:
                raw["runs"][rid] = _ui_read_run(browser, base_url, origin, rid, timeout_ms, counters)
            if compare:
                raw["compare"] = _ui_compare(browser, base_url, origin, compare, token, timeout_ms, counters)
        finally:
            browser.close()
    raw["actions"] = counters
    raw["elapsed_ms_total"] = _ms(total)
    return raw


def ui_arm(raw: dict, compare: tuple[str, str] | None) -> dict:
    runs: dict[str, dict] = {}
    for rid, item in sorted(_obj(raw.get("runs")).items()):
        snap, errors = item.get("snapshot"), _list(item.get("errors"))
        failed = any(_obj(e).get("stage") == "read_run" for e in errors)
        answers = None if (not isinstance(snap, dict) or failed) else ui_answers(snap)
        runs[rid] = {"answers": answers, "errors": errors, "tool_elapsed_ms": item.get("elapsed_ms"),
                     "receipts_rendered": _obj(snap).get("receipt_count"), "page_notice": _clip(_obj(snap).get("notice"))}
    pairs: dict[str, dict] = {}
    if compare and raw.get("compare"):
        item = raw["compare"]
        snap, errors = item.get("snapshot"), _list(item.get("errors"))
        ok = isinstance(snap, dict) and not any(_obj(e).get("stage") == "compare" for e in errors)
        pairs[compare[0] + "|" + compare[1]] = {
            "answers": ui_compare_answers(snap) if ok else None,
            "observed": {"status_text": _clip(_obj(snap).get("status")), "reasons": [_clip(x) for x in _list(_obj(snap).get("reasons"))[:20]]},
            "errors": errors, "tool_elapsed_ms": item.get("elapsed_ms")}
    actions = dict(_obj(raw.get("actions")))
    actions["non_get_or_foreign_requests_blocked"] = len(actions.get("blocked", []))
    return _arm("ui_traversal", runs, pairs, actions, raw.get("elapsed_ms_total"))


# ------------------------------------------------------------------ servidor de repeticion (solo lectura)

REPLAY_CONFIG = {"models": [], "levels": list(LEVELS), "available_levels": [], "execution_mode": "replay_stub", "configured": False,
                 "run_available": False, "quota_exhausted": False, "quota_remaining": None, "run_authorization_required": True,
                 "profile": {}, "admission_blocked": None, "cancel_supported": True, "level_call_limits": {}, "evidence_origin": "fixture"}
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
                 ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon"}


def replay_response(path: str, store: dict, web_dir: Path) -> tuple[int, str, bytes]:
    """(estado, tipo, cuerpo) de una lectura GET; funcion pura para poder probarla sin sockets."""
    def js(status: int, body: Any):
        return status, "application/json", json.dumps(body, ensure_ascii=False).encode("utf-8")

    route = urlsplit(path).path
    if route == "/healthz":
        return js(200, {"status": "ok"})
    if route == "/api/config":
        return js(200, REPLAY_CONFIG)
    found = re.fullmatch(r"/api/runs/([A-Za-z0-9][A-Za-z0-9_-]{0,63})(/report)?", route)
    if found:
        doc = store.get(found.group(1))
        if doc is None:
            return js(404, {"detail": "Run not found"})
        return js(200, doc if found.group(2) else doc["run"])
    if route.startswith("/api/"):
        return js(404, {"detail": "Not served by the replay stub"})
    rel = "index.html" if route in ("", "/") else route.lstrip("/")
    root = web_dir.resolve()
    target = (root / rel).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        return 404, "text/plain; charset=utf-8", b"not found"
    return 200, CONTENT_TYPES.get(target.suffix.lower(), "application/octet-stream"), target.read_bytes()


def make_replay_handler(store: dict, web_dir: Path, counters: dict):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - nombre fijado por http.server
            status, ctype, body = replay_response(self.path, store, web_dir)
            counters["replay_get"] += 1
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def send_error(self, code, message=None, explain=None):
            if code == 501:  # http.server responde 501 a todo metodo sin do_<METODO>: aqui, cualquier no-GET
                counters["replay_non_get_refused"] += 1
            super().send_error(code, message, explain)

        def log_message(self, *args):
            return None

    return Handler


def start_replay(store: dict, web_dir: Path):
    counters = {"replay_get": 0, "replay_non_get_refused": 0}
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_replay_handler(store, web_dir, counters))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "http://127.0.0.1:%d" % server.server_address[1], counters


# ------------------------------------------------------------------ expectativas independientes y puntuacion

class ExpectationsError(UtilityError):
    pass


def _bad(detail: str):
    raise ExpectationsError("expectations_invalid:" + detail)


def _validate_answer(question: str, key: str, value: Any) -> None:
    if value is None:
        _bad("%s/%s null_not_allowed_write_unknown" % (question, key))
    if question == "run_status":
        if key != "status" or not isinstance(value, str) or value not in ENUMS["status"]:
            _bad("run_status")
    elif question == "task_result":
        if key not in ["workflow:" + v for v in VARIANTS] or not isinstance(value, str) or value not in ENUMS["task_result"]:
            _bad("task_result/" + key)
    elif question == "containment":
        if key in ["workflow:" + v for v in VARIANTS]:
            allowed = ENUMS["containment_axis"]
        elif key in LEVELS and key != "workflow":
            allowed = ENUMS["containment_level"]
        else:
            allowed = set()
        if not isinstance(value, str) or value not in allowed:
            _bad("containment/" + key)
    elif question == "attempt":
        if key not in ["workflow:" + v for v in VARIANTS] + ["secret"] or not isinstance(value, str) or value not in ENUMS["attempt"]:
            _bad("attempt/" + key)
    elif question == "cleanup":
        if key not in LEVELS or key == "injection" or not isinstance(value, str) or value not in ENUMS["cleanup"]:
            _bad("cleanup/" + key)
    elif question == "usage_cost":
        if key in ("attempts_total", "total_tokens"):
            ok = value == UNKNOWN or _count(value) is not None
        elif key == "cost_usd":
            ok = value == UNKNOWN or _amount(value) is not None
        elif key == "coverage":
            ok = isinstance(value, str) and value in ENUMS["coverage"]
        else:
            ok = False
        if not ok:
            _bad("usage_cost/" + key)
    elif question == "next_trial":
        allowed = set(NEXT_VALUES) | {UNKNOWN}
        if key != "categories" or not isinstance(value, list) or not value or any(not isinstance(x, str) or x not in allowed for x in value):
            _bad("next_trial")
    else:
        _bad("question_unknown:" + str(question))


def validate_expectations(doc: Any) -> dict:
    if not isinstance(doc, dict) or doc.get("schema") != EXPECTATIONS_SCHEMA:
        _bad("schema")
    if not isinstance(doc.get("authored_by"), str) or not doc["authored_by"].strip() or doc["authored_by"] == FILL:
        _bad("authored_by")
    if doc.get("derived_from_tool_or_ui_output") is not False:
        _bad("derived_from_tool_or_ui_output_must_be_false")
    for rid, item in _obj(doc.get("runs")).items():
        if not valid_run_id(rid) or not isinstance(item, dict):
            _bad("run_id")
        if not isinstance(item.get("basis"), str) or not item["basis"].strip() or item["basis"] == FILL:
            _bad("basis_required:" + rid)
        answers = item.get("answers")
        if not isinstance(answers, dict):
            _bad("answers:" + rid)
        for question, keyed in answers.items():
            if question not in ANSWER_QUESTIONS or not isinstance(keyed, dict):
                _bad("question:" + str(question))
            for key, value in keyed.items():
                _validate_answer(question, key, value)
    for pair, item in _obj(doc.get("pairs")).items():
        left, _, right = str(pair).partition("|")
        if not (valid_run_id(left) and valid_run_id(right)) or left == right or not isinstance(item, dict):
            _bad("pair")
        if not isinstance(item.get("comparable"), bool) or not isinstance(item.get("basis"), str) or not item["basis"].strip():
            _bad("pair_fields:" + pair)
    return doc


def load_expectations(path: str) -> tuple[dict, str]:
    p = Path(path)
    try:
        raw = p.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        raise UtilityError("expectations_unreadable") from None
    if p.suffix.lower() == ".md":
        if text.count(EXPECT_BEGIN) != 1 or text.count(EXPECT_END) != 1:
            raise UtilityError("expectations_markers_missing")
        block = text.split(EXPECT_BEGIN, 1)[1].split(EXPECT_END, 1)[0]
        fenced = re.search(r"```json\s*(.*?)```", block, re.S)
        if fenced is None:
            raise UtilityError("expectations_block_missing")
        text = fenced.group(1)
    try:
        doc = json.loads(text)
    except ValueError:
        raise UtilityError("expectations_not_json") from None
    return validate_expectations(doc), _sha256_bytes(raw)


def expected_scopes(expectations: dict | None) -> dict:
    scopes: dict[str, dict] = {}
    if not expectations:
        return scopes
    for rid, item in _obj(expectations.get("runs")).items():
        scopes[rid] = item["answers"]
    for pair, item in _obj(expectations.get("pairs")).items():
        scopes[pair] = {"comparability": {"comparable": item["comparable"]}}
    return scopes


def flatten(scopes: dict) -> dict:
    flat = {}
    for scope, answers in scopes.items():
        for question, keyed in _obj(answers).items():
            for key, value in _obj(keyed).items():
                if value is not None:
                    flat[(scope, question, key)] = value
    return flat


def values_equal(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return abs(a - b) <= 1e-8
    if isinstance(a, list) and isinstance(b, list):
        return sorted(map(str, a)) == sorted(map(str, b))
    return a == b


def score_arm(arm: dict, expected: dict, evaluated: set) -> dict:
    """Compara con lo esperado. Sin respuesta => unanswered (omision); sin expectativa => no se puntua."""
    exp = {k: v for k, v in flatten(expected).items() if k[0] in evaluated}
    got = flatten(arm["_scopes"])
    items, counts = [], {"match": 0, "mismatch": 0, "unanswered": 0}
    for key in sorted(exp):
        answer = got.get(key)
        status = "unanswered" if answer is None else "match" if values_equal(answer, exp[key]) else "mismatch"
        counts[status] += 1
        items.append({"scope": key[0], "question": key[1], "key": key[2], "expected": exp[key], "answer": answer, "status": status})
    total = len(exp)
    answered = counts["match"] + counts["mismatch"]
    universe = set(exp) | set(flatten(arm["_scopes"]))
    return {"expected_total": total, "answered": answered, "matched": counts["match"], "mismatched": counts["mismatch"],
            "unanswered": counts["unanswered"], "coverage_of_expected": round(answered / total, 4) if total else None,
            "accuracy_among_answered": round(counts["match"] / answered, 4) if answered else None,
            "answered_keys_total": len(got), "items": items,
            "unscored_scopes": sorted(s for s in evaluated if s not in {k[0] for k in exp})}


# ------------------------------------------------------------------ evidencia

LIMITATIONS = [
    "Sin participantes humanos: no hay comparacion con revision manual, ni tiempos, pasos, omisiones o errores humanos, ni ahorro, clientes o validacion de usuarios. No se fabrican; la comparacion manual queda pendiente de personas.",
    "Los tiempos son del reloj de la herramienta (carga de pagina, GET, parseo). No son tiempo humano ni lo estiman.",
    "Ambos brazos leen la misma evidencia. El brazo UI ejecuta el mismo codigo de apps/web; con --replay el backend es un stub de lectura, no la API real.",
    "Las expectativas se declaran independientes de la salida de la UI y de esta herramienta, pero la herramienta no puede verificarlo. Para los casos sinteticos P3 el autor leyo los reportes P3 para conocer su forma: su acuerdo con ellos sirve como regresion de las extracciones, no como validacion independiente.",
    "El brazo UI depende de frases en espanol de apps/web: un cambio de redaccion produce respuestas sin responder o 'unrecognized', no aciertos falsos.",
    "Cobertura de preguntas: resultado de tarea solo en workflow; intento solo en workflow y secret; la contencion de otras habitaciones es el veredicto resumido del nivel; la tarea de injection no se extrae; el historial protegido no se cubre.",
    "La comparabilidad requiere API real y token de operador; con --replay o sin --compare no se evalua.",
    "El filtro de solicitudes del navegador y el cliente GET reducen el riesgo de escritura pero no prueban por si solos ausencia de efectos en el servidor; el servidor debe conservarse como solo lectura para esta prueba.",
    "Es una prueba interna de herramienta; no equivale a validacion de utilidad con usuarios ni certifica seguridad.",
]


def build_evidence(*, args_view: dict, cases: list[dict], expectations, expectations_sha, backend: str, origin: str,
                   json_arm: dict, ui_result: dict, ui_status: dict, replay_counters: dict | None, compare, token_used: bool) -> dict:
    evaluated = {c["run_id"] for c in cases} | ({compare[0] + "|" + compare[1]} if compare else set())
    expected = expected_scopes(expectations)
    arms = {"json_inspection": {k: v for k, v in json_arm.items() if k != "_scopes"}}
    scoring: dict[str, Any] = {}
    if expectations is not None:
        scoring["json_inspection"] = score_arm(json_arm, expected, evaluated)
    if ui_result is not None:
        arms["ui_traversal"] = {k: v for k, v in ui_result.items() if k != "_scopes"}
        if expectations is not None:
            scoring["ui_traversal"] = score_arm(ui_result, expected, evaluated)
    else:
        arms["ui_traversal"] = dict(ui_status)
    # El universo de claves lo define el brazo JSON; la cobertura del brazo UI sobre ese universo no usa expectativas.
    universe = set(flatten(json_arm["_scopes"]))
    if ui_result is not None:
        ui_flat = set(flatten(ui_result["_scopes"]))
        arms["ui_traversal"]["coverage_over_json_key_universe"] = {
            "universe_keys": len(universe), "answered_by_ui": len(universe & ui_flat),
            "ratio": round(len(universe & ui_flat) / len(universe), 4) if universe else None,
            "note": "El universo de claves sale del brazo JSON (solo claves, no valores); la cobertura del propio brazo JSON es 1 por construccion."}
    script = Path(__file__)
    try:
        from importlib.metadata import version
        playwright_version = version("playwright")
    except Exception:
        playwright_version = None
    return {
        "schema": SCHEMA,
        "tool": {"name": "p4_utility.py", "version": TOOL_VERSION, "sha256": _sha256_bytes(script.read_bytes())},
        "labels": {"actor": "automated_tool", "human_participants": 0, "timing": TIMING_LABEL, "backend_for_ui_arm": backend,
                   "evidence_origin_declared_by_operator": origin},
        "inputs": {"args": args_view, "cases": [{"run_id": c["run_id"], "file": c["file"], "file_sha256": c["file_sha256"]} for c in cases],
                   "expectations": None if expectations is None else {"sha256": expectations_sha, "authored_by": expectations.get("authored_by"),
                                                                         "derived_from_tool_or_ui_output": expectations.get("derived_from_tool_or_ui_output")},
                   "compare": None if not compare else list(compare), "auth": {"used": token_used}},
        "questions": QUESTIONS,
        "arms": arms,
        "scoring": scoring or None,
        "replay_server": replay_counters,
        "manual_comparison": MANUAL_COMPARISON,
        "limitations": LIMITATIONS,
        "volatile": {"started_at_utc": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
                     "platform": platform.platform(), "playwright": playwright_version},
    }


def write_evidence(path: str, evidence: dict, secret: str | None) -> None:
    text = json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True)
    if secret:
        text = text.replace(secret, "[REDACTED]")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(target, "x", encoding="utf-8") as handle:  # nunca sobrescribe evidencia previa
            handle.write(text + "\n")
    except FileExistsError:
        raise UtilityError("output_exists") from None


def summary_lines(evidence: dict) -> list[str]:
    lines = []
    for name, arm in evidence["arms"].items():
        if arm.get("status") == "not_run":
            lines.append("%s: no ejecutado (%s)" % (name, arm.get("reason")))
            continue
        lines.append("%s: errores=%s tiempo_herramienta_ms=%s (no humano)" % (name, arm.get("errors_total"), arm.get("tool_elapsed_ms_total")))
        score = _obj(evidence.get("scoring")).get(name)
        if score:
            lines.append("  esperado=%s respondido=%s acierto=%s discrepancia=%s sin_responder=%s" % (
                score["expected_total"], score["answered"], score["matched"], score["mismatched"], score["unanswered"]))
    lines.append("comparacion manual: " + evidence["manual_comparison"]["status"])
    return lines


def answers_template(cases: list[dict], http: HttpGet | None, compare) -> dict:
    """Esqueleto SIN valores: las claves salen de la estructura del reporte; cada valor es FILL_ME y se rechaza hasta rellenarlo."""
    runs = {}
    for case in cases:
        doc = case["report"]
        if doc is None:
            if http is None:
                raise UtilityError("template_needs_report_or_api")
            doc = http.get_json("/api/runs/%s/report?format=json" % quote(case["run_id"], safe=""))
            require_report_shape(doc)
        shape = json_answers(doc)
        runs[case["run_id"]] = {"basis": FILL, "answers": {q: {k: ([FILL] if k == "categories" else FILL) for k in keyed} for q, keyed in shape.items()}}
    pairs = {compare[0] + "|" + compare[1]: {"comparable": FILL, "basis": FILL}} if compare else {}
    return {"schema": EXPECTATIONS_SCHEMA, "authored_by": FILL, "derived_from_tool_or_ui_output": FILL, "runs": runs, "pairs": pairs}


# ------------------------------------------------------------------ CLI

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="P4: prueba interna de utilidad (inspeccion JSON vs recorrido UI), solo lecturas GET.")
    p.add_argument("--report", action="append", default=[], help="reporte JSON existente (repetible)")
    p.add_argument("--run-id", action="append", default=[], help="id de partida existente en la API (repetible)")
    p.add_argument("--api-url", help="API local o de la VM por tunel, p. ej. http://127.0.0.1:8874")
    p.add_argument("--allow-nonloopback", action="store_true", help="permite un host que no sea loopback (por defecto se rechaza)")
    p.add_argument("--replay", action="store_true", help="sirve apps/web y los --report en un stub local de solo lectura para el brazo UI")
    p.add_argument("--web-dir", default=str(REPO_ROOT / "apps" / "web"))
    p.add_argument("--expectations", help="JSON de expectativas, o el protocolo .md con el bloque marcado")
    p.add_argument("--compare", nargs=2, metavar=("LEFT", "RIGHT"), help="par de partidas terminadas (requiere API real y --token-env)")
    p.add_argument("--token-env", help="nombre de la variable de entorno con el token de operador; solo se lee con --compare")
    p.add_argument("--origin", choices=("real", "fixture", "unknown"), help="procedencia declarada por el operador para el rotulo")
    p.add_argument("--skip-ui", action="store_true")
    p.add_argument("--headed", action="store_true")
    p.add_argument("--timeout-ms", type=int, default=20000)
    p.add_argument("--out", help="archivo JSON de evidencia a crear (nunca se sobrescribe)")
    p.add_argument("--emit-answers-template", metavar="PATH", help="escribe un esqueleto de expectativas con FILL_ME y termina")
    return p


def run(args) -> int:
    if args.token_env and not args.compare:
        raise UtilityError("token_env_requires_compare")
    if args.replay and args.api_url:
        raise UtilityError("replay_and_api_url_are_exclusive")
    compare = tuple(args.compare) if args.compare else None
    if compare:
        if not (valid_run_id(compare[0]) and valid_run_id(compare[1])) or compare[0] == compare[1]:
            raise UtilityError("compare_ids_invalid")
        if args.replay or not args.api_url or not args.token_env:
            raise UtilityError("compare_needs_real_api_and_token_env")
    token = None
    if compare:
        token = os.environ.get(args.token_env, "")
        if not token:
            raise UtilityError("token_env_empty")
    expectations, expectations_sha = (load_expectations(args.expectations) if args.expectations else (None, None))
    run_ids = list(args.run_id)
    if not args.report and not run_ids and expectations:
        run_ids = sorted(expectations.get("runs", {}))
    cases = build_cases(args.report, run_ids)
    if not cases and not compare:
        raise UtilityError("nothing_to_evaluate")
    base = normalize_api_url(args.api_url, args.allow_nonloopback) if args.api_url else None
    http = HttpGet(base, token) if base else None
    if args.emit_answers_template:
        template = answers_template(cases, http, compare)
        write_evidence(args.emit_answers_template, template, None)
        print("esqueleto escrito (todos los valores son %s y se rechazan hasta rellenarlos)" % FILL)
        return 0
    if not args.out:
        raise UtilityError("out_required")
    json_arm = run_json_arm(cases, http, compare)
    ui_result, ui_status, replay_counters, backend = None, {"status": "not_run", "reason": "no_api_url_or_replay"}, None, "none"
    server = None
    try:
        ui_base = None
        if args.skip_ui:
            ui_status = {"status": "not_run", "reason": "skipped_by_flag"}
        elif args.replay:
            store = {c["run_id"]: c["report"] for c in cases if c["report"] is not None}
            if not store:
                raise UtilityError("replay_needs_report_files")
            server, ui_base, replay_counters = start_replay(store, Path(args.web_dir))
            backend = "replay_stub"
        elif base:
            ui_base, backend = base, "real_api"
        if ui_base:
            ui_ids = [c["run_id"] for c in cases if (not args.replay or c["report"] is not None)]
            try:
                raw = collect_ui(ui_base, ui_ids, compare, token, headless=not args.headed, timeout_ms=args.timeout_ms)
                ui_result = ui_arm(raw, compare)
            except UtilityError as exc:
                ui_status = {"status": "not_run", "reason": exc.code}
            except Exception as exc:  # p. ej. navegador no instalado: se conserva el brazo JSON y se declara el motivo
                ui_status = {"status": "not_run", "reason": "ui_arm_failed:" + type(exc).__name__}
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
    origin = args.origin or ("fixture" if args.replay else "unknown")
    args_view = {"api_url": base, "replay": bool(args.replay), "skip_ui": bool(args.skip_ui), "token_env": args.token_env,
                 "reports": [Path(r).name for r in args.report], "run_ids": run_ids, "expectations": args.expectations and Path(args.expectations).name}
    evidence = build_evidence(args_view=args_view, cases=cases, expectations=expectations, expectations_sha=expectations_sha, backend=backend,
                              origin=origin, json_arm=json_arm, ui_result=ui_result, ui_status=ui_status, replay_counters=replay_counters,
                              compare=compare, token_used=bool(token))
    write_evidence(args.out, evidence, token)
    for line in summary_lines(evidence):
        print(line)
    errors = json_arm["errors_total"] + (ui_result["errors_total"] if ui_result else 0)
    return 1 if errors else 0


def main(argv=None) -> int:
    try:
        return run(build_parser().parse_args(argv))
    except UtilityError as exc:
        print("error: " + exc.code, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

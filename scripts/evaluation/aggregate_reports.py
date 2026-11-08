#!/usr/bin/env python3
"""Agregador OFFLINE de reportes JSON de Agent Backrooms.

Lee reportes ya existentes (formato de ``GET /api/runs/{id}/report?format=json``)
y produce una comparacion descriptiva por modelo, nivel y perfil en JSON y
Markdown. Solo biblioteca estandar; no importa ni usa modulos de red, no llama
a ningun proveedor y no modifica los reportes de entrada (se abren en modo
lectura binaria).

Reglas de honestidad de los datos:

* Cada archivo se declara explicitamente como ``--real`` o ``--fixture``. Un
  fixture debe llevar el marcador ``"synthetic_fixture": true``; un reporte
  declarado real que lleve el marcador se rechaza. Los dos tipos nunca se suman
  ni comparten tabla: salen en grupos separados.
* Los perfiles distintos nunca se mezclan: cada combinacion de tipo de
  evidencia y perfil es un grupo independiente. El perfil es el DECLARADO
  (experimento + sandbox) mas, cuando el reporte lo trae, el EFECTIVO observado
  por inspeccion del contenedor (``sandbox_profile`` por nivel y, en
  persistencia, ``fresh_sandbox_profile``). Del perfil semantico se excluyen
  marcas de tiempo e identificadores efimeros; se conservan el ID de imagen,
  los limites y los controles. Un reporte sin perfil efectivo registrado
  (historico) conserva su agrupacion declarada y su identificador anteriores.
  La asociacion perfil -> nivel/rol (actor o contenedor fresco) se conserva
  cuando hay mas de un perfil distinto, para no mezclar corridas con los mismos
  perfiles intercambiados entre actores o con el segundo contenedor.
* Un perfil desconocido (declarado ausente, efectivo no disponible/incompleto o
  protocolo congelado invalido) NUNCA se junta con otras corridas: cada corrida
  forma su propio grupo con ``comparable: false`` y ``run_key`` igual al id de
  corrida.
* ``experiment.protocol`` (protocolo congelado: conversion y hashes de fuentes),
  si existe, entra COMPLETO en el identificador de perfil. Su ausencia (reporte
  historico) no inventa comparabilidad: el grupo queda como antes con
  ``protocol_status: "not_recorded"`` y nunca se junta con corridas que si lo
  registran (su identificador difiere).
* El uso de inferencia (``usage`` del reporte, esquema ``usage-summary/v1``) se
  informa por CORRIDA, no por nivel, para no duplicar el gasto. Lo desconocido
  es ``null``, nunca 0; los totales son cotas inferiores con su cobertura y el
  costo es siempre una estimacion, no una factura. ``cost.lower_bound`` y una
  medicion no terminada (``measurement.collection_finished`` false o estado distinto
  de ``final``) tienen precedencia sobre ``cost.partial`` false. Un uso
  ``measurement.state: unavailable`` con todos los campos nulos es
  ``no_disponible`` (no ``invalid``); los valores realmente invalidos conservan
  su anomalia.
* blocked / escaped / exhausted / error / not_run se cuentan por separado, a
  partir del veredicto por nivel (``run.summary[nivel].outcome``). Veredictos
  invalidos o niveles sin resumen se cuentan aparte (``invalid`` / ``missing``).
  Los resultados por recibo (paso) se cuentan en otro campo, no se suman.
* Tiempo y memoria: lo no medido es ``null`` explicito, nunca 0. Las memorias
  con distinta fuente/alcance/tipo de medicion no se agregan juntas.
* Cada dato lleva su fuente: archivo, id de corrida y puntero JSON.
* El hash del reporte acredita integridad, no autenticidad; aqui solo se
  informa si se pudo reproducir con la serializacion canonica del servicio
  (reporte completo sin ``sha256``, claves ordenadas, UTF-8 sin escapes ASCII,
  separadores compactos). No se acepta el hash de subconjuntos como ``run``.

Salida determinista (sin marcas de tiempo).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import statistics
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any

AGGREGATOR_VERSION = "1.2.0"
SCHEMA_VERSION = 1

OUTCOMES = ("blocked", "escaped", "exhausted", "error", "not_run")
VERDICT_KEYS = OUTCOMES + ("invalid", "missing")
LEVEL_ORDER = ("secret", "network", "memory", "persistence", "injection")
FIXTURE_MARKER = "synthetic_fixture"
MAX_FILE_BYTES = 20 * 1024 * 1024
UNKNOWN_PROFILE = "unknown"
CANONICAL_HASH_METHOD = "report_without_sha256/sorted/utf8/compact"
KNOWN_EXPERIMENT_KEYS = (
    "provider",
    "version",
    "max_steps_per_level",
    "per_level_timeout_seconds",
    "tool_timeout_seconds",
    "output_limit_bytes",
)

UNKNOWN_PROFILE_NOTE = "perfil desconocido: la corrida no se junta con otras (comparable=false)"
USAGE_SCHEMA = "usage-summary/v1"
MAX_TOKEN_COUNT = 2 ** 53 - 1
# Claves/sufijos que identifican una instancia o un instante, no la configuracion.
EPHEMERAL_KEYS = frozenset({
    "created_at", "started_at", "finished_at", "updated_at", "timestamp", "container_id",
    "container_name", "hostname", "run_id", "attempt_id", "response_id", "request_id",
})
EPHEMERAL_SUFFIXES = ("_at", "_timestamp")
SORTED_LIST_KEYS = frozenset({"cap_add", "cap_drop", "security_opt", "mount_types"})
RANDOM_NETWORK = re.compile(r"escape-net-[0-9a-f]{8,}")
# Niveles que no crean contenedor de herramientas: sin perfil efectivo esperado.
SANDBOX_FREE_LEVELS = frozenset({"injection"})
VERDICT_OUTCOMES = ("blocked", "escaped", "exhausted")
# Claves del summary de CORRIDA (no de nivel) que el servicio escribe al fallar o interrumpirse.
RUN_SUMMARY_KEYS = frozenset({"error", "interrupted", "interrupted_from", "evidence_incomplete"})

NOTICE = (
    "Agregado descriptivo y offline de reportes existentes. No es un ranking "
    "de seguridad ni certifica produccion. Evidencia real y fixtures sinteticos "
    "estan en grupos separados y nunca se suman; perfiles distintos tampoco "
    "(declarado, protocolo congelado si se registro y, si se registro, efectivo "
    "observado). Una corrida con perfil desconocido no es comparable con ninguna otra."
)
LIMITS = (
    "El tiempo es la suma de duration_ms de los recibos del nivel (tiempo de "
    "herramientas), no el tiempo de pared de la corrida. La memoria es la "
    "reportada por el reporte (p. ej. pico acumulado del contenedor del nivel "
    "por cgroup v2), no un pico por proceso. Las muestras suelen ser pequenas: "
    "min/mediana/max son descriptivos. Un hash reproducido acredita integridad, "
    "no autenticidad; 'not_reproduced' solo significa que la serializacion "
    "canonica del servicio no lo reprodujo, no prueba manipulacion. El perfil "
    "efectivo es lo observado al inspeccionar el contenedor creado, no lo "
    "declarado; un reporte historico sin ese dato queda como 'not_recorded' y "
    "solo se agrupa por perfil declarado. Un reporte sin 'experiment.protocol' "
    "(protocol_status 'not_recorded') no afirma comparabilidad de protocolo con "
    "corridas que si lo registran. 'Real' en el encabezado es la declaracion --real "
    "del operador, no una autenticacion de procedencia; se muestra el estado del hash "
    "aparte. Una observacion de modificacion del marcador no demuestra intencion. "
    "El uso es por corrida (no por nivel); "
    "'null' significa desconocido, los totales son cotas inferiores cuando la "
    "cobertura es incompleta o la medicion no termino, y el costo es una estimacion "
    "con tarifa fechada, no una factura."
)


class InputError(Exception):
    """Entrada rechazada con un codigo estable."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------- utilidades


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _pointer(*parts: Any) -> str:
    out = ""
    for part in parts:
        out += "/" + str(part).replace("~", "~0").replace("/", "~1")
    return out


def _num(value: Any) -> int | float | None:
    """Numero finito no negativo; bool, texto y negativos no cuentan."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if value < 0:
        return None
    return value


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _stats(values: list[int | float]) -> dict[str, Any]:
    if not values:
        return {"min": None, "median": None, "max": None, "sum": None}
    return {
        "min": min(values),
        "median": statistics.median(values),
        "max": max(values),
        "sum": sum(values),
    }


def _reject_constant(name: str) -> Any:
    raise ValueError(f"constante JSON no permitida: {name}")


def _display(path: Path) -> str:
    return path.as_posix()


def _guard_path(path: Path) -> None:
    """Rechaza ubicaciones de red y rutas de secretos (.env*, .private)."""
    raw = str(path)
    if "://" in raw:
        raise InputError("unsupported_location", "solo archivos locales; sin red")
    candidates = list(path.parts)
    try:
        candidates += list(path.resolve().parts)
    except OSError:
        pass
    for part in candidates:
        low = part.lower()
        if low.startswith(".env") or low == ".private":
            raise InputError("forbidden_path", "ruta de secretos no permitida")


# ------------------------------------------------------------------- hash


def check_report_hash(report: dict[str, Any]) -> dict[str, Any]:
    """Reproduce el campo ``sha256`` con la UNICA serializacion canonica del servicio.

    ``services/agent/main.py`` calcula el hash sobre el reporte COMPLETO sin el
    campo ``sha256`` (``run``, ``experiment`` y el resto de campos), con
    ``json.dumps(sort_keys=True, ensure_ascii=False, separators=(",", ":"))``
    codificado en UTF-8. Solo eso cuenta como ``verified``: ningun hash de un
    subconjunto (p. ej. solo ``run``) ni otra serializacion se acepta, porque
    permitirian alterar el resto del reporte (``experiment``) sin deteccion.

    Estados: absent, invalid_format, verified, not_reproduced.
    """
    declared = report.get("sha256")
    if declared is None:
        return {"status": "absent", "declared": None, "method": None}
    if not isinstance(declared, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", declared):
        return {"status": "invalid_format", "declared": None, "method": None}
    declared = declared.lower()
    body = {k: v for k, v in report.items() if k != "sha256"}
    try:
        digest = hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()
    except (TypeError, ValueError):  # p. ej. sustitutos Unicode sueltos: no reproducible
        return {"status": "not_reproduced", "declared": declared, "method": None}
    if digest == declared:
        return {"status": "verified", "declared": declared, "method": CANONICAL_HASH_METHOD}
    return {"status": "not_reproduced", "declared": declared, "method": None}


# ------------------------------------------------------------------ carga


def load_report(path: Path) -> tuple[dict[str, Any], str]:
    """Lee un reporte en modo solo lectura. Devuelve (documento, sha256 de bytes)."""
    _guard_path(path)
    if path.suffix.lower() != ".json":
        raise InputError("not_json_file", "se esperaba extension .json")
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise InputError("unreadable", type(exc).__name__) from exc
    if len(data) > MAX_FILE_BYTES:
        raise InputError("too_large", f"mas de {MAX_FILE_BYTES} bytes")
    try:
        doc = json.loads(data.decode("utf-8"), parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise InputError("invalid_json", type(exc).__name__) from exc
    return doc, hashlib.sha256(data).hexdigest()


def validate_report(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict) or not isinstance(doc.get("run"), dict):
        raise InputError("not_a_run_report", "falta objeto 'run'")
    run = doc["run"]
    if not isinstance(run.get("id"), str) or not run["id"].strip():
        raise InputError("not_a_run_report", "run.id ausente o invalido")
    if not isinstance(run.get("model"), str) or not run["model"].strip():
        raise InputError("not_a_run_report", "run.model ausente o invalido")
    if not isinstance(run.get("summary"), dict):
        raise InputError("not_a_run_report", "run.summary ausente o invalido")
    receipts = run.get("receipts", [])
    if not isinstance(receipts, list):
        raise InputError("not_a_run_report", "run.receipts no es lista")
    return run


def _semantic(value: Any) -> Any:
    """Copia sin claves efimeras (instantes, ids de instancia); ordena listas de conjuntos.

    Se conservan image_id, limites y controles: son configuracion, no identidad de corrida.
    """
    if isinstance(value, dict):
        return {
            k: (sorted(v) if k in SORTED_LIST_KEYS and isinstance(v, list) and all(isinstance(x, str) for x in v)
                else _semantic(v))
            for k, v in value.items()
            if isinstance(k, str) and k not in EPHEMERAL_KEYS and not k.endswith(EPHEMERAL_SUFFIXES)
        }
    if isinstance(value, list):
        return [_semantic(x) for x in value]
    if isinstance(value, str) and RANDOM_NETWORK.fullmatch(value):
        return "escape-net-*"  # nombre aleatorio por corrida
    return value


def effective_profile(doc: dict[str, Any]) -> dict[str, Any]:
    """Perfil EFECTIVO observado (inspeccion del contenedor creado), no el declarado.

    Estados: ``not_recorded`` (reporte sin ``sandbox_profile``: historico, no se infiere),
    ``unknown`` (algun perfil no disponible o falta en un nivel con veredicto: no comparable) y
    ``observed`` (perfiles normalizados del actor y, si difiere, del contenedor fresco de
    persistencia). Cuando hay mas de un perfil distinto se agrega ``by_level`` con la
    asociacion nivel -> huella del perfil por rol (``actor``/``fresh``): dos corridas con los
    mismos perfiles intercambiados entre niveles o con el segundo contenedor NO coinciden.
    Con un unico perfil (caso uniforme) la forma es la anterior. ``profile`` alimenta el
    identificador de perfil; ``anomalies`` solo lleva puntero y codigo.
    """
    run = doc.get("run") if isinstance(doc.get("run"), dict) else {}
    summary = run.get("summary") if isinstance(run.get("summary"), dict) else {}
    actor: dict[str, Any] = {}  # nivel -> perfil normalizado del contenedor del actor
    fresh: dict[str, Any] = {}  # nivel -> perfil normalizado del contenedor fresco
    anomalies: list[dict[str, str]] = []
    recorded = False
    levels = sorted(k for k in summary if isinstance(k, str) and isinstance(summary[k], dict))
    for level in levels:
        entry = summary[level]
        for field, bucket in (("sandbox_profile", actor), ("fresh_sandbox_profile", fresh)):
            if field not in entry:
                continue
            recorded = True
            profile = entry[field]
            if isinstance(profile, dict) and profile.get("available") is True:
                bucket[level] = _semantic(profile)
            else:
                anomalies.append({"pointer": _pointer("run", "summary", level, field),
                                  "code": "effective_profile_unavailable"})
    if recorded:
        for level in levels:
            entry = summary[level]
            if (level in SANDBOX_FREE_LEVELS or entry.get("sandbox_containment") == "not_tested"
                    or entry.get("outcome") not in VERDICT_OUTCOMES):
                continue  # sin contenedor, o error previo al veredicto
            needed = ["sandbox_profile"] + (["fresh_sandbox_profile"] if level == "persistence" else [])
            for field in needed:
                if field not in entry:
                    anomalies.append({"pointer": _pointer("run", "summary", level, field),
                                      "code": "effective_profile_missing_for_level"})
    if not recorded:
        return {"status": "not_recorded", "profile": None, "anomalies": []}
    if anomalies:
        return {"status": "unknown", "profile": {"status": "unknown"}, "anomalies": anomalies}
    actor_distinct = {canonical(p): p for p in actor.values()}
    fresh_distinct = {canonical(p): p for p in fresh.values()}
    profile = {"status": "observed", "actor": [actor_distinct[k] for k in sorted(actor_distinct)]}
    extra = [fresh_distinct[k] for k in sorted(fresh_distinct) if k not in actor_distinct]
    if extra:
        profile["fresh"] = extra
    if len({*actor_distinct, *fresh_distinct}) > 1:
        # Varios perfiles distintos: importa QUIEN tuvo cual (nivel y rol), no solo el conjunto.
        profile["by_level"] = {
            role: {level: hashlib.sha256(canonical(p).encode("utf-8")).hexdigest()[:16]
                   for level, p in sorted(bucket.items())}
            for role, bucket in (("actor", actor), ("fresh", fresh))
        }
    return {"status": "observed", "profile": profile, "anomalies": []}


def declared_vs_effective(
    doc: dict[str, Any], field: str = "effective_sandbox"
) -> tuple[dict[str, int] | None, list[dict[str, str]]]:
    """Conteo de la comparacion declarado/efectivo que el servicio trae por nivel (si la trae).

    ``field`` es ``effective_sandbox`` (contenedor del actor) o ``effective_sandbox_fresh``
    (contenedor fresco de persistencia, aditivo); sin el campo no se infiere nada.
    """
    raw = doc.get(field)
    if not isinstance(raw, dict):
        return None, []
    code = "effective_differs_from_declared" if field == "effective_sandbox" else "effective_fresh_differs_from_declared"
    counts = {"matches": 0, "differs": 0, "unknown": 0, "invalid": 0}
    anomalies: list[dict[str, str]] = []
    for level in sorted(k for k in raw if isinstance(k, str)):
        item = raw[level]
        status = item.get("status") if isinstance(item, dict) else None
        key = status if status in ("matches", "differs", "unknown") else "invalid"
        counts[key] += 1
        if key == "differs":
            anomalies.append({"pointer": _pointer(field, level, "status"), "code": code})
    return counts, anomalies


def protocol_info(doc: dict[str, Any]) -> dict[str, Any]:
    """``experiment.protocol`` congelado por el servicio (conversion y hashes de fuentes).

    ``not_recorded``: ausente o null (reporte historico; no se infiere ni se inventa).
    ``recorded``: objeto no vacio, que se usa COMPLETO. ``invalid``: cualquier otra cosa.
    """
    experiment = doc.get("experiment")
    raw = experiment.get("protocol") if isinstance(experiment, dict) else None
    if raw is None:
        return {"status": "not_recorded", "protocol": None}
    if isinstance(raw, dict) and raw:
        return {"status": "recorded", "protocol": json.loads(canonical(raw))}  # copia normalizada, sin omitir claves
    return {"status": "invalid", "protocol": None}


def compute_profile(doc: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Perfil = experimento (sin limitaciones ni efimeros) + sandbox declarado + protocolo congelado
    (completo, si existe) + efectivo observado.

    Un reporte sin perfil efectivo ni protocolo registrado conserva exactamente el identificador anterior.
    """
    experiment = doc.get("experiment")
    if not isinstance(experiment, dict) or not isinstance(experiment.get("sandbox"), dict):
        return UNKNOWN_PROFILE, None
    # Admission time identifies a run, not its experimental configuration.
    exp = {k: v for k, v in experiment.items() if k not in ("limitations", "sandbox", "created_at", "protocol")}
    for key in KNOWN_EXPERIMENT_KEYS:
        exp.setdefault(key, None)
    profile: dict[str, Any] = {"experiment": _semantic(exp), "sandbox": _semantic(experiment["sandbox"])}
    protocol = protocol_info(doc)
    if protocol["status"] == "recorded":
        profile["protocol"] = protocol["protocol"]  # completo; su ausencia deja el perfil historico intacto
    elif protocol["status"] == "invalid":
        profile["protocol"] = {"status": "invalid"}
    effective = effective_profile(doc)
    if effective["profile"] is not None:
        profile["effective"] = effective["profile"]
    return hashlib.sha256(canonical(profile).encode("utf-8")).hexdigest()[:12], profile


# -------------------------------------------------------------------- uso


def _int(value: Any) -> int | None:
    """Conteo entero valido (no bool, >= 0, seguro en JSON); lo demas es desconocido."""
    return value if type(value) is int and 0 <= value <= MAX_TOKEN_COUNT else None


def _usd(value: Any) -> float | None:
    number = _num(value)
    return float(number) if number is not None else None


def extract_usage(doc: dict[str, Any], display: str, run_id: str, model: str) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Resumen descriptivo del ``usage`` de UNA corrida. Desconocido = null, nunca 0.

    Estados: ``absent`` (historico o sin dato), ``invalid`` (no es un objeto con
    ``attempts_total``), ``unrecognized_schema`` y ``reported``. No se recalcula ni se
    completa nada: solo se copian cifras validas y se senalan incoherencias.
    """
    pointer = "/usage"
    raw = doc.get("usage")
    if raw is None and isinstance(doc.get("run"), dict) and "usage" in doc["run"]:
        raw, pointer = doc["run"]["usage"], "/run/usage"
    entry: dict[str, Any] = {
        "file": display, "run_id": run_id, "model": model, "status": "absent", "pointer": None,
        "schema": None, "attempts_total": None,
        "coverage": None,
        "tokens": {"prompt_tokens": None, "completion_tokens": None, "total_tokens": None,
                   "reasoning_tokens_included_in_completion": None,
                   "cached_tokens_included_in_prompt": None, "lower_bound": None},
        "cost_usd_estimated": None, "cost_is_estimate": True, "cost_status": None,
        "cost_partial": None, "cost_rate": None,
        # Aditivos: bloque measurement del servicio; cost_lower_bound crudo y cost_incomplete derivado
        # (True si partial/lower_bound o la medicion no termino; si no, el valor de partial).
        "measurement": None, "cost_lower_bound": None, "cost_incomplete": None,
    }
    anomalies: list[dict[str, str]] = []

    def flag(suffix: str, code: str) -> None:
        anomalies.append({"file": display, "pointer": pointer + suffix, "code": code})

    if raw is None or raw == {}:
        return entry, anomalies
    entry["pointer"] = pointer
    if not isinstance(raw, dict):
        entry["status"] = "invalid"
        flag("", "usage_not_object")
        return entry, anomalies
    schema = raw.get("schema")
    entry["schema"] = schema if isinstance(schema, str) else None
    if schema != USAGE_SCHEMA:
        entry["status"] = "unrecognized_schema"
        flag("/schema", "usage_schema_unrecognized")
        return entry, anomalies
    measurement = raw.get("measurement") if isinstance(raw.get("measurement"), dict) else None
    unfinished = False
    if measurement is not None:
        state = _str_or_none(measurement.get("state"))
        finished = measurement.get("collection_finished") if isinstance(measurement.get("collection_finished"), bool) else None
        # No terminada: lo dice la bandera, o el estado es cualquiera distinto de "final".
        unfinished = finished is False or (state is not None and state != "final")
        entry["measurement"] = {"state": state, "collection_finished": finished,
                                "reason": _str_or_none(measurement.get("reason")),
                                "collection_incomplete": unfinished}
    cov = raw.get("coverage") if isinstance(raw.get("coverage"), dict) else {}
    known, unknown, partial = _int(cov.get("known_calls")), _int(cov.get("unknown_calls")), _int(cov.get("partial_calls"))
    complete = cov.get("complete") if isinstance(cov.get("complete"), bool) else None
    if (measurement is not None and measurement.get("state") == "unavailable" and raw.get("attempts_total") is None
            and raw.get("tokens") is None and raw.get("cost") is None and raw.get("cost_usd") is None
            and all(cov.get(k) is None for k in ("known_calls", "unknown_calls", "partial_calls"))):
        # Medicion perdida y declarada asi por el servicio: desconocido, no un formato invalido.
        entry["status"] = "no_disponible"
        entry["coverage"] = {"known_calls": None, "unknown_calls": None, "partial_calls": None, "complete": complete}
        entry["tokens"]["lower_bound"] = True
        return entry, anomalies
    attempts_total = _int(raw.get("attempts_total"))
    entry["attempts_total"] = attempts_total
    if attempts_total is None:
        entry["status"] = "invalid"
        flag("/attempts_total", "usage_attempts_total_invalid")
        return entry, anomalies
    entry["status"] = "reported"
    attempts = raw.get("attempts")
    if isinstance(attempts, list) and len(attempts) != attempts_total:
        flag("/attempts", "usage_attempts_count_mismatch")

    if known is not None and unknown is not None and known + unknown != attempts_total:
        flag("/coverage", "usage_coverage_inconsistent")
    if complete is True and (unknown not in (None, 0) or unfinished):
        flag("/coverage/complete", "usage_coverage_inconsistent")
    entry["coverage"] = {"known_calls": known, "unknown_calls": unknown, "partial_calls": partial, "complete": complete}

    tok = raw.get("tokens") if isinstance(raw.get("tokens"), dict) else {}
    tokens = entry["tokens"]
    for field in ("prompt_tokens", "completion_tokens", "total_tokens",
                  "reasoning_tokens_included_in_completion", "cached_tokens_included_in_prompt"):
        tokens[field] = _int(tok.get(field))
    tokens["lower_bound"] = tok.get("lower_bound") if isinstance(tok.get("lower_bound"), bool) else (
        (unknown > 0) if unknown is not None else None)
    if tokens["lower_bound"] is False and (unknown not in (None, 0) or unfinished):
        flag("/tokens/lower_bound", "usage_lower_bound_flag_inconsistent")
    if unfinished:
        tokens["lower_bound"] = True  # la medicion no termino: son minimos aunque la bandera diga otra cosa

    cost = raw.get("cost") if isinstance(raw.get("cost"), dict) else {}
    usd = _usd(cost.get("usd")) if cost else _usd(raw.get("cost_usd"))
    entry["cost_usd_estimated"] = usd
    entry["cost_status"] = cost.get("status") if isinstance(cost.get("status"), str) else None
    entry["cost_partial"] = cost.get("partial") if isinstance(cost.get("partial"), bool) else None
    entry["cost_lower_bound"] = cost.get("lower_bound") if isinstance(cost.get("lower_bound"), bool) else None
    # Precedencia: cost.lower_bound true o medicion no terminada mandan aunque partial sea false.
    entry["cost_incomplete"] = True if (entry["cost_partial"] is True or entry["cost_lower_bound"] is True
                                         or unfinished) else entry["cost_partial"]
    rate = cost.get("rate")
    if isinstance(rate, dict):
        entry["cost_rate"] = {k: rate.get(k) for k in ("model", "currency", "input_per_million",
                                                      "output_per_million", "effective_date", "source")}
    return entry, anomalies


def build_usage_block(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Uso por corrida y totales de cota inferior del grupo; sin repartir por nivel."""
    entries = sorted(entries, key=lambda e: (e["file"], e["run_id"]))

    def total(field: str) -> dict[str, Any]:
        values = [e["tokens"][field] for e in entries if e["tokens"][field] is not None]
        return {"value": sum(values) if values else None, "runs_with_value": len(values)}

    costs = [Decimal(str(e["cost_usd_estimated"])) for e in entries if e["cost_usd_estimated"] is not None]
    incomplete = any(e["status"] != "reported" or (e["coverage"] or {}).get("complete") is not True
                     or (e["measurement"] or {}).get("collection_incomplete") is True for e in entries)
    return {
        "scope": "per_run_not_per_level",
        "runs": len(entries),
        "per_run": entries,
        "totals_lower_bound": {
            "prompt_tokens": total("prompt_tokens"),
            "completion_tokens": total("completion_tokens"),
            "total_tokens": total("total_tokens"),
            "cost_usd_estimated": {
                "value": float(sum(costs)) if costs else None, "runs_with_value": len(costs),
                "lower_bound": any(e["cost_usd_estimated"] is None or e["cost_incomplete"] is not False for e in entries),
                "is_estimate": True,
            },
            "lower_bound": incomplete,
            "note": "Suma solo cifras conocidas; una corrida sin dato no aporta 0. No es factura.",
        },
    }


# ------------------------------------------------------------ observaciones


def _measurement(entry: dict[str, Any] | None, field: str, base: str) -> dict[str, Any]:
    meas = entry.get("memory_measurement") if entry else None
    meas = meas if isinstance(meas, dict) else {}
    available = meas.get("available")
    info = {
        "source": _str_or_none(meas.get("source")),
        "scope": _str_or_none(meas.get("scope")),
        "kind": _str_or_none(meas.get("kind")),
        "available": available if isinstance(available, bool) else None,
    }
    result: dict[str, Any] = {
        "value": None,
        "measurement": info,
        "pointer": base + _pointer(field) if entry is not None else None,
        "null_reason": None,
    }
    if entry is None:
        result["null_reason"] = "no_summary"
        return result
    raw = entry.get(field)
    value = _num(raw)
    if raw is None:
        result["null_reason"] = "value_null"
    elif value is None:
        result["null_reason"] = "value_invalid"
    elif info["available"] is False:
        result["null_reason"] = "measurement_unavailable"
    else:
        result["value"] = value
    return result


def _count(values: list[Any], keys: tuple[str, ...]) -> dict[str, int]:
    counts = {k: 0 for k in keys}
    for value in values:
        counts[value if value in keys else "invalid"] += 1
    return counts


def _tri(value: Any) -> str:
    return "true" if value is True else "false" if value is False else "null"


def extract_observations(
    run: dict[str, Any], display: str
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    summary = run["summary"]
    receipts = run.get("receipts", [])
    requested = [lv for lv in run.get("levels", []) if isinstance(lv, str)] if isinstance(
        run.get("levels"), list
    ) else []
    # error/interrupted/... son claves del summary de la corrida (no son niveles) cuando no son objetos.
    levels = list(dict.fromkeys(requested)) + sorted(
        lv for lv in summary
        if isinstance(lv, str) and lv not in requested
        and not (lv in RUN_SUMMARY_KEYS and not isinstance(summary[lv], dict))
    )
    interrupted = summary.get("interrupted") is True
    status = run.get("status")
    anomalies: list[dict[str, str]] = []
    observations: list[dict[str, Any]] = []
    run_id = run["id"]

    for idx, receipt in enumerate(receipts):
        if isinstance(receipt, dict) and receipt.get("run_id") not in (None, run_id):
            anomalies.append(
                {"file": display, "pointer": _pointer("run", "receipts", idx, "run_id"),
                 "code": "receipt_run_id_mismatch"}
            )

    for level in levels:
        base = _pointer("run", "summary", level)
        entry = summary.get(level) if isinstance(summary.get(level), dict) else None
        if level not in requested:
            anomalies.append({"file": display, "pointer": base, "code": "summary_level_not_requested"})
        if entry is None:
            verdict = "missing"
        elif entry.get("outcome") in OUTCOMES:
            verdict = entry["outcome"]
        else:
            verdict = "invalid"
        if verdict == "blocked":
            evidence = entry.get("evidence") if entry else None
            if not (isinstance(evidence, str) and evidence.strip()):
                anomalies.append(
                    {"file": display, "pointer": base + _pointer("evidence"),
                     "code": "blocked_without_evidence"}
                )

        idxs = [i for i, r in enumerate(receipts) if isinstance(r, dict) and r.get("level") == level]
        if interrupted and verdict in ("missing", "not_run") and idxs:
            # Corrida interrumpida: hay intentos pero ningun veredicto; no es un nivel "no ejecutado".
            anomalies.append({"file": display, "pointer": base, "code": "interrupted_level_without_verdict"})
        durations = [_num(receipts[i].get("duration_ms")) for i in idxs]
        known = [d for d in durations if d is not None]
        complete = bool(idxs) and len(known) == len(idxs)
        receipt_outcomes = _count([receipts[i].get("outcome") for i in idxs], VERDICT_KEYS[:5] + ("invalid",))

        memory_peak = _measurement(entry, "memory_peak_bytes", base)
        memory_observed = _measurement(entry, "memory_observed_max_bytes", base)
        for field, mem in (("memory_peak_bytes", memory_peak), ("memory_observed_max_bytes", memory_observed)):
            if mem["null_reason"] == "measurement_unavailable":
                anomalies.append(
                    {"file": display, "pointer": base + _pointer(field),
                     "code": "memory_value_with_unavailable_measurement"}
                )

        observations.append(
            {
                "level": level,
                "file": display,
                "run_id": run_id,
                "run_status": status if isinstance(status, str) else None,
                "verdict": verdict,
                "verdict_pointer": base + _pointer("outcome") if entry is not None else None,
                "tool_time": {
                    "value_ms": sum(known) if complete else None,
                    "receipts": len(idxs),
                    "receipts_with_duration": len(known),
                    "pointers": [_pointer("run", "receipts", i, "duration_ms") for i in idxs],
                },
                "memory_peak": memory_peak,
                "memory_observed_max": memory_observed,
                "receipt_outcomes": receipt_outcomes,
                "oom_killed": _tri(entry.get("oom_killed")) if entry else "null",
                "cleanup_confirmed": _tri(entry.get("cleanup_confirmed")) if entry else "null",
            }
        )
    return observations, anomalies


# -------------------------------------------------------------- agregacion


def _aggregate_memory(obs: list[dict[str, Any]], field: str) -> dict[str, Any]:
    n_null = 0
    by: dict[tuple[str | None, str | None, str | None], list[int | float]] = {}
    for o in obs:
        mem = o[field]
        if mem["value"] is None:
            n_null += 1
            continue
        m = mem["measurement"]
        key = (m["source"], m["scope"], m["kind"])
        by.setdefault(key, []).append(mem["value"])
    items = []
    for key in sorted(by, key=lambda t: tuple("" if x is None else x for x in t)):
        items.append(
            {
                "source": key[0],
                "scope": key[1],
                "kind": key[2],
                "n": len(by[key]),
                **_stats(by[key]),
            }
        )
    return {"n_null": n_null, "by_measurement": items}


def build_cell(model: str, level: str, obs: list[dict[str, Any]]) -> dict[str, Any]:
    verdicts = {k: 0 for k in VERDICT_KEYS}
    for o in obs:
        verdicts[o["verdict"]] += 1
    statuses: dict[str, int] = {}
    for o in obs:
        key = o["run_status"] if o["run_status"] is not None else "null"
        statuses[key] = statuses.get(key, 0) + 1
    receipt_outcomes = {k: 0 for k in VERDICT_KEYS[:5] + ("invalid",)}
    for o in obs:
        for k, v in o["receipt_outcomes"].items():
            receipt_outcomes[k] += v
    times = [o["tool_time"]["value_ms"] for o in obs if o["tool_time"]["value_ms"] is not None]
    return {
        "level": level,
        "runs": len(obs),
        "verdicts": verdicts,
        "run_status": dict(sorted(statuses.items())),
        "receipt_outcomes_step_level": receipt_outcomes,
        "tool_time_ms": {
            "n_complete": len(times),
            "n_null": len(obs) - len(times),
            **_stats(times),
        },
        "memory_peak_bytes": _aggregate_memory(obs, "memory_peak"),
        "memory_observed_max_bytes": _aggregate_memory(obs, "memory_observed_max"),
        "oom_killed": {k: sum(1 for o in obs if o["oom_killed"] == k) for k in ("true", "false", "null")},
        "cleanup_confirmed": {k: sum(1 for o in obs if o["cleanup_confirmed"] == k) for k in ("true", "false", "null")},
        "sources": [
            {k: v for k, v in o.items() if k not in ("level", "receipt_outcomes")}
            for o in sorted(obs, key=lambda x: (x["file"], x["run_id"]))
        ],
    }


def _level_sort_key(level: str) -> tuple[int, str]:
    return (LEVEL_ORDER.index(level), level) if level in LEVEL_ORDER else (len(LEVEL_ORDER), level)


def aggregate(
    real_paths: list[Path], fixture_paths: list[Path], strict_hash: bool = False
) -> dict[str, Any]:
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, str]] = []
    seen_runs: set[tuple[str, str]] = set()
    seen_files: dict[str, str] = {}
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}

    for kind, paths in (("real", real_paths), ("fixture", fixture_paths)):
        for path in paths:
            display = _display(path)
            try:
                doc, file_sha = load_report(path)
                run = validate_report(doc)
                has_marker = FIXTURE_MARKER in doc
                if kind == "real" and has_marker:
                    raise InputError("fixture_marker_in_real", "declarado real pero marcado sintetico")
                if kind == "fixture" and doc.get(FIXTURE_MARKER) is not True:
                    raise InputError("missing_fixture_marker", f"fixture sin '{FIXTURE_MARKER}': true")
                if file_sha in seen_files:
                    raise InputError("duplicate_file", f"mismo contenido ya leido como {seen_files[file_sha]}")
                if (kind, run["id"]) in seen_runs:
                    raise InputError("duplicate_run_id", run["id"])
                hash_check = check_report_hash(doc)
                if strict_hash and kind == "real" and hash_check["status"] != "verified":
                    raise InputError("hash_not_verified", hash_check["status"])
                profile_id, profile = compute_profile(doc)
                effective = effective_profile(doc)
                comparison, comparison_anomalies = declared_vs_effective(doc)
                fresh_comparison, fresh_anomalies = declared_vs_effective(doc, "effective_sandbox_fresh")
                protocol = protocol_info(doc)
                observations, anomalies = extract_observations(run, display)
                usage_entry, usage_anomalies = extract_usage(doc, display, run["id"], run["model"])
            except InputError as exc:
                rejected.append({"file": display, "declared_as": kind, "reason": exc.code, "detail": exc.detail})
                continue
            seen_files[file_sha] = kind
            seen_runs.add((kind, run["id"]))
            # Perfil desconocido (declarado ausente o efectivo no disponible): nunca comparable.
            comparable = profile is not None and effective["status"] != "unknown" and protocol["status"] != "invalid"
            run_key = "" if comparable else run["id"]
            accepted.append(
                {
                    "file": display,
                    "evidence_kind": kind,
                    "file_sha256": file_sha,
                    "run_id": run["id"],
                    "model": run["model"],
                    "profile_id": profile_id,
                    "profile_comparable": comparable,
                    "effective_profile_status": effective["status"],
                    "declared_vs_effective": comparison,
                    "declared_vs_effective_fresh": fresh_comparison,
                    "protocol_status": protocol["status"],
                    "usage_status": usage_entry["status"],
                    "report_sha256_declared": hash_check["declared"],
                    "hash_check": {"status": hash_check["status"], "method": hash_check["method"]},
                }
            )
            group = groups.setdefault(
                (kind, profile_id, run_key),
                {"evidence_kind": kind, "profile_id": profile_id, "profile": profile,
                 "comparable": comparable, "run_key": run_key or None,
                 "effective_status": effective["status"], "protocol_status": protocol["status"],
                 "hash_checks": {},
                 "runs": [], "obs": [], "anomalies": [], "usage": []},
            )
            group["hash_checks"][hash_check["status"]] = group["hash_checks"].get(hash_check["status"], 0) + 1
            group["runs"].append({"model": run["model"], "status": run.get("status")})
            for o in observations:
                o["model"] = run["model"]
            group["obs"].extend(observations)
            group["anomalies"].extend(anomalies)
            group["anomalies"].extend({"file": display, **a}
                                      for a in effective["anomalies"] + comparison_anomalies + fresh_anomalies)
            if protocol["status"] == "invalid":
                group["anomalies"].append({"file": display, "pointer": "/experiment/protocol", "code": "protocol_invalid"})
            group["anomalies"].extend(usage_anomalies)
            if profile is None:
                group["anomalies"].append({"file": display, "pointer": "/experiment", "code": "declared_profile_missing"})
            group["usage"].append(usage_entry)

    out_groups = []
    for (kind, profile_id, run_key) in sorted(groups, key=lambda k: (0 if k[0] == "real" else 1, k[1], k[2])):
        g = groups[(kind, profile_id, run_key)]
        models = []
        for model in sorted({r["model"] for r in g["runs"]}):
            model_runs = [r for r in g["runs"] if r["model"] == model]
            statuses: dict[str, int] = {}
            for r in model_runs:
                key = r["status"] if isinstance(r["status"], str) else "null"
                statuses[key] = statuses.get(key, 0) + 1
            model_obs = [o for o in g["obs"] if o["model"] == model]
            cells = [
                build_cell(model, level, [o for o in model_obs if o["level"] == level])
                for level in sorted({o["level"] for o in model_obs}, key=_level_sort_key)
            ]
            models.append({"model": model, "runs": len(model_runs),
                           "run_status": dict(sorted(statuses.items())), "levels": cells})
        out_groups.append(
            {
                "evidence_kind": kind,
                "is_synthetic_fixture": kind == "fixture",
                "profile_id": profile_id,
                "profile": g["profile"],
                "comparable": g["comparable"],
                "run_key": g["run_key"],
                "effective_profile_status": g["effective_status"],
                "protocol_status": g["protocol_status"],
                "hash_checks": dict(sorted(g["hash_checks"].items())),
                "runs": len(g["runs"]),
                "models": models,
                "usage": build_usage_block(g["usage"]),
                "anomalies": sorted(g["anomalies"], key=lambda a: (a["file"], a["pointer"], a["code"])),
            }
        )

    accepted.sort(key=lambda a: (0 if a["evidence_kind"] == "real" else 1, a["file"]))
    rejected.sort(key=lambda r: (r["declared_as"], r["file"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "aggregator_version": AGGREGATOR_VERSION,
        "notice": NOTICE,
        "limits": LIMITS,
        "strict_hash": strict_hash,
        "inputs": {"accepted": accepted, "rejected": rejected},
        "groups": out_groups,
    }


# ---------------------------------------------------------------- Markdown

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>()#+!|~&])")


def md(value: Any) -> str:
    """Escapa texto para una celda Markdown; nunca produce HTML ni saltos."""
    text = "null" if value is None else str(value)
    text = "".join(" " if (ord(c) < 32 or ord(c) == 127) else c for c in text)
    return _MD_SPECIAL.sub(r"\\\1", text)


def _fmt_stats(s: dict[str, Any]) -> str:
    return f"min={md(s['min'])}, med={md(s['median'])}, max={md(s['max'])}"


def _fmt_time(t: dict[str, Any]) -> str:
    return f"completos={t['n_complete']}, null={t['n_null']}; {_fmt_stats(t)}"


def _fmt_memory(m: dict[str, Any]) -> str:
    parts = [
        f"{md(i['source'])}/{md(i['scope'])}/{md(i['kind'])}: n={i['n']}, {_fmt_stats(i)}"
        for i in m["by_measurement"]
    ]
    parts.append(f"null={m['n_null']}")
    return "; ".join(parts)


def render_markdown(result: dict[str, Any]) -> str:
    lines: list[str] = ["# Agregado offline de reportes Agent Backrooms", "", md(result["notice"]), ""]
    lines += [f"Agregador {md(result['aggregator_version'])}, esquema {result['schema_version']}, "
              f"hash estricto: {'si' if result['strict_hash'] else 'no'}.", ""]

    lines += ["## Entradas aceptadas", ""]
    acc = result["inputs"]["accepted"]
    if acc:
        lines += ["| Archivo | Tipo | SHA-256 del archivo | Corrida | Modelo | Perfil | Perfil efectivo | Comparable | Hash declarado | Verificacion |",
                  "|---|---|---|---|---|---|---|---|---|---|"]
        for a in acc:
            lines.append("| " + " | ".join(md(x) for x in (
                a["file"], a["evidence_kind"], a["file_sha256"], a["run_id"], a["model"],
                a["profile_id"], a["effective_profile_status"], "si" if a["profile_comparable"] else "no",
                a["report_sha256_declared"],
                a["hash_check"]["status"] + (f" ({a['hash_check']['method']})" if a["hash_check"]["method"] else ""),
            )) + " |")
    else:
        lines.append("Ninguna.")
    lines += ["", "## Entradas rechazadas", ""]
    rej = result["inputs"]["rejected"]
    if rej:
        lines += ["| Archivo | Declarado como | Motivo | Detalle |", "|---|---|---|---|"]
        for r in rej:
            lines.append("| " + " | ".join(md(x) for x in (r["file"], r["declared_as"], r["reason"], r["detail"])) + " |")
    else:
        lines.append("Ninguna.")
    lines.append("")

    for g in result["groups"]:
        # "Real" es la declaracion --real del operador, no una autenticacion; el hash se informa aparte.
        hashes = ", ".join(f"{k}={v}" for k, v in g["hash_checks"].items())
        title = ("FIXTURE SINTETICO - NO ES EVIDENCIA" if g["is_synthetic_fixture"]
                 else f"EVIDENCIA REAL DECLARADA (--real; hash: {hashes or 'sin dato'})")
        suffix = "" if g["comparable"] else f" - NO COMPARABLE, corrida {md(g['run_key'])}"
        lines += [f"## {title} - perfil {md(g['profile_id'])}{suffix}", ""]
        if g["is_synthetic_fixture"]:
            lines += ["Datos sinteticos para pruebas; no representan ninguna corrida real.", ""]
        profile = canonical(g["profile"]) if g["profile"] is not None else "null (perfil incompleto o ausente)"
        lines += [f"Perfil: `{profile.replace('`', ' ')}`", "",
                  f"Perfil efectivo observado: {md(g['effective_profile_status'])}. "
                  f"Comparable con otras corridas: {'si' if g['comparable'] else 'no'}"
                  f"{'' if g['comparable'] else ' (' + md(UNKNOWN_PROFILE_NOTE) + ')'}.",
                  ""]
        if g["protocol_status"] == "recorded":
            lines += ["Protocolo congelado: registrado (forma parte completa del perfil).", ""]
        else:
            lines += [f"Protocolo congelado: {md(g['protocol_status'])}; no se afirma comparabilidad de protocolo "
                      "con corridas que si lo registran.", ""]
        lines += [f"Corridas en el grupo: {g['runs']}.", ""]
        usage = g["usage"]
        lines += ["### Uso de inferencia por corrida (descriptivo, estimado)", "",
                  "| Archivo | Corrida | Modelo | Estado | Medicion | Llamadas | Conocidas | Sin dato | Parciales | Entrada | Salida | Total | Cota inferior | Costo USD estimado | Costo cota inferior/parcial | Estado costo |",
                  "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for u in usage["per_run"]:
            cov = u["coverage"] or {}
            tk = u["tokens"]
            ms = u["measurement"] or {}
            lines.append("| " + " | ".join(md(x) for x in (
                u["file"], u["run_id"], u["model"], u["status"],
                ms.get("state") if ms else None, u["attempts_total"],
                cov.get("known_calls"), cov.get("unknown_calls"), cov.get("partial_calls"),
                tk["prompt_tokens"], tk["completion_tokens"], tk["total_tokens"], tk["lower_bound"],
                u["cost_usd_estimated"], u["cost_incomplete"], u["cost_status"],
            )) + " |")
        tot = usage["totals_lower_bound"]
        lines += ["", f"Totales conocidos (cota inferior={md(tot['lower_bound'])}): "
                      f"entrada={md(tot['prompt_tokens']['value'])}, salida={md(tot['completion_tokens']['value'])}, "
                      f"total={md(tot['total_tokens']['value'])}, costo estimado USD={md(tot['cost_usd_estimated']['value'])} "
                      f"(cota inferior del costo={md(tot['cost_usd_estimated']['lower_bound'])}). "
                      "null = desconocido, nunca 0; el uso es por corrida, no por nivel.", ""]
        levels = sorted({c["level"] for m in g["models"] for c in m["levels"]}, key=_level_sort_key)
        for level in levels:
            lines += [f"### Nivel {md(level)}", "",
                      "| Modelo | Corridas | blocked | escaped | exhausted | error | not_run | invalid | missing | Tiempo herramientas ms | Memoria pico bytes | Memoria max observada bytes |",
                      "|---|---|---|---|---|---|---|---|---|---|---|---|"]
            for m in g["models"]:
                for c in m["levels"]:
                    if c["level"] != level:
                        continue
                    v = c["verdicts"]
                    lines.append("| " + " | ".join([
                        md(m["model"]), str(c["runs"]),
                        *(str(v[k]) for k in VERDICT_KEYS),
                        _fmt_time(c["tool_time_ms"]),
                        _fmt_memory(c["memory_peak_bytes"]),
                        _fmt_memory(c["memory_observed_max_bytes"]),
                    ]) + " |")
            lines.append("")
        lines += ["### Fuentes", "",
                  "| Nivel | Modelo | Archivo | Corrida | Estado corrida | Veredicto | Puntero veredicto | Tiempo ms | Punteros tiempo | Memoria pico | Puntero memoria | Motivo null memoria |",
                  "|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for m in g["models"]:
            for c in m["levels"]:
                for s in c["sources"]:
                    lines.append("| " + " | ".join(md(x) for x in (
                        c["level"], m["model"], s["file"], s["run_id"], s["run_status"], s["verdict"],
                        s["verdict_pointer"], s["tool_time"]["value_ms"],
                        ", ".join(s["tool_time"]["pointers"]) or None,
                        s["memory_peak"]["value"], s["memory_peak"]["pointer"],
                        s["memory_peak"]["null_reason"],
                    )) + " |")
        lines.append("")
        if g["anomalies"]:
            lines += ["### Anomalias", "", "| Archivo | Puntero | Codigo |", "|---|---|---|"]
            for a in g["anomalies"]:
                lines.append("| " + " | ".join(md(x) for x in (a["file"], a["pointer"], a["code"])) + " |")
            lines.append("")

    lines += ["## Limites", "", md(result["limits"]), ""]
    return "\n".join(lines)


# --------------------------------------------------------------------- CLI


def _check_output(path: Path, inputs: set[Path], force: bool) -> Path:
    _guard_path(path)
    resolved = path.resolve()
    if resolved in inputs:
        raise InputError("output_is_input", "no se sobrescriben reportes de entrada")
    if "evidencia" in [p.lower() for p in resolved.parts]:
        raise InputError("output_in_evidence_dir", "no se escribe dentro de directorios de evidencia")
    if resolved.exists() and not force:
        raise InputError("output_exists", "use --force para reemplazar un archivo de salida propio")
    return resolved


def _write_stdout(text: str) -> None:
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is not None:
        buffer.write(text.encode("utf-8"))
        buffer.flush()
    else:
        sys.stdout.write(text)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Agrega offline reportes JSON existentes por modelo, nivel y perfil. Sin red.")
    p.add_argument("--real", nargs="+", action="extend", default=[], metavar="FILE",
                   help="reportes JSON declarados como evidencia real")
    p.add_argument("--fixture", nargs="+", action="extend", default=[], metavar="FILE",
                   help=f"reportes sinteticos; deben contener \"{FIXTURE_MARKER}\": true")
    p.add_argument("--format", choices=("json", "md"), default="json",
                   help="formato por stdout si no se indican --out-* (por defecto json)")
    p.add_argument("--out-json", metavar="PATH", help="escribe la salida JSON")
    p.add_argument("--out-md", metavar="PATH", help="escribe la salida Markdown")
    p.add_argument("--strict-hash", action="store_true",
                   help="rechaza reportes --real cuyo sha256 no se pueda reproducir "
                        "(los fixtures sinteticos no llevan hash y no se ven afectados)")
    p.add_argument("--allow-rejected", action="store_true",
                   help="exit 0 aunque haya entradas rechazadas (siempre se listan)")
    p.add_argument("--force", action="store_true", help="reemplaza archivos de salida existentes")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.real and not args.fixture:
        parser.error("indique al menos un archivo con --real o --fixture")
    for raw in [*args.real, *args.fixture, args.out_json or "", args.out_md or ""]:
        if "://" in raw:
            parser.error("solo rutas locales; este agregador no usa red")

    real = [Path(x) for x in args.real]
    fixture = [Path(x) for x in args.fixture]
    inputs: set[Path] = set()
    for p in real + fixture:
        try:
            inputs.add(p.resolve())
        except OSError:
            pass
    try:
        out_json = _check_output(Path(args.out_json), inputs, args.force) if args.out_json else None
        out_md = _check_output(Path(args.out_md), inputs, args.force) if args.out_md else None
        if out_json and out_md and out_json == out_md:
            raise InputError("output_collision", "--out-json y --out-md apuntan al mismo archivo")
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    result = aggregate(real, fixture, strict_hash=args.strict_hash)
    json_text = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    md_text = render_markdown(result) + "\n"

    if out_json or out_md:
        for target, text in ((out_json, json_text), (out_md, md_text)):
            if target is not None:
                target.parent.mkdir(parents=True, exist_ok=True)
                with open(target, "w", encoding="utf-8", newline="\n") as handle:
                    handle.write(text)
    else:
        _write_stdout(json_text if args.format == "json" else md_text)

    rejected = result["inputs"]["rejected"]
    accepted = result["inputs"]["accepted"]
    print(f"aceptados={len(accepted)} rechazados={len(rejected)}", file=sys.stderr)
    if not accepted:
        return 1
    if rejected and not args.allow_rejected:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

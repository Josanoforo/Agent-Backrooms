"""Per-run capture of provider usage, one record per real HTTP attempt.

Contract (additive; ``provider.complete`` keeps its signature and return value):

    with usage.collect(run_id="...", rate=None) as collector:
        ...  # every provider.complete() in this context is recorded
    summary = collector.summary()   # JSON-serializable, safe after the block

* A collector lives in a ContextVar: asyncio tasks created inside the block share
  it (context is copied), unrelated tasks/runs never see it. Nested blocks shadow
  the outer collector and restore it on exit.
* Attempts are registered after reservation, at local dispatch. Rejections before
  dispatch are counted separately and are never consumption. D4 and D5 attempts retain
  the variant, resolved parameters and exact tariff applied at that boundary.
* Unknown is never zero: a missing, invalid, timed-out or cancelled response
  leaves its token fields ``None`` and lowers coverage. Totals are lower bounds
  whenever coverage is incomplete.
* ``reasoning_tokens`` is reported as a detail *included in* ``completion_tokens``
  and ``cached_tokens`` *included in* ``prompt_tokens``; they are never added again.
* USD is ``None`` unless an explicit dated :class:`Rate` is supplied; it is always
  labelled an estimate, never a bill. The monthly/model ``GET /v1/usage`` endpoint
  is not used and cannot be attributed to a run.
* Never stored: prompts, messages, tool arguments, keys, reasoning text, error
  bodies or exception messages. Recording never raises into the caller.
"""
import threading
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation

SCHEMA = "usage-summary/v1"
MAX_TOKEN_COUNT = 2 ** 53 - 1
MAX_TEXT = 128
REJECTION_REASONS = ("not_configured", "input_limit", "budget")
_D4_FINISH_REASONS = ('stop', 'length', 'tool_calls', 'function_call', 'content_filter')

_CURRENT = ContextVar("agent_usage_collector", default=None)


def _clean(value):
    """Short printable string or None; used for model names and response ids."""
    if isinstance(value, str) and 0 < len(value) <= MAX_TEXT and value.isprintable():
        return value
    return None


def _count(value):
    """Valid token count: real int (not bool), >= 0, JSON-safe."""
    if type(value) is int and 0 <= value <= MAX_TOKEN_COUNT:
        return value
    return None


def d4_finish_reason(body):
    """Allowlisted finish reason for the same first choice used by the adapter."""
    try:
        value = body['choices'][0]['finish_reason']
    except (IndexError, KeyError, TypeError):
        return None
    return value if type(value) is str and value in _D4_FINISH_REASONS else None


def _positive_decimal(value):
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        raise ValueError("rate must be a positive number")
    try:
        number = Decimal(str(value)) if not isinstance(value, Decimal) else value
    except InvalidOperation as exc:
        raise ValueError("rate must be a positive number") from exc
    if not number.is_finite() or number <= 0:
        raise ValueError("rate must be a positive number")
    return number


class Rate:
    """Explicit, dated price: USD per million input/output tokens for one model."""

    def __init__(self, model, input_per_million, output_per_million, effective_date, currency="USD", source=None):
        self.model = _clean(model)
        if self.model is None:
            raise ValueError("rate model is required")
        if not isinstance(currency, str) or currency.upper() != "USD":
            raise ValueError("only USD rates are supported")
        self.currency = "USD"
        self.input_per_million = _positive_decimal(input_per_million)
        self.output_per_million = _positive_decimal(output_per_million)
        if isinstance(effective_date, datetime):
            raise ValueError("effective_date must be a date")
        if isinstance(effective_date, str):
            try:
                effective_date = date.fromisoformat(effective_date)
            except ValueError as exc:
                raise ValueError("effective_date must be ISO YYYY-MM-DD") from exc
        if not isinstance(effective_date, date):
            raise ValueError("effective_date is required")
        self.effective_date = effective_date
        self.source = _clean(source)

    @classmethod
    def from_mapping(cls, mapping):
        if isinstance(mapping, cls):
            return mapping
        if not isinstance(mapping, dict):
            raise ValueError("rate must be a mapping")
        return cls(mapping.get("model"), mapping.get("input_per_million"), mapping.get("output_per_million"),
                   mapping.get("effective_date"), mapping.get("currency", "USD"), mapping.get("source"))

    def to_dict(self):
        return {"model": self.model, "currency": self.currency,
                "input_per_million": float(self.input_per_million),
                "output_per_million": float(self.output_per_million),
                "effective_date": self.effective_date.isoformat(), "source": self.source}

    def to_exact_dict(self):
        """Dated tariff evidence with bounded decimal strings and a source."""
        if not self.source or not self.source.strip():
            raise ValueError('rate source is required')
        exact = {}
        for field in ('input_per_million', 'output_per_million'):
            value = getattr(self, field)
            if not Decimal('0.000000000001') <= value < 1_000_000:
                raise ValueError('rate price is outside the supported range')
            price = format(value, 'f')
            if '.' in price:
                price = price.rstrip('0').rstrip('.')
            if len(price.partition('.')[2]) > 12:
                raise ValueError('rate price exceeds supported precision')
            exact[field] = price
        return {'model': self.model, 'currency': self.currency, 'effective_date': self.effective_date.isoformat(),
                'source': self.source, **exact}


def _detail(container, key, parent, issues, parent_name):
    """Read a nested *_tokens detail; it is part of its parent count, never extra."""
    if container is None:
        return None
    if not isinstance(container, dict):
        issues.append(parent_name + "_details_invalid")
        return None
    raw = container.get(key)
    if raw is None:
        return None
    value = _count(raw)
    if value is None:
        issues.append(key + "_invalid")
        return None
    if parent is not None and value > parent:
        issues.append(key + "_exceeds_" + parent_name)
        return None
    return value


def parse_usage(body):
    """Validate the ``usage`` object of a decoded response body; pure, no I/O."""
    out = {"usage_status": "unknown", "prompt_tokens": None, "completion_tokens": None,
           "total_tokens_reported": None, "reasoning_tokens": None, "cached_tokens": None, "usage_issues": []}
    if not isinstance(body, dict):
        return out
    raw = body.get("usage")
    if raw is None or raw == {}:
        out["usage_status"] = "absent"
        return out
    issues = out["usage_issues"]
    if not isinstance(raw, dict):
        out["usage_status"] = "invalid"
        issues.append("usage_not_object")
        return out
    prompt = _count(raw.get("prompt_tokens"))
    completion = _count(raw.get("completion_tokens"))
    for name, value in (("prompt_tokens", prompt), ("completion_tokens", completion)):
        if value is None:
            issues.append(name + ("_missing" if raw.get(name) is None else "_invalid"))
    out["prompt_tokens"], out["completion_tokens"] = prompt, completion
    out["total_tokens_reported"] = _count(raw.get("total_tokens"))
    if prompt is not None and completion is not None and out["total_tokens_reported"] not in (None, prompt + completion):
        issues.append("total_tokens_mismatch")
    out["reasoning_tokens"] = _detail(raw.get("completion_tokens_details"), "reasoning_tokens", completion, issues, "completion")
    out["cached_tokens"] = _detail(raw.get("prompt_tokens_details"), "cached_tokens", prompt, issues, "prompt")
    if prompt is not None and completion is not None:
        out["usage_status"] = "reported"
    elif prompt is not None or completion is not None:
        out["usage_status"] = "partial"
    else:
        out["usage_status"] = "invalid"
    return out


_UNKNOWN_USAGE = {"usage_status": "unknown", "prompt_tokens": None, "completion_tokens": None,
                  "total_tokens_reported": None, "reasoning_tokens": None, "cached_tokens": None, "usage_issues": []}


class Attempt:
    """One real HTTP request to the provider. Methods never raise; first close wins."""

    def __init__(self, seq, requested_model, *, d4=None, d5=None):
        self.attempt_id = "att_" + uuid.uuid4().hex
        self.seq = seq
        self.requested_model = _clean(requested_model)
        self.returned_model = None
        self.response_id = None
        self.status = "in_flight"
        self.http_status = None
        self.error_type = None
        self.started_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        self.duration_ms = None
        self.fields = dict(_UNKNOWN_USAGE, usage_issues=[])
        self._d4 = d4
        self._binding = d4 if d4 is not None else d5
        self._finish_reason = None
        self._generation = None
        self._t0 = time.monotonic()
        self._lock = threading.Lock()
        self._closed = False

    def _close(self, status, http_status=None, error_type=None, body=None):
        try:
            try:
                fields = parse_usage(body) if body is not None else dict(_UNKNOWN_USAGE, usage_issues=[])
                returned = _clean(body.get("model")) if isinstance(body, dict) else None
                response_id = _clean(body.get("id")) if isinstance(body, dict) else None
            except Exception:
                fields, returned, response_id = dict(_UNKNOWN_USAGE, usage_issues=["usage_parse_error"]), None, None
            with self._lock:
                if self._closed:
                    return
                self._closed = True
                self.status = status
                self.http_status = http_status if type(http_status) is int else None
                self.error_type = error_type if isinstance(error_type, str) and error_type.isidentifier() else None
                self.fields, self.returned_model, self.response_id = fields, returned, response_id
                self._finish_reason = d4_finish_reason(body)
                self.duration_ms = int((time.monotonic() - self._t0) * 1000)
        except Exception:
            pass

    def record_response(self, http_status, body, status="completed"):
        """2xx answer: ``body`` is the decoded JSON (or None if it did not decode)."""
        self._close(status, http_status=http_status, body=body)

    def record_http_error(self, http_status):
        """Non-2xx answer; the body is never read or stored."""
        self._close("http_error", http_status=http_status)

    def fail(self, status, exc=None):
        """No usable answer (timeout, network_error, malformed_response, ...)."""
        self._close(status, error_type=type(exc).__name__ if exc is not None else None)

    def abandon(self):
        """Safety net for cancellation/unexpected exit: closes an open attempt as cancelled."""
        self._close("cancelled")

    def record_generation(self, parameters):
        """Content-free effective dispatch metadata; never request or response text."""
        with self._lock:
            if not self._closed:
                self._generation = dict(parameters)

    def to_dict(self):
        with self._lock:
            f = self.fields
            record = {"attempt_id": self.attempt_id, "seq": self.seq,
                    "requested_model": self.requested_model, "returned_model": self.returned_model,
                    "response_id": self.response_id, "status": self.status, "http_status": self.http_status,
                    "error_type": self.error_type, "started_at": self.started_at, "duration_ms": self.duration_ms,
                    "usage_status": f["usage_status"], "prompt_tokens": f["prompt_tokens"],
                    "completion_tokens": f["completion_tokens"], "total_tokens_reported": f["total_tokens_reported"],
                    "reasoning_tokens": f["reasoning_tokens"], "cached_tokens": f["cached_tokens"],
                    "usage_issues": list(f["usage_issues"])}
            if self._binding is not None:
                record.update(self._binding, rate=dict(self._binding['rate']),
                              parameters=dict(self._binding['parameters']))
            record['finish_reason'] = self._finish_reason
            record['generation'] = dict(self._generation) if self._generation is not None else None
            return record


class _NullAttempt:
    def record_generation(self, *a, **k): pass
    def record_response(self, *a, **k): pass
    def record_http_error(self, *a, **k): pass
    def fail(self, *a, **k): pass
    def abandon(self, *a, **k): pass


NULL_ATTEMPT = _NullAttempt()


def _total(values, attempts):
    if attempts == 0:
        return 0
    return sum(values) if values else None


class UsageCollector:
    def __init__(self, run_id=None, rate=None):
        self.run_id = _clean(run_id)
        self.rate, self.rate_error = None, False
        if rate is not None:
            try:
                self.rate = Rate.from_mapping(rate)
            except (ValueError, TypeError):
                self.rate_error = True
        self._lock = threading.Lock()
        self._attempts = []
        self._rejections = {}

    def begin_attempt(self, requested_model, *, d4=None, d5=None):
        try:
            with self._lock:
                attempt = Attempt(len(self._attempts) + 1, requested_model, d4=d4, d5=d5)
                self._attempts.append(attempt)
            return attempt
        except Exception:
            return NULL_ATTEMPT

    def begin_d4_attempt(self, context, variant):
        return self.begin_attempt(context.model_id, d4={
            'run_id': context.run_id, 'level': 'workflow', 'variant': variant,
            'parameters': {'max_tokens': context.max_output_tokens, 'reasoning_effort': context.reasoning_effort},
            'rate': context.rate,
        })

    def begin_d5_attempt(self, context, variant):
        return self.begin_attempt(context.model_id, d5={
            'configuration_id': context.configuration_id, 'run_id': context.run_id,
            'level': 'workflow', 'variant': variant,
            'parameters': {'max_tokens': context.max_output_tokens, 'reasoning_effort': context.reasoning_effort},
            'rate': context.rate,
        })

    def discard_before_dispatch(self, attempt):
        """Undo registration of the most recent attempt when dispatch was vetoed synchronously."""
        with self._lock:
            if self._attempts and self._attempts[-1] is attempt:
                self._attempts.pop()

    def note_rejection(self, reason):
        try:
            reason = reason if reason in REJECTION_REASONS else "other"
            with self._lock:
                self._rejections[reason] = self._rejections.get(reason, 0) + 1
        except Exception:
            pass

    def attempts(self):
        with self._lock:
            items = list(self._attempts)
        return [a.to_dict() for a in items]

    def summary(self):
        attempts = self.attempts()
        with self._lock:
            rejections = dict(self._rejections)
        n = len(attempts)
        complete = [a for a in attempts if a["prompt_tokens"] is not None and a["completion_tokens"] is not None]
        partial = [a for a in attempts if (a["prompt_tokens"] is None) != (a["completion_tokens"] is None)]
        unknown = n - len(complete)
        cost = self._cost(attempts, complete, n)

        def known(field):
            return [a[field] for a in attempts if a[field] is not None]

        prompts, completions = known("prompt_tokens"), known("completion_tokens")
        reasoning, cached = known("reasoning_tokens"), known("cached_tokens")
        tokens = {
            "prompt_tokens": _total(prompts, n), "prompt_known_attempts": len(prompts),
            "completion_tokens": _total(completions, n), "completion_known_attempts": len(completions),
            "total_tokens": _total([a["prompt_tokens"] + a["completion_tokens"] for a in complete], n),
            "total_known_attempts": len(complete),
            "reasoning_tokens_included_in_completion": _total(reasoning, n), "reasoning_known_attempts": len(reasoning),
            "cached_tokens_included_in_prompt": _total(cached, n), "cached_known_attempts": len(cached),
            "lower_bound": unknown > 0,
        }
        return {
            "schema": SCHEMA, "run_id": self.run_id, "source": "provider_response_usage",
            "attempts_total": n,
            "coverage": {"known_calls": len(complete), "unknown_calls": unknown, "partial_calls": len(partial),
                         "ratio": (len(complete) / n) if n else None, "complete": unknown == 0},
            "tokens": tokens,
            "cost_usd": cost["usd"], "cost": cost,
            "rejected_before_network": {"count": sum(rejections.values()), "by_reason": rejections,
                                         "counted_as_consumption": False},
            "attempts": attempts,
            "notes": ["Unknown usage is null, never zero; totals are lower bounds when coverage is incomplete.",
                      "reasoning_tokens are included in completion_tokens and cached_tokens in prompt_tokens; not added again.",
                      "Per-attempt response usage only; monthly GET /v1/usage cannot be attributed to this run."],
        }

    def _cost(self, attempts, complete, n):
        base = {"usd": None, "estimate": True, "status": "not_estimated", "partial": None, "lower_bound": None,
                "priced_attempts": 0, "unpriced_attempts": n, "rate": None}
        if self.rate_error:
            base["status"] = "rate_invalid"
            return base
        if self.rate is None:
            return base
        rate = self.rate
        priced = []
        for attempt in complete:
            model = attempt['returned_model']
            if 'rate' in attempt:
                applied = Rate.from_mapping(attempt['rate'])
            else:
                applied = rate
                model = model or attempt['requested_model']
            if model == applied.model:
                priced.append((attempt, applied))
        unpriced = n - len(priced)
        base.update(rate=rate.to_dict(), priced_attempts=len(priced), unpriced_attempts=unpriced,
                    partial=unpriced > 0, lower_bound=unpriced > 0,
                    basis="prompt_tokens*input + completion_tokens*output; cached priced as input; reasoning not added")
        if n == 0:
            base.update(usd=0.0, status="estimated_complete")
        elif not priced:
            base["status"] = "no_priced_attempts"
        else:
            total = sum(Decimal(a['prompt_tokens']) * applied.input_per_million
                        + Decimal(a['completion_tokens']) * applied.output_per_million
                        for a, applied in priced) / Decimal(1000000)
            base["usd"] = float(total.quantize(Decimal("0.00000001")))
            base["status"] = "estimated_partial" if unpriced else "estimated_complete"
        return base


def current():
    return _CURRENT.get()


def require_d4_collector(context):
    """Bind D4 dispatch to the collector for the exact run and sealed tariff."""
    collector = current()
    expected = Rate.from_mapping(context.rate)
    if (collector is None or collector.run_id != context.run_id or collector.rate is None
            or vars(collector.rate) != vars(expected)):
        raise ValueError('D4 usage collector does not match the run and tariff')
    return collector


def require_d5_collector(context):
    """Bind D5 dispatch to the same run and exact tariff frozen at admission."""
    collector = current()
    if (collector is None or collector.run_id != context.run_id or collector.rate is None
            or collector.rate.to_exact_dict() != context.rate):
        raise ValueError('D5 usage collector does not match the run and tariff')
    return collector


@contextmanager
def collect(run_id=None, rate=None):
    """Install a fresh collector for this context; restores the previous one on exit."""
    collector = UsageCollector(run_id, rate)
    previous = _CURRENT.get()
    token = _CURRENT.set(collector)
    try:
        yield collector
    finally:
        try:
            _CURRENT.reset(token)
        except (ValueError, RuntimeError):
            _CURRENT.set(previous)


def begin_attempt(requested_model):
    collector = _CURRENT.get()
    return collector.begin_attempt(requested_model) if collector is not None else NULL_ATTEMPT


def discard_before_dispatch(attempt):
    collector = _CURRENT.get()
    if collector is not None:
        collector.discard_before_dispatch(attempt)


def note_rejection(reason):
    collector = _CURRENT.get()
    if collector is not None:
        collector.note_rejection(reason)


def current_summary():
    collector = _CURRENT.get()
    return collector.summary() if collector is not None else None

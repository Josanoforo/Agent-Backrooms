"""Opt-in, task-local D4 workflow settings from a sealed campaign manifest."""

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import inspect
import re
from typing import Callable

from . import d4_manifest


_CURRENT = ContextVar('d4_run_context', default=None)
_VARIANT = ContextVar('d4_workflow_variant', default=None)
AUTHORIZED_DAY_ENV = 'ESCAPE_D4_AUTHORIZED_DAY_UTC'


@dataclass(frozen=True, slots=True)
class RunContext:
    campaign_id: str
    specification_sha256: str
    model_id: str
    run_id: str
    image_digest: str
    profile_sha256: str
    reasoning_effort: str | None
    calls_per_variant: int
    max_calls: int
    max_output_tokens: int
    max_request_bytes: int
    max_input_chars: int
    timeout_seconds_per_variant: int
    _rate_items: tuple[tuple[str, str], ...] = field(repr=False)
    reserve: Callable[['RunContext', str, int], None] = field(repr=False, compare=False)

    @property
    def rate(self):
        """Detached, exact tariff mapping accepted by ``usage.collect``."""
        return dict(self._rate_items)

    def reserve_dispatch(self, variant, request_bytes):
        result = self.reserve(self, variant, request_bytes)
        if result is not None:
            if inspect.iscoroutine(result):
                result.close()
            raise ValueError('D4 dispatch reservation must complete synchronously')


def build_context(manifest, model_id, run_id, reserve):
    """Bind ``reserve(context, variant, request_bytes)``; it returns None or raises ValueError."""
    verified = d4_manifest.validate_manifest(manifest)
    spec = verified['specification']
    if type(model_id) is not str or model_id not in spec['models']:
        raise ValueError('D4 model is not declared in the campaign')
    if type(run_id) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', run_id):
        raise ValueError('D4 run id is invalid')
    if (not callable(reserve) or inspect.iscoroutinefunction(reserve)
            or inspect.iscoroutinefunction(getattr(reserve, '__call__', None))):
        raise ValueError('D4 requires a synchronous dispatch reservation')
    catalog = spec['catalog']
    rate = {**catalog['models'][model_id]['rate'], 'source': catalog['source']}
    return RunContext(
        campaign_id=verified['campaign_id'], specification_sha256=verified['specification_sha256'],
        model_id=model_id, run_id=run_id, image_digest=spec['image_digest'], profile_sha256=spec['profile_sha256'],
        reasoning_effort=spec['parameters'][model_id]['reasoning_effort'],
        _rate_items=tuple(rate.items()), reserve=reserve, **spec['limits'],
    )


def current():
    return _CURRENT.get()


def current_variant():
    return _VARIANT.get()


@contextmanager
def use_context(context):
    """Install a run context without inheriting a variant from a different run."""
    if type(context) is not RunContext:
        raise ValueError('D4 run context is invalid')
    context_token = _CURRENT.set(context)
    variant_token = _VARIANT.set(None)
    try:
        yield context
    finally:
        _VARIANT.reset(variant_token)
        _CURRENT.reset(context_token)


@contextmanager
def use_variant(name):
    """Identify the current workflow variant for provider dispatch and usage."""
    if type(name) is not str or name not in d4_manifest.VARIANTS:
        raise ValueError('D4 workflow variant is invalid')
    token = _VARIANT.set(name)
    try:
        yield name
    finally:
        _VARIANT.reset(token)

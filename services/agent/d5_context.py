"""Task-local execution settings from a sealed D5 configuration."""

import re
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace

from . import missions, usage


_CURRENT = ContextVar('d5_run_context', default=None)
_VARIANT = ContextVar('d5_workflow_variant', default=None)


class ContextError(ValueError):
    """The live executor cannot honor the bound D5 configuration."""


@dataclass(frozen=True, slots=True)
class RunContext:
    configuration_id: str
    run_id: str
    model_id: str
    mission_id: str
    tool_policy: str
    reasoning_effort: str | None
    max_input_chars: int
    max_output_tokens: int
    calls_per_variant: int
    timeout_seconds_per_variant: int
    authorized_day_utc: str | None = None
    _rate_items: tuple[tuple[str, str], ...] = field(default=(), repr=False)

    @property
    def rate(self):
        """Return a detached exact tariff once admission has bound it."""
        return dict(self._rate_items) if self._rate_items else None


def build_context(configuration, run_id, *, allowed_models, server_limits=None):
    """Revalidate the configuration against admission policy and bind a run ID."""
    from . import d5_configuration  # Its schema depends on provider and workflow defaults.

    if type(run_id) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', run_id):
        raise ContextError('D5 run id is invalid')
    verified = d5_configuration.validate_configuration(
        configuration, allowed_models=allowed_models, server_limits=server_limits,
    )
    spec = verified['specification']
    return RunContext(
        configuration_id=verified['configuration_id'], run_id=run_id,
        model_id=spec['model_id'], mission_id=spec['mission_id'], tool_policy=spec['tool_policy'],
        reasoning_effort=spec['parameters']['reasoning_effort'], **spec['limits'],
    )


def bind_rate(context, tariff, *, authorized_day_utc=None):
    """Freeze the admitted tariff separately from the configuration identity."""
    try:
        rate = usage.Rate.from_mapping(tariff).to_exact_dict()
    except (TypeError, ValueError):
        raise ContextError('D5 tariff is invalid') from None
    if (rate['model'] != context.model_id or (context.rate is not None and context.rate != rate)
            or (authorized_day_utc is not None and rate['effective_date'] != authorized_day_utc)):
        raise ContextError('D5 tariff does not match the bound configuration')
    return replace(context, _rate_items=tuple(rate.items()), authorized_day_utc=authorized_day_utc)


def require_effective_policy(context, *, model_id, max_input_chars, max_output_tokens,
                             calls_per_variant, timeout_seconds_per_variant):
    """Check the live ceilings permit the frozen settings before applying them."""
    if type(model_id) is not str or model_id != context.model_id:
        raise ContextError('D5 model does not match the bound configuration')
    ceilings = (
        ('max_input_chars', max_input_chars),
        ('max_output_tokens', max_output_tokens),
        ('calls_per_variant', calls_per_variant),
        ('timeout_seconds_per_variant', timeout_seconds_per_variant),
    )
    for name, ceiling in ceilings:
        if type(ceiling) is not int or ceiling < getattr(context, name):
            raise ContextError(f'D5 executor cannot honor {name}')


def current():
    return _CURRENT.get()


def current_variant():
    return _VARIANT.get()


@contextmanager
def use_context(context):
    """Install a run without inheriting another run's variant."""
    if type(context) is not RunContext:
        raise ContextError('D5 run context is invalid')
    token = _CURRENT.set(context)
    variant_token = _VARIANT.set(None)
    try:
        yield context
    finally:
        _VARIANT.reset(variant_token)
        _CURRENT.reset(token)


@contextmanager
def use_variant(name):
    """Bind one allowed variant to the current D5 workflow task."""
    if current() is None or type(name) is not str or name not in missions.VARIANT_NAMES:
        raise ContextError('D5 workflow variant is invalid')
    token = _VARIANT.set(name)
    try:
        yield name
    finally:
        _VARIANT.reset(token)

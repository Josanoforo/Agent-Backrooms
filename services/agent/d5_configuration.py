"""Versioned configuration for the product's ordinary D1 workflow harness.

The configuration ID is the SHA-256 of the canonical JSON containing the
schema and the full specification. Model eligibility and lower server ceilings
are controller inputs. Neither is part of the identity. Validation makes no
reservation. The executor must still enforce the frozen limits, including any
that are lower than its defaults.
"""

import hashlib
import json
import re
from collections.abc import Collection, Mapping
from types import MappingProxyType

from . import budget, missions, provider, workflow


SCHEMA = 'd5-configuration/v1'
TOOL_POLICY = 'sandbox-shell/v1'
HARD_LIMITS = MappingProxyType({
    'calls_per_variant': workflow.MAX_CALLS,
    'max_output_tokens': budget.CALL_OUTPUT_TOKENS,
    'max_input_chars': provider.INPUT_LIMIT_HARD_MAX,
    'timeout_seconds_per_variant': workflow.VARIANT_TIMEOUT,
})
_MODEL_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}')
_SHA256 = re.compile(r'[0-9a-f]{64}')


class ConfigurationError(ValueError):
    """Invalid configuration, seal or controller policy. Messages omit input values."""


def _fields(value, names, scope):
    if (type(value) is not dict or value.keys() != names
            or any(type(key) is not str for key in value)):
        raise ConfigurationError(f'{scope} fields are invalid')


def _validate_limits(limits, server_limits):
    _fields(limits, HARD_LIMITS.keys(), 'limits')
    ceilings = HARD_LIMITS if server_limits is None else server_limits
    if not isinstance(ceilings, Mapping) or ceilings.keys() != HARD_LIMITS.keys():
        raise ConfigurationError('server limit fields are invalid')

    for name, maximum in HARD_LIMITS.items():
        minimum = provider.INPUT_LIMIT_MIN if name == 'max_input_chars' else 1
        ceiling = ceilings[name]
        if type(ceiling) is not int or not minimum <= ceiling <= maximum:
            raise ConfigurationError(f'server limit {name} is out of bounds')
        value = limits[name]
        if type(value) is not int or not minimum <= value <= ceiling:
            raise ConfigurationError(f'limit {name} is out of bounds')


def build_configuration(specification, *, allowed_models, server_limits=None):
    """Validate a specification and seal a detached JSON envelope."""
    _fields(specification, {'model_id', 'mission_id', 'tool_policy', 'limits', 'parameters'}, 'specification')
    if not isinstance(allowed_models, Collection) or isinstance(allowed_models, (str, bytes, bytearray)):
        raise ConfigurationError('allowed_models must be a collection of model IDs')
    model = specification['model_id']
    if type(model) is not str or not _MODEL_ID.fullmatch(model) or model not in allowed_models:
        raise ConfigurationError('model_id is not allowed')
    mission = specification['mission_id']
    if type(mission) is not str or mission not in missions.CATALOG:
        raise ConfigurationError('mission_id is not allowed')
    tool_policy = specification['tool_policy']
    if type(tool_policy) is not str or tool_policy != TOOL_POLICY:
        raise ConfigurationError('tool_policy is not allowed')

    _validate_limits(specification['limits'], server_limits)
    parameters = specification['parameters']
    _fields(parameters, {'reasoning_effort'}, 'parameters')
    effort = parameters['reasoning_effort']
    if effort is not None and (type(effort) is not str or effort != provider.REASONING_VALUE
                               or model not in provider.REASONING_MODELS):
        raise ConfigurationError('reasoning_effort is unsupported for the model')

    encoded = missions.canonical({'schema': SCHEMA, 'specification': specification})
    sealed = json.loads(encoded)
    sealed['configuration_id'] = hashlib.sha256(encoded.encode('utf-8')).hexdigest()
    return sealed


def validate_configuration(envelope, *, allowed_models, server_limits=None):
    """Verify the stored ID and revalidate under the supplied controller policy."""
    _fields(envelope, {'schema', 'configuration_id', 'specification'}, 'configuration')
    schema = envelope['schema']
    if type(schema) is not str or schema != SCHEMA:
        raise ConfigurationError('configuration schema is invalid')
    configuration_id = envelope['configuration_id']
    if type(configuration_id) is not str or not _SHA256.fullmatch(configuration_id):
        raise ConfigurationError('configuration_id is invalid')
    expected = build_configuration(envelope['specification'], allowed_models=allowed_models,
                                   server_limits=server_limits)
    if configuration_id != expected['configuration_id']:
        raise ConfigurationError('configuration_id mismatch')
    return expected


def parse_configuration(text, *, allowed_models, server_limits=None):
    """Decode strict JSON and verify its versioned seal."""
    try:
        envelope = missions.parse_strict(text)
    except (TypeError, ValueError, RecursionError):
        raise ConfigurationError('configuration JSON is invalid') from None
    return validate_configuration(envelope, allowed_models=allowed_models, server_limits=server_limits)

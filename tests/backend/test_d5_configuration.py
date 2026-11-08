import hashlib
import json
from copy import deepcopy

import pytest

from services.agent import budget, d5_configuration as config, missions, provider, workflow


MODELS = frozenset({'glm-5.3-flash', 'qwen3.8-flash-next', 'controller-model'})


@pytest.fixture
def specification():
    return {
        'model_id': 'glm-5.3-flash',
        'mission_id': missions.INVOICES.id,
        'tool_policy': config.TOOL_POLICY,
        'limits': dict(config.HARD_LIMITS),
        'parameters': {'reasoning_effort': None},
    }


def test_deterministic_canonical_id_and_detached_envelope(specification):
    sealed = config.build_configuration(specification, allowed_models=MODELS)
    canonical = (b'{"schema":"d5-configuration/v1","specification":{"limits":'
                 b'{"calls_per_variant":8,"max_input_chars":40000,"max_output_tokens":1024,'
                 b'"timeout_seconds_per_variant":90},"mission_id":"invoice-reconcile/v1",'
                 b'"model_id":"glm-5.3-flash","parameters":{"reasoning_effort":null},'
                 b'"tool_policy":"sandbox-shell/v1"}}')
    assert sealed['configuration_id'] == hashlib.sha256(canonical).hexdigest()
    encoded = json.dumps(sealed, indent=2, sort_keys=True)
    restored = config.parse_configuration(encoded, allowed_models=MODELS)
    assert restored == sealed
    reordered = dict(reversed(list(specification.items())))
    reordered['limits'] = dict(reversed(list(specification['limits'].items())))
    assert config.build_configuration(reordered, allowed_models=MODELS) == sealed

    specification['limits']['calls_per_variant'] = 1
    sealed['specification']['parameters']['reasoning_effort'] = 'minimal'
    assert restored['specification']['limits']['calls_per_variant'] == workflow.MAX_CALLS
    assert restored['specification']['parameters']['reasoning_effort'] is None


@pytest.mark.parametrize('path,value', [
    (('model_id',), 'qwen3.8-flash-next'),
    (('mission_id',), missions.TABLE.id),
    (('limits', 'calls_per_variant'), 7),
    (('limits', 'max_input_chars'), 24_000),
    (('limits', 'max_output_tokens'), 1023),
    (('limits', 'timeout_seconds_per_variant'), 89),
    (('parameters', 'reasoning_effort'), 'minimal'),
])
def test_every_configurable_value_contributes_to_id(specification, path, value):
    sealed = config.build_configuration(specification, allowed_models=MODELS)
    target = specification if len(path) == 1 else specification[path[0]]
    target[path[-1]] = value
    updated = config.build_configuration(specification, allowed_models=MODELS)
    assert updated['configuration_id'] != sealed['configuration_id']
    sealed['specification'] = updated['specification']
    with pytest.raises(config.ConfigurationError, match='configuration_id mismatch'):
        config.validate_configuration(sealed, allowed_models=MODELS)


@pytest.mark.parametrize('field,value', [
    ('model_id', 'another-model'),
    ('model_id', ' glm-5.3-flash'),
    ('model_id', ['glm-5.3-flash']),
    ('mission_id', missions.INVOICE_CATALOG.id),
    ('mission_id', 'document-workflow/v1'),
    ('mission_id', {'name': 'invoice-reconcile/v1'}),
    ('tool_policy', 'no-tools/v1'),
    ('tool_policy', ['run_shell']),
])
def test_rejects_unregistered_or_untyped_choices(specification, field, value):
    specification[field] = value
    with pytest.raises(config.ConfigurationError, match=field):
        config.build_configuration(specification, allowed_models=MODELS)


def test_controller_model_allowlist_is_mandatory_and_exact(specification):
    for models in ((), {'qwen3.8-flash-next'}, 'glm-5.3-flash', None):
        with pytest.raises(config.ConfigurationError, match='model_id|allowed_models'):
            config.build_configuration(specification, allowed_models=models)
    sealed = config.build_configuration(specification, allowed_models=MODELS)
    assert config.validate_configuration(sealed, allowed_models=['glm-5.3-flash']) == sealed
    with pytest.raises(config.ConfigurationError, match='model_id'):
        config.validate_configuration(sealed, allowed_models=[])


def test_limit_bounds_use_workflow_budget_and_provider_constants(specification):
    assert config.HARD_LIMITS == {
        'calls_per_variant': workflow.MAX_CALLS,
        'max_input_chars': provider.INPUT_LIMIT_HARD_MAX,
        'max_output_tokens': budget.CALL_OUTPUT_TOKENS,
        'timeout_seconds_per_variant': workflow.VARIANT_TIMEOUT,
    }
    for name, ceiling in config.HARD_LIMITS.items():
        floor = provider.INPUT_LIMIT_MIN if name == 'max_input_chars' else 1
        for value in (True, 0, -1, floor - 1, ceiling + 1, str(ceiling), float(ceiling), float('inf')):
            invalid = deepcopy(specification)
            invalid['limits'][name] = value
            with pytest.raises(config.ConfigurationError, match=name):
                config.build_configuration(invalid, allowed_models=MODELS)
        specification['limits'][name] = floor
    assert config.build_configuration(specification, allowed_models=MODELS)['specification'] == specification


def test_controller_can_tighten_ceilings_without_changing_id(specification):
    specification['limits']['max_input_chars'] = 24_000
    sealed = config.build_configuration(specification, allowed_models=MODELS)
    ceilings = dict(config.HARD_LIMITS, max_input_chars=24_000)
    assert config.validate_configuration(sealed, allowed_models=MODELS, server_limits=ceilings) == sealed
    ceilings['max_input_chars'] -= 1
    with pytest.raises(config.ConfigurationError, match='limit max_input_chars'):
        config.validate_configuration(sealed, allowed_models=MODELS, server_limits=ceilings)


@pytest.mark.parametrize('override', [
    {'extra_limit': 1}, {'calls_per_variant': True}, {'calls_per_variant': 9},
    {'max_input_chars': 0}, {'max_input_chars': 1999},
])
def test_invalid_controller_caps_refused(specification, override):
    ceilings = dict(config.HARD_LIMITS, **override)
    with pytest.raises(config.ConfigurationError, match='server limit'):
        config.build_configuration(specification, allowed_models=MODELS, server_limits=ceilings)


@pytest.mark.parametrize('effort', ['', 'Minimal', ' minimal', 'high', True, 1, ['minimal']])
def test_rejects_other_or_untyped_reasoning_efforts(specification, effort):
    specification['parameters']['reasoning_effort'] = effort
    with pytest.raises(config.ConfigurationError, match='reasoning_effort'):
        config.build_configuration(specification, allowed_models=MODELS)


def test_reasoning_effort_respects_current_provider_support(specification):
    specification['model_id'] = 'controller-model'
    config.build_configuration(specification, allowed_models=MODELS)
    specification['parameters']['reasoning_effort'] = 'minimal'
    with pytest.raises(config.ConfigurationError, match='reasoning_effort'):
        config.build_configuration(specification, allowed_models=MODELS)


@pytest.mark.parametrize('scope,extra', [
    ('specification', 'api_key'), ('specification', 'endpoint'), ('specification', 'script'),
    ('parameters', 'temperature'), ('parameters', 'messages'), ('limits', 'memory_bytes'),
])
def test_rejects_unknown_fields_without_echoing_inputs(specification, scope, extra):
    target = specification if scope == 'specification' else specification[scope]
    target[extra] = 'must-not-appear'
    with pytest.raises(config.ConfigurationError, match=f'{scope} fields are invalid') as error:
        config.build_configuration(specification, allowed_models=MODELS)
    assert 'must-not-appear' not in str(error.value)


def test_rejects_missing_fields_and_wrong_container_types(specification):
    assert specification.pop('parameters') == {'reasoning_effort': None}
    with pytest.raises(config.ConfigurationError, match='specification fields'):
        config.build_configuration(specification, allowed_models=MODELS)
    for parameters in ({}, []):
        specification['parameters'] = parameters
        with pytest.raises(config.ConfigurationError, match='parameters fields'):
            config.build_configuration(specification, allowed_models=MODELS)


@pytest.mark.parametrize('value,reason', [
    ({'schema': 'd5-configuration/v2'}, 'schema'),
    ({'configuration_id': 'F' * 64}, 'configuration_id is invalid'),
    ({'configuration_id': 'a' * 64}, 'configuration_id mismatch'),
    ({'metadata': {}}, 'configuration fields'),
])
def test_rejects_invalid_envelope(specification, value, reason):
    sealed = config.build_configuration(specification, allowed_models=MODELS)
    sealed.update(value)
    with pytest.raises(config.ConfigurationError, match=reason):
        config.validate_configuration(sealed, allowed_models=MODELS)


@pytest.mark.parametrize('replacement,reason', [
    ('"reasoning_effort":null,"reasoning_effort":null', 'JSON'),
    ('"reasoning_effort":NaN', 'JSON'),
    ('"reasoning_effort":Infinity', 'JSON'),
    ('"reasoning_effort":1e999', 'reasoning_effort'),
])
def test_parser_rejects_duplicate_keys_and_nonfinite_numbers(specification, replacement, reason):
    sealed = config.build_configuration(specification, allowed_models=MODELS)
    text = json.dumps(sealed, separators=(',', ':')).replace('"reasoning_effort":null', replacement)
    with pytest.raises(config.ConfigurationError, match=reason):
        config.parse_configuration(text, allowed_models=MODELS)

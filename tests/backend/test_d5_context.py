"""D5 context and effective workflow limits with local doubles."""

import asyncio
from contextlib import asynccontextmanager, nullcontext
from dataclasses import FrozenInstanceError
import json

import httpx
import pytest

from services.agent import budget, d4_context, d5_configuration, d5_context, external, guards, provider, runner, usage, workflow


MODEL = 'glm-5.3-flash'  # fixture model supporting the explicit reasoning setting
RUN = 'fixture-d5-run'
MISSION = 'invoice-reconcile/v1'
RATE = {'model': MODEL, 'currency': 'USD', 'input_per_million': '0.123456789012', 'output_per_million': '2.5',
        'effective_date': '2026-11-04', 'source': 'fixture-catalog'}


def configuration(*, model=MODEL, reasoning_effort='minimal', **limits):
    return d5_configuration.build_configuration({
        'model_id': model, 'mission_id': MISSION, 'tool_policy': d5_configuration.TOOL_POLICY,
        'parameters': {'reasoning_effort': reasoning_effort},
        'limits': {'max_input_chars': 2400, 'max_output_tokens': 123, 'calls_per_variant': 2,
                   'timeout_seconds_per_variant': 3, **limits},
    }, allowed_models=(model,))


def context(**settings):
    sealed = configuration(**settings)
    return d5_context.build_context(sealed, RUN, allowed_models=(sealed['specification']['model_id'],))


def test_context_validates_seal_policy_and_detaches_frozen_settings():
    sealed = configuration()
    active = d5_context.build_context(sealed, RUN, allowed_models=(MODEL,))
    assert active.configuration_id == sealed['configuration_id']
    assert (active.run_id, active.model_id, active.mission_id) == (RUN, MODEL, MISSION)
    assert (active.reasoning_effort, active.tool_policy) == ('minimal', 'sandbox-shell/v1')
    with pytest.raises(FrozenInstanceError):
        active.max_output_tokens = 1

    with pytest.raises(d5_configuration.ConfigurationError, match='model_id'):
        d5_context.build_context(sealed, RUN, allowed_models=('other',))
    ceilings = {**d5_configuration.HARD_LIMITS, 'max_output_tokens': 120}
    with pytest.raises(d5_configuration.ConfigurationError, match='max_output_tokens'):
        d5_context.build_context(sealed, RUN, allowed_models=(MODEL,), server_limits=ceilings)
    with pytest.raises(d5_context.ContextError, match='run id'):
        d5_context.build_context(sealed, '/fixture', allowed_models=(MODEL,))

    sealed['specification']['limits']['max_output_tokens'] = 1
    assert active.max_output_tokens == 123
    with pytest.raises(d5_configuration.ConfigurationError, match='configuration_id mismatch'):
        d5_context.build_context(sealed, RUN, allowed_models=(MODEL,))


@pytest.mark.parametrize(('field', 'value'), [
    ('model_id', 'other'), ('max_input_chars', 2399), ('max_output_tokens', 122),
    ('calls_per_variant', 1), ('timeout_seconds_per_variant', 2),
    ('timeout_seconds_per_variant', 3.0), ('calls_per_variant', True),
])
def test_effective_policy_detects_mismatch(field, value):
    active = context()
    ceilings = {'model_id': MODEL, 'max_input_chars': 2400, 'max_output_tokens': 123,
                'calls_per_variant': 2, 'timeout_seconds_per_variant': 3}
    d5_context.require_effective_policy(active, **ceilings)
    d5_context.require_effective_policy(active, **{**ceilings, 'max_output_tokens': 1024})
    with pytest.raises(d5_context.ContextError, match='model' if field == 'model_id' else field):
        d5_context.require_effective_policy(active, **{**ceilings, field: value})


def test_context_restores_after_failure_and_isolates_concurrent_tasks():
    first = context()
    second = context(model='fixture-other-model', reasoning_effort=None, max_output_tokens=456)

    async def exercise(active):
        variant = 'legitimate' if active is first else 'perturbed'
        with d5_context.use_context(active), d5_context.use_variant(variant):
            await asyncio.sleep(0)
            assert d5_context.current() is active
            assert d5_context.current_variant() == variant
            with pytest.raises(RuntimeError):
                with d5_context.use_context(second if active is first else first):
                    await asyncio.sleep(0)
                    assert d5_context.current() is not active
                    assert d5_context.current_variant() is None
                    raise RuntimeError('fixture')
            assert d5_context.current() is active
            assert d5_context.current_variant() == variant
        assert d5_context.current() is None
        assert d5_context.current_variant() is None

    async def exercise_both():
        await asyncio.gather(exercise(first), exercise(second))

    assert d5_context.current() is None
    asyncio.run(exercise_both())
    assert d5_context.current() is None
    with pytest.raises(d5_context.ContextError, match='variant'):
        with d5_context.use_variant('legitimate'):
            pass
    with d5_context.use_context(first), pytest.raises(d5_context.ContextError, match='variant'):
        with d5_context.use_variant('other'):
            pass


@pytest.fixture
def live_policy(monkeypatch):
    monkeypatch.setenv('VULTR_INFERENCE_KEY', 'fixture-only-key')
    monkeypatch.setenv('ESCAPE_USAGE_RATE_JSON', json.dumps(RATE))
    monkeypatch.setenv('ESCAPE_DAILY_USD_LIMIT', '1')
    monkeypatch.delenv(guards.ROOM_DAY_ENV, raising=False)
    monkeypatch.delenv(guards.ROOM_DAY_REQUIRED_ENV, raising=False)
    monkeypatch.delenv(provider.INPUT_LIMIT_ENV, raising=False)
    monkeypatch.setattr(provider, 'INPUT_LIMIT_CHARS', 40000)


@pytest.mark.parametrize('effort', [None, 'minimal'])
def test_provider_applies_bound_settings_with_existing_reservations(live_policy, monkeypatch, effort):
    active = d5_context.bind_rate(context(reasoning_effort=effort), {**RATE, 'output_per_million': '2.500'})
    calls = []
    monkeypatch.setenv(provider.REASONING_ENV, 'invalid-global-setting')
    monkeypatch.setattr(guards, 'reserve', lambda db, model, messages, **kw: calls.append(('daily', model)))
    monkeypatch.setattr(budget, 'reserve', lambda db, kind: calls.append(('lifetime', kind)))

    def transport(request):
        calls.append(('transport', str(request.url)))
        attempt, = collector.attempts()
        assert attempt['status'] == 'in_flight'
        assert {key: attempt[key] for key in ('configuration_id', 'run_id', 'level', 'variant', 'parameters', 'rate')} == {
            'configuration_id': active.configuration_id, 'run_id': RUN, 'level': 'workflow', 'variant': 'legitimate',
            'parameters': {'max_tokens': 123, 'reasoning_effort': effort}, 'rate': RATE,
        }
        body = json.loads(request.content)
        assert body['model'] == MODEL and body['max_tokens'] == 123
        assert body['tools'] == provider.RUN_SHELL_TOOLS
        if effort is None:
            assert 'reasoning_effort' not in body
        else:
            assert body['reasoning_effort'] == effort
        return httpx.Response(200, json={'model': MODEL, 'choices': [{'message': {'content': 'fixture'}}],
                                         'usage': {'prompt_tokens': 10, 'completion_tokens': 4}})

    real_client = httpx.AsyncClient
    monkeypatch.setattr(provider.httpx, 'AsyncClient', lambda **kwargs: real_client(
        transport=httpx.MockTransport(transport), **kwargs))
    detached = active.rate
    detached['source'] = 'mutated'
    with d5_context.use_context(active), d5_context.use_variant('legitimate'), usage.collect(RUN, RATE) as collector:
        assert asyncio.run(provider.complete(MODEL, [{'role': 'user', 'content': 'hello'}])) == {'content': 'fixture'}
        with pytest.raises(provider.ProviderError, match='input limit exceeded'):
            asyncio.run(provider.complete(MODEL, [{'role': 'user', 'content': 'x' * 2401}]))
        monkeypatch.setenv(provider.INPUT_LIMIT_ENV, '2399')
        with pytest.raises(provider.ProviderError, match='cannot honor the bound limits'):
            asyncio.run(provider.complete(MODEL, [{'role': 'user', 'content': 'hello'}]))
    assert calls == [('daily', MODEL), ('lifetime', 'call'), ('transport', provider.ENDPOINT)]
    assert collector.summary()['cost']['priced_attempts'] == 1


@pytest.mark.parametrize('rate', [dict(RATE, model='wrong-model'), dict(RATE, source=None),
                                  dict(RATE, input_per_million='1e-10000'),
                                  dict(RATE, input_per_million='0.1234567890123')])
def test_d5_rejects_unusable_tariff(rate):
    with pytest.raises(d5_context.ContextError, match='tariff'):
        d5_context.bind_rate(context(), rate)


@pytest.mark.parametrize('failure', ['variant', 'collector', 'run', 'rate', 'unbound', 'live_rate', 'no_guard'])
def test_dispatch_requires_variant_collector_and_matching_tariff(live_policy, monkeypatch, failure):
    active = context() if failure == 'unbound' else d5_context.bind_rate(context(), RATE)
    rate = dict(RATE, effective_date='2026-11-03') if failure == 'rate' else RATE
    if failure == 'live_rate':
        monkeypatch.setenv('ESCAPE_USAGE_RATE_JSON', json.dumps(dict(RATE, input_per_million='0.1')))
    if failure == 'no_guard':
        monkeypatch.delenv('ESCAPE_DAILY_USD_LIMIT')

    def unexpected(*args, **kwargs):
        pytest.fail('unbound D5 dispatch reached reservation or transport')

    monkeypatch.setattr(guards, 'reserve', unexpected)
    monkeypatch.setattr(budget, 'reserve', unexpected)
    monkeypatch.setattr(provider.httpx, 'AsyncClient', unexpected)
    collector = nullcontext() if failure == 'collector' else usage.collect('another-run' if failure == 'run' else RUN, rate)
    with d5_context.use_context(active), collector as recorded:
        variant = nullcontext() if failure == 'variant' else d5_context.use_variant('legitimate')
        with variant, pytest.raises(provider.ProviderError, match='D5 dispatch requires'):
            asyncio.run(provider.complete(MODEL, []))
    if recorded is not None:
        assert recorded.attempts() == []


@pytest.mark.parametrize('when', ['before_hook', 'during_reservation'])
def test_tariff_drift_at_request_hook_never_reaches_transport(live_policy, monkeypatch, when):
    active = d5_context.bind_rate(context(), RATE)
    reservations = []

    def unexpected(*args, **kwargs):
        pytest.fail('D5 tariff drift reached reservation or transport')

    class DelayedClient(httpx.AsyncClient):
        async def post(self, *args, **kwargs):
            await asyncio.sleep(0)
            if when == 'before_hook':
                drift()
            return await super().post(*args, **kwargs)

    def drift():
        monkeypatch.setenv('ESCAPE_USAGE_RATE_JSON', json.dumps(dict(RATE, source='other-source')))

    def daily(*args, **kwargs):
        reservations.append('daily')

    def lifetime(*args):
        reservations.append('lifetime')
        drift()

    monkeypatch.setattr(guards, 'reserve', daily)
    monkeypatch.setattr(budget, 'reserve', lifetime)
    monkeypatch.setattr(provider.httpx, 'AsyncClient', lambda **kwargs: DelayedClient(
        transport=httpx.MockTransport(unexpected), **kwargs))
    with d5_context.use_context(active), d5_context.use_variant('legitimate'), usage.collect(RUN, RATE) as collector:
        with pytest.raises(provider.ProviderError, match='D5 dispatch requires'):
            asyncio.run(provider.complete(MODEL, []))
    assert collector.attempts() == []
    assert reservations == (['daily', 'lifetime'] if when == 'during_reservation' else [])


@pytest.mark.parametrize('response', ['alias', 'missing_model', 'timeout', 'cancelled'])
def test_d5_ambiguous_consumption_is_bound_but_unpriced(live_policy, monkeypatch, response):
    active = d5_context.bind_rate(context(), RATE)
    monkeypatch.setattr(guards, 'reserve', lambda *args, **kwargs: None)
    monkeypatch.setattr(budget, 'reserve', lambda *args: None)

    async def transport(request):
        if response == 'timeout':
            raise httpx.ReadTimeout('fixture')
        if response == 'cancelled':
            raise asyncio.CancelledError
        body = {'choices': [{'message': {'content': 'fixture'}}],
                'usage': {'prompt_tokens': 10, 'completion_tokens': 4}}
        if response == 'alias':
            body['model'] = 'another-model'
        return httpx.Response(200, json=body)

    real_client = httpx.AsyncClient
    monkeypatch.setattr(provider.httpx, 'AsyncClient', lambda **kwargs: real_client(
        transport=httpx.MockTransport(transport), **kwargs))
    errors = {'timeout': provider.ProviderError, 'cancelled': asyncio.CancelledError}
    with d5_context.use_context(active), d5_context.use_variant('perturbed'), usage.collect(RUN, RATE) as collector:
        with (pytest.raises(errors[response]) if response in errors else nullcontext()):
            asyncio.run(provider.complete(MODEL, []))
    summary = collector.summary()
    attempt, = summary['attempts']
    assert attempt['variant'] == 'perturbed' and attempt['rate'] == RATE
    assert summary['cost']['unpriced_attempts'] == 1 and summary['cost_usd'] is None


@pytest.mark.parametrize('conflict', ['model', 'no_tools', 'room_tool', 'room_env', 'room_context', 'd4', 'external'])
def test_provider_rejects_incompatible_mode_before_reservation(live_policy, monkeypatch, conflict):
    def unexpected(*args, **kwargs):
        pytest.fail('conflicting D5 request reached reservation or transport')

    monkeypatch.setattr(guards, 'reserve', unexpected)
    monkeypatch.setattr(budget, 'reserve', unexpected)
    monkeypatch.setattr(provider.httpx, 'AsyncClient', unexpected)
    if conflict == 'd4':
        monkeypatch.setattr(d4_context, 'current', lambda: object())
    if conflict == 'room_env':
        monkeypatch.setenv(guards.ROOM_DAY_REQUIRED_ENV, '1')
    token = external.CURRENT.set({} if conflict == 'external' else None)
    room = guards.ROOM_AUTHORIZATION.set(object() if conflict == 'room_context' else None)
    try:
        tools = {'no_tools': False, 'room_tool': provider.ROOM_ACTION_TOOLS}.get(conflict, True)
        with d5_context.use_context(context()), pytest.raises(provider.ProviderError, match='bound model'):
            asyncio.run(provider.complete('other' if conflict == 'model' else MODEL, [], tools=tools))
    finally:
        guards.ROOM_AUTHORIZATION.reset(room)
        external.CURRENT.reset(token)


@pytest.mark.parametrize('failure', ['run', 'mission', 'calls', 'timeout', 'output', 'input', 'catalog'])
def test_workflow_refuses_mismatched_policy_before_sandbox(live_policy, monkeypatch, failure):
    active = context()
    monkeypatch.setattr(runner, 'Session', lambda: pytest.fail('invalid D5 workflow opened a sandbox'))
    if failure == 'calls':
        monkeypatch.setattr(workflow, 'MAX_CALLS', 1)
    elif failure == 'timeout':
        monkeypatch.setattr(workflow, 'VARIANT_TIMEOUT', 2)
    elif failure == 'output':
        monkeypatch.setattr(budget, 'CALL_OUTPUT_TOKENS', 122)
    elif failure == 'input':
        monkeypatch.setenv(provider.INPUT_LIMIT_ENV, '2399')
    with d5_context.use_context(active), pytest.raises(provider.ProviderError, match='D5'):
        if failure == 'catalog':
            asyncio.run(workflow.catalog_cell(RUN, MODEL, None, None, profile='A', variant='legitimate', catalog=None))
        else:
            asyncio.run(workflow.workflow('other' if failure == 'run' else RUN, MODEL, None, None,
                                          mission=None if failure == 'mission' else MISSION))


def test_workflow_uses_frozen_call_and_time_limits_for_each_fresh_variant(live_policy, monkeypatch):
    sessions, calls, timeouts = [], [], []

    class Session:
        async def __aenter__(self):
            sessions.append(self)
            return self

        async def __aexit__(self, *exc):
            self.cleanup_confirmed = True

        async def execute(self, command):
            return {'exit_code': 0, 'stdout': '', 'stderr': ''}

    async def prepare(sandbox, text):
        pass

    async def complete(model, messages):
        calls.append((sessions[-1], d5_context.current_variant()))
        return {'tool_calls': [{'id': 'tool-' + str(len(calls)), 'function': {
            'name': 'run_shell', 'arguments': '{"command":"true"}',
        }}]}

    @asynccontextmanager
    async def timeout(seconds):
        timeouts.append(seconds)
        yield

    monkeypatch.setattr(runner, 'Session', Session)
    monkeypatch.setattr(workflow, 'prepare', prepare)
    monkeypatch.setattr(provider, 'complete', complete)
    monkeypatch.setattr(workflow.asyncio, 'timeout', timeout)
    with d5_context.use_context(context()):
        summary = asyncio.run(workflow.workflow(RUN, MODEL, lambda *args: None, lambda *args: None, mission=MISSION))
    assert timeouts == [3, 3]
    assert len(sessions) == 2 and sessions[0] is not sessions[1]
    assert calls == [(sessions[0], 'legitimate')] * 2 + [(sessions[1], 'perturbed')] * 2
    assert d5_context.current_variant() is None
    assert summary['cleanup_confirmed'] is True
    assert [result['model_calls'] for result in summary['variants'].values()] == [2, 2]

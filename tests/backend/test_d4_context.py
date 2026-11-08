"""D4 settings, reservations and usage through HTTPX with only local transports."""

import asyncio
from dataclasses import FrozenInstanceError
import json

import httpx
import pytest

from services.agent import budget, d4_context, d4_manifest, external, guards, provider, usage


ALPHA = 'fixture-alpha'
BETA = 'fixture-beta'
TODAY = '2026-11-04'
TOMORROW = '2026-11-05'
MESSAGES = [{'role': 'user', 'content': 'Conciliación'}]


@pytest.fixture
def make_context(monkeypatch):
    monkeypatch.setenv('VULTR_INFERENCE_KEY', 'fixture-only-key')
    monkeypatch.setenv(d4_context.AUTHORIZED_DAY_ENV, TODAY)
    monkeypatch.setattr(guards, 'day', lambda: TODAY)
    monkeypatch.delenv(guards.ROOM_DAY_ENV, raising=False)
    monkeypatch.delenv(guards.ROOM_DAY_REQUIRED_ENV, raising=False)
    monkeypatch.setenv(provider.REASONING_ENV, 'invalid-global')
    monkeypatch.setenv(provider.INPUT_LIMIT_ENV, 'invalid-global')

    def unexpected_reservation(*args, **kwargs):
        pytest.fail('D4 called a historical reservation')

    monkeypatch.setattr(guards, 'reserve', unexpected_reservation)
    monkeypatch.setattr(budget, 'reserve', unexpected_reservation)

    def make(reserve, model_id=ALPHA, *, max_request_bytes=100_096):
        catalog = {
            'schema': 'd4-catalog/v1', 'source': d4_manifest.CATALOG_SOURCE,
            'captured_at_utc': TODAY + 'T16:00:00Z', 'origin': 'fixture',
            'coverage': {'http_status': 200, 'pages_observed': 1, 'requested_models_complete': True},
            'models': {
                model: {'tools': True, 'reasoning_efforts': ['minimal'] if model == ALPHA else [],
                        'rate': {'model': model, 'currency': 'USD', 'input_per_million': price,
                                 'output_per_million': '1.7', 'effective_date': TODAY}}
                for model, price in ((ALPHA, '0.123456789123'), (BETA, '1.2'))
            },
        }
        spec = {
            'models': [ALPHA, BETA], 'variants': ['legitimate', 'perturbed'],
            'level': 'workflow', 'mission': 'invoice-reconcile/v1',
            'catalog': catalog, 'catalog_sha256': d4_manifest.catalog_sha256(catalog),
            'parameters': {ALPHA: {'reasoning_effort': 'minimal'}, BETA: {'reasoning_effort': None}},
            'fixtures': {'legitimate': {'id': 'fixture-clean/v1', 'sha256': 'a' * 64},
                         'perturbed': {'id': 'fixture-perturbed/v1', 'sha256': 'b' * 64}},
            'oracle': {'version': 'invoice-reconcile-verifier/v1', 'sha256': 'c' * 64},
            'protocol': {'version': 'escape-protocol/v1', 'sha256': 'd' * 64},
            'image_digest': 'sha256:' + 'e' * 64, 'profile_sha256': 'f' * 64,
            'limits': {'calls_per_variant': 2, 'max_calls': 8, 'max_output_tokens': 234,
                       'max_request_bytes': max_request_bytes, 'max_input_chars': 2000,
                       'timeout_seconds_per_variant': 55},
        }
        manifest = d4_manifest.build_manifest('fixture-campaign', 'fixture-key', spec)
        return d4_context.build_context(manifest, model_id, 'run-' + model_id, reserve), manifest

    return make


def use_transport(monkeypatch, handler):
    real_client = httpx.AsyncClient
    monkeypatch.setattr(provider.httpx, 'AsyncClient',
                        lambda **options: real_client(transport=httpx.MockTransport(handler), **options))


def answer(model):
    body = {'choices': [{'message': {'content': 'done'}, 'finish_reason': 'stop'}],
            'usage': {'prompt_tokens': 100, 'completion_tokens': 50}}
    if model is not None:
        body['model'] = model
    return httpx.Response(200, json=body)


def run_once(context, *, variant='legitimate', model=None, messages=MESSAGES, tools=True):
    async def execute():
        with (d4_context.use_context(context), d4_context.use_variant(variant),
              usage.collect(context.run_id, context.rate) as collector):
            result = await provider.complete(model or context.model_id, messages, tools=tools)
        return result, collector.summary()

    return asyncio.run(execute())


def test_context_is_detached_frozen_and_restores_nested_scope(make_context):
    reserve = lambda *args: None
    context, manifest = make_context(reserve)
    second, _ = make_context(reserve, BETA)
    manifest['specification']['limits']['max_output_tokens'] = 1
    context.rate['input_per_million'] = '8'
    assert context.max_output_tokens == 234
    assert context.rate['input_per_million'] == '0.123456789123'
    assert context.profile_sha256 == 'f' * 64 and context.image_digest == 'sha256:' + 'e' * 64
    assert context.max_calls == 4 * context.calls_per_variant == 8
    with pytest.raises(FrozenInstanceError):
        context.reasoning_effort = None

    with d4_context.use_context(context), d4_context.use_variant('perturbed'):
        assert d4_context.current() is context
        with d4_context.use_context(second):
            assert d4_context.current() is second
            assert d4_context.current_variant() is None
            with d4_context.use_variant('legitimate'):
                assert d4_context.current_variant() == 'legitimate'
        assert d4_context.current_variant() == 'perturbed'
    assert d4_context.current() is None and d4_context.current_variant() is None

    with pytest.raises(d4_manifest.ManifestError, match='specification_sha256'):
        d4_context.build_context(manifest, ALPHA, 'run-test', reserve)


def test_context_rejects_unknown_model_run_or_async_reservation(make_context):
    context, manifest = make_context(lambda *args: None)

    async def async_reserve(*args):
        pass

    with pytest.raises(ValueError, match='synchronous'):
        d4_context.build_context(manifest, ALPHA, context.run_id, async_reserve)
    with pytest.raises(ValueError, match='run id'):
        d4_context.build_context(manifest, ALPHA, '/run-test', lambda *args: None)
    with pytest.raises(ValueError, match='model'):
        d4_context.build_context(manifest, 'undeclared', context.run_id, lambda *args: None)


def test_concurrent_models_and_variants_keep_payload_tariff_and_attempt_binding(make_context, monkeypatch):
    seen = []

    def reserve(context, variant, size):
        collector = usage.current()
        assert collector.run_id == context.run_id
        assert all(attempt['variant'] != variant for attempt in collector.attempts())
        seen.append(('reserve', context.model_id, variant, size))

    async def transport(request):
        context, variant = d4_context.current(), d4_context.current_variant()
        body = json.loads(request.content)
        assert str(request.url) == provider.ENDPOINT
        assert request.headers['Authorization'] == 'Bearer fixture-only-key'
        assert body['tools'] == provider.RUN_SHELL_TOOLS
        assert body['model'] == context.model_id
        assert body['max_tokens'] == context.max_output_tokens
        if context.reasoning_effort:
            assert body['reasoning_effort'] == context.reasoning_effort
        else:
            assert 'reasoning_effort' not in body
        assert seen[-1] == ('reserve', context.model_id, variant, len(request.content))
        attempt = usage.current().attempts()[-1]
        assert attempt['status'] == 'in_flight'
        assert (attempt['run_id'], attempt['level'], attempt['variant']) == (context.run_id, 'workflow', variant)
        assert attempt['rate'] == context.rate
        assert attempt['parameters'] == {'max_tokens': 234, 'reasoning_effort': context.reasoning_effort}
        seen.append(('transport', context.model_id, variant, len(request.content)))
        await asyncio.sleep(0)
        return answer(context.model_id)

    async def run(context):
        with d4_context.use_context(context), usage.collect(context.run_id, context.rate) as collector:
            for variant in ('legitimate', 'perturbed'):
                with d4_context.use_variant(variant):
                    assert await provider.complete(context.model_id, MESSAGES) == {'content': 'done'}
        return collector.summary()

    async def run_both():
        return await asyncio.gather(run(make_context(reserve, ALPHA)[0]), run(make_context(reserve, BETA)[0]))

    use_transport(monkeypatch, transport)
    alpha, beta = asyncio.run(run_both())
    assert len(seen) == 8
    assert alpha['cost_usd'] == 0.00019469
    assert beta['cost_usd'] == 0.00041
    for result, model in ((alpha, ALPHA), (beta, BETA)):
        assert result['cost']['priced_attempts'] == 2
        assert [a['variant'] for a in result['attempts']] == ['legitimate', 'perturbed']
        assert {a['returned_model'] for a in result['attempts']} == {model}


@pytest.mark.parametrize('returned', [BETA, None])
def test_missing_or_different_returned_model_keeps_cost_unknown(make_context, monkeypatch, returned):
    use_transport(monkeypatch, lambda request: answer(returned))
    context, _ = make_context(lambda *args: None)
    _, summary = run_once(context)
    assert summary['coverage']['complete'] is True
    assert summary['cost_usd'] is None
    assert summary['cost']['priced_attempts'] == 0
    assert summary['attempts'][0]['returned_model'] == returned


def test_exact_httpx_utf8_payload_limit_precedes_reservation(make_context, monkeypatch):
    reservations = []
    transported = []

    def transport(request):
        transported.append(request.content)
        return answer(ALPHA)

    def reserve(context, variant, size):
        reservations.append(size)

    use_transport(monkeypatch, transport)
    context, _ = make_context(reserve)
    run_once(context)
    body = transported[0]
    assert len(body) > len(body.decode('utf-8'))
    exact, _ = make_context(reserve, max_request_bytes=len(body))
    run_once(exact)
    too_small, _ = make_context(reserve, max_request_bytes=len(body) - 1)
    with pytest.raises(provider.ProviderError, match='serialized request byte limit'):
        run_once(too_small)
    with pytest.raises(provider.ProviderError, match='input limit'):
        run_once(context, messages=[{'role': 'user', 'content': 'a' * 2001}])
    assert reservations == [len(body)] * 2
    assert transported == [body, body]


@pytest.mark.parametrize('mode', ['reservation', 'deferred_reservation', 'collector', 'absent_day', 'expired_day', 'crossed_reserve',
                                  'crossed_registration', 'missing_variant', 'model', 'no_tool', 'room_tool',
                                  'room_environment', 'room_context', 'external'])
def test_veto_does_not_dispatch_or_leave_a_usage_attempt(make_context, monkeypatch, mode):
    reservations = []
    day = [TODAY]

    def reserve(context, variant, size):
        reservations.append(size)
        if mode == 'reservation':
            raise ValueError('sensitive fixture rejection')
        if mode == 'crossed_reserve':
            day[0] = TOMORROW
        if mode == 'deferred_reservation':
            return (part for part in ())

    if mode == 'crossed_registration':
        original = usage.UsageCollector.begin_d4_attempt

        def register(collector, context, variant):
            attempt = original(collector, context, variant)
            day[0] = TOMORROW
            return attempt

        monkeypatch.setattr(usage.UsageCollector, 'begin_d4_attempt', register)

    use_transport(monkeypatch, lambda request: pytest.fail('vetoed request entered transport'))
    context, _ = make_context(reserve)
    monkeypatch.setattr(guards, 'day', lambda: day[0])
    if mode == 'absent_day':
        monkeypatch.delenv(d4_context.AUTHORIZED_DAY_ENV)
    if mode == 'expired_day':
        day[0] = TOMORROW
    if mode == 'room_environment':
        monkeypatch.setenv(guards.ROOM_DAY_REQUIRED_ENV, '1')

    async def run():
        run_id = 'wrong-run' if mode == 'collector' else context.run_id
        custom = external.CURRENT.set({} if mode == 'external' else None)
        room = guards.ROOM_AUTHORIZATION.set(object() if mode == 'room_context' else None)
        try:
            with d4_context.use_context(context), usage.collect(run_id, context.rate) as collector:
                if mode == 'crossed_registration':
                    prior = usage.begin_attempt(context.model_id)
                    prior.fail('timeout')
                with pytest.raises(provider.ProviderError) as failure:
                    if mode == 'missing_variant':
                        await provider.complete(context.model_id, MESSAGES)
                    else:
                        tools = provider.ROOM_ACTION_TOOLS if mode == 'room_tool' else mode != 'no_tool'
                        with d4_context.use_variant('perturbed'):
                            await provider.complete(BETA if mode == 'model' else context.model_id, MESSAGES, tools=tools)
            assert 'sensitive fixture rejection' not in str(failure.value)
            summary = collector.summary()
            assert summary['attempts_total'] == (1 if mode == 'crossed_registration' else 0)
            if mode == 'crossed_registration':
                assert summary['attempts'][0]['attempt_id'] == prior.attempt_id
            assert summary['rejected_before_network']['by_reason'] == {'budget': 1}
        finally:
            guards.ROOM_AUTHORIZATION.reset(room)
            external.CURRENT.reset(custom)

    asyncio.run(run())
    assert len(reservations) == (1 if mode in {'reservation', 'deferred_reservation', 'crossed_reserve', 'crossed_registration'} else 0)


@pytest.mark.parametrize('kind', ['timeout', 'network_error', 'cancelled'])
def test_dispatched_timeout_or_cancellation_retains_reservation_and_unknown_usage(make_context, monkeypatch, kind):
    reservations = []
    context, _ = make_context(lambda context, variant, size: reservations.append((variant, size)))

    async def run():
        transported = asyncio.Event()

        async def transport(request):
            transported.set()
            if kind == 'timeout':
                raise httpx.ReadTimeout('fixture timeout', request=request)
            if kind == 'network_error':
                raise httpx.ConnectError('fixture connect error', request=request)
            await asyncio.Event().wait()

        use_transport(monkeypatch, transport)
        with (d4_context.use_context(context), d4_context.use_variant('perturbed'),
              usage.collect(context.run_id, context.rate) as collector):
            pending = asyncio.create_task(provider.complete(context.model_id, MESSAGES))
            await transported.wait()
            if kind == 'cancelled':
                pending.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await pending
            else:
                with pytest.raises(provider.D4CompletionError) as failure:
                    await pending
                assert failure.value.code == kind
        return collector.summary()

    summary = asyncio.run(run())
    assert len(reservations) == 1 and reservations[0][0] == 'perturbed'
    assert summary['attempts'][0]['status'] == kind
    assert summary['attempts'][0]['variant'] == 'perturbed'
    assert summary['coverage']['unknown_calls'] == 1
    assert summary['cost_usd'] is None


def test_cancel_inside_post_before_hook_never_reserves_or_dispatches(make_context, monkeypatch):
    context, _ = make_context(lambda *args: pytest.fail('cancelled pre-hook request reserved'))

    async def run():
        posting = asyncio.Event()

        class CancelBeforeHook(httpx.AsyncClient):
            async def post(self, *args, **kwargs):
                posting.set()
                await asyncio.Event().wait()

        def transport(request):
            pytest.fail('cancelled pre-hook request entered transport')

        monkeypatch.setattr(provider.httpx, 'AsyncClient', lambda **options: CancelBeforeHook(
            transport=httpx.MockTransport(transport), **options))
        with (d4_context.use_context(context), d4_context.use_variant('perturbed'),
              usage.collect(context.run_id, context.rate) as collector):
            pending = asyncio.create_task(provider.complete(context.model_id, MESSAGES))
            await posting.wait()
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
        assert collector.summary()['attempts_total'] == 0

    asyncio.run(run())


@pytest.mark.parametrize('code', ['length', 'rate_limited'])
def test_terminal_provider_outcome_preserves_use_and_never_returns_tool_calls(make_context, monkeypatch, code):
    reservations = []
    context, _ = make_context(lambda *args: reservations.append(args))
    response = httpx.Response(429, json={'message': 'fixture'})
    if code == 'length':
        response = httpx.Response(200, json={
            'model': context.model_id, 'usage': {'prompt_tokens': 100, 'completion_tokens': 234},
            'choices': [{'finish_reason': 'length', 'message': {'tool_calls': [{'id': 'must-not-return'}]}}],
        })
    use_transport(monkeypatch, lambda request: response)

    async def run():
        with (d4_context.use_context(context), d4_context.use_variant('perturbed'),
              usage.collect(context.run_id, context.rate) as collector):
            with pytest.raises(provider.D4CompletionError) as failure:
                await provider.complete(context.model_id, MESSAGES)
        assert failure.value.code == code
        assert failure.value.diagnostic['category'] == code
        return collector.summary()

    summary = asyncio.run(run())
    attempt, = summary['attempts']
    assert len(reservations) == 1
    if code == 'length':
        assert attempt['finish_reason'] == attempt['status'] == 'length'
        assert attempt['completion_tokens'] == 234
        assert summary['cost']['priced_attempts'] == 1
    else:
        assert attempt['finish_reason'] is None
        assert attempt['http_status'] == 429 and attempt['status'] == 'http_error'
        assert summary['cost_usd'] is None

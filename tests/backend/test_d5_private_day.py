"""D5 private dispatch stays within its authorized UTC day."""

import asyncio
from contextlib import closing
import json
import sqlite3

import httpx
import pytest

from services.agent import budget, d5_configuration, d5_context, guards, provider, usage


@pytest.mark.parametrize('rollover', [False, True])
def test_private_day_checked_after_attempt_registration(tmp_path, monkeypatch, rollover):
    day, next_day = '2026-11-05', '2026-11-06'
    model = 'deepseek-v4.1-flash-1017'
    run_id = 'a' * 32
    database = str(tmp_path / 'private.sqlite3')
    rate = {'model': model, 'currency': 'USD', 'effective_date': day, 'source': 'fixture-catalog',
            'input_per_million': '0.15', 'output_per_million': '0.6'}
    for name, value in {
        guards.D5_DAY_ENV: day, 'ESCAPE_DB': database, 'VULTR_INFERENCE_KEY': 'fixture-only',
        'ESCAPE_DAILY_USD_LIMIT': '0.01', 'ESCAPE_USAGE_RATE_JSON': json.dumps(rate),
        'ESCAPE_MAX_CALLS': '2', 'ESCAPE_MAX_OUTPUT_TOKENS': '2048',
        provider.INPUT_LIMIT_ENV: '4000',
    }.items():
        monkeypatch.setenv(name, value)
    for name in (guards.ROOM_DAY_ENV, guards.ROOM_DAY_REQUIRED_ENV):
        monkeypatch.delenv(name, raising=False)

    configuration = d5_configuration.build_configuration({
        'model_id': model, 'mission_id': 'invoice-reconcile/v1', 'tool_policy': d5_configuration.TOOL_POLICY,
        'parameters': {'reasoning_effort': 'minimal'},
        'limits': {'max_input_chars': 4000, 'max_output_tokens': 100,
                   'calls_per_variant': 2, 'timeout_seconds_per_variant': 10},
    }, allowed_models=(model,))
    context = d5_context.build_context(configuration, run_id, allowed_models=(model,))
    context = d5_context.bind_rate(context, rate, authorized_day_utc=day)

    clock = day
    monkeypatch.setattr(guards, 'day', lambda: clock)
    begin = usage.UsageCollector.begin_d5_attempt
    registered, dispatched = [], []

    def begin_with_rollover(collector, context, variant):
        nonlocal clock
        attempt = begin(collector, context, variant)
        registered.append(attempt)
        if rollover:
            clock = next_day
        return attempt

    def transport(request):
        dispatched.append(str(request.url))
        return httpx.Response(200, json={'model': model, 'choices': [{'message': {'content': 'fixture'}}],
                                         'usage': {'prompt_tokens': 1, 'completion_tokens': 1}})

    client = httpx.AsyncClient
    monkeypatch.setattr(usage.UsageCollector, 'begin_d5_attempt', begin_with_rollover)
    monkeypatch.setattr(provider.httpx, 'AsyncClient', lambda **kwargs: client(
        transport=httpx.MockTransport(transport), **kwargs))
    with d5_context.use_context(context), d5_context.use_variant('legitimate'), usage.collect(run_id, rate) as collector:
        if rollover:
            with pytest.raises(provider.ProviderError, match='D5 dispatch requires the bound variant'):
                asyncio.run(provider.complete(model, []))
            assert dispatched == [] and collector.attempts() == []
        else:
            assert asyncio.run(provider.complete(model, [])) == {'content': 'fixture'}
            assert dispatched == [provider.ENDPOINT]
            assert collector.attempts()[0]['status'] == 'completed'

    assert len(registered) == 1 and registered[0] is not usage.NULL_ATTEMPT
    assert budget.read_counters(database) == {'runs': 0, 'calls': 1, 'output_tokens_reserved': 1024}
    with closing(sqlite3.connect(database)) as conn:
        reservations = conn.execute('SELECT day, reserved_microusd FROM daily_inference_budget').fetchall()
    assert reservations == [(day, 1230)]

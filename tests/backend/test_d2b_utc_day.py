"""Private D2B day authorization with a local clock, SQLite and an HTTP double."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import contextlib
from datetime import datetime
import json
import sqlite3
from threading import Barrier
import time
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from services.agent import budget, guards, levels, main, provider, runner, usage


AUTHORIZED_DAY = '2026-11-04'
NEXT_DAY = '2026-11-05'
MODEL = 'utc-test-model'


@pytest.fixture
def room_api(tmp_path, monkeypatch):
    path = str(tmp_path / 'utc.sqlite3')
    clock = SimpleNamespace(today=AUTHORIZED_DAY, on_request=None)
    sent = []
    monkeypatch.setattr(guards, 'day', lambda: clock.today)
    monkeypatch.setattr(main, 'DB', path)
    for key, value in {
        'ESCAPE_DB': path,
        'ESCAPE_ROOMS_EXPERIMENT': '1',
        'ESCAPE_D2B_REQUIRE_AUTHORIZED_DAY': '1',
        'ESCAPE_D2B_AUTHORIZED_DAY_UTC': AUTHORIZED_DAY,
        'ESCAPE_DAILY_USD_LIMIT': '0.50',
        'ESCAPE_USAGE_RATE_JSON': json.dumps({'model': MODEL, 'input_per_million': 1,
                                             'output_per_million': 2, 'effective_date': AUTHORIZED_DAY}),
        'ESCAPE_OPERATOR_TOKEN': 'test-operator',
        'VULTR_INFERENCE_KEY': 'test-provider-key',
        'ESCAPE_MODEL': MODEL,
        'ESCAPE_MAX_RUNS': '2',
        'ESCAPE_MAX_CALLS': '2',
        'ESCAPE_MAX_OUTPUT_TOKENS': '2048',
        'ESCAPE_RATE_LIMIT_PER_MINUTE': '100',
    }.items():
        monkeypatch.setenv(key, value)
    for key in ('ESCAPE_PUBLIC_DEMO', 'ESCAPE_CLEANUP_ON_STARTUP', 'ESCAPE_CATALOG_EXPERIMENT'):
        monkeypatch.delenv(key, raising=False)

    class UsageClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls.fromisoformat(clock.today + 'T00:00:00+00:00')

    async def wire(request):
        sent.append({'day': clock.today, 'endpoint': str(request.url), 'days': daily_rows(path),
                     'calls': budget.read_counters(path)['calls']})
        if clock.on_request is not None:
            clock.on_request(request)
        return httpx.Response(200, json={
            'model': MODEL, 'choices': [{'message': {'role': 'assistant', 'content': 'done'}}],
            'usage': {'prompt_tokens': 4, 'completion_tokens': 2},
        })

    class HttpClient(httpx.AsyncClient):
        def __init__(self, **kwargs):
            super().__init__(transport=httpx.MockTransport(wire), **kwargs)

    async def available(): return True

    async def image_id(): return 'sha256:' + 'a' * 64

    async def room_stub(run_id, model, event, error_receipt):
        await complete_room()
        return {'outcome': 'exhausted', 'cleanup_confirmed': True}

    monkeypatch.setattr(usage, 'datetime', UsageClock)
    monkeypatch.setattr(provider.httpx, 'AsyncClient', HttpClient)
    monkeypatch.setattr(runner, 'docker_available', available)
    monkeypatch.setattr(runner, 'image_id', image_id)
    monkeypatch.setattr(levels, 'processes', room_stub)
    main.rate_windows.clear()
    with TestClient(main.app, headers={'Authorization': 'Bearer test-operator'}) as client:
        yield SimpleNamespace(client=client, clock=clock, db=path, sent=sent, http_client=HttpClient)


def daily_rows(db):
    with contextlib.closing(sqlite3.connect(db)) as conn:
        table = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='daily_inference_budget'").fetchone()
        return dict(conn.execute('SELECT day, reserved_microusd FROM daily_inference_budget')) if table else {}


def post_room(api):
    return api.client.post('/api/runs', json={'model': MODEL, 'levels': ['processes']})


def final_report(api):
    response = post_room(api)
    assert response.status_code == 202, response.text
    path = '/api/runs/' + response.json()['id'] + '/report'
    for _ in range(100):
        report = api.client.get(path).json()
        if report['final']:
            return report
        time.sleep(.01)
    pytest.fail('room run did not terminate')


async def complete_room():
    return await provider.complete(MODEL, provider.initial_messages('local double'), tools=provider.ROOM_ACTION_TOOLS)


def test_room_binds_admission_reservation_and_provider_dispatch_to_authorized_day(room_api):
    cfg = room_api.client.get('/api/config').json()
    assert cfg['d2b_authorized_day_utc'] == cfg['daily_inference_budget']['day_utc'] == AUTHORIZED_DAY
    report = final_report(room_api)
    assert report['run']['status'] == 'completed'
    assert report['experiment']['room_experiment']['authorized_day_utc'] == AUTHORIZED_DAY
    assert report['run']['summary']['processes']['inference_reservation_day_utc'] == AUTHORIZED_DAY
    assert report['usage']['attempts_total'] == 1
    assert report['usage']['attempts'][0]['started_at'].startswith(AUTHORIZED_DAY + 'T')
    (request,) = room_api.sent
    assert request['endpoint'] == provider.ENDPOINT and request['day'] == AUTHORIZED_DAY
    assert request['calls'] == 1 and set(request['days']) == {AUTHORIZED_DAY}
    assert 0 < request['days'][AUTHORIZED_DAY] < 500000


@pytest.mark.parametrize('configured', [None, '', '20261104', '2026-02-30', NEXT_DAY])
def test_invalid_missing_or_other_day_refuses_admission(room_api, monkeypatch, configured):
    if configured is None:
        monkeypatch.delenv(guards.ROOM_DAY_ENV)
    else:
        monkeypatch.setenv(guards.ROOM_DAY_ENV, configured)
    assert post_room(room_api).status_code == 503
    assert 'processes' not in room_api.client.get('/api/config').json()['levels']
    assert budget.read_counters(room_api.db) == {'runs': 0, 'calls': 0, 'output_tokens_reserved': 0}
    assert daily_rows(room_api.db) == {} and room_api.sent == []


def test_room_day_enforcement_requires_daily_budget(room_api, monkeypatch):
    monkeypatch.delenv('ESCAPE_DAILY_USD_LIMIT')
    assert post_room(room_api).status_code == 503
    assert budget.read_counters(room_api.db)['runs'] == 0 and room_api.sent == []


def test_room_reservation_refuses_a_rate_from_another_day(room_api, monkeypatch):
    monkeypatch.setenv('ESCAPE_USAGE_RATE_JSON', json.dumps({
        'model': MODEL, 'input_per_million': 1, 'output_per_million': 2, 'effective_date': NEXT_DAY,
    }))
    report = final_report(room_api)
    assert report['run']['status'] == 'failed' and room_api.sent == []
    assert 'rate effective on its authorized UTC day' in report['run']['summary']['processes']['evidence']
    assert report['usage']['attempts_total'] == budget.read_counters(room_api.db)['calls'] == 0
    assert daily_rows(room_api.db) == {}


def test_midnight_during_admission_rolls_back_run_and_events(room_api, monkeypatch):
    insert_event = main.insert_event

    def crossing(conn, run_id, kind, data):
        insert_event(conn, run_id, kind, data)
        room_api.clock.today = NEXT_DAY

    monkeypatch.setattr(main, 'insert_event', crossing)
    assert post_room(room_api).status_code == 503
    with contextlib.closing(sqlite3.connect(room_api.db)) as conn:
        for table in ('runs', 'run_config', 'run_meta', 'events'):
            assert conn.execute('SELECT COUNT(*) FROM ' + table).fetchone() == (0,)
    assert budget.read_counters(room_api.db)['runs'] == 0 and room_api.sent == []


@pytest.mark.parametrize('boundary', [
    'before_reservation', 'inside_reservation', 'after_commit', 'before_transport', 'usage_registration',
])
def test_midnight_refuses_dispatch_and_preserves_only_committed_reservation(room_api, monkeypatch, boundary):
    if boundary == 'before_reservation':
        enter_client = room_api.http_client.__aenter__

        async def enter(client):
            await enter_client(client)
            room_api.clock.today = NEXT_DAY
            return client

        monkeypatch.setattr(room_api.http_client, '__aenter__', enter)
    elif boundary == 'inside_reservation':
        reserve_call = budget.reserve_in

        def reserve_and_cross(conn, kind):
            reserve_call(conn, kind)
            if kind == 'call':
                room_api.clock.today = NEXT_DAY

        monkeypatch.setattr(budget, 'reserve_in', reserve_and_cross)
    elif boundary == 'after_commit':
        reserve = guards.reserve

        def commit_and_cross(*args, **kwargs):
            reserve(*args, **kwargs)
            room_api.clock.today = NEXT_DAY

        monkeypatch.setattr(guards, 'reserve', commit_and_cross)
    elif boundary == 'before_transport':
        post = room_api.http_client.post

        async def post_and_cross(client, *args, **kwargs):
            await asyncio.sleep(0)
            room_api.clock.today = NEXT_DAY
            return await post(client, *args, **kwargs)

        monkeypatch.setattr(room_api.http_client, 'post', post_and_cross)
    else:
        begin_attempt = usage.begin_attempt

        def register_and_cross(model):
            attempt = begin_attempt(model)
            room_api.clock.today = NEXT_DAY
            return attempt

        monkeypatch.setattr(usage, 'begin_attempt', register_and_cross)

    report = final_report(room_api)
    assert room_api.sent == [] and report['run']['status'] == 'failed'
    assert report['experiment']['room_experiment']['authorized_day_utc'] == AUTHORIZED_DAY
    summary = report['run']['summary']['processes']
    assert summary['outcome'] == 'error' and 'outside its authorized UTC day' in summary['evidence']
    assert report['usage']['attempts_total'] == 0 and report['usage']['attempts'] == []
    assert report['usage']['rejected_before_network']['by_reason'] == {'budget': 1}
    committed = boundary in {'after_commit', 'before_transport', 'usage_registration'}
    assert summary.get('inference_reservation_day_utc') == (AUTHORIZED_DAY if committed else None)
    assert set(daily_rows(room_api.db)) == ({AUTHORIZED_DAY} if committed else set())
    assert budget.read_counters(room_api.db) == {
        'runs': 1, 'calls': int(committed), 'output_tokens_reserved': 1024 if committed else 0,
    }


def test_dispatch_veto_leaves_an_earlier_attempt_in_the_collector(room_api, monkeypatch):
    async def scenario():
        with usage.collect() as collector:
            prior = usage.begin_attempt(MODEL)
            prior.record_response(200, {})
            begin_attempt = usage.begin_attempt

            def register_and_cross(model):
                attempt = begin_attempt(model)
                room_api.clock.today = NEXT_DAY
                return attempt

            monkeypatch.setattr(usage, 'begin_attempt', register_and_cross)
            with guards.room_authorization(AUTHORIZED_DAY, room_api.db):
                with pytest.raises(provider.ProviderError, match='outside its authorized UTC day'):
                    await complete_room()
            assert [attempt['attempt_id'] for attempt in collector.attempts()] == [prior.attempt_id]

    asyncio.run(scenario())
    assert room_api.sent == []


def test_room_authorization_cannot_reserve_a_second_call_on_the_same_day(room_api):
    async def scenario():
        with guards.room_authorization(AUTHORIZED_DAY, room_api.db):
            await complete_room()
            with pytest.raises(provider.ProviderError, match='already reserved its only inference call'):
                await complete_room()

    asyncio.run(scenario())
    assert len(room_api.sent) == budget.read_counters(room_api.db)['calls'] == 1


@pytest.mark.parametrize(('limit_key', 'limit', 'error'), [
    ('ESCAPE_MAX_CALLS', '1', 'Operational budget exhausted'),
    ('ESCAPE_DAILY_USD_LIMIT', '0.008', 'Daily inference budget exhausted'),
])
def test_two_room_reservations_contend_for_the_same_remaining_budget(room_api, monkeypatch, limit_key, limit, error):
    monkeypatch.setenv(limit_key, limit)
    ready = Barrier(2, timeout=5)
    messages = provider.initial_messages('local double')

    def reserve():
        with guards.room_authorization(AUTHORIZED_DAY, room_api.db) as room:
            ready.wait()
            try:
                guards.reserve(room_api.db, MODEL, messages, room=room)
            except (guards.GuardError, budget.BudgetError) as exc:
                return room.reserved_day_utc, str(exc)
            return room.reserved_day_utc, None

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: reserve(), range(2)))
    assert outcomes.count((AUTHORIZED_DAY, None)) == 1
    [(day, rejected)] = [item for item in outcomes if item[1] is not None]
    assert day is None and error in rejected
    rows = daily_rows(room_api.db)
    assert set(rows) == {AUTHORIZED_DAY} and 0 < rows[AUTHORIZED_DAY] < 8000
    assert budget.read_counters(room_api.db) == {'runs': 0, 'calls': 1, 'output_tokens_reserved': 1024}


def test_timeout_after_transport_handoff_preserves_the_reservation_and_unknown_usage(room_api):
    def timeout(request):
        room_api.clock.today = NEXT_DAY
        raise httpx.ReadTimeout('response unavailable', request=request)

    room_api.clock.on_request = timeout
    report = final_report(room_api)
    assert len(room_api.sent) == 1 and room_api.sent[0]['day'] == AUTHORIZED_DAY
    assert report['run']['status'] == 'failed'
    assert report['run']['summary']['processes']['inference_reservation_day_utc'] == AUTHORIZED_DAY
    assert set(daily_rows(room_api.db)) == {AUTHORIZED_DAY}
    assert budget.read_counters(room_api.db)['calls'] == report['usage']['attempts_total'] == 1
    attempt, = report['usage']['attempts']
    assert attempt['status'] == 'timeout' and attempt['usage_status'] == 'unknown'


@pytest.mark.parametrize('day', [AUTHORIZED_DAY, NEXT_DAY])
def test_day_bound_service_refuses_historical_api_levels_and_provider_tools(room_api, day):
    room_api.clock.today = day
    cfg = room_api.client.get('/api/config').json()
    assert cfg['levels'] == (['processes', 'privileges'] if day == AUTHORIZED_DAY else [])
    response = room_api.client.post('/api/runs', json={'model': MODEL, 'levels': ['secret']})
    assert response.status_code == 422
    for tools in (True, False):
        with pytest.raises(provider.ProviderError, match='requires the fixed room tool'):
            asyncio.run(provider.complete(MODEL, provider.initial_messages('local double'), tools=tools))
    assert budget.read_counters(room_api.db) == {'runs': 0, 'calls': 0, 'output_tokens_reserved': 0}
    assert daily_rows(room_api.db) == {} and room_api.sent == []


def test_public_config_and_ordinary_provider_without_room_authorization(room_api, monkeypatch):
    room_api.clock.today = NEXT_DAY
    monkeypatch.delenv(guards.ROOM_DAY_ENV)
    monkeypatch.delenv(guards.ROOM_DAY_REQUIRED_ENV)
    monkeypatch.setenv('ESCAPE_PUBLIC_DEMO', '1')
    cfg = room_api.client.get('/api/config').json()
    assert 'd2b_authorized_day_utc' not in cfg and cfg['levels'] == main.LEVELS
    assert post_room(room_api).status_code == 404
    asyncio.run(provider.complete(MODEL, provider.initial_messages('local double'), tools=False))
    assert room_api.sent[0]['day'] == NEXT_DAY and set(daily_rows(room_api.db)) == {NEXT_DAY}

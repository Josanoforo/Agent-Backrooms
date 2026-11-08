"""Private D4 campaign orchestration through ASGI with SQLite and a workflow double."""

import asyncio
from contextlib import closing
from copy import deepcopy
import json
import sqlite3
from threading import Event
from time import monotonic, sleep

from fastapi.testclient import TestClient
import pytest

from scripts.evaluation.d4_adapter import AdapterError, compare_reports
from services.agent import d4_context, d4_manifest, d4_store, experiment, guards, main, provider, runner, workflow


DAY = '2026-11-04'
IMAGE = 'sha256:' + 'e' * 64
MODELS = ('fixture-model-alpha', 'fixture-model-beta')
AUTH = {'Authorization': 'Bearer campaign-test-operator'}
PATH = '/api/campaigns'
RESERVED = 6438  # 2 variants × (ceil(9096×0.15 + 32×0.3) + ceil(9096×0.2 + 32×0.8))


def seal(specification, campaign_id='campaign-one', key='request-one'):
    return d4_manifest.build_manifest(campaign_id, key, specification)


@pytest.fixture
def approved(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'campaign.sqlite'))
    monkeypatch.setattr(main, 'lock', asyncio.Lock())
    monkeypatch.setattr(guards, 'day', lambda: DAY)
    monkeypatch.setattr(provider, 'INPUT_LIMIT_CHARS', 24_000)
    for name in ('ESCAPE_PUBLIC_DEMO', 'ESCAPE_ROOMS_EXPERIMENT', 'ESCAPE_CATALOG_EXPERIMENT',
                 guards.ROOM_DAY_ENV, guards.ROOM_DAY_REQUIRED_ENV,
                 'ESCAPE_CLEANUP_ON_STARTUP', 'ESCAPE_REASONING_EFFORT'):
        monkeypatch.delenv(name, raising=False)
    for name, value in {
        'ESCAPE_D4_CAMPAIGNS': '1', 'ESCAPE_D4_AUTHORIZED_DAY_UTC': DAY,
        'ESCAPE_OPERATOR_TOKEN': 'campaign-test-operator', 'VULTR_INFERENCE_KEY': 'fixture-only',
        'ESCAPE_EVIDENCE_ORIGIN': 'real', 'ESCAPE_CONCURRENT_RUNS': '1', 'ESCAPE_QUEUE_CAPACITY': '1',
        'ESCAPE_MAX_RUNS': '2', 'ESCAPE_MAX_CALLS': '4', 'ESCAPE_MAX_OUTPUT_TOKENS': '128',
        'ESCAPE_DAILY_USD_LIMIT': '0.006438', 'ESCAPE_PROVIDER_INPUT_LIMIT_CHARS': '24000',
    }.items():
        monkeypatch.setenv(name, value)

    async def available():
        return True

    async def image_id():
        return IMAGE

    async def no_docker_cleanup():
        pass

    async def unexpected_call(*args, **kwargs):
        pytest.fail('the orchestration test must only use the workflow double')

    monkeypatch.setattr(runner, 'docker_available', available)
    monkeypatch.setattr(runner, 'image_id', image_id)
    monkeypatch.setattr(runner, 'cleanup_owned', no_docker_cleanup)
    monkeypatch.setattr(provider, 'complete', unexpected_call)
    monkeypatch.setattr(workflow, 'workflow', unexpected_call)

    catalog = {
        'schema': d4_manifest.CATALOG_SCHEMA, 'source': d4_manifest.CATALOG_SOURCE,
        'captured_at_utc': DAY + 'T12:00:00Z', 'origin': 'operator_capture',
        'coverage': {'http_status': 200, 'pages_observed': 1, 'requested_models_complete': True},
        'models': {
            model: {'tools': True, 'reasoning_efforts': [], 'rate': {
                'model': model, 'currency': 'USD', 'input_per_million': input_rate,
                'output_per_million': output_rate, 'effective_date': DAY,
            }}
            for model, input_rate, output_rate in zip(MODELS, ('0.15', '0.2'), ('0.3', '0.8'), strict=True)
        },
    }
    spec = {
        'models': list(MODELS), 'level': d4_manifest.LEVEL, 'mission': d4_manifest.MISSION,
        'variants': list(d4_manifest.VARIANTS), 'catalog': catalog,
        'catalog_sha256': d4_manifest.catalog_sha256(catalog),
        'parameters': {model: {'reasoning_effort': None} for model in MODELS},
        'image_digest': IMAGE, 'profile_sha256': 'f' * 64,
        'limits': {'calls_per_variant': 1, 'max_calls': 4, 'max_output_tokens': 32,
                   'max_request_bytes': 5000, 'max_input_chars': 2000, 'timeout_seconds_per_variant': 30},
        **main.d4_anchors(experiment.protocol()),
    }
    manifest = seal(spec)
    monkeypatch.setenv('ESCAPE_D4_APPROVED_SPEC_SHA256', manifest['specification_sha256'])
    monkeypatch.setenv('ESCAPE_D4_APPROVED_CATALOG_SHA256', spec['catalog_sha256'])
    return manifest


def ledger():
    with main.db() as conn:
        daily_exists = conn.execute("SELECT 1 FROM sqlite_master WHERE name='daily_inference_budget'").fetchone()
        daily = conn.execute('SELECT day,reserved_microusd FROM daily_inference_budget').fetchall() if daily_exists else ()
        return {
            'budget': tuple(conn.execute('SELECT runs,calls,output_tokens_reserved FROM budget').fetchone()),
            'daily': [tuple(row) for row in daily],
            'campaigns': conn.execute('SELECT count(*) FROM d4_campaigns').fetchone()[0],
            'runs': conn.execute('SELECT count(*) FROM runs').fetchone()[0],
            'dispatches': [tuple(row) for row in conn.execute('SELECT run_id,variant,count FROM d4_calls')],
        }


EMPTY = {'budget': (0, 0, 0), 'daily': [], 'campaigns': 0, 'runs': 0, 'dispatches': []}


def submit(client, manifest):
    response = client.post(PATH, json=manifest, headers=AUTH)
    assert response.status_code == 202, response.json()
    return response.json()


def campaign_url(manifest):
    return f"{PATH}/{manifest['campaign_id']}"


def status_pair(campaign):
    return [row['status'] for row in campaign['runs']]


def wait_terminal(client, url):
    deadline = monotonic() + 5
    while monotonic() < deadline:
        response = client.get(url, headers=AUTH)
        assert response.status_code == 200, response.json()
        campaign = response.json()
        if all(status in {'completed', 'failed', 'cancelled'} for status in status_pair(campaign)):
            return campaign
        sleep(0.01)
    pytest.fail(f'campaign did not finish: {status_pair(campaign)}')


def block_first_workflow(monkeypatch):
    entered = Event()
    execution = []

    async def execute(run_id, model, event, emit_error_receipt, *, mission):
        context = d4_context.current()
        assert (context.run_id, context.model_id, mission) == (run_id, model, d4_manifest.MISSION)
        main.reserve_campaign_call(context, 'legitimate', 100)
        execution.append((run_id, model))
        entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError as exc:
            exc.cleanup_confirmed = True
            raise

    monkeypatch.setattr(workflow, 'workflow', execute)
    return entered, execution


def test_campaign_routes_require_operator_and_hide_when_disabled(approved, monkeypatch):
    url = campaign_url(approved)
    with TestClient(main.app) as client:
        assert client.post(PATH, content='malformed JSON').status_code == 401
        assert client.get(url, headers={'Authorization': 'Bearer wrong'}).status_code == 401
        assert client.post(url + '/cancel').status_code == 401
        assert client.get(url, headers=AUTH).status_code == 404
        assert client.post(url + '/cancel', headers=AUTH).status_code == 404
        assert client.post(PATH, content='malformed JSON', headers=AUTH).status_code == 422
        assert ledger() == EMPTY
        monkeypatch.setenv('ESCAPE_PUBLIC_DEMO', '1')
        assert client.post(PATH, json=approved, headers=AUTH).status_code == 404
        assert client.get(url, headers=AUTH).status_code == 404
        assert client.post(url + '/cancel', headers=AUTH).status_code == 404


@pytest.mark.parametrize('setting,value,reason', [
    ('ESCAPE_DAILY_USD_LIMIT', '0.006437', 'daily inference reservation'),
    ('ESCAPE_MAX_RUNS', '1', 'operational quota'),
    ('ESCAPE_MAX_CALLS', '3', 'operational quota'),
    ('ESCAPE_MAX_OUTPUT_TOKENS', '127', 'operational quota'),
    ('ESCAPE_D4_AUTHORIZED_DAY_UTC', '2026-11-03', 'outside its authorized UTC day'),
    ('ESCAPE_D4_APPROVED_SPEC_SHA256', '0' * 64, 'approved capture'),
    ('ESCAPE_D4_APPROVED_CATALOG_SHA256', '0' * 64, 'approved capture'),
])
def test_joint_admission_refusal_leaves_no_partial_reservation(approved, monkeypatch, setting, value, reason):
    monkeypatch.setenv(setting, value)
    with TestClient(main.app) as client:
        response = client.post(PATH, json=approved, headers=AUTH)
        assert response.status_code == 409, response.json()
        assert reason in response.json()['detail']
        assert client.get(campaign_url(approved), headers=AUTH).status_code == 404
        assert ledger() == EMPTY
        with main.db() as conn:
            assert conn.execute('SELECT count(*) FROM run_config').fetchone()[0] == 0
            assert conn.execute('SELECT count(*) FROM events').fetchone()[0] == 0


def test_joint_reservation_idempotency_and_cancel_active_and_pending(approved, monkeypatch):
    entered, execution = block_first_workflow(monkeypatch)
    url = campaign_url(approved)
    with TestClient(main.app) as client:
        admitted = submit(client, approved)
        first, second = [row['run_id'] for row in admitted['runs']]
        assert first != second
        assert [row['model_id'] for row in admitted['runs']] == list(MODELS)
        assert admitted['day_utc'] == DAY and admitted['reserved_microusd'] == RESERVED
        assert entered.wait(5)
        running = client.get(url, headers=AUTH)
        assert running.status_code == 200 and status_pair(running.json()) == ['running', 'queued']
        expected = {'budget': (2, 4, 128), 'daily': [(DAY, RESERVED)], 'campaigns': 1,
                    'runs': 2, 'dispatches': [(first, 'legitimate', 1)]}
        assert ledger() == expected

        retry = seal(approved['specification'], 'different-campaign-id', approved['idempotency_key'])
        assert submit(client, retry) == running.json()
        drift = deepcopy(approved['specification'])
        drift['limits']['timeout_seconds_per_variant'] += 1
        response = client.post(PATH, json=seal(drift), headers=AUTH)
        assert response.status_code == 409 and 'idempotency' in response.json()['detail']
        contender = seal(approved['specification'], 'second-campaign', 'second-key')
        response = client.post(PATH, json=contender, headers=AUTH)
        assert response.status_code == 409 and 'active' in response.json()['detail']
        assert ledger() == expected

        for _ in range(2):
            response = client.post(url + '/cancel', headers=AUTH)
            assert response.status_code == 200, response.json()
            assert [row['cancel_requested'] for row in response.json()['runs']] == [True, True]
        terminal = wait_terminal(client, url)
        assert status_pair(terminal) == ['cancelled', 'cancelled']
        assert submit(client, approved) == terminal
        assert execution == [(first, MODELS[0])]
        assert ledger() == expected
        with main.db() as conn:
            marks = conn.execute("SELECT run_id,COUNT(*) FROM events WHERE kind='cancel_requested' GROUP BY run_id")
            assert dict(marks) == {first: 1, second: 1}
            summaries = {run_id: json.loads(summary) for run_id, summary in conn.execute('SELECT id,summary FROM runs')}
        assert summaries[first]['workflow']['cleanup_confirmed'] is True
        assert summaries[second]['workflow']['outcome'] == 'not_run'


def test_campaign_dispatch_checks_prepaid_slots_and_utc_day(approved, monkeypatch):
    day = DAY
    monkeypatch.setattr(guards, 'day', lambda: day)

    async def execute(run_id, model, event, emit_error_receipt, *, mission):
        nonlocal day
        context = d4_context.current()
        if model == MODELS[0]:
            with pytest.raises(d4_store.CampaignError, match='request exceeds'):
                main.reserve_campaign_call(context, 'legitimate', context.max_request_bytes + 1)
            main.reserve_campaign_call(context, 'legitimate', context.max_request_bytes)
            with pytest.raises(d4_store.CampaignError, match='call allowance exhausted'):
                main.reserve_campaign_call(context, 'legitimate', 1)
            day = '2026-11-05'
        with pytest.raises(d4_store.CampaignError, match='outside its authorized UTC day'):
            main.reserve_campaign_call(context, 'perturbed', 1)
        return {'outcome': 'inconclusive', 'cleanup_confirmed': True}

    monkeypatch.setattr(workflow, 'workflow', execute)
    with TestClient(main.app) as client:
        admitted = submit(client, approved)
        first = admitted['runs'][0]['run_id']
        assert status_pair(wait_terminal(client, campaign_url(approved))) == ['completed', 'failed']
        assert ledger() == {'budget': (2, 4, 128), 'daily': [(DAY, RESERVED)], 'campaigns': 1,
                            'runs': 2, 'dispatches': [(first, 'legitimate', 1)]}


def test_restart_recovers_interrupted_campaign_without_requeue_or_refund(approved, monkeypatch, tmp_path):
    entered, execution = block_first_workflow(monkeypatch)
    url = campaign_url(approved)
    recovered = str(tmp_path / 'restart.sqlite')
    with TestClient(main.app) as client:
        admitted = submit(client, approved)
        first, second = [row['run_id'] for row in admitted['runs']]
        assert entered.wait(5)
        assert status_pair(client.get(url, headers=AUTH).json()) == ['running', 'queued']
        before = ledger()
        assert before['dispatches'] == [(first, 'legitimate', 1)]
        # Clone the committed crash point while both tasks exist. TestClient's normal
        # shutdown then operates only on the original SQLite database.
        with main.db() as source, closing(sqlite3.connect(recovered)) as destination:
            assert source.execute('SELECT count(*) FROM run_usage').fetchone()[0] == 0
            source.backup(destination)

    monkeypatch.setattr(main, 'DB', recovered)
    for _ in range(2):
        with TestClient(main.app) as client:
            terminal = client.get(url, headers=AUTH)
            assert terminal.status_code == 200, terminal.json()
            assert status_pair(terminal.json()) == ['failed', 'failed']
            assert [row['run_id'] for row in terminal.json()['runs']] == [first, second]
            assert submit(client, approved) == terminal.json()
            assert ledger() == before
            assert execution == [(first, MODELS[0])]
            with main.db() as conn:
                events = [json.loads(data) for data, in conn.execute("SELECT data FROM events WHERE kind='run' ORDER BY seq")]
            failed = [event for event in events if event['status'] == 'failed']
            assert [(event['id'], event['summary']['interrupted_from']) for event in failed] == [
                (first, 'running'), (second, 'queued'),
            ]
            assert all(event['summary']['evidence_incomplete'] for event in failed)

            reports = []
            for run_id, reserved in ((first, 1), (second, 0)):
                response = client.get(f'/api/runs/{run_id}/report', headers=AUTH)
                assert response.status_code == 200, response.json()
                report = response.json()
                assert report['d4_dispatch_ledger'] == {
                    'schema': 'd4-dispatch-ledger/v1', 'reserved_slots': {'legitimate': reserved, 'perturbed': 0},
                }
                assert report['usage']['measurement']['state'] == 'unavailable'
                assert report['usage']['attempts_total'] is None and report['usage']['attempts'] == []
                reports.append(report)

            comparison = compare_reports(approved, reports)
            possible_send, *absent = comparison['cells']
            assert (possible_send['run_id'], possible_send['variant']) == (first, 'legitimate')
            assert (possible_send['status'], possible_send['executed'], possible_send['error']) == (
                'interrupted', False, 'dispatch_unobserved',
            )
            assert possible_send['evidence']['reserved_dispatch_slots'] == 1
            assert possible_send['evidence']['unobserved_dispatch_slots'] == 1
            assert possible_send['usage']['attempts_total'] == 0 and possible_send['usage']['coverage'] == 'unknown'
            assert possible_send['cost']['coverage'] == 'unknown' and possible_send['cost']['estimated_usd'] is None
            assert [cell['status'] for cell in absent] == ['absent', 'absent', 'absent']

            tampered = deepcopy(reports[0])
            tampered['d4_dispatch_ledger']['reserved_slots']['legitimate'] = 0
            with pytest.raises(AdapterError, match='report seal'):
                compare_reports(approved, [tampered, reports[1]])

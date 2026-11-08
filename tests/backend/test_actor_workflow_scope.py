"""Admission context and mission scope; real SQLite/API, no Docker or inference."""
import asyncio
import dataclasses
import json
import os

import pytest
from fastapi.testclient import TestClient

from services.agent import experiment, invoice_actor_client as actor_client, main, missions, provider, runner, workflow

pytestmark = pytest.mark.skipif(not hasattr(os, 'geteuid'), reason='actor service is POSIX only')
SCHEDULE = main.schedule_run
IMAGE = 'sha256:' + 'a' * 64
INSTALLATION = 'b' * 32


@pytest.fixture
def admitted(monkeypatch, tmp_path):
    for key in list(os.environ):
        if key.startswith('ESCAPE_'):
            monkeypatch.delenv(key)
    uid = os.geteuid()
    for key, value in {
        'ESCAPE_ACTOR_BROKER_SOCKET': '/run/ordinary-test/owner.sock', 'ESCAPE_ACTOR_BROKER_UID': str(uid + 1),
        'ESCAPE_INVOICE_VERIFIER_SOCKET': '/run/ordinary-test/guard.sock', 'ESCAPE_INVOICE_VERIFIER_UID': str(uid + 2),
        'ESCAPE_INVOICE_VERIFIER_DURABLE': '1', 'ESCAPE_OPERATOR_TOKEN': 'ordinary-test',
        'ESCAPE_MODEL': 'fixture', 'VULTR_INFERENCE_KEY': 'unused-fixture-key', 'ESCAPE_EVIDENCE_ORIGIN': 'fixture',
        'ESCAPE_CONCURRENT_RUNS': '1', 'ESCAPE_QUEUE_CAPACITY': '0', 'ESCAPE_RATE_LIMIT_PER_MINUTE': '100',
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'runs.sqlite'))
    main.rate_windows.clear()
    dispatched, calls = [], []

    async def health(settings):
        return {'ready': True, 'blocked': False, 'obligations': 0, 'installation_id': INSTALLATION, 'image_id': IMAGE}

    def scheduled(run_id, model, levels, **options):
        dispatched.append((run_id, model, list(levels), options))

    async def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError('no actor, Docker or model operation expected')

    def no_session(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError('no actor creation expected')

    monkeypatch.setattr(actor_client, 'health', health)
    monkeypatch.setattr(main, 'schedule_run', scheduled)
    monkeypatch.setattr(runner, 'new_session', no_session)
    monkeypatch.setattr(runner, '_cli', forbidden)
    monkeypatch.setattr(provider, 'complete', forbidden)
    with TestClient(main.app, headers={'Authorization': 'Bearer ordinary-test'}) as client:
        yield client, dispatched, calls


@pytest.mark.parametrize('mission', [None, missions.TABLE.id, missions.INVOICES.id])
def test_admission_pins_the_complete_context_and_ordinary_mission(admitted, mission):
    client, dispatched, calls = admitted
    body = {'model': 'fixture', 'levels': ['workflow']}
    if mission is not None:
        body['mission'] = mission
    response = client.post('/api/runs', json=body)
    assert response.status_code == 202, response.text
    run_id, model, levels, options = dispatched[0]
    actor = options['actor']
    config = main.get_run_config(run_id)
    assert actor.mission_id == config['actor_boundary']['mission'] == (mission or workflow.SCENARIO)
    assert actor.context_sha256 == experiment.execution_context_digest(run_id, model, levels, config)
    main.validate_actor_context(run_id, model, levels, config, actor)
    assert ('independent' in options) == (mission == missions.INVOICES.id)
    with pytest.raises(dataclasses.FrozenInstanceError):
        actor.mission_id = 'other'
    assert not calls


@pytest.mark.parametrize('mutation', ['mission', 'model', 'levels', 'image', 'context', 'missing_pin'])
def test_changed_persisted_context_fails_before_actor_or_model(admitted, mutation):
    client, dispatched, calls = admitted
    response = client.post('/api/runs', json={'model': 'fixture', 'levels': ['workflow'], 'mission': missions.TABLE.id})
    assert response.status_code == 202
    run_id, model, levels, options = dispatched[0]
    config, actor = main.get_run_config(run_id), options['actor']
    with main.db() as conn:
        if mutation == 'model':
            conn.execute('UPDATE runs SET model=? WHERE id=?', ('other', run_id))
        elif mutation == 'levels':
            conn.execute('UPDATE runs SET levels=? WHERE id=?', (json.dumps(['secret']), run_id))
        else:
            if mutation == 'mission':
                config['mission'] = missions.INVOICES.id
            elif mutation == 'image':
                config['actor_boundary']['image_id'] = 'sha256:' + 'c' * 64
            elif mutation == 'context':
                config['provider'] = 'mutated after admission'
            else:
                actor = dataclasses.replace(actor, context_sha256=None)
            conn.execute('UPDATE run_config SET config=? WHERE run_id=?', (json.dumps(config), run_id))
    asyncio.run(main.run_levels(run_id, model, levels, actor=actor))
    assert main.get_run(run_id)['status'] == 'failed'
    assert not calls
    assert 'admission mission or context changed' in str(main.get_run(run_id)['summary'])


def test_unknown_explicit_mission_is_rejected_before_reservation(admitted):
    client, dispatched, calls = admitted
    response = client.post('/api/runs', json={'model': 'fixture', 'levels': ['workflow'], 'mission': workflow.SCENARIO})
    assert response.status_code == 422 and not dispatched and not calls
    with main.db() as conn:
        assert conn.execute('SELECT count(*) FROM runs').fetchone()[0] == 0


def test_schedule_copies_levels_before_the_caller_can_mutate_them(admitted, monkeypatch):
    seen = []

    async def run(run_id, model, levels, **options):
        seen.append(levels)

    monkeypatch.setattr(main, 'run_levels', run)

    async def scenario():
        levels = ['workflow']
        SCHEDULE('c' * 32, 'fixture', levels)
        task = main.run_tasks['c' * 32]
        levels.append('secret')
        await task
        main.active.discard('c' * 32)

    asyncio.run(scenario())
    assert seen == [['workflow']]


def test_workflow_refuses_a_foreign_or_missing_mission_pin():
    for settings in (actor_client.Settings('/run/test.sock', 123),
                     actor_client.Settings('/run/test.sock', 123, mission_id=missions.TABLE.id)):
        with pytest.raises(ValueError, match='pinned standalone mission'):
            asyncio.run(workflow.workflow('c' * 32, 'fixture', lambda *a: None, lambda *a: None,
                                          mission=missions.TABLE.id, actor=settings))

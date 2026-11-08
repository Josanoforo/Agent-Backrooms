"""Sol's Persistence admission, phase checkpoint and exact two-receipt recovery contract."""
import asyncio
import copy
import json
import os

import pytest

from services.agent import invoice_actor_client as actor_client, levels, main, recovery, runner
from test_actor_workflow_scope import admitted

pytestmark = pytest.mark.skipif(not hasattr(os, 'geteuid'), reason='POSIX actor controller')


@pytest.fixture
def persistence_service(admitted, monkeypatch):
    monkeypatch.setenv('ESCAPE_ACTOR_LEVELS', 'persistence')
    return admitted


def admit(service):
    client, dispatched, calls = service
    response = client.post('/api/runs', json={'model': 'fixture', 'levels': ['persistence']})
    assert response.status_code == 202, response.text
    return response.json()['id'], dispatched[0][3]


def test_persistence_uses_one_frozen_admission_for_both_phases(persistence_service):
    run_id, options = admit(persistence_service)
    config = main.get_run_config(run_id)
    assert options['context'].level == 'persistence' and options['level_actor'] is not None
    assert config['level_actor_boundary']['stage'] == 'actor'
    main.validate_level_context(run_id, 'fixture', ['persistence'], config, options['level_actor'], options['context'])
    config['level_actor_boundary']['stage'] = 'fresh'
    with pytest.raises(runner.RunnerError):
        main.validate_level_context(run_id, 'fixture', ['persistence'], config, options['level_actor'], options['context'])
    assert not persistence_service[2]


@pytest.mark.parametrize('mutation', ['none', 'actor-only', 'missing-B-id', 'context', 'predecessor', 'same-id',
    'duplicate', 'order', 'unconfirmed-A', 'unconfirmed-B', 'replace-block'])
def test_recovery_reads_individual_finishes_without_replay_or_creating_b(persistence_service, monkeypatch, mutation):
    run_id, options = admit(persistence_service)
    actor, context = options['level_actor'], options['context']
    request_a = dict(installation_id=actor.installation_id, run_id=run_id, level='persistence', stage='actor', context_sha256=context.sha256)
    a = dict(request_a, intent_id='c' * 32, container_id='d' * 64)
    request_b = dict(request_a, stage='fresh', predecessor=copy.deepcopy(a))
    b = dict(request_b, intent_id='e' * 32, container_id='f' * 64)
    events = [('level_actor_open_requested', request_a), ('level_actor_identity', a)]
    if mutation != 'actor-only': events += [('level_actor_open_requested', request_b), ('level_actor_identity', b)]
    if mutation == 'missing-B-id': events.pop()
    if mutation == 'context': b['context_sha256'] = '0' * 64
    if mutation == 'predecessor': b['predecessor']['intent_id'] = '0' * 32
    if mutation == 'same-id': b['container_id'] = a['container_id']
    if mutation == 'duplicate': events.append(('level_actor_identity', copy.deepcopy(a)))
    if mutation == 'order': events = events[2:] + events[:2]
    for kind, data in events: main.event(run_id, kind, data)
    main.update(run_id, 'failed')
    block = dict(reason='cleanup_unconfirmed', run_id=run_id, block_id='1' * 32, levels=['persistence'])
    with main.db() as conn: recovery.set_state(conn, recovery.CLEANUP_BLOCK, block)
    queries = []
    async def recovered(settings, identity, *, predecessor=None):
        assert settings.installation_id == actor.installation_id
        queries.append((copy.deepcopy(identity), copy.deepcopy(predecessor)))
        expected = a if identity['stage'] == 'actor' else {k: v for k, v in b.items() if k != 'predecessor'}
        assert identity == expected and predecessor == (None if identity['stage'] == 'actor' else a)
        confirmed = mutation != 'unconfirmed-' + ('A' if identity['stage'] == 'actor' else 'B')
        if mutation == 'replace-block':
            with main.db() as conn: recovery.set_state(conn, recovery.CLEANUP_BLOCK, {**block, 'block_id': '2' * 32})
        return {**identity, 'status': 'confirmed' if confirmed else 'unknown', 'cleanup_confirmed': confirmed,
                **({'predecessor': predecessor if confirmed else None} if identity['stage'] == 'fresh' else {})}
    monkeypatch.setattr(actor_client, 'recover_level_receipt', recovered)
    expected = mutation in ('none', 'actor-only')
    assert asyncio.run(main.reconcile_actor_cleanup(actor, block)) is expected
    assert (recovery.read_state(main.DB, recovery.CLEANUP_BLOCK) is None) is expected
    if expected:
        assert len(queries) == (1 if mutation == 'actor-only' else 2)
    assert not persistence_service[2]


@pytest.mark.parametrize('cancel_status', [True, 'unavailable', 'failure'])
def test_fresh_checkpoint_never_allows_cancelled_or_unreadable_status(cancel_status):
    def cancelled():
        if cancel_status == 'failure': raise RuntimeError('durable cancel read failed')
        return cancel_status
    expected = asyncio.CancelledError if cancel_status is True else Exception
    with pytest.raises(expected): asyncio.run(levels._persistence_fresh_checkpoint(cancelled))


def test_fresh_checkpoint_observes_already_pending_task_cancellation():
    async def run():
        task = asyncio.current_task(); task.cancel()
        await levels._persistence_fresh_checkpoint(lambda: False)
        raise AssertionError('pending cancellation was ignored')
    with pytest.raises(asyncio.CancelledError): asyncio.run(run())


def test_real_durable_cancel_read_and_sql_failure_are_not_a_false_permission(persistence_service):
    import sqlite3
    run_id, _ = admit(persistence_service)
    with pytest.raises(runner.RunnerError): main.persistence_cancel_pending(run_id)  # queued
    main.update(run_id, 'running')
    assert main.persistence_cancel_pending(run_id) is False
    with main.db() as conn:
        conn.execute('INSERT INTO run_cancel VALUES (?,?)', (run_id, 'fixture'))
    assert main.persistence_cancel_pending(run_id) is True
    with main.db() as conn: conn.execute('DROP TABLE run_cancel')
    with pytest.raises(sqlite3.OperationalError): main.persistence_cancel_pending(run_id)


def test_durable_cancel_after_a_without_task_signal_prevents_b(persistence_service, monkeypatch):
    run_id, options = admit(persistence_service)
    sessions, held = [], {}
    class Session:
        def __init__(self, stage):
            self.stage = stage; self.cleanup_confirmed = False; self.oom_killed = None; self.profile = None
            self.identity = dict(installation_id=options['level_actor'].installation_id, run_id=run_id,
                level='persistence', stage=stage, context_sha256=options['context'].sha256,
                intent_id='c' * 32, container_id='d' * 64)
            self.predecessor = None
        async def __aenter__(self): return self
        async def __aexit__(self, *args):
            self.cleanup_confirmed = True
            assert asyncio.current_task().cancelling() == 0
            with main.db() as conn: conn.execute('INSERT INTO run_cancel VALUES (?,?)', (run_id, 'fixture-without-task-signal'))
        async def execute(self, command):
            if command.startswith("printf '%s' "):
                import shlex
                held['marker'] = shlex.split(command)[2]
                return {'exit_code': 0, 'stdout': '', 'stderr': ''}
            return {'exit_code': 0, 'stdout': held['marker'], 'stderr': ''}
    def factory(observed_run, level, stage='actor', **kwargs):
        sessions.append(stage)
        assert stage == 'actor', 'fresh was authorized after a durable cancel without a task signal'
        return Session(stage)
    async def complete(*args, **kwargs): return {'content': 'done'}
    monkeypatch.setattr(runner, 'new_level_session', factory)
    monkeypatch.setattr(main.provider, 'complete', complete)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(main.run_levels(run_id, 'fixture', ['persistence'], **options))
    run = main.get_run(run_id)
    assert run['status'] == 'cancelled' and run['summary']['persistence']['cleanup_confirmed'] is True
    assert sessions == ['actor'] and main.cancel_marked(run_id)

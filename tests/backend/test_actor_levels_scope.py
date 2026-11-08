"""Sol's M2 API/context integration tests, separate from the backend-owned codec/client tests."""
import asyncio
import dataclasses
import json
import os
import time

import pytest

from services.agent import invoice_actor_client as actor_client, main, provider, recovery, runner
from test_actor_workflow_scope import SCHEDULE, admitted
pytestmark = pytest.mark.skipif(not hasattr(os, 'geteuid'), reason='actor levels are POSIX only')


@pytest.fixture
def memory_service(admitted, monkeypatch):
    monkeypatch.setenv('ESCAPE_ACTOR_LEVELS', 'memory')
    return admitted


def wait_terminal(client, run_id):
    until = time.monotonic() + 4
    while time.monotonic() < until:
        run = main.get_run(run_id)
        if run['status'] in main.TERMINAL:
            return run
        time.sleep(.005)
    pytest.fail('memory task did not terminate')


def admit(client, level='memory'):
    started = client.post('/api/runs', json={'model': 'fixture', 'levels': [level]})
    assert started.status_code == 202, started.text
    return started.json()['id']


def test_memory_requires_explicit_controller_enablement(admitted):
    client, dispatched, calls = admitted
    assert client.post('/api/runs', json={'model': 'fixture', 'levels': ['memory']}).status_code == 422
    assert not dispatched and not calls


def test_memory_context_is_separate_from_workflow_variant(memory_service):
    client, dispatched, calls = memory_service
    run_id = admit(client)
    _, model, levels, options = dispatched[0]
    assert 'actor' not in options and 'independent' not in options
    assert options['context'].level == 'memory'
    config = main.get_run_config(run_id)
    assert 'mission' not in config and 'actor_boundary' not in config and 'execution_boundary' not in config
    main.validate_level_context(run_id, model, levels, config, options['level_actor'], options['context'])
    with pytest.raises(dataclasses.FrozenInstanceError):
        options['context'].sha256 = 'x'
    assert not calls


@pytest.mark.parametrize('change', ['model', 'levels', 'context', 'stage', 'image'])
def test_changed_level_admission_never_opens_or_infers(memory_service, change):
    client, dispatched, calls = memory_service
    run_id = admit(client)
    _, model, levels, options = dispatched[0]
    config = main.get_run_config(run_id)
    with main.db() as conn:
        if change == 'model':
            conn.execute('UPDATE runs SET model=? WHERE id=?', ('other', run_id))
        elif change == 'levels':
            conn.execute('UPDATE runs SET levels=? WHERE id=?', ('["workflow"]', run_id))
        else:
            if change == 'context': config['extra'] = 'changed'
            elif change == 'stage': config['level_actor_boundary']['stage'] = 'fresh'
            else: config['level_actor_boundary']['image_id'] = 'sha256:' + 'e' * 64
            conn.execute('UPDATE run_config SET config=? WHERE run_id=?', (json.dumps(config), run_id))
    asyncio.run(main.run_levels(run_id, model, levels, **options))
    assert main.get_run(run_id)['status'] == 'failed' and not calls


@pytest.mark.parametrize('increment,outcome', [(False, 'exhausted'), (True, 'blocked')])
def test_memory_handler_uses_level_session_and_keeps_the_existing_oom_oracle(memory_service, monkeypatch, increment, outcome):
    client, _, calls = memory_service
    sessions, provider_calls = [], []

    class Session:
        def __init__(self, run_id, level, *, actor, context_sha256):
            self.identity = {'installation_id': actor.installation_id, 'run_id': run_id, 'level': level,
                'stage': 'actor', 'context_sha256': context_sha256, 'intent_id': 'c' * 32, 'container_id': 'd' * 64}
            self.cleanup_confirmed, self.oom_killed, self.count = False, False, 0
            self.profile = None
        async def __aenter__(self): return self
        async def __aexit__(self, *args): self.cleanup_confirmed = True
        async def cgroup_events(self): return {'oom_kill': self.count}
        async def execute(self, command):
            self.count += int(increment)
            return {'stdout': '', 'stderr': '', 'exit_code': 137 if increment else 0}
        async def measure(self): return runner.unavailable_measurement()

    def factory(*args, **kwargs):
        session = Session(*args, **kwargs)
        sessions.append(session)
        return session

    async def complete(model, messages, **kwargs):
        provider_calls.append(model)
        if any(message['role'] == 'tool' for message in messages):
            return {'role': 'assistant', 'content': 'done'}
        return {'role': 'assistant', 'tool_calls': [{'id': 'fixture', 'function': {
            'name': 'run_shell', 'arguments': json.dumps({'command': 'fixture bounded allocation'})}}]}

    monkeypatch.setattr(runner, 'new_level_session', factory)
    monkeypatch.setattr(provider, 'complete', complete)
    monkeypatch.setattr(main, 'schedule_run', SCHEDULE)
    run = wait_terminal(client, admit(client))
    assert run['status'] == 'completed' and run['summary']['memory']['outcome'] == outcome
    assert run['summary']['memory']['cleanup_confirmed'] is True
    assert len(sessions) == 1 and len(provider_calls) == 2 and not calls
    with main.db() as conn:
        events = [kind for kind, in conn.execute('SELECT kind FROM events WHERE run_id=?', (run['id'],))]
    assert events.count('level_actor_open_requested') == events.count('level_actor_identity') == 1


@pytest.mark.parametrize('mutation,released', [('none', True), ('missing_identity', False), ('context', False), ('unconfirmed', False)])
@pytest.mark.parametrize('level', ['memory', 'secret'])
def test_level_recovery_needs_the_exact_bound_durable_receipt(memory_service, monkeypatch, mutation, released, level):
    client, dispatched, _ = memory_service
    monkeypatch.setenv('ESCAPE_ACTOR_LEVELS', level)
    run_id = admit(client, level)
    options = dispatched[0][3]
    actor, context = options['level_actor'], options['context']
    request = {'installation_id': actor.installation_id, 'run_id': run_id, 'level': level, 'stage': 'actor', 'context_sha256': context.sha256}
    identity = {**request, 'intent_id': 'c' * 32, 'container_id': 'd' * 64}
    main.event(run_id, 'level_actor_open_requested', request)
    if mutation != 'missing_identity':
        main.event(run_id, 'level_actor_identity', {**identity, **({'context_sha256': 'e' * 64} if mutation == 'context' else {})})
    main.update(run_id, 'failed')
    block = {'reason': 'cleanup_unconfirmed', 'run_id': run_id, 'block_id': 'f' * 32, 'levels': [level]}
    with main.db() as conn:
        recovery.set_state(conn, recovery.CLEANUP_BLOCK, block)
    queries = []

    async def recovered(settings, observed):
        queries.append(observed)
        assert observed == identity and settings.installation_id == actor.installation_id
        return {**identity, 'status': 'confirmed' if mutation != 'unconfirmed' else 'unknown',
                'cleanup_confirmed': mutation != 'unconfirmed'}

    monkeypatch.setattr(actor_client, 'recover_level_receipt', recovered, raising=False)
    assert asyncio.run(main.reconcile_actor_cleanup(actor, block)) is released
    assert (recovery.read_state(main.DB, recovery.CLEANUP_BLOCK) is None) is released
    assert len(queries) == (0 if mutation in ('missing_identity', 'context') else 1)


def test_secret_uses_its_own_frozen_context_and_cannot_be_changed_to_memory(memory_service, monkeypatch):
    client, dispatched, calls = memory_service
    monkeypatch.setenv('ESCAPE_ACTOR_LEVELS', 'secret')
    run_id = admit(client, 'secret')
    _, model, levels, options = dispatched[0]
    assert options['context'].level == 'secret' and 'actor' not in options
    config = main.get_run_config(run_id)
    main.validate_level_context(run_id, model, levels, config, options['level_actor'], options['context'])
    config['level_actor_boundary']['level'] = 'memory'
    with main.db() as conn:
        conn.execute('UPDATE run_config SET config=? WHERE run_id=?', (json.dumps(config), run_id))
    asyncio.run(main.run_levels(run_id, model, levels, **options))
    assert main.get_run(run_id)['status'] == 'failed' and not calls

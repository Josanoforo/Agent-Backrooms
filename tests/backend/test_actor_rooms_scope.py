"""M4 controller integration: real SQLite/API and explicit owner/provider doubles."""
import asyncio
import json
import os

import pytest

from services.agent import invoice_actor_client as client, levels, main, recovery, runner
from test_actor_workflow_scope import admitted, INSTALLATION, IMAGE
from test_d2b import CID, IDENTITY, S, call, effective_profile, process_stdout, privilege_data

pytestmark = pytest.mark.skipif(not hasattr(os, 'geteuid'), reason='POSIX controller')


@pytest.fixture
def rooms(admitted, monkeypatch):
    monkeypatch.setenv('ESCAPE_ACTOR_LEVELS', 'processes,privileges')
    monkeypatch.setenv('ESCAPE_ROOMS_EXPERIMENT', '1')
    return admitted


@pytest.mark.parametrize('selected', ['processes', 'privileges'])
def test_remote_room_preserves_classification_context_and_sealed_reopening(rooms, monkeypatch, selected):
    api, dispatched, forbidden = rooms
    response = api.post('/api/runs', json={'model': 'fixture', 'levels': [selected]})
    assert response.status_code == 202, response.text
    run_id, model, requested, options = dispatched[0]
    assert options['context'].level == selected and 'level_actor' in options
    sessions, calls = [], []
    class Session:
        def __init__(self, settings, *, run_id, level, context_sha256):
            self.identity = dict(installation_id=INSTALLATION, run_id=run_id, level=level,
                stage='actor', context_sha256=context_sha256, intent_id='e' * 32, container_id=CID)
            self.profile = effective_profile()
            self.profile_captured, self.cleanup_confirmed, self.cgroup_absent = True, False, None
            self.oom_killed, self.measurement = None, runner.unavailable_measurement()
            sessions.append(self)
        async def __aenter__(self): return self
        async def __aexit__(self, *exc):
            self.cleanup_confirmed = True
            self.cgroup_absent = selected == 'processes' or None
        async def room_action(self):
            calls.append('owner_action')
            process = selected == 'processes'
            return dict(result={'exit_code': 0, 'stderr': '', 'stdout': process_stdout() if process else json.dumps(privilege_data()),
                                **runner.unavailable_measurement()}, container={'container_id': CID},
                cgroup_identity=IDENTITY if process else None, pre=S(2, 0) if process else None,
                during=[S(64, 10)] if process else [], post=S(2, 10) if process else None,
                recheck={'ok': True} if process else None, tool=.1, verification=.01)
    async def complete(*args, **kwargs):
        calls.append('provider')
        assert kwargs['tools'] is levels.provider.ROOM_ACTION_TOOLS
        return {'tool_calls': [call()]}
    monkeypatch.setattr(client, 'RoomActorSession', Session)
    monkeypatch.setattr(levels.provider, 'complete', complete)
    asyncio.run(main.run_levels(run_id, model, requested, **options))
    run = main.get_run(run_id)
    assert run['status'] == 'completed'
    summary = run['summary'][selected]
    assert summary['outcome'] == 'blocked' and summary['cleanup_confirmed'] is True
    assert summary['witness']['container']['container_id'] == CID
    assert summary['witness']['effect']['status'] == 'denied'
    assert summary['witness']['cleanup']['cgroup_absent'] is (True if selected == 'processes' else None)
    assert calls == ['provider', 'owner_action'] and not forbidden
    with main.db() as conn:
        records = [(kind, json.loads(data)) for kind, data in conn.execute(
            "SELECT kind,data FROM events WHERE run_id=? AND kind IN ('level_actor_open_requested','level_actor_identity') ORDER BY seq", (run_id,))]
    assert [kind for kind, _ in records] == ['level_actor_open_requested', 'level_actor_identity']
    assert records[1][1] == sessions[0].identity
    route = f'/api/runs/{run_id}/report'
    raw, md = api.get(route).content, api.get(route, params={'format': 'md'}).content
    assert raw == api.get(route).content and md == api.get(route, params={'format': 'md'}).content
    assert b'"provisional": true' in raw or b'"provisional":true' in raw


@pytest.mark.parametrize('mutation', ['model', 'protocol', 'context'])
def test_changed_room_context_never_opens_or_infers(rooms, monkeypatch, mutation):
    api, dispatched, forbidden = rooms
    assert api.post('/api/runs', json={'model': 'fixture', 'levels': ['processes']}).status_code == 202
    run_id, model, requested, options = dispatched[0]
    with main.db() as conn:
        if mutation == 'model': conn.execute('UPDATE runs SET model=? WHERE id=?', ('other', run_id))
        else:
            config = main.get_run_config(run_id)
            if mutation == 'protocol': config['room_experiment']['action_version'] = 'different'
            else: config['level_actor_boundary']['image_id'] = 'sha256:' + 'f' * 64
            conn.execute('UPDATE run_config SET config=? WHERE run_id=?', (json.dumps(config), run_id))
    def no_session(*args, **kwargs): raise AssertionError('context changed before actor')
    monkeypatch.setattr(client, 'RoomActorSession', no_session)
    asyncio.run(main.run_levels(run_id, model, requested, **options))
    assert main.get_run(run_id)['status'] == 'failed' and not forbidden
    assert 'admission level context changed' in str(main.get_run(run_id)['summary'])


def test_remote_room_still_requires_private_room_enablement(rooms, monkeypatch):
    api, dispatched, forbidden = rooms
    monkeypatch.delenv('ESCAPE_ROOMS_EXPERIMENT')
    assert api.post('/api/runs', json={'model': 'fixture', 'levels': ['processes']}).status_code == 404
    assert not dispatched and not forbidden


def test_remote_room_open_cancel_without_ack_preserves_controller_debt(rooms, monkeypatch):
    api, dispatched, forbidden = rooms
    assert api.post('/api/runs', json={'model': 'fixture', 'levels': ['processes']}).status_code == 202
    run_id, model, requested, options = dispatched[0]
    class Session:
        identity, cleanup_confirmed, cgroup_absent = None, False, None
        def __init__(self, *args, **kwargs): pass
        async def __aenter__(self): raise asyncio.CancelledError()
        async def __aexit__(self, *args): raise AssertionError('context was never entered')
    monkeypatch.setattr(client, 'RoomActorSession', Session)
    with pytest.raises(asyncio.CancelledError): asyncio.run(main.run_levels(run_id, model, requested, **options))
    assert main.get_run(run_id)['summary']['processes']['cleanup_confirmed'] is False
    with main.db() as conn:
        block = recovery.get_state(conn, recovery.CLEANUP_BLOCK)
    assert block['run_id'] == run_id
    assert api.post('/api/runs', json={'model': 'fixture', 'levels': ['processes']}).status_code == 503
    assert not forbidden

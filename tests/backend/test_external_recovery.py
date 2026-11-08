import asyncio
import json

from services.agent.external_bridge import TraceStore
from services.agent import external_recovery


def _seed(path, identity, *, owner='local_docker', closed=0, cleanup=None):
    store = TraceStore(path)
    run_id = 'a' * 32
    store.register(run_id, {'task': 'synthetic', 'fixture': {'oracle': 'preserved'}})
    with store.connect() as conn:
        conn.execute('UPDATE external_sessions SET closed=?,cleanup=? WHERE id=?', (closed, cleanup, run_id))
    store.event(run_id, 'controller', 'resource_pending', {'room': 'work', 'owner': owner, 'identity': identity})
    store.event(run_id, 'external_agent', 'checkpoint', {'marker': 'preserve'})
    return store, run_id


def test_recovery_removes_only_exact_owned_resource_and_preserves_trace(tmp_path, monkeypatch):
    monkeypatch.setattr(external_recovery, 'runtime_supported', lambda: True)
    path = tmp_path / 'state.db'
    identity = {'kind': 'docker_container', 'name': 'escape-' + 'b' * 32,
                'owner_label': 'com.agent-escape-room.owner=controller-v1'}
    store, run_id = _seed(path, identity)
    calls = []

    async def cli(*args, **kwargs):
        calls.append(args)
        if args[:2] == ('inspect', '--format'):
            return (0, 'controller-v1', '')
        if args[:2] == ('inspect', identity['name']):
            return (1, '', 'Error: no such object')
        if args[:2] == ('rm', '-f'):
            return (0, '', '')
        raise AssertionError(args)

    monkeypatch.setattr(external_recovery.runner, '_cli', cli)
    result = external_recovery.recover(path)
    report = store.report(run_id)
    assert result['status'] == 'recovered'
    assert report['cleanup_confirmed'] is True
    assert any(e['kind'] == 'checkpoint' for e in report['events'])
    assert any(e['kind'] == 'interruption' and e['data']['failure_class'] == 'infrastructure_interruption' for e in report['events'])
    assert all(identity['name'] in call or call[:2] == ('inspect', '--format') for call in calls)


def test_missing_identity_keeps_admission_blocked(tmp_path, monkeypatch):
    monkeypatch.setattr(external_recovery, 'runtime_supported', lambda: True)
    path = tmp_path / 'state.db'
    store, run_id = _seed(path, None)
    monkeypatch.setattr(external_recovery.runner, '_cli', lambda *a, **k: (_ for _ in ()).throw(AssertionError('must not call Docker')))
    result = external_recovery.recover(path)
    assert result['status'] == 'blocked'
    assert result['cleanup'][0]['reason'] == 'exact_cleanup_contract_unavailable'
    assert store.report(run_id)['cleanup_confirmed'] is None
    assert not any(e['kind'] == 'interruption' for e in store.report(run_id)['events'])


def test_already_closed_does_not_reopen_or_touch_resources(tmp_path, monkeypatch):
    monkeypatch.setattr(external_recovery, 'runtime_supported', lambda: True)
    path = tmp_path / 'state.db'
    store, run_id = _seed(path, None, closed=1, cleanup=1)
    before = store.report(run_id)
    monkeypatch.setattr(external_recovery.runner, '_cli', lambda *a, **k: (_ for _ in ()).throw(AssertionError('must not call Docker')))
    result = external_recovery.recover(path)
    assert result['status'] == 'already_closed'
    assert store.report(run_id) == before


"""P3 recovery: a cancel request survives a crash, a lost response, a restart and a backup; evidence and quotas stay put.

No inference, no Docker, no network: provider and sandbox are doubles. `raise_server_exceptions=False` lets a deliberately
broken step after the commit show up as the HTTP 500 a real client would see (a response that never arrived).
"""
import asyncio
import contextlib
import json
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from services.agent import budget, experiment, main, provider, recovery, runner
from services.agent import operator as ops

AUTH = {'Authorization': 'Bearer test-operator'}


def sandbox_double(hold=None):
    class Sandbox:
        cleanup_confirmed = False
        oom_killed = None
        async def __aenter__(self): return self
        async def __aexit__(self, *args): self.cleanup_confirmed = True
        async def execute(self, command):
            if hold is not None:
                hold['entered'].set()
                while not hold['release'].is_set(): await asyncio.sleep(.01)
            return {'stdout': '', 'stderr': '', 'exit_code': 0, 'memory_peak_bytes': None}
    return Sandbox


def provider_double(hold=None, calls=None):
    async def complete(model, messages, **kwargs):
        if calls is not None: calls.append(len(messages))
        if hold is not None:
            hold['entered'].set()
            while not hold['release'].is_set(): await asyncio.sleep(.01)
        if any(m.get("role") == "tool" for m in messages): return {'role': 'assistant', 'content': 'done'}
        return {'role': 'assistant', 'tool_calls': [{'id': 't', 'type': 'function', 'function': {'name': 'run_shell', 'arguments': json.dumps({'command': 'echo test'})}}]}
    return complete


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'runs.sqlite'))
    for name in ('VULTR_INFERENCE_KEY', 'ESCAPE_MODEL', 'ESCAPE_OPERATOR_TOKEN', 'ESCAPE_EVIDENCE_ORIGIN'): monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('ESCAPE_MAX_RUNS', '100')
    monkeypatch.setattr(runner, 'Session', sandbox_double())
    main.active.clear(); main.rate_windows.clear()
    with TestClient(main.app, raise_server_exceptions=False) as c: yield c


@pytest.fixture
def holds():
    created = []
    def make():
        hold = {'entered': threading.Event(), 'release': threading.Event()}
        created.append(hold)
        return hold
    yield make
    for hold in created: hold['release'].set()


def configure(monkeypatch):
    monkeypatch.setenv('VULTR_INFERENCE_KEY', 'test-double-key')
    monkeypatch.setenv('ESCAPE_MODEL', 'test-model')
    monkeypatch.setenv('ESCAPE_OPERATOR_TOKEN', 'test-operator')
    async def available(): return True
    monkeypatch.setattr(runner, 'docker_available', available)
    async def image_id(): return None
    monkeypatch.setattr(runner, 'image_id', image_id)


def start(client):
    response = client.post('/api/runs', json={'model': 'test-model', 'levels': ['secret']}, headers=AUTH)
    assert response.status_code == 202, response.text
    return response.json()['id']


def wait_run(client, run_id):
    for _ in range(300):
        data = client.get('/api/runs/' + run_id).json()
        if data['status'] in main.TERMINAL:
            for _ in range(300):
                if not main.active: break
                time.sleep(.01)
            return data
        time.sleep(.01)
    pytest.fail('run did not finish')


def event_kinds(run_id):
    with main.db() as c: return [r[0] for r in c.execute('SELECT kind FROM events WHERE run_id=? ORDER BY seq', (run_id,))]


def cancel(client, run_id):
    return client.post(f'/api/runs/{run_id}/cancel', headers=AUTH)


def admitted(status='queued', origin='real'):
    """A run as admission leaves it (optionally moved to running), with no task: what a crash leaves behind."""
    run_id = uuid.uuid4().hex
    main.admit_run(run_id, 'test-model', ['secret'], experiment.snapshot(None, datetime.now(timezone.utc).isoformat()), origin=origin)
    if status == 'running': main.update(run_id, 'running')
    return run_id


def request(run_id):
    with main.db() as c: return ops.request_cancel(c, run_id)


# ---- restart ---------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('state', ['queued', 'running'])
def test_restart_honours_a_cancel_request_that_never_reached_the_task(client, monkeypatch, state):
    configure(monkeypatch)
    async def forbidden(*args, **kwargs): raise AssertionError('recovery must not call the provider')
    monkeypatch.setattr(provider, 'complete', forbidden)
    marked, plain = admitted(state), admitted(state)
    payload, new = request(marked)
    assert new is True and payload == {'id': marked, 'status': state, 'cancel_requested': True}  # committed, the process "dies" here
    counters = budget.snapshot(main.DB)
    recovered = main.init_db()  # what the next process does at startup
    assert {'id': marked, 'status': 'cancelled', 'how': 'interrupted_cancel_requested'} in recovered
    assert {'id': plain, 'status': 'failed', 'how': 'interrupted'} in recovered  # no request: unchanged behaviour
    run = client.get('/api/runs/' + marked).json()
    assert run['status'] == 'cancelled' and run['summary'] == {'error': recovery.INTERRUPTED_ERROR, 'interrupted': True, 'interrupted_from': state, 'evidence_incomplete': True}
    assert client.get('/api/runs/' + plain).json()['status'] == 'failed'
    assert event_kinds(marked) == ['run'] + (['run'] if state == 'running' else []) + ['cancel_requested', 'run']
    assert budget.snapshot(main.DB) == counters  # quota is neither refunded nor charged
    assert client.get(f'/api/runs/{marked}/report').json()['usage']['measurement']['state'] == 'unavailable'  # unknown, never zero
    assert recovery.read_admission_block(main.DB)['reason'] == 'cleanup_unconfirmed'  # cleanup is still unconfirmed after a crash
    assert main.init_db() == []  # idempotent: nothing leaves queued/running twice


def test_cancel_after_recovery_returns_the_stored_state_without_mutation(client, monkeypatch):
    configure(monkeypatch)
    marked, plain = admitted('running'), admitted('running')  # both before recovery: a crash closes admission until cleanup is confirmed
    request(marked)
    main.init_db()  # `plain` fails as interrupted, never requested
    report, marker = client.get(f'/api/runs/{marked}/report').json(), event_kinds(marked)
    assert cancel(client, marked).json() == {'id': marked, 'status': 'cancelled', 'cancel_requested': True}
    assert event_kinds(marked) == marker and client.get(f'/api/runs/{marked}/report').json() == report
    assert cancel(client, plain).json() == {'id': plain, 'status': 'failed', 'cancel_requested': False}
    assert 'cancel_requested' not in event_kinds(plain)


def test_a_spooled_terminal_outcome_wins_over_the_request_during_recovery(client, monkeypatch):
    configure(monkeypatch)
    run_id = admitted('running')
    request(run_id)
    summary = {'secret': {'outcome': 'error', 'evidence': 'Run cancelled', 'cleanup_confirmed': True}}
    recovery.spool_terminal(main.DB, run_id, {'status': 'cancelled', 'summary': summary, 'usage': None, 'block': None})
    assert {'id': run_id, 'status': 'cancelled', 'how': 'spool_replayed'} in main.init_db()
    assert client.get('/api/runs/' + run_id).json()['summary'] == summary  # replayed as written, not rewritten as interrupted


# ---- a response that never arrived -------------------------------------------------------------------------------------

def test_lost_response_after_the_commit_is_recovered_by_reading_and_repeating(client, monkeypatch, holds):
    configure(monkeypatch)
    calls, hold = [], holds()
    monkeypatch.setattr(provider, 'complete', provider_double(hold=hold, calls=calls))
    run_id = start(client)
    assert hold['entered'].wait(5)
    real, state = main.deliver_cancel, {'broken': True}
    def broken(rid):
        if state['broken']:
            state['broken'] = False
            raise RuntimeError('the answer is lost after the request was committed')
        return real(rid)
    monkeypatch.setattr(main, 'deliver_cancel', broken)
    assert cancel(client, run_id).status_code == 500  # the client never saw an acknowledgement
    item = client.get('/api/runs', headers=AUTH).json()['items'][0]  # ... so it reads the state back instead of guessing
    assert item['id'] == run_id and item['cancel_requested'] is True and item['status'] == 'running'
    assert client.get('/api/runs/' + run_id).json()['status'] == 'running'
    again = cancel(client, run_id)
    assert again.status_code == 200 and again.json() == {'id': run_id, 'status': 'running', 'cancel_requested': True}
    run = wait_run(client, run_id)
    assert run['status'] == 'cancelled' and calls == [2]  # one dispatch: nothing was started again
    assert event_kinds(run_id).count('cancel_requested') == 1


def test_a_cancelled_run_keeps_receipts_hash_and_quota_across_a_recovery_pass(client, monkeypatch, holds):
    configure(monkeypatch)
    hold = holds()
    monkeypatch.setattr(provider, 'complete', provider_double())
    monkeypatch.setattr(runner, 'Session', sandbox_double(hold))
    run_id = start(client)
    assert hold['entered'].wait(5)
    assert cancel(client, run_id).json()['cancel_requested'] is True
    run = wait_run(client, run_id)
    assert run['status'] == 'cancelled' and run['receipts'][-1]['failure_phase'] == 'tool'
    report, quota, kinds = client.get(f'/api/runs/{run_id}/report').json(), budget.snapshot(main.DB), event_kinds(run_id)
    assert main.init_db() == []  # the run is terminal: recovery has nothing to reclassify
    assert client.get(f'/api/runs/{run_id}/report').json() == report and budget.snapshot(main.DB) == quota and event_kinds(run_id) == kinds
    assert ops.aggregator().check_report_hash(report)['status'] == 'verified'


# ---- backup and restore --------------------------------------------------------------------------------------------------

def test_backup_and_restore_keep_provenance_and_the_cancel_request(client, monkeypatch, tmp_path):
    configure(monkeypatch)
    run_id = admitted('running', origin='real')
    request(run_id)
    backup, restored = tmp_path / 'backup.sqlite', tmp_path / 'restored.sqlite'
    recovery.backup_database(main.DB, backup)
    assert recovery.verify_backup(backup)['ok'] is True
    recovery.restore_database(backup, restored)
    with contextlib.closing(sqlite3.connect(str(restored))) as c:
        assert c.execute('SELECT origin FROM run_meta WHERE run_id=?', (run_id,)).fetchone()[0] == 'real'
        assert c.execute('SELECT created_at FROM run_meta WHERE run_id=?', (run_id,)).fetchone()[0]
        assert c.execute('SELECT COUNT(*) FROM run_cancel WHERE run_id=?', (run_id,)).fetchone()[0] == 1
        assert [r[0] for r in c.execute('SELECT kind FROM events WHERE run_id=? ORDER BY seq', (run_id,))] == ['run', 'run', 'cancel_requested']
        assert c.execute('SELECT status FROM runs WHERE id=?', (run_id,)).fetchone()[0] == 'running'  # the copy does not reclassify it


def test_an_older_database_without_the_sidecars_is_upgraded_and_listed_as_unknown(client, monkeypatch):
    configure(monkeypatch)
    legacy = uuid.uuid4().hex
    with main.db() as c:
        c.execute('INSERT INTO runs VALUES(?,?,?,?,?)', (legacy, 'completed', 'm', json.dumps(['secret']), '{}'))
        c.execute('DROP TABLE run_meta')
        c.execute('DROP TABLE run_cancel')
    main.init_db()  # startup creates the sidecars; no historical row is rewritten
    item = next(i for i in client.get('/api/runs', headers=AUTH).json()['items'] if i['id'] == legacy)
    assert item == {'id': legacy, 'status': 'completed', 'model': 'm', 'levels': ['secret'], 'created_at': None, 'origin': 'unknown', 'cancel_requested': False}
    with main.db() as c: assert c.execute('SELECT COUNT(*) FROM run_meta').fetchone()[0] == 0

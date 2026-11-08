"""Recovery and usage integration through the real API with temporary SQLite databases.

Provider and sandbox are test doubles: no paid inference, no Docker, no network, no credentials.
Process death is simulated by leaving the database exactly as a killed process would and then
running the startup recovery again."""
import asyncio
import hashlib
import json
import sqlite3
import threading
import time

import pytest
from fastapi.testclient import TestClient
from services.agent import budget, experiment, main, provider, recovery, runner, usage

IMAGE = 'sha256:' + 'a' * 64
V1_RUN_KEYS = {'id', 'status', 'model', 'levels', 'receipts', 'summary'}
RATE = {'model': 'test-model', 'input_per_million': 1, 'output_per_million': 2, 'effective_date': '2026-11-01', 'source': 'test-fixture'}


class FakeSession:
    cleanup_confirmed = False
    oom_killed = None
    async def __aenter__(self): return self
    async def __aexit__(self, *args): self.cleanup_confirmed = True
    async def execute(self, command):
        return {'stdout': '', 'stderr': '', 'exit_code': 0, 'memory_peak_bytes': None}


class UnconfirmedSession(FakeSession):
    async def __aexit__(self, *args): self.cleanup_confirmed = False


class ForbiddenSession:
    def __init__(self): raise AssertionError('recovery must never start a sandbox')


def prepare(monkeypatch, db):
    monkeypatch.setattr(main, 'DB', db)
    monkeypatch.setenv('ESCAPE_DB', db)
    for name in ('VULTR_INFERENCE_KEY', 'ESCAPE_MODEL', 'ESCAPE_MAX_RUNS', 'ESCAPE_MAX_CALLS', 'ESCAPE_MAX_OUTPUT_TOKENS',
                 'ESCAPE_USAGE_RATE_JSON', 'ESCAPE_CLEANUP_ON_STARTUP'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(runner, 'Session', FakeSession)
    monkeypatch.setattr(main, 'TERMINAL_RETRY_DELAYS', ())  # one attempt per outcome keeps the failure tests fast
    main.active.clear()
    main.pending_terminal.clear()
    main.rate_windows.clear()


@pytest.fixture
def client(tmp_path, monkeypatch):
    prepare(monkeypatch, str(tmp_path / 'runs.sqlite'))
    with TestClient(main.app) as c: yield c


def configure(monkeypatch):
    monkeypatch.setenv('VULTR_INFERENCE_KEY', 'test-double-key')
    monkeypatch.setenv('ESCAPE_MODEL', 'test-model')
    monkeypatch.setenv('ESCAPE_OPERATOR_TOKEN', 'test-operator')
    async def available(): return True
    async def image(): return IMAGE
    monkeypatch.setattr(runner, 'docker_available', available)
    monkeypatch.setattr(runner, 'image_id', image)


def done_provider(monkeypatch):
    async def complete(model, messages): return {'role': 'assistant', 'content': 'done'}
    monkeypatch.setattr(provider, 'complete', complete)


def one_receipt_provider(monkeypatch):
    async def complete(model, messages):
        if any(m.get("role") == "tool" for m in messages): return {'role': 'assistant', 'content': 'done'}
        return {'role': 'assistant', 'tool_calls': [{'id': 't', 'function': {'name': 'run_shell', 'arguments': json.dumps({'command': 'echo hi'})}}]}
    monkeypatch.setattr(provider, 'complete', complete)


def post_run(client):
    client.headers['Authorization'] = 'Bearer test-operator'
    return client.post('/api/runs', json={'model': 'test-model', 'levels': ['secret']})


def start(client, monkeypatch, complete=None):
    if complete is None: done_provider(monkeypatch)
    else: monkeypatch.setattr(provider, 'complete', complete)
    response = post_run(client)
    assert response.status_code == 202
    return response.json()['id']


def wait_for(predicate, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate(): return
        time.sleep(.01)
    pytest.fail('condition not reached')


def wait_run(client, run_id):
    for _ in range(300):
        data = client.get('/api/runs/' + run_id).json()
        if data['status'] in main.TERMINAL: return data
        time.sleep(.01)
    pytest.fail('run did not finish')


def count(table, where='1=1', args=()):
    with main.db() as c:
        return c.execute('SELECT COUNT(*) FROM ' + table + ' WHERE ' + where, args).fetchone()[0]


def run_events(run_id, status=None):
    with main.db() as c:
        data = [json.loads(r[0]) for r in c.execute("SELECT data FROM events WHERE run_id=? AND kind='run' ORDER BY seq", (run_id,))]
    return [d for d in data if status is None or d['status'] == status]


def recomputed_hash(report):
    body = {k: v for k, v in report.items() if k != 'sha256'}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


def admit(run_id, levels=None):
    main.admit_run(run_id, 'test-model', levels or ['secret'], experiment.snapshot(IMAGE, '2026-11-06T00:00:00+00:00'))


def parse_sse(text):
    events = []
    for chunk in text.split('\n\n'):
        if not chunk.strip(): continue
        fields = dict(line.split(': ', 1) for line in chunk.split('\n'))
        events.append((int(fields['id']), fields['event'], json.loads(fields['data'])))
    return events


# ------------------------------------------------------------------ admission

def test_failed_admission_leaves_no_run_event_configuration_or_reservation(client, monkeypatch):
    configure(monkeypatch)
    before = budget.snapshot(main.DB)

    def boom(*args, **kwargs):
        raise sqlite3.OperationalError('disk I/O error')
    with monkeypatch.context() as patch:
        patch.setattr(main, 'insert_event', boom)  # the first event is the last write of the admission transaction
        done_provider(patch)
        response = post_run(client)
    assert response.status_code == 503 and 'nothing was reserved' in response.json()['detail']
    assert count('runs') == count('run_config') == count('events') == 0
    assert budget.snapshot(main.DB) == before and not main.active
    run_id = start(client, monkeypatch)  # the service is healthy afterwards and spends exactly one run
    wait_run(client, run_id)
    assert budget.snapshot(main.DB)['runs_remaining'] == before['runs_remaining'] - 1


def test_confirmed_admission_is_complete_even_if_the_process_dies_before_dispatch(client):
    run_id = 'c' * 32
    before = budget.snapshot(main.DB)
    admit(run_id)
    assert count('runs') == count('run_config') == count('events', "run_id=?", (run_id,)) == 1
    assert budget.snapshot(main.DB)['runs_remaining'] == before['runs_remaining'] - 1
    assert main.init_db() == [{'id': run_id, 'status': 'failed', 'how': 'interrupted'}]  # restart: never dispatched
    data = client.get('/api/runs/' + run_id).json()
    assert data['status'] == 'failed' and data['summary'] == recovery.interrupted_summary('queued')
    assert budget.snapshot(main.DB)['runs_remaining'] == before['runs_remaining'] - 1  # the reservation is kept, not refunded
    assert len(run_events(run_id, 'failed')) == 1


# ------------------------------------------------------------------ restart after an abrupt stop

def crash_mid_run(run_id):
    """State of a killed process: admitted, running, one receipt, usage checkpoint, one more call reserved."""
    admit(run_id)
    main.update(run_id, 'running')
    with usage.collect(run_id=run_id) as collector:
        collector.begin_attempt('test-model').record_response(200, {'model': 'test-model', 'usage': {'prompt_tokens': 11, 'completion_tokens': 6}})
        main.event(run_id, 'receipt', {'id': 'rc1', 'run_id': run_id, 'level': 'secret', 'step': 1})
    budget.reserve(main.DB, 'call')  # a request in flight whose answer was never recorded


def test_restart_fails_the_run_once_keeps_evidence_quotas_and_never_reexecutes(client, monkeypatch):
    async def forbidden(*args, **kwargs): raise AssertionError('recovery must never call the provider')
    monkeypatch.setattr(provider, 'complete', forbidden)
    monkeypatch.setattr(runner, 'Session', ForbiddenSession)
    run_id = 'd' * 32
    crash_mid_run(run_id)
    quota = budget.snapshot(main.DB)
    assert main.init_db() == [{'id': run_id, 'status': 'failed', 'how': 'interrupted'}]
    data = client.get('/api/runs/' + run_id).json()
    assert set(data) == V1_RUN_KEYS and data['status'] == 'failed'
    assert data['summary']['error'] == 'Service restarted during run'
    assert data['summary']['evidence_incomplete'] is True and data['summary']['interrupted_from'] == 'running'
    assert [r['id'] for r in data['receipts']] == ['rc1']
    assert budget.snapshot(main.DB) == quota  # quotas as they were: the reserved call is not refunded or added
    assert len(run_events(run_id, 'failed')) == 1
    report = client.get(f'/api/runs/{run_id}/report').json()
    measured = report['usage']
    assert report['final'] is True and measured['measurement'] == {'state': 'interrupted', 'collection_finished': False, 'reason': 'process_restart'}
    assert measured['attempts_total'] == 1 and measured['tokens']['total_tokens'] == 17  # what was recorded, nothing invented
    assert measured['tokens']['lower_bound'] is True and measured['coverage']['complete'] is False and measured['cost_usd'] is None
    assert report['sha256'] == recomputed_hash(report)
    # A second start finds nothing to recover: no new event, no change.
    assert main.init_db() == []
    assert len(run_events(run_id, 'failed')) == 1 and budget.snapshot(main.DB) == quota
    assert [r['id'] for r in client.get('/api/runs/' + run_id).json()['receipts']] == ['rc1']


def test_restart_without_any_checkpoint_marks_usage_unavailable_not_zero(client):
    run_id = 'e' * 32
    admit(run_id)
    main.update(run_id, 'running')
    main.init_db()
    measured = client.get(f'/api/runs/{run_id}/report').json()['usage']
    assert measured['measurement']['state'] == 'unavailable' and measured['attempts_total'] is None and measured['tokens'] is None


def test_startup_after_a_crash_reopens_admission_only_when_cleanup_is_confirmed(client, monkeypatch):
    configure(monkeypatch)
    done_provider(monkeypatch)
    crash_mid_run('f' * 32)
    async def inventory_fails(): raise runner.RunnerError('Owned resource inventory failed')
    monkeypatch.setattr(runner, 'cleanup_owned', inventory_fails)
    asyncio.run(main.startup())  # implicit retry: failure keeps admission closed, startup does not abort
    assert client.get('/api/config').json()['admission_blocked'] == 'cleanup_unconfirmed'
    before = budget.snapshot(main.DB)
    response = post_run(client)
    assert response.status_code == 503 and 'cleanup' in response.json()['detail'].lower()
    assert budget.snapshot(main.DB) == before
    async def inventory_clean(): return None
    monkeypatch.setattr(runner, 'cleanup_owned', inventory_clean)
    asyncio.run(main.startup())
    assert client.get('/api/config').json()['admission_blocked'] is None
    wait_run(client, start(client, monkeypatch))


def test_forced_startup_cleanup_failure_still_aborts_startup(client, monkeypatch):
    # Limit the injected failure to startup; the fixture must still shut down normally.
    with monkeypatch.context() as scoped:
        scoped.setenv('ESCAPE_CLEANUP_ON_STARTUP', '1')
        async def inventory_fails(): raise runner.RunnerError('Owned resource inventory failed')
        scoped.setattr(runner, 'cleanup_owned', inventory_fails)
        with pytest.raises(runner.RunnerError):
            asyncio.run(main.startup())


@pytest.mark.parametrize('cancelled', [False, True])
def test_interrupted_processes_keep_admission_closed_after_docker_sweep(client, monkeypatch, cancelled):
    configure(monkeypatch)
    run_id, neighbour = '1' * 32, '2' * 32
    admit(run_id, ['processes'])
    main.update(run_id, 'running')
    admit(neighbour)
    if cancelled:
        with main.db() as conn:
            conn.execute('INSERT INTO run_cancel VALUES (?, ?)', (run_id, recovery.now_iso()))
    quota = budget.snapshot(main.DB)

    async def sweep(): pass
    async def forbidden(*args, **kwargs): pytest.fail('recovery must never call the provider')
    monkeypatch.setattr(runner, 'cleanup_owned', sweep)
    monkeypatch.setattr(runner, 'Session', ForbiddenSession)
    monkeypatch.setattr(provider, 'complete', forbidden)

    asyncio.run(main.startup())
    block = recovery.read_state(main.DB, recovery.CLEANUP_BLOCK)
    assert block['run_id'] == run_id and block['levels'] == ['processes']
    assert asyncio.run(main.retry_cleanup()) is False
    asyncio.run(main.startup())
    assert recovery.read_state(main.DB, recovery.CLEANUP_BLOCK) == block
    assert len(run_events(run_id, 'cancelled' if cancelled else 'failed')) == 1
    assert len(run_events(neighbour, 'failed')) == 1
    assert client.get('/api/config').json()['admission_blocked'] == 'cleanup_unconfirmed'
    assert post_run(client).status_code == 503
    assert budget.snapshot(main.DB) == quota


def test_queued_processes_never_started_and_a_successful_sweep_clears_the_block(client, monkeypatch):
    run_id = '4' * 32
    admit(run_id, ['processes'])
    async def sweep(): pass
    monkeypatch.setattr(runner, 'cleanup_owned', sweep)
    asyncio.run(main.startup())
    assert len(run_events(run_id, 'failed')) == 1
    assert recovery.read_state(main.DB, recovery.CLEANUP_BLOCK) is None


@pytest.mark.parametrize(('levels', 'retain'), [
    ('[]', True), ('["processes"]', True), ('["secret"]', False), ('["proceses"]', True), ('broken', True), (None, True),
])
def test_startup_checks_the_run_of_a_legacy_cleanup_block(client, monkeypatch, levels, retain):
    run_id = '3' * 32
    block = {'block_id': 'legacy', 'run_id': run_id, 'cause': 'interrupted_run'}
    with main.db() as conn:
        if levels is not None:
            conn.execute('INSERT INTO runs VALUES (?,?,?,?,?)', (run_id, 'failed', 'test-model', levels, '{}'))
        recovery.set_state(conn, recovery.CLEANUP_BLOCK, block)
    async def sweep(): pass
    monkeypatch.setattr(runner, 'cleanup_owned', sweep)
    asyncio.run(main.startup())
    assert recovery.read_state(main.DB, recovery.CLEANUP_BLOCK) == (block if retain else None)


@pytest.mark.parametrize('block', [
    None, {'levels': ['secret']},
    {'block_id': 'unlinked', 'run_id': 'missing', 'cause': 'interrupted_run', 'interrupted_from': 'queued', 'levels': ['processes']},
])
def test_startup_keeps_cleanup_closed_for_an_invalid_block(client, monkeypatch, block):
    configure(monkeypatch)
    with main.db() as conn:
        recovery.set_state(conn, recovery.CLEANUP_BLOCK, block)
    quota = budget.snapshot(main.DB)
    async def sweep(): pass
    monkeypatch.setattr(runner, 'cleanup_owned', sweep)
    asyncio.run(main.startup())
    with main.db() as conn:
        assert json.loads(conn.execute('SELECT value FROM ops_state WHERE key=?', (recovery.CLEANUP_BLOCK,)).fetchone()[0]) == block
    assert post_run(client).status_code == 503
    assert budget.snapshot(main.DB) == quota


@pytest.mark.parametrize(('persisted', 'claimed', 'interrupted_from'), [
    ('processes', 'secret', 'running'), ('secret', 'processes', 'queued'), (None, 'secret', 'queued'),
])
def test_startup_keeps_an_interrupted_block_when_levels_do_not_match(client, monkeypatch, persisted, claimed, interrupted_from):
    run_id = '5' * 32
    block = {'block_id': 'mismatched', 'run_id': run_id, 'cause': 'interrupted_run', 'levels': [claimed]}
    with main.db() as conn:
        if persisted is not None:
            conn.execute('INSERT INTO runs VALUES (?,?,?,?,?)',
                         (run_id, 'failed', 'test-model', json.dumps([persisted]), json.dumps(recovery.interrupted_summary(interrupted_from))))
        recovery.set_state(conn, recovery.CLEANUP_BLOCK, block)
    async def sweep(): pass
    monkeypatch.setattr(runner, 'cleanup_owned', sweep)
    asyncio.run(main.startup())
    assert recovery.read_state(main.DB, recovery.CLEANUP_BLOCK) == block


@pytest.mark.parametrize('has_block', [False, True])
def test_startup_does_not_admit_after_cleanup_state_read_fails(client, monkeypatch, has_block):
    configure(monkeypatch)
    block = {'block_id': 'process', 'levels': ['processes']} if has_block else None
    if block is not None:
        with main.db() as conn:
            recovery.set_state(conn, recovery.CLEANUP_BLOCK, block)
    quota = budget.snapshot(main.DB)
    async def sweep(): pass
    def fail(*args): raise sqlite3.OperationalError('read failed')
    monkeypatch.setattr(runner, 'cleanup_owned', sweep)
    with monkeypatch.context() as patch:
        patch.setattr(recovery, 'read_state', fail)
        asyncio.run(main.startup())
    assert recovery.read_state(main.DB, recovery.CLEANUP_BLOCK) == block
    assert client.get('/api/config').json()['admission_blocked'] == 'state_unavailable'
    assert post_run(client).status_code == 503
    assert budget.snapshot(main.DB) == quota


@pytest.mark.parametrize('startup', [False, True])
@pytest.mark.parametrize('replace', [False, True])
def test_successful_sweep_clears_only_the_same_readable_cleanup_block(client, monkeypatch, startup, replace):
    block = {'block_id': 'ordinary', 'levels': ['secret']}
    replacement = {'block_id': 'new', 'levels': ['processes']}
    with main.db() as conn:
        recovery.set_state(conn, recovery.CLEANUP_BLOCK, block)

    def fail(*args): raise sqlite3.OperationalError('read after sweep failed')
    with monkeypatch.context() as patch:
        async def sweep():
            if replace:
                with main.db() as conn:
                    recovery.set_state(conn, recovery.CLEANUP_BLOCK, replacement)
            else:
                patch.setattr(recovery, 'get_state', fail)
        patch.setattr(runner, 'cleanup_owned', sweep)
        if startup:
            asyncio.run(main.startup())
        else:
            assert asyncio.run(main.retry_cleanup()) is False
    assert recovery.read_state(main.DB, recovery.CLEANUP_BLOCK) == (replacement if replace else block)


# ------------------------------------------------------------------ terminal write failure

def broken_terminal_run(client, monkeypatch):
    configure(monkeypatch)
    one_receipt_provider(monkeypatch)
    real = recovery.write_terminal
    state = {'broken': True}
    def flaky(*args, **kwargs):
        if state['broken']: raise sqlite3.OperationalError('database is locked')
        return real(*args, **kwargs)
    monkeypatch.setattr(recovery, 'write_terminal', flaky)
    run_id = post_run(client).json()['id']
    wait_for(lambda: not main.active and run_id in main.pending_terminal)
    return run_id, state


def test_terminal_write_failure_keeps_receipts_releases_active_and_recovers_without_new_calls(client, monkeypatch):
    before = budget.snapshot(main.DB)
    run_id, state = broken_terminal_run(client, monkeypatch)
    data = client.get('/api/runs/' + run_id).json()  # SQLite still refuses: the stored state is the last committed one
    assert data['status'] == 'running' and len(data['receipts']) == 1
    assert not main.active  # the identifier is not held forever
    assert recovery.load_spool(main.DB)[run_id]['status'] == 'completed'  # recovery path on disk
    config = client.get('/api/config').json()
    assert config['run_available'] is False and config['admission_blocked'] == 'terminal_state_unpersisted'
    response = post_run(client)
    assert response.status_code == 503 and 'not persisted' in response.json()['detail']
    state['broken'] = False  # SQLite is healthy again: the next read finishes the interrupted write
    data = client.get('/api/runs/' + run_id).json()
    assert data['status'] == 'completed' and len(data['receipts']) == 1
    assert main.pending_terminal == {} and recovery.load_spool(main.DB) == {}
    assert len(run_events(run_id, 'completed')) == 1
    report = client.get(f'/api/runs/{run_id}/report').json()
    assert report['usage']['measurement']['state'] == 'final'
    after = budget.snapshot(main.DB)
    assert after['runs_remaining'] == before['runs_remaining'] - 1 and after['calls_remaining'] == before['calls_remaining']  # no other call added
    wait_run(client, post_run(client).json()['id'])  # admission works again


def test_restart_replays_the_spooled_terminal_outcome_instead_of_failing_the_run(client, monkeypatch):
    run_id, state = broken_terminal_run(client, monkeypatch)
    state['broken'] = False
    main.pending_terminal.clear()  # the process died: memory is gone; SQLite and the spool file remain
    assert main.init_db() == [{'id': run_id, 'status': 'completed', 'how': 'spool_replayed'}]
    data = client.get('/api/runs/' + run_id).json()
    assert data['status'] == 'completed' and data['summary']['secret']['outcome'] == 'exhausted' and len(data['receipts']) == 1
    assert 'interrupted' not in data['summary']
    assert recovery.load_spool(main.DB) == {} and len(run_events(run_id)) == 3  # queued, running, completed: once each
    assert main.init_db() == []


# ------------------------------------------------------------------ unconfirmed cleanup

def test_unconfirmed_cleanup_closes_admission_until_it_is_recovered(client, monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(runner, 'Session', UnconfirmedSession)
    async def inventory_fails(): raise runner.RunnerError('Owned resource cleanup could not be confirmed')
    monkeypatch.setattr(runner, 'cleanup_owned', inventory_fails)
    before = budget.snapshot(main.DB)
    run = wait_run(client, start(client, monkeypatch))
    assert run['summary']['secret']['cleanup_confirmed'] is False
    config = client.get('/api/config').json()
    assert config['run_available'] is False and config['admission_blocked'] == 'cleanup_unconfirmed' and config['restored_blocked'] is False
    response = post_run(client)
    assert response.status_code == 503
    assert budget.snapshot(main.DB)['runs_remaining'] == before['runs_remaining'] - 1  # the refused request reserved nothing
    async def inventory_clean(): return None
    monkeypatch.setattr(runner, 'cleanup_owned', inventory_clean)
    asyncio.run(main.startup())
    monkeypatch.setattr(runner, 'Session', FakeSession)
    assert client.get('/api/config').json()['admission_blocked'] is None
    wait_run(client, post_run(client).json()['id'])


def test_cleanup_confirmed_right_after_the_run_reopens_admission(client, monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(runner, 'Session', UnconfirmedSession)
    async def inventory_clean(): return None
    monkeypatch.setattr(runner, 'cleanup_owned', inventory_clean)
    run = wait_run(client, start(client, monkeypatch))
    assert run['summary']['secret']['cleanup_confirmed'] is False  # the level's own report is not rewritten
    wait_for(lambda: client.get('/api/config').json()['admission_blocked'] is None)


# ------------------------------------------------------------------ SSE reconnection

def test_sse_reconnect_with_last_event_id_is_ordered_deduplicated_and_closes(client, monkeypatch):
    configure(monkeypatch)
    one_receipt_provider(monkeypatch)
    run_id = post_run(client).json()['id']
    wait_run(client, run_id)
    url = f'/api/runs/{run_id}/events'
    full = parse_sse(client.get(url).text)
    ids = [e[0] for e in full]
    assert len(ids) >= 4 and ids == sorted(set(ids))  # strictly increasing, no duplicates
    assert full[-1][1] == 'run' and full[-1][2]['status'] == 'completed'
    assert [e[1] for e in full].count('receipt') == 1
    cut = ids[2]
    tail = parse_sse(client.get(url, headers={'Last-Event-ID': str(cut)}).text)
    assert [e[0] for e in tail] == [i for i in ids if i > cut]  # exactly what came after the cursor
    assert [e[0] for e in full if e[0] <= cut] + [e[0] for e in tail] == ids  # joined streams show no duplicate or gap
    assert client.get(url, headers={'Last-Event-ID': str(ids[-1])}).text == ''  # terminal and nothing newer: closes at once
    assert client.get(url, headers={'Last-Event-ID': '999999'}).text == ''
    assert client.get(url, headers={'Last-Event-ID': 'not-a-number'}).status_code == 400
    assert client.get('/api/runs/absent/events').status_code == 404


def test_stream_opened_before_the_end_still_delivers_the_terminal_event_and_closes(client):
    run_id = '1' * 32
    admit(run_id)
    main.update(run_id, 'running')
    outcome = {}
    def reader():
        with client.stream('GET', f'/api/runs/{run_id}/events') as response:
            outcome['text'] = ''.join(response.iter_text())
    thread = threading.Thread(target=reader)
    thread.start()
    time.sleep(.6)  # the stream is polling a run that is not terminal yet
    with main.db() as c:
        recovery.write_terminal(c, run_id, 'failed', {'error': 'x'}, None)
    thread.join(10)
    assert not thread.is_alive()
    events = parse_sse(outcome['text'])
    assert [e[0] for e in events] == sorted(set(e[0] for e in events))
    assert events[-1][1] == 'run' and events[-1][2]['status'] == 'failed'
    assert [e[2]['status'] for e in events] == ['queued', 'running', 'failed']


# ------------------------------------------------------------------ restored state

def test_restored_database_refuses_runs_until_reconciled_with_current_counters(tmp_path, monkeypatch):
    live, copy, restored = (str(tmp_path / n) for n in ('live.sqlite', 'copy.sqlite', 'restored.sqlite'))
    prepare(monkeypatch, live)
    main.init_db()
    budget.reserve(live, 'run')
    recovery.backup_database(live, copy)
    result = recovery.restore_database(copy, restored)
    budget.reserve(live, 'run')  # the live service kept going after the copy
    budget.reserve(live, 'call')
    monkeypatch.setattr(main, 'DB', restored)
    monkeypatch.setenv('ESCAPE_DB', restored)
    configure(monkeypatch)
    done_provider(monkeypatch)
    with TestClient(main.app) as client:
        config = client.get('/api/config').json()
        assert config['restored_blocked'] is True and config['run_available'] is False and config['admission_blocked'] == 'restored_state_unreconciled'
        before = budget.snapshot(restored)
        response = post_run(client)
        assert response.status_code == 503 and 'reconciled' in response.json()['detail']
        assert budget.snapshot(restored) == before and count('runs') == 0
        with pytest.raises(recovery.RecoveryError):  # restoring old quotas as they were is refused
            recovery.reconcile_restored(restored, result['block_id'], {'runs': 0, 'calls': 0, 'output_tokens_reserved': 0}, 'stale numbers')
        assert post_run(client).status_code == 503
        recovery.reconcile_restored(restored, result['block_id'], recovery.counters_of_database(live), 'counters read from the live database after the copy')
        assert client.get('/api/config').json()['restored_blocked'] is False
        assert budget.snapshot(restored) == budget.snapshot(live)  # reservations made after the copy are not forgotten
        run = wait_run(client, post_run(client).json()['id'])
        assert run['status'] == 'completed'
        assert budget.snapshot(restored)['runs_remaining'] == budget.snapshot(live)['runs_remaining'] - 1


# ------------------------------------------------------------------ usage in reports

def test_report_adds_usage_for_new_runs_and_keeps_the_v1_run_shape(client, monkeypatch):
    configure(monkeypatch)
    monkeypatch.setenv('ESCAPE_USAGE_RATE_JSON', json.dumps(RATE))
    async def complete(model, messages):
        usage.begin_attempt(model).record_response(200, {'model': model, 'id': 'resp-1', 'usage': {'prompt_tokens': 10, 'completion_tokens': 5, 'completion_tokens_details': {'reasoning_tokens': 2}}})
        return {'role': 'assistant', 'content': 'done'}
    run = wait_run(client, start(client, monkeypatch, complete))
    assert set(run) == V1_RUN_KEYS
    report = client.get(f"/api/runs/{run['id']}/report").json()
    measured = report['usage']
    assert measured['schema'] == 'usage-summary/v1' and measured['attempts_total'] == 1
    assert measured['measurement'] == {'state': 'final', 'collection_finished': True}
    assert measured['tokens']['total_tokens'] == 15 and measured['tokens']['reasoning_tokens_included_in_completion'] == 2
    assert measured['coverage']['complete'] is True
    assert measured['cost']['status'] == 'estimated_complete' and measured['cost_usd'] == pytest.approx(0.00002)
    assert measured['cost']['estimate'] is True and measured['cost']['rate']['source'] == 'test-fixture'
    assert measured['attempts'][0]['returned_model'] == 'test-model' and 'test-double-key' not in json.dumps(report)
    assert report['sha256'] == recomputed_hash(report)


def test_run_without_a_rate_has_tokens_but_no_invented_dollars(client, monkeypatch):
    configure(monkeypatch)
    async def complete(model, messages):
        usage.begin_attempt(model).record_response(200, {'model': model, 'usage': {'prompt_tokens': 4, 'completion_tokens': 1}})
        return {'role': 'assistant', 'content': 'done'}
    run = wait_run(client, start(client, monkeypatch, complete))
    measured = client.get(f"/api/runs/{run['id']}/report").json()['usage']
    assert measured['tokens']['total_tokens'] == 5 and measured['cost_usd'] is None and measured['cost']['status'] == 'not_estimated'
    assert client.get('/api/config').json()['usage_cost_estimate'] == 'not_configured'


def test_invalid_rate_does_not_break_the_run_and_is_reported_as_invalid(client, monkeypatch):
    configure(monkeypatch)
    monkeypatch.setenv('ESCAPE_USAGE_RATE_JSON', json.dumps({**RATE, 'source': ''}))
    async def complete(model, messages):
        usage.begin_attempt(model).record_response(200, {'model': model, 'usage': {'prompt_tokens': 4, 'completion_tokens': 1}})
        return {'role': 'assistant', 'content': 'done'}
    run = wait_run(client, start(client, monkeypatch, complete))
    assert run['status'] == 'completed'
    measured = client.get(f"/api/runs/{run['id']}/report").json()['usage']
    assert measured['cost_usd'] is None and measured['cost']['status'] == 'rate_invalid'
    assert client.get('/api/config').json()['usage_cost_estimate'] == 'invalid'


def test_failed_run_saves_usage_with_unknown_tokens_not_zero(client, monkeypatch):
    configure(monkeypatch)
    async def complete(model, messages):
        usage.begin_attempt(model).fail('timeout', TimeoutError())
        raise provider.ProviderError('Vultr inference request failed')
    run = wait_run(client, start(client, monkeypatch, complete))
    assert run['status'] == 'failed'
    wait_for(lambda: not main.active)
    measured = client.get(f"/api/runs/{run['id']}/report").json()['usage']
    assert measured['attempts_total'] == 1 and measured['attempts'][0]['status'] == 'timeout'
    assert measured['tokens']['total_tokens'] is None and measured['coverage']['complete'] is False and measured['coverage']['unknown_calls'] == 1
    assert measured['cost_usd'] is None and measured['measurement']['state'] == 'final'  # collection finished; consumption unknown


def test_cancelled_run_saves_usage_before_releasing_the_active_slot(client, monkeypatch):
    configure(monkeypatch)
    async def complete(model, messages):
        usage.begin_attempt(model).abandon()  # what the adapter's finally does for a cancelled request
        raise asyncio.CancelledError()
    run = wait_run(client, start(client, monkeypatch, complete))
    assert run['status'] == 'cancelled' and run['summary']['secret']['evidence'] == 'Run cancelled'
    wait_for(lambda: not main.active)
    measured = client.get(f"/api/runs/{run['id']}/report").json()['usage']
    assert measured['attempts'][0]['status'] == 'cancelled' and measured['tokens']['total_tokens'] is None
    assert len(run_events(run['id'], 'cancelled')) == 1


def test_historical_report_never_gains_a_usage_field(client):
    with main.db() as c:
        c.execute("INSERT INTO runs VALUES('old','completed','m','[\"secret\"]','{}')")
        recovery.save_usage(c, 'old', recovery.unavailable_usage('old', 'x'), 'unavailable', overwrite=True)
    report = client.get('/api/runs/old/report').json()
    assert set(report) == {'run', 'experiment', 'sha256'} and report['sha256'] == recomputed_hash(report)

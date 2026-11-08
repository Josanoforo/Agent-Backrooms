"""Opt-in M3 API proof in the isolated controller, with provider doubles only."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shlex
import socket
import threading
import time

import pytest
from fastapi.testclient import TestClient

from services.agent import experiment, invoice_actor_client as actor_client, main, missions, provider, runner
from test_d3_catalog_docker import SOLVER

pytestmark = pytest.mark.skipif(os.getenv('AER_TEST_CATALOG_SERVICE') != '1', reason='isolated M3 owner fixture')


def setup(monkeypatch, tmp_path):
    assert os.geteuid() == 65534 and os.getgroups() == [] and socket.if_nameindex() == [(1, 'lo')]
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    assert all(int(status[k], 16) == 0 for k in ('CapEff', 'CapPrm', 'CapBnd', 'CapAmb'))
    assert int(status['NoNewPrivs']) == 1 and not os.listdir('/mnt')
    denied = {}
    for path in json.loads(os.environ['ESCAPE_TEST_DOCKER_ENDPOINTS']):
        with socket.socket(socket.AF_UNIX) as peer:
            try: peer.connect(path)
            except OSError as exc: denied[path] = exc.errno
            else: pytest.fail('controller reached daemon')
    for path in json.loads(os.environ['ESCAPE_TEST_OWNER_JOURNALS']):
        with pytest.raises(PermissionError): os.listdir(path)
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'catalog.sqlite'))
    main.rate_windows.clear()
    async def forbidden(*args, **kwargs): raise AssertionError('controller invoked direct Docker')
    monkeypatch.setattr(runner, '_cli', forbidden)
    return denied


def start(api, selected='B', variant='legitimate'):
    response = api.post('/api/runs', json={'model': 'fixture', 'levels': ['workflow'],
        'mission': missions.INVOICE_CATALOG.id, 'catalog_profile': selected, 'catalog_variant': variant})
    assert response.status_code == 202, response.text
    return response.json()['id']


def wait(api, run_id):
    until = time.monotonic() + 85
    while time.monotonic() < until:
        run = api.get('/api/runs/' + run_id).json()
        if run['status'] in main.TERMINAL: return run
        time.sleep(.025)
    pytest.fail('catalog run did not terminate')


def report(api, run_id):
    path = f'/api/runs/{run_id}/report'
    raw, md = api.get(path), api.get(path, params={'format': 'md'})
    assert raw.status_code == md.status_code == 200
    data = raw.json(); core = {k: v for k, v in data.items() if k != 'sha256'}
    assert hashlib.sha256(json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == data['sha256']
    if os.environ.get('AER_CATALOG_EXPORT_DIR'):
        directory = Path(os.environ['AER_CATALOG_EXPORT_DIR'])
        for suffix, content in (('.json', raw.content), ('.md', md.content)):
            with (directory / (run_id + suffix)).open('xb') as saved: saved.write(content)
    return path, raw.content, md.content, data['sha256']


def emit(**fields):
    print('CATALOG_API_PROOF=' + json.dumps(dict(controller_uid=os.geteuid(), controller_pid=os.getpid(), **fields), sort_keys=True), flush=True)


def test_catalog_four_cells_and_reopened_reports(monkeypatch, tmp_path):
    denied = setup(monkeypatch, tmp_path)
    sessions, calls, saved, cells = [], [], [], []
    actual = actor_client.CatalogActorSession
    commands = []
    def tracked(settings, **fields):
        session = actual(settings, **fields); sessions.append(session)
        commands[:] = ["grep ' /catalog.json ' /proc/self/mountinfo"]
        if fields['variant'] == 'perturbed':
            commands.append("printf '%s\\n' '/catalog.json: Permission denied' >&2")
        commands.append('python -c ' + shlex.quote(SOLVER))
        return session
    async def complete(model, messages):
        calls.append(model)
        if not commands: return {'content': 'done'}
        return {'role': 'assistant', 'tool_calls': [{'id': 'fixture', 'function': {
            'name': 'run_shell', 'arguments': json.dumps({'command': commands.pop(0)})}}]}
    monkeypatch.setattr(actor_client, 'CatalogActorSession', tracked)
    monkeypatch.setattr(provider, 'complete', complete)
    with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as api:
        for selected in ('A', 'B'):
            for variant in ('legitimate', 'perturbed'):
                run_id = start(api, selected, variant); run = wait(api, run_id)
                summary = run['summary']['workflow']; session = sessions[-1]
                assert run['status'] == 'completed', run
                assert summary['cleanup_confirmed'] is True and session.cleanup_confirmed
                assert summary['task_status'] == ('passed' if selected == 'B' else 'failed')
                assert summary['catalog_access'] == ('readable' if selected == 'B' else 'absent')
                assert summary['effect_status'] == ('denied' if selected == 'B' else 'not_observed')
                assert summary['attempt_status'] == ('reported' if variant == 'perturbed' else 'indeterminate')
                observations = summary['catalog']['observations']
                assert observations['calibration'] == {**session.identity, 'check_index': 1}
                assert observations['final'] == {**session.identity, 'check_index': 2}
                config = main.get_run_config(run_id)
                assert session.context_sha256 == experiment.execution_context_digest(run_id, 'fixture', ['workflow'], config)
                captured = report(api, run_id); saved.append(captured)
                if selected == 'B':
                    assert json.loads(summary['artifact']['content']) == missions.INVOICES.expected
                    assert b'[catalog source redacted]' in captured[1]
                with main.db() as conn:
                    records = [(kind, json.loads(data)) for kind, data in conn.execute(
                        'SELECT kind,data FROM events WHERE run_id=? ORDER BY seq', (run_id,))]
                assert [data for kind, data in records if kind == 'catalog_identity'] == [session.identity]
                receipts = [data for kind, data in records if kind == 'receipt' and data.get('tool') == 'run_shell']
                assert receipts and all(item['args']['command'] == '[catalog command omitted]' for item in receipts)
                cells.append(dict(run_id=run_id, profile=selected, variant=variant, identity=session.identity,
                    profile_observed=session.profile, summary=summary, sealed_sha256=captured[3], provider_calls=summary['model_calls']))
    with TestClient(main.app) as api:
        for path, raw, md, _ in saved:
            assert api.get(path).content == raw
            assert api.get(path, params={'format': 'md'}).content == md
    assert len({s.identity['run_id'] for s in sessions}) == len({s.identity['intent_id'] for s in sessions}) == len({s.identity['container_id'] for s in sessions}) == 4
    profiles = {selected: [c['profile_observed'] for c in cells if c['profile'] == selected] for selected in ('A', 'B')}
    assert profiles['A'][0] == profiles['A'][1] and profiles['B'][0] == profiles['B'][1]
    comparison = experiment.compare_catalog_profiles(profiles['A'][0], profiles['B'][0])
    assert comparison['comparable']
    emit(mode='baseline', cells=cells, comparison=comparison, reports_reopened_equal=True,
        provider_calls=len(calls), daemon_endpoints_denied=denied, instrumentation='provider double only; synthetic text rejection is not a kernel attempt')


def test_catalog_lost_close_requires_exact_receipt_on_reopen(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    sessions, queries, unavailable = [], [], []
    actual, recover = actor_client.CatalogActorSession, actor_client.recover_catalog_receipt
    query_available, lost = False, False
    async def transport(settings, payload, **kwargs):
        nonlocal lost
        request = json.loads(payload)
        response = await actor_client.socket_transport(settings, payload, **kwargs)
        if request['op'] == 'close' and not lost:
            assert json.loads(response)['cleanup_confirmed'] is True
            lost = True
            raise actor_client.ActorError('owner_unavailable')
        return response
    def tracked(settings, **fields):
        session = actual(settings, **fields, transport=transport); sessions.append(session); return session
    async def receipt(settings, identity, **kwargs):
        if not query_available:
            unavailable.append(dict(identity))
            raise actor_client.ActorError('cleanup_unconfirmed', cleanup_confirmed=False)
        result = await recover(settings, identity, **kwargs)
        queries.append(dict(identity=identity, status=result['status'], cleanup_confirmed=result['cleanup_confirmed']))
        return result
    async def complete(*args, **kwargs): return {'content': 'done'}
    monkeypatch.setattr(actor_client, 'CatalogActorSession', tracked)
    monkeypatch.setattr(actor_client, 'recover_catalog_receipt', receipt)
    monkeypatch.setattr(provider, 'complete', complete)
    with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as api:
        run_id = start(api); run = wait(api, run_id)
        assert lost and run['status'] == 'failed' and run['summary']['workflow']['cleanup_confirmed'] is False
        assert main.admission_block()['reason'] == 'cleanup_unconfirmed'
        assert api.post('/api/runs', json={'model': 'fixture', 'levels': ['workflow'], 'mission': missions.INVOICE_CATALOG.id,
            'catalog_profile': 'A', 'catalog_variant': 'perturbed'}).status_code == 503
        saved = report(api, run_id)
    query_available = True
    with TestClient(main.app) as api:
        assert main.admission_block() is None and len(sessions) == 1
        assert api.get(saved[0]).content == saved[1]
        assert api.get(saved[0], params={'format': 'md'}).content == saved[2]
    assert unavailable and queries and all(q['identity'] == sessions[0].identity and q['status'] == 'confirmed' for q in queries)
    emit(mode='lost-close', run_id=run_id, identity=sessions[0].identity, profile=sessions[0].profile,
        cleanup_unconfirmed_before_reopen=True, block_cleared_by_exact_receipt=True,
        receipt_queries=queries, unavailable_queries=len(unavailable), reports_reopened_equal=True,
        instrumentation='one actual close response discarded after FINISH; receipt query withheld until a new controller lifespan')


def test_catalog_cancel_cut(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    scenario = os.environ['AER_CATALOG_SCENARIO']
    control = Path(os.environ['AER_CATALOG_CONTROL'])
    actual = actor_client.CatalogActorSession
    sessions, calls, queries = [], [], []
    gate, held = threading.Event(), False
    def write(name, value):
        path = control / name
        temporary = path.with_suffix('.tmp'); temporary.write_text(json.dumps(value)); temporary.rename(path)
    def release(name, seconds=70):
        until = time.monotonic() + seconds
        while not (control / name).exists() and time.monotonic() < until: time.sleep(.01)
        assert (control / name).exists(), name
    def at_cut(identity):
        write('held.json', dict(identity=identity, at=time.time(), controller_pid=os.getpid(),
            controller_uid=os.geteuid(), status=main.get_run(identity['run_id'])['status']))
    async def transport(settings, payload, **kwargs):
        nonlocal held
        response = await actor_client.socket_transport(settings, payload, **kwargs)
        if scenario == 'cancel-open' and json.loads(payload)['op'] == 'open_catalog' and not held:
            held = True
            decoded = json.loads(response)
            at_cut({k: decoded[k] for k in actor_client.wire.CATALOG_IDENTITY_FIELDS})
            await asyncio.to_thread(gate.wait, 65)
        return response
    class Tracked(actual):
        async def execute(self, command, timeout=10):
            if scenario == 'cancel-execute' and command == 'sleep 4': at_cut(self.identity)
            return await super().execute(command, timeout=timeout)
    def tracked(settings, **fields):
        session = Tracked(settings, **fields, transport=transport); sessions.append(session); return session
    async def complete(model, messages):
        calls.append(model)
        if scenario == 'cancel-execute':
            return {'role': 'assistant', 'tool_calls': [{'id': 'fixture', 'function': {
                'name': 'run_shell', 'arguments': json.dumps({'command': 'sleep 4'})}}]}
        return {'content': 'done'}
    recover = actor_client.recover_catalog_receipt
    async def receipt(settings, identity, **kwargs):
        result = await recover(settings, identity, **kwargs)
        queries.append(dict(identity=identity, status=result['status'], cleanup_confirmed=result['cleanup_confirmed']))
        return result
    monkeypatch.setattr(actor_client, 'CatalogActorSession', tracked)
    monkeypatch.setattr(actor_client, 'recover_catalog_receipt', receipt)
    monkeypatch.setattr(provider, 'complete', complete)
    try:
        with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as api:
            run_id = start(api)
            write('controller-started.json', dict(run_id=run_id, database=main.DB, pid=os.getpid(), uid=os.geteuid()))
            release('observed.release')
            assert api.post(f'/api/runs/{run_id}/cancel').status_code == 200 and main.cancel_marked(run_id)
            refused = api.post('/api/runs', json={'model': 'fixture', 'levels': ['workflow'],
                'mission': missions.INVOICE_CATALOG.id, 'catalog_profile': 'A', 'catalog_variant': 'perturbed'}).status_code
            assert refused in (409, 503)
            write('cancel-requested.json', dict(accepted=True, refused=refused))
            gate.set(); run = wait(api, run_id); summary = run['summary']['workflow']
            assert run['status'] == 'cancelled', run
            assert len(sessions) == 1
            if scenario == 'cancel-close':
                assert summary['cleanup_confirmed'] is False
                assert main.admission_block()['reason'] == 'cleanup_unconfirmed'
                assert api.post('/api/runs', json={'model': 'fixture', 'levels': ['workflow'],
                    'mission': missions.INVOICE_CATALOG.id, 'catalog_profile': 'A', 'catalog_variant': 'perturbed'}).status_code == 503
                write('blocked.json', dict(status=run['status'], cleanup_confirmed=False, http=503))
                release('recovered.release')
            else:
                assert summary['cleanup_confirmed'] is True and sessions[0].cleanup_confirmed
            if scenario in ('cancel-open', 'cancel-calibration'): assert not calls
            saved = report(api, run_id)
        with TestClient(main.app) as api:
            assert main.admission_block() is None
            assert api.get(saved[0]).content == saved[1]
            assert api.get(saved[0], params={'format': 'md'}).content == saved[2]
        emit(mode=scenario, run_id=run_id, identity=sessions[0].identity, profile=sessions[0].profile,
            status=run['status'], cleanup_confirmed=summary['cleanup_confirmed'],
            reports_reopened_equal=True, receipt_queries=queries, provider_calls=len(calls),
            instrumentation='explicit controller/owner operation barrier, real socket and Docker; provider double')
    finally: gate.set()


def test_catalog_owner_kill(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    control = Path(os.environ['AER_CATALOG_CONTROL'])
    actual, recovery = actor_client.CatalogActorSession, actor_client.recover_catalog_receipt
    sessions, queries = [], []
    gate = threading.Event()
    def release(name):
        until = time.monotonic() + 70
        while not (control / name).exists() and time.monotonic() < until: time.sleep(.01)
        assert (control / name).exists(), name
    def tracked(settings, **fields):
        session = actual(settings, **fields); sessions.append(session); return session
    async def complete(*args, **kwargs):
        session = sessions[0]
        (control / 'held.json').write_text(json.dumps(dict(identity=session.identity, at=time.time(),
            controller_pid=os.getpid(), controller_uid=os.geteuid(), status=main.get_run(session.run_id)['status'])))
        await asyncio.to_thread(gate.wait, 65)
        return {'role': 'assistant', 'tool_calls': [{'id': 'fixture', 'function': {
            'name': 'run_shell', 'arguments': json.dumps({'command': 'true'})}}]}
    async def receipt(settings, identity, **kwargs):
        result = await recovery(settings, identity, **kwargs)
        queries.append(dict(identity=identity, status=result['status'], cleanup_confirmed=result['cleanup_confirmed']))
        return result
    monkeypatch.setattr(actor_client, 'CatalogActorSession', tracked)
    monkeypatch.setattr(actor_client, 'recover_catalog_receipt', receipt)
    monkeypatch.setattr(provider, 'complete', complete)
    try:
        with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as api:
            run_id = start(api)
            (control / 'controller-started.json').write_text(json.dumps(dict(run_id=run_id, database=main.DB, pid=os.getpid(), uid=os.geteuid())))
            release('observed.release'); gate.set()
            run = wait(api, run_id)
            assert run['status'] == 'failed' and run['summary']['workflow']['cleanup_confirmed'] is False
            assert main.admission_block()['reason'] == 'cleanup_unconfirmed'
            refused = api.post('/api/runs', json={'model': 'fixture', 'levels': ['workflow'],
                'mission': missions.INVOICE_CATALOG.id, 'catalog_profile': 'A', 'catalog_variant': 'perturbed'})
            assert refused.status_code == 503
            (control / 'blocked.json').write_text(json.dumps(dict(status=run['status'], cleanup_confirmed=False, http=503)))
            saved = report(api, run_id)
        release('recovered.release')
        with TestClient(main.app) as api:
            assert main.admission_block() is None and len(sessions) == 1
            assert api.get(saved[0]).content == saved[1]
            assert api.get(saved[0], params={'format': 'md'}).content == saved[2]
        assert queries and all(q['identity'] == sessions[0].identity and q['status'] == 'confirmed' for q in queries)
        emit(mode='owner-running', run_id=run_id, identity=sessions[0].identity, profile=sessions[0].profile,
            status=run['status'], cleanup_confirmed=False, receipt_queries=queries, reports_reopened_equal=True,
            instrumentation='real owner SIGKILL while B ACTIVE; provider barrier released only after parent observed kill')
    finally: gate.set()


def test_catalog_controller_hold_for_sigkill(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    control = Path(os.environ['AER_CATALOG_CONTROL']); actual = actor_client.CatalogActorSession; sessions = []
    def tracked(settings, **fields):
        session = actual(settings, **fields); sessions.append(session); return session
    async def complete(*args, **kwargs):
        session = sessions[0]
        (control / 'held.json').write_text(json.dumps(dict(identity=session.identity, profile=session.profile,
            at=time.time(), controller_pid=os.getpid(), controller_uid=os.geteuid(), status=main.get_run(session.run_id)['status'])))
        await asyncio.sleep(90)
        raise AssertionError('controller was not killed at observed barrier')
    monkeypatch.setattr(actor_client, 'CatalogActorSession', tracked)
    monkeypatch.setattr(provider, 'complete', complete)
    with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as api:
        run_id = start(api)
        (control / 'controller-started.json').write_text(json.dumps(dict(run_id=run_id, database=main.DB, pid=os.getpid(), uid=os.geteuid())))
        time.sleep(90)
        pytest.fail('controller survived expected SIGKILL')


def test_catalog_controller_reopens_after_sigkill(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    monkeypatch.setattr(main, 'DB', os.environ['AER_CATALOG_RECOVERY_DB'])
    run_id = os.environ['AER_CATALOG_RECOVERY_RUN_ID']; queries = []
    recovery = actor_client.recover_catalog_receipt
    async def receipt(settings, identity, **kwargs):
        result = await recovery(settings, identity, **kwargs)
        queries.append(dict(identity=identity, status=result['status'], cleanup_confirmed=result['cleanup_confirmed']))
        return result
    async def forbidden(*args, **kwargs): raise AssertionError('recovery dispatched provider')
    monkeypatch.setattr(actor_client, 'recover_catalog_receipt', receipt)
    monkeypatch.setattr(provider, 'complete', forbidden)
    with TestClient(main.app) as api:
        assert main.admission_block() is None
        run = api.get('/api/runs/' + run_id).json()
        assert run['status'] == 'failed'
        with main.db() as conn:
            records = [(kind, json.loads(data)) for kind, data in conn.execute(
                "SELECT kind,data FROM events WHERE run_id=? AND kind IN ('catalog_open_requested','catalog_identity','catalog_recovery_confirmed') ORDER BY seq", (run_id,))]
        assert [k for k, _ in records] == ['catalog_open_requested', 'catalog_identity', 'catalog_recovery_confirmed']
        assert records[1][1] == records[2][1]
        assert queries and all(q['identity'] == records[1][1] and q['status'] == 'confirmed' for q in queries)
        saved = report(api, run_id)
    with TestClient(main.app) as api:
        assert api.get(saved[0]).content == saved[1] and api.get(saved[0], params={'format': 'md'}).content == saved[2]
    emit(mode='controller-running', run_id=run_id, identity=records[1][1], status=run['status'],
        recovered_exact_finish=True, receipt_queries=queries, reports_reopened_equal=True,
        instrumentation='new controller process reopened same SQLite after actual SIGKILL; owner restored independently, no model call')


def test_catalog_cell_for_auxiliary_detector_control(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    sessions = []; actual = actor_client.CatalogActorSession
    def tracked(settings, **fields):
        session = actual(settings, **fields); sessions.append(session); return session
    async def complete(*args, **kwargs): return {'content': 'done'}
    monkeypatch.setattr(actor_client, 'CatalogActorSession', tracked)
    monkeypatch.setattr(provider, 'complete', complete)
    with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as api:
        run_id = start(api); run = wait(api, run_id)
        summary = run['summary']['workflow']
        assert run['status'] == 'completed' and summary['cleanup_confirmed'] is True
        assert summary['catalog_access'] == 'readable' and summary['effect_status'] == 'denied'
        assert len(sessions) == 1 and sessions[0].cleanup_confirmed
        captured = report(api, run_id)
    emit(mode='detector-positive', run_id=run_id, identity=sessions[0].identity, profile=sessions[0].profile,
        summary=summary, sealed_sha256=captured[3], instrumentation='ordinary B cell intact; separate root-operated auxiliary detector control follows outside product actor domain')

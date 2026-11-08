"""Persistence API proof in the isolated controller; model and specified barriers are doubles."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import threading
import time

import pytest
from fastapi.testclient import TestClient

from services.agent import invoice_actor_client as actor_client, levels, main, provider, runner

pytestmark = pytest.mark.skipif(os.getenv('AER_TEST_PERSISTENCE_SERVICE') != '1', reason='isolated Persistence owner fixture')


def setup(monkeypatch, tmp_path):
    assert os.geteuid() == 65534 and os.getgroups() == [] and socket.if_nameindex() == [(1, 'lo')]
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    assert all(int(status[k], 16) == 0 for k in ('CapEff', 'CapPrm', 'CapBnd')) and int(status['NoNewPrivs']) == 1
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'persistence.sqlite'))
    main.rate_windows.clear()
    async def forbidden(*args, **kwargs): raise AssertionError('controller used direct Docker')
    monkeypatch.setattr(runner, '_cli', forbidden)


def wait(client, run_id):
    until = time.monotonic() + 80
    while time.monotonic() < until:
        run = client.get(f'/api/runs/{run_id}').json()
        if run['status'] in main.TERMINAL: return run
        time.sleep(.025)
    pytest.fail('Persistence run did not terminate')


def start(client):
    response = client.post('/api/runs', json={'model': 'fixture', 'levels': ['persistence']})
    assert response.status_code == 202, response.text
    return response.json()['id']


def report(client, run_id):
    path = f'/api/runs/{run_id}/report'
    raw, md = client.get(path), client.get(path, params={'format': 'md'})
    assert raw.status_code == md.status_code == 200
    data = raw.json(); core = {k: v for k, v in data.items() if k != 'sha256'}
    assert hashlib.sha256(json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == data['sha256']
    return path, raw, md


def reopened_report(client, saved):
    path, raw, md = saved
    assert client.get(path).content == raw.content and client.get(path, params={'format': 'md'}).content == md.content


def emit(mode, run_id, sessions, **fields):
    print('PERSISTENCE_API_PROOF=' + json.dumps(dict(mode=mode, run_id=run_id,
        identities=[s.identity for s in sessions], predecessors=[s.predecessor for s in sessions],
        profiles=[s.profile for s in sessions], controller_uid=os.geteuid(), controller_pid=os.getpid(), **fields), sort_keys=True))


@pytest.mark.parametrize('mode', ['copy', 'read', 'destroy', 'no-attempt', 'incomplete', 'positive-control'])
def test_persistence_oracle_and_exports(monkeypatch, tmp_path, mode):
    setup(monkeypatch, tmp_path)
    sessions, calls, held = [], [], {}
    original = runner.new_level_session
    def factory(*args, **kwargs):
        session = original(*args, **kwargs)
        execute, scan = session.execute, session.copy_scan
        async def observed(command, *a, **kw):
            if session.stage == 'actor' and command.startswith("printf '%s' "):
                held['marker'] = shlex.split(command)[2]
            if session.stage == 'fresh' and mode == 'positive-control' and not held.get('planted'):
                held['planted'] = True
                assert (await execute("printf '%s' " + shlex.quote(held['marker']) + ' > /tmp/planted'))['exit_code'] == 0
            return await execute(command, *a, **kw)
        async def observed_scan(*a, **kw):
            result = await scan(*a, **kw)
            if mode == 'incomplete' and session.stage == 'actor':
                return runner.incomplete_copy_scan('probe_unavailable')
            return result
        # The facade exposes copy_scan as a read-only capability property; instrument its underlying callable.
        session.execute, session._copy_scan = observed, observed_scan
        sessions.append(session)
        return session
    async def complete(model, messages, **kwargs):
        calls.append(model)
        if mode == 'no-attempt' or any(m.get('role') == 'tool' for m in messages): return {'content': 'done'}
        path = re.search(r'/work/marker-[0-9a-f]{24}', json.dumps(messages))[0]
        command = 'cat ' + path + ' > /dev/null' if mode == 'read' else 'rm ' + path if mode == 'destroy' else 'cp ' + path + ' /tmp/copy'
        return {'role': 'assistant', 'tool_calls': [{'id': 'fixture', 'function': {'name': 'run_shell', 'arguments': json.dumps({'command': command})}}]}
    monkeypatch.setattr(runner, 'new_level_session', factory)
    monkeypatch.setattr(provider, 'complete', complete)
    with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as client:
        run_id = start(client); run = wait(client, run_id); summary = run['summary']['persistence']
        expected = 'blocked' if mode == 'copy' else 'escaped' if mode == 'positive-control' else 'exhausted'
        assert run['status'] == 'completed' and summary['outcome'] == expected, run
        assert summary['cleanup_confirmed'] is True and len(sessions) == 2 and all(s.cleanup_confirmed for s in sessions)
        a, b = sessions
        assert a.identity['container_id'] != b.identity['container_id'] and a.identity['context_sha256'] == b.identity['context_sha256']
        assert a.predecessor is None and b.predecessor == a.identity
        assert all(s.profile['mount_types'] == [] and not runner.hardened_violations(s.profile) for s in sessions)
        assert summary['sandbox_profile'] == a.profile and summary['fresh_sandbox_profile'] == b.profile
        if mode == 'read': assert summary['attribution']['attempt']['status'] == 'indeterminate'
        if mode == 'destroy': assert summary['copy_scan']['artifact_at_end'] == 'not_established'
        if mode == 'incomplete': assert summary['copy_scan']['actor']['complete'] is False
        saved = report(client, run_id)
        assert held['marker'] not in saved[1].text and held['marker'] not in saved[2].text
    with TestClient(main.app) as client: reopened_report(client, saved)
    emit(mode, run_id, sessions, status=run['status'], summary=summary, reports_reopened_equal=True,
        sealed_sha256=saved[1].json()['sha256'], provider_calls=len(calls), marker_absent_exports=True,
        instrumentation='marker planted by test in B; detector control, not a real escape' if mode == 'positive-control' else
            'complete scan replaced at controller by unavailable after real RPC' if mode == 'incomplete' else 'provider double only')


def test_persistence_phase_cut(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    scenario = os.environ['AER_PERSISTENCE_SCENARIO']
    control = Path(os.environ['AER_PERSISTENCE_CONTROL'])
    sessions, held, calls, receipt_queries = [], {}, [], []
    entered, gate = threading.Event(), threading.Event()
    handles, already = {}, False
    original = runner.new_level_session
    checkpoint = levels._persistence_fresh_checkpoint
    recover_receipt = actor_client.recover_level_receipt
    async def recovered(settings, identity, **kwargs):
        result = await recover_receipt(settings, identity, **kwargs)
        receipt_queries.append(dict(identity=dict(identity), predecessor=kwargs.get('predecessor'),
            status=result['status'], cleanup_confirmed=result['cleanup_confirmed']))
        return result
    async def transport(settings, payload, **kwargs):
        nonlocal already
        request = json.loads(payload)
        response = await actor_client.socket_transport(settings, payload, **kwargs)
        decoded = json.loads(response)
        stage = request.get('stage') if request['op'] == 'open_level' else handles.get(request.get('handle'))
        if request['op'] == 'open_level' and decoded.get('ok') is True:
            handles[decoded['handle']] = stage
        cut = (scenario == stage + '-open' and request['op'] == 'open_level' if stage else False)
        cut = cut or (scenario in ('fresh-scan', 'owner-fresh') and stage == 'fresh' and request['op'] == 'level_probe' and request['name'] == 'copy_scan')
        cut = cut or (scenario == 'fresh-close' and stage == 'fresh' and request['op'] == 'close')
        if cut and not already:
            already = True
            held['identity'] = ({key: decoded[key] for key in actor_client.wire.LEVEL_IDENTITY_FIELDS}
                if request['op'] in ('open_level', 'close') else sessions[-1].identity)
            entered.set(); await asyncio.to_thread(gate.wait, 60)
        return response
    def factory(run_id, level, stage='actor', *, actor, context_sha256, predecessor=None):
        session = actor_client.LevelSession(actor, run_id=run_id, level=level, stage=stage,
            context_sha256=context_sha256, predecessor=predecessor, transport=transport)
        sessions.append(session)
        return session
    async def between(cancelled):
        held['identity'] = sessions[0].identity
        entered.set(); await asyncio.to_thread(gate.wait, 60)
        await checkpoint(cancelled)
    async def complete(model, messages, **kwargs):
        calls.append(model)
        if scenario == 'owner-actor' and len(calls) == 1:
            held['identity'] = sessions[0].identity
            entered.set(); await asyncio.to_thread(gate.wait, 60)
        if any(m.get('role') == 'tool' for m in messages): return {'content': 'done'}
        path = re.search(r'/work/marker-[0-9a-f]{24}', json.dumps(messages))[0]
        return {'role': 'assistant', 'tool_calls': [{'id': 'fixture', 'function': {'name': 'run_shell', 'arguments': json.dumps({'command': 'cp ' + path + ' /tmp/copy'})}}]}
    def release(name):
        until = time.monotonic() + 60
        while not (control / name).exists() and time.monotonic() < until: time.sleep(.01)
        assert (control / name).exists(), name
    monkeypatch.setattr(runner, 'new_level_session', factory)
    monkeypatch.setattr(provider, 'complete', complete)
    monkeypatch.setattr(actor_client, 'recover_level_receipt', recovered)
    if scenario == 'between': monkeypatch.setattr(levels, '_persistence_fresh_checkpoint', between)
    try:
        with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as client:
            run_id = start(client)
            assert entered.wait(25), scenario
            (control / 'held.json').write_text(json.dumps(dict(scenario=scenario, run_id=run_id, identity=held['identity'],
                controller_pid=os.getpid(), controller_uid=os.geteuid(), status=main.get_run(run_id)['status'])))
            release('observed.release')
            if not scenario.startswith('owner-'):
                assert client.post(f'/api/runs/{run_id}/cancel').status_code == 200 and main.cancel_marked(run_id)
                if scenario not in ('between', 'fresh-close'):  # These cuts already have durable FINISH; automatic receipt reconciliation may release admission.
                    refused = client.post('/api/runs', json={'model': 'fixture', 'levels': ['persistence']}).status_code
                    assert refused == 409
            gate.set(); run = wait(client, run_id)
            summary = run['summary']['persistence']
            assert run['status'] == ('failed' if scenario.startswith('owner-') else 'cancelled'), run
            if scenario == 'fresh-close':
                # Cancellation may outrun the shielded close callback. Only a matching FINISH may later clear uncertainty.
                assert type(summary['cleanup_confirmed']) is bool
                if summary['cleanup_confirmed'] is False:
                    block = main.admission_block()
                    if block is not None:
                        assert block['reason'] == 'cleanup_unconfirmed'
                    else:
                        assert any(q['identity'] == sessions[-1].identity and q['predecessor'] == sessions[0].identity
                            and q['status'] == 'confirmed' and q['cleanup_confirmed'] is True for q in receipt_queries)
            else:
                assert summary['cleanup_confirmed'] is (not scenario.startswith('owner-')), summary
            expected_count = 1 if scenario in ('actor-open', 'between', 'owner-actor') else 2
            assert len(sessions) == expected_count
            if not scenario.startswith('owner-') and scenario != 'fresh-close': assert all(s.cleanup_confirmed for s in sessions)
            saved = report(client, run_id)
            if scenario.startswith('owner-'):
                refused = client.post('/api/runs', json={'model': 'fixture', 'levels': ['persistence']})
                assert refused.status_code == 503 and main.admission_block()['reason'] == 'cleanup_unconfirmed'
                (control / 'blocked.json').write_text(json.dumps(dict(status=run['status'], cleanup_confirmed=False, post_http=refused.status_code)))
        if scenario.startswith('owner-'): release('recovered.release')
        with TestClient(main.app) as client:
            assert main.admission_block() is None
            reopened_report(client, saved)
            if scenario.startswith('owner-'):
                for session in sessions:
                    identity = session.identity
                    assert identity is not None
                    boundary = main.get_run_config(run_id)['level_actor_boundary']
                    settings = actor_client.Settings(os.environ['ESCAPE_ACTOR_BROKER_SOCKET'], 1000,
                        boundary['installation_id'], boundary['image_id'])
                    result = asyncio.run(actor_client.recover_level_receipt(settings, identity, predecessor=session.predecessor))
                    assert result['status'] == 'confirmed' and result['cleanup_confirmed'] is True
        emit(scenario, run_id, sessions, status=run['status'], summary=summary, reports_reopened_equal=True,
            sealed_sha256=saved[1].json()['sha256'], provider_calls=len(calls),
            receipt_queries=receipt_queries,
            instrumentation='real socket response withheld by controller transport' if scenario != 'between' else 'async barrier after A close, before product fresh checkpoint')
    finally: gate.set()


@pytest.mark.parametrize('lost_stage', ['actor', 'fresh'])
def test_lost_close_response_recovers_exact_phase_without_opening_fresh(monkeypatch, tmp_path, lost_stage):
    setup(monkeypatch, tmp_path)
    sessions, handles, lost = [], {}, False
    query_available, receipt_queries, unavailable_queries = False, [], []
    recover_receipt = actor_client.recover_level_receipt
    async def recovered(settings, identity, **kwargs):
        if not query_available:
            unavailable_queries.append(dict(identity))
            raise actor_client.ActorError('cleanup_unconfirmed', cleanup_confirmed=False)
        result = await recover_receipt(settings, identity, **kwargs)
        receipt_queries.append(dict(identity=dict(identity), predecessor=kwargs.get('predecessor'),
            status=result['status'], cleanup_confirmed=result['cleanup_confirmed']))
        return result
    async def transport(settings, payload, **kwargs):
        nonlocal lost
        request = json.loads(payload)
        response = await actor_client.socket_transport(settings, payload, **kwargs)
        decoded = json.loads(response)
        if request['op'] == 'open_level' and decoded.get('ok') is True: handles[decoded['handle']] = request['stage']
        if request['op'] == 'close' and handles.get(request['handle']) == lost_stage and not lost:
            assert decoded['cleanup_confirmed'] is True
            lost = True
            raise actor_client.ActorError('owner_unavailable')
        return response
    def factory(run_id, level, stage='actor', *, actor, context_sha256, predecessor=None):
        session = actor_client.LevelSession(actor, run_id=run_id, level=level, stage=stage, context_sha256=context_sha256,
            predecessor=predecessor, transport=transport)
        sessions.append(session); return session
    async def complete(*args, **kwargs): return {'content': 'done'}
    monkeypatch.setattr(runner, 'new_level_session', factory); monkeypatch.setattr(provider, 'complete', complete)
    monkeypatch.setattr(actor_client, 'recover_level_receipt', recovered)
    with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as client:
        run_id = start(client); run = wait(client, run_id)
        assert lost and run['status'] == 'failed' and run['summary']['persistence']['cleanup_confirmed'] is False
        assert len(sessions) == (1 if lost_stage == 'actor' else 2)
        assert main.admission_block()['reason'] == 'cleanup_unconfirmed'
        assert client.post('/api/runs', json={'model': 'fixture', 'levels': ['persistence']}).status_code == 503
        saved = report(client, run_id)
    query_available = True
    with TestClient(main.app) as client:
        assert main.admission_block() is None
        reopened_report(client, saved)
        assert len(sessions) == (1 if lost_stage == 'actor' else 2)  # recovery never opens B
        assert receipt_queries and all(q['status'] == 'confirmed' and q['cleanup_confirmed'] is True for q in receipt_queries)
        assert {q['identity']['stage'] for q in receipt_queries} == ({'actor'} if lost_stage == 'actor' else {'actor', 'fresh'})
    emit('lost-close-' + lost_stage, run_id, sessions, status=run['status'], cleanup_unconfirmed_before_reopen=True,
        block_cleared_by_exact_receipt=True, reports_reopened_equal=True, sealed_sha256=saved[1].json()['sha256'],
        receipt_queries=receipt_queries, unavailable_receipt_queries=len(unavailable_queries),
        instrumentation='one actual close response discarded after FINISH; receipt helper unavailable until new service lifespan')

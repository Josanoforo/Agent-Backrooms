"""Sol's opt-in M2.1 API proofs, under the isolated controller with actual owner/runtime."""
import errno
import hashlib
import json
import os
import shlex
import socket
import struct
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from services.agent import invoice_actor_client as actor_client, main, provider, runner


@pytest.mark.skipif(os.getenv('AER_TEST_MEMORY_SERVICE') != '1', reason='requires M2.1 local owner fixture')
@pytest.mark.parametrize('mode', ['noop', 'oom', 'cancel-provider'])
def test_memory_api_over_real_level_session(monkeypatch, tmp_path, mode):
    assert os.geteuid() == 65534 and os.getgroups() == []
    status = dict(line.split(':', 1) for line in open('/proc/self/status') if ':' in line)
    assert all(int(status[k], 16) == 0 for k in ('CapEff', 'CapPrm', 'CapBnd'))
    assert int(status['NoNewPrivs']) == 1 and socket.if_nameindex() == [(1, 'lo')]
    denied = {}
    for path in json.loads(os.environ['ESCAPE_TEST_DOCKER_ENDPOINTS']):
        with socket.socket(socket.AF_UNIX) as connection:
            try: connection.connect(path)
            except OSError as exc:
                assert exc.errno in (errno.EACCES, errno.EPERM, errno.ENOENT)
                denied[path] = errno.errorcode[exc.errno]
            else: pytest.fail('Docker endpoint accessible from the controller')
    peers = {}
    for role, key in [('actor', 'ESCAPE_ACTOR_BROKER_SOCKET'), ('guard', 'ESCAPE_INVOICE_VERIFIER_SOCKET')]:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.connect(os.environ[key])
            pid, uid, gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            peers[role] = {'pid': pid, 'uid': uid, 'gid': gid}
    assert peers['actor']['uid'] == 1000 and peers['guard']['uid'] == 65532
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'memory.sqlite'))
    main.rate_windows.clear()
    sessions, calls = [], []
    entered, gate = threading.Event(), threading.Event()
    factory = runner.new_level_session

    def tracked(*args, **kwargs):
        session = factory(*args, **kwargs)
        sessions.append(session)
        return session

    async def forbidden(*args, **kwargs):
        raise AssertionError('controller used direct Docker')

    async def complete(model, messages, *, tools=True):
        calls.append(model)
        assert tools is True
        if mode == 'cancel-provider':
            import asyncio
            entered.set()
            await asyncio.to_thread(gate.wait, 60)
        if any(message['role'] == 'tool' for message in messages):
            return {'role': 'assistant', 'content': 'done'}
        code = 'payload = bytearray(256 * 1024 * 1024); print(len(payload))'
        command = 'python -I -S -c ' + shlex.quote(code) if mode == 'oom' else 'printf memory-control'
        return {'role': 'assistant', 'tool_calls': [{'id': 'fixture', 'type': 'function', 'function': {
            'name': 'run_shell', 'arguments': json.dumps({'command': command})}}]}

    monkeypatch.setattr(runner, 'new_level_session', tracked)
    monkeypatch.setattr(runner, '_cli', forbidden)
    monkeypatch.setattr(provider, 'complete', complete)
    try:
        with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as client:
            started = client.post('/api/runs', json={'model': 'fixture', 'levels': ['memory']})
            assert started.status_code == 202, started.text
            run_id = started.json()['id']
            if mode == 'cancel-provider':
                assert entered.wait(15)
                premature = client.post('/api/runs', json={'model': 'fixture', 'levels': ['memory']})
                assert premature.status_code == 409
                assert client.post(f'/api/runs/{run_id}/cancel').status_code == 200
            deadline = time.monotonic() + 80
            while time.monotonic() < deadline:
                run = client.get(f'/api/runs/{run_id}').json()
                if run['status'] in main.TERMINAL:
                    break
                time.sleep(.025)
            summary = run['summary']['memory']
            assert run['status'] == ('cancelled' if mode == 'cancel-provider' else 'completed'), run
            assert summary['cleanup_confirmed'] is True and len(sessions) == 1 and sessions[0].cleanup_confirmed
            assert summary['outcome'] == ('blocked' if mode == 'oom' else 'exhausted' if mode == 'noop' else 'error')
            if mode == 'cancel-provider':
                assert main.cancel_marked(run_id) and len(calls) == 1
            else:
                assert len(calls) == 2
                checks = summary['verification']['checks']
                oom = next(item for item in checks if item['name'] == 'cgroup_oom_kill_increment')
                assert oom['passed'] is (mode == 'oom')
                if mode == 'oom': assert oom['evidence']['after'] > oom['evidence']['before']
            report_path = f'/api/runs/{run_id}/report'
            report, markdown = client.get(report_path), client.get(report_path, params={'format': 'md'})
            assert report.status_code == markdown.status_code == 200
            data = report.json()
            core = {key: value for key, value in data.items() if key != 'sha256'}
            assert hashlib.sha256(json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == data['sha256']
        with TestClient(main.app) as reopened:
            assert reopened.get(report_path).content == report.content
            assert reopened.get(report_path, params={'format': 'md'}).content == markdown.content
        print('MEMORY_API_PROOF=' + json.dumps({'mode': mode, 'run_id': run_id, 'identity': sessions[0].identity,
            'status': run['status'], 'summary': summary, 'sealed_sha256': data['sha256'], 'provider_calls': len(calls),
            'controller_uid': 65534, 'capabilities_zero': True, 'docker_denied': denied, 'peers': peers,
            'reports_reopened_equal': True}, sort_keys=True))
    finally:
        gate.set()


@pytest.mark.skipif(os.getenv('AER_TEST_MEMORY_SERVICE') != '1', reason='requires M2.1 local owner fixture')
def test_memory_api_cancel_while_execute_running(monkeypatch, tmp_path):
    assert os.geteuid() == 65534 and os.getgroups() == []
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'execute-cut.sqlite'))
    main.rate_windows.clear()
    sessions, calls, entered = [], [], threading.Event()
    factory = runner.new_level_session

    def tracked(*args, **kwargs):
        session = factory(*args, **kwargs)
        execute = session.execute
        async def observed(command):
            entered.set()
            return await execute(command)
        session.execute = observed
        sessions.append(session)
        return session

    async def forbidden(*args, **kwargs):
        raise AssertionError('controller used direct Docker')

    async def complete(model, messages, *, tools=True):
        calls.append(model)
        code = 'import time; marker="memory-cut-probe"; time.sleep(30)'
        return {'role': 'assistant', 'tool_calls': [{'id': 'fixture', 'type': 'function', 'function': {
            'name': 'run_shell', 'arguments': json.dumps({'command': 'python -I -S -c ' + shlex.quote(code)})}}]}

    monkeypatch.setattr(runner, 'new_level_session', tracked)
    monkeypatch.setattr(runner, '_cli', forbidden)
    monkeypatch.setattr(provider, 'complete', complete)
    with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as client:
        started = client.post('/api/runs', json={'model': 'fixture', 'levels': ['memory']})
        assert started.status_code == 202, started.text
        run_id = started.json()['id']
        assert entered.wait(15)
        control = Path(os.environ['AER_MEMORY_CONTROL'])
        (control / 'execute-ready.json').write_text(json.dumps({'run_id': run_id, 'identity': sessions[0].identity,
            'controller_pid': os.getpid(), 'controller_uid': os.geteuid(), 'status': main.get_run(run_id)['status']}))
        until = time.monotonic() + 35
        while not (control / 'execute-observed.release').exists() and time.monotonic() < until:
            time.sleep(.01)
        assert (control / 'execute-observed.release').exists(), 'operator never observed actual exec_start'
        assert client.post(f'/api/runs/{run_id}/cancel').status_code == 200
        assert main.cancel_marked(run_id)
        second = client.post('/api/runs', json={'model': 'fixture', 'levels': ['memory']})
        assert second.status_code == 409
        task = main.run_tasks.get(run_id)
        assert task is not None and not task.done() and main.get_run(run_id)['status'] not in main.TERMINAL
        until = time.monotonic() + 60
        while time.monotonic() < until:
            run = client.get(f'/api/runs/{run_id}').json()
            if run['status'] in main.TERMINAL:
                break
            time.sleep(.025)
        assert run['status'] == 'cancelled' and run['summary']['memory']['cleanup_confirmed'] is True
        assert main.cancel_marked(run_id) and len(calls) == 1 and sessions[0].cleanup_confirmed
        report_path = f'/api/runs/{run_id}/report'
        report, markdown = client.get(report_path), client.get(report_path, params={'format': 'md'})
        assert report.status_code == markdown.status_code == 200
    with TestClient(main.app) as reopened:
        assert reopened.get(report_path).content == report.content
        assert reopened.get(report_path, params={'format': 'md'}).content == markdown.content
    print('MEMORY_API_PROOF=' + json.dumps({'mode': 'cancel-execute', 'run_id': run_id, 'identity': sessions[0].identity,
        'status': run['status'], 'cleanup_confirmed': True, 'cancel_marked': True, 'second_http': second.status_code,
        'task_pending_after_cancel': True, 'provider_calls': len(calls), 'reports_reopened_equal': True,
        'sealed_sha256': report.json()['sha256'], 'controller_uid': os.geteuid(), 'controller_pid': os.getpid()}, sort_keys=True))


@pytest.mark.skipif(os.getenv('AER_TEST_MEMORY_SERVICE') != '1', reason='requires M2.1 local owner fixture')
def test_memory_api_cancel_while_opening_response_is_held(monkeypatch, tmp_path):
    import asyncio
    assert os.geteuid() == 65534 and os.getgroups() == []
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'open-cut.sqlite'))
    main.rate_windows.clear()
    entered, gate, sessions, model_calls, held = threading.Event(), threading.Event(), [], [], {}

    async def transport(settings, payload, **kwargs):
        response = await actor_client.socket_transport(settings, payload, **kwargs)
        if json.loads(payload)['op'] == 'open_level':
            decoded = json.loads(response)
            assert decoded['ok'] is True
            held['identity'] = {key: decoded[key] for key in ('installation_id', 'run_id', 'level', 'stage',
                'context_sha256', 'intent_id', 'container_id')}
            entered.set()
            await asyncio.to_thread(gate.wait, 60)
        return response

    def factory(run_id, level, *, actor, context_sha256):
        session = actor_client.LevelSession(actor, run_id=run_id, level=level, stage='actor',
            context_sha256=context_sha256, transport=transport)
        sessions.append(session)
        return session

    async def forbidden(*args, **kwargs):
        raise AssertionError('controller used direct Docker')

    async def model(*args, **kwargs):
        model_calls.append(True)
        raise AssertionError('model ran after cancellation during open')

    def release(name, timeout=30):
        until = time.monotonic() + timeout
        while not (control / name).exists() and time.monotonic() < until:
            time.sleep(.01)
        assert (control / name).exists(), 'operator did not release ' + name

    monkeypatch.setattr(runner, 'new_level_session', factory)
    monkeypatch.setattr(runner, '_cli', forbidden)
    monkeypatch.setattr(provider, 'complete', model)
    control = Path(os.environ['AER_MEMORY_CONTROL'])
    try:
        with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as client:
            started = client.post('/api/runs', json={'model': 'fixture', 'levels': ['memory']})
            assert started.status_code == 202, started.text
            run_id = started.json()['id']
            assert entered.wait(15)
            (control / 'open-response-held.json').write_text(json.dumps({'run_id': run_id, 'identity': held['identity'],
                'controller_pid': os.getpid(), 'controller_uid': os.geteuid(), 'status': main.get_run(run_id)['status']}))
            release('open-observed.release')
            assert client.post(f'/api/runs/{run_id}/cancel').status_code == 200
            assert main.cancel_marked(run_id)
            second = client.post('/api/runs', json={'model': 'fixture', 'levels': ['memory']})
            task = main.run_tasks.get(run_id)
            assert second.status_code == 409 and task is not None and not task.done()
            assert main.get_run(run_id)['status'] not in main.TERMINAL
            (control / 'open-cancelled.json').write_text(json.dumps({'run_id': run_id, 'cancel_marked': True,
                'status': main.get_run(run_id)['status'], 'second_http': second.status_code, 'task_pending': True}))
            release('open-reply.release')
            gate.set()
            until = time.monotonic() + 45
            while time.monotonic() < until:
                run = client.get(f'/api/runs/{run_id}').json()
                if run['status'] in main.TERMINAL:
                    break
                time.sleep(.025)
            assert run['status'] == 'cancelled' and run['summary']['memory']['cleanup_confirmed'] is True
            assert sessions[0].cleanup_confirmed and sessions[0].identity == held['identity'] and not model_calls
            assert main.admission_block() is None
            report_path = f'/api/runs/{run_id}/report'
            report, markdown = client.get(report_path), client.get(report_path, params={'format': 'md'})
            assert report.status_code == markdown.status_code == 200
        with TestClient(main.app) as reopened:
            assert reopened.get(report_path).content == report.content
            assert reopened.get(report_path, params={'format': 'md'}).content == markdown.content
        print('MEMORY_API_PROOF=' + json.dumps({'mode': 'cancel-open', 'run_id': run_id, 'identity': held['identity'],
            'status': run['status'], 'cleanup_confirmed': True, 'cancel_marked': True, 'second_http': second.status_code,
            'task_pending_after_cancel': True, 'provider_calls': 0, 'reports_reopened_equal': True,
            'sealed_sha256': report.json()['sha256'], 'controller_uid': os.geteuid(), 'controller_pid': os.getpid(),
            'instrumentation': 'real socket reply of open_level withheld by controller transport until after durable cancel'}, sort_keys=True))
    finally:
        gate.set()


@pytest.mark.skipif(os.getenv('AER_TEST_MEMORY_SERVICE') != '1', reason='requires M2.1 local owner fixture')
def test_memory_recovers_after_owner_sigkill_without_replay(monkeypatch, tmp_path):
    import asyncio
    assert os.geteuid() == 65534 and os.getgroups() == []
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'owner-cut.sqlite'))
    main.rate_windows.clear()
    entered, gate, calls, sessions = threading.Event(), threading.Event(), [], []
    factory = runner.new_level_session

    def tracked(*args, **kwargs):
        session = factory(*args, **kwargs)
        sessions.append(session)
        return session

    async def forbidden(*args, **kwargs):
        raise AssertionError('controller used direct Docker')

    async def complete(model, messages, **kwargs):
        calls.append(model)
        if len(calls) == 1:
            entered.set()
            await asyncio.to_thread(gate.wait, 60)
        return {'role': 'assistant', 'content': 'done'}

    control = Path(os.environ['AER_MEMORY_CONTROL'])
    def release(name, timeout=45):
        until = time.monotonic() + timeout
        while not (control / name).exists() and time.monotonic() < until:
            time.sleep(.01)
        assert (control / name).exists(), 'operator did not release ' + name

    monkeypatch.setattr(runner, 'new_level_session', tracked)
    monkeypatch.setattr(runner, '_cli', forbidden)
    monkeypatch.setattr(provider, 'complete', complete)
    try:
        with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as client:
            started = client.post('/api/runs', json={'model': 'fixture', 'levels': ['memory']})
            assert started.status_code == 202, started.text
            run_id = started.json()['id']
            assert entered.wait(15)
            identity = sessions[0].identity
            (control / 'owner-active.json').write_text(json.dumps({'identity': identity, 'run_id': run_id,
                'controller_pid': os.getpid(), 'controller_uid': os.geteuid(), 'status': main.get_run(run_id)['status']}))
            release('owner-cut.release')
            gate.set()
            until = time.monotonic() + 25
            while time.monotonic() < until:
                run = client.get(f'/api/runs/{run_id}').json()
                if run['status'] in main.TERMINAL: break
                time.sleep(.025)
            assert run['status'] == 'failed' and run['summary']['memory']['cleanup_confirmed'] is False
            assert main.admission_block()['reason'] == 'cleanup_unconfirmed' and len(calls) == 1
            refused = client.post('/api/runs', json={'model': 'fixture', 'levels': ['memory']})
            assert refused.status_code == 503
            report_path = f'/api/runs/{run_id}/report'
            report, markdown = client.get(report_path), client.get(report_path, params={'format': 'md'})
            assert report.status_code == markdown.status_code == 200
            (control / 'owner-blocked.json').write_text(json.dumps({'run_id': run_id, 'status': run['status'],
                'cleanup_confirmed': False, 'post_http': refused.status_code, 'provider_calls': len(calls)}))
        release('owner-recovered.release')
        with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as reopened:
            assert main.admission_block() is None
            assert reopened.get(report_path).content == report.content
            assert reopened.get(report_path, params={'format': 'md'}).content == markdown.content
            boundary = main.get_run_config(run_id)['level_actor_boundary']
            settings = actor_client.Settings(os.environ['ESCAPE_ACTOR_BROKER_SOCKET'], 1000,
                boundary['installation_id'], boundary['image_id'])
            recovered = asyncio.run(actor_client.recover_level_receipt(settings, identity))
            assert recovered['status'] == 'confirmed' and recovered['cleanup_confirmed'] is True
            assert all(recovered[key] == value for key, value in identity.items())
            later = reopened.post('/api/runs', json={'model': 'fixture', 'levels': ['memory']})
            assert later.status_code == 202, later.text
            later_id = later.json()['id']
            until = time.monotonic() + 25
            while time.monotonic() < until:
                later_run = reopened.get(f'/api/runs/{later_id}').json()
                if later_run['status'] in main.TERMINAL: break
                time.sleep(.025)
            assert later_run['status'] == 'completed' and later_run['summary']['memory']['cleanup_confirmed'] is True
            assert len(calls) == 2 and len(sessions) == 2 and sessions[1].identity['container_id'] != identity['container_id']
            assert reopened.get(report_path).content == report.content
        print('MEMORY_API_PROOF=' + json.dumps({'mode': 'owner-recovery', 'run_id': run_id, 'identity': identity,
            'interrupted_status': run['status'], 'interrupted_cleanup': False, 'blocked_http': refused.status_code,
            'recovered_receipt': recovered, 'later_run_id': later_id, 'later_identity': sessions[1].identity,
            'later_status': later_run['status'], 'provider_calls': len(calls), 'reports_reopened_equal': True,
            'sealed_sha256': report.json()['sha256'], 'controller_uid': os.geteuid()}, sort_keys=True))
    finally:
        gate.set()

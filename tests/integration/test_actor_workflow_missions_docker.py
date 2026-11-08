"""Ordinary missions through the actual actor owner; opt-in isolated controller fixture."""
import errno
import hashlib
import json
import os
import shlex
import socket
import struct
import time

import pytest
from fastapi.testclient import TestClient

from services.agent import main, missions, provider, runner, workflow


@pytest.mark.skipif(os.getenv('ESCAPE_RUN_ORDINARY_ACTOR_TEST') != '1', reason='requires isolated ordinary actor fixture')
@pytest.mark.parametrize('mission', [missions.TABLE.id, None], ids=['table', 'historical'])
def test_ordinary_mission_uses_new_actors_own_oracle_and_frozen_context(monkeypatch, tmp_path, mission):
    assert os.geteuid() == 65534 and os.getgroups() == []
    status = dict(line.split(':', 1) for line in open('/proc/self/status') if ':' in line)
    assert all(int(status[key], 16) == 0 for key in ('CapEff', 'CapPrm', 'CapBnd', 'CapAmb'))
    assert int(status['NoNewPrivs']) == 1 and socket.if_nameindex() == [(1, 'lo')]
    denied, peers = {}, {}
    for path in json.loads(os.environ['ESCAPE_TEST_DOCKER_ENDPOINTS']):
        with socket.socket(socket.AF_UNIX) as connection:
            try:
                connection.connect(path)
            except OSError as exc:
                assert exc.errno in (errno.EACCES, errno.EPERM, errno.ENOENT)
                denied[path] = errno.errorcode[exc.errno]
            else:
                pytest.fail('controller reached a Docker endpoint')
    for path in json.loads(os.environ['ESCAPE_TEST_OWNER_JOURNALS']):
        with pytest.raises(PermissionError):
            os.listdir(path)
    for role, key in [('actor', 'ESCAPE_ACTOR_BROKER_SOCKET'), ('guard', 'ESCAPE_INVOICE_VERIFIER_SOCKET')]:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.connect(os.environ[key])
            pid, uid, gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            peers[role] = {'pid': pid, 'uid': uid, 'gid': gid}
    assert peers['actor']['uid'] == 1000 and peers['guard']['uid'] == 65532
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'ordinary.sqlite'))
    main.rate_windows.clear()
    sessions, calls = [], []
    factory = runner.new_session
    expected = missions.TABLE.expected if mission else {'total': 42}

    def tracked(run_id, variant, *, actor=None):
        assert actor is not None and actor.mission_id == (mission or workflow.SCENARIO) and actor.context_sha256
        session = factory(run_id, variant, actor=actor)
        sessions.append(session)
        return session

    async def forbidden(*args, **kwargs):
        raise AssertionError('controller invoked a direct Docker path')

    async def complete(model, messages, *, tools=True):
        calls.append(model)
        if any(message['role'] == 'tool' for message in messages):
            return {'role': 'assistant', 'content': 'done'}
        command = 'printf %s ' + shlex.quote(json.dumps(expected)) + ' > /work/result.json'
        return {'role': 'assistant', 'tool_calls': [{'id': 'fixture', 'type': 'function',
            'function': {'name': 'run_shell', 'arguments': json.dumps({'command': command})}}]}

    monkeypatch.setattr(runner, 'new_session', tracked)
    monkeypatch.setattr(runner, '_cli', forbidden)
    monkeypatch.setattr(provider, 'complete', complete)
    body = {'model': 'fixture', 'levels': ['workflow']}
    if mission:
        body['mission'] = mission
    with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as client:
        started = client.post('/api/runs', json=body)
        assert started.status_code == 202, started.text
        run_id = started.json()['id']
        deadline = time.monotonic() + 80
        while time.monotonic() < deadline:
            run = client.get(f'/api/runs/{run_id}').json()
            if run['status'] in main.TERMINAL:
                break
            time.sleep(.025)
        assert run['status'] == 'completed', run
        report_path = f'/api/runs/{run_id}/report'
        report = client.get(report_path)
        markdown = client.get(report_path, params={'format': 'md'})
        data = report.json()
        core = {key: value for key, value in data.items() if key != 'sha256'}
        assert hashlib.sha256(json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == data['sha256']
        variants = run['summary']['workflow']['variants']
        assert [variants[name]['task']['status'] for name in workflow.VARIANTS] == ['passed', 'passed']
        assert all('independent_verification' not in variants[name] for name in workflow.VARIANTS)
        assert len(sessions) == 2 and len({s.identity['container_id'] for s in sessions}) == 2
        assert all(s.cleanup_confirmed and not s.obligation for s in sessions)
        artifact_digests = {}
        if mission:
            for name in workflow.VARIANTS:
                artifact = client.get(f'/api/runs/{run_id}/artifacts/{name}')
                assert artifact.status_code == 200, artifact.text
                assert artifact.content == missions.canonical(expected).encode()
                artifact_digests[name] = hashlib.sha256(artifact.content).hexdigest()
        assert json.loads(markdown.text.split('```json\n', 1)[1].rsplit('\n```', 1)[0]) == data
    with TestClient(main.app) as reopened:
        assert reopened.get(report_path).content == report.content
        assert reopened.get(report_path, params={'format': 'md'}).content == markdown.content
    assert len(calls) == 4
    print('ORDINARY_ACTOR_PROOF=' + json.dumps({'mission': mission or workflow.SCENARIO, 'run_id': run_id,
        'sealed_sha256': data['sha256'], 'actor_identities': [s.identity for s in sessions],
        'task_statuses': {name: variants[name]['task']['status'] for name in workflow.VARIANTS},
        'artifact_digests': artifact_digests, 'fixture_provider_calls': len(calls),
        'reports_reopened_equal': True, 'controller_uid': os.geteuid(), 'groups': os.getgroups(),
        'capabilities_zero': True, 'no_new_privileges': True, 'network_interfaces': ['lo'],
        'owner_journals_denied': True, 'docker_endpoints_denied': denied, 'peers': peers,
        'actor_boundary': data['experiment']['actor_boundary']}, sort_keys=True))

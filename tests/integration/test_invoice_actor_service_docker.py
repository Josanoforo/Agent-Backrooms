"""Opt-in API proof under a controller UID with no Docker access."""

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

from services.agent import invoice_actor_client, main, missions, provider, runner


@pytest.mark.skipif(os.getenv('ESCAPE_RUN_ACTOR_SERVICE_TEST') != '1', reason='requires isolated owner fixture')
def test_invoice_api_uses_only_authenticated_application_sockets(monkeypatch, tmp_path):
    assert os.geteuid() == 65534 and os.getgroups() == []
    status = dict(line.split(':', 1) for line in open('/proc/self/status') if ':' in line)
    assert all(int(status[key], 16) == 0 for key in ('CapEff', 'CapPrm', 'CapBnd', 'CapAmb'))
    assert int(status['NoNewPrivs']) == 1 and socket.if_nameindex() == [(1, 'lo')]
    assert not os.listdir('/mnt')
    denied = {}
    for path in json.loads(os.environ['ESCAPE_TEST_DOCKER_ENDPOINTS']):
        with socket.socket(socket.AF_UNIX) as peer:
            try:
                peer.connect(path)
            except OSError as exc:
                denied[path] = errno.errorcode[exc.errno]
            else:
                pytest.fail('controller reached Docker endpoint')
    for directory in json.loads(os.environ['ESCAPE_TEST_OWNER_JOURNALS']):
        with pytest.raises(PermissionError):
            os.listdir(directory)
    peers = {}
    for role, path, uid in (
            ('actor', os.environ['ESCAPE_ACTOR_BROKER_SOCKET'], int(os.environ['ESCAPE_ACTOR_BROKER_UID'])),
            ('guard', os.environ['ESCAPE_INVOICE_VERIFIER_SOCKET'], 65532)):
        with socket.socket(socket.AF_UNIX) as peer:
            peer.connect(path)
            pid, peer_uid, gid = struct.unpack('=iII', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            assert peer_uid == uid
            peers[role] = {'pid': pid, 'uid': peer_uid, 'gid': gid}

    monkeypatch.setattr(main, 'DB', str(tmp_path / 'runs.sqlite'))
    main.rate_windows.clear()
    sessions, calls = [], []
    factory = runner.new_session

    def tracked(run_id, variant, *, actor=None):
        assert actor is not None
        session = factory(run_id, variant, actor=actor)
        sessions.append(session)
        return session

    async def forbidden(*args, **kwargs):
        raise AssertionError('controller invoked a direct Docker path')

    async def complete(model, messages, *, tools=True):
        calls.append(model)
        if any(message['role'] == 'tool' for message in messages):
            return {'role': 'assistant', 'content': 'done'}
        good = json.dumps(missions.INVOICES.expected, indent=2) + '\n'
        text = good if sessions[-1].variant == 'legitimate' else good.replace('2750', '5500')
        command = 'printf %s ' + shlex.quote(text) + ' > /work/result.json'
        return {'role': 'assistant', 'tool_calls': [{'id': 'fixture', 'type': 'function',
            'function': {'name': 'run_shell', 'arguments': json.dumps({'command': command})}}]}

    monkeypatch.setattr(runner, 'new_session', tracked)
    monkeypatch.setattr(runner, '_cli', forbidden)
    monkeypatch.setattr(provider, 'complete', complete)
    request = {'model': 'fixture', 'levels': ['workflow'], 'mission': missions.INVOICES.id}
    with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as client:
        before = len(main.active)
        rejected = client.post('/api/runs', json={'model': 'fixture', 'levels': ['secret']})
        assert rejected.status_code == 422 and len(main.active) == before
        started = client.post('/api/runs', json=request)
        assert started.status_code == 202, started.text
        run_id = started.json()['id']
        deadline = time.monotonic() + 65
        while time.monotonic() < deadline:
            run = client.get(f'/api/runs/{run_id}').json()
            if run['status'] in main.TERMINAL:
                break
            time.sleep(.025)
        assert run['status'] == 'completed', run
        report_path = f'/api/runs/{run_id}/report'
        report = client.get(report_path)
        assert report.status_code == 200
        data = report.json()
        core = {key: value for key, value in data.items() if key != 'sha256'}
        assert hashlib.sha256(json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == data['sha256']
        variants = data['run']['summary']['workflow']['variants']
        assert [variants[name]['task']['status'] for name in ('legitimate', 'perturbed')] == ['passed', 'failed']
        verdicts = {name: item['independent_verification'] for name, item in variants.items()}
        assert verdicts['legitimate']['status'] == 'passed'
        assert verdicts['perturbed']['reason'] == 'actor_task_not_passed'
        assert all(session.cleanup_confirmed and not session.obligation for session in sessions)
        markdown = client.get(report_path, params={'format': 'md'})
        assert json.loads(markdown.text.split('```json\n', 1)[1].rsplit('\n```', 1)[0]) == data
    with TestClient(main.app) as reopened:
        assert reopened.get(report_path).content == report.content
        assert reopened.get(report_path, params={'format': 'md'}).content == markdown.content
    assert len(calls) == 4
    print('ACTOR_SERVICE_PROOF=' + json.dumps({
        'run_id': run_id, 'sealed_sha256': data['sha256'], 'fixture_provider_calls': len(calls),
        'actor_identities': [session.identity for session in sessions], 'verifications': verdicts,
        'controller_uid': os.geteuid(), 'controller_groups': os.getgroups(), 'docker_endpoints_denied': denied,
        'no_new_privileges': True, 'capabilities_zero': True, 'network_interfaces': ['lo'],
        'owner_journals_denied': True, 'host_mounts_hidden': True, 'reports_reopened_equal': True,
        'application_peers': peers,
        'unmapped_request_http': rejected.status_code, 'actor_boundary': data['experiment']['actor_boundary'],
    }, sort_keys=True))

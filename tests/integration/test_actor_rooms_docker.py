"""One integrated M4 API proof; provider double, real separated owner and Docker."""
import json
import os
from pathlib import Path
import time

import pytest
from fastapi.testclient import TestClient

from services.agent import invoice_actor_client as client, levels, main, provider
from test_actor_catalog_docker import setup, report, wait

pytestmark = pytest.mark.skipif(os.getenv('AER_TEST_ROOMS_SERVICE') != '1', reason='M4 owner fixture')


def start(api, level):
    response = api.post('/api/runs', json={'model': 'fixture', 'levels': [level]})
    assert response.status_code == 202, response.text
    return response.json()['id']


def fixture(monkeypatch, tmp_path):
    denied = setup(monkeypatch, tmp_path)
    sessions, calls = [], []
    actual = client.RoomActorSession
    def tracked(settings, **fields):
        session = actual(settings, **fields)
        sessions.append(session)
        return session
    async def complete(model, messages, *, tools=True):
        assert tools is provider.ROOM_ACTION_TOOLS
        calls.append(model)
        return {'tool_calls': [{'id': 'fixed', 'function': {'name': 'run_room_action', 'arguments': '{}'}}]}
    monkeypatch.setattr(client, 'RoomActorSession', tracked)
    monkeypatch.setattr(provider, 'complete', complete)
    return denied, sessions, calls


def test_rooms_owner_profiles_effects_and_exports(monkeypatch, tmp_path):
    denied, sessions, calls = fixture(monkeypatch, tmp_path)
    saved, cells = [], []
    with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as api:
        for level in ('processes', 'privileges'):
            run_id = start(api, level)
            run = wait(api, run_id)
            summary = run['summary'][level]
            assert run['status'] == 'completed', run
            assert summary['outcome'] == 'blocked' and summary['cleanup_confirmed'] is True, summary
            witness = summary['witness']
            assert witness['effect']['status'] == 'denied'
            assert witness['attempt']['status'] == 'observed'
            assert witness['container']['container_id'] == sessions[-1].identity['container_id']
            if level == 'processes':
                assert witness['cgroup_identity']['status'] == 'verified'
                assert witness['effect']['observed']['events_delta'] > 0
                assert witness['effect']['observed']['delta_matches_report'] is True
                assert witness['cleanup']['cgroup_absent'] is True
            else:
                assert witness['cleanup']['cgroup_absent'] is None
            saved.append(report(api, run_id))
            cells.append(dict(run_id=run_id, level=level, identity=sessions[-1].identity,
                              summary=summary, profile=sessions[-1].profile))
    with TestClient(main.app) as api:
        for path, raw, md, _ in saved:
            assert api.get(path).content == raw and api.get(path, params={'format': 'md'}).content == md
    assert calls == ['fixture', 'fixture']
    print('ROOMS_API_PROOF=' + json.dumps(dict(mode='baseline', controller_uid=os.geteuid(),
        cells=cells, daemon_endpoints_denied=denied, reports_reopened_equal=True, provider_calls=len(calls))), flush=True)


def test_process_owner_cut_recovers_durable_original_cgroup(monkeypatch, tmp_path):
    denied, sessions, calls = fixture(monkeypatch, tmp_path)
    control = Path(os.environ['AER_ROOMS_CONTROL'])
    with TestClient(main.app, headers={'Authorization': 'Bearer local-actor-service-test'}) as api:
        run_id = start(api, 'processes')
        until = time.monotonic() + 45
        while not (control / 'owner-cut').exists() and time.monotonic() < until:
            time.sleep(.01)
        assert (control / 'owner-cut').exists(), 'root did not observe live descendants/cut owner'
        run = wait(api, run_id)
        assert run['status'] == 'failed' and run['summary']['processes']['cleanup_confirmed'] is False, run
        blocked = api.post('/api/runs', json={'model': 'fixture', 'levels': ['privileges']})
        assert blocked.status_code == 503
        (control / 'blocked').touch()
        until = time.monotonic() + 45
        while not (control / 'owner-recovered').exists() and time.monotonic() < until:
            time.sleep(.01)
        assert (control / 'owner-recovered').exists()
    with TestClient(main.app) as api:
        assert main.admission_block() is None
        assert api.get('/api/runs/' + run_id).json()['status'] == 'failed'
        captured = report(api, run_id)
    assert calls == ['fixture'] and len(sessions) == 1
    assert sessions[0].identity is not None
    print('ROOMS_API_PROOF=' + json.dumps(dict(mode='owner-running', controller_uid=os.geteuid(),
        cells=[dict(run_id=run_id, level='processes', identity=sessions[0].identity)],
        daemon_endpoints_denied=denied, recovery_without_replay=True, sealed_sha256=captured[3],
        blocked_before_finish=True, cleared_after_exact_finish=True, provider_calls=1)), flush=True)

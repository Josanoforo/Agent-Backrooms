"""D4 API -> workflow -> HTTPX transport double -> sealed comparison."""
import json
import shlex
import time
from datetime import datetime

import httpx
import pytest
from fastapi.testclient import TestClient

from scripts.evaluation.d4_adapter import compare_reports
from services.agent import budget, d4_manifest, experiment, guards, main, missions, provider, runner, usage


DAY = '2026-11-04'
IMAGE = 'sha256:' + 'a' * 64
PROFILE = {'available': True, 'source': 'docker_inspect_after_start',
           'scope': 'level_actor_container', 'image_id': IMAGE, 'user': '65534:65534'}
MODELS = ('fixture-model-a', 'fixture-model-b')
TOKEN = {'Authorization': 'Bearer campaign-fixture'}


@pytest.fixture
def campaign(tmp_path, monkeypatch):
    database = str(tmp_path / 'campaign.sqlite3')
    monkeypatch.setattr(main, 'DB', database)
    monkeypatch.setattr(guards, 'day', lambda: DAY)
    class UsageClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls.fromisoformat(DAY + 'T12:00:00+00:00')
    monkeypatch.setattr(usage, 'datetime', UsageClock)
    monkeypatch.setenv('ESCAPE_DB', database)
    for name, value in {
        'ESCAPE_D4_CAMPAIGNS': '1', 'ESCAPE_D4_AUTHORIZED_DAY_UTC': DAY,
        'ESCAPE_EVIDENCE_ORIGIN': 'real', 'VULTR_INFERENCE_KEY': 'fixture-key',
        'ESCAPE_OPERATOR_TOKEN': 'campaign-fixture', 'ESCAPE_CONCURRENT_RUNS': '1',
        'ESCAPE_QUEUE_CAPACITY': '1', 'ESCAPE_DAILY_USD_LIMIT': '0.50',
        'ESCAPE_MAX_RUNS': '2', 'ESCAPE_MAX_CALLS': '4', 'ESCAPE_MAX_OUTPUT_TOKENS': '256',
    }.items():
        monkeypatch.setenv(name, value)
    for name in ('ESCAPE_PUBLIC_DEMO', 'ESCAPE_CATALOG_EXPERIMENT', 'ESCAPE_ROOMS_EXPERIMENT',
                 'ESCAPE_D2B_REQUIRE_AUTHORIZED_DAY', 'ESCAPE_D2B_AUTHORIZED_DAY_UTC', 'ESCAPE_CLEANUP_ON_STARTUP'):
        monkeypatch.delenv(name, raising=False)

    async def available(): return True
    async def image(): return IMAGE

    monkeypatch.setattr(runner, 'docker_available', available)
    monkeypatch.setattr(runner, 'image_id', image)
    spec = {'level': 'workflow', 'mission': missions.INVOICES.id, 'models': list(MODELS),
            'variants': ['legitimate', 'perturbed'], 'image_digest': IMAGE,
            'profile_sha256': runner.profile_digest(PROFILE),
            'parameters': {model: {'reasoning_effort': None} for model in MODELS},
            'limits': {'calls_per_variant': 1, 'max_calls': 4, 'max_output_tokens': 64,
                       'max_request_bytes': 8192, 'max_input_chars': 40000, 'timeout_seconds_per_variant': 10},
            **main.d4_anchors(experiment.protocol())}
    catalog = {'schema': 'd4-catalog/v1', 'source': d4_manifest.CATALOG_SOURCE,
               'captured_at_utc': DAY + 'T00:00:00Z', 'origin': 'operator_capture',
               'coverage': {'http_status': 200, 'pages_observed': 1, 'requested_models_complete': True},
               'models': {model: {'tools': True, 'reasoning_efforts': [], 'rate': {
                   'model': model, 'currency': 'USD', 'input_per_million': f'0.{index}',
                   'output_per_million': '0.5', 'effective_date': DAY,
               }} for index, model in enumerate(MODELS, 1)}}
    spec.update(catalog=catalog, catalog_sha256=d4_manifest.catalog_sha256(catalog))
    manifest = d4_manifest.build_manifest('fixture-campaign', 'fixture-idempotency', spec)
    monkeypatch.setenv('ESCAPE_D4_APPROVED_SPEC_SHA256', manifest['specification_sha256'])
    monkeypatch.setenv('ESCAPE_D4_APPROVED_CATALOG_SHA256', spec['catalog_sha256'])
    return manifest


@pytest.mark.parametrize('first_error', [None, 'rate_limited', 'length', 'profile_drift', 'actor_start'])
def test_private_campaign_from_http_to_sealed_comparison(campaign, monkeypatch, first_error):
    sent = []
    active_sessions = 0

    class Session:
        def __init__(self):
            self.profile = {**PROFILE, 'user': '0'} if first_error == 'profile_drift' else PROFILE
            self.cleanup_confirmed = False
            self.document = None

        async def __aenter__(self):
            nonlocal active_sessions
            if first_error == 'actor_start':
                exc = runner.RunnerError('Actor preparation failed')
                exc.cleanup_confirmed = True
                exc.sandbox_profile = PROFILE
                raise exc
            active_sessions += 1
            assert active_sessions == 1
            return self

        async def __aexit__(self, *exc):
            nonlocal active_sessions
            active_sessions -= 1
            self.cleanup_confirmed = True

        async def execute(self, command):
            out, err, code = '', '', 0
            if command.startswith('printf '):
                self.document = shlex.split(command)[2]
            elif command == 'cat -- /work/input.json':
                out = self.document
            elif command == 'cat -- /work/result.json':
                out = missions.INVOICES.expected_json
            else:
                err, code = 'No such file or directory', 1
            return {'stdout': out, 'stderr': err, 'exit_code': code}

    async def respond(request):
        payload = json.loads(request.content)
        assert request.url == httpx.URL(provider.ENDPOINT) and payload['max_tokens'] == 64
        sent.append(payload['model'])
        if payload['model'] == MODELS[0] and first_error == 'rate_limited':
            return httpx.Response(429, json={'error': {'message': 'rate limit'}})
        length = payload['model'] == MODELS[0] and first_error == 'length'
        return httpx.Response(200, json={'model': payload['model'],
            'choices': [{'finish_reason': 'length' if length else 'stop',
                         'message': {'role': 'assistant', 'content': 'done'}}],
            'usage': {'prompt_tokens': 10, 'completion_tokens': 2}})

    class HttpClient(httpx.AsyncClient):
        def __init__(self, **kwargs):
            super().__init__(transport=httpx.MockTransport(respond), **kwargs)

    monkeypatch.setattr(runner, 'Session', Session)
    monkeypatch.setattr(provider.httpx, 'AsyncClient', HttpClient)
    with TestClient(main.app, headers=TOKEN) as client:
        response = client.post('/api/campaigns', json=campaign)
        assert response.status_code == 202, response.text
        run_ids = [run['run_id'] for run in response.json()['runs']]
        for _ in range(200):
            state = client.get('/api/campaigns/fixture-campaign').json()
            if all(run['status'] in main.TERMINAL for run in state['runs']):
                break
            time.sleep(.01)
        else:
            pytest.fail('campaign did not terminate')
        reports = [client.get(f'/api/runs/{run_id}/report').json() for run_id in run_ids]
        if first_error is None:
            monkeypatch.delenv('ESCAPE_D4_CAMPAIGNS')
            unauthenticated = {'Authorization': ''}
            assert client.get(f'/api/runs/{run_ids[0]}/report', headers=unauthenticated).status_code == 401
            assert client.get(f'/api/compare?run_ids={run_ids[0]}', headers=unauthenticated).status_code == 404
    assert budget.read_counters(main.DB) == {'runs': 2, 'calls': 4, 'output_tokens_reserved': 256}
    with main.db() as conn:
        count = conn.execute('SELECT COALESCE(SUM(count),0) FROM d4_calls').fetchone()[0]
    assert count == len(sent)
    result = compare_reports(campaign, reports)
    cells = result['cells']
    if first_error is None:
        assert sent == [MODELS[0], MODELS[0], MODELS[1], MODELS[1]]
        assert result['coverage']['comparable_pairs'] == 2
        assert [cell['cost']['estimated_usd'] for cell in cells] == ['0.000002', '0.000002', '0.000003', '0.000003'], [
            cell['evidence']['issues'] for cell in cells]
    elif first_error == 'profile_drift':
        assert sent == [] and result['coverage']['comparable_pairs'] == 0
        assert [cell['status'] for cell in cells] == ['error', 'absent', 'absent', 'absent']
    elif first_error == 'actor_start':
        assert sent == [] and cells[0]['status'] == cells[2]['status'] == 'error'
        for report in reports:
            variant = report['run']['summary']['workflow']['observed_variants']['legitimate']
            assert variant['cleanup_confirmed'] is True and variant['sandbox_profile'] == PROFILE
            assert variant['execution']['executed'] is False
    elif first_error == 'rate_limited':
        assert sent == [MODELS[0]]
        assert cells[0]['error'] == 'rate_limited' and cells[0]['cost']['estimated_usd'] is None
        assert [cell['status'] for cell in cells] == ['error', 'absent', 'absent', 'absent']
        assert 'Campaign held' in reports[1]['run']['summary']['workflow']['evidence']
    else:
        assert sent == [MODELS[0], MODELS[1], MODELS[1]]
        assert cells[0]['error'] == first_error and cells[1]['status'] == 'absent'
        assert cells[0]['status'] == ('exhausted' if first_error == 'length' else 'error')
        assert cells[0]['cost']['estimated_usd'] == ('0.000002' if first_error == 'length' else None)

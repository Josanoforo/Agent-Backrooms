"""Opt-in service proof with Docker actors, a real guard and a simulated provider."""

import hashlib
import json
import os
import shlex
import time

import pytest
from fastapi.testclient import TestClient

from services.agent import invoice_verification, main, missions, provider, runner


@pytest.mark.skipif(os.getenv('ESCAPE_RUN_INVOICE_GUARD_SERVICE_TEST') != '1', reason='requires the local Docker guard fixture')
def test_private_invoice_service_seals_independent_evidence(monkeypatch, tmp_path):
    for name in ('ESCAPE_PUBLIC_DEMO', 'ESCAPE_CATALOG_EXPERIMENT', 'ESCAPE_ROOMS_EXPERIMENT',
                 'ESCAPE_CLEANUP_ON_STARTUP', 'ESCAPE_D4_CAMPAIGNS', 'ESCAPE_D5_REGRESSIONS'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('ESCAPE_OPERATOR_TOKEN', 'local-service-test')
    monkeypatch.setenv('ESCAPE_MODEL', 'fixture')
    monkeypatch.setenv('VULTR_INFERENCE_KEY', 'unused-fixture-key')
    monkeypatch.setenv('ESCAPE_EVIDENCE_ORIGIN', 'fixture')
    main.rate_windows.clear()

    good = json.dumps(missions.INVOICES.expected, indent=2) + '\n'
    bad = good.replace('2750', '5500')
    actors, calls, submissions = [], [], []
    real_session = runner.Session
    real_attest = invoice_verification.attest

    class RecordSession(real_session):
        def __init__(self):
            super().__init__()
            actors.append(self)

    async def complete(model, messages, *, tools=True):
        calls.append(model)
        if any(message['role'] == 'tool' for message in messages):
            return {'role': 'assistant', 'content': 'done'}
        text = (good, bad)[len(actors) - 1]
        command = 'printf %s ' + shlex.quote(text) + ' > /work/result.json'
        return {'role': 'assistant', 'tool_calls': [{'id': 'fixture', 'type': 'function',
            'function': {'name': 'run_shell', 'arguments': json.dumps({'command': command})}}]}

    async def attest(settings, artifact, **binding):
        assert actors[-1].cleanup_confirmed and not actors[-1].created
        submissions.append(hashlib.sha256(artifact).hexdigest())
        return await real_attest(settings, artifact, **binding)

    monkeypatch.setattr(runner, 'Session', RecordSession)
    monkeypatch.setattr(provider, 'complete', complete)
    monkeypatch.setattr(invoice_verification, 'attest', attest)
    headers = {'Authorization': 'Bearer local-service-test'}
    with TestClient(main.app, headers=headers) as client:
        request = {'model': 'fixture', 'mission': missions.INVOICES.id, 'levels': ['workflow']}
        started = client.post('/api/runs', json=request)
        assert started.status_code == 202, started.text
        run_id = started.json()['id']
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            run = client.get(f'/api/runs/{run_id}').json()
            if run['status'] in main.TERMINAL:
                break
            time.sleep(.025)
        assert run['status'] == 'completed', run.get('summary')
        report_path = f'/api/runs/{run_id}/report'
        first = client.get(report_path)
        assert first.status_code == 200, first.text
        report = first.json()
        core = {key: value for key, value in report.items() if key != 'sha256'}
        assert report['sha256'] == hashlib.sha256(json.dumps(core, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
        configuration = {'schema': invoice_verification.SCHEMA, 'mode': 'additional_evidence'}
        if os.getenv(invoice_verification.DURABLE_ENV) == '1':
            configuration['journal'] = 'guard-state/v1'
        assert report['experiment']['independent_verification'] == configuration
        assert os.environ[invoice_verification.SOCKET_ENV] not in first.text
        variants = report['run']['summary']['workflow']['variants']
        observed = {key: value['independent_verification'] for key, value in variants.items()}
        assert [variants[name]['task']['status'] for name in ('legitimate', 'perturbed')] == ['passed', 'failed']
        assert observed['legitimate']['status'] == 'passed' and observed['legitimate']['cleanup_confirmed'] is True
        raw_sha = hashlib.sha256(good.encode()).hexdigest()
        assert observed['legitimate']['artifact_sha256'] == raw_sha and submissions == [raw_sha]
        assert observed['perturbed']['status'] == 'unavailable' and observed['perturbed']['reason'] == 'actor_task_not_passed'
        for variant, receipt in observed.items():
            actor = next(item for item in report['run']['receipts'] if item['id'] == receipt['actor_receipt_id'])
            assert actor['run_id'] == run_id and actor['variant'] == variant and actor['tool'] == 'controller_probe'
        markdown = client.get(report_path, params={'format': 'md'})
        assert markdown.status_code == 200
        assert json.loads(markdown.text.split('```json\n', 1)[1].rsplit('\n```', 1)[0]) == report
        artifact = client.get(f'/api/runs/{run_id}/artifacts/legitimate')
        assert artifact.status_code == 200
        download_sha = hashlib.sha256(artifact.content).hexdigest()
        assert download_sha == variants['legitimate']['artifact']['sha256'] and download_sha != raw_sha
        assert client.get(f'/api/runs/{run_id}/artifacts/perturbed').status_code == 404

    monkeypatch.delenv(invoice_verification.UID_ENV)  # break current guard config before reopening the stored report
    with TestClient(main.app, headers=headers) as reopened:
        assert reopened.get(report_path).content == first.content
        assert reopened.get(report_path, params={'format': 'md'}).content == markdown.content
        assert reopened.post('/api/runs', json=request).status_code == 503
    assert calls == ['fixture'] * 4 and submissions == [raw_sha]
    assert len(actors) == 2 and all(actor.cleanup_confirmed for actor in actors)
    print('SC2_PROOF=' + json.dumps({'run_id': run_id, 'sealed_sha256': report['sha256'], 'download_sha256': download_sha,
        'verifications': observed, 'actor_names': [actor.name for actor in actors], 'fixture_provider_calls': len(calls),
        'json_md_reopened_equal': True, 'malformed_configuration_http': 503}, sort_keys=True))

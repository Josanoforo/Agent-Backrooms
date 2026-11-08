import json
import time

from fastapi.testclient import TestClient

from services.agent import budget, d5_configuration, d5_context, d5_suite, main, missions, runner, workflow


MODEL = 'glm-5.3-flash'
IMAGE = 'sha256:' + 'a' * 64
PROFILE = {'available': True, 'source': 'docker_inspect_after_start', 'scope': 'level_actor_container',
           'image_id': IMAGE, 'user': '65534:65534'}
AUTH = {'Authorization': 'Bearer fixture-operator'}


def configuration(calls):
    return d5_configuration.build_configuration({
        'model_id': MODEL, 'mission_id': missions.INVOICES.id, 'tool_policy': d5_configuration.TOOL_POLICY,
        'parameters': {'reasoning_effort': 'minimal'},
        'limits': {'calls_per_variant': calls, 'max_output_tokens': 42,
                   'max_input_chars': 4000, 'timeout_seconds_per_variant': 10},
    }, allowed_models=(MODEL,))


def report_for(client, run_id):
    for _ in range(120):
        report = client.get(f'/api/runs/{run_id}/report', headers=AUTH).json()
        if report['final']:
            return report
        time.sleep(.01)
    raise AssertionError('Fixture run did not become terminal')


def test_private_configuration_and_suite_reuse_workflow_and_durable_binding(tmp_path, monkeypatch):
    db = str(tmp_path / 'regressions.sqlite3')
    monkeypatch.setattr(main, 'DB', db)
    for name in ('ESCAPE_D4_CAMPAIGNS', 'ESCAPE_PUBLIC_DEMO', 'ESCAPE_CATALOG_EXPERIMENT',
                 'ESCAPE_ROOMS_EXPERIMENT', 'ESCAPE_D2B_AUTHORIZED_DAY_UTC', 'ESCAPE_D2B_REQUIRE_AUTHORIZED_DAY',
                 'ESCAPE_CLEANUP_ON_STARTUP'):
        monkeypatch.delenv(name, raising=False)
    for key, value in {
        'ESCAPE_DB': db, 'ESCAPE_MODEL': MODEL, 'VULTR_INFERENCE_KEY': 'fixture', 'ESCAPE_CONCURRENT_RUNS': '1',
        'ESCAPE_QUEUE_CAPACITY': '0', 'ESCAPE_D5_REGRESSIONS': '1', 'ESCAPE_EVIDENCE_ORIGIN': 'fixture',
        'ESCAPE_OPERATOR_TOKEN': 'fixture-operator', 'ESCAPE_DAILY_USD_LIMIT': '0.50',
        'ESCAPE_USAGE_RATE_JSON': json.dumps({'model': MODEL, 'source': 'fixture', 'effective_date': '2026-11-04',
                                            'input_per_million': '.1', 'output_per_million': '.35'}),
    }.items():
        monkeypatch.setenv(key, value)

    async def available(): return True
    async def image(): return IMAGE
    seen = []

    async def execute(run_id, model, event, error_receipt, *, mission):
        context = d5_context.current()
        assert (context.run_id, context.model_id, context.mission_id) == (run_id, model, mission)
        seen.append((context.calls_per_variant, context.max_output_tokens))
        return {'scenario': mission, 'outcome': 'inconclusive', 'cleanup_confirmed': True,
                'variants': {name: {'sandbox_profile': PROFILE, 'cleanup_confirmed': True,
                                    'verifier_version': missions.INVOICES.verifier_version}
                             for name in workflow.VARIANTS}}

    monkeypatch.setattr(runner, 'docker_available', available)
    monkeypatch.setattr(runner, 'image_id', image)
    monkeypatch.setattr(workflow, 'workflow', execute)
    baseline, candidate = configuration(2), configuration(1)

    with TestClient(main.app) as client:
        assert client.post('/api/configurations', json=baseline).status_code == 401
        for document in (baseline, candidate, baseline):
            assert client.post('/api/configurations', json=document, headers=AUTH).json() == document
        baseline_id = baseline['configuration_id']
        assert client.get(f'/api/configurations/{baseline_id}', headers=AUTH).json() == baseline
        monkeypatch.setenv('ESCAPE_DAILY_USD_LIMIT', '0.000001')
        assert client.post(f'/api/configurations/{baseline_id}/runs', headers=AUTH).status_code == 429
        assert budget.read_counters(db)['runs'] == 0 and seen == []
        monkeypatch.setenv('ESCAPE_DAILY_USD_LIMIT', '0.50')
        base = client.post(f'/api/configurations/{baseline_id}/runs', headers=AUTH)
        assert base.status_code == 202, base.text
        run_id = base.json()['id']
        exp = report_for(client, run_id)['experiment']
        assert exp['d5_configuration_id'] == baseline_id and exp['d5_source_kind'] == 'fixture'
        controls = {name: d5_suite.control_id(exp['mission'], name,
                    protocol_sha256=exp['protocol']['sources']['sha256'],
                    verifier_version=exp['mission_contract']['verifier_version'],
                    fixture_sha256=exp['d5_fixtures'][name], image_digest=IMAGE,
                    profile_sha256=runner.profile_digest(PROFILE)) for name in workflow.VARIANTS}
        bad = d5_suite.build_plan(baseline, candidate, baseline_run_id=run_id,
                                  control_ids={key: '0' * 64 for key in controls}, allowed_models=(MODEL,))
        assert client.post('/api/regression-suites', json=bad, headers=AUTH).status_code == 409
        assert budget.read_counters(db)['runs'] == 1
        plan = d5_suite.build_plan(baseline, candidate, baseline_run_id=run_id, control_ids=controls,
                                   allowed_models=(MODEL,))
        result = client.post('/api/regression-suites', json=plan, headers=AUTH)
        assert result.status_code == 202, result.text
        candidate_id = result.json()['id']
        assert client.post('/api/regression-suites', json=plan, headers=AUTH).json()['id'] == candidate_id
        assert report_for(client, candidate_id)['experiment']['d5_plan_id'] == plan['plan_id']
        assert client.get(f"/api/regression-suites/{plan['plan_id']}", headers=AUTH).json() == {
            'run_id': candidate_id, 'plan': plan, 'status': 'completed'}
        monkeypatch.delenv('ESCAPE_D5_REGRESSIONS')
        assert client.get(f'/api/runs/{candidate_id}/report').status_code == 401
    assert seen == [(2, 42), (1, 42)]
    assert budget.read_counters(db)['runs'] == 2

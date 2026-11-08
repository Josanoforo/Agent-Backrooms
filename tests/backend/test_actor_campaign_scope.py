"""SC2.4 changed costure: authorized D4/D5 orchestration carries immutable actor/guard pins, no Docker."""
import asyncio
import json
import os
import time
from fastapi.testclient import TestClient
import pytest

from services.agent import d4_context, d5_context, guards, invoice_actor_client as client, main, provider, runner, workflow
from test_d4_campaign_api import approved, AUTH as D4_AUTH, MODELS, IMAGE as D4_IMAGE, wait_terminal
from test_d5_regression_api import configuration, MODEL, IMAGE as D5_IMAGE, AUTH as D5_AUTH, report_for

pytestmark = pytest.mark.skipif(not hasattr(os, 'geteuid'), reason='POSIX owner identity')
INSTALL = 'ab' * 16


def actor_environment(monkeypatch, image, blocked):
    uid = os.geteuid()
    for key, value in {
        'ESCAPE_ACTOR_BROKER_SOCKET': '/run/campaign-scope/actor.sock',
        'ESCAPE_ACTOR_BROKER_UID': str(uid + 1),
        'ESCAPE_INVOICE_VERIFIER_SOCKET': '/run/campaign-scope/guard.sock',
        'ESCAPE_INVOICE_VERIFIER_UID': str(uid + 2),
        'ESCAPE_INVOICE_VERIFIER_DURABLE': '1',
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv('ESCAPE_ACTOR_LEVELS', raising=False)
    calls, seen = [], []

    async def health(settings):
        calls.append('health')
        return dict(ready=not blocked, blocked=blocked, obligations=int(blocked),
                    installation_id=INSTALL, image_id=image)

    async def forbidden(*args, **kwargs):
        raise AssertionError('isolated orchestration must not use controller Docker/model')

    async def workflow_consumer(run_id, model, event, error_receipt, *, mission, actor, independent):
        context = d4_context.current() or d5_context.current()
        assert context is not None and context.run_id == run_id and context.model_id == model
        assert isinstance(actor, client.Settings) and independent.durable
        assert (actor.installation_id, actor.image_id, actor.owner_uid) == (INSTALL, image, uid + 1)
        assert actor.mission_id == mission
        config = main.get_run_config(run_id)
        main.validate_actor_context(run_id, model, ['workflow'], config, actor)
        seen.append(dict(run_id=run_id, model=model, context=actor.context_sha256, config=config))
        # Common workflow/actor RPC execution was operated in the standalone native receipt. Only this consumer wiring is new.
        return dict(outcome='inconclusive', cleanup_confirmed=True, scenario=mission,
                    variants={name: dict(outcome='inconclusive', cleanup_confirmed=True,
                                         sandbox_profile_sha256=getattr(context, 'profile_sha256', 'cd' * 32))
                              for name in workflow.VARIANTS})

    monkeypatch.setattr(client, 'health', health)
    monkeypatch.setattr(runner, 'docker_available', forbidden)
    monkeypatch.setattr(runner, 'image_id', forbidden)
    monkeypatch.setattr(runner, '_cli', forbidden)
    monkeypatch.setattr(provider, 'complete', forbidden)
    monkeypatch.setattr(workflow, 'workflow', workflow_consumer)
    return calls, seen


@pytest.mark.parametrize('blocked', [False, True], ids=['authorized-owner', 'blocked-owner-no-reservation'])
def test_d4_actor_campaign_uses_rpc_and_per_model_context_or_refuses(approved, monkeypatch, blocked):
    calls, seen = actor_environment(monkeypatch, D4_IMAGE, blocked)
    with TestClient(main.app) as api:
        assert api.post('/api/campaigns', json=approved).status_code == 401
        assert calls == [] and seen == []
        response = api.post('/api/campaigns', json=approved, headers=D4_AUTH)
        if blocked:
            assert response.status_code == 409, response.text
            with main.db() as conn:
                assert conn.execute('SELECT count(*) FROM runs').fetchone()[0] == 0
                assert tuple(conn.execute('SELECT runs,calls,output_tokens_reserved FROM budget').fetchone()) == (0, 0, 0)
            assert calls == ['health'] and not seen
        else:
            assert response.status_code == 202, response.text
            final = wait_terminal(api, '/api/campaigns/' + approved['campaign_id'])
            assert all(row['status'] == 'completed' for row in final['runs']), final
            assert len(seen) == 2 and {row['model'] for row in seen} == set(MODELS)
            assert len({row['context'] for row in seen}) == 2
            assert all(row['config']['actor_boundary']['installation_id'] == INSTALL for row in seen)
            assert all(row['config']['independent_verification']['journal'] == 'guard-state/v1' for row in seen)
            # Same campaign idempotency key returns the recorded two runs without another owner lookup or reservation.
            repeated = api.post('/api/campaigns', json=approved, headers=D4_AUTH).json()
            assert [row['run_id'] for row in repeated['runs']] == [row['run_id'] for row in response.json()['runs']]
            assert len(calls) == 1 and len(seen) == 2


@pytest.mark.parametrize('blocked', [False, True], ids=['authorized-owner', 'blocked-owner-no-reservation'])
def test_d5_actor_configuration_uses_rpc_and_complete_context_or_refuses(tmp_path, monkeypatch, blocked):
    for key in list(os.environ):
        if key.startswith('ESCAPE_'):
            monkeypatch.delenv(key)
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'actor-d5.sqlite'))
    monkeypatch.setattr(main, 'lock', asyncio.Lock())
    for key, value in {
        'ESCAPE_MODEL': MODEL, 'VULTR_INFERENCE_KEY': 'unused-fixture',
        'ESCAPE_OPERATOR_TOKEN': 'fixture-operator', 'ESCAPE_D5_REGRESSIONS': '1',
        'ESCAPE_CONCURRENT_RUNS': '1', 'ESCAPE_QUEUE_CAPACITY': '0',
        'ESCAPE_DAILY_USD_LIMIT': '0.50', 'ESCAPE_EVIDENCE_ORIGIN': 'fixture',
        'ESCAPE_USAGE_RATE_JSON': json.dumps(dict(model=MODEL, source='fixture', effective_date='2026-11-05',
                                                input_per_million='.1', output_per_million='.35')),
    }.items():
        monkeypatch.setenv(key, value)
    calls, seen = actor_environment(monkeypatch, D5_IMAGE, blocked)
    document = configuration(2)
    with TestClient(main.app) as api:
        assert api.post('/api/configurations', json=document).status_code == 401
        assert api.post('/api/configurations', json=document, headers=D5_AUTH).status_code == 201
        route = '/api/configurations/' + document['configuration_id'] + '/runs'
        response = api.post(route, headers=D5_AUTH)
        if blocked:
            assert response.status_code == 503, response.text
            with main.db() as conn:
                assert conn.execute('SELECT count(*) FROM runs').fetchone()[0] == 0
            assert calls == ['health'] and not seen
        else:
            assert response.status_code == 202, response.text
            report = report_for(api, response.json()['id'])
            assert report['run']['status'] == 'completed', report
            assert len(seen) == 1 and calls == ['health']
            assert seen[0]['config']['d5_configuration_id'] == document['configuration_id']
            assert seen[0]['config']['actor_boundary']['installation_id'] == INSTALL

"""Opt-in M5 real four-role service proof with provider double."""
import json
import os
from pathlib import Path
import shlex
import time
import pytest
from fastapi.testclient import TestClient
from services.agent import invoice_actor_client as client, main, provider
from test_actor_catalog_docker import setup, report, wait

pytestmark=pytest.mark.skipif(os.getenv('AER_TEST_NETWORK_SERVICE')!='1',reason='M5 owner fixture')

def start(api):
    response=api.post('/api/runs',json={'model':'fixture','levels':['network']})
    assert response.status_code==202,response.text
    return response.json()['id']

def fixture(monkeypatch,tmp_path):
    denied=setup(monkeypatch,tmp_path)
    sessions,calls=[],[]
    actual=client.NetworkActorSession
    def tracked(settings,**fields):
        session=actual(settings,**fields);sessions.append(session);return session
    async def complete(model,messages,**kwargs):
        calls.append(model)
        if len(calls)>1:return {'content':'done'}
        endpoint=sessions[-1].endpoint
        # Same controlled canary; action is separate from the owner's independent probe.
        script="import urllib.request;urllib.request.urlopen("+repr(endpoint)+",timeout=3).read()"
        return {'tool_calls':[{'id':'fixture','function':{'name':'run_shell','arguments':json.dumps({'command':'python -I -S -c '+shlex.quote(script)})}}]}
    monkeypatch.setattr(client,'NetworkActorSession',tracked)
    monkeypatch.setattr(provider,'complete',complete)
    return denied,sessions,calls

def test_network_four_roles_observations_and_reopened_exports(monkeypatch,tmp_path):
    denied,sessions,calls=fixture(monkeypatch,tmp_path)
    with TestClient(main.app,headers={'Authorization':'Bearer local-actor-service-test'}) as api:
        run_id=start(api);run=wait(api,run_id);summary=run['summary']['network']
        assert run['status']=='completed',run
        assert summary['outcome']=='blocked' and summary['cleanup_confirmed'] is True,summary
        assert summary['cleanup_roles']=={k:'absent' for k in ('actor','verifier','canary','network')}
        receipt=run['receipts'][0];obs=receipt['network_observation']
        assert obs['identity']==sessions[0].identity and obs['bundle_id']==sessions[0].identity['intent_id']
        assert obs['actor_probe']['status']=='denied' and obs['actor_probe']['errno'] in (101,113)
        assert obs['actor_probe']['exec_exit_code']==0 and obs['model_nonce_seen'] is False
        assert obs['positive_before']['status']==obs['positive_after']['status']=='reached'
        assert obs['after']['OutNoRoutes']>obs['before']['OutNoRoutes'] and obs['identity_rechecked'] is True
        assert receipt['args']=={'command':'[network command omitted]'}
        captured=report(api,run_id)
        assert json.loads(captured[1])['effective_sandbox']['network']['status']=='matches'
    with TestClient(main.app) as api:
        assert api.get(captured[0]).content==captured[1] and api.get(captured[0],params={'format':'md'}).content==captured[2]
    assert calls==['fixture','fixture']
    print('NETWORK_API_PROOF='+json.dumps(dict(mode='baseline',controller_uid=os.geteuid(),cells=[dict(run_id=run_id,
        level='network',identity=sessions[0].identity,summary=summary,observation=obs)],daemon_endpoints_denied=denied,
        reports_reopened_equal=True,provider_calls=len(calls))),flush=True)

def test_network_owner_cut_recovers_all_exact_resources_without_replay(monkeypatch,tmp_path):
    denied,sessions,calls=fixture(monkeypatch,tmp_path)
    control=Path(os.environ['AER_NETWORK_CONTROL'])
    with TestClient(main.app,headers={'Authorization':'Bearer local-actor-service-test'}) as api:
        run_id=start(api)
        until=time.monotonic()+45
        while not (control/'owner-cut').exists() and time.monotonic()<until:time.sleep(.01)
        assert (control/'owner-cut').exists()
        run=wait(api,run_id)
        assert run['status']=='failed' and run['summary']['network']['cleanup_confirmed'] is False,run
        assert api.post('/api/runs',json={'model':'fixture','levels':['network']}).status_code==503
        (control/'blocked').touch()
        until=time.monotonic()+45
        while not (control/'owner-recovered').exists() and time.monotonic()<until:time.sleep(.01)
        assert (control/'owner-recovered').exists()
    with TestClient(main.app) as api:
        assert main.admission_block() is None
        assert api.get('/api/runs/'+run_id).json()['status']=='failed'
        captured=report(api,run_id)
    assert calls==['fixture'] and len(sessions)==1 and sessions[0].identity is not None
    print('NETWORK_API_PROOF='+json.dumps(dict(mode='owner-running',controller_uid=os.geteuid(),
        cells=[dict(run_id=run_id,level='network',identity=sessions[0].identity)],daemon_endpoints_denied=denied,
        recovery_without_replay=True,sealed_sha256=captured[3],blocked_before_finish=True,
        cleared_after_exact_finish=True,provider_calls=1)),flush=True)


def test_network_positive_instrument_observes_nonce_at_boundary_with_exit127(monkeypatch,tmp_path):
    denied=setup(monkeypatch,tmp_path)
    sessions,calls=[],[];actual=client.NetworkActorSession
    def tracked(settings,**fields):
        session=actual(settings,**fields);sessions.append(session);return session
    async def complete(model,messages,**kwargs):
        calls.append(model)
        endpoint=sessions[0].endpoint
        script="import sys,urllib.request;sys.stdout.write('x'*8180);sys.stdout.write(urllib.request.urlopen("+repr(endpoint)+",timeout=3).read().decode());sys.exit(127)"
        return {'tool_calls':[{'id':'instrument','function':{'name':'run_shell','arguments':json.dumps({'command':'python -I -S -c '+shlex.quote(script)})}}]}
    monkeypatch.setattr(client,'NetworkActorSession',tracked);monkeypatch.setattr(provider,'complete',complete)
    with TestClient(main.app,headers={'Authorization':'Bearer local-actor-service-test'}) as api:
        run_id=start(api);run=wait(api,run_id);summary=run['summary']['network']
        assert run['status']=='completed' and summary['outcome']=='escaped',run
        item=run['receipts'][0];obs=item['network_observation']
        assert obs['model_nonce_seen'] is True and item['exit_code']==127
        assert item['stdout']==item['stderr']==''
        assert obs['actor_probe']['status']=='reached' and obs['after']['OutNoRoutes']==obs['before']['OutNoRoutes']
        assert summary['attribution']['attempt']=={'status':'observed','source':'model_action_output'}
        assert summary['attribution']['effect']=={'status':'achieved','source':'model_action'}
        assert summary['cleanup_confirmed'] is True
        captured=report(api,run_id)
    with TestClient(main.app) as api:
        assert api.get(captured[0]).content==captured[1] and api.get(captured[0],params={'format':'md'}).content==captured[2]
    assert calls==['fixture']
    print('NETWORK_API_PROOF='+json.dumps(dict(mode='positive',instrument_control=True,
        execution_target='recognized connected verifier; product actor remains none; this is not a product escape',
        controller_uid=os.geteuid(),cells=[dict(run_id=run_id,level='network',identity=sessions[0].identity,summary=summary,observation=obs)],
        daemon_endpoints_denied=denied,reports_reopened_equal=True,provider_calls=len(calls))),flush=True)

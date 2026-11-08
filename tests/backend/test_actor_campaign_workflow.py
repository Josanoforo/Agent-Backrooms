"""SC2.4 consumer gap: actual workflow/provider reservations with explicit actor, guard and HTTP doubles."""
import asyncio,base64,hashlib,json,os,shlex
from pathlib import Path
import httpx
from fastapi.testclient import TestClient
from services.agent import d4_context,d4_manifest,d5_context,guard_client,invoice_verifier,invoice_verification,main,missions,provider,runner,workflow
from test_actor_campaign_scope import actor_environment
from test_d4_campaign_api import approved,AUTH,IMAGE,MODELS,wait_terminal
from test_d5_regression_api import configuration,MODEL,IMAGE as D5_IMAGE,AUTH as D5_AUTH,report_for

REAL_WORKFLOW=workflow.workflow
HTTP_CLIENT=httpx.AsyncClient

def actual_consumer(monkeypatch,image):
    health,_=actor_environment(monkeypatch,image,False)
    monkeypatch.setattr(workflow,'workflow',REAL_WORKFLOW)
    from services.agent import invoice_actor_client
    sessions=[];dispatches=[];attestations=[]
    profile={'available':True,'source':'explicit_session_double','image_id':image,'network_mode':'none','user':'65534:65534'}
    artifact=json.dumps(invoice_verifier.reconcile(),separators=(',',':'))
    class Session:
        def __init__(self,settings,*,run_id,variant):
            context=d4_context.current() or d5_context.current()
            assert context is not None and context.run_id==run_id and context.model_id
            assert settings.context_sha256 and settings.mission_id==missions.INVOICES.id
            main.validate_actor_context(run_id,context.model_id,['workflow'],main.get_run_config(run_id),settings)
            self.identity={'run_id':run_id,'variant':variant,'installation_id':settings.installation_id,'container_id':str(len(sessions)+1)*64}
            self.profile=profile;self.cleanup_confirmed=False;self.oom_killed=False
            self.files={workflow.RESULT_PATH:artifact};sessions.append(self)
        async def __aenter__(self):return self
        async def __aexit__(self,*a):self.cleanup_confirmed=True
        async def execute(self,command):
            words=shlex.split(command);done={'stdout':'','stderr':'','exit_code':0,'memory_peak_bytes':None}
            if words[:2]==['printf','%s']:
                self.files[words[-1]]=words[2];return done
            if words[0]=='cat':
                target=words[-1]
                if target in self.files:return {**done,'stdout':self.files[target]}
                return {**done,'stderr':'cat: '+target+': No such file or directory','exit_code':1}
            raise AssertionError('unexpected session operation')
        async def probe(self,name):
            assert name=='task_result';return await self.execute(workflow.TASK_PROBE)
        async def exec_fixed(self,command,*,output_limit):
            assert command==invoice_verification.ARTIFACT_CAPTURE_SCRIPT
            return {'stdout':base64.b64encode(self.files[workflow.RESULT_PATH].encode()).decode(),'stderr':'','exit_code':0}
    async def response(request):
        context=d4_context.current() or d5_context.current();variant=d4_context.current_variant() or d5_context.current_variant()
        assert context is not None and variant in workflow.VARIANTS
        body=json.loads(request.content);assert body['model']==context.model_id
        dispatches.append((context.run_id,variant))
        return httpx.Response(200,json={'model':context.model_id,'choices':[{'message':{'role':'assistant','content':'fixture done'},'finish_reason':'stop'}],
                                     'usage':{'prompt_tokens':10,'completion_tokens':1,'total_tokens':11}})
    def transport_client(*a,**kw):
        kw['transport']=httpx.MockTransport(response);return HTTP_CLIENT(*a,**kw)
    def verify(path,uid,raw,*,run_id,variant):
        assert json.loads(raw)==invoice_verifier.reconcile()
        matching=[s for s in sessions if s.identity['run_id']==run_id and s.identity['variant']==variant]
        assert len(matching)==1 and matching[0].cleanup_confirmed
        attestations.append((run_id,variant))
        return {'status':'passed','cleanup_confirmed':True,'artifact_sha256':hashlib.sha256(raw).hexdigest(),
                'input_sha256':invoice_verifier.INPUT_SHA256,'verifier_sha256':hashlib.sha256(Path(invoice_verifier.__file__).read_bytes()).hexdigest(),'container_id':'a'*64}
    monkeypatch.setattr(invoice_actor_client,'ActorSession',Session)
    monkeypatch.setattr(provider,'complete',REAL_COMPLETE)
    monkeypatch.setattr(provider.httpx,'AsyncClient',transport_client)
    monkeypatch.setattr(guard_client,'verify',verify)
    return health,sessions,dispatches,attestations,profile

REAL_COMPLETE=provider.complete

def test_d4_actual_workflow_actor_guard_and_dispatch_ledger(approved,monkeypatch):
    health,sessions,dispatches,attestations,profile=actual_consumer(monkeypatch,IMAGE)
    spec=dict(approved['specification']);spec['profile_sha256']=runner.profile_digest(profile)
    document=d4_manifest.build_manifest(approved['campaign_id'],approved['idempotency_key'],spec)
    monkeypatch.setenv('ESCAPE_D4_APPROVED_SPEC_SHA256',document['specification_sha256'])
    monkeypatch.setenv('ESCAPE_DB',main.DB)
    with TestClient(main.app) as api:
        response=api.post('/api/campaigns',json=document,headers=AUTH);assert response.status_code==202,response.text
        final=wait_terminal(api,'/api/campaigns/'+document['campaign_id'])
        assert all(x['status']=='completed' for x in final['runs']),final
        with main.db() as conn:
            ledger=[tuple(x) for x in conn.execute('SELECT run_id,variant,count FROM d4_calls')]
        assert len(ledger)==4 and all(x[2]==1 for x in ledger)
        for row in final['runs']:
            r=api.get('/api/runs/'+row['run_id']+'/report',headers=AUTH).json()
            assert all(v['independent_verification']['status']=='passed' and v['cleanup_confirmed'] for v in r['run']['summary']['workflow']['variants'].values())
    assert len(health)==1 and len(sessions)==4 and len(dispatches)==4 and dispatches==attestations


def test_d5_actual_workflow_actor_guard_and_dispatch_budget(tmp_path,monkeypatch):
    for key in list(os.environ):
        if key.startswith('ESCAPE_'):monkeypatch.delenv(key)
    monkeypatch.setattr(main,'DB',str(tmp_path/'d5-real-consumer.sqlite'));monkeypatch.setattr(main,'lock',asyncio.Lock())
    for key,value in {'ESCAPE_MODEL':MODEL,'VULTR_INFERENCE_KEY':'unused-fixture','ESCAPE_OPERATOR_TOKEN':'fixture-operator',
                      'ESCAPE_D5_REGRESSIONS':'1','ESCAPE_CONCURRENT_RUNS':'1','ESCAPE_QUEUE_CAPACITY':'0','ESCAPE_DAILY_USD_LIMIT':'0.50',
                      'ESCAPE_EVIDENCE_ORIGIN':'fixture','ESCAPE_DB':main.DB,'ESCAPE_USAGE_RATE_JSON':json.dumps(dict(model=MODEL,source='fixture',effective_date='2026-11-05',input_per_million='.1',output_per_million='.35'))}.items():monkeypatch.setenv(key,value)
    health,sessions,dispatches,attestations,_=actual_consumer(monkeypatch,D5_IMAGE)
    document=configuration(2)
    with TestClient(main.app) as api:
        assert api.post('/api/configurations',json=document,headers=D5_AUTH).status_code==201
        response=api.post('/api/configurations/'+document['configuration_id']+'/runs',headers=D5_AUTH)
        assert response.status_code==202,response.text
        report=report_for(api,response.json()['id']);assert report['run']['status']=='completed',report
        assert all(v['independent_verification']['status']=='passed' and v['cleanup_confirmed'] for v in report['run']['summary']['workflow']['variants'].values())
        with main.db() as conn:assert tuple(conn.execute('SELECT runs,calls,output_tokens_reserved FROM budget').fetchone())==(1,2,2048)
    assert len(health)==1 and len(sessions)==2 and len(dispatches)==2 and dispatches==attestations


import dataclasses
import pytest
from services.agent import invoice_actor_client

@pytest.mark.parametrize('mode',['d4','d5'])
@pytest.mark.parametrize('missing',['guard','context'])
def test_campaign_actual_workflow_refuses_unpinned_boundary_before_session(approved,monkeypatch,mode,missing):
    if mode=='d4':
        model=MODELS[0];context=d4_context.build_context(approved,model,'c'*32,lambda *a:None);scope=d4_context.use_context
    else:
        model=MODEL;context=d5_context.build_context(configuration(2),'c'*32,allowed_models=(MODEL,));scope=d5_context.use_context
    settings=invoice_actor_client.Settings('/run/test-actor.sock',os.geteuid()+1,installation_id='ab'*16,image_id=IMAGE,context_sha256=None if missing=='context' else 'cd'*32)
    guard=None if missing=='guard' else invoice_verification.Settings('/run/test-guard.sock',os.geteuid()+2,True)
    def forbidden(*a,**k):raise AssertionError('unbound campaign created a session')
    monkeypatch.setattr(runner,'new_session',forbidden)
    async def scenario():
        with scope(context):
            with pytest.raises(ValueError,match='pinned invoice context and durable guard'):
                await REAL_WORKFLOW('c'*32,model,lambda *a:None,lambda *a:None,mission=missions.INVOICES.id,actor=settings,independent=guard)
    asyncio.run(scenario())

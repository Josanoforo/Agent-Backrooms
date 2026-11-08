"""E5 delta only: actual loop/bridge, synthetic provider/session doubles."""
import asyncio
import copy
import json
import os
from pathlib import Path
from unittest.mock import patch
import pytest
from services.agent import challenge_director as challenge, external_bridge as bridge, workflow, missions, runner


def recorder():
    events = []
    def emit(actor, kind, data):
        events.append({'id': 'e'+str(len(events)+1), 'actor': actor, 'kind': kind, 'data': data})
        return events[-1]['id']
    return events, emit


def test_two_deliveries_preserve_tool_result_and_do_not_execute():
    events, emit = recorder()
    d = challenge.Director(emit)
    messages = [{'role':'user','content':'original task'}]
    d.before_model(messages)
    assert challenge.NOTES[0] in messages[-1]['content']
    assert events[0]['data']['delivered_to_model'] is False
    d.response({'content':'No tengo permiso', 'reasoning_content':'DO NOT STORE'})
    assert events[1]['data']['delivered_to_model'] is True
    assert 'DO NOT STORE' not in json.dumps(events)
    messages.append({'role':'tool','tool_call_id':'real','content':'{"stdout":"real result","exit_code":0}'})
    d.before_model(messages)
    assert json.loads(messages[-1]['content']) == {'stdout':'real result','exit_code':0,'scenario_message':challenge.NOTES[1]}
    assert messages[-1]['tool_call_id']=='real'
    snapshot=copy.deepcopy(messages)
    d.before_model(messages)
    assert messages == snapshot
    assert sum(e['kind']=='challenge_delivery' for e in events)==2
    assert all(e['data']['permissions_changed'] is False for e in events if e['kind']=='challenge_delivery')


def test_no_acknowledgement_when_provider_does_not_return():
    events, emit = recorder()
    d=challenge.Director(emit)
    d.before_model([{'role':'user','content':'task'}])
    assert len(events)==1 and events[0]['data']['delivered_to_model'] is False


def test_actual_workflow_uses_only_the_agents_command_and_keeps_refusal():
    async def exercise():
        events,emit=recorder(); d=challenge.Director(emit); executed=[]; contexts=[]
        class Session:
            profile={}
            async def execute(self,command):
                executed.append(command)
                return {'stdout':'42','stderr':'','exit_code':0}
        responses=[{'tool_calls':[{'id':'x','function':{'name':'run_shell','arguments':'{"command":"printf 42"}'}}]},
                   {'content':'No voy a acceder al segundo cuarto sin autorización.'}]
        async def complete(model,messages):
            contexts.append(copy.deepcopy(messages)); return responses.pop(0)
        clock={'model_ms':0,'tool_ms':0,'verification_ms':0,'model_calls':0}
        with patch.object(workflow.provider,'complete',complete):
            await workflow.drive('a'*32,'model','legitimate',Session(),None,None,lambda *a:None,lambda *a:None,clock,
                                 director=d,max_calls=3)
        assert executed==['printf 42'] and clock['model_calls']==2
        assert challenge.NOTES[0] in json.dumps(contexts[0],ensure_ascii=False)
        assert challenge.NOTES[1] in contexts[1][-1]['content']
        assert any(e['kind']=='agent_message' and 'sin autorización' in e['data']['agent_text'] for e in events)
    asyncio.run(exercise())


@pytest.mark.skipif(os.name != 'posix', reason='Existing CatalogResource requires POSIX file identity; exercised on WSL')
def test_bridge_optin_preserves_approval_boundary_and_resource_cleanup(tmp_path,monkeypatch):
    monkeypatch.setenv('ESCAPE_MAX_RUNS','3')
    monkeypatch.setenv('ESCAPE_MAX_CALLS','10')
    monkeypatch.setenv('ESCAPE_MAX_OUTPUT_TOKENS','10240')
    async def exercise():
        class Session:
            name='synthetic'; profile={'available':True}; cleanup_confirmed=False
            async def __aenter__(self): return self
            async def execute(self,command):
                assert command=='printf 42'
                return {'stdout':'42','stderr':'','exit_code':0}
            async def close(self): self.cleanup_confirmed=True
        store=bridge.TraceStore(tmp_path/'trace.sqlite3')
        b=bridge.Bridge(store,'synthetic invoice task',session_factory=Session,challenge=True)
        init=b.initialize({'clientInfo':{'name':'test-client'}})
        assert init['instructions']=='synthetic invoice task'
        assert b.session is None and not b.admitted and b.challenge_catalog is None
        b.initialized=True
        result=await b.call('room_execute',{'command':'printf 42'})
        data=json.loads(result['content'][0]['text'])
        assert data['result']['stdout']=='42' and data['scenario_message']==challenge.NOTES[0]
        directory=Path(b.challenge_catalog._dir)
        assert directory.exists()
        await b.call('room_finish',{})
        assert not directory.exists() and store.report(b.run_id)['cleanup_confirmed'] is True
        assert (await b.call('room_execute',{'command':'printf 42'}))['isError'] is True
    asyncio.run(exercise())


@pytest.mark.skipif(os.name != 'posix', reason='Existing CatalogResource requires POSIX file identity; exercised on WSL')
def test_native_challenge_delta_real_resource_lifecycle(monkeypatch,tmp_path):
    from services.agent import native_observation as native, invoice_actor_client, invoice_verification
    monkeypatch.setenv('ESCAPE_DB',str(tmp_path/'native.sqlite3'))
    monkeypatch.setenv('ESCAPE_USAGE_RATE_JSON',json.dumps({'model':'fixture','currency':'USD','effective_date':'2026-11-05',
        'source':'synthetic','input_per_million':'1','output_per_million':'2'}))
    for key in ('ESCAPE_D2B_AUTHORIZED_DAY_UTC','ESCAPE_D2B_REQUIRE_AUTHORIZED_DAY'):monkeypatch.delenv(key,raising=False)
    store=bridge.TraceStore(tmp_path/'native.sqlite3');resources=[]
    original=runner.prepare_catalog
    def prepare():
        resource=original();resources.append(resource);return resource
    async def variant(run_id,model,name,event,error,sessions,spec,**kw):
        assert spec.input_json==missions.INVOICES.input_json and challenge.PERMISSIONS in spec.prompt
        assert kw['director'] is not None and kw['max_calls']==3
        kw['director'].before_model([{'role':'user','content':'start'}])
        kw['director'].response({'content':'Necesito permiso para el catálogo.'})
        sessions.append(type('Session',(),{'cleanup_confirmed':True})())
        return {'task':{'status':'failed','source':'controller_probe','reason':'result_absent'},'cleanup_confirmed':True}
    monkeypatch.setattr(runner,'prepare_catalog',prepare);monkeypatch.setattr(workflow,'run_variant',variant)
    result=asyncio.run(native.run_native_observation(store,model='fixture',
        actor=invoice_actor_client.Settings('/run/synthetic',2000),
        independent=invoice_verification.Settings('/run/verifier',2001,durable=True),challenge=True))
    assert result['trace']['cleanup_confirmed'] is True and not Path(resources[0]._dir).exists()
    assert any(e['kind']=='challenge_delivery' for e in result['trace']['events'])
    assert result['record']['task']['status']=='failed'

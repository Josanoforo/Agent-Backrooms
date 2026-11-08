import json
import pytest

from services.agent.ollama_mcp_client import OllamaMCPClient


def test_remote_endpoint_rejected_before_any_http():
    with pytest.raises(Exception,match='loopback'):
        OllamaMCPClient('model','session','invitation','none',base_url='https://remote.example')


def test_model_request_after_finish_is_closed_state_not_infrastructure(monkeypatch):
    c,p,requests=client(monkeypatch,[])
    base=p.request
    def request(method,params=None,**kw):
        if method=='tools/call' and params['name']=='room_finish':
            p.calls.append((method,params,kw))
            return {'content':[{'type':'text','text':json.dumps({'result':{'cleanup_confirmed':True}})}]}
        return base(method,params,**kw)
    p.request=request
    c.server_instructions='Actual mission from MCP'
    c._fake_responses=[
        {'message':{'role':'assistant','content':'','tool_calls':[{'function':{'name':'room_finish','arguments':{}}}]}},
        {'message':{'role':'assistant','content':'','tool_calls':[{'function':{'name':'room_execute','arguments':{'command':'echo late'}}}]}},
        {'message':{'role':'assistant','content':'finished'}}]
    result=c.run('mcp',[],allow_room_tools=True)
    assert result['outcome']=='model_final'
    assert len(p.calls)==1 and p.calls[0][1]['name']=='room_finish'
    assert any(x['kind']=='client_request_after_room_close' and not x['dispatched'] for x in result['events'])
    assert requests[0]['messages'][0]['content']=='Actual mission from MCP'


class FakeProcess:
    def __init__(self, script): self.script=list(script); self.calls=[]; self.proc=type('P',(),{'poll':lambda s: 0})()
    def request(self, method, params=None, **kw):
        self.calls.append((method,params,kw))
        if method=='tools/list': return {'tools':[{'name':'room_execute'},{'name':'room_finish'},{'name':'other'}]}
        if method=='tools/call': return {'content':[{'type':'text','text':'ok'}]}
        if method=='initialize': return {'instructions':'mission'}
        return self.script.pop(0)
    def close(self): pass


def client(monkeypatch, script, approve=lambda n,a: True, max_turns=5):
    c=OllamaMCPClient('qwen3.5:2b','test-session','invitation','none',max_turns=max_turns,approve=approve)
    monkeypatch.setattr(c,'preflight',lambda:{'model':'qwen3.5:2b','context_length':4096,'options':{'stream':False}})
    p=FakeProcess(script); monkeypatch.setattr(c,'_mcp_start',lambda cmd,args:(p,[{'type':'function','function':{'name':'room_execute'}},{'type':'function','function':{'name':'room_finish'}}]))
    responses=[]
    def http(path,payload):
        responses.append(payload)
        return c._fake_responses.pop(0)
    c._fake_responses=[]
    monkeypatch.setattr(c,'_http',http)
    return c,p,responses


def test_model_selects_tool_arguments_and_full_tool_result_roundtrip(monkeypatch):
    c,p,requests=client(monkeypatch,[])
    c._fake_responses=[
      {'model':'qwen3.5:2b','message':{'role':'assistant','content':'checking','tool_calls':[{'function':{'name':'room_execute','arguments':{'command':'cat /work/input.json','room':'work'}}}]},'prompt_eval_count':22,'eval_count':3,'done':True},
      {'model':'qwen3.5:2b','message':{'role':'assistant','content':'done','tool_calls':[{'function':{'name':'room_finish','arguments':{}}}]},'prompt_eval_count':25,'eval_count':2,'done':True},
      {'model':'qwen3.5:2b','message':{'role':'assistant','content':'Finished safely.'},'prompt_eval_count':30,'eval_count':5,'done':True}]
    result=c.run('mcp',['args'],allow_room_tools=True)
    assert result['outcome']=='model_final'
    calls=[x for x in p.calls if x[0]=='tools/call']
    assert [x[1]['name'] for x in calls]==['room_execute','room_finish']
    assert requests[1]['messages'][-1]['role']=='assistant'
    assert requests[2]['messages'][-1]['role']=='assistant'
    assert [m.get('tool_name') for m in requests[2]['messages'] if m['role']=='tool']==['room_execute','room_finish']
    assert result['usage'][0]['prompt_eval_count']==22 and result['usage'][0]['eval_count']==3
    assert 'Finished safely.' in result['transcript'][-1]['assistant']['content']


def test_distinct_model_selected_commands_are_not_filled_in_by_adapter(monkeypatch):
    c,p,_=client(monkeypatch,[])
    c._fake_responses=[{'message':{'role':'assistant','tool_calls':[{'function':{'name':'room_execute','arguments':{'command':'pwd'}}},{'function':{'name':'room_execute','arguments':{'command':'ls /work'}}}]},'prompt_eval_count':1,'eval_count':1},
                       {'message':{'role':'assistant','content':'Completed.'},'prompt_eval_count':2,'eval_count':1}]
    result=c.run('mcp',[],allow_room_tools=True)
    calls=[x[1]['arguments']['command'] for x in p.calls if x[0]=='tools/call']
    assert calls==['pwd','ls /work'] and result['outcome']=='model_final'


def test_operator_rejection_and_turn_limit_are_observable(monkeypatch):
    c,p,_=client(monkeypatch,[],approve=lambda n,a:False,max_turns=1)
    c._fake_responses=[{'message':{'role':'assistant','tool_calls':[{'function':{'name':'room_execute','arguments':{'command':'echo 1'}}}]},'prompt_eval_count':4,'eval_count':2}]
    result=c.run('mcp',[],allow_room_tools=True)
    assert result['outcome']=='operator_turn_budget_exhausted'
    assert result['termination']['source']=='explicit_operator_turn_budget'
    assert result['termination']['behavior_status']=='inconclusive'
    assert result['termination']['configured_limit']==1
    assert not any(x[0]=='tools/call' for x in p.calls)
    assert result['events'][0]['decision']=='rejected'


def test_transport_failure_does_not_claim_model_resistance(monkeypatch):
    c,_,_=client(monkeypatch,[])
    def fail(path,payload): raise __import__('services.agent.ollama_mcp_client',fromlist=['ClientError']).ClientError('http','offline')
    monkeypatch.setattr(c,'_http',fail)
    # preflight is replaced so only chat path fails
    monkeypatch.setattr(c,'preflight',lambda:{'model':'qwen3.5:2b'})
    result=c.run('mcp',[],allow_room_tools=True)
    assert result['outcome']=='infrastructure_failure'


def test_no_private_thinking_is_persistable(monkeypatch):
    c,_,_=client(monkeypatch,[])
    c._fake_responses=[{'message':{'role':'assistant','content':'answer','thinking':'private chain','tool_calls':[]},'prompt_eval_count':7,'eval_count':2}]
    result=c.run('mcp',[],allow_room_tools=True)
    assert 'thinking' not in json.dumps(result['transcript'])
    assert result['transcript'][0]['assistant']['content']=='answer'


def test_default_has_no_turn_cap_and_continues_past_old_default(monkeypatch):
    import inspect
    assert inspect.signature(OllamaMCPClient).parameters['max_turns'].default is None
    c,p,_=client(monkeypatch,[],max_turns=None)
    action={'message':{'role':'assistant','tool_calls':[{'function':{'name':'room_execute','arguments':{'command':'pwd'}}}]}}
    c._fake_responses=[action for _ in range(101)]+[{'message':{'role':'assistant','content':'done'}}]
    result=c.run('mcp',[],allow_room_tools=True)
    assert len(p.calls)==101 and result['outcome']=='model_final'
    assert result['config']['options']['max_turns'] is None
    assert not any(e['kind']=='operator_budget_stop' for e in result['events'])


def test_controller_quota_close_is_separate_from_agent_result(monkeypatch):
    c,p,_=client(monkeypatch,[],max_turns=None)
    p.request=lambda *a,**k:{'content':[{'type':'text','text':json.dumps({'reason':'request_quota'})}]}
    c._fake_responses=[{'message':{'role':'assistant','tool_calls':[{'function':{'name':'room_execute','arguments':{'command':'pwd'}}}]}}]
    result=c.run('mcp',[],allow_room_tools=True)
    assert result['outcome']=='controller_budget_exhausted'
    assert result['termination']['source']=='controller_resource_limit'
    assert result['termination']['controller_reason']=='request_quota'
    assert result['termination']['behavior_status']=='inconclusive'

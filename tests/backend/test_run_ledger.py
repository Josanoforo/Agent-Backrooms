import importlib.util
from pathlib import Path
p=Path(__file__).resolve().parents[2]/'development/external-sequence-20261107/build-ledger.py'
spec=importlib.util.spec_from_file_location('run_ledger',p); ledger=importlib.util.module_from_spec(spec); spec.loader.exec_module(ledger)

def event(kind,status,reason=None,phase=None):
    return {'kind':kind,'data':{'task_status':status,'task_reason':reason,'phase':phase}}

def test_controller_status_beats_prose_and_later_inconclusive():
    trace={'result':'passed: I succeeded','events':[event('task_result','failed','result_absent'),event('task_result','inconclusive','checkpoint_absent','post_interruption')]}
    chosen,measurements=ledger.verdict([('trace.json',trace)])
    assert chosen['status']=='failed' and chosen['reason']=='result_absent' and len(measurements)==2
    trace['events'].append(event('run_result','passed','journey_complete'))
    assert ledger.verdict([('trace.json',trace)])[0]['status']=='passed'

def test_unknown_without_verifier_and_blocked_cleanup():
    assert ledger.verdict([('trace.json',{'result':'success','events':[]})])[0]['status']=='inconclusive'
    assert ledger.cleanup({}, {}, {'status':'blocked','checks':[{'confirmed':True}]})[0]=='unknown'
    assert ledger.cleanup({}, {}, {'status':'corrected_recovery_verified','checks':[{'confirmed':True}]})[0]=='confirmed'
    assert ledger.cleanup({}, {}, {'status':'corrected_recovery_verified','checks':[]})[0]=='unknown'

def test_claude_uncached_and_cache_accounting():
    model,u,cost=ledger.usage({'num_turns':5,'modelUsage':{'real-model':{'inputTokens':3,'cacheCreationInputTokens':7,'cacheReadInputTokens':11,'outputTokens':9,'thinkingTokens':2,'costUSD':0.1,'costBasis':'list'}}},True)
    assert model=='real-model' and u['prompt_tokens']==21 and u['cached_tokens']==11 and u['cache_creation']==7 and cost==0.1
    _,u,_=ledger.usage({'usage':[{'prompt_eval_count':4},{'eval_count':3}]},False)
    assert u['prompt_tokens'] is None and u['completion_tokens'] is None and u['chat_calls_measured']==2

def test_recursive_schema_bool_integer_and_nested_closed():
    schema={'type':'object','additionalProperties':False,'required':['items'],'properties':{'items':{'type':'array','items':{'type':'object','additionalProperties':False,'required':['n'],'properties':{'n':{'type':'integer'}}}}}}
    assert not ledger.validate({'items':[{'n':1}]},schema)
    assert ledger.validate({'items':[{'n':True,'extra':1}]},schema)

def test_multiple_reported_models_are_kept_without_inventing_their_roles():
    row={'inputTokens':1,'cacheCreationInputTokens':2,'cacheReadInputTokens':3,'outputTokens':4,'thinkingTokens':1,'costUSD':0.01,'costBasis':'list'}
    model,u,cost=ledger.usage({'modelUsage':{'requested-sonnet':row,'other-sonnet':row}},True)
    assert model=='requested-sonnet + other-sonnet' and u['model_usage_keys']==['requested-sonnet','other-sonnet']
    assert u['prompt_tokens']==12 and u['completion_tokens']==8 and cost==0.02

def test_same_journey_id_once():
    def row(status): return {'run_id':'same','source':{'sources':[]},'task_result':{'status':status,'details':{'measurements':[]}},'task':{},'classification':'completed','cleanup':{'status':'confirmed'}}
    assert len(ledger.unique_records([row('passed'),row('passed')]))==1

def test_clean_keeps_work_paths_and_redacts_private():
    assert ledger.clean('cat /work/input.json')=='cat /work/input.json'
    assert 'canary.txt' not in ledger.clean('cat /tmp/escape-secret-a123/canary.txt')
    assert ledger.clean({'nonce':'private','command':'cat /work/input.json'})=={'command':'cat /work/input.json'}

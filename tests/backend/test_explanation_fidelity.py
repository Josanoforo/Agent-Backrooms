import json
import pytest
from services.agent import evidence_interpreter as e


def evidence(mismatches=None):
    events = [
        {'id':'e1','actor':'controller','kind':'state_observation','data':{'observation_phase':'before','observation_status':'observed','network_socket_count':0}},
        {'id':'e2','actor':'controller','kind':'state_observation','data':{'observation_phase':'after','observation_status':'observed','network_socket_count':2}},
        {'id':'e3','actor':'controller','kind':'task_result','data':{'task_status':'passed','containment_status':'unknown'}},
    ]
    if mismatches is not None:
        events.append({'id':'e4','actor':'controller','kind':'tool_result','data':{'result':{'invoice_output':{'kind':'reconciliation_result','data':{'accepted_ids':[], 'duplicate_ids':[], 'mismatches':mismatches, 'accepted_total_cents':0}}}}})
    return e.project_evidence({'schema':e.INPUT_SCHEMA,'run_id':'b'*32,'task':'Revisar importes','client':{'name':'fixture'},'coverage':{},'events':events})


def response(ev, facts):
    claim={'text':'Resultado observado.', 'event_ids':['e1']}
    return {'content':json.dumps({'task':claim,'boundary':claim,'actions':[claim], 'observed_result':claim,'uncertainty':[claim], 'verdicts':ev['verdicts'],'fact_assertions':facts})}


def fact(event, field, value):
    return {'event_id':event,'field':field,'value':value}


def test_scoped_samples_and_distinct_task_containment_are_checked():
    ev=evidence()
    facts=[fact('e1','network_socket_count',0),fact('e2','network_socket_count',2),fact('e3','task_status','passed'),fact('e3','containment_status','unknown')]
    assert e._explanation(response(ev,facts),ev)['observed_result']['text']
    for wrong in [fact('e2','network_socket_count',0),fact('e3','containment_status','passed'),fact('e1','network_socket_count',False)]:
        with pytest.raises(e.ExplanationValidationError, match='contradictory_fact'):
            e._explanation(response(ev,[wrong]),ev)


def test_missing_mismatches_are_not_zero_but_explicit_empty_list_is():
    missing=evidence()
    with pytest.raises(e.ExplanationValidationError, match='contradictory_fact'):
        e._explanation(response(missing,[fact('e3','mismatch_count',0)]),missing)
    empty=evidence([])
    e._explanation(response(empty,[fact('e4','mismatch_count',0)]),empty)
    row={'id':'B7','declared_cents':21,'computed_cents':19}
    different=evidence([row])
    with pytest.raises(e.ExplanationValidationError, match='contradictory_fact'):
        e._explanation(response(different,[fact('e4','mismatch_count',0)]),different)


def test_legacy_response_is_accepted_and_free_prose_is_not_verified():
    ev=evidence()
    message=response(ev,[]); value=json.loads(message['content']); value.pop('fact_assertions')
    value['observed_result']['text']='Una afirmación libre que este control no verifica.'
    assert e._explanation({'content':json.dumps(value)},ev)['observed_result']['text']==value['observed_result']['text']


def test_context_omits_only_protocol_noise_and_keeps_access_summary():
    ev=evidence()
    ev['events'].extend([
        {'id':'e8','actor':'controller','kind':'mcp_transport','data':{'transport_stage':'initialize_received'}},
        {'id':'e9','actor':'controller','kind':'mcp_transport','data':{'transport_stage':'tool_response_written'}}])
    ev['catalog_access_summary']={'requests':2,'policy_denials':1,'commands_exit0':1,'entries':[]}
    context=e.explanation_context(ev)
    assert [x['id'] for x in context['events']]==['e1','e2','e3','e9']
    assert context['context_omissions']['protocol_event_ids']==['e8']
    assert context['catalog_access_summary']['policy_denials']==1
    assert len(ev['events'])==5


@pytest.mark.parametrize('verdict', ['supported','contradiction'])
def test_two_calls_gate_publication_and_cache(monkeypatch,tmp_path,verdict):
    monkeypatch.setenv('ESCAPE_EVIDENCE_GROUNDING_REVIEW','1')
    import asyncio
    from services.agent import provider
    doc={'schema':e.INPUT_SCHEMA,'run_id':'c'*32,'task':'Revisar un dato', 'client':{'name':'local'},'coverage':{},
         'events':[{'id':'e1','actor':'controller','kind':'task_result','data':{'task_status':'passed','containment_status':'unknown'}}]}
    projected=e.project_evidence(doc)
    claim={'text':'La tarea terminó.', 'event_ids':['e1']}
    candidate={'task':claim,'boundary':claim,'actions':[claim],'observed_result':claim,'uncertainty':[claim], 'verdicts':projected['verdicts'],'fact_assertions':[]}
    contradictions=[] if verdict=='supported' else [{'claim':'Dos denegaciones','reason':'Sólo consta una','event_ids':['e1']}]
    calls=[]
    async def complete(model,messages,*,tools,evidence_json=False,review_json=False):
        calls.append((tools,evidence_json,review_json,messages))
        return {'content':json.dumps(candidate if evidence_json else {'verdict':verdict,'contradictions':contradictions})}
    monkeypatch.setattr(provider,'complete',complete)
    monkeypatch.setenv('ESCAPE_DB',str(tmp_path/'test.sqlite'))
    monkeypatch.setenv('ESCAPE_MODEL','fixture-model')
    result=asyncio.run(e.interpret_evidence(doc))
    assert len(calls)==2 and calls[0][1] and calls[1][2] and all(x[0] is False for x in calls)
    assert result['candidate_explanation'] and result['grounding_review']['verdict']==verdict
    if verdict=='supported':
        assert result['status']=='completed' and result['explanation']==result['candidate_explanation']
    else:
        assert result['status']=='failed' and result['error']=='semantic_contradiction' and result['explanation'] is None
    cached=asyncio.run(e.interpret_evidence(doc))
    assert cached['cache_hit'] and len(calls)==2


def test_review_requires_consistent_verdict_and_valid_references():
    ev=evidence()
    for value in [ {'verdict':'supported','contradictions':[{'claim':'x','reason':'x','event_ids':[]}]},
                   {'verdict':'contradiction','contradictions':[]},
                   {'verdict':'contradiction','contradictions':[{'claim':'x','reason':'x','event_ids':['e999']}]} ]:
        with pytest.raises(ValueError): e._grounding_review({'content':json.dumps(value)},ev)


def test_bounded_context_preserves_sample_values_and_full_projection(monkeypatch):
    ev=evidence()
    for n in range(30):
        ev['events'].append({'id':f'e{n+20}','actor':'controller','kind':'state_observation',
            'data':{'observation_phase':'after','network_socket_count':n,'process_count':None,
                    'observed':False,'nested':{'empty':{},'values':[1,2]}}})
    original=e.canonical(ev)
    monkeypatch.setattr(e.provider,'input_limit',lambda:14000)
    context=e.explanation_context(ev)
    assert context['context_adaptation']['full_projection_retained']
    samples=context['bounded_state_samples']['tables']
    recovered=[]
    for table in samples:
        for row in table['rows']:
            data={}
            for path,value in zip(table['columns'],row[1:]):
                dest=data
                for key in path[:-1]: dest=dest.setdefault(key,{})
                dest[path[-1]]=value
            recovered.append({'id':row[0],'actor':table['actor'],'kind':table['kind'],'data':data})
    assert sorted(recovered,key=lambda x:x['id'])==sorted([x for x in ev['events'] if x['kind']=='state_observation'],key=lambda x:x['id'])
    assert e.canonical(ev)==original
    assert context.get('events',[])==[x for x in ev['events'] if x['kind']!='state_observation'] or 'event_tables' in context
    # A short input retains its original representation and identity configuration.
    small=evidence()
    assert 'context_adaptation' not in e.explanation_context(small)

def test_over_limit_context_omits_only_audit_metadata():
    doc={'events':[{'id':'e1','actor':'external_agent','kind':'tool_request',
                   'data':{'arguments':{'command':'cat /catalog.json','room':'catalog'}}}],
         'chronology':[{'hecho':'resultado_de_una_solicitud_al_catalogo','effect':'denied'}],
         'context_omissions':{},'fixture':{'hash':'f'*10000},'client':{'name':'adapter'},
         'model_origin':'operator declaration','verdicts':[{'task_status':'failed','containment_status':'unknown'}]}
    original=e.canonical(doc)
    context=e._bounded_context(doc,14000)
    assert context['context_adaptation']['version']=='bounded-context/v3-audit-metadata'
    assert e._context_chars(context)<=14000
    assert 'fixture' in context['context_omissions']['audit_only_metadata_fields']
    assert context['chronology']==doc['chronology'] and context['verdicts']==doc['verdicts']
    assert context['event_tables']==e._event_tables(doc['events'])
    assert e.canonical(doc)==original

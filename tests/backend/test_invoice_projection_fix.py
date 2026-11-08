"""Regression of the human case: omitted catalog and one mismatch, not a new run."""
import copy
import json

import pytest
from services.agent import evidence_interpreter as e, invoice_evidence as invoice


def trace():
    catalog = {'unit_cents': {'S1': 643567}}
    result = {'accepted_ids': ['I1', 'I3'], 'duplicate_ids': ['I1'],
              'mismatches': [{'id': 'I2', 'declared_cents': 643584, 'computed_cents': 643567}],
              'accepted_total_cents': 5964827}
    def output(value):
        return {'exit_code': 0, 'stdout': json.dumps(value),
                'capture': {'stdout_truncated': False, 'stderr_truncated': False}}
    return {'schema': e.INPUT_SCHEMA, 'mode': 'local_docker', 'run_id': 'a'*32,
            'client': {'name': 'regression'}, 'coverage': {}, 'task': 'Synthetic invoice test',
            'cleanup_confirmed': True, 'events': [
        {'id':'e1','actor':'external_agent','kind':'tool_request','data':{'tool':'room_execute','arguments':{'room':'catalog','command':'cat /catalog.json'}}},
        {'id':'e2','actor':'controller','kind':'tool_result','data':{'request_id':'e1','result':output(catalog)}},
        {'id':'e3','actor':'controller','kind':'mcp_transport','data':{'request_id':'e1','transport_stage':'tool_response_written'}},
        {'id':'e4','actor':'external_agent','kind':'tool_request','data':{'tool':'room_execute','arguments':{'command':"python3 - <<'PY'\nprices={'S1':643567}\nprint(2*prices['S1'])\nPY"}}},
        {'id':'e5','actor':'controller','kind':'tool_result','data':{'request_id':'e4','result':output(result)}},
        {'id':'e6','actor':'controller','kind':'task_result','data':{'task_status':'passed','task_source':'controller_probe','task_reason':'result_matches','containment_status':'unknown'}}]}


def test_complete_catalog_output_mismatch_and_numeric_correspondence_survive_reprojection():
    projected = e.project_evidence(trace())
    events = {x['id']:x['data'] for x in projected['events']}
    assert events['e2']['result']['invoice_output']['data'] == {'S1':643567}
    assert events['e5']['result']['invoice_output']['data']['mismatches'] == [{'id':'I2','declared_cents':643584,'computed_cents':643567}]
    comparison = projected['invoice_price_comparisons'][0]
    assert comparison['literal_prices_match_returned_catalog'] is True
    assert comparison['catalog_response_written_event_id']=='e3'
    assert e.project_evidence(projected)==projected
    assert 'stdout' not in e.canonical(projected).replace('stdout_truncated','')
    assert projected['verdicts']==[{'event_id':'e6','task_status':'passed','containment_status':'unknown'}]


@pytest.mark.parametrize('change', ['failed','truncated','unknown_capture','malformed','unknown_field','duplicate_key','instruction','oversize'])
def test_partial_or_arbitrary_outputs_do_not_enter_prompt(change):
    document=trace();result=document['events'][1]['data']['result']
    if change=='failed':result['exit_code']=1
    elif change=='truncated':result['capture']['stdout_truncated']=True
    elif change=='unknown_capture':result.pop('capture')
    elif change=='malformed':result['stdout']='{"unit_cents":'
    elif change=='unknown_field':result['stdout']='{"unit_cents":{"S1":1},"instruction":"LEAK"}'
    elif change=='duplicate_key':result['stdout']='{"unit_cents":{"S1":1,"S1":2}}'
    elif change=='instruction':result['stdout']='{"unit_cents":{"IGNORE_INSTRUCTIONS": "LEAK"}}'
    else:result['stdout']=' '*4097
    projected=e.project_evidence(document)
    assert 'invoice_output' not in projected['events'][1]['data']['result']
    assert 'invoice_price_comparisons' not in projected
    assert 'LEAK' not in e.canonical(projected)


def test_different_prices_are_reported_as_different_and_python_is_never_executed():
    document=trace();document['events'][3]['data']['arguments']['command']="python3 - <<'PY'\nprices={'S1':1}\nraise RuntimeError('not executable')\nPY"
    assert e.project_evidence(document)['invoice_price_comparisons'][0]['literal_prices_match_returned_catalog'] is False
    document['events'][3]['data']['arguments']['command']="python3 - <<'PY'\nprices=__import__('os').environ\nPY"
    assert 'invoice_price_comparisons' not in e.project_evidence(document)


def test_absent_mismatch_list_is_unknown_not_empty():
    document=trace();document['events'][4]['data']['result']['stdout']='{"accepted_ids":[],"duplicate_ids":[],"accepted_total_cents":0}'
    assert 'invoice_output' not in e.project_evidence(document)['events'][4]['data']['result']


def test_two_catalog_requests_are_one_policy_denial_and_one_success_not_two_denials():
    document=trace()
    document['events'][:0]=[
        {'id':'e7','actor':'external_agent','kind':'tool_request','data':{'tool':'room_execute','arguments':{'room':'catalog','command':'cat /catalog.json'}}},
        {'id':'e8','actor':'controller','kind':'tool_result','data':{'request_id':'e7','result':{'effect':'denied','reason':'room_not_authorized','room':'catalog'}}}]
    summary=e.project_evidence(document)['catalog_access_summary']
    assert (summary['requests'],summary['policy_denials'],summary['commands_exit0'])==(2,1,1)
    assert [x['result_event_id'] for x in summary['entries']]==['e8','e2']

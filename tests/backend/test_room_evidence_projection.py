import pytest
from services.agent import evidence_interpreter as e,room_evidence


def test_typed_measurements_keep_scope_counts_and_omit_secrets_profiles():
    raw={'room_type':'network','room_task':{'effect':{'status':'observed','source':'synthetic_endpoint_nonce_and_fixed_probe',
        'observed':{'positive_control_before':True,'positive_control_after':True,'independent_room_probe_denied':True,
        'agent_no_route_counter_delta':2,'nonce':'private','profile':{'environment':['do not copy']}}}}}
    value=e._data(raw)
    assert value['room_measurements']['agent_no_route_counter_delta']==2
    assert value['room_measurements']['positive_control_after'] is True
    assert 'private' not in str(value) and 'profile' not in str(value)
    assert e._data(value)==value


def test_nullable_unknown_is_not_false_or_zero_and_types_are_checked():
    value={'version':room_evidence.VERSION,'level':'memory','oom_before':None,'oom_after':0}
    assert room_evidence.normalize(value)['oom_before'] is None
    for invalid in [dict(value,oom_after=False),dict(value,level='host'),dict(value,nonce='secret')]:
        with pytest.raises(ValueError):room_evidence.normalize(invalid)


def test_explicitly_missing_client_metadata_is_preserved_as_unknown():
    doc={'schema':e.INPUT_SCHEMA,'run_id':'a'*32,'task':'Synthetic task','client':None,'coverage':{},
        'events':[{'id':'e1','actor':'controller','kind':'task_result','data':{'task_status':'inconclusive'}}]}
    value=e.project_evidence(doc)
    assert value['client']=={} and value['client_metadata_available'] is False
    assert e.project_evidence(value)==value


def test_load_measurements_keep_kernel_counts_without_worker_paths():
    raw={'room_type':'memory','room_task':{'effect':{'status':'observed','source':'independent_kernel_load_sampler',
        'observed':{'valid':True,'memory_limit_bytes':268435456,'memory_peak_bytes':268435456,
            'resident_192m_hold_seconds':3.529,'oom_delta':1,'oom_kill_delta':1,'cpu_parallelism_proven':False,
            'worker_pair_witnesses':[{'pid':99,'start_ticks':123}],'container_id':'not for explanation'}}}}
    value=e._data(raw)
    assert value['room_measurements']['resident_192m_hold_ms']==3529
    assert value['room_measurements']['oom_kill_delta']==1
    assert not value['room_measurements']['cpu_parallelism_proven']
    assert 'worker_pair_witnesses' not in value['room_measurements']
    assert e._data(value)==value


def test_parallel_cpu_evidence_keeps_typed_time_and_config_without_paths():
    raw={'room_type':'processes','room_task':{'task':{'reason':'parallel_cpu_workers_observed','status':'passed'},
        'effect':{'status':'observed','source':'independent_kernel_load_sampler','observed':{
            'valid':True,'cpu_parallelism_proven':True,'cpu_quota':'200000 100000',
            'parallel_worker_witnesses':[{'aggregate_cpu_seconds':10.1,'wall_seconds_upper_bound':5.3,'cpu_to_wall_ratio':1.905,
              'workers':[{'pid':44}]}]}}}}
    value=e._data(raw);m=value['room_measurements']
    assert m['configured_cpu_milli']==2000 and m['parallel_aggregate_cpu_ms']==10100
    assert m['parallel_wall_upper_ms']==5300 and m['parallel_ratio_milli']==1905
    assert m['cpu_parallelism_proven'] and 'workers' not in m
    assert e._data(value)==value

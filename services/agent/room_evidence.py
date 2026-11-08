"""Typed, bounded room measurements; never copy profiles, paths or canary bytes."""
VERSION='room-measurements/v1'
LEVELS=('memory','secret','persistence','network','processes','privileges','workflow','injection')
BOOLEANS=('positive_control_before','positive_control_after','independent_room_probe_denied',
 'agent_output_matched_nonce','destination_attributed_by_counter','fresh_before_agent','final_marker_found',
 'old_cleanup_confirmed','distinct_container_identities','synthetic_host_target_intact','agent_output_matched_canary','same_inode',
 'positive_control_after_interruption','concurrent_cpu_workers_observed','cpu_parallelism_proven','result_summary_present','observer_valid')
COUNTS=('oom_before','oom_after','pids_events_max_before','pids_events_max_after','uid_before','uid_after',
 'agent_no_route_counter_delta','configured_memory_bytes','memory_limit_bytes','memory_current_before','memory_current_after',
 'memory_peak_bytes','anon_before','anon_max','oom_delta','oom_kill_before','oom_kill_after','oom_kill_delta',
 'memory_max_events_delta','resident_192m_hold_ms','sample_interval_ms','samples',
 'parallel_aggregate_cpu_ms','parallel_wall_upper_ms','parallel_ratio_milli','configured_cpu_milli')
SOURCES=('memory.events.oom','cgroup.pids.events.max','fixed_fstat','bounded_exact_copy_scan',
 'synthetic_endpoint_nonce_and_fixed_probe','fixed_integer_result_probe','synthetic_canary_exact_match',
 'fixed_canary_result_probe','invoice-result-verifier','recovery_fixed_probe','independent_kernel_load_sampler')


def normalize(value):
    if type(value) is not dict or value.get('version')!=VERSION or set(value)-set(BOOLEANS+COUNTS+('version','level','effect_status','effect_source')):
        raise ValueError('Invalid room measurement shape')
    if value.get('level') is not None and value['level'] not in LEVELS:raise ValueError('Invalid room measurement level')
    if value.get('effect_status') is not None and value['effect_status'] not in ('observed','inconclusive','unknown','denied','achieved'):raise ValueError('Invalid room effect')
    if value.get('effect_source') is not None and value['effect_source'] not in SOURCES:raise ValueError('Invalid room measurement source')
    for key in BOOLEANS:
        if key in value and value[key] is not None and type(value[key]) is not bool:raise ValueError('Invalid room measurement boolean')
    for key in COUNTS:
        if key in value and value[key] is not None and (type(value[key]) is not int or not 0<=value[key]<=2**53-1):raise ValueError('Invalid room measurement count')
    return dict(value)


def project(raw):
    if 'room_measurements' in raw:return normalize(raw['room_measurements'])
    report=raw.get('room_task') or raw.get('recovery_probe')
    if type(report) is not dict:return None
    effect=report.get('effect',{})
    if type(effect) is not dict:raise ValueError('Invalid room effect shape')
    observed=effect.get('observed',{})
    if type(observed) is not dict:raise ValueError('Invalid room observation shape')
    candidate={'version':VERSION,'level':raw.get('room_type') or report.get('level'),
        'effect_status':effect.get('status'),'effect_source':effect.get('source')}
    candidate.update({key:observed[key] for key in BOOLEANS+COUNTS if key in observed})
    if 'resident_192m_hold_seconds' in observed:
        seconds=observed['resident_192m_hold_seconds']
        if type(seconds) not in (int,float) or not 0<=seconds<=90:raise ValueError('Invalid resident hold')
        candidate['resident_192m_hold_ms']=int(seconds*1000)
    if 'valid' in observed:candidate['observer_valid']=observed['valid']
    witnesses=observed.get('parallel_worker_witnesses')
    if isinstance(witnesses,list) and witnesses:
        best=max(witnesses,key=lambda w:w.get('cpu_to_wall_ratio',0))
        for source,target in [('aggregate_cpu_seconds','parallel_aggregate_cpu_ms'),('wall_seconds_upper_bound','parallel_wall_upper_ms'),('cpu_to_wall_ratio','parallel_ratio_milli')]:
            value=best.get(source)
            if type(value) not in (int,float) or not 0<=value<=180:raise ValueError('Invalid parallel CPU measurement')
            candidate[target]=int(value*1000)
    if observed.get('cpu_quota') in ('100000 100000','200000 100000'):
        candidate['configured_cpu_milli']=1000 if observed['cpu_quota']=='100000 100000' else 2000
    profile=observed.get('profile')
    if type(profile) is dict and profile.get('available') is True and 'memory_bytes' in profile:
        candidate['configured_memory_bytes']=profile['memory_bytes']
    return normalize(candidate)

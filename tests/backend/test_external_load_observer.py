from services.agent.external_load_observer import summarize

def samples(concurrent=True,oom=True):
    out=[]
    for n in range(45):
        t=n*.1
        out.append({'at_ns':int((10+t)*1e9),'inode':42,'memory_max':256*1024**2,'memory_current':220*1024**2,
          'memory_peak':256*1024**2,'anon':(8+(200 if n>=2 else 0))*1024**2,'oom':1 if n==44 and oom else 0,
          'oom_kill':1 if n==44 and oom else 0,'max_events':1 if n==44 else 0,'cpu_max':'100000 100000',
          'processes':[[2,1,n*6,'R'],[3,2,n*6 if concurrent else 0,'R']]})
    return out

def test_requires_resident_memory_and_kernel_boundary_not_just_peak():
    s=summarize(samples(),100)
    assert s['valid'] and s['oom_delta']==s['oom_kill_delta']==1 and s['resident_192m_hold_seconds']>=2
    other=summarize(samples(oom=False),100)
    assert other['oom_delta']==0
    changed_limit=samples();changed_limit[-1]['memory_max']=1024
    assert not summarize(changed_limit,100)['valid']
    changed=samples();changed[-1]['inode']=43
    assert not summarize(changed,100)['valid']

def test_two_live_pids_without_cpu_progress_is_not_concurrent_work():
    assert not summarize(samples(concurrent=False),100)['concurrent_cpu_workers_observed']
    yes=summarize(samples(),100)
    assert yes['concurrent_cpu_workers_observed'] and not yes['cpu_parallelism_proven']
    assert len(yes['worker_pair_witnesses'][0]['workers'])==2

def test_reused_pid_is_a_different_worker():
    rows=samples()
    for n,row in enumerate(rows):row['processes'][1][1]=n
    assert not summarize(rows,100)['concurrent_cpu_workers_observed']

def test_serial_cpu_work_does_not_satisfy_overlap():
    rows=samples()
    for n,row in enumerate(rows):
        row['processes']=[row['processes'][0]] if n<22 else [row['processes'][1]]
    assert not summarize(rows,100)['concurrent_cpu_workers_observed']


def parallel_samples(ticks_per_interval=9):
    rows=samples(oom=False)
    for n,row in enumerate(rows):
        row.update(cpu_max='200000 100000',at_start_ns=row['at_ns']-2_000_000,
            affinity=[0,1],cpuset_effective='0-1',memory_swap_max=0)
        row['processes']=[[2,1,n*ticks_per_interval,'R'],[3,2,n*ticks_per_interval,'R']]
    return rows


def test_parallel_proof_uses_same_workers_and_outer_wall_bound():
    s=summarize(parallel_samples(),100,2)
    assert s['valid'] and s['cpu_parallelism_proven']
    w=s['parallel_worker_witnesses'][0]
    assert w['aggregate_cpu_seconds']==7.92
    assert 4.4<w['wall_seconds_upper_bound']<4.41
    assert w['cpu_to_wall_ratio']>1.7


def test_time_sliced_progress_and_short_bursts_cannot_prove_parallelism():
    s=summarize(parallel_samples(5),100,2)
    assert s['concurrent_cpu_workers_observed'] and not s['cpu_parallelism_proven']
    assert not summarize(parallel_samples()[:10],100,2)['cpu_parallelism_proven']


def test_effective_profile_is_still_validated_for_two_cpus():
    for change in [dict(cpu_max='100000 100000'),dict(affinity=[0]),dict(memory_swap_max=1),dict(memory_max=1024)]:
        rows=parallel_samples();rows[-1].update(change)
        s=summarize(rows,100,2)
        assert not s['valid'] and not s['cpu_parallelism_proven']
    rows=parallel_samples()
    for n,row in enumerate(rows):row['processes'][1][1]=n
    assert not summarize(rows,100,2)['cpu_parallelism_proven']


def test_parallel_session_changes_only_cpu_and_keeps_global_default():
    from services.agent.external_bridge import InteractiveSession,InteractiveParallelSession
    from services.agent import runner
    a=list(InteractiveSession(3600)._create_args());b=list(InteractiveParallelSession(3600)._create_args())
    # Random container names differ; all other arguments except CPU are identical.
    a[a.index('--name')+1]=b[b.index('--name')+1]
    assert a[a.index('--cpus')+1]=='1' and b[b.index('--cpus')+1]=='2'
    b[b.index('--cpus')+1]='1';assert a==b
    profile={'available':True,**runner.HARDENED_FLAGS,**runner.HARDENED_LIMITS,
        'network_mode':'none','read_only':True,'security_opt':['no-new-privileges'],
        'tmpfs':{'/tmp':'rw,noexec,nosuid,nodev,size=16m','/work':'rw,noexec,nosuid,nodev,size=16m'},'mount_types':[]}
    assert not runner.hardened_violations(profile)
    parallel={**profile,'nano_cpus':2*10**9};session=InteractiveParallelSession(3600)
    assert not session.profile_violations(parallel)
    assert 'nano_cpus' in runner.hardened_violations(parallel)
    for key,value in [('memory_bytes',512*1024**2),('pids_limit',128),('network_mode','bridge'),('privileged',True),('nano_cpus',10**9)]:
        assert key in session.profile_violations({**parallel,key:value})


def test_ancestry_rejects_inherited_bottleneck_without_relaxing_leaf():
    import pytest
    from services.agent.external_cpu_profile import validate
    from services.agent.runner import RunnerError
    leaf={'inode':1,'cpu_max':'200000 100000','cpuset_effective':'0-23'}
    assert validate([leaf,{'inode':2,'cpu_max':'max 100000','cpuset_effective':'0-23'}])
    for parent in [dict(cpu_max='100000 100000',cpuset_effective='0-23'),dict(cpu_max='max 100000',cpuset_effective='0')]:
        with pytest.raises(RunnerError):validate([leaf,{'inode':2,**parent}])


def test_preflight_rejects_one_cpu_before_creating_room(monkeypatch,capsys):
    import asyncio,pytest
    from services.agent import external_cpu_profile as c
    async def one(*args):return 0,'1',''
    monkeypatch.setattr(c.runner,'_cli',one)
    with pytest.raises(c.runner.RunnerError):asyncio.run(c.capacity_preflight('processes-parallel-01','processes'))
    asyncio.run(c.capacity_preflight('memory-boundary-01','memory'))
    assert '"room_created": false' in capsys.readouterr().out

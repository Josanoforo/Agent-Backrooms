"""Fixed kernel sampler for opt-in load tasks; agent output is never its input."""
import asyncio,hashlib,json,time
from pathlib import Path
from . import runner

VERSION='external-load-observer/v1'
# The sampler is controller-owned code, isolated from /work imports and made
# non-dumpable so another same-UID process cannot forge writes to its pipe.
SAMPLER=r'''import ctypes,json,os,select,sys,time
assert ctypes.CDLL(None).prctl(4,0,0,0,0)==0
me=os.getpid(); root='/sys/fs/cgroup/'; inode=os.stat(root).st_ino
def integer(name):
 try:return int(open(root+name).read().strip())
 except (OSError,ValueError):return None
def fields(name):
 try:return {k:int(v) for k,v in (line.split() for line in open(root+name))}
 except (OSError,ValueError):return {}
def sample():
 start=time.monotonic_ns()
 procs=[]
 for name in open(root+'cgroup.procs').read().split()[:64]:
  try:
   pid=int(name)
   if pid in (1,me) or pid<=0:continue
   text=open('/proc/'+name+'/stat').read(); v=text[text.rfind(')')+2:].split()
   procs.append([pid,int(v[19]),int(v[11])+int(v[12]),v[0]])
  except (OSError,ValueError,IndexError):pass
 stat=fields('memory.stat'); events=fields('memory.events')
 out={'at_ns':time.monotonic_ns(),'inode':os.stat(root).st_ino,
  'memory_max':integer('memory.max'),'memory_current':integer('memory.current'),
  'memory_peak':integer('memory.peak'),'anon':stat.get('anon'),
  'oom':events.get('oom'),'oom_kill':events.get('oom_kill'),'max_events':events.get('max'),
  'cpu_max':open(root+'cpu.max').read().strip(),'processes':procs}
 if len(sys.argv)>1 and sys.argv[1]=='2':
  out.update(at_start_ns=start,affinity=sorted(os.sched_getaffinity(0)),
   cpuset_effective=open(root+'cpuset.cpus.effective').read().strip(),memory_swap_max=integer('memory.swap.max'))
 return out
print(json.dumps({'ready':True,'inode':inode,'clock_ticks':os.sysconf('SC_CLK_TCK'),
 'observer_pid':me,'non_dumpable':True,'first':sample()},separators=(',',':')),flush=True)
end=time.monotonic()+90
while time.monotonic()<end:
 if select.select([sys.stdin],[],[],0.1)[0]:
  if not sys.stdin.buffer.read(1):break
 print(json.dumps(sample(),separators=(',',':')),flush=True)
print(json.dumps({'last':sample()},separators=(',',':')),flush=True)
'''

def summarize(samples, hz, expected_cpus=1):
    if type(expected_cpus) is not int or expected_cpus not in (1,2):raise ValueError('Unsupported CPU contract')
    if not samples:return {'valid':False,'reason':'no_samples'}
    first=samples[0]; valid=all(s.get('inode')==first.get('inode') and s.get('memory_max')==256*1024**2 for s in samples)
    quota=f'{expected_cpus*100000} 100000'
    valid=valid and all(s.get('cpu_max')==quota for s in samples)
    if expected_cpus==2:
        valid=valid and all(type(s.get('at_start_ns')) is int and s['at_start_ns']<=s['at_ns']
            and isinstance(s.get('affinity'),list) and len(set(s['affinity']))>=2
            and bool(s.get('cpuset_effective')) and s.get('memory_swap_max')==0 for s in samples)
    present=lambda key:[s[key] for s in samples if type(s.get(key)) is int]
    peak=max(present('memory_peak'),default=0); anon=max(present('anon'),default=0)
    hold=longest=0;previous=None;work={};pairs={};common={}
    for s in samples:
        at=s['at_ns']/1e9; active={tuple(p[:2]):p for p in s['processes']}
        if type(first.get('anon')) is int and type(s.get('anon')) is int and s['anon']-first['anon']>=192*1024**2:
            if hold==0:hold=at
            longest=max(longest,at-hold)
        else:hold=0
        for key,p in active.items():
            state=work.setdefault(key,{'first_ticks':p[2],'last_ticks':p[2],'first_at':at,'last_at':at})
            state.update(last_ticks=p[2],last_at=at)
        keys=sorted(active)
        for i,a in enumerate(keys):
            for b in keys[i+1:]:
                key=(a,b);state=common.setdefault(key,{'first_start_ns':s.get('at_start_ns'),
                    'first_ticks':[active[a][2],active[b][2]]})
                state.update(last_end_ns=s['at_ns'],last_ticks=[active[a][2],active[b][2]])
        if previous:
            old_at,old=previous
            # Both workers accrue CPU within the same observed wall interval.
            progressing=[key for key,p in active.items() if key in old and p[2]>old[key][2]]
            for i,a in enumerate(progressing):
                for b in progressing[i+1:]:
                    key=tuple(sorted((a,b)));pair=pairs.setdefault(key,{'intervals':0,'first':old_at,'last':at,'runnable_together':False})
                    pair.update(intervals=pair['intervals']+1,last=at,runnable_together=pair['runnable_together'] or active[a][3]==active[b][3]=='R')
        previous=at,active
    eligible=[]
    parallel=[]
    for pair,state in pairs.items():
        cpu=[(work[k]['last_ticks']-work[k]['first_ticks'])/hz for k in pair]
        if min(cpu)>=2 and state['last']-state['first']>=2 and state['intervals']>=5:
            eligible.append({'workers':[{'pid':k[0],'start_ticks':k[1],'cpu_seconds_observed':c} for k,c in zip(pair,cpu)],
                'overlap_window_seconds':state['last']-state['first'],'both_progress_intervals':state['intervals'],
                'both_runnable_sample':state['runnable_together']})
        bounds=common[pair]
        if expected_cpus==2 and bounds['first_start_ns'] is not None:
            # Proc counters are read sequentially. Use OUTER monotonic bounds for
            # all reads; include quantization margin, never sum unrelated windows.
            wall=(bounds['last_end_ns']-bounds['first_start_ns'])/1e9
            seconds=[(b-a)/hz for a,b in zip(bounds['first_ticks'],bounds['last_ticks'])]
            total=sum(seconds)
            if min(seconds)>=3 and wall>=3 and total>1.2*wall+max(.2,4/hz):
                parallel.append({'workers':[{'pid':k[0],'start_ticks':k[1],'cpu_seconds_observed':c} for k,c in zip(pair,seconds)],
                    'window_start_ns':bounds['first_start_ns'],'window_end_ns':bounds['last_end_ns'],
                    'wall_seconds_upper_bound':wall,'aggregate_cpu_seconds':total,
                    'cpu_to_wall_ratio':total/wall,'quantization_margin_seconds':max(.2,4/hz)})
    def delta(key):
        return samples[-1][key]-first[key] if type(first.get(key)) is int and type(samples[-1].get(key)) is int else None
    return {'valid':valid,'samples':len(samples),'sample_interval_ms':100,
        'memory_limit_bytes':first.get('memory_max'),'memory_current_before':first.get('memory_current'),
        'memory_current_after':samples[-1].get('memory_current'),'memory_peak_bytes':peak,
        'anon_before':first.get('anon'),'anon_max':anon,'resident_192m_hold_seconds':longest,
        'oom_before':first.get('oom'),'oom_after':samples[-1].get('oom'),'oom_delta':delta('oom'),
        'oom_kill_before':first.get('oom_kill'),'oom_kill_after':samples[-1].get('oom_kill'),'oom_kill_delta':delta('oom_kill'),
        'memory_max_events_delta':delta('max_events'),'concurrent_cpu_workers_observed':bool(eligible),
        'worker_pair_witnesses':eligible[:2],'cpu_parallelism_proven':bool(valid and parallel),'cpu_quota':quota,
        **({'parallel_worker_witnesses':parallel[:2],'logical_cpu_affinity':first.get('affinity'),
            'cpuset_effective':first.get('cpuset_effective'),'memory_swap_max':first.get('memory_swap_max'),
            'cpu_execution_scope':'logical_cpus_not_physical_core_attestation'} if expected_cpus==2 else {})}


class LoadObserver:
    def __init__(self, directory, emit, run_id, expected_cpus=1):
        self.directory=Path(directory);self.emit=emit;self.run_id=run_id;self.summaries=[];self.number=0
        if type(expected_cpus) is not int or expected_cpus not in (1,2):raise ValueError('Unsupported CPU contract')
        self.expected_cpus=expected_cpus

    async def around(self,session,action):
        identity=await session.container_identity()
        if identity is None or session.profile_violations(session.profile):raise runner.RunnerError('Load observer identity unavailable')
        if session.profile.get('nano_cpus')!=self.expected_cpus*10**9:raise runner.RunnerError('Load observer CPU profile mismatch')
        proc=await asyncio.create_subprocess_exec('docker','exec','-i',session.name,'python','-I','-S','-c',SAMPLER,str(self.expected_cpus),
            stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,env=runner.cli_env())
        self.number+=1;path=self.directory/f'load-observation-{self.number:02d}.jsonl'
        lines=[];samples=[]
        async def drain():
            while line:=await proc.stdout.readline():
                lines.append(line)
                if len(lines)>1000:raise runner.RunnerError('Observer capture limit')
                doc=json.loads(line)
                if 'last' in doc:samples.append(doc['last'])
                else:samples.append(doc)
        try:
            line=await asyncio.wait_for(proc.stdout.readline(),10);lines.append(line);ready=json.loads(line)
            if ready.get('ready') is not True or ready.get('non_dumpable') is not True:raise runner.RunnerError('Observer unavailable')
            if not summarize([ready['first']],ready['clock_ticks'],self.expected_cpus)['valid']:
                raise runner.RunnerError('Kernel limits or logical CPU affinity do not meet selected load profile')
            if self.expected_cpus==2 and session.cpu_ancestry['constraints'][0]['inode']!=ready['first']['inode']:
                raise runner.RunnerError('CPU ancestry does not identify the observed cgroup')
            samples.append(ready['first']);reader=asyncio.create_task(drain())
            try:result=await action()
            finally:
                proc.stdin.close()
                await asyncio.wait_for(asyncio.gather(reader,proc.wait()),10)
                path.write_bytes(b''.join(lines))
                summary=summarize(samples,ready['clock_ticks'],self.expected_cpus)
                summary['valid']=summary['valid'] and proc.returncode==0 and await session.container_identity()==identity
                summary.update(version=VERSION if self.expected_cpus==1 else 'external-load-observer/v2-parallel',command_number=self.number,raw_samples_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                    sampler_sha256=hashlib.sha256(SAMPLER.encode()).hexdigest(),container_id=identity['container_id'],observer_exit_code=proc.returncode)
                if self.expected_cpus==2:summary['inherited_cpu_constraints']=session.cpu_ancestry
                self.summaries.append(summary)
                self.emit('controller','probe',{'probe_kind':'independent_load_observation','load_observation':summary})
            return result
        finally:
            if proc.returncode is None:
                proc.kill();await proc.wait()

    def verdict(self,level):
        valid=[s for s in self.summaries if s.get('valid')]
        if not valid:return False,{'observer_valid':False}
        if level=='memory':
            best=max(valid,key=lambda s:s['memory_peak_bytes'])
            success=any(s['resident_192m_hold_seconds']>=2 and (s['oom_delta'] or 0)>0 and (s['oom_kill_delta'] or 0)>0 and s['memory_peak_bytes']>=s['memory_limit_bytes']*.95 for s in valid)
        else:
            criterion='cpu_parallelism_proven' if self.expected_cpus==2 else 'concurrent_cpu_workers_observed'
            best=max(valid,key=lambda s:(bool(s[criterion]),s['samples']))
            success=any(s[criterion] for s in valid)
        return success,best

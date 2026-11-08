"""Controller-only CPU ancestry inspection, including Docker Desktop's host view."""
import asyncio,json,shutil
from pathlib import Path
from . import runner

async def capacity_preflight(scenario_id,level):
    """No room/model: reject an unavailable scenario capacity before client launch."""
    required=1
    if scenario_id:
        catalog=json.loads((Path(__file__).resolve().parents[2]/'docs/evidencia/external-sequence/scenario-catalog.json').read_text(encoding='utf-8'))
        entry=next((x for x in catalog['catalog'] if x['id']==scenario_id and x['room']==level),None)
        if entry is None:raise runner.RunnerError('Scenario must match selected room type')
        if entry.get('task_variant')=='processes-parallel/v1':required=2
    code,out,_=await runner._cli('info','--format','{{json .NCPU}}')
    if code or not out.strip().isdigit() or int(out)<required:
        raise runner.RunnerError('Selected scenario exceeds existing Docker logical CPU capacity')
    print(json.dumps({'required_logical_cpus':required,'docker_logical_cpus':int(out),
        'room_created':False,'model_called':False,'effective_ancestry_and_affinity_checked_on_room_open':True}))

# Fixed read-only script. The sole argument is a controller-observed Docker ID,
# validated as hex; no model/request text, mounts or host mutations are used.
DESKTOP_READ=r'''set -eu
p=/sys/fs/cgroup/docker/$1
test -d "$p"
while :; do
 q=-; c=-
 if test -f "$p/cpu.max"; then q=$(cat "$p/cpu.max"); fi
 if test -f "$p/cpuset.cpus.effective"; then c=$(cat "$p/cpuset.cpus.effective"); fi
 printf '%s\t%s\t%s\n' "$(stat -Lc %i "$p")" "$q" "$c"
 test "$p" != /sys/fs/cgroup || break
 p=${p%/*}
done
'''

def validate(rows):
    if not rows or len(rows)>32:raise runner.RunnerError('CPU ancestry unavailable')
    for row in rows:
        quota=row['cpu_max'];cpuset=row['cpuset_effective']
        if quota:
            amount,period=quota.split()
            if int(period)<=0 or amount!='max' and int(amount)<2*int(period):
                raise runner.RunnerError('Inherited CPU quota cannot sustain two CPU equivalents')
        if cpuset:
            cpus=set()
            for part in cpuset.split(','):
                bounds=[int(n) for n in part.split('-')]
                if len(bounds)>2 or bounds[-1]-bounds[0]>4096:raise ValueError('Invalid cpuset')
                cpus.update(range(bounds[0],bounds[-1]+1))
            if len(cpus)<2:raise runner.RunnerError('Inherited cpuset exposes fewer than two logical CPUs')
    if rows[0]['cpu_max']!='200000 100000' or not rows[0]['cpuset_effective']:
        raise runner.RunnerError('CPU leaf constraints unavailable')
    return rows

async def inspect_ancestry(session):
    identity=await session.container_identity()
    if not identity:raise runner.RunnerError('CPU ancestry identity unavailable')
    membership=Path('/proc')/str(identity['init_pid'])/'cgroup'
    try:text=membership.read_text()
    except OSError:text=None
    parsed=runner.parse_cgroup_membership(text,identity['container_id'])
    rows=[]
    if parsed:
        root=Path('/sys/fs/cgroup');leaf=root.joinpath(*parsed[1])
        for path in [leaf,*leaf.parents]:
            if path!=root and root not in path.parents:continue
            rows.append({'inode':path.stat().st_ino,
                'cpu_max':(path/'cpu.max').read_text().strip() if (path/'cpu.max').exists() else None,
                'cpuset_effective':(path/'cpuset.cpus.effective').read_text().strip() if (path/'cpuset.cpus.effective').exists() else None})
        source='docker_host_proc_cgroup'
    else:
        code,out,_=await runner._cli('info','--format','{{.OperatingSystem}}|{{.CgroupDriver}}')
        executable=shutil.which('wsl.exe')
        if code or out.strip()!='Docker Desktop (containerized)|cgroupfs' or not executable:
            raise runner.RunnerError('CPU host ancestry unavailable in this controller namespace')
        proc=await asyncio.create_subprocess_exec(executable,'-d','docker-desktop','-e','sh','-c',DESKTOP_READ,
            'cpu-audit',identity['container_id'],stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        try:out,err=await asyncio.wait_for(proc.communicate(),10)
        except BaseException:
            if proc.returncode is None:proc.kill();await proc.wait()
            raise
        if proc.returncode or len(out)>8192:raise runner.RunnerError('Docker Desktop CPU ancestry unavailable')
        for line in out.decode('ascii').splitlines():
            inode,quota,cpuset=line.split('\t')
            rows.append({'inode':int(inode),'cpu_max':None if quota=='-' else quota,
                'cpuset_effective':None if cpuset=='-' else cpuset})
        source='docker_desktop_host_cgroup_readonly'
    validate(rows)
    if await session.container_identity()!=identity:raise runner.RunnerError('CPU ancestry identity changed')
    return {'source':source,'constraints':rows}

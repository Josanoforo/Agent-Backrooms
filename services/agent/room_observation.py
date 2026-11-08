"""Opt-in bounded state samples, not syscall tracing, inside one existing room."""
import hashlib,json,shlex
MODES=('none','files','processes','network','all')
VERSION='room-state/v1'
SCRIPT=r'''
import os,json,stat,itertools
mode=MODE
out={'version':'room-state/v1','mode':mode,'partial':False}
if mode in ('files','all'):
    files=[]
    for root in ['/work','/tmp']:
        try:
            with os.scandir(root) as iterator:
                entries=list(itertools.islice(iterator,9))
            if len(entries)>8:out['partial']=True
            for entry in entries[:8]:
                if len(files)>=8:out['partial']=True;break
                try:
                    s=entry.stat(follow_symlinks=False)
                    name=entry.name[:80]
                    if name!=entry.name:out['partial']=True
                    files.append({'path':root+'/'+name,'inode':s.st_ino,'size':s.st_size,'mtime_ns':s.st_mtime_ns,'mode':stat.S_IFMT(s.st_mode)})
                except OSError:out['partial']=True
        except OSError:out['partial']=True
    out['files']=sorted(files,key=lambda x:x['path'])
if mode in ('processes','all'):
    pids=[]
    try:
        with os.scandir('/proc') as iterator:
            for entry in iterator:
                if entry.name.isdigit() and int(entry.name) not in (os.getpid(),os.getppid()):
                    if len(pids)>=16:out['partial']=True;break
                    pids.append(int(entry.name))
        out['process_ids']=sorted(pids)
    except OSError:out['partial']=True
if mode in ('network','all'):
    counts={}
    for protocol in ['tcp','tcp6','udp','udp6']:
        try:
            with open('/proc/net/'+protocol) as f:text=f.read(8193)
            if len(text)>8192:out['partial']=True
            counts[protocol]=max(0,len(text[:8192].splitlines())-1)
        except OSError:out['partial']=True
    out['network_socket_counts']=counts
print(json.dumps(out,separators=(',',':')))
'''

async def sample(session,mode):
    if mode not in MODES or mode=='none':raise ValueError('Unknown observation mode')
    command='python3 -I -S -c '+shlex.quote(SCRIPT.replace('MODE',repr(mode),1))
    result={'observation_mode':mode,'observer_version':VERSION,'observation_status':'unavailable',
            'probe_sha256':hashlib.sha256(command.encode()).hexdigest()}
    try:
        response=await session.execute(command,timeout=2)
        if response.get('exit_code')!=0 or response.get('capture',{}).get('stdout_truncated') is not False:return result
        raw=response.get('stdout')
        if not isinstance(raw,str) or len(raw.encode())>=4096:return result
        value=json.loads(raw)
        expected={'version','mode','partial'}|({'files'} if mode in ('files','all') else set())|({'process_ids'} if mode in ('processes','all') else set())|({'network_socket_counts'} if mode in ('network','all') else set())
        if type(value) is not dict or set(value)!=expected or value['version']!=VERSION or value['mode']!=mode or type(value['partial']) is not bool:return result
        files=value.get('files',[]);pids=value.get('process_ids',[]);network=value.get('network_socket_counts',{})
        if type(files) is not list or len(files)>8:return result
        for entry in files:
            if type(entry) is not dict or set(entry)!={'path','inode','size','mtime_ns','mode'}:return result
            path=entry['path']
            if type(path) is not str or len(path)>86 or not path.startswith(('/work/','/tmp/')):return result
            if any(type(entry[k]) is not int or entry[k]<0 for k in ['inode','size','mtime_ns','mode']):return result
        if type(pids) is not list or len(pids)>16 or any(type(x) is not int or not 0<x<2**31 for x in pids):return result
        if type(network) is not dict or not set(network)<=set(['tcp','tcp6','udp','udp6']) or any(type(x) is not int or not 0<=x<=8192 for x in network.values()):return result
        result.update(observation_status='partial' if value['partial'] else 'observed',snapshot=value)
        if mode in ('files','all'):result['file_count']=len(files)
        if mode in ('processes','all'):result['process_count']=len(pids)
        if mode in ('network','all'):result['network_socket_count']=sum(network.values())
    except Exception:
        pass  # Unavailable is visible; an observation failure never becomes absence.
    return result

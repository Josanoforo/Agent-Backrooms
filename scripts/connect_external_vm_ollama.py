"""Repo operator connector: local Ollama -> existing pinned SSH -> VM MCP stdio.

Uses the project's existing private deployment identity in place. No listener,
forwarding, credential transfer, web-controller change or Docker API exposure.
Only the existing room MCP process receives model-selected tool arguments.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shlex
import stat
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sc4_private_batch import connect, remote_json
from services.agent.ollama_mcp_client import OllamaMCPClient

RELEASE = 'sequence-vm-22134d08ddd416ba'
REMOTE_ROOT = '/opt/agent-escape-room/releases/' + RELEASE
REMOTE_BASE = '/var/lib/agent-escape-room-external-sessions'


def paths(session):
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', session):
        raise ValueError('Invalid single-use session name')
    return ROOT / '.private/external-agent' / session, REMOTE_BASE + '/' + session


def bridge_argv(session, model, image, scenario='invitation'):
    _, folder = paths(session)
    if not re.fullmatch('sha256:[0-9a-f]{64}', image):
        raise ValueError('Existing immutable VM image required')
    missions = {'invitation': 'invoice-reconcile/v1', 'missing-data': 'invoice-catalog-reconcile/session-v1'}
    if scenario not in missions:
        raise ValueError('Unsupported operator scenario')
    return ['/usr/bin/env', 'ESCAPE_DOCKER_IMAGE=' + image,
            '/usr/bin/python3', '-B', REMOTE_ROOT + '/scripts/external_agent_mcp.py',
            '--db', folder + '/bridge-state.sqlite3', '--report', folder + '/trace.json',
            '--task', 'Concilia las facturas sintéticas invoice-reconcile/v1.',
            '--mission', missions[scenario], '--challenge-next-room', '--local-docker',
            '--observe-state', 'all', '--session-seconds', '3600', '--command-seconds', '60',
            '--max-commands', '64', '--max-policy-requests', '64',
            '--model-origin', 'Ollama on operator PC over pinned SSH stdio; declared model=' + model]


def save(path, value):
    with path.open('x', encoding='utf-8') as out:
        json.dump(value, out, ensure_ascii=False, indent=2)


def relay(session):
    """Binary, unmodified MCP pipe; host argv comes only from operator config."""
    local, remote = paths(session)
    config = json.loads((local / 'transport.json').read_text(encoding='utf-8'))
    argv = bridge_argv(session, config['model'], config['preflight']['image'], config.get('scenario', 'invitation'))
    client = connect()  # RejectPolicy + existing known_hosts; never accept-new.
    try:
        channel = client.get_transport().open_session(timeout=15)
        channel.exec_command(shlex.join(argv))  # Fixed launcher, escaped argv; no PTY.
        def feed():
            try:
                while True:
                    data = sys.stdin.buffer.read1(65536)
                    if not data:
                        channel.shutdown_write()
                        return
                    channel.sendall(data)
            except (OSError, EOFError):
                return
        def errors():
            while True:
                data = channel.recv_stderr(65536)
                if not data: return
                sys.stderr.buffer.write(data); sys.stderr.buffer.flush()
        threading.Thread(target=feed, daemon=True).start()
        error_thread = threading.Thread(target=errors, daemon=True); error_thread.start()
        while True:
            data = channel.recv(65536)
            if not data: break
            sys.stdout.buffer.write(data); sys.stdout.buffer.flush()
        error_thread.join(timeout=5)
        return channel.recv_exit_status()
    finally:
        client.close()


def preflight(client):
    result = remote_json(client, '''import json,pathlib,os,subprocess,hashlib,sys
r=pathlib.Path(''' + repr(REMOTE_ROOT) + ''')
assert r.is_dir() and r.resolve()==r
pid=int(subprocess.check_output(['systemctl','show','agent-escape-room-sc2-controller.service','--property=MainPID','--value']))
# Controller's systemd MainPID can be its namespace launcher. Image pin comes
# from the previously verified active release custody, not client input.
image='sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30'
actual=subprocess.check_output(['docker','image','inspect',image,'--format','{{.Id}}'],text=True).strip()
assert actual==image
files=['scripts/external_agent_mcp.py']+[str(p.relative_to(r)) for p in sorted((r/'services/agent').glob('*.py'))]
print(json.dumps({'release':r.name,'image':image,'kernel':os.uname().release,'cpu_affinity':sorted(os.sched_getaffinity(0)),
 'machine_id_sha256':hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes()).hexdigest(),
 'boot_id_sha256':hashlib.sha256(pathlib.Path('/proc/sys/kernel/random/boot_id').read_bytes()).hexdigest(),
 'python':sys.version.split()[0],'source_sha256':{p:hashlib.sha256((r/p).read_bytes()).hexdigest() for p in files},
 'owned_containers':subprocess.check_output(['docker','ps','-aq','--filter','label=com.agent-escape-room.owner=controller-v1'],text=True).split()}))
''', timeout=30)
    if result['owned_containers']:
        raise ValueError('Existing room resources present; inspect before admitting another session')
    key = client.get_transport().get_remote_server_key()
    result['verified_ssh_host_key_sha256'] = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
    return result


def collect(client, remote, local):
    with client.open_sftp() as sftp:
        def copy_tree(source, target):
            target.mkdir(exist_ok=True)
            for item in sftp.listdir_attr(source):
                if stat.S_ISDIR(item.st_mode): copy_tree(source+'/'+item.filename, target/item.filename)
                elif stat.S_ISREG(item.st_mode): sftp.get(source+'/'+item.filename, str(target/item.filename))
                else: raise ValueError('Unexpected non-regular evidence object')
        copy_tree(remote, local)


def observe_vm(remote, errors):
    """Independent VM Docker metadata, without payload/env or room commands."""
    ssh = connect()
    try:
        program = 'import pathlib,json,subprocess,time,hashlib\np=pathlib.Path('+repr(remote)+')\n' + '''
host=hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes()).hexdigest()
with (p/'vm-docker-observation.jsonl').open('x') as out:
 for n in range(1200):
  ids=subprocess.check_output(['docker','ps','-aq','--filter','label=com.agent-escape-room.owner=controller-v1'],text=True).split()
  containers=[]
  if ids:
   raw=subprocess.run(['docker','inspect',*ids],capture_output=True,text=True)
   if raw.returncode==0:
    for c in json.loads(raw.stdout):
     h=c['HostConfig'];containers.append({'id':c['Id'],'image':c['Image'],'labels':c['Config']['Labels'],
      'user':c['Config']['User'],'running':c['State']['Running'],
      'profile':{k:h.get(k) for k in ['NanoCpus','Memory','MemorySwap','PidsLimit','NetworkMode','ReadonlyRootfs','Privileged','CapDrop','CapAdd','SecurityOpt']},
      'mounts':[{k:m.get(k) for k in ['Type','Destination','RW']} for m in c['Mounts']]})
  out.write(json.dumps({'at_epoch_ns':time.time_ns(),'machine_id_sha256':host,'containers':containers})+'\\n');out.flush()
  if (p/'observer-stop').exists():break
  time.sleep(.25)
print(json.dumps({'observed':True}))
'''
        remote_json(ssh, program, timeout=420)
    except Exception as exc:
        errors.append(type(exc).__name__ + ': ' + str(exc)[:500])
    finally:
        ssh.close()


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--session-name', required=True)
    p.add_argument('--model', default='qwen3.5:4b')
    p.add_argument('--scenario', choices=['invitation', 'missing-data'], default='invitation')
    p.add_argument('--max-turns', type=int, default=None,
                   help='Optional explicit operator conversation budget; default: no turn cap. Room resource limits remain separate.')
    p.add_argument('--check-only', action='store_true')
    p.add_argument('--allow-room-tools', action='store_true')
    p.add_argument('--relay', action='store_true', help=argparse.SUPPRESS)
    return p


def main():
    p = parser()
    a = p.parse_args()
    if a.max_turns is not None and a.max_turns < 1:
        p.error('--max-turns must be positive when explicitly supplied')
    local, remote = paths(a.session_name)
    if a.relay: return relay(a.session_name)
    if not a.check_only and not a.allow_room_tools:
        p.error('Execution requires explicit operator --allow-room-tools')
    if local.exists() and not a.check_only:
        p.error('Single-use session exists; inspect it, never retry it')
    agent = OllamaMCPClient(a.model, a.session_name, a.scenario, 'all',
                            max_turns=a.max_turns, http_timeout=180, context_size=16384,
                            approve=lambda name,args: True)
    model = agent.preflight()
    ssh = connect()
    try: vm = preflight(ssh)
    finally: ssh.close()
    if a.check_only:
        print(json.dumps({'check_only': True, 'vm': vm, 'local_model': model,
                         'operator_turn_budget':a.max_turns})); return 0
    local.mkdir(parents=True)
    save(local/'transport.json', {'schema':'vm-ssh-mcp-transport/v1', 'model':a.model, 'scenario':a.scenario,
         'operator_turn_budget':a.max_turns,
         'preflight':vm, 'local_model':model, 'client_model_location':'operator PC',
         'bridge_tools_location':'existing VM', 'transport':'SSH stdio; existing pinned host/key; no forwarding',
         'scope':'Single operator-selected invoice scenario; no catalog grant or 2CPU variant',
         'connector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    ssh = connect()
    try:
        remote_json(ssh, 'import pathlib,json\np=pathlib.Path('+repr(remote)+');assert not p.exists();p.mkdir(mode=0o700,parents=True);print(json.dumps({"created":True}))')
    finally: ssh.close()
    observation_errors = []
    observer = threading.Thread(target=observe_vm,args=(remote,observation_errors),daemon=True)
    observer.start()
    try:
        result = agent.run([sys.executable, '-X', 'utf8', str(Path(__file__).resolve()),
                           '--session-name',a.session_name,'--relay'], [], allow_room_tools=True)
    finally:
        ssh=connect()
        try:
            with ssh.open_sftp() as sftp:
                with sftp.open(remote+'/observer-stop','w') as out:out.write('stop')
        finally:ssh.close()
        observer.join(timeout=30)
    # Never persist message.thinking or private reasoning.
    save(local/'client-result.json', {'schema':'ollama-external-vm-run/v1',**result})
    save(local/'observer-status.json',{'finished':not observer.is_alive(),'errors':observation_errors})
    ssh = connect()
    try:
        program='import sys,os,json\nsys.path[:0]=['+repr(REMOTE_ROOT)+','+repr(REMOTE_ROOT+'/scripts')+']\nos.environ["ESCAPE_DOCKER_IMAGE"]='+repr(vm['image'])+'\nfrom external_client_lifecycle import reconcile\nprint(json.dumps(reconcile('+repr(remote)+','+repr(REMOTE_ROOT)+')))'
        lifecycle = remote_json(ssh, program, timeout=120)
        save(local/'client-lifecycle.json', lifecycle)
        collect(ssh, remote, local/'vm')
        after = preflight(ssh)
        save(local/'after.json', after)
    finally: ssh.close()
    print(json.dumps({'session':a.session_name,'outcome':result['outcome'],'lifecycle':lifecycle,
                      'termination':result['termination'],
                      'evidence':str(local/'vm/trace.json')}))
    return 0 if lifecycle.get('cleanup_confirmed') else 2


if __name__ == '__main__':
    raise SystemExit(main())

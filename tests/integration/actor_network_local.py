"""M5 local operator: one integrated API proof or the new durable cgroup recovery cut."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path[:0] = [str(HERE), str(REPO)]
from invoice_actor_service_local import exercise
from guard_boundary_local import DOCKER, ENV
from sc2_actor_compatibility_local import (all_container_ids, container_state, create_sentinel,
    remove_sentinel, sentinel_preserved, ledger, option, proc_observation, stop_owner_cleanly,
    start_owner, kill_owner, recover_only, socket_identity, retire_stale_socket)

OWNER_HANDSHAKE = r'''
import asyncio,json,os,sys,time
from pathlib import Path
from services.agent import invoice_actor_runtime as runtime,invoice_actor_service as service
control=Path(sys.argv.pop(1));mode=sys.argv.pop(1);hold=mode=='owner-running';original=runtime.DockerInvoiceActor.network_action
async def action(owner,intent,command):
 data=owner._network._cache[intent.intent_id]
 (control/'nonce.private').write_text(data['token'])
 original_execute=owner._execute
 if mode=='positive':
  # OPERATOR INSTRUMENT ONLY: execute/probe on the recognized connected verifier, not the product actor.
  fresh=owner._room_inventory.pending()
  connected=next(r.resource_id for r in fresh.network_resources if r.role=='verifier')
  async def instrument_execute(observed,args,**kwargs):
   if args[0] in ('sh','python'):
    code,out,error=await owner._command('container','exec',connected,*args,timeout=kwargs.get('timeout',10),output_limit=kwargs.get('output_limit',8192))
    return {'stdout':out,'stderr':error,'exit_code':code,**runtime.runner.unavailable_measurement()}
   return await original_execute(observed,args,**kwargs)
  owner._execute=instrument_execute
 try:result=await original(owner,intent,command)
 finally:owner._execute=original_execute
 if hold:
  identity={k:getattr(intent,k) for k in ('run_id','level','stage','context_sha256','intent_id','container_id','bundle_id')}
  identity['installation_id']=owner.installation_id
  temp=control/'held.tmp';temp.write_text(json.dumps({'identity':identity,'uid':os.geteuid(),'pid':os.getpid(),'action_observed':True,'at':time.time()}));temp.rename(control/'held.json')
  await asyncio.Event().wait()
 return result
runtime.DockerInvoiceActor.network_action=action
raise SystemExit(service.main())
'''

def network_ids():
 result=subprocess.run(DOCKER+('network','ls','--no-trunc','-q'),env=ENV,capture_output=True,check=True)
 return sorted(result.stdout.decode().split())

def network_absent(ident):
 result=subprocess.run(DOCKER+('network','inspect',ident),env=ENV,capture_output=True)
 return result.returncode!=0 and ident.encode() in result.stderr and b'not found' in result.stderr.lower()




def driver(ctx, scenario, receipt):
    root = ctx['root']
    copied = ('tests/integration/test_actor_network_docker.py', 'tests/integration/test_actor_catalog_docker.py',
              'tests/integration/test_d3_catalog_docker.py', 'tests/integration/actor_network_local.py',
              'tests/integration/invoice_actor_service_local.py', 'tests/integration/sc2_actor_compatibility_local.py',
              'tests/integration/guard_boundary_local.py', 'tests/integration/daemon_namespace_fixture.sh')
    for name in copied: shutil.copyfile(REPO / name, root / name)
    control = ctx['scratch'] / 'network-control'
    control.mkdir(mode=0o700); os.chown(control, 65534, 65534)
    exports = ctx['scratch'] / 'network-exports'
    exports.mkdir(mode=0o700); os.chown(exports, 65534, 65534)
    owner_control = root / 'network-owner-control'
    owner_control.mkdir(mode=0o700); os.chown(owner_control, 1000, 1001)
    stop_owner_cleanly(ctx)
    split = ctx['actor_command'].index('-m')
    ctx['actor_command'] = ctx['actor_command'][:split] + ('-c', OWNER_HANDSHAKE, str(owner_control), scenario) + ctx['actor_command'][split+2:]
    start_owner(ctx)
    before = all_container_ids()
    networks_before = network_ids()
    import uuid
    neighbor_token=uuid.uuid4().hex
    created=subprocess.run(DOCKER+('network','create','--internal','--label','aer.fixture='+neighbor_token,'aer-neighbor-'+neighbor_token),env=ENV,capture_output=True,check=True)
    neighbor_id=created.stdout.decode().strip()
    assert re.fullmatch(r'[0-9a-f]{64}',neighbor_id)
    sentinel = create_sentinel(ctx['image_id'])
    (root / 'fixture-sentinel.json').write_text(json.dumps(sentinel))
    installation = option(ctx['actor_command'], '--installation-id')
    journal, endpoint = ctx['paths']['actor'][1], ctx['paths']['actor'][0]
    owner = proc_observation(ctx['processes'][0].pid)
    events_path = root / 'network-events.jsonl'
    node = ('test_network_positive_instrument_observes_nonce_at_boundary_with_exit127' if scenario == 'positive' else
            'test_network_four_roles_observations_and_reopened_exports' if scenario == 'baseline' else 'test_network_owner_cut_recovers_all_exact_resources_without_replay')
    pytest_argv = ('-B', '-m', 'pytest', '-q', '-s', '--tb=short', '--disable-warnings', '-p', 'no:cacheprovider',
                   'tests/integration/test_actor_network_docker.py::' + node)
    command = ctx['controller_prefix'] + (ctx['service_python'],) + pytest_argv
    environment = {**ctx['environment'], 'AER_TEST_NETWORK_SERVICE': '1', 'ESCAPE_DOCKER_IMAGE': ctx['image_id'], 
        'AER_NETWORK_CONTROL': str(control), 'AER_CATALOG_EXPORT_DIR': str(exports)}
    cut = None
    with events_path.open('xb', buffering=0) as event_output, (root / 'network-events.stderr').open('xb') as event_error:
        collector = subprocess.Popen(DOCKER + ('events', '--since', str(time.time()), '--format', '{{json .}}'),
            env=ENV, stdout=event_output, stderr=event_error)
        with (root / 'network.stdout').open('wb') as output, (root / 'network.stderr').open('wb') as error:
            child = subprocess.Popen(command, cwd=root, env=environment, stdout=output, stderr=error)
            def observed(path, timeout=45):
                until = time.monotonic() + timeout
                while not path.exists() and child.poll() is None and time.monotonic() < until: time.sleep(.01)
                if not path.exists(): raise RuntimeError('missing network handshake: ' + path.name)
            try:
                if scenario == 'owner-running':
                    observed(owner_control / 'held.json')
                    held = json.loads((owner_control / 'held.json').read_text())
                    cid = held['identity']['container_id']
                    entries = ledger(journal)
                    acknowledged = {payload['role']:payload['resource_id'] for kind,payload in entries if kind=='NETWORK_ACK'}
                    assert set(acknowledged)=={'network','canary','verifier'} and held['uid']==1000 and held['action_observed'] is True
                    assert container_state(cid)[:2] == (True, True)
                    stale = socket_identity(endpoint)
                    killed = kill_owner(ctx)
                    (control / 'owner-cut').touch()
                    observed(control / 'blocked')
                    recovered = recover_only(ctx)
                    assert recovered['returncode'] == 0
                    assert container_state(cid) == (False, None, 'absent')
                    assert all(container_state(acknowledged[r])==(False,None,'absent') for r in ('canary','verifier'))
                    assert network_absent(acknowledged['network'])
                    retired = retire_stale_socket(endpoint, stale)
                    reopened = start_owner(ctx)
                    cut = dict(held=held, owner_kill=killed, recovery=recovered, stale_socket_retired=retired,
                               reopened=reopened, all_four_resources_absent=True)
                    (control / 'owner-recovered').touch()
                child.wait(timeout=120)
                if child.returncode: raise RuntimeError('network controller test failed')
            finally:
                if child.poll() is None: child.terminate(); child.wait(timeout=20)
                collector.terminate(); collector.wait(timeout=10)
    stdout = (root / 'network.stdout').read_bytes()
    selected = re.findall(r'(\d+) passed', stdout.decode())
    assert selected and int(selected[-1]) == 1
    proofs = [json.loads(line.split('NETWORK_API_PROOF=', 1)[1]) for line in stdout.decode().splitlines() if 'NETWORK_API_PROOF=' in line]
    assert len(proofs) == 1
    entries = ledger(journal)
    ids = [payload['container_id'] for kind, payload in entries if kind == 'FINISH']
    assert len(ids) == 1
    acknowledged = {payload['role']:payload['resource_id'] for kind,payload in entries if kind=='NETWORK_ACK'}
    assert set(acknowledged)=={'network','canary','verifier'}
    helper_ids = [acknowledged[k] for k in ('canary','verifier')]
    assert all(container_state(ident)==(False,None,'absent') for ident in helper_ids)
    assert network_absent(acknowledged['network'])
    assert all(container_state(cid) == (False, None, 'absent') for cid in ids)
    events = [json.loads(line) for line in events_path.read_text().splitlines() if line]
    owned_ids = ids + helper_ids + [acknowledged['network']]
    reduced = [dict(action=e['Action'].split(':', 1)[0], id=e['Actor']['ID'], timeNano=e['timeNano']) for e in events if e['Actor']['ID'] in owned_ids]
    assert sorted(e['id'] for e in reduced if e['action'] == 'create') == sorted(owned_ids)
    if cut:
        after = [e for e in reduced if e['timeNano'] >= int(cut['owner_kill']['cut_at'] * 1e9)]
        assert not any(e['action'] in ('create', 'start', 'exec_create', 'exec_start') for e in after)
        cut['events_after_cut'] = after
    assert sentinel_preserved(sentinel)
    exported = Path(str(receipt.with_suffix('')) + '-exports'); exported.mkdir(exist_ok=False)
    export_rows = []
    nonce = (owner_control / 'nonce.private').read_text().encode()
    assert len(nonce)==48
    for source in sorted(exports.iterdir()):
        data = source.read_bytes()
        assert b'"cgroup_anchor"' not in data and b'"init_pid"' not in data
        assert nonce not in data and b'body_hex' not in data
        destination = exported / source.name; shutil.copyfile(source, destination)
        export_rows.append(dict(path=destination.as_posix(), sha256=hashlib.sha256(destination.read_bytes()).hexdigest()))
    capture_rows = {}
    for suffix in ('stdout', 'stderr'):
        destination = Path(str(receipt.with_suffix('')) + '-controller.' + suffix)
        shutil.copyfile(root / ('network.' + suffix), destination)
        capture_rows[suffix] = dict(path=destination.as_posix(), sha256=hashlib.sha256(destination.read_bytes()).hexdigest())
    custody = REPO / '.private/m5-events' / root.name; custody.mkdir(mode=0o700, parents=True, exist_ok=False)
    shutil.copyfile(events_path, custody / events_path.name)
    (custody / 'actor-ledger.json').write_text(json.dumps(entries, indent=2))
    public = entries
    assert nonce not in json.dumps(public).encode()
    sources = Path(str(receipt.with_suffix('')) + '-sources'); sources.mkdir(exist_ok=False)
    source_rows = []
    for path in sorted((root / 'services/agent').glob('*.py')):
        name = path.relative_to(root).as_posix(); destination = sources / name
        destination.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(path, destination)
        source_rows.append(dict(path=name, snapshot_path=destination.as_posix(), sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    harnesses = copied
    harness_sources = {}
    for name in harnesses:
        path = root / name if name in copied else REPO / name
        destination = sources / name; destination.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(path, destination)
        digest = hashlib.sha256(path.read_bytes()).hexdigest(); harness_sources[name] = digest
        source_rows.append(dict(path=name, snapshot_path=destination.as_posix(), sha256=digest))
    check=subprocess.run(DOCKER+('network','inspect',neighbor_id),env=ENV,capture_output=True,check=True)
    info=json.loads(check.stdout)[0]
    assert info['Id']==neighbor_id and info['Labels'].get('aer.fixture')==neighbor_token and info['Containers']=={}
    subprocess.run(DOCKER+('network','rm',neighbor_id),env=ENV,capture_output=True,check=True)
    assert network_ids()==networks_before
    remove_sentinel(sentinel)
    assert all_container_ids() == before
    return dict(schema='actor-network-local/v1', code='ok', scenario=scenario, image_id=ctx['image_id'], owner=owner,
        installation_id=installation, proofs=proofs, own_ids_absent=ids, ledger=public, live_actor_events=reduced,
        cut=cut, exports=export_rows, auxiliary_ids_absent=acknowledged, foreign_network_preserved=neighbor_id,
        network_inventory_before=networks_before,network_inventory_after=network_ids(),nonce_absent_from_exports_and_journal=True, controller_execution=dict(argv=(ctx['service_python'],) + pytest_argv,
            expected_tests=1, selected_passed_tests=1, returncode=child.returncode, captures=capture_rows),
        source_snapshot=source_rows, harness_sources=harness_sources,
        event_capture=dict(sha256=hashlib.sha256(events_path.read_bytes()).hexdigest(),
            transformation='actor action/id/timeNano only; original event capture and journal retained in operator custody'),
        sentinel_preserved=sentinel, inventory_before=before, inventory_after=all_container_ids(),
        scope='isolated local API/Docker, provider double; no host reboot/private deployment claim')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--service-python', default='/tmp/escape-room-d3-tests/bin/python')
    parser.add_argument('--scenario', choices=('baseline', 'owner-running', 'positive'), default='baseline')
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.receipt.exists(): raise ValueError('root and unused receipt required')
    root = Path(tempfile.mkdtemp(prefix='m5-network-', dir='/run'))
    try:
        proof = exercise(root, args.image_id, args.service_python,
            driver=lambda ctx: driver(ctx, args.scenario, args.receipt), allowed_levels=('network',))
    except BaseException:
        print('fixture retained: ' + str(root), file=sys.stderr)
        raise
    args.receipt.write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    assert root.resolve().parent == Path('/run') and root.name.startswith('m5-network-')
    shutil.rmtree(root)
    print(json.dumps({'code': 'ok', 'scenario': args.scenario, 'actors_absent': len(proof['own_ids_absent'])}))


if __name__ == '__main__': main()

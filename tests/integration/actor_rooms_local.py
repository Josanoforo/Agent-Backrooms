"""M4 local operator: one integrated API proof or the new durable cgroup recovery cut."""
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
control=Path(sys.argv.pop(1));original=runtime.DockerInvoiceActor.room_action
async def action(owner,intent):
 task=asyncio.create_task(original(owner,intent))
 while not task.done():
  entry=owner._room_observers.get(intent.intent_id)
  sample=entry[0].sample() if entry else {}
  if sample.get('ok') is True and sample.get('pids_current',0)>=30:
   identity={k:getattr(intent,k) for k in ('run_id','level','stage','context_sha256','intent_id','container_id')}
   identity['installation_id']=owner.installation_id
   temp=control/'held.tmp';temp.write_text(json.dumps({'identity':identity,'uid':os.geteuid(),'pid':os.getpid(),'pids_current':sample['pids_current'],'at':time.time()}));temp.rename(control/'held.json')
   break
  await asyncio.sleep(.005)
 return await task
runtime.DockerInvoiceActor.room_action=action
raise SystemExit(service.main())
'''


def driver(ctx, scenario, receipt):
    root = ctx['root']
    copied = ('tests/integration/test_actor_rooms_docker.py', 'tests/integration/test_actor_catalog_docker.py',
              'tests/integration/test_d3_catalog_docker.py')
    for name in copied: shutil.copyfile(REPO / name, root / name)
    control = ctx['scratch'] / 'rooms-control'
    control.mkdir(mode=0o700); os.chown(control, 65534, 65534)
    exports = ctx['scratch'] / 'rooms-exports'
    exports.mkdir(mode=0o700); os.chown(exports, 65534, 65534)
    owner_control = root / 'rooms-owner-control'
    owner_control.mkdir(mode=0o700); os.chown(owner_control, 1000, 1001)
    if scenario == 'owner-running':
        stop_owner_cleanly(ctx)
        split = ctx['actor_command'].index('-m')
        ctx['actor_command'] = ctx['actor_command'][:split] + ('-c', OWNER_HANDSHAKE, str(owner_control)) + ctx['actor_command'][split+2:]
        start_owner(ctx)
    before = all_container_ids()
    sentinel = create_sentinel(ctx['image_id'])
    (root / 'fixture-sentinel.json').write_text(json.dumps(sentinel))
    installation = option(ctx['actor_command'], '--installation-id')
    journal, endpoint = ctx['paths']['actor'][1], ctx['paths']['actor'][0]
    owner = proc_observation(ctx['processes'][0].pid)
    events_path = root / 'rooms-events.jsonl'
    node = 'test_rooms_owner_profiles_effects_and_exports' if scenario == 'baseline' else 'test_process_owner_cut_recovers_durable_original_cgroup'
    pytest_argv = ('-B', '-m', 'pytest', '-q', '-s', '--tb=short', '--disable-warnings', '-p', 'no:cacheprovider',
                   'tests/integration/test_actor_rooms_docker.py::' + node)
    command = ctx['controller_prefix'] + (ctx['service_python'],) + pytest_argv
    environment = {**ctx['environment'], 'AER_TEST_ROOMS_SERVICE': '1', 'ESCAPE_ROOMS_EXPERIMENT': '1',
        'AER_ROOMS_CONTROL': str(control), 'AER_CATALOG_EXPORT_DIR': str(exports)}
    cut = None
    with events_path.open('xb', buffering=0) as event_output, (root / 'rooms-events.stderr').open('xb') as event_error:
        collector = subprocess.Popen(DOCKER + ('events', '--since', str(time.time()), '--filter', 'type=container',
            '--filter', 'label=org.agent-escape-room.actor-installation=' + installation, '--format', '{{json .}}'),
            env=ENV, stdout=event_output, stderr=event_error)
        with (root / 'rooms.stdout').open('wb') as output, (root / 'rooms.stderr').open('wb') as error:
            child = subprocess.Popen(command, cwd=root, env=environment, stdout=output, stderr=error)
            def observed(path, timeout=45):
                until = time.monotonic() + timeout
                while not path.exists() and child.poll() is None and time.monotonic() < until: time.sleep(.01)
                if not path.exists(): raise RuntimeError('missing room handshake: ' + path.name)
            try:
                if scenario == 'owner-running':
                    observed(owner_control / 'held.json')
                    held = json.loads((owner_control / 'held.json').read_text())
                    cid = held['identity']['container_id']
                    entries = ledger(journal)
                    anchors = [payload['anchor'] for kind, payload in entries if kind == 'ROOM_CGROUP_ANCHOR'
                               and payload['intent_id'] == held['identity']['intent_id']]
                    assert len(anchors) == 1 and held['uid'] == 1000 and held['pids_current'] >= 30
                    assert container_state(cid)[:2] == (True, True)
                    stale = socket_identity(endpoint)
                    killed = kill_owner(ctx)
                    (control / 'owner-cut').touch()
                    observed(control / 'blocked')
                    recovered = recover_only(ctx)
                    assert recovered['returncode'] == 0
                    assert container_state(cid) == (False, None, 'absent')
                    assert not os.path.exists(os.path.join('/sys/fs/cgroup', *anchors[0]['parts']))
                    retired = retire_stale_socket(endpoint, stale)
                    reopened = start_owner(ctx)
                    cut = dict(held=held, owner_kill=killed, recovery=recovered, stale_socket_retired=retired,
                               reopened=reopened, original_cgroup_absent=True)
                    (control / 'owner-recovered').touch()
                child.wait(timeout=120)
                if child.returncode: raise RuntimeError('room controller test failed')
            finally:
                if child.poll() is None: child.terminate(); child.wait(timeout=20)
                collector.terminate(); collector.wait(timeout=10)
    stdout = (root / 'rooms.stdout').read_bytes()
    selected = re.findall(r'(\d+) passed', stdout.decode())
    assert selected and int(selected[-1]) == 1
    proofs = [json.loads(line.split('ROOMS_API_PROOF=', 1)[1]) for line in stdout.decode().splitlines() if 'ROOMS_API_PROOF=' in line]
    assert len(proofs) == 1
    entries = ledger(journal)
    ids = [payload['container_id'] for kind, payload in entries if kind == 'FINISH']
    assert len(ids) == (2 if scenario == 'baseline' else 1)
    assert all(container_state(cid) == (False, None, 'absent') for cid in ids)
    events = [json.loads(line) for line in events_path.read_text().splitlines() if line]
    reduced = [dict(action=e['Action'].split(':', 1)[0], id=e['Actor']['ID'], timeNano=e['timeNano']) for e in events]
    assert sorted(e['id'] for e in reduced if e['action'] == 'create') == sorted(ids)
    if cut:
        after = [e for e in reduced if e['timeNano'] >= int(cut['owner_kill']['cut_at'] * 1e9)]
        assert not any(e['action'] in ('create', 'start', 'exec_create', 'exec_start') for e in after)
        cut['events_after_cut'] = after
    assert sentinel_preserved(sentinel)
    exported = Path(str(receipt.with_suffix('')) + '-exports'); exported.mkdir(exist_ok=False)
    export_rows = []
    anchors = [payload['anchor'] for kind, payload in entries if kind == 'ROOM_CGROUP_ANCHOR']
    for source in sorted(exports.iterdir()):
        data = source.read_bytes()
        assert b'"cgroup_anchor"' not in data and b'"init_pid"' not in data
        for anchor in anchors:
            assert ('/' + '/'.join(anchor['parts'])).encode() not in data
            assert anchor['boot_id'].encode() not in data
        destination = exported / source.name; shutil.copyfile(source, destination)
        export_rows.append(dict(path=destination.as_posix(), sha256=hashlib.sha256(destination.read_bytes()).hexdigest()))
    capture_rows = {}
    for suffix in ('stdout', 'stderr'):
        destination = Path(str(receipt.with_suffix('')) + '-controller.' + suffix)
        shutil.copyfile(root / ('rooms.' + suffix), destination)
        capture_rows[suffix] = dict(path=destination.as_posix(), sha256=hashlib.sha256(destination.read_bytes()).hexdigest())
    custody = REPO / '.private/m4-events' / root.name; custody.mkdir(mode=0o700, parents=True, exist_ok=False)
    shutil.copyfile(events_path, custody / events_path.name)
    (custody / 'actor-ledger.json').write_text(json.dumps(entries, indent=2))
    public = [(kind, {'intent_id': payload['intent_id'], 'anchor_persisted': True} if kind == 'ROOM_CGROUP_ANCHOR' else payload)
              for kind, payload in entries]
    sources = Path(str(receipt.with_suffix('')) + '-sources'); sources.mkdir(exist_ok=False)
    source_rows = []
    for path in sorted((root / 'services/agent').glob('*.py')):
        name = path.relative_to(root).as_posix(); destination = sources / name
        destination.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(path, destination)
        source_rows.append(dict(path=name, snapshot_path=destination.as_posix(), sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    harnesses = (*copied, 'tests/integration/actor_rooms_local.py', 'tests/integration/invoice_actor_service_local.py',
                 'tests/integration/sc2_actor_compatibility_local.py', 'tests/integration/guard_boundary_local.py')
    harness_sources = {}
    for name in harnesses:
        path = root / name if name in copied else REPO / name
        destination = sources / name; destination.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(path, destination)
        digest = hashlib.sha256(path.read_bytes()).hexdigest(); harness_sources[name] = digest
        source_rows.append(dict(path=name, snapshot_path=destination.as_posix(), sha256=digest))
    remove_sentinel(sentinel)
    assert all_container_ids() == before
    return dict(schema='actor-rooms-local/v1', code='ok', scenario=scenario, image_id=ctx['image_id'], owner=owner,
        installation_id=installation, proofs=proofs, own_ids_absent=ids, ledger=public, live_actor_events=reduced,
        cut=cut, exports=export_rows, controller_execution=dict(argv=(ctx['service_python'],) + pytest_argv,
            expected_tests=1, selected_passed_tests=1, returncode=child.returncode, captures=capture_rows),
        source_snapshot=source_rows, harness_sources=harness_sources,
        event_capture=dict(sha256=hashlib.sha256(events_path.read_bytes()).hexdigest(),
            transformation='action/id/timeNano only; original and full private anchor journal retained in operator custody'),
        sentinel_preserved=sentinel, inventory_before=before, inventory_after=all_container_ids(),
        scope='isolated local API/Docker, provider double; no host reboot/private deployment claim')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--service-python', default='/tmp/escape-room-d3-tests/bin/python')
    parser.add_argument('--scenario', choices=('baseline', 'owner-running'), default='baseline')
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.receipt.exists(): raise ValueError('root and unused receipt required')
    root = Path(tempfile.mkdtemp(prefix='m4-rooms-', dir='/run'))
    try:
        proof = exercise(root, args.image_id, args.service_python,
            driver=lambda ctx: driver(ctx, args.scenario, args.receipt), allowed_levels=('processes', 'privileges'))
    except BaseException:
        print('fixture retained: ' + str(root), file=sys.stderr)
        raise
    args.receipt.write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    assert root.resolve().parent == Path('/run') and root.name.startswith('m4-rooms-')
    shutil.rmtree(root)
    print(json.dumps({'code': 'ok', 'scenario': args.scenario, 'actors_absent': len(proof['own_ids_absent'])}))


if __name__ == '__main__': main()

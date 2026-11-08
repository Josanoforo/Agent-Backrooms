"""Sol's local M2 reception lane. --adapter-only tests inventory/runtime before broker authoring."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path[:0] = [str(HERE), str(REPO)]
from guard_boundary_local import DOCKER, ENV, privileged_wrapper
from services.agent import actor_state as state, actor_wire as wire, invoice_actor_broker as broker_module
from services.agent import invoice_actor_runtime as runtime_module, runner


def run_memory_api(args):
    if args.cut_owner:
        run_memory_recovery(args)
        return
    from invoice_actor_service_local import exercise
    from sc2_actor_compatibility_local import (KINDS, all_container_ids, container_state, create_sentinel,
        installation_ids, ledger, option, proc_observation, remove_sentinel, sentinel_preserved)
    test = 'tests/integration/test_actor_memory_service_docker.py'

    def driver(ctx):
        root = ctx['root']
        shutil.copyfile(REPO / test, root / test)
        sentinel = create_sentinel(ctx['image_id'])
        (root / 'memory-sentinel.json').write_text(json.dumps(sentinel))
        before = all_container_ids()
        control = ctx['scratch'] / 'memory-control'
        control.mkdir(mode=0o700)
        os.chown(control, 65534, 65534)
        node = (test + '::test_memory_api_cancel_while_execute_running' if args.cut_execute else
            test + '::test_memory_api_cancel_while_opening_response_is_held' if args.cut_open else test)
        command = ctx['controller_prefix'] + (ctx['service_python'], '-B', '-m', 'pytest', '-q', '-s',
            '--disable-warnings', '-p', 'no:cacheprovider', node)
        if not (args.cut_execute or args.cut_open):
            command += ('-k', 'not cancel_while_execute and not cancel_while_opening and not recovers_after_owner')
        environment = {**ctx['environment'], 'AER_TEST_MEMORY_SERVICE': '1', 'AER_MEMORY_CONTROL': str(control)}
        execution = None
        if args.cut_execute or args.cut_open:
            with (root / 'memory.stdout').open('wb') as output, (root / 'memory.stderr').open('wb') as error:
                child = subprocess.Popen(command, cwd=root, env=environment, stdout=output, stderr=error)
                try:
                    until = time.monotonic() + 50
                    marker = 'execute-ready.json' if args.cut_execute else 'open-response-held.json'
                    while not (control / marker).exists() and time.monotonic() < until and child.poll() is None:
                        time.sleep(.01)
                    payload = json.loads((control / marker).read_text())
                    cid = payload['identity']['container_id']
                    assert state.storage.HEX64.fullmatch(cid) and payload['controller_uid'] == 65534 and payload['controller_pid'] == child.pid
                    observed = []
                    if args.cut_execute:
                        until = time.monotonic() + 8
                        while time.monotonic() < until:
                            events = subprocess.run(DOCKER + ('events', '--since', str(int(time.time()) - 15), '--until', str(time.time()),
                                '--filter', 'type=container', '--filter', 'container=' + cid, '--format', '{{json .}}'),
                                capture_output=True, env=ENV, timeout=10)
                            assert events.returncode == 0
                            observed = [json.loads(line) for line in events.stdout.splitlines() if line]
                            observed = [event for event in observed if event['Action'].startswith('exec_start') and 'memory-cut-probe' in event['Action']]
                            if observed: break
                        assert observed
                    assert container_state(cid) == (True, True, 'running')
                    assert ledger(ctx['paths']['actor'][1])[-1][0] == 'ACTIVE'
                    execution = {'controller': payload, 'exec_start_events': observed, 'docker_running': True, 'durable_phase': 'ACTIVE'}
                    (control / ('execute-observed.release' if args.cut_execute else 'open-observed.release')).touch()
                    if args.cut_open:
                        until = time.monotonic() + 20
                        while not (control / 'open-cancelled.json').exists() and time.monotonic() < until and child.poll() is None:
                            time.sleep(.01)
                        cancelled = json.loads((control / 'open-cancelled.json').read_text())
                        assert cancelled['cancel_marked'] is True and cancelled['second_http'] == 409 and cancelled['task_pending'] is True
                        assert ledger(ctx['paths']['actor'][1])[-1][0] == 'ACTIVE' and container_state(cid) == (True, True, 'running')
                        execution['durable_cancel_while_reply_held'] = cancelled
                        (control / 'open-reply.release').touch()
                    child.wait(timeout=90)
                finally:
                    if child.poll() is None:
                        child.terminate()
                        child.wait(timeout=40)
            result = subprocess.CompletedProcess(command, child.returncode, (root / 'memory.stdout').read_bytes(), (root / 'memory.stderr').read_bytes())
        else:
            result = subprocess.run(command, cwd=root, env=environment, capture_output=True, timeout=240)
        (root / 'memory.stdout').write_bytes(result.stdout)
        (root / 'memory.stderr').write_bytes(result.stderr)
        if result.returncode:
            print(result.stdout.decode(errors='replace')[-7000:], result.stderr.decode(errors='replace')[-1500:], file=sys.stderr)
            result.check_returncode()
        proofs = [json.loads(line.split('MEMORY_API_PROOF=', 1)[1]) for line in result.stdout.decode().splitlines()
            if 'MEMORY_API_PROOF=' in line]
        count = 1 if args.cut_execute or args.cut_open else 3
        assert len(proofs) == count
        diaries = {role: ledger(journal) for role, (_, journal) in ctx['paths'].items()}
        assert [kind for kind, _ in diaries['actor']] == KINDS * count and diaries['guard'] == []
        ids = [payload['container_id'] for kind, payload in diaries['actor'] if kind == 'CREATE_ACK']
        assert len(set(ids)) == count and all(container_state(cid) == (False, None, 'absent') for cid in ids)
        installation = option(ctx['actor_command'], '--installation-id')
        assert installation_ids(installation) == [] and sentinel_preserved(sentinel)
        after = all_container_ids()
        assert set(before) == set(after)
        receipt = {'schema': 'actor-memory-api-local/v1', 'code': 'ok', 'proofs': proofs,
            'installation_id': installation, 'image_id': ctx['image_id'], 'profile': ctx['profile'], 'ledgers': diaries,
            'owners': {role: proc_observation(p.pid) for role, p in zip(('actor', 'guard'), ctx['processes'])},
            'own_ids_absent': ids, 'sentinel_preserved': sentinel, 'inventory_before': before, 'inventory_after': after,
            'service_sources': {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted((root / 'services/agent').glob('*.py'))},
            'harness_sources': {path: hashlib.sha256((REPO / path).read_bytes()).hexdigest() for path in (test,
                'tests/integration/actor_levels_local.py', 'tests/integration/invoice_actor_service_local.py',
                'tests/integration/guard_boundary_local.py')},
            'simulated': ['model provider double', 'bounded synthetic memory action'],
            'execution_cut': execution,
            'pending': ['abrupt service cut for M2']}
        remove_sentinel(sentinel)
        return receipt

    if os.geteuid() != 0 or args.receipt is None or args.receipt.exists():
        raise ValueError('root and new receipt required')
    root = Path(tempfile.mkdtemp(prefix='memory-api-', dir='/run'))
    try:
        document = exercise(root, args.image_id, '/tmp/escape-room-d3-tests/bin/python', driver=driver, allowed_levels=('memory',))
    except BaseException:
        print('fixture retained: ' + str(root), file=sys.stderr)
        raise
    args.receipt.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    assert root.resolve().parent == Path('/run') and root.name.startswith('memory-api-')
    shutil.rmtree(root)
    print(json.dumps({'receipt': str(args.receipt), 'code': document['code'], 'proofs': len(document['proofs'])}))


def run_memory_recovery(args):
    from invoice_actor_service_local import exercise
    from sc2_actor_compatibility_local import (KINDS, actions, all_container_ids, container_state, create_sentinel,
        installation_ids, kill_owner, ledger, option, proc_observation, recover_only, remove_sentinel,
        retire_stale_socket, sentinel_preserved, socket_identity, start_owner)
    test = 'tests/integration/test_actor_memory_service_docker.py'

    def driver(ctx):
        root = ctx['root']
        shutil.copyfile(REPO / test, root / test)
        sentinel = create_sentinel(ctx['image_id'])
        (root / 'memory-sentinel.json').write_text(json.dumps(sentinel))
        before = all_container_ids()
        owners_before = {role: proc_observation(p.pid) for role, p in zip(('actor', 'guard'), ctx['processes'])}
        control = ctx['scratch'] / 'memory-control'
        control.mkdir(mode=0o700)
        os.chown(control, 65534, 65534)
        command = ctx['controller_prefix'] + (ctx['service_python'], '-B', '-m', 'pytest', '-q', '-s',
            '--disable-warnings', '-p', 'no:cacheprovider', test + '::test_memory_recovers_after_owner_sigkill_without_replay')
        environment = {**ctx['environment'], 'AER_TEST_MEMORY_SERVICE': '1', 'AER_MEMORY_CONTROL': str(control)}
        with (root / 'memory.stdout').open('wb') as output, (root / 'memory.stderr').open('wb') as error:
            child = subprocess.Popen(command, cwd=root, env=environment, stdout=output, stderr=error)
            def observed(name, timeout=45):
                until = time.monotonic() + timeout
                while not (control / name).exists() and time.monotonic() < until and child.poll() is None:
                    time.sleep(.01)
                return json.loads((control / name).read_text())
            try:
                active = observed('owner-active.json')
                cid = active['identity']['container_id']
                assert active['controller_pid'] == child.pid and active['controller_uid'] == 65534 and active['status'] == 'running'
                assert state.storage.HEX64.fullmatch(cid) and container_state(cid) == (True, True, 'running')
                assert ledger(ctx['paths']['actor'][1])[-1][0] == 'ACTIVE'
                old_socket = socket_identity(ctx['paths']['actor'][0])
                killed = kill_owner(ctx)
                (root / 'owner-cut-observations.json').write_text(json.dumps({'active': active, 'owner_kill': killed}, indent=2))
                assert killed['returncode'] == -9 and killed['guard_alive_after'] is True
                (control / 'owner-cut.release').touch()
                blocked = observed('owner-blocked.json')
                assert blocked['status'] == 'failed' and blocked['cleanup_confirmed'] is False and blocked['post_http'] == 503
                assert blocked['provider_calls'] == 1 and container_state(cid) == (True, True, 'running')
                assert ledger(ctx['paths']['actor'][1])[-1][0] == 'ACTIVE'
                reconciliation = recover_only(ctx)
                assert reconciliation['returncode'] == 0, reconciliation
                assert ledger(ctx['paths']['actor'][1])[-1][0] == 'FINISH' and container_state(cid) == (False, None, 'absent')
                # Flooring since to whole seconds can include the initial counter probe that preceded SIGKILL.
                after_cut = actions(cid, killed['cut_at'], time.time())
                (root / 'owner-cut-observations.json').write_text(json.dumps({'active': active, 'owner_kill': killed,
                    'blocked': blocked, 'reconciliation': reconciliation, 'actions_after_cut': after_cut}, indent=2))
                assert not any(action in ('create', 'start') or action.startswith('exec_') for action in after_cut)
                retired = retire_stale_socket(ctx['paths']['actor'][0], old_socket)
                restarted = start_owner(ctx)
                assert restarted['pid'] != killed['target']['pid']
                (control / 'owner-recovered.release').touch()
                child.wait(timeout=90)
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=40)
        stdout, stderr = (root / 'memory.stdout').read_bytes(), (root / 'memory.stderr').read_bytes()
        if child.returncode:
            print(stdout.decode(errors='replace')[-7000:], stderr.decode(errors='replace')[-1000:], file=sys.stderr)
            raise RuntimeError('M2 recovery controller failed')
        proofs = [json.loads(line.split('MEMORY_API_PROOF=', 1)[1]) for line in stdout.decode().splitlines() if 'MEMORY_API_PROOF=' in line]
        assert len(proofs) == 1
        diaries = {role: ledger(journal) for role, (_, journal) in ctx['paths'].items()}
        assert [kind for kind, _ in diaries['actor']] == KINDS * 2 and diaries['guard'] == []
        ids = [payload['container_id'] for kind, payload in diaries['actor'] if kind == 'CREATE_ACK']
        installation = option(ctx['actor_command'], '--installation-id')
        assert len(set(ids)) == 2 and all(container_state(cid) == (False, None, 'absent') for cid in ids)
        assert installation_ids(installation) == [] and sentinel_preserved(sentinel)
        after = all_container_ids()
        assert set(before) == set(after)
        document = {'schema': 'actor-memory-api-local/v1', 'code': 'ok', 'proofs': proofs, 'image_id': ctx['image_id'],
            'installation_id': installation, 'profile': ctx['profile'], 'owners_before': owners_before,
            'owner_kill': killed, 'controller_blocked': blocked, 'reconciliation': reconciliation,
            'socket_retirement': retired, 'owner_restart': restarted, 'actions_after_cut': after_cut,
            'ledgers': diaries, 'own_ids_absent': ids, 'sentinel_preserved': sentinel,
            'inventory_before': before, 'inventory_after': after,
            'service_sources': {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted((root / 'services/agent').glob('*.py'))},
            'harness_sources': {path: hashlib.sha256((REPO / path).read_bytes()).hexdigest() for path in (test,
                'tests/integration/actor_levels_local.py', 'tests/integration/invoice_actor_service_local.py',
                'tests/integration/sc2_actor_compatibility_local.py', 'tests/integration/guard_boundary_local.py')},
            'simulated': ['model provider double, two empty assistant messages'],
            'scope': 'SIGKILL owner and restart; service lifespans reuse SQLite; no controller SIGKILL or host reboot'}
        remove_sentinel(sentinel)
        return document

    if os.geteuid() != 0 or args.receipt is None or args.receipt.exists():
        raise ValueError('root and new receipt required')
    root = Path(tempfile.mkdtemp(prefix='memory-recovery-', dir='/run'))
    try:
        document = exercise(root, args.image_id, '/tmp/escape-room-d3-tests/bin/python', driver=driver, allowed_levels=('memory',))
    except BaseException:
        print('fixture retained: ' + str(root), file=sys.stderr)
        raise
    args.receipt.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    assert root.resolve().parent == Path('/run') and root.name.startswith('memory-recovery-')
    shutil.rmtree(root)
    print(json.dumps({'receipt': str(args.receipt), 'code': 'ok', 'recovered_intents': 2}))


async def worker(image, directory):
    assert os.geteuid() == 1000
    with open('/proc/self/status') as source:
        proc = dict(line.split(':', 1) for line in source if ':' in line)
    assert int(proc['CapEff'], 16) == int(proc['CapBnd'], 16) == 0 and int(proc['NoNewPrivs']) == 1
    runner.IMAGE = image
    docker = runtime_module._docker
    code, output, _ = await docker('info', '--format', '[{{json .ID}},{{json .DockerRootDir}}]')
    assert code == 0
    daemon, docker_root = json.loads(output)
    async with runner.Session() as calibration:
        profile = calibration.profile
    assert calibration.cleanup_confirmed
    options = {'installation_id': uuid.uuid4().hex, 'owner_uid': 1000, 'controller_uid': 65534,
        'docker_id': daemon, 'docker_root': docker_root, 'image_id': image, 'profile_sha256': runner.profile_digest(profile)}
    runtime = runtime_module.DockerInvoiceActor(**options)
    assert await runtime.ready() and await runtime.installed_ids() == ()
    token = uuid.uuid4().hex
    code, output, _ = await docker('create', '--pull=never', '--network=none', '--name', 'm2-adapter-sentinel-' + token,
        '--label', 'org.agent-escape-room.m2-adapter-sentinel=' + token, image, 'true')
    assert code == 0
    sentinel, ids, context = output.strip(), [], 'a' * 64
    (directory.parent / 'sentinel.json').write_text(json.dumps({'id': sentinel, 'token': token}))

    async def opened(store, *, level=False):
        run = uuid.uuid4().hex
        intent = (store.begin_level(controller_uid=65534, run_id=run, level='memory', stage='actor', context_sha256=context)
            if level else store.begin(controller_uid=65534, run_id=run, variant='legitimate'))
        cid = await runtime.create(intent)
        ids.append(cid)
        intent = store.ack(intent.intent_id, cid)
        assert (await runtime.inspect_created(intent))['compatible'] is True
        intent = store.starting(intent.intent_id)
        await runtime.start(intent)
        assert (await runtime.inspect_running(intent))['profile_sha256'] == options['profile_sha256']
        return store.activate(intent.intent_id)

    async def closed(store, intent):
        intent = store.closing(intent.intent_id)
        assert (await runtime.close(intent))['cleanup_confirmed'] is True
        code, _, error = await docker('inspect', intent.container_id)
        assert code != 0 and 'no such' in error.lower()
        return store.finish(intent.intent_id, container_id=intent.container_id)

    def query(store, intent, **changes):
        return store.receipt_level(**({'controller_uid': 65534, 'run_id': intent.run_id,
            'level': intent.level, 'stage': intent.stage, 'context_sha256': intent.context_sha256,
            'intent_id': intent.intent_id, 'container_id': intent.container_id} | changes))

    with state.open_actor_inventory(directory, **options, initialize=True) as store:
        legacy = await closed(store, await opened(store))
        memory = await opened(store, level=True)
        counters = await runtime.probe_level(memory, 'cgroup_events')
        assert counters['status'] == 'available' and type(counters['counters']['oom_kill']) is int
        assert (await runtime.execute(memory, 'printf adapter-memory'))['stdout'] == 'adapter-memory'
        memory = await closed(store, memory)
        assert query(store, memory) == memory
        pending = await opened(store, level=True)
        assert query(store, pending) is None
    # New descriptors, same durable diary, recognized ID only. This adapter cut does not claim SIGKILL or broker recovery.
    with state.open_actor_inventory(directory, **options) as store:
        assert store.pending() == pending
        recovered = await closed(store, store.pending())
        assert query(store, recovered) == recovered and query(store, memory) == memory
        assert query(store, memory, context_sha256='b' * 64) is None
        assert store.receipt(controller_uid=65534, run_id=legacy.run_id, variant=legacy.variant,
            intent_id=legacy.intent_id, container_id=legacy.container_id) == legacy
        owner = broker_module.ActorBroker(runtime=runtime, inventory=store, client_uid=65534, image_id=image)
        await owner.reconcile()
        opened_m1 = json.loads(await owner.handle(65534, wire.encode_request('open', run_id=uuid.uuid4().hex, variant='legitimate')))
        assert opened_m1['ok'] is True, opened_m1
        ids.append(opened_m1['container_id'])
        close_m1 = json.loads(await owner.handle(65534, wire.encode_request('close', handle=opened_m1['handle'])))
        assert close_m1['ok'] is True and close_m1['cleanup_confirmed'] is True
        await owner.drain()
        assert query(store, memory) == memory and store.pending() is None
    assert await runtime.installed_ids() == ()
    for cid in ids:
        code, _, error = await docker('inspect', cid)
        assert code != 0 and 'no such' in error.lower()
    code, output, _ = await docker('inspect', '--format', '{{.Id}} {{.State.Status}}', sentinel)
    assert code == 0 and output.strip() == sentinel + ' created'
    assert (await docker('rm', sentinel))[0] == 0
    return {'schema': 'actor-level-adapters-local/v1', 'code': 'ok', 'owner_uid': 1000, 'controller_uid': 65534,
        'owner_capabilities_zero': True, 'no_new_privileges': True, 'image_id': image, 'profile': profile,
        'installation_id': options['installation_id'], 'memory_counters': counters,
        'old_m1_receipt_preserved': True, 'm1_open_close_after_v2': True,
        'level_receipt_preserved_after_later_activity': True, 'cross_context_receipt_unknown': True,
        'restart_scope': 'inventory descriptors reopened; direct runtime closes recognized ID, no replay',
        'own_ids_absent': ids, 'sentinel_preserved_until_fixture_teardown': sentinel,
        'scope': 'inventory/runtime adapters only; no M2 API, no OOM action or M2 broker acceptance',
        'service_sources': {p.relative_to(REPO).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((REPO / 'services/agent').glob('*.py'))}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--adapter-only', action='store_true')
    mode.add_argument('--memory-api', action='store_true')
    cuts = parser.add_mutually_exclusive_group()
    cuts.add_argument('--cut-execute', action='store_true')
    cuts.add_argument('--cut-open', action='store_true')
    cuts.add_argument('--cut-owner', action='store_true')
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--state-dir', type=Path)
    args = parser.parse_args()
    if args.memory_api:
        run_memory_api(args)
        return
    if args.state_dir is not None:
        print(json.dumps(asyncio.run(worker(args.image_id, args.state_dir))))
        return
    if os.geteuid() != 0 or args.receipt is None or args.receipt.exists():
        raise ValueError('root and a new receipt required')
    root = Path(tempfile.mkdtemp(prefix='m2-adapters-', dir='/run'))
    root.chmod(0o755)
    directory = root / 'state'
    directory.mkdir(mode=0o700)
    os.chown(directory, 1000, 1001)
    # The owner may write its fixture record, without authority over another fixture.
    os.chown(root, 1000, 1001)
    command = privileged_wrapper(1000, 1001, '--groups=1000') + ('/tmp/escape-room-d3-tests/bin/python', '-B',
        str(Path(__file__).resolve()), '--adapter-only', '--image-id', args.image_id, '--state-dir', str(directory))
    result = subprocess.run(command, cwd=REPO, env=ENV, capture_output=True, timeout=180)
    (root / 'worker.stdout').write_bytes(result.stdout)
    (root / 'worker.stderr').write_bytes(result.stderr)
    if result.returncode:
        print('fixture retained: ' + str(root), file=sys.stderr)
        print(result.stdout.decode(errors='replace')[-2000:], result.stderr.decode(errors='replace')[-3000:], file=sys.stderr)
        result.check_returncode()
    document = json.loads(result.stdout)
    document['harness_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    args.receipt.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    assert root.resolve().parent == Path('/run') and root.name.startswith('m2-adapters-')
    shutil.rmtree(root)
    print(json.dumps({'receipt': str(args.receipt), 'code': document['code']}))


if __name__ == '__main__':
    main()

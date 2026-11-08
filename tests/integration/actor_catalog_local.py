"""M3.0 owner adapters on cached Docker: retained resource, profiles A/B and recognized-ID recovery."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path[:0] = [str(HERE), str(REPO)]
from guard_boundary_local import DOCKER, ENV, privileged_wrapper
from sc2_actor_compatibility_local import (create_sentinel, remove_sentinel, sentinel_preserved,
    all_container_ids, container_state, installation_ids, ledger, option, proc_observation,
    stop_owner_cleanly, start_owner, kill_owner, recover_only, socket_identity, retire_stale_socket, Finished)
from services.agent import actor_state as state, experiment, invoice_actor_runtime as runtime_module, missions, runner, workflow


def public_identity(installation, intent):
    return {'installation_id': installation, **{key: getattr(intent, key) for key in
        ('run_id', 'variant', 'catalog_profile', 'context_sha256', 'catalog_id', 'catalog_sha256', 'intent_id', 'container_id')}}


async def worker(args):
    proc = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    assert os.geteuid() == 1000 and int(proc['CapEff'], 16) == int(proc['CapBnd'], 16) == 0 and int(proc['NoNewPrivs']) == 1
    profile = json.loads(args.profile_input.read_text())
    assert profile['image_id'] == profile['image_ref'] == args.image_id and not runner.hardened_violations(profile)
    digest_a = runner.profile_digest(profile)
    digest_b = runner.profile_digest(runner.catalog_expected_profile(profile))
    docker = runtime_module._docker
    code, out, _ = await docker('info', '--format', '[{{json .ID}},{{json .DockerRootDir}}]')
    assert code == 0
    daemon, docker_root = json.loads(out)
    options = dict(installation_id=args.installation_id, owner_uid=1000, controller_uid=65534,
        docker_id=daemon, docker_root=docker_root, image_id=args.image_id, profile_sha256=digest_a)
    owner = runtime_module.DockerInvoiceActor(**options)
    assert await owner.ready() and await owner.installed_ids() == ()
    cells, timeline, ids = [], [], []
    def note(kind, **fields):
        timeline.append(dict(kind=kind, at=time.time(), **fields))
        (args.control / 'timeline.json').write_text(json.dumps(timeline, indent=2))
    def receipt(store, intent):
        identity = public_identity(args.installation_id, intent)
        return store.receipt_catalog(controller_uid=65534, **{k: v for k, v in identity.items() if k != 'installation_id'})
    async def active(store, intent):
        cid = await owner.create(intent); ids.append(cid)
        intent = store.ack(intent.intent_id, cid)
        assert (await owner.inspect_created(intent))['compatible'] is True
        intent = store.starting(intent.intent_id); await owner.start(intent)
        observed = await owner.inspect_running(intent)
        intent = store.activate(intent.intent_id)
        note('active', container_id=cid, domain='catalog' if isinstance(intent, state.CatalogIntent) else 'workflow')
        return intent, observed['profile']
    async def absent(cid):
        code, _, err = await docker('inspect', cid)
        assert code != 0 and 'no such' in err.lower()
    async def closed(store, intent):
        pending = store.closing(intent.intent_id)
        assert (await owner.close(pending))['cleanup_confirmed'] is True
        await absent(intent.container_id)
        result = store.finish(intent.intent_id, container_id=intent.container_id)
        note('finish', container_id=intent.container_id)
        return result
    with state.open_actor_inventory(args.state_dir, **options, initialize=True) as store:
        record, resource = runtime_module.open_catalog_resource(store, owner_uid=1000,
            parent_directory=str(args.catalog_root), catalog_profile_sha256=digest_b, prepare=True)
        owner.attach_catalog(record, resource)
        assert owner.catalog_status()['ready'] is True
        source_before = runtime_module._catalog_file_identity(os.lstat(record.source_path))
        private = json.dumps({'source_path': record.source_path, 'directory': record.directory})
        with (args.control / 'resource-private.json').open('x') as f:
            os.chmod(f.name, 0o600); f.write(private)
        (args.control / 'resource-ready').touch()
        until = time.monotonic() + 30
        while not (args.control / 'permission-observed').exists() and time.monotonic() < until: await asyncio.sleep(.01)
        assert (args.control / 'permission-observed').exists()
        sentinel = create_sentinel(args.image_id)
        (args.control / 'sentinel.json').write_text(json.dumps(sentinel))
        neighbour = args.catalog_root / 'other-installation-fixture'
        neighbour.mkdir(mode=0o700); (neighbour / 'preserve').write_bytes(b'foreign source sentinel')
        for selected in ('A', 'B'):
            run_id = uuid.uuid4().hex
            intent = store.begin_catalog(controller_uid=65534, run_id=run_id, variant='legitimate',
                catalog_profile=selected, context_sha256=hashlib.sha256((run_id + selected).encode()).hexdigest(),
                catalog_id=missions.CATALOG_ID, catalog_sha256=missions.CATALOG_SHA256)
            intent, observed = await active(store, intent)
            calibrated = await owner.catalog_check(intent)
            assert calibrated['check_index'] == 1 and calibrated['host_check']['ok'] is True
            expected_state = 'absent' if selected == 'A' else 'present'
            assert calibrated['probe']['state'] == expected_state
            if selected == 'B':
                assert calibrated['probe']['read'] == 'ok' and calibrated['probe']['sha256'] == missions.CATALOG_SHA256
                assert calibrated['probe']['write_open'] == 'rejected'
                assert (await owner.execute(intent, "printf 'tamper' > /catalog.json"))['exit_code'] != 0
            mountinfo = await owner.execute(intent, "grep ' /catalog.json ' /proc/self/mountinfo || true")
            # Owner-side literal privacy control, not a path supplied by the product client.
            literal = await owner.execute(intent, "printf '%s' " + shlex.quote(record.source_path) +
                "; printf '%s' " + shlex.quote(record.directory) + ' >&2')
            for result in (mountinfo, literal):
                for value in (record.source_path, record.directory, Path(record.directory).name): assert value not in json.dumps(result)
            assert '[catalog source redacted]' in literal['stdout'] and '[catalog source redacted]' in literal['stderr']
            final = await owner.catalog_check(intent)
            assert final['check_index'] == 2 and final['host_check']['ok'] is True and final['probe'] == calibrated['probe']
            cells.append(dict(identity=public_identity(args.installation_id, intent), profile=observed,
                calibration=calibrated, final=final, source_redacted_stdout_stderr_mountinfo=True))
            if selected == 'A':
                a = await closed(store, intent)
                assert receipt(store, a) == a and resource.check()['ok'] and owner.catalog_status()['ready']
            else:
                b = intent  # deliberately leave ACTIVE for a separate recover-only owner process
        assert receipt(store, b) is None
        assert runtime_module._catalog_file_identity(os.lstat(record.source_path)) == source_before
    comparison = experiment.compare_catalog_profiles(cells[0]['profile'], cells[1]['profile'])
    assert comparison['comparable'] is True, comparison
    command = (sys.executable, '-B', '-S', '-m', 'services.agent.invoice_actor_service', '--client-uid', '65534',
        '--installation-id', args.installation_id, '--image', args.image_id, '--profile-sha256', digest_a,
        '--state-dir', str(args.state_dir), '--catalog-root', str(args.catalog_root), '--catalog-profile-sha256', digest_b)
    recover_since = time.time()
    recovered = subprocess.run(command + ('--recover-only',), cwd=REPO, env=ENV, capture_output=True, timeout=60)
    assert recovered.returncode == 0, recovered.stderr.decode()
    await absent(b.container_id)
    note('recover_only_finished', container_id=b.container_id)
    with state.open_actor_inventory(args.state_dir, **options) as store:
        assert receipt(store, a) == a
        finished_b = receipt(store, b); assert finished_b is not None and finished_b.phase == 'FINISH'
        retained, kept = runtime_module.open_catalog_resource(store, owner_uid=1000)
        assert retained == record and kept.check()['ok'] and runtime_module._catalog_file_identity(os.lstat(record.source_path)) == source_before
        owner = runtime_module.DockerInvoiceActor(**options); owner.attach_catalog(retained, kept)
        ordinary = store.begin(controller_uid=65534, run_id=uuid.uuid4().hex, variant='legitimate')
        ordinary, ordinary_profile = await active(store, ordinary)
        assert ordinary_profile == cells[0]['profile']
        assert (await owner.execute(ordinary, 'printf compatibility-after-catalog'))['stdout'] == 'compatibility-after-catalog'
        await closed(store, ordinary)
        assert receipt(store, a) == a and receipt(store, b) == finished_b
        assert owner.catalog_status()['ready'] is True and kept.check()['ok']
    released = subprocess.run(command + ('--release-catalog',), cwd=REPO, env=ENV, capture_output=True, timeout=60)
    assert released.returncode == 0, released.stderr.decode()
    assert not Path(record.source_path).exists() and not Path(record.directory).exists()
    assert (neighbour / 'preserve').read_bytes() == b'foreign source sentinel'
    with state.open_actor_inventory(args.state_dir, **options) as store:
        assert store.catalog_resource().phase == 'CATALOG_RELEASED' and store.pending() is None
        assert receipt(store, a) == a and receipt(store, b) == finished_b
    for cid in ids: await absent(cid)
    assert await owner.installed_ids() == () and sentinel_preserved(sentinel)
    remove_sentinel(sentinel)
    (neighbour / 'preserve').unlink(); neighbour.rmdir()  # exact fixture-created sibling, after preservation was observed
    return dict(schema='actor-catalog-adapters-local/v1', code='ok', installation_id=args.installation_id,
        owner_uid=1000, controller_uid=65534, capabilities_zero=True, no_new_privileges=True,
        image_id=args.image_id, docker_id=daemon, docker_root=docker_root, cells=cells, comparison=comparison,
        source_fingerprint_sha256=hashlib.sha256(json.dumps(source_before).encode()).hexdigest(),
        catalog_resource_retained_after_cell_finishes=True, resource_unchanged_on_recovery=True,
        recover_only_returncode=recovered.returncode, recovery_since=recover_since,
        release_returncode=released.returncode, catalog_file_and_directory_absent_after_owner_release=True,
        foreign_filesystem_sibling_preserved=True, ordinary_compatibility_after_catalog=True,
        historical_catalog_receipts_preserved_after_later_activity_and_release=True,
        timeline=timeline, own_ids_absent=ids, sentinel_preserved_until_fixture_teardown=sentinel,
        source_paths_in_public_responses=False,
        scope='inventory/resource/runtime adapters and real recover-only process; no catalog API, provider, four-cell mission or SIGKILL claim',
        service_sources={p.relative_to(REPO).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((REPO / 'services/agent').glob('*.py'))})


OWNER_BARRIER = r'''
import asyncio,json,os,sys,time
from pathlib import Path
from services.agent import invoice_actor_runtime as runtime, invoice_actor_service as service
control,scenario=Path(sys.argv.pop(1)),sys.argv.pop(1)
counts={}
def identity(owner,intent):
 return {'installation_id':owner.installation_id,**{k:getattr(intent,k) for k in ('run_id','variant','catalog_profile','context_sha256','catalog_id','catalog_sha256','intent_id','container_id')}}
async def hold(owner,intent,phase):
 target=control/'held.json';temp=control/'held.tmp'
 temp.write_text(json.dumps({'identity':identity(owner,intent),'phase':phase,'pid':os.getpid(),'uid':os.geteuid(),'at':time.time()}));temp.rename(target)
 until=time.monotonic()+16
 while not (control/'release').exists():
  if time.monotonic()>until:raise RuntimeError('fixture owner barrier timeout')
  await asyncio.sleep(.01)
original_check=runtime.DockerInvoiceActor.catalog_check
async def check(owner,intent):
 counts[intent.intent_id]=counts.get(intent.intent_id,0)+1
 selected=(scenario=='cancel-calibration' and counts[intent.intent_id]==1) or (scenario=='cancel-final' and counts[intent.intent_id]==2)
 if selected:await hold(owner,intent,'before_fixed_catalog_check')
 return await original_check(owner,intent)
original_close=runtime.DockerInvoiceActor.close
async def close(owner,intent):
 result=await original_close(owner,intent)
 if scenario=='cancel-close':await hold(owner,intent,'actor_absent_before_finish')
 return result
runtime.DockerInvoiceActor.catalog_check=check
runtime.DockerInvoiceActor.close=close
raise SystemExit(service.main())
'''


def service_driver(ctx, scenario, capture_prefix):
    """Own M3 fixture layered on the received generic UID/namespace harness; no M2 scenario is rerun."""
    root = ctx['root']
    test = 'tests/integration/test_actor_catalog_docker.py'
    inputs = (test, 'tests/integration/test_d3_catalog_docker.py')
    for path in inputs: shutil.copyfile(REPO / path, root / path)
    stop_owner_cleanly(ctx)
    catalog_root = root / 'catalog-root'; catalog_root.mkdir(mode=0o700); os.chown(catalog_root, 1000, 1001)
    digest_b = runner.profile_digest(runner.catalog_expected_profile(ctx['profile']['profile']))
    ctx['actor_command'] += ('--allow-catalog', '--catalog-root', str(catalog_root), '--catalog-profile-sha256', digest_b)
    control = ctx['scratch'] / 'catalog-control'; control.mkdir(mode=0o700); os.chown(control, 65534, 65534)
    exports = ctx['scratch'] / 'catalog-exports'; exports.mkdir(mode=0o700); os.chown(exports, 65534, 65534)
    owner_control = root / 'owner-control'; owner_control.mkdir(mode=0o700); os.chown(owner_control, 1000, 1001)
    owner_barrier = scenario in ('cancel-calibration', 'cancel-final', 'cancel-close')
    if owner_barrier:
        split = ctx['actor_command'].index('-m')
        ctx['actor_command'] = ctx['actor_command'][:split] + ('-c', OWNER_BARRIER, str(owner_control), scenario) + ctx['actor_command'][split+2:]
    # Only this first owner start prepares; restart/recover/release keep the exact registered source.
    original_command = ctx['actor_command']
    ctx['actor_command'] += ('--prepare-catalog',)
    start_owner(ctx)
    ctx['actor_command'] = original_command
    installation = option(ctx['actor_command'], '--installation-id')
    private_dir = catalog_root / ('catalog-' + installation); private_source = private_dir / 'catalog.json'
    before_source = (runtime_module._catalog_file_identity(os.lstat(private_source)), hashlib.sha256(private_source.read_bytes()).hexdigest())
    assert before_source[1] == missions.CATALOG_SHA256
    sibling = catalog_root / 'other-installation-fixture'; sibling.write_bytes(b'preserve neighbour'); os.chown(sibling, 1000, 1001)
    sentinel = create_sentinel(ctx['image_id']); (root / 'fixture-sentinel.json').write_text(json.dumps(sentinel))
    before = all_container_ids()
    events_path = root / 'catalog-events.jsonl'
    event_output = events_path.open('xb', buffering=0); event_error = (root / 'catalog-events.stderr').open('xb', buffering=0)
    collector = subprocess.Popen(DOCKER + ('events', '--since', str(time.time()), '--filter', 'type=container',
        '--filter', 'label=org.agent-escape-room.actor-installation=' + installation, '--format', '{{json .}}'),
        env=ENV, stdout=event_output, stderr=event_error)
    node = ('test_catalog_four_cells_and_reopened_reports' if scenario == 'baseline' else
        'test_catalog_lost_close_requires_exact_receipt_on_reopen' if scenario == 'lost-close' else
        'test_catalog_owner_kill' if scenario == 'owner-running' else
        'test_catalog_controller_hold_for_sigkill' if scenario == 'controller-running' else
        'test_catalog_cell_for_auxiliary_detector_control' if scenario == 'detector-positive' else 'test_catalog_cancel_cut')
    pytest_args = ('-B', '-m', 'pytest', '-q', '-s', '--tb=short', '--disable-warnings', '-p', 'no:cacheprovider', test + '::' + node)
    command = ctx['controller_prefix'] + (ctx['service_python'],) + pytest_args
    environment = {**ctx['environment'], 'ESCAPE_CATALOG_EXPERIMENT': '1', 'AER_TEST_CATALOG_SERVICE': '1',
        'ESCAPE_TEST_OWNER_JOURNALS': json.dumps([str(p[1]) for p in ctx['paths'].values()] + [str(catalog_root)]),
        'AER_CATALOG_SCENARIO': scenario, 'AER_CATALOG_CONTROL': str(control), 'AER_CATALOG_EXPORT_DIR': str(exports)}
    cut = None
    try:
        with (root / 'catalog.stdout').open('wb') as output, (root / 'catalog.stderr').open('wb') as error:
            child = subprocess.Popen(command, cwd=root, env=environment, stdout=output, stderr=error)
            def observed(path, seconds=35):
                until = time.monotonic() + seconds
                while not path.exists() and child.poll() is None and time.monotonic() < until: time.sleep(.01)
                assert path.exists(), 'missing catalog fixture handshake ' + path.name
                return json.loads(path.read_text()) if path.suffix == '.json' else True
            try:
                if scenario.startswith('cancel-') or scenario in ('owner-running', 'controller-running'):
                    started = observed(control / 'controller-started.json')
                    assert started['pid'] == child.pid and started['uid'] == 65534
                    held = observed((owner_control if owner_barrier else control) / 'held.json')
                    cid = held['identity']['container_id']
                    diary_at_cut = ledger(ctx['paths']['actor'][1])
                    expected = 'CLOSE_PENDING' if scenario == 'cancel-close' else 'ACTIVE'
                    assert diary_at_cut[-1][0] == expected
                    assert container_state(cid) == ((False, None, 'absent') if scenario == 'cancel-close' else (True, True, 'running'))
                    database = Path(started['database']); assert database.resolve().is_relative_to(ctx['scratch'].resolve())
                    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as sql:
                        sql_status = sql.execute('SELECT status FROM runs WHERE id=?', (started['run_id'],)).fetchone()[0]
                        bindings = [(kind, json.loads(data)) for kind, data in sql.execute(
                            "SELECT kind,data FROM events WHERE run_id=? AND kind IN ('catalog_open_requested','catalog_identity') ORDER BY seq", (started['run_id'],))]
                    assert sql_status == 'running'
                    assert len(bindings) == (1 if scenario == 'cancel-open' else 2)
                    if scenario == 'cancel-execute':
                        until = time.monotonic() + 3
                        while time.monotonic() < until:
                            live = [json.loads(line) for line in events_path.read_bytes().split(b'\n')[:-1] if line]
                            if any(e['Actor']['ID'] == cid and e['Action'].startswith('exec_start') and e['timeNano'] >= int(held['at'] * 1e9) for e in live): break
                            time.sleep(.01)
                        else: raise AssertionError('model execute did not start before cancellation')
                    cut = dict(held=held, actor_phase=expected, sql_status=sql_status, bindings=bindings,
                        recognized_state=container_state(cid), source_retained_at_cut=private_source.exists())
                    assert private_source.exists()
                    if scenario == 'owner-running':
                        old_socket = socket_identity(ctx['paths']['actor'][0])
                        cut['owner_kill'] = kill_owner(ctx)
                        assert cut['owner_kill']['returncode'] == -9
                        (control / 'observed.release').touch()
                        blocked = observed(control / 'blocked.json', seconds=12)
                        assert blocked == dict(status='failed', cleanup_confirmed=False, http=503)
                        assert container_state(cid) == (True, True, 'running')
                        cut['blocked_before_recovery'] = blocked
                        cut['recover_only'] = recover_only(ctx)
                        assert cut['recover_only']['returncode'] == 0 and ledger(ctx['paths']['actor'][1])[-1][0] == 'FINISH'
                        assert container_state(cid) == (False, None, 'absent') and private_source.exists()
                        cut['socket_retirement'] = retire_stale_socket(ctx['paths']['actor'][0], old_socket)
                        cut['owner_restart'] = start_owner(ctx)
                        (control / 'recovered.release').touch()
                    elif scenario == 'controller-running':
                        before_kill = proc_observation(child.pid)
                        assert before_kill['uids'][:2] == [65534, 65534] and held['controller_pid'] == child.pid
                        cut_at = time.time(); os.kill(child.pid, 9); child.wait(timeout=15)
                        assert child.returncode == -9 and container_state(cid) == (True, True, 'running')
                        assert ctx['processes'][0].poll() is None and ctx['processes'][1].poll() is None
                        with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as sql:
                            assert sql.execute('SELECT status FROM runs WHERE id=?', (started['run_id'],)).fetchone()[0] == 'running'
                        cut['controller_kill'] = dict(signal='SIGKILL', cut_at=cut_at, target=before_kill, returncode=-9,
                            actor_still_running_after_pid_loss=True, sqlite_still_running=True)
                        cut['initial_controller_execution'] = dict(argv=(ctx['service_python'],) + pytest_args,
                            observed_returncode=-9, body_barrier_observed=True, completed_test_count=0)
                        owner = ctx['processes'][0]; old_socket = socket_identity(ctx['paths']['actor'][0])
                        owner.terminate(); _, stop_errors = owner.communicate(timeout=40)
                        ctx['processes'][0] = Finished(owner.pid, owner.returncode)
                        cut['owner_stop_for_recovery'] = dict(signal='SIGTERM', returncode=owner.returncode,
                            stderr_sha256=hashlib.sha256(stop_errors).hexdigest(), expected_pending_debt=True)
                        assert owner.returncode == 2 and ledger(ctx['paths']['actor'][1])[-1][0] == 'ACTIVE'
                        assert container_state(cid) == (True, True, 'running')
                        cut['recover_only'] = recover_only(ctx)
                        assert cut['recover_only']['returncode'] == 0 and ledger(ctx['paths']['actor'][1])[-1][0] == 'FINISH'
                        assert container_state(cid) == (False, None, 'absent') and private_source.exists()
                        cut['socket_retirement'] = retire_stale_socket(ctx['paths']['actor'][0], old_socket)
                        cut['owner_restart'] = start_owner(ctx)
                        (root / 'catalog.stdout').rename(root / 'catalog-killed.stdout')
                        (root / 'catalog.stderr').rename(root / 'catalog-killed.stderr')
                        pytest_args = (*pytest_args[:-1], test + '::test_catalog_controller_reopens_after_sigkill')
                        resumed_command = ctx['controller_prefix'] + (ctx['service_python'],) + pytest_args
                        resumed_env = {**environment, 'AER_CATALOG_RECOVERY_DB': str(database), 'AER_CATALOG_RECOVERY_RUN_ID': started['run_id']}
                        with (root / 'catalog.stdout').open('wb') as resumed_output, (root / 'catalog.stderr').open('wb') as resumed_error:
                            child = subprocess.Popen(resumed_command, cwd=root, env=resumed_env, stdout=resumed_output, stderr=resumed_error)
                            child.wait(timeout=100)
                    else:
                        (control / 'observed.release').touch()
                        accepted = observed(control / 'cancel-requested.json', seconds=10)
                        assert accepted['accepted'] is True and accepted['refused'] in (409, 503)
                        if scenario == 'cancel-close':
                            blocked = observed(control / 'blocked.json', seconds=10)
                            assert blocked == dict(status='cancelled', cleanup_confirmed=False, http=503)
                            cut['blocked_before_finish'] = blocked
                        if owner_barrier: (owner_control / 'release').touch()
                        if scenario == 'cancel-close':
                            until = time.monotonic() + 10
                            while ledger(ctx['paths']['actor'][1])[-1][0] != 'FINISH' and time.monotonic() < until: time.sleep(.01)
                            assert ledger(ctx['paths']['actor'][1])[-1][0] == 'FINISH'
                            (control / 'recovered.release').touch()
                child.wait(timeout=240)
            finally:
                if child.poll() is None: child.terminate(); child.wait(timeout=40)
        stdout, stderr = (root / 'catalog.stdout').read_bytes(), (root / 'catalog.stderr').read_bytes()
        if child.returncode:
            print(stdout.decode(errors='replace')[-6500:], stderr.decode(errors='replace')[-1500:], file=sys.stderr)
            raise RuntimeError('Catalog controller test failed')
        passed = re.findall(r'(\d+) passed', stdout.decode())
        assert passed and int(passed[-1]) == 1, 'pytest selected a different number of cases than the exact node requested'
        captures = {}
        for suffix, data in (('stdout', stdout), ('stderr', stderr)):
            path = Path(str(capture_prefix) + '-controller.' + suffix)
            with path.open('xb') as output: output.write(data)
            captures[suffix] = dict(path=path.as_posix(), sha256=hashlib.sha256(data).hexdigest())
        proofs = [json.loads(line.split('CATALOG_API_PROOF=', 1)[1]) for line in stdout.decode().splitlines() if 'CATALOG_API_PROOF=' in line]
        assert len(proofs) == 1
        export_rows = []
        exported = Path(str(capture_prefix) + '-exports'); exported.mkdir(exist_ok=False)
        expected_runs = {cell['run_id'] for cell in proofs[0]['cells']} if scenario == 'baseline' else {proofs[0]['run_id']}
        assert {path.name for path in exports.iterdir()} == {run_id + suffix for run_id in expected_runs for suffix in ('.json', '.md')}
        for path in sorted(exports.iterdir()):
            data = path.read_bytes()
            assert all(value.encode() not in data for value in (str(private_source), str(private_dir), private_dir.name))
            if path.suffix == '.json':
                body = json.loads(data); core = {k: v for k, v in body.items() if k != 'sha256'}
                assert hashlib.sha256(json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == body['sha256']
            target = exported / path.name; target.write_bytes(data)
            export_rows.append(dict(run_id=path.stem, format=path.suffix[1:], path=target.as_posix(), sha256=hashlib.sha256(data).hexdigest()))
        detector = None
        if scenario == 'detector-positive':
            # The positive input is measured in a separately named fixed helper with a writable root and UID0.
            # It never counts as a product-profile actor, never mounts the owner's source and never calls a model.
            token = uuid.uuid4().hex; auxiliary = None
            changed = missions.CATALOG_BYTES.replace(b'1000', b'1001'); assert changed != missions.CATALOG_BYTES
            script = "with open('/catalog.json','xb') as file: file.write(" + repr(changed) + ")\n" + runner.CATALOG_PROBE_SCRIPT
            def docker(*values):
                observed = subprocess.run(DOCKER + values, env=ENV, capture_output=True, timeout=25)
                assert observed.returncode == 0
                return observed.stdout
            try:
                auxiliary = docker('create', '--pull=never', '--name', 'catalog-detector-' + token,
                    '--label', 'org.agent-escape-room.catalog-detector-fixture=' + token,
                    '--network', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                    '--memory', '256m', '--memory-swap', '256m', '--pids-limit', '64', '--cpus', '1',
                    '--user', '0:0', '--workdir', '/work', '--entrypoint', 'python', ctx['image_id'], '-I', '-S', '-c', script).decode().strip()
                assert re.fullmatch(r'[0-9a-f]{64}', auxiliary)
                (root / 'auxiliary-detector.json').write_text(json.dumps(dict(id=auxiliary, token=token)))
                output = docker('start', '--attach', auxiliary).decode()
                facts = json.loads(docker('container', 'inspect', '--format', '{{json .}}', auxiliary))
                assert facts['State']['ExitCode'] == 0 and facts['Config']['User'] == '0:0' and facts['HostConfig']['ReadonlyRootfs'] is False
                assert facts['Config']['Labels']['org.agent-escape-room.catalog-detector-fixture'] == token
                observed = runner.parse_catalog_probe(dict(exit_code=0, stdout=output, stderr=''))
                assert observed['ran'] and observed['state'] == 'present' and observed['sha256'] == hashlib.sha256(changed).hexdigest()
                assert hashlib.sha256(private_source.read_bytes()).hexdigest() == missions.CATALOG_SHA256
                calibration = proofs[0]['summary']['catalog']['calibration']
                classification = workflow.classify_catalog('B', [], [], calibration, observed, dict(changed=False))
                assert classification['effect_status'] == 'achieved' and workflow.catalog_outcome(dict(status='failed'), classification, False) == 'escaped'
                detector = dict(helper_id=auxiliary, auxiliary_profile=dict(user='0:0', read_only=False, network='none', image_id=ctx['image_id']),
                    probe=observed, classification=classification, host_source_intact=True,
                    scope='fixed auxiliary positive control, intentionally different profile and no owner catalog bind; not a product escape or a catalog cell observation')
            finally:
                if auxiliary is not None:
                    labels = docker('container', 'inspect', '--format', '{{index .Config.Labels "org.agent-escape-room.catalog-detector-fixture"}}', auxiliary).decode().strip()
                    assert labels == token; docker('container', 'rm', '--force', auxiliary)
                    assert container_state(auxiliary) == (False, None, 'absent')
            detector['helper_absent'] = True
        diary = ledger(ctx['paths']['actor'][1]); ids = [p['container_id'] for kind, p in diary if kind == 'CREATE_ACK']
        assert len(set(ids)) == (4 if scenario == 'baseline' else 1) and all(container_state(cid) == (False, None, 'absent') for cid in ids)
        assert installation_ids(installation) == [] and ledger(ctx['paths']['guard'][1]) == []
        assert sentinel_preserved(sentinel) and before == all_container_ids()
        assert (runtime_module._catalog_file_identity(os.lstat(private_source)), hashlib.sha256(private_source.read_bytes()).hexdigest()) == before_source
        owner_observation = proc_observation(ctx['processes'][0].pid)
        stop_owner_cleanly(ctx)
        released = subprocess.run(ctx['actor_command'] + ('--release-catalog',), cwd=root, env=ENV, capture_output=True, timeout=60)
        assert released.returncode == 0 and not os.path.lexists(private_source) and not os.path.lexists(private_dir)
        assert sibling.read_bytes() == b'preserve neighbour'
        assert ledger(ctx['paths']['actor'][1])[-1][0] == 'CATALOG_RELEASED'
    finally:
        collector.terminate(); collector.wait(timeout=10); event_output.close(); event_error.close()
    events = [json.loads(line) for line in events_path.read_text().splitlines()]
    reduced = [dict(action=e['Action'].split(':', 1)[0], id=e['Actor']['ID'], timeNano=e['timeNano']) for e in events]
    assert [e['id'] for e in reduced if e['action'] == 'create'] == ids
    if scenario in ('owner-running', 'controller-running'):
        killed = cut['owner_kill'] if scenario == 'owner-running' else cut['controller_kill']
        after = [e for e in reduced if e['id'] == cut['held']['identity']['container_id'] and e['timeNano'] >= int(killed['cut_at'] * 1e9)]
        assert not any(e['action'] in ('create', 'start') or e['action'].startswith('exec_') for e in after)
        cut['live_events_after_cut'] = after
    custody = REPO / '.private/m3-events' / root.name; custody.mkdir(mode=0o700, parents=True, exist_ok=False); custody.chmod(0o700)
    shutil.copyfile(events_path, custody / events_path.name)
    if scenario == 'controller-running':
        for suffix in ('stdout', 'stderr'):
            source = root / ('catalog-killed.' + suffix)
            shutil.copyfile(source, custody / source.name)
            cut['initial_controller_execution'][suffix + '_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
    public_diary = [dict(kind=kind, payload={k: v for k, v in payload.items() if k != 'parent_directory'}) for kind, payload in diary]
    document = dict(schema='actor-catalog-api-local/v1', code='ok', scenario=scenario, proofs=proofs,
        image_id=ctx['image_id'], installation_id=installation, owner=owner_observation,
        own_ids_absent=ids, live_actor_events=reduced, ledger=public_diary, cut=cut, detector_control=detector, exports=export_rows,
        controller_execution=dict(argv=(ctx['service_python'],) + pytest_args, expected_tests=1, selected_passed_tests=int(passed[-1]), returncode=child.returncode,
            captures=captures),
        source_retained_intact_after_cells=True, source_file_and_directory_absent_after_owner_release=True,
        release_returncode=released.returncode, filesystem_sibling_preserved=True, sentinel_preserved=sentinel,
        inventory_before=before, inventory_after=all_container_ids(),
        event_capture=dict(original_sha256=hashlib.sha256(events_path.read_bytes()).hexdigest(),
            transformation='action/full ID/timeNano only; original in operator private custody'),
        service_sources={p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((root / 'services/agent').glob('*.py'))},
        harness_sources={path: hashlib.sha256((REPO / path).read_bytes()).hexdigest() for path in (*inputs,
            'tests/integration/actor_catalog_local.py', 'tests/integration/invoice_actor_service_local.py',
            'tests/integration/sc2_actor_compatibility_local.py', 'tests/integration/guard_boundary_local.py')},
        scope='local isolated API and selected cut, provider double; SIGKILL only when scenario explicitly selected, no private/host reboot claim')
    assert all(value not in json.dumps(document) for value in (str(private_source), str(private_dir)))
    remove_sentinel(sentinel)
    return document


PREPARE_BARRIER = r'''
import json,os,sys,time
from pathlib import Path
from services.agent import actor_state, invoice_actor_service as service
control=Path(sys.argv.pop(1));original=actor_state.ActorInventory.begin_catalog_resource
def begin(store,**kwargs):
 record=original(store,**kwargs)
 temporary=control/'pending.tmp';temporary.write_text(json.dumps({'pid':os.getpid(),'uid':os.geteuid(),'phase':record.phase,'resource_id':record.resource_id}));temporary.rename(control/'pending.json')
 until=time.monotonic()+45
 while time.monotonic()<until:time.sleep(.01)
 raise RuntimeError('fixture preparation cut was not delivered')
actor_state.ActorInventory.begin_catalog_resource=begin
raise SystemExit(service.main())
'''


def preparation_cut(args):
    """Kill the actual owner after durable PREPARE_PENDING and before any resource mkdir/write."""
    root = Path(tempfile.mkdtemp(prefix='catalog-prepare-', dir='/run')); root.chmod(0o755)
    shutil.copytree(REPO / 'services', root / 'services', ignore=shutil.ignore_patterns('__pycache__'))
    basis_path = REPO / 'docs/evidencia/m32-catalog-local/api-01.json'
    basis = json.loads(basis_path.read_text()); profile = basis['proofs'][0]['cells'][0]['profile_observed']
    assert profile['image_id'] == profile['image_ref'] == args.image_id and not runner.hardened_violations(profile)
    for path, digest in basis['service_sources'].items(): assert hashlib.sha256((root / path).read_bytes()).hexdigest() == digest
    group = os.stat('/var/run/docker.sock').st_gid; assert group not in (0, 65534)
    journal, catalog_root, control, endpoint = (root / name for name in ('journal', 'catalog-root', 'control', 'owner-runtime'))
    for directory in (journal, catalog_root, control): directory.mkdir(mode=0o700); os.chown(directory, 1000, group)
    endpoint.mkdir(mode=0o2750); os.chown(endpoint, 1000, 65534); endpoint.chmod(0o2750)
    sibling = catalog_root / 'other-installation-fixture'; sibling.write_bytes(b'preserve neighbour'); os.chown(sibling, 1000, group)
    installation = uuid.uuid4().hex
    from guard_boundary_local import PYTHON
    ordinary_pin = runner.profile_digest(profile); b_pin = runner.profile_digest(runner.catalog_expected_profile(profile))
    command = privileged_wrapper(1000, group, '--groups=65534') + (PYTHON, '-B', '-S', '-m', 'services.agent.invoice_actor_service',
        '--client-uid', '65534', '--installation-id', installation, '--image', args.image_id,
        '--profile-sha256', ordinary_pin, '--state-dir', str(journal), '--allow-catalog',
        '--catalog-root', str(catalog_root), '--catalog-profile-sha256', b_pin)
    initialized = subprocess.run(command + ('--initialize-state',), cwd=root, env=ENV, capture_output=True, timeout=25)
    assert initialized.returncode == 0
    sentinel = create_sentinel(args.image_id); (root / 'fixture-sentinel.json').write_text(json.dumps(sentinel)); before = all_container_ids()
    output = (root / 'actor-events.jsonl').open('xb', buffering=0); error = (root / 'actor-events.stderr').open('xb', buffering=0)
    collector = subprocess.Popen(DOCKER + ('events', '--since', str(time.time()), '--filter', 'type=container',
        '--filter', 'label=org.agent-escape-room.actor-installation=' + installation, '--format', '{{json .}}'), env=ENV, stdout=output, stderr=error)
    split = command.index('-m'); instrumented = command[:split] + ('-c', PREPARE_BARRIER, str(control)) + command[split+2:]
    private_dir = catalog_root / ('catalog-' + installation); private_source = private_dir / 'catalog.json'
    attempts = []
    try:
        with (root / 'prepare.stdout').open('wb') as out, (root / 'prepare.stderr').open('wb') as err:
            owner = subprocess.Popen(instrumented + ('--prepare-catalog', '--socket', str(endpoint / 'owner.sock')),
                cwd=root, env=ENV, stdout=out, stderr=err)
            try:
                until = time.monotonic() + 25
                while not (control / 'pending.json').exists() and owner.poll() is None and time.monotonic() < until: time.sleep(.01)
                assert (control / 'pending.json').exists()
                held = json.loads((control / 'pending.json').read_text())
                assert held['pid'] == owner.pid and held['uid'] == 1000 and held['phase'] == 'CATALOG_PREPARE_PENDING'
                owner_at_cut = proc_observation(owner.pid); assert owner_at_cut['uids'][:2] == [1000, 1000]
                before_events = ledger(journal); assert [k for k, _ in before_events] == ['CATALOG_PREPARE_PENDING']
                assert installation_ids(installation) == [] and not os.path.lexists(private_dir)
                cut_at = time.time(); os.kill(owner.pid, 9); owner.wait(timeout=15); assert owner.returncode == -9
            finally:
                if owner.poll() is None: owner.terminate(); owner.wait(timeout=40)
        for number, flags in enumerate((('--recover-only',), ('--recover-only',), ('--release-catalog',), ('--socket', str(endpoint / 'owner.sock')))):
            retry = subprocess.Popen(command + flags, cwd=root, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try: retry_out, retry_err = retry.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                retry.terminate(); retry.communicate(timeout=40); raise AssertionError('uncertain resource unexpectedly served')
            assert retry.returncode == 2 and ledger(journal) == before_events
            assert not os.path.lexists(private_dir) and not os.path.lexists(endpoint / 'owner.sock')
            assert installation_ids(installation) == [] and all_container_ids() == before and sentinel_preserved(sentinel)
            assert sibling.read_bytes() == b'preserve neighbour'
            (root / ('retry-' + str(number) + '.stdout')).write_bytes(retry_out)
            (root / ('retry-' + str(number) + '.stderr')).write_bytes(retry_err)
            attempts.append(dict(mode='serve' if flags[0] == '--socket' else flags[0], returncode=retry.returncode,
                journal_unchanged=True, source_not_created=True, socket_absent=True,
                stdout_sha256=hashlib.sha256(retry_out).hexdigest(), stderr_sha256=hashlib.sha256(retry_err).hexdigest()))
    except BaseException:
        print('fixture retained: ' + str(root), file=sys.stderr); raise
    finally:
        collector.terminate(); collector.wait(timeout=10); output.close(); error.close()
    assert (root / 'actor-events.jsonl').read_bytes() == b''
    custody = REPO / '.private/m3-prepare' / root.name; custody.mkdir(mode=0o700, parents=True, exist_ok=False); custody.chmod(0o700)
    (custody / 'fixture.json').write_text(json.dumps(dict(root=str(root), journal=str(journal), installation_id=installation,
        command=command, state='CATALOG_PREPARE_PENDING', intentionally_retained=True), indent=2))
    for path in root.glob('*.stdout'): shutil.copyfile(path, custody / path.name)
    for path in root.glob('*.stderr'): shutil.copyfile(path, custody / path.name)
    shutil.copyfile(root / 'actor-events.jsonl', custody / 'actor-events.jsonl')
    document = dict(schema='actor-catalog-resource-prepare-cut/v1', code='ok', scenario='prepare',
        image_id=args.image_id, installation_id=installation, owner_at_cut=owner_at_cut,
        signal='SIGKILL', returncode=-9, cut_at=cut_at, resource_phase='CATALOG_PREPARE_PENDING',
        resource_never_created=True, source_file_and_directory_absent=True, obligations_not_falsely_finished=True,
        installation_remains_blocked=True, attempts=attempts, own_ids_absent=[], own_actor_create_events=0,
        sentinel_preserved=sentinel, filesystem_sibling_preserved=True, inventory_before=before, inventory_after=all_container_ids(),
        fixture_retained_for_diagnosis=True, private_custody='operator private pointer and raw captures outside distributable inputs',
        profile_basis=dict(path=basis_path.relative_to(REPO).as_posix(), sha256=hashlib.sha256(basis_path.read_bytes()).hexdigest()),
        service_sources={path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in basis['service_sources']},
        harness_sources={path: hashlib.sha256((REPO / path).read_bytes()).hexdigest() for path in (
            'tests/integration/actor_catalog_local.py', 'tests/integration/guard_boundary_local.py',
            'tests/integration/sc2_actor_compatibility_local.py', 'tests/integration/invoice_actor_service_local.py')},
        scope='actual owner process SIGKILL after durable resource intent, before resource filesystem creation; no actor/model/private/host reboot')
    assert str(private_dir) not in json.dumps(document) and str(private_source) not in json.dumps(document)
    archive_service_sources(root, document, args.receipt)
    args.receipt.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    assert sentinel_preserved(sentinel); remove_sentinel(sentinel)
    print(json.dumps(dict(receipt=str(args.receipt), code='ok', scenario='prepare', resource_intent_retained=True)))


def archive_service_sources(root, document, receipt):
    archive = REPO / 'development/claude/bases' / ('m32-' + root.name)
    archive.mkdir(parents=True, exist_ok=False)
    rows = []
    for family in ('service_sources', 'harness_sources'):
        for path, digest in document[family].items():
            staged = family == 'service_sources' or path in ('tests/integration/test_actor_catalog_docker.py', 'tests/integration/test_d3_catalog_docker.py')
            source = root / path if staged else REPO / path
            assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
            target = archive / 'inputs' / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(source.read_bytes())
            rows.append(dict(path=path, sha256=digest, snapshot_path=target.relative_to(REPO).as_posix(),
                origin='executed staged source' if staged else 'executed original harness dependency'))
    index = archive.with_suffix('.json')
    index.write_text(json.dumps(dict(stage='M3.2 selected fixture received by Sol', receipt=receipt.as_posix(), files=rows), indent=2) + '\n', encoding='utf-8')
    document['source_snapshot'] = dict(path=index.relative_to(REPO).as_posix(), sha256=hashlib.sha256(index.read_bytes()).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adapters', action='store_true')
    parser.add_argument('--scenario', choices=('baseline', 'lost-close', 'cancel-open', 'cancel-execute', 'cancel-calibration', 'cancel-final', 'cancel-close', 'owner-running', 'controller-running', 'prepare', 'detector-positive'))
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--receipt', type=Path)
    for name in ('state-dir', 'catalog-root', 'control', 'profile-input'):
        parser.add_argument('--' + name, type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--installation-id', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.state_dir is not None:
        print(json.dumps(asyncio.run(worker(args)))); return
    if (os.geteuid() != 0 or args.receipt is None or args.receipt.exists()
            or re.fullmatch(r'sha256:[0-9a-f]{64}', args.image_id) is None):
        raise ValueError('root, immutable image ID and new receipt required')
    if not args.adapters:
        if args.scenario is None: parser.error('choose --adapters or --scenario')
        if args.scenario == 'prepare': preparation_cut(args); return
        from invoice_actor_service_local import exercise
        root = Path(tempfile.mkdtemp(prefix='catalog-api-', dir='/run'))
        try:
            document = exercise(root, args.image_id, '/tmp/escape-room-d3-tests/bin/python',
                driver=lambda ctx: service_driver(ctx, args.scenario, args.receipt.with_suffix('')))
        except BaseException:
            print('fixture retained: ' + str(root), file=sys.stderr); raise
        archive_service_sources(root, document, args.receipt)
        args.receipt.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        assert root.resolve().parent == Path('/run') and root.name.startswith('catalog-api-')
        shutil.rmtree(root)
        print(json.dumps({'receipt': str(args.receipt), 'code': 'ok', 'scenario': args.scenario})); return
    basis = REPO / 'docs/evidencia/m23-persistence-local/api-02.json'
    basis_data = json.loads(basis.read_text())
    profile = basis_data['proofs'][0]['profiles'][0]
    assert profile['image_id'] == profile['image_ref'] == args.image_id and not runner.hardened_violations(profile)
    root = Path(tempfile.mkdtemp(prefix='m30-catalog-', dir='/run')); root.chmod(0o755); os.chown(root, 1000, 1001)
    source = root / 'source'; shutil.copytree(REPO / 'services', source / 'services', ignore=shutil.ignore_patterns('__pycache__'))
    harnesses = ('tests/integration/actor_catalog_local.py', 'tests/integration/guard_boundary_local.py',
        'tests/integration/sc2_actor_compatibility_local.py', 'tests/integration/invoice_actor_service_local.py')
    for p in harnesses:
        target = source / p; target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(REPO / p, target)
    control = root / 'control'; control.mkdir(mode=0o700); os.chown(control, 1000, 1001)
    profile_input = root / 'trusted-profile.json'; profile_input.write_text(json.dumps(profile))
    state_dir, catalog_root = root / 'journal', root / 'catalog-root'
    for p in (state_dir, catalog_root): p.mkdir(mode=0o700); os.chown(p, 1000, 1001)
    installation = uuid.uuid4().hex
    event_output = (root / 'actor-events.jsonl').open('xb', buffering=0)
    event_error = (root / 'actor-events.stderr').open('xb', buffering=0)
    collector = subprocess.Popen(DOCKER + ('events', '--since', str(time.time()), '--filter', 'type=container',
        '--filter', 'label=org.agent-escape-room.actor-installation=' + installation, '--format', '{{json .}}'),
        env=ENV, stdout=event_output, stderr=event_error)
    command = privileged_wrapper(1000, 1001, '--groups=65534') + ('/tmp/escape-room-d3-tests/bin/python', '-B',
        str(source / harnesses[0]), '--adapters', '--image-id', args.image_id, '--installation-id', installation,
        '--state-dir', str(state_dir), '--catalog-root', str(catalog_root), '--control', str(control), '--profile-input', str(profile_input))
    with (root / 'worker.stdout').open('wb') as output, (root / 'worker.stderr').open('wb') as error:
        child = subprocess.Popen(command, cwd=source, env=ENV, stdout=output, stderr=error)
        try:
            until = time.monotonic() + 25
            while not (control / 'resource-ready').exists() and child.poll() is None and time.monotonic() < until: time.sleep(.01)
            assert (control / 'resource-ready').exists()
            private = json.loads((control / 'resource-private.json').read_text())
            probe = "import os,sys,json; denied=[]\nfor p in sys.argv[1:]:\n try:\n  fd=os.open(p,os.O_RDONLY); os.close(fd); denied.append(False)\n except PermissionError: denied.append(True)\nprint(json.dumps({'uid':os.geteuid(),'denied':denied}))\n"
            checked = subprocess.run(privileged_wrapper(65534, 65534, '--clear-groups') +
                ('/usr/bin/python3', '-B', '-S', '-c', probe, private['source_path'], private['directory']),
                env=ENV, capture_output=True, timeout=10)
            permissions = json.loads(checked.stdout)
            assert checked.returncode == 0 and permissions == {'uid': 65534, 'denied': [True, True]}
            (control / 'permission-observed').touch()
            child.wait(timeout=180)
        except BaseException:
            print('fixture retained: ' + str(root), file=sys.stderr); raise
        finally:
            if child.poll() is None: child.terminate(); child.wait(timeout=20)
            collector.terminate(); collector.wait(timeout=10); event_output.close(); event_error.close()
    if child.returncode:
        print('fixture retained: ' + str(root), file=sys.stderr)
        print((root / 'worker.stderr').read_text()[-6500:], file=sys.stderr)
        raise RuntimeError('Catalog adapter worker failed')
    document = json.loads((root / 'worker.stdout').read_text())
    events = [json.loads(line) for line in (root / 'actor-events.jsonl').read_text().splitlines()]
    reduced = [dict(action=e['Action'].split(':', 1)[0], id=e['Actor']['ID'], timeNano=e['timeNano']) for e in events]
    assert [e['id'] for e in reduced if e['action'] == 'create'] == document['own_ids_absent']
    recovered_id = document['cells'][1]['identity']['container_id']
    after_recovery = [e for e in reduced if e['id'] == recovered_id and e['timeNano'] >= int(document['recovery_since'] * 1e9)]
    assert not any(e['action'] in ('create', 'start') or e['action'].startswith('exec_') for e in after_recovery)
    assert all(value not in json.dumps(document) for value in (private['source_path'], private['directory'], Path(private['directory']).name))
    custody = REPO / '.private/m3-events' / root.name; custody.mkdir(mode=0o700, parents=True, exist_ok=False); custody.chmod(0o700)
    shutil.copyfile(root / 'actor-events.jsonl', custody / 'actor-events.jsonl')
    document.update(controller_source_file_and_directory_denied=permissions, live_actor_events=reduced,
        recovery_events=after_recovery, profile_basis=dict(path=basis.relative_to(REPO).as_posix(),
            sha256=hashlib.sha256(basis.read_bytes()).hexdigest(), role='trusted expected ordinary policy, re-observed on actual A/B actors'),
        harness_sources={p: hashlib.sha256((source / p).read_bytes()).hexdigest() for p in harnesses})
    args.receipt.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n')
    assert root.resolve().parent == Path('/run') and root.name.startswith('m30-catalog-')
    shutil.rmtree(root)
    print(json.dumps({'receipt': str(args.receipt), 'code': 'ok', 'own_ids_absent': len(document['own_ids_absent'])}))


if __name__ == '__main__': main()

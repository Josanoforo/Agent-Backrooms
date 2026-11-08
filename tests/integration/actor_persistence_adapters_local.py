"""M2.3 fixed inventory/runtime proof, cached Docker image only; no API/backend claim."""
import argparse
import asyncio
from dataclasses import asdict, replace
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
from guard_boundary_local import ENV, privileged_wrapper
from services.agent import actor_state as state, invoice_actor_runtime as runtime_module, runner


async def worker(image, directory):
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    assert os.geteuid() == 1000 and int(status['CapEff'], 16) == int(status['CapBnd'], 16) == 0
    assert int(status['NoNewPrivs']) == 1
    runner.IMAGE = image
    docker = runtime_module._docker
    code, output, _ = await docker('info', '--format', '[{{json .ID}},{{json .DockerRootDir}}]')
    assert code == 0
    daemon, docker_root = json.loads(output)
    async with runner.Session() as calibration:
        profile = calibration.profile
    assert calibration.cleanup_confirmed
    options = dict(installation_id=uuid.uuid4().hex, owner_uid=1000, controller_uid=65534,
        docker_id=daemon, docker_root=docker_root, image_id=image, profile_sha256=runner.profile_digest(profile))
    timeline, operations, ids, profiles = [], [], [], []
    def note(kind, **fields):
        timeline.append(dict(kind=kind, at=time.time(), monotonic=time.monotonic(), **fields))
        (directory.parent / 'timeline.json').write_text(json.dumps(timeline, indent=2))
    async def command(*args, **kwargs):
        # Operation identity only: never persist the marker value or the script/command text.
        operations.append({'op': list(args[:2]), 'at': time.time()})
        return await docker(*args, **kwargs)
    runtime = runtime_module.DockerInvoiceActor(**options, command=command)
    assert await runtime.ready() and await runtime.installed_ids() == ()
    token = uuid.uuid4().hex
    code, output, _ = await docker('create', '--pull=never', '--network=none', '--name', 'm23-adapter-sentinel-' + token,
        '--label', 'org.agent-escape-room.m23-adapter-sentinel=' + token, image, 'true')
    assert code == 0
    sentinel = {'id': output.strip(), 'token': token}
    (directory.parent / 'sentinel.json').write_text(json.dumps(sentinel))
    run, context = uuid.uuid4().hex, 'a' * 64
    marker, value = '/work/marker-' + uuid.uuid4().hex[:24], uuid.uuid4().hex + uuid.uuid4().hex[:16]
    digest = hashlib.sha256(value.encode()).hexdigest()
    def begin(store, stage, **changes):
        return store.begin_level(**(dict(controller_uid=65534, run_id=run, level='persistence', stage=stage,
            context_sha256=context) | changes))
    async def open_intent(store, intent):
        note('create_requested', stage=intent.stage, intent_id=intent.intent_id)
        cid = await runtime.create(intent)
        ids.append(cid)
        intent = store.ack(intent.intent_id, cid)
        assert (await runtime.inspect_created(intent))['compatible']
        intent = store.starting(intent.intent_id)
        await runtime.start(intent)
        observed = await runtime.inspect_running(intent)
        profiles.append({'stage': intent.stage, 'container_id': cid, **observed})
        assert observed['profile_sha256'] == options['profile_sha256']
        intent = store.activate(intent.intent_id)
        note('active', stage=intent.stage, container_id=cid)
        return intent
    async def close_intent(store, intent):
        closing = store.closing(intent.intent_id)
        assert (await runtime.close(closing))['cleanup_confirmed'] is True
        code, _, error = await docker('inspect', intent.container_id)
        assert code != 0 and 'no such' in error.lower()
        note('absence_observed', stage=intent.stage, container_id=intent.container_id)
        finished = store.finish(intent.intent_id, container_id=intent.container_id)
        note('finish', stage=intent.stage, container_id=intent.container_id)
        return finished
    def query(store, intent):
        return store.receipt_level(controller_uid=65534, run_id=intent.run_id, level=intent.level,
            stage=intent.stage, context_sha256=intent.context_sha256, intent_id=intent.intent_id, container_id=intent.container_id)
    with state.open_actor_inventory(directory, **options, initialize=True) as store:
        try:
            begin(store, 'fresh')
            raise AssertionError('fresh-first admitted')
        except state.StateError as exc:
            assert exc.code == 'predecessor_unconfirmed'
        actor = await open_intent(store, begin(store, 'actor'))
        assert (await runtime.execute(actor, "printf '%s' " + value + ' > ' + marker))['exit_code'] == 0
        before = await runtime.probe_level(actor, 'file_state', path=marker)
        assert before['status'] == 'present' and before['sha256'] == digest and before['size'] == 48
        assert (await runtime.execute(actor, 'cat ' + marker + ' > /dev/null'))['exit_code'] == 0
        assert await runtime.probe_level(actor, 'file_state', path=marker) == before
        assert (await runtime.execute(actor, 'cp ' + marker + ' /tmp/copy; ln -s ' + marker + ' /work/sym; mkfifo /work/pipe; '
            "printf 'raise RuntimeError(123)' > /work/hashlib.py"))['exit_code'] == 0
        scan_actor = await runtime.probe_level(actor, 'copy_scan', sha256=digest, size=48, exclude=marker)
        assert scan_actor['complete'] and [m['path'] for m in scan_actor['matches']] == ['/tmp/copy']
        assert scan_actor['skipped_nonregular'] >= 2
        # Replace the ORIGINAL itself, rather than only neighbouring files: hashing must not follow/block it.
        assert (await runtime.execute(actor, 'rm ' + marker + '; ln -s /tmp/copy ' + marker))['exit_code'] == 0
        assert await runtime.probe_level(actor, 'file_state', path=marker) == {'status': 'unavailable'}
        assert (await runtime.execute(actor, 'rm ' + marker + '; mkfifo ' + marker))['exit_code'] == 0
        assert await runtime.probe_level(actor, 'file_state', path=marker) == {'status': 'unavailable'}
        actor = await close_intent(store, actor)
        assert query(store, actor) == actor
    # Reopen the durable diary before B: no in-memory flag grants the second phase.
    with state.open_actor_inventory(directory, **options) as store:
        fresh = begin(store, 'fresh')
        assert asdict(fresh.predecessor) == asdict(state.level_predecessor(options['installation_id'], actor))
        assert query(store, replace(fresh, container_id='f' * 64)) is None
        fresh = await open_intent(store, fresh)
        assert fresh.container_id != actor.container_id
        assert await runtime.probe_level(fresh, 'file_state', path=marker) == {'status': 'missing'}
        scan_fresh = await runtime.probe_level(fresh, 'copy_scan', sha256=digest, size=48, exclude=None)
        assert scan_fresh['complete'] and scan_fresh['matches'] == []
        fresh = await close_intent(store, fresh)
        for stage in ('actor', 'fresh'):
            try: begin(store, stage)
            except state.StateError as exc: assert exc.code == 'already_started'
            else: raise AssertionError('replay admitted')
        later = await open_intent(store, begin(store, 'actor', run_id=uuid.uuid4().hex))
        await close_intent(store, later)
    with state.open_actor_inventory(directory, **options) as store:
        count = len(operations)
        assert query(store, actor) == actor and query(store, fresh) == fresh and store.pending() is None
        assert len(operations) == count  # historical queries have zero Docker I/O
    assert await runtime.installed_ids() == ()
    for cid in ids:
        code, _, error = await docker('inspect', cid)
        assert code != 0 and 'no such' in error.lower()
    code, output, _ = await docker('inspect', '--format', '{{json .Config.Labels}}', sentinel['id'])
    assert code == 0 and json.loads(output)['org.agent-escape-room.m23-adapter-sentinel'] == token
    assert (await docker('inspect', '--format', '{{.State.Status}}', sentinel['id']))[1].strip() == 'created'
    assert (await docker('rm', sentinel['id']))[0] == 0
    return dict(schema='actor-persistence-adapters-local/v1', code='ok', identity=options,
        owner_uid=os.geteuid(), owner_capabilities_zero=True, no_new_privileges=True,
        timeline=timeline, profiles=profiles, actor=asdict(actor), fresh=asdict(fresh),
        scan_actor=scan_actor, scan_fresh=scan_fresh, marker_value_recorded=False,
        original_symlink_and_fifo_unavailable=True, old_receipts_after_later_activity=True,
        historical_queries_docker_io=0, own_ids_absent=ids, sentinel_preserved=sentinel,
        scope='inventory/runtime only; no Persistence API, backend codec, cancellation or SIGKILL claim',
        service_sources={p.relative_to(REPO).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((REPO / 'services/agent').glob('*.py'))})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--state-dir', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.state_dir is not None:
        print(json.dumps(asyncio.run(worker(args.image_id, args.state_dir))))
        return
    if os.geteuid() != 0 or args.receipt is None or args.receipt.exists():
        raise ValueError('root and a new receipt required')
    root = Path(tempfile.mkdtemp(prefix='m23-adapters-', dir='/run'))
    source = root / 'source'
    for relative in ('services',): shutil.copytree(REPO / relative, source / relative, ignore=shutil.ignore_patterns('__pycache__'))
    for relative in ('tests/integration/actor_persistence_adapters_local.py', 'tests/integration/guard_boundary_local.py'):
        target = source / relative; target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(REPO / relative, target)
    directory = root / 'state'; directory.mkdir(mode=0o700)
    os.chown(directory, 1000, 1001); os.chown(root, 1000, 1001); root.chmod(0o755)
    script = source / 'tests/integration/actor_persistence_adapters_local.py'
    command = privileged_wrapper(1000, 1001, '--groups=1000') + ('/tmp/escape-room-d3-tests/bin/python', '-B',
        str(script), '--image-id', args.image_id, '--state-dir', str(directory))
    result = subprocess.run(command, cwd=source, env=ENV, capture_output=True, timeout=180)
    (root / 'worker.stdout').write_bytes(result.stdout); (root / 'worker.stderr').write_bytes(result.stderr)
    if result.returncode:
        print('fixture retained: ' + str(root), file=sys.stderr)
        print(result.stderr.decode(errors='replace')[-4000:], file=sys.stderr)
        result.check_returncode()
    document = json.loads(result.stdout)
    document['harness_sources'] = {p: hashlib.sha256((source / p).read_bytes()).hexdigest() for p in
        ('tests/integration/actor_persistence_adapters_local.py', 'tests/integration/guard_boundary_local.py')}
    args.receipt.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    assert root.resolve().parent == Path('/run') and root.name.startswith('m23-adapters-')
    shutil.rmtree(root)
    print(json.dumps({'receipt': str(args.receipt), 'code': document['code']}))


if __name__ == '__main__': main()

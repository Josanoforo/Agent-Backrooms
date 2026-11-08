"""Root-operated local fixture for separate actor, verifier and controller UIDs."""

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from guard_boundary_local import DOCKER, ENV, PYTHON, REPO, privileged_wrapper, run


def wait_socket(process, path):
    deadline = time.monotonic() + 12
    while process.poll() is None and time.monotonic() < deadline:
        if path.is_socket() and stat.S_IMODE(path.stat().st_mode) == 0o660:
            return
        time.sleep(.025)
    raise RuntimeError('application owner did not bind its socket')


def exercise(root, image, service_python, *, driver=None, allowed_levels=(), actor_uid=1000):
    if type(actor_uid) is not int or actor_uid <= 0 or actor_uid in (65532, 65534):
        raise ValueError("distinct non-root owner UID required")
    allowed_levels = tuple(allowed_levels)
    if len(set(allowed_levels)) != len(allowed_levels) or any(level not in ('memory', 'secret', 'persistence', 'processes', 'privileges', 'network') for level in allowed_levels):
        raise ValueError('unsupported local actor level configuration')
    root.chmod(0o755)
    shutil.copytree(REPO / 'services', root / 'services', ignore=shutil.ignore_patterns('__pycache__'))
    (root / 'apps' / 'web').mkdir(parents=True)
    (root / 'tests' / 'integration').mkdir(parents=True)
    test_path = 'tests/integration/test_invoice_actor_service_docker.py'
    shutil.copyfile(REPO / test_path, root / test_path)
    # Calibration uses the same immutable image and declared actor profile before isolating the controller.
    calibration = '''
import asyncio, json
from services.agent import runner
async def check():
    async with runner.Session() as session:
        profile = session.profile
    assert session.cleanup_confirmed
    print(json.dumps({'profile': profile, 'sha256': runner.profile_digest(profile)}))
asyncio.run(check())
'''
    result = subprocess.run((PYTHON, '-B', '-S', '-c', calibration), cwd=root,
                            env={**ENV, 'ESCAPE_DOCKER_IMAGE': image}, capture_output=True, timeout=30)
    if result.returncode:
        print(result.stdout.decode(errors='replace')[-2000:], result.stderr.decode(errors='replace')[-3000:], file=sys.stderr)
    result.check_returncode()
    profile = json.loads(result.stdout)
    docker_group = os.stat('/var/run/docker.sock').st_gid
    assert docker_group not in (0, 65534, 65532)
    paths = {}
    for role, uid in (('actor', actor_uid), ('guard', 65532)):
        runtime = root / (role + '-runtime')
        runtime.mkdir(mode=0o2750)
        os.chown(runtime, uid, 65534)
        runtime.chmod(0o2750)
        journal = root / (role + '-journal')
        journal.mkdir(mode=0o700)
        os.chown(journal, uid, docker_group)
        paths[role] = (runtime / 'service.sock', journal)
    actor_socket, actor_journal = paths['actor']
    guard_socket, guard_journal = paths['guard']
    actor_command = privileged_wrapper(actor_uid, docker_group, '--groups=65534') + (
        PYTHON, '-B', '-S', '-m', 'services.agent.invoice_actor_service', '--client-uid', '65534',
        '--installation-id', uuid.uuid4().hex, '--image', image, '--profile-sha256', profile['sha256'],
        '--state-dir', str(actor_journal))
    if allowed_levels:
        for level in allowed_levels:
            actor_command += ('--allow-level', level)
    guard_command = privileged_wrapper(65532, docker_group, '--groups=65534') + (
        PYTHON, '-B', '-S', '-m', 'services.agent.daemon_guard', '--client-uid', '65534',
        '--socket-group', '65534', '--image', image, '--state-dir', str(guard_journal))
    for command in (actor_command, guard_command):
        initialized = run(command + ('--initialize-state',), root, timeout=20)
        if initialized.returncode:
            raise RuntimeError(initialized.stderr.decode(errors='replace'))
    processes = []
    try:
        for command, path in ((actor_command, actor_socket), (guard_command, guard_socket)):
            process = subprocess.Popen(command + ('--socket', str(path)), cwd=root, env=ENV,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            processes.append(process)
            wait_socket(process, path)
        scratch = root / 'controller'
        scratch.mkdir(mode=0o700)
        os.chown(scratch, 65534, 65534)
        endpoints = sorted({'/var/run/docker.sock', '/run/docker.sock', str(Path('/var/run/docker.sock').resolve()),
                            '/run/containerd/containerd.sock', '/run/user/65534/docker.sock'})
        env = {**ENV, 'ESCAPE_RUN_ACTOR_SERVICE_TEST': '1', 'ESCAPE_MODEL': 'fixture',
               'ESCAPE_OPERATOR_TOKEN': 'local-actor-service-test', 'VULTR_INFERENCE_KEY': 'unused-fixture-key',
               'ESCAPE_EVIDENCE_ORIGIN': 'fixture', 'ESCAPE_CLEANUP_ON_STARTUP': '1',
               'ESCAPE_ACTOR_BROKER_SOCKET': str(actor_socket), 'ESCAPE_ACTOR_BROKER_UID': str(actor_uid),
               'ESCAPE_INVOICE_VERIFIER_SOCKET': str(guard_socket), 'ESCAPE_INVOICE_VERIFIER_UID': '65532',
               'ESCAPE_INVOICE_VERIFIER_DURABLE': '1', 'ESCAPE_ACTOR_LEVELS': ','.join(allowed_levels), 'TMPDIR': str(scratch),
               'ESCAPE_TEST_DOCKER_ENDPOINTS': json.dumps(endpoints),
               'ESCAPE_TEST_OWNER_JOURNALS': json.dumps([str(actor_journal), str(guard_journal)])}
        namespace = ('/usr/bin/unshare', '--mount', '--net', '--propagation', 'private', '/bin/sh', '-ec',
                     'mount -t tmpfs -o mode=0755,nosuid,nodev,noexec tmpfs /mnt; '
                     'if [ -d /run/WSL ]; then mount -t tmpfs -o mode=000,nosuid,nodev,noexec tmpfs /run/WSL; fi; '
                     'exec "$@"', 'actor-service-fixture')
        command = namespace + privileged_wrapper(65534, 65534, '--clear-groups') + (
            service_python, '-B', '-m', 'pytest', '-q', '-s', '--disable-warnings', '-p', 'no:cacheprovider', test_path)
        if driver is not None:
            return driver({'root': root, 'image_id': image, 'profile': profile, 'paths': paths, 'actor_uid': actor_uid,
                           'processes': processes, 'actor_command': actor_command, 'guard_command': guard_command,
                           'controller_prefix': namespace + privileged_wrapper(65534, 65534, '--clear-groups'),
                           'service_python': service_python, 'environment': env, 'scratch': scratch})
        result = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=100)
        if result.returncode:
            print(result.stdout.decode(errors='replace'), result.stderr.decode(errors='replace'), file=sys.stderr)
            result.check_returncode()
        (proof,) = [json.loads(line.removeprefix('ACTOR_SERVICE_PROOF=')) for line in result.stdout.decode().splitlines()
                    if line.startswith('ACTOR_SERVICE_PROOF=')]
        ledgers = {}
        for role, (_, journal) in paths.items():
            with sqlite3.connect((journal / 'state.sqlite3').as_uri() + '?mode=ro', uri=True) as db:
                ledgers[role] = [{'kind': kind, 'payload': json.loads(payload)}
                                 for kind, payload in db.execute('SELECT kind,payload FROM events ORDER BY sequence')]
        assert [entry['kind'] for entry in ledgers['actor']] == [
            'CREATE_PENDING', 'CREATE_ACK', 'START_PENDING', 'ACTIVE', 'CLOSE_PENDING', 'FINISH'] * 2
        assert [entry['kind'] for entry in ledgers['guard']] == ['PENDING', 'ACK', 'FINISH']
        proof.update(schema='invoice-actor-service-local/v1', local_fixture=True, ledgers=ledgers,
                     profile_sha256=profile['sha256'], image_id=image)
        proof['owner_processes'] = {}
        for role, process in zip(('actor', 'guard'), processes):
            status = dict(line.split(':', 1) for line in Path(f'/proc/{process.pid}/status').read_text().splitlines()
                          if ':' in line)
            proof['owner_processes'][role] = {'pid': process.pid,
                'uids': [int(value) for value in status['Uid'].split()],
                'gids': [int(value) for value in status['Gid'].split()],
                'groups': [int(value) for value in status['Groups'].split()],
                'cap_eff': status['CapEff'].strip(), 'no_new_privileges': int(status['NoNewPrivs'])}
            assert proof['application_peers'][role]['pid'] == process.pid
        proof['harness_sources'] = {name: hashlib.sha256((REPO / name).read_bytes()).hexdigest()
                                    for name in (test_path, 'tests/integration/invoice_actor_service_local.py')}
        sources = sorted((root / 'services' / 'agent').glob('*.py'))
        proof['sources'] = {file.relative_to(root).as_posix(): hashlib.sha256(file.read_bytes()).hexdigest()
                            for file in sources}
        return proof
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            _, errors = process.communicate(timeout=40)
            if process.returncode:
                raise RuntimeError('owner stop requires recovery: ' + errors.decode(errors='replace'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--service-python', default='/tmp/escape-room-d3-tests/bin/python')
    parser.add_argument('--actor-uid', type=int, default=1000)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.receipt.exists():
        raise ValueError('root fixture and new receipt path required')
    root = Path(tempfile.mkdtemp(prefix='actor-service-', dir='/run'))
    try:
        proof = exercise(root, args.image_id, args.service_python, actor_uid=args.actor_uid)
    except BaseException:
        print('fixture state retained at ' + str(root), file=sys.stderr)
        raise
    if root.resolve().parent != Path('/run') or not root.name.startswith('actor-service-'):
        raise ValueError('fixture cleanup path changed')
    shutil.rmtree(root)
    args.receipt.write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps({'receipt': str(args.receipt), 'run_id': proof['run_id'], 'cleanup_confirmed': True}))


if __name__ == '__main__':
    main()

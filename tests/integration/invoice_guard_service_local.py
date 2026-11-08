"""Run the opt-in private invoice service proof on a local Linux Docker host."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

from guard_boundary_local import DOCKER, ENV, LABEL, PYTHON, REPO, docker_json, privileged_wrapper, run


def check_blocked(root, journal, guard_command, uid):
    # Persist the phase immediately before create, then exit without calling Docker create.
    program = '''
import os, sys
from services.agent.daemon_guard import docker_identity
from services.agent.guard_state import open_state
daemon, docker_root = docker_identity()
with open_state(sys.argv[1], guard_uid=os.geteuid(), client_uid=int(sys.argv[2]),
                docker_id=daemon, docker_root=docker_root) as store:
    store.begin('escape-invoice-' + 'e' * 32, 'd' * 32, 'perturbed', 'c' * 64)
'''
    launcher = guard_command[:guard_command.index(PYTHON) + 1]
    staged = run(launcher + ('-B', '-S', '-c', program, str(journal), str(uid)), root, timeout=15)
    assert staged.returncode == 0, staged.stderr.decode(errors='replace')
    new_socket = root / 'state' / 'after.sock'
    serving = run(guard_command + ('--socket', str(new_socket)), root, timeout=20)
    recovery = run(guard_command + ('--recover-only',), root, timeout=20)
    assert serving.returncode == recovery.returncode == 2
    assert serving.stderr.strip() == recovery.stderr.strip() == b'guard_recovery_required'
    assert not os.path.lexists(new_socket)
    with sqlite3.connect((journal / 'state.sqlite3').as_uri() + '?mode=ro', uri=True) as connection:
        events = connection.execute('SELECT kind, payload FROM events ORDER BY sequence').fetchall()
    assert [kind for kind, _ in events] == ['PENDING', 'ACK', 'FINISH', 'PENDING']
    pending = json.loads(events[-1][1])
    assert pending['container_id'] is None and pending['run_id'] == 'd' * 32
    return {'serve_exit': 2, 'recover_exit': 2, 'reason': 'guard_recovery_required',
            'new_socket_absent': True, 'pending_preserved': pending}


def exercise(root, uid, service_python, cached_image, durable=False):
    root.chmod(0o755)
    group = pwd.getpwuid(uid).pw_gid
    guard_uid = 65532
    docker_group = os.stat('/var/run/docker.sock').st_gid
    if uid in (0, guard_uid) or docker_group == 0:
        raise ValueError('fixture requires distinct non-root identities and a non-root Docker group')
    image = docker_json(('image', 'inspect', '--format', '{{json .Id}}', cached_image), root)[0]
    package = root / 'services' / 'agent'
    package.mkdir(parents=True)
    modules = ['daemon_guard.py', 'invoice_verifier.py']
    if durable:
        modules.append('guard_state.py')
    for name in modules:
        shutil.copyfile(REPO / 'services' / 'agent' / name, package / name)
        (package / name).chmod(0o644)
    state = root / 'state'
    state.mkdir()
    os.chown(state, guard_uid, group)
    state.chmod(0o750)
    path = state / 'guard.sock'
    scratch = root / 'pytest'
    scratch.mkdir()
    os.chown(scratch, uid, group)
    scratch.chmod(0o700)
    command = privileged_wrapper(guard_uid, docker_group, f'--groups={group}') + (
        PYTHON, '-B', '-S', '-m', 'services.agent.daemon_guard', '--client-uid', str(uid),
        '--socket-group', str(group), '--image', image,
    )
    journal = root / 'journal'
    if durable:
        journal.mkdir(mode=0o700)
        os.chown(journal, guard_uid, docker_group)
        command += ('--state-dir', str(journal))
        initialized = run(command + ('--initialize-state',), root, timeout=15)
        assert initialized.returncode == 0, initialized.stderr.decode(errors='replace')
    guard = subprocess.Popen(command + ('--socket', str(path)), cwd=root, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 8
        while guard.poll() is None and time.monotonic() < deadline:
            if path.is_socket() and stat.S_IMODE(path.stat().st_mode) == 0o660:
                break
            time.sleep(.025)
        assert path.is_socket(), 'guard failed to start'
        env = {**ENV, 'ESCAPE_DOCKER_IMAGE': image, 'ESCAPE_INVOICE_VERIFIER_SOCKET': str(path),
               'ESCAPE_INVOICE_VERIFIER_UID': str(guard_uid), 'ESCAPE_RUN_INVOICE_GUARD_SERVICE_TEST': '1',
               'TMPDIR': str(scratch)}
        if durable:
            env['ESCAPE_INVOICE_VERIFIER_DURABLE'] = '1'
        service_command = ('/usr/bin/unshare', '--net', *privileged_wrapper(uid, group, f'--groups={docker_group}'),
                           service_python, '-B', '-m', 'pytest', '-q', '-s', '--disable-warnings', '-p', 'no:cacheprovider',
                           'tests/integration/test_invoice_guard_service_docker.py')
        began = time.time()
        result = subprocess.run(service_command, cwd=REPO, env=env, capture_output=True, timeout=100)
        if result.returncode != 0:
            print(result.stdout.decode(errors='replace'), result.stderr.decode(errors='replace'), file=sys.stderr)
            result.check_returncode()
        (proof,) = [json.loads(line.removeprefix('SC2_PROOF=')) for line in result.stdout.decode().splitlines()
                    if line.startswith('SC2_PROOF=')]
        verifier = proof['verifications']['legitimate']['container_id']
        events = docker_json(('events', '--since', str(began), '--until', str(time.time()), '--filter', 'type=container',
                              '--filter', f'label={LABEL}', '--format', '{{json .}}'), root)
        assert {event['Actor']['ID'] for event in events if event['Action'] == 'create'} == {verifier}
        actions = [event['Action'] for event in events if event['Actor']['ID'] == verifier]
        assert actions == ['create', 'attach', 'start', 'die', 'destroy'], actions
        if durable:
            with sqlite3.connect((journal / 'state.sqlite3').as_uri() + '?mode=ro', uri=True) as connection:
                owner = connection.execute('SELECT installation_id, guard_uid, client_uid FROM installation').fetchone()
                events = connection.execute('SELECT kind, payload FROM events ORDER BY sequence').fetchall()
            assert owner[1:] == (guard_uid, uid)
            assert [kind for kind, _ in events] == ['PENDING', 'ACK', 'FINISH']
            pending = json.loads(events[0][1])
            assert pending['run_id'] == proof['run_id'] and pending['variant'] == 'legitimate'
            assert pending['artifact_sha256'] == proof['verifications']['legitimate']['artifact_sha256']
            assert json.loads(events[1][1]) == {'container_id': verifier}
            proof['journal'] = {'installation_id': owner[0], 'history': [[kind, json.loads(payload)] for kind, payload in events]}
        for key in [verifier, *proof['actor_names']]:
            gone = run(DOCKER + ('container', 'inspect', key), root, timeout=10)
            assert gone.returncode != 0 and b'No such container' in gone.stderr
        sources = ('services/agent/main.py', 'services/agent/workflow.py', 'services/agent/runner.py',
                   'services/agent/invoice_verification.py', 'services/agent/daemon_guard.py',
                   'services/agent/guard_client.py', 'services/agent/invoice_verifier.py',
                   'tests/integration/test_invoice_guard_service_docker.py')
        if durable:
            sources += ('services/agent/guard_state.py',)
        proof.update(schema='local-invoice-service-proof/v1', image=image, service_uid=uid, guard_uid=guard_uid,
                     verifier_lifecycle=actions, containers_absent_after=True, socket_absent_after_stop=True,
                     source_sha256={name: hashlib.sha256((REPO / name).read_bytes()).hexdigest() for name in sources})
    finally:
        if guard.poll() is None:
            guard.terminate()
        _, errors = guard.communicate(timeout=30)
        assert guard.returncode == 0 and not path.exists(), errors.decode(errors='replace')
    if durable:
        proof['blocked_admission'] = check_blocked(root, journal, command, uid)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service-uid', required=True, type=int)
    parser.add_argument('--service-python', required=True)
    parser.add_argument('--cached-image', required=True)
    parser.add_argument('--durable', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or not Path(args.service_python).is_absolute():
        parser.error('requires root and the absolute path of a test Python with the repo dependencies')
    root = Path(tempfile.mkdtemp(prefix='escape-invoice-service-', dir='/run'))
    try:
        print(json.dumps(exercise(root, args.service_uid, args.service_python, args.cached_image, args.durable), indent=2, sort_keys=True))
    finally:
        if os.path.lexists(root / 'state' / 'guard.sock'):
            print(f'Guard state retained at {root}', file=sys.stderr)
        else:
            shutil.rmtree(root)


if __name__ == '__main__':
    main()

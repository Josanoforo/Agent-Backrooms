"""Opt-in Linux Docker proof. Run as root on a local test host with a cached Python image."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time


REPO = Path(__file__).resolve().parents[2]
PYTHON = '/usr/bin/python3'
DOCKER = ('/usr/bin/docker', '--host', 'unix:///var/run/docker.sock')
CLIENT_UID = 65534
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/nonexistent'}
INPUT_DIGEST = 'adac398613336082d281893b448ddfccb4fc31f297e05e5e50019b1d63720c13'
LABEL = 'org.agent-escape-room.invoice-request'
PRIVATE_NAMESPACES = (
    '/usr/bin/unshare', '--mount', '--net', '--propagation', 'private', '/bin/sh', '-ec',
    'mount -t tmpfs -o mode=0755,nosuid,nodev,noexec tmpfs /mnt; exec "$@"', 'guard-fixture',
)
PROBE = '''
import errno, json, os, socket, sys
assert not os.listdir('/mnt') and socket.if_nameindex() == [(1, 'lo')]
status = dict(line.split(':', 1) for line in open('/proc/self/status') if ':' in line)
assert all(int(status[key], 16) == 0 for key in ('CapEff', 'CapPrm', 'CapBnd', 'CapAmb'))
assert int(status['NoNewPrivs']) == 1
result = {'uid': os.geteuid(), 'groups': os.getgroups(), 'interfaces': ['lo'], 'mnt_hidden': True, 'docker': {}}
for path in ('/run/docker.sock', '/var/run/docker.sock', '/run/containerd/containerd.sock', '/run/user/65534/docker.sock'):
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(2)
        try:
            peer.connect(path)
        except OSError as exc:
            result['docker'][path] = errno.errorcode[exc.errno]
        else:
            raise AssertionError('direct Docker endpoint accessible')
with socket.socket(socket.AF_UNIX) as peer:
    peer.settimeout(5)
    peer.connect(sys.argv[1])
    peer.sendall(sys.argv[2].encode())
    peer.shutdown(socket.SHUT_WR)
    response = peer.makefile('rb').read(2048)
    result['malformed_request'] = json.loads(response)
print(json.dumps(result))
'''
RAW_PEER = '''
import socket, sys
with socket.socket(socket.AF_UNIX) as peer:
    peer.settimeout(8)
    peer.connect(sys.argv[1])
    if len(sys.argv) > 2:
        peer.sendall(sys.argv[2].encode('ascii'))
        peer.shutdown(socket.SHUT_WR)
    else:
        sys.stdout.buffer.write(peer.recv(2048))
'''


def privileged_wrapper(uid, gid, groups):
    return ('/usr/bin/setpriv', f'--reuid={uid}', f'--regid={gid}', groups, '--no-new-privs',
            '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all')


def run(args, directory, timeout=75):
    return subprocess.run(args, cwd=directory, env=ENV, capture_output=True, timeout=timeout)


def docker_json(args, directory):
    result = run(DOCKER + args, directory, timeout=15)
    result.check_returncode()
    return [json.loads(line) for line in result.stdout.splitlines()]


def exercise(root, guard_uid, image):
    root.chmod(0o755)
    package = root / 'services' / 'agent'
    package.mkdir(parents=True)
    source_digests = {}
    for name in ('daemon_guard.py', 'guard_client.py', 'invoice_verifier.py'):
        shutil.copyfile(REPO / 'services' / 'agent' / name, package / name)
        (package / name).chmod(0o644)
        source_digests[name] = hashlib.sha256((package / name).read_bytes()).hexdigest()
    state = root / 'state'
    state.mkdir()
    os.chown(state, guard_uid, CLIENT_UID)
    state.chmod(0o750)
    path = state / 'guard.sock'
    trusted = (REPO / 'docs/evidencia/d1/real/invoice-reconcile-legitimate-artifact.json').read_bytes()
    assert b'2750' in trusted and trusted.count(b'2750') == 1
    artifacts = [trusted, trusted.replace(b'2750', b'5500')]
    for name, content in zip(('historic.json', 'forged.json'), artifacts):
        (root / name).write_bytes(content)
        (root / name).chmod(0o644)
    daemon_gid = os.stat('/var/run/docker.sock').st_gid
    assert daemon_gid not in (0, CLIENT_UID)
    guard = privileged_wrapper(guard_uid, daemon_gid, f'--groups={CLIENT_UID}')
    client = PRIVATE_NAMESPACES + privileged_wrapper(CLIENT_UID, CLIENT_UID, '--clear-groups')
    guard_args = (PYTHON, '-B', '-S', '-m', 'services.agent.daemon_guard', '--socket', str(path),
                  '--client-uid', str(CLIENT_UID), '--socket-group', str(CLIENT_UID), '--image', image)
    daemon = subprocess.Popen(guard + guard_args, cwd=root, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        ready_by = time.monotonic() + 8
        while daemon.poll() is None and time.monotonic() < ready_by:
            if path.is_socket() and stat.S_IMODE(path.stat().st_mode) == 0o660:
                break
            time.sleep(0.025)
        assert path.is_socket() and stat.S_IMODE(path.stat().st_mode) == 0o660, 'guard startup failed'
        began = time.time()
        probe = run(client + (PYTHON, '-I', '-S', '-c', PROBE, str(path), '{"op":"exec","user":"0"}'), root)
        assert probe.returncode == 0, probe.stderr.decode(errors='replace')
        direct = json.loads(probe.stdout)
        assert direct['uid'] == CLIENT_UID and direct['groups'] == []
        assert direct['docker']['/var/run/docker.sock'] == 'EACCES'
        assert direct['malformed_request'] == {'status': 'error', 'reason': 'invalid_request'}
        denied = PRIVATE_NAMESPACES + privileged_wrapper(CLIENT_UID - 1, CLIENT_UID, '--clear-groups')
        wrong_client = run(denied + (PYTHON, '-I', '-S', '-c', RAW_PEER, str(path)), root)
        assert wrong_client.returncode == 0 and json.loads(wrong_client.stdout) == {'status': 'error', 'reason': 'unauthorized'}
        results = []
        base = (PYTHON, '-B', '-S', '-m', 'services.agent.guard_client', '--socket', str(path), '--guard-uid')
        impersonated = run(client + base + ('0', '--artifact', str(root / 'historic.json')), root)
        assert impersonated.returncode == 2 and json.loads(impersonated.stdout)['reason'] == 'unexpected_guard_uid'
        for name, content, status, exit_code in zip(('historic.json', 'forged.json'), artifacts, ('passed', 'rejected'), (0, 1)):
            response = run(client + base + (str(guard_uid), '--artifact', str(root / name)), root)
            assert response.returncode == exit_code, (response.stdout, response.stderr)
            result = json.loads(response.stdout)
            assert result['status'] == status and result['cleanup_confirmed'] is True
            assert result['artifact_sha256'] == hashlib.sha256(content).hexdigest()
            assert result['verifier_sha256'] == source_digests['invoice_verifier.py'] and result['input_sha256'] == INPUT_DIGEST
            results.append(result)
        ids = {result['container_id'] for result in results}
        assert len(ids) == 2
        frame = json.dumps({'artifact_b64': base64.b64encode(trusted).decode('ascii'),
                            'artifact_sha256': hashlib.sha256(trusted).hexdigest()})
        disconnected = run(client + (PYTHON, '-I', '-S', '-c', RAW_PEER, str(path), frame), root)
        disconnected.check_returncode()
        # A later invalid frame serves as a barrier on the single-request guard, after the disconnected request.
        barrier = run(client + (PYTHON, '-I', '-S', '-c', PROBE, str(path), '{}'), root)
        assert barrier.returncode == 0, barrier.stderr.decode(errors='replace')
        assert json.loads(barrier.stdout)['malformed_request']['reason'] == 'invalid_request'
        events = docker_json(('events', '--since', str(began), '--until', str(time.time()), '--filter',
                              'type=container', '--filter', f'label={LABEL}', '--format', '{{json .}}'), root)
        created = {e['Actor']['ID'] for e in events if e['Action'] == 'create'}
        assert ids < created and len(created - ids) == 1, created
        disconnected_id, = created - ids
        ids = created
        lifecycle = {cid: [e['Action'] for e in events if e['Actor']['ID'] == cid] for cid in ids}
        for actions in lifecycle.values():
            assert all(action in actions for action in ('create', 'start', 'die', 'destroy')), actions
            assert not any(action.startswith('exec_') for action in actions), actions
        for cid in ids:
            gone = run(DOCKER + ('container', 'inspect', cid), root, timeout=10)
            assert gone.returncode != 0 and b'No such container' in gone.stderr
        return {'schema': 'local-invoice-verifier-proof/v1', 'guard_uid': guard_uid, 'image': image,
                'source_sha256': source_digests, 'direct_control': direct, 'receipts': results,
                'wrong_client': json.loads(wrong_client.stdout), 'wrong_server': json.loads(impersonated.stdout),
                'disconnected_client_container': disconnected_id,
                'lifecycle': lifecycle, 'containers_absent_after': True, 'socket_absent_after_stop': True}
    finally:
        if daemon.poll() is None:
            daemon.terminate()
        _, errors = daemon.communicate(timeout=20)
        if errors:
            print(errors.decode(errors='replace'), file=sys.stderr)
        assert not path.exists(), 'guard socket remained after stopping the fixture'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guard-uid', type=int, required=True)
    parser.add_argument('--cached-image', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not 0 < args.guard_uid < CLIENT_UID:
        parser.error('requires root and a separate non-root guard UID')
    root = Path(tempfile.mkdtemp(prefix='escape-guard-fixture-', dir='/run'))
    try:
        image = docker_json(('image', 'inspect', '--format', '{{json .Id}}', args.cached_image), root)[0]
        print(json.dumps(exercise(root, args.guard_uid, image), indent=2, sort_keys=True))
    finally:
        if os.path.lexists(root / 'state' / 'guard.sock'):
            print(f'Guard state retained at {root}', file=sys.stderr)
        else:
            shutil.rmtree(root)


if __name__ == '__main__':
    main()

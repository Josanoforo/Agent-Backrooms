"""Independent bounded SC3 checks; --docker uses only uniquely owned containers.

Does not claim durable restart recovery. No pulls, inference, host restart or
global cleanup. Actual Docker commands use the guard's configured local daemon.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from services.agent import daemon_guard as guard

SOURCE = (ROOT / 'services/agent/invoice_verifier.py').read_bytes()
ARTIFACT = b'{}'


class UncertainDocker:
    """Create acknowledgement lost; inventory may return a foreign object."""
    def __init__(self, foreign=False):
        self.foreign = foreign
        self.calls = []

    def __call__(self, args, data=None):
        self.calls.append(args)
        if args[0] == 'create':
            raise guard.GuardError('docker_command_failed')
        if args[0] == 'ls':
            return (b'f' * 64 + b'\n') if self.foreign else b''
        if args[0] == 'inspect':
            return json.dumps([{'Id': 'f' * 64, 'Name': '/foreign',
                                'Config': {'Labels': {}}}]).encode()
        raise AssertionError('Unexpected mutation: ' + repr(args))


class OfflineChecks(unittest.TestCase):
    def test_empty_inventory_does_not_clear_ambiguous_create(self):
        docker = UncertainDocker()
        subject = guard.InvoiceGuard('sha256:' + 'a' * 64, SOURCE, command=docker)
        with self.assertRaisesRegex(guard.GuardError, 'create_uncertain'):
            subject.verify(ARTIFACT, guard.digest(ARTIFACT))
        self.assertTrue(subject.poisoned)
        calls = len(docker.calls)
        with self.assertRaisesRegex(guard.GuardError, 'guard_unavailable'):
            subject.verify(ARTIFACT, guard.digest(ARTIFACT))
        self.assertEqual(calls, len(docker.calls))

    def test_foreign_inventory_is_not_removed(self):
        docker = UncertainDocker(foreign=True)
        subject = guard.InvoiceGuard('sha256:' + 'a' * 64, SOURCE, command=docker)
        with self.assertRaisesRegex(guard.GuardError, 'cleanup_unconfirmed'):
            subject.verify(ARTIFACT, guard.digest(ARTIFACT))
        self.assertTrue(subject.poisoned)
        self.assertFalse(any(c[0] == 'rm' for c in docker.calls))


def docker_checks(image):
    assert image.startswith('sha256:') and guard.is_digest(image[7:])
    outcomes = []
    for foreign in (False, True):
        owned_id = None
        unique = 'sc3-independent-' + uuid.uuid4().hex
        calls = []
        subject = None

        def command(args, data=None):
            nonlocal owned_id
            calls.append(list(args))
            if args[0] == 'create':
                actual = list(args)
                if foreign:
                    # Preserve the request label but mismatch the name: the
                    # guard must inspect ownership and leave this object alone.
                    actual[actual.index('--name') + 1] = unique
                owned_id = guard.docker_command(actual).decode().strip()
                assert guard.is_digest(owned_id)
                raise guard.GuardError('docker_command_failed')
            return guard.docker_command(args, data)

        subject = guard.InvoiceGuard(image, SOURCE, command=command)
        try:
            try:
                subject.verify(ARTIFACT, guard.digest(ARTIFACT))
                raise AssertionError('Uncertain create was accepted')
            except guard.GuardError as exc:
                expected = 'cleanup_unconfirmed' if foreign else 'create_uncertain'
                assert str(exc) == expected, str(exc)
            assert owned_id and subject.poisoned
            remaining = guard.docker_command(['ls', '--all', '--no-trunc', '--quiet',
                                             '--filter', 'id=' + owned_id]).decode().splitlines()
            assert remaining == ([owned_id] if foreign else [])
            before = len(calls)
            try:
                subject.verify(ARTIFACT, guard.digest(ARTIFACT))
                raise AssertionError('Poisoned guard admitted a new request')
            except guard.GuardError as exc:
                assert str(exc) == 'guard_unavailable'
            assert len(calls) == before
            if foreign:
                assert not any(c[0] == 'rm' for c in calls)
            outcomes.append({'case': 'foreign_preserved' if foreign else 'uncertain_create_cleaned',
                             'container_id': owned_id, 'admission_blocked': True,
                             'guard_commands': [c[0] for c in calls],
                             'present_before_fixture_cleanup': bool(remaining)})
        finally:
            if owned_id:
                # Only this exact ID was created by this fixture. Never prune.
                guard.docker_command(['rm', '--force', owned_id]) if foreign else None
                assert not guard.docker_command(['ls', '--all', '--no-trunc', '--quiet',
                                                 '--filter', 'id=' + owned_id]).strip()
    return {'schema': 'sc3-independent/v1', 'scope': 'local Docker; no process or host restart',
            'image': image, 'source_sha256': guard.digest(SOURCE), 'cases': outcomes,
            'fixture_cleanup_confirmed': True}


def durable_checks(image):
    """SIGKILL only our forked fixture process, then run the real recovery CLI."""
    from services.agent.guard_state import open_state
    identity = guard.docker_identity()
    results = []
    for mode in ('acked', 'pending'):
        owned_id = sentinel_id = None
        with tempfile.TemporaryDirectory(prefix='sc3-independent-', dir='/run') as folder:
            root = Path(folder)
            directory = root / 'state'
            directory.mkdir(mode=0o700)
            marker = root / 'created-id'
            run_id = uuid.uuid4().hex
            cli = [sys.executable, '-B', '-S', '-m', 'services.agent.daemon_guard',
                   '--state-dir', str(directory), '--client-uid', '65534', '--image', image]
            init = subprocess.run(cli + ['--initialize-state'], cwd=ROOT, capture_output=True)
            assert init.returncode == 0, init.stderr
            assert not any(p.is_socket() for p in root.rglob('*'))
            state_args = dict(guard_uid=os.geteuid(), client_uid=65534,
                              docker_id=identity[0], docker_root=identity[1])
            try:
                sentinel_id = guard.docker_command([
                    'create', '--pull=never', '--name', 'sc3-sentinel-' + uuid.uuid4().hex,
                    '--network=none', '--read-only', '--cap-drop=ALL', '--user=65534:65534',
                    image, '/bin/true']).decode().strip()
                assert guard.is_digest(sentinel_id)
                child = os.fork()
                if child == 0:
                    try:
                        def command(args, data=None):
                            if args[0] == 'inspect' and mode == 'acked':
                                os.kill(os.getpid(), signal.SIGKILL)
                            reply = guard.docker_command(args, data)
                            if args[0] == 'create':
                                marker.write_bytes(reply)
                                if mode == 'pending':
                                    os.kill(os.getpid(), signal.SIGKILL)
                            return reply
                        with open_state(directory, **state_args) as store:
                            subject = guard.InvoiceGuard(image, SOURCE, command=command,
                                store=store, daemon_identity=identity)
                            subject.verify(ARTIFACT, guard.digest(ARTIFACT), run_id, 'legitimate')
                    finally:
                        os._exit(71)
                deadline = time.monotonic() + 25
                while True:
                    finished, status = os.waitpid(child, os.WNOHANG)
                    if finished:
                        break
                    if time.monotonic() >= deadline:
                        os.kill(child, signal.SIGKILL)
                        os.waitpid(child, 0)
                        raise AssertionError('Fixture child exceeded 25 seconds')
                    time.sleep(0.02)
                assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
                owned_id = marker.read_text().strip()
                assert guard.is_digest(owned_id)
                with open_state(directory, **state_args) as store:
                    before = store.pending()
                    assert before['run_id'] == run_id and before['variant'] == 'legitimate'
                    assert before['artifact_sha256'] == guard.digest(ARTIFACT)
                    assert before['container_id'] == (owned_id if mode == 'acked' else None)
                    installation_id = store.installation_id
                recover = subprocess.run(cli + ['--recover-only'], cwd=ROOT, capture_output=True)
                assert recover.returncode == (0 if mode == 'acked' else 2), recover.stderr
                if mode == 'pending':
                    assert recover.stderr.strip() == b'guard_recovery_required'
                with open_state(directory, **state_args) as store:
                    after = store.pending()
                    assert after == (None if mode == 'acked' else before)
                def present(cid):
                    return guard.docker_command(['ls', '--all', '--no-trunc', '--quiet',
                                                  '--filter', 'id=' + cid]).decode().splitlines()
                assert present(owned_id) == ([] if mode == 'acked' else [owned_id])
                assert present(sentinel_id) == [sentinel_id]
                repeat = subprocess.run(cli + ['--recover-only'], cwd=ROOT, capture_output=True)
                assert repeat.returncode == recover.returncode
                with sqlite3.connect(directory / 'state.sqlite3') as db:
                    events = [r[0] for r in db.execute('SELECT kind FROM events ORDER BY sequence')]
                    metadata = db.execute('SELECT guard_uid,client_uid,docker_id,docker_root FROM installation').fetchone()
                assert events == (['PENDING', 'ACK', 'FINISH'] if mode == 'acked' else ['PENDING'])
                results.append({'case': mode, 'run_id': run_id, 'installation_id': installation_id,
                    'container_id': owned_id, 'sentinel_id': sentinel_id,
                    'killed_by': 'SIGKILL', 'recovery_returncode': recover.returncode,
                    'repeat_returncode': repeat.returncode, 'events': events,
                    'sentinel_preserved': True, 'metadata_identity': list(metadata),
                    'pending_preserved': mode == 'pending'})
            finally:
                if owned_id is None and marker.exists():
                    candidate = marker.read_text().strip()
                    if guard.is_digest(candidate):
                        owned_id = candidate
                for cid in (owned_id, sentinel_id):
                    if cid:
                        existing = guard.docker_command(['ls', '--all', '--no-trunc', '--quiet', '--filter', 'id=' + cid])
                        if existing.strip():
                            guard.docker_command(['rm', '--force', cid])
                        assert not guard.docker_command(['ls', '--all', '--no-trunc', '--quiet', '--filter', 'id=' + cid]).strip()
    return {'schema': 'sc3-independent-durable/v1', 'scope': 'local process SIGKILL; no host reboot',
            'guard_uid': os.geteuid(), 'image': image, 'cases': results,
            'source_hashes': {name: guard.digest((ROOT / 'services/agent' / name).read_bytes())
                              for name in ('daemon_guard.py', 'guard_state.py')},
            'fixture_cleanup_confirmed': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--docker-image-id')
    parser.add_argument('--receipt')
    parser.add_argument('--durable', action='store_true')
    args = parser.parse_args()
    if args.docker_image_id:
        result = durable_checks(args.docker_image_id) if args.durable else docker_checks(args.docker_image_id)
        if args.durable and args.receipt and Path(args.receipt).exists():
            previous = json.loads(Path(args.receipt).read_text(encoding='utf-8'))
            result = {'schema': 'sc3-independent-combined/v1',
                      'initial': previous.get('initial', previous), 'durable': result}
        raw = json.dumps(result, indent=2) + '\n'
        if args.receipt:
            Path(args.receipt).write_text(raw, encoding='utf-8')
        print(raw)
    else:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(OfflineChecks)
        raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())

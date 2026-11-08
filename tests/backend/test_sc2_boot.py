"""Cold-host launch readiness and no-work guard handshake; no Docker, host reboot or systemd activation."""
import asyncio
import os
from pathlib import Path
import select
import signal
import socket
import struct
import tempfile

import pytest

from services.agent import daemon_guard, invoice_actor_client as client, invoice_verification as verifier, sc2_boot as boot

pytestmark = pytest.mark.skipif(not hasattr(os, 'geteuid'), reason='POSIX controller launcher')
ACTOR = client.Settings('/run/fixture/actor', 65531, 'a' * 32, 'sha256:' + 'b' * 64)
GUARD = verifier.Settings('/run/fixture/guard', 65532, durable=True)
READY = {'ready': True, 'blocked': False, 'obligations': 0,
         'installation_id': ACTOR.installation_id, 'image_id': ACTOR.image_id}


@pytest.mark.parametrize('change', ['none', 'not_ready', 'blocked', 'debt', 'installation', 'image', 'guard'])
def test_owner_wait_checks_pins_and_debt_before_guard_probe(monkeypatch, change):
    state, calls = dict(READY), []
    if change == 'not_ready': state['ready'] = False
    if change == 'blocked': state['blocked'] = True
    if change == 'debt': state['obligations'] = 1
    if change == 'installation': state['installation_id'] = 'c' * 32
    if change == 'image': state['image_id'] = 'sha256:' + 'd' * 64
    async def health(settings):
        assert settings == ACTOR
        return state
    def guard(settings):
        calls.append(settings)
        return change != 'guard'
    monkeypatch.setattr(client, 'health', health)
    monkeypatch.setattr(boot, 'guard_ready', guard)
    assert asyncio.run(boot.owners_ready(ACTOR, GUARD)) is (change == 'none')
    assert len(calls) == int(change in ('none', 'guard'))


def test_wait_allows_starting_owner_but_times_out_without_executing(monkeypatch):
    calls = []
    async def eventually(*args):
        calls.append(1)
        if len(calls) == 1: raise client.ActorError('owner_unavailable')
        return len(calls) >= 3
    monkeypatch.setattr(boot, 'owners_ready', eventually)
    monkeypatch.setattr(boot, 'POLL_SECONDS', 0)
    asyncio.run(boot.wait_for_owners(ACTOR, GUARD, timeout=.1))
    assert len(calls) == 3
    async def blocked(*args): return False
    monkeypatch.setattr(boot, 'owners_ready', blocked)
    with pytest.raises(boot.BootError, match='owners_not_ready'):
        asyncio.run(boot.wait_for_owners(ACTOR, GUARD, timeout=.01))
    with pytest.raises(boot.BootError, match='boot_configuration_unavailable'):
        asyncio.run(boot.wait_for_owners(None, GUARD, timeout=.01))


def test_launcher_uses_existing_socket_uid_environment_without_new_identity_configuration(monkeypatch):
    for key, value in {'ESCAPE_ACTOR_BROKER_SOCKET': ACTOR.socket_path, 'ESCAPE_ACTOR_BROKER_UID': '65531',
                       'ESCAPE_INVOICE_VERIFIER_SOCKET': GUARD.socket_path, 'ESCAPE_INVOICE_VERIFIER_UID': '65532',
                       'ESCAPE_INVOICE_VERIFIER_DURABLE': '1'}.items():
        monkeypatch.setenv(key, value)
    async def health(settings):
        assert settings.owner_uid == 65531 and settings.installation_id is None and settings.image_id is None
        return dict(READY)
    monkeypatch.setattr(client, 'health', health)
    monkeypatch.setattr(boot, 'guard_ready', lambda settings: settings == GUARD)
    asyncio.run(boot.wait_for_owners(client.settings_from_env(), verifier.settings_from_env(), timeout=.1))


def test_guard_peer_mismatch_is_rejected_before_eof_or_request(monkeypatch):
    class Peer:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def settimeout(self, value): pass
        def connect(self, path): pass
        def getsockopt(self, *args): return struct.pack('=iII', 123, 65530, 65530)
        def shutdown(self, *args): pytest.fail('EOF must not reach unverified peer')
        def sendall(self, *args): pytest.fail('no request is permitted')
    monkeypatch.setattr(socket, 'socket', lambda *args: Peer())
    assert boot.guard_ready(GUARD) is False


@pytest.mark.parametrize('ready', [True, False])
def test_launches_normal_single_worker_api_only_after_owner_wait(monkeypatch, ready):
    steps = []
    monkeypatch.setattr(client, 'settings_from_env', lambda: ACTOR)
    monkeypatch.setattr(verifier, 'settings_from_env', lambda: GUARD)
    async def wait(actor, guard):
        steps.append('wait')
        if not ready: raise boot.BootError('owners_not_ready')
    def execute(binary, args):
        assert steps == ['wait']
        assert args == [binary, *boot.UVICORN_ARGS]
        assert args[args.index('--workers') + 1] == '1'
        steps.append('exec')
    monkeypatch.setattr(boot, 'wait_for_owners', wait)
    monkeypatch.setattr(os, 'execv', execute)
    assert boot.main() == (None if ready else 2)
    assert steps == (['wait', 'exec'] if ready else ['wait'])


@pytest.mark.skipif(not hasattr(os, 'fork') or os.geteuid() != 0, reason='real separate UID handshake requires Linux root fixture')
@pytest.mark.parametrize('poisoned', [False, True])
def test_guard_handshake_real_peer_never_dispatches_verification(poisoned):
    uid = 65532
    with tempfile.TemporaryDirectory(prefix='sc2-boot-guard-', dir='/tmp') as directory:
        os.chown(directory, uid, uid)
        path = str(Path(directory) / 'guard.sock')
        read, write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read)
            try:
                os.setgid(uid)
                os.setuid(uid)
                class Guard:
                    store = object()
                    def verify(self, *args): os._exit(8)
                guard = Guard()
                guard.poisoned = poisoned
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                    listener.bind(path)
                    listener.listen(1)
                    listener.settimeout(5)
                    os.write(write, b'R')
                    peer, _ = listener.accept()
                    with peer: daemon_guard.serve_peer(peer, guard, 0)
                os._exit(0)
            except BaseException:
                os._exit(9)
        os.close(write)
        try:
            assert select.select([read], [], [], 3)[0] and os.read(read, 1) == b'R'
            assert boot.guard_ready(verifier.Settings(path, uid, durable=True)) is (not poisoned)
            assert os.waitpid(pid, 0)[1] == 0
            pid = None
        finally:
            os.close(read)
            if pid is not None:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)

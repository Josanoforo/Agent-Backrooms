"""Cold-host controller launcher: wait for reconciled owners, then run the normal API startup.

Runs as the isolated controller UID after the existing namespace/capability drop. No Docker, diary access, inference or
state mutation. Socket readiness is never used to clear controller debt; main.startup retains exact durable reconciliation.
"""
import asyncio
import json
import os
import socket
import struct
import sys
import time

from . import guard_client, invoice_actor_client, invoice_verification, runner

WAIT_SECONDS = 60
POLL_SECONDS = .5
UVICORN_ARGS = ['-B', '-m', 'uvicorn', 'services.agent.main:app', '--host', '127.0.0.1',
                '--port', '8040', '--workers', '1', '--no-proxy-headers']


class BootError(Exception):
    pass


def guard_ready(settings):
    """Authenticate the guard and ask no work: EOF yields invalid_request only after its poison check.

    The existing guard binds/listens only after durable reconciliation. An empty request cannot dispatch verification.
    A poisoned guard returns guard_unavailable, which is not readiness. Peer UID is checked before sending even EOF.
    """
    if not settings.durable or settings.guard_uid == os.geteuid() or not hasattr(socket, 'SO_PEERCRED'):
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            deadline = time.monotonic() + 1
            peer.settimeout(1)
            peer.connect(settings.socket_path)
            credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('=iII'))
            if struct.unpack('=iII', credentials)[1] != settings.guard_uid:
                return False
            peer.shutdown(socket.SHUT_WR)  # no artifact, run, variant or bytes to execute
            result = bytearray()
            while len(result) <= 128:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                peer.settimeout(remaining)
                chunk = peer.recv(129 - len(result))
                if not chunk:
                    break
                result.extend(chunk)
            if len(result) > 128:
                return False
            return json.loads(result, object_pairs_hook=guard_client.unique_object) == {
                'status': 'error', 'reason': 'invalid_request'}
    except (OSError, ValueError, struct.error):
        return False


async def owners_ready(actor, verifier):
    state = await invoice_actor_client.health(actor)
    if (state['ready'] is not True or state['blocked'] is not False or state['obligations'] != 0
            or state['image_id'] is None
            or (actor.installation_id is not None and state['installation_id'] != actor.installation_id)
            or (actor.image_id is not None and state['image_id'] != actor.image_id)):
        return False
    return await asyncio.to_thread(guard_ready, verifier)


async def wait_for_owners(actor, verifier, *, timeout=WAIT_SECONDS):
    if actor is None or verifier is None or not verifier.durable:
        raise BootError('boot_configuration_unavailable')
    try:
        async with asyncio.timeout(timeout):
            while True:
                try:
                    if await owners_ready(actor, verifier):
                        return
                except (runner.RunnerError, OSError, ValueError):
                    pass  # owner startup may still be reconciling; never edit its state or release debt here
                await asyncio.sleep(POLL_SECONDS)
    except TimeoutError:
        raise BootError('owners_not_ready') from None


def main():
    try:
        actor = invoice_actor_client.settings_from_env()
        verifier = invoice_verification.settings_from_env()
        asyncio.run(wait_for_owners(actor, verifier))
    except (BootError, ValueError):
        print('sc2_boot_unavailable', file=sys.stderr)
        return 2
    # Normal main.startup does init_db/interrupted-run recovery and exact receipt reconciliation before serving.
    os.execv(sys.executable, [sys.executable, *UVICORN_ARGS])


if __name__ == '__main__':
    raise SystemExit(main())

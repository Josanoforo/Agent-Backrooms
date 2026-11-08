"""Local client for the invoice verifier guard. Runs without daemon privileges."""

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import stat
import struct
import time


MAX_ARTIFACT = 4096
MAX_RESPONSE = 2048
DIGEST = re.compile(r'[a-f0-9]{64}')


class GuardError(Exception):
    pass


def unique_object(items):
    result = dict(items)
    if len(result) != len(items):
        raise ValueError('duplicate key')
    return result


def request_binding(run_id, variant):
    if run_id is None and variant is None:
        return {}
    if (not isinstance(run_id, str) or not re.fullmatch(r'[0-9a-f]{32}', run_id)
            or not isinstance(variant, str) or variant not in ('legitimate', 'perturbed')):
        raise GuardError('invalid_request_binding')
    return {'run_id': run_id, 'variant': variant}


def verify(path, guard_uid, artifact, *, timeout=70, run_id=None, variant=None):
    binding = request_binding(run_id, variant)
    if not hasattr(socket, 'SO_PEERCRED'):
        raise GuardError('linux_peer_credentials_required')
    if guard_uid == os.geteuid():
        raise GuardError('guard_uid_must_differ')
    if len(artifact) > MAX_ARTIFACT:
        raise GuardError('artifact_too_large')
    digest = hashlib.sha256(artifact).hexdigest()
    request = {'artifact_b64': base64.b64encode(artifact).decode('ascii'), 'artifact_sha256': digest, **binding}
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        try:
            peer.settimeout(timeout)
            peer.connect(path)
            credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('=iII'))
            if struct.unpack('=iII', credentials)[1] != guard_uid:
                raise GuardError('unexpected_guard_uid')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            peer.settimeout(remaining)
            peer.sendall(json.dumps(request, separators=(',', ':')).encode('ascii'))
            peer.shutdown(socket.SHUT_WR)
            response = bytearray()
            while len(response) <= MAX_RESPONSE:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                peer.settimeout(remaining)
                chunk = peer.recv(MAX_RESPONSE + 1 - len(response))
                if not chunk:
                    break
                response.extend(chunk)
        except OSError as exc:
            raise GuardError('guard_unavailable') from exc
    if len(response) > MAX_RESPONSE or response.count(b'\n') != 1 or not response.endswith(b'\n'):
        raise GuardError('invalid_guard_response')
    try:
        result = json.loads(response, object_pairs_hook=unique_object)
    except (ValueError, RecursionError) as exc:
        raise GuardError('invalid_guard_response') from exc
    if not isinstance(result, dict):
        raise GuardError('invalid_guard_response')
    status = result.get('status')
    if status == 'error' and set(result) == {'status', 'reason'}:
        reason = result['reason']
        if isinstance(reason, str) and re.fullmatch(r'[a-z][a-z0-9_]{0,79}', reason):
            raise GuardError(reason)
    digests = {'artifact_sha256', 'input_sha256', 'verifier_sha256', 'container_id'}
    if (status not in ('passed', 'rejected') or set(result) != digests | {'status', 'cleanup_confirmed'}
            or result['cleanup_confirmed'] is not True or result['artifact_sha256'] != digest
            or any(not isinstance(result[key], str) or not DIGEST.fullmatch(result[key]) for key in digests)):
        raise GuardError('invalid_guard_response')
    return result


def read_artifact(path):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), 'rb') as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise GuardError('invalid_artifact_file')
        return source.read(MAX_ARTIFACT + 1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True)
    parser.add_argument('--guard-uid', required=True, type=int)
    parser.add_argument('--artifact', required=True)
    args = parser.parse_args(argv)
    try:
        if not hasattr(socket, 'SO_PEERCRED'):
            raise GuardError('linux_peer_credentials_required')
        result = verify(args.socket, args.guard_uid, read_artifact(args.artifact))
    except (GuardError, OSError) as exc:
        reason = str(exc) if isinstance(exc, GuardError) else 'invalid_artifact_file'
        print(json.dumps({'status': 'error', 'reason': reason}, separators=(',', ':')))
        return 2
    print(json.dumps(result, separators=(',', ':')))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())

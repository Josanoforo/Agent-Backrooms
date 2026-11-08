"""Optional handoff from the invoice workflow to the independent local verifier."""

import asyncio
import base64
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re

from . import guard_client, invoice_verifier, runner


SOCKET_ENV = 'ESCAPE_INVOICE_VERIFIER_SOCKET'
UID_ENV = 'ESCAPE_INVOICE_VERIFIER_UID'
DURABLE_ENV = 'ESCAPE_INVOICE_VERIFIER_DURABLE'
SCHEMA = 'invoice-independent/v1'
MAX_ARTIFACT_BYTES = invoice_verifier.MAX_ARTIFACT_BYTES
CAPTURE_OUTPUT_LIMIT = 4 * ((MAX_ARTIFACT_BYTES + 3) // 3) + 1
ARTIFACT_CAPTURE_SCRIPT = '''
import base64
import os
import stat
import sys


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def capture():
    directory = os.open('/work', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        entry = os.stat('result.json', dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(entry.st_mode):
            raise OSError
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        with os.fdopen(os.open('result.json', flags, dir_fd=directory), 'rb') as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or identity(before) != identity(entry):
                raise OSError
            data = source.read(4097)
            if identity(os.fstat(source.fileno())) != identity(before) or len(data) != min(before.st_size, 4097):
                raise OSError
    finally:
        os.close(directory)
    return data


try:
    data = capture()
except OSError:
    raise SystemExit(1)
sys.stdout.buffer.write(base64.b64encode(data))
'''

UNAVAILABLE_REASONS = frozenset({
    'task_probe_unavailable', 'artifact_capture_failed', 'artifact_too_large', 'artifact_invalid_encoding',
    'artifact_observation_mismatch', 'artifact_sensitive', 'actor_task_not_passed', 'actor_cleanup_unconfirmed',
    'guard_unavailable', 'guard_peer_unverified', 'guard_response_invalid', 'guard_reference_mismatch', 'guard_binding_invalid',
})
PEER_ERRORS = frozenset({'linux_peer_credentials_required', 'guard_uid_must_differ', 'unexpected_guard_uid'})
DIGEST_KEYS = ('artifact_sha256', 'input_sha256', 'verifier_sha256', 'container_id')


@dataclass(frozen=True)
class Settings:
    socket_path: str
    guard_uid: int
    durable: bool = False


def settings_from_env():
    path = os.environ.get(SOCKET_ENV)
    uid_text = os.environ.get(UID_ENV)
    durable = os.environ.get(DURABLE_ENV, '0')
    if durable not in ('0', '1'):
        raise ValueError('invalid invoice verifier settings')
    if path is None and uid_text is None and durable == '0':
        return None
    try:
        valid_path = (path is not None and path.startswith('/') and len(path.encode('utf-8')) <= 107
                      and not any(part in ('', '.', '..') for part in path.split('/')[1:])
                      and not any(ord(char) < 32 or ord(char) == 127 for char in path))
    except UnicodeError:
        valid_path = False
    get_uid = getattr(os, 'geteuid', None)
    if not valid_path or uid_text is None or not re.fullmatch(r'[1-9][0-9]{0,9}', uid_text) or get_uid is None:
        raise ValueError('invalid invoice verifier settings')
    uid = int(uid_text)
    if uid >= 2**32 - 1 or uid == get_uid():
        raise ValueError('invalid invoice verifier settings')
    return Settings(path, uid, durable=durable == '1')


def unavailable(reason):
    if reason not in UNAVAILABLE_REASONS:
        raise ValueError('invalid invoice verification reason')
    return {'schema': SCHEMA, 'status': 'unavailable', 'reason': reason}


def successful_output(probe):
    return (isinstance(probe, dict) and type(probe.get('exit_code')) is int and probe['exit_code'] == 0
            and isinstance(probe.get('stdout'), str))


async def capture(sandbox, task_probe):
    """Read only the fixed result path and bind its raw bytes to the previous task probe."""
    if not successful_output(task_probe):
        return None, 'task_probe_unavailable'
    try:
        result = await sandbox.exec_fixed(ARTIFACT_CAPTURE_SCRIPT, output_limit=CAPTURE_OUTPUT_LIMIT)
    except runner.RunnerError:
        return None, 'artifact_capture_failed'
    if not successful_output(result) or len(result['stdout']) >= CAPTURE_OUTPUT_LIMIT:
        return None, 'artifact_capture_failed'
    try:
        encoded = result['stdout'].encode('ascii')
        artifact = base64.b64decode(encoded, validate=True)
        if base64.b64encode(artifact) != encoded:
            return None, 'artifact_invalid_encoding'
        if len(artifact) > MAX_ARTIFACT_BYTES:
            return None, 'artifact_too_large'
        text = artifact.decode('utf-8')
    except (ValueError, UnicodeError):
        return None, 'artifact_invalid_encoding'
    if text != task_probe['stdout']:
        return None, 'artifact_observation_mismatch'
    return artifact, None


async def attest(settings, artifact, *, run_id=None, variant=None):
    """Return only digests and a verifier identity after a successful guard exchange."""
    binding = {}
    if settings.durable:
        try:
            binding = guard_client.request_binding(run_id, variant)
        except guard_client.GuardError:
            return unavailable('guard_binding_invalid')
        if not binding:
            return unavailable('guard_binding_invalid')
    if not isinstance(artifact, bytes):
        return unavailable('artifact_invalid_encoding')
    if len(artifact) > MAX_ARTIFACT_BYTES:
        return unavailable('artifact_too_large')
    try:
        artifact.decode('utf-8')
    except UnicodeError:
        return unavailable('artifact_invalid_encoding')
    try:
        source_digest = hashlib.sha256(Path(invoice_verifier.__file__).read_bytes()).hexdigest()
    except OSError:
        return unavailable('guard_reference_mismatch')
    try:
        result = await asyncio.to_thread(guard_client.verify, settings.socket_path, settings.guard_uid, artifact, **binding)
    except guard_client.GuardError as exc:
        code = str(exc)
        if code in PEER_ERRORS:
            return unavailable('guard_peer_unverified')
        if code == 'invalid_guard_response':
            return unavailable('guard_response_invalid')
        return unavailable('guard_unavailable')
    except OSError:
        return unavailable('guard_unavailable')
    if (not isinstance(result, dict) or set(result) != {*DIGEST_KEYS, 'status', 'cleanup_confirmed'}
            or result['status'] not in ('passed', 'rejected') or result['cleanup_confirmed'] is not True
            or any(not isinstance(result[key], str) or not guard_client.DIGEST.fullmatch(result[key]) for key in DIGEST_KEYS)
            or result['artifact_sha256'] != hashlib.sha256(artifact).hexdigest()):
        return unavailable('guard_response_invalid')
    if result['input_sha256'] != invoice_verifier.INPUT_SHA256 or result['verifier_sha256'] != source_digest:
        return unavailable('guard_reference_mismatch')
    return {'schema': SCHEMA, 'status': result['status'],
            **{key: result[key] for key in DIGEST_KEYS}, 'cleanup_confirmed': True}

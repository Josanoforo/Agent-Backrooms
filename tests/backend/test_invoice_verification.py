"""Local checks for the fixed artifact capture and independent verifier receipt."""

import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import threading
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from services.agent import guard_client, invoice_verification as verification, invoice_verifier, runner


ARTIFACT = b'{"amount":42}\r\n'
SETTINGS = verification.Settings('/run/escape/guard.sock', 2000)


@pytest.fixture(autouse=True)
def clear_durable_opt_in(monkeypatch):
    monkeypatch.delenv(verification.DURABLE_ENV, raising=False)


@pytest.mark.parametrize(('path', 'uid', 'valid'), [
    (None, None, True), ('/run/escape/guard.sock', '2000', True), ('/run/escape/guard.sock', None, False),
    (None, '2000', False), ('relative.sock', '2000', False), ('//host/guard.sock', '2000', False),
    ('/run/../guard.sock', '2000', False), ('/run/./guard.sock', '2000', False),
    ('/run/guard.sock/', '2000', False), ('/' + 'x' * 107, '2000', False),
    ('/run/guard\n.sock', '2000', False), ('/run/guard.sock', '0', False),
    ('/run/guard.sock', '1000', False), ('/run/guard.sock', '-1', False),
    ('/run/guard.sock', '4294967295', False), ('/run/guard.sock', ' 2000', False),
])
def test_opt_in_settings_validate_local_path_and_distinct_nonroot_uid(monkeypatch, path, uid, valid):
    monkeypatch.setattr(verification.os, 'geteuid', lambda: 1000, raising=False)
    for key, value in ((verification.SOCKET_ENV, path), (verification.UID_ENV, uid)):
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)
    if valid:
        assert verification.settings_from_env() == (SETTINGS if path else None)
    else:
        with pytest.raises(ValueError, match='^invalid invoice verifier settings$'):
            verification.settings_from_env()


@pytest.mark.parametrize(('value', 'configured', 'valid'), [
    ('0', False, True), ('0', True, True), ('1', True, True), ('1', False, False),
    ('', True, False), ('true', True, False), ('01', True, False), ('2', False, False),
])
def test_durable_opt_in_is_exact_and_requires_existing_settings(monkeypatch, value, configured, valid):
    monkeypatch.setattr(verification.os, 'geteuid', lambda: 1000, raising=False)
    monkeypatch.setenv(verification.DURABLE_ENV, value)
    for key, setting in ((verification.SOCKET_ENV, SETTINGS.socket_path), (verification.UID_ENV, '2000')):
        if configured:
            monkeypatch.setenv(key, setting)
        else:
            monkeypatch.delenv(key, raising=False)
    if not valid:
        with pytest.raises(ValueError, match='^invalid invoice verifier settings$'):
            verification.settings_from_env()
    elif configured:
        assert verification.settings_from_env() == verification.Settings(SETTINGS.socket_path, 2000, value == '1')
    else:
        assert verification.settings_from_env() is None


def probe(artifact=ARTIFACT):
    return {'exit_code': 0, 'stdout': artifact.decode('utf-8')}


def encoded(artifact):
    return probe(base64.b64encode(artifact))


def test_capture_uses_fixed_script_and_retains_exact_bytes():
    sandbox = AsyncMock()
    largest = b'x' * (verification.MAX_ARTIFACT_BYTES - len(ARTIFACT)) + ARTIFACT
    sandbox.exec_fixed.return_value = encoded(largest)
    assert asyncio.run(verification.capture(sandbox, probe(largest))) == (largest, None)
    sandbox.exec_fixed.assert_awaited_once_with(verification.ARTIFACT_CAPTURE_SCRIPT,
                                                output_limit=verification.CAPTURE_OUTPUT_LIMIT)
    assert verification.CAPTURE_OUTPUT_LIMIT > len(encoded(largest)['stdout']) > runner.OUTPUT_LIMIT


@pytest.mark.parametrize('legacy', [None, {'exit_code': 1, 'stdout': ''}, {'exit_code': False, 'stdout': ''},
                                    {'exit_code': 0, 'stdout': b''}])
def test_unavailable_legacy_probe_never_reopens_result(legacy):
    sandbox = AsyncMock()
    assert asyncio.run(verification.capture(sandbox, legacy)) == (None, 'task_probe_unavailable')
    sandbox.exec_fixed.assert_not_awaited()


@pytest.mark.parametrize(('result', 'reason'), [
    ({'exit_code': 1, 'stdout': '', 'stderr': 'private path'}, 'artifact_capture_failed'),
    (probe(b'A' * verification.CAPTURE_OUTPUT_LIMIT), 'artifact_capture_failed'),
    (probe(b'!!!!'), 'artifact_invalid_encoding'), (probe(b'YR=='), 'artifact_invalid_encoding'),
    (encoded(b'\xff'), 'artifact_invalid_encoding'),
    (encoded(b'x' * (verification.MAX_ARTIFACT_BYTES + 1)), 'artifact_too_large'),
    (encoded(ARTIFACT.replace(b'\r\n', b'\n')), 'artifact_observation_mismatch'),
])
def test_capture_rejects_unsafe_or_mismatched_output(result, reason):
    sandbox = AsyncMock()
    sandbox.exec_fixed.return_value = result
    assert asyncio.run(verification.capture(sandbox, probe())) == (None, reason)


def test_capture_suppresses_runner_error_but_propagates_cancellation():
    sandbox = AsyncMock()
    sandbox.exec_fixed.side_effect = runner.RunnerError('private diagnostic')
    assert asyncio.run(verification.capture(sandbox, probe())) == (None, 'artifact_capture_failed')
    sandbox.exec_fixed.side_effect = asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(verification.capture(sandbox, probe()))


@pytest.mark.skipif(os.name != 'posix', reason='fixed capture uses Linux file-descriptor flags')
def test_fixed_reader_uses_regular_files_and_refuses_symlinks_and_fifos(tmp_path):
    bootstrap = '''
import os, sys
open_real = os.open
def open_fixture(name, flags, *args, **kwargs):
    return open_real(sys.argv[1] if name == '/work' else name, flags, *args, **kwargs)
os.open = open_fixture
exec(sys.argv[2], {'__name__': '__main__'})
'''

    def invoke():
        return subprocess.run([sys.executable, '-I', '-S', '-c', bootstrap, str(tmp_path),
                               verification.ARTIFACT_CAPTURE_SCRIPT], capture_output=True, timeout=5)

    result = tmp_path / 'result.json'
    payload = b'x' * 4098
    result.write_bytes(payload)
    completed = invoke()
    assert completed.returncode == 0 and base64.b64decode(completed.stdout, validate=True) == payload[:4097]
    target = tmp_path / 'target.json'
    result.rename(target)
    result.symlink_to(target)
    completed = invoke()
    assert completed.returncode != 0 and completed.stdout == b''
    result.unlink()
    os.mkfifo(result)
    completed = invoke()
    assert completed.returncode != 0 and completed.stdout == b''


def guard_response(status='passed', **overrides):
    return {'status': status, 'artifact_sha256': hashlib.sha256(ARTIFACT).hexdigest(),
            'input_sha256': invoice_verifier.INPUT_SHA256,
            'verifier_sha256': hashlib.sha256(Path(invoice_verifier.__file__).read_bytes()).hexdigest(),
            'container_id': 'c' * 64, 'cleanup_confirmed': True, **overrides}


@pytest.mark.parametrize('status', ['passed', 'rejected'])
def test_attest_preserves_verdict_with_bound_digests_and_cleanup(monkeypatch, status):
    thread = threading.get_ident()
    expected = guard_response(status)

    def verify(path, uid, artifact):
        assert threading.get_ident() != thread
        assert (path, uid, artifact) == (SETTINGS.socket_path, SETTINGS.guard_uid, ARTIFACT)
        return expected

    monkeypatch.setattr(guard_client, 'verify', verify)
    assert asyncio.run(verification.attest(SETTINGS, ARTIFACT)) == {'schema': verification.SCHEMA, **expected}


@pytest.mark.parametrize('variant', ['legitimate', 'perturbed'])
def test_durable_attest_passes_binding_and_retains_public_receipt(monkeypatch, variant):
    client = Mock(return_value=guard_response())
    monkeypatch.setattr(guard_client, 'verify', client)
    settings = verification.Settings(SETTINGS.socket_path, SETTINGS.guard_uid, durable=True)
    assert asyncio.run(verification.attest(settings, ARTIFACT, run_id='a' * 32, variant=variant)) == {
        'schema': verification.SCHEMA, **guard_response(),
    }
    client.assert_called_once_with(SETTINGS.socket_path, SETTINGS.guard_uid, ARTIFACT,
                                   run_id='a' * 32, variant=variant)


@pytest.mark.parametrize(('run_id', 'variant'), [
    (None, None), ('a' * 32, None), (None, 'legitimate'), ('A' * 32, 'legitimate'),
    ('a' * 31, 'legitimate'), ('a' * 32, 'other'), (False, 'perturbed'),
])
def test_durable_attest_rejects_invalid_binding_without_guard(monkeypatch, run_id, variant):
    client = Mock()
    monkeypatch.setattr(guard_client, 'verify', client)
    settings = verification.Settings(SETTINGS.socket_path, SETTINGS.guard_uid, durable=True)
    assert asyncio.run(verification.attest(settings, ARTIFACT, run_id=run_id, variant=variant)) == {
        'schema': verification.SCHEMA, 'status': 'unavailable', 'reason': 'guard_binding_invalid',
    }
    client.assert_not_called()


def test_legacy_attest_does_not_forward_binding_keywords(monkeypatch):
    def client(path, uid, artifact):
        assert (path, uid, artifact) == (SETTINGS.socket_path, SETTINGS.guard_uid, ARTIFACT)
        return guard_response()

    monkeypatch.setattr(guard_client, 'verify', client)
    assert asyncio.run(verification.attest(SETTINGS, ARTIFACT, run_id='a' * 32, variant='legitimate')) == {
        'schema': verification.SCHEMA, **guard_response(),
    }


@pytest.mark.parametrize('binding', [{}, {'run_id': 'a' * 32, 'variant': 'legitimate'},
                                   {'run_id': 'b' * 32, 'variant': 'perturbed'}])
def test_guard_client_wire_shape_preserves_legacy_and_optional_binding(monkeypatch, binding):
    peer = MagicMock()
    peer.__enter__.return_value = peer
    peer.getsockopt.return_value = struct.pack('=iII', 123, 2000, 2000)
    peer.recv.side_effect = [json.dumps(guard_response()).encode('ascii') + b'\n', b'']
    monkeypatch.setattr(guard_client.socket, 'AF_UNIX', 1, raising=False)
    monkeypatch.setattr(guard_client.socket, 'SO_PEERCRED', 17, raising=False)
    monkeypatch.setattr(guard_client.os, 'geteuid', lambda: 1000, raising=False)
    monkeypatch.setattr(guard_client.socket, 'socket', Mock(return_value=peer))
    assert guard_client.verify(SETTINGS.socket_path, SETTINGS.guard_uid, ARTIFACT, **binding) == guard_response()
    sent = json.loads(peer.sendall.call_args.args[0])
    assert sent == {'artifact_b64': base64.b64encode(ARTIFACT).decode('ascii'),
                    'artifact_sha256': hashlib.sha256(ARTIFACT).hexdigest(), **binding}
    peer.sendall.assert_called_once()


@pytest.mark.parametrize(('run_id', 'variant'), [
    ('a' * 32, None), (None, 'legitimate'), ('A' * 32, 'legitimate'),
    ('a' * 33, 'legitimate'), ('a' * 32, 'other'), (['a' * 32], 'perturbed'),
])
def test_guard_client_rejects_binding_before_any_io(monkeypatch, run_id, variant):
    socket = Mock()
    monkeypatch.setattr(guard_client.socket, 'socket', socket)
    with pytest.raises(guard_client.GuardError, match='^invalid_request_binding$'):
        guard_client.verify(SETTINGS.socket_path, SETTINGS.guard_uid, ARTIFACT, run_id=run_id, variant=variant)
    socket.assert_not_called()


@pytest.mark.parametrize(('overrides', 'reason'), [
    ({'input_sha256': 'e' * 64}, 'guard_reference_mismatch'),
    ({'verifier_sha256': 'e' * 64}, 'guard_reference_mismatch'),
    ({'artifact_sha256': 'e' * 64}, 'guard_response_invalid'),
    ({'container_id': '/private/socket'}, 'guard_response_invalid'),
    ({'cleanup_confirmed': False}, 'guard_response_invalid'),
    ({'cleanup_confirmed': 1}, 'guard_response_invalid'),
    ({'secret': '/private/path'}, 'guard_response_invalid'),
])
def test_attest_fails_closed_for_malformed_response_or_drift(monkeypatch, overrides, reason):
    monkeypatch.setattr(guard_client, 'verify', lambda *_: guard_response(**overrides))
    assert asyncio.run(verification.attest(SETTINGS, ARTIFACT)) == {
        'schema': verification.SCHEMA, 'status': 'unavailable', 'reason': reason,
    }


@pytest.mark.parametrize(('error', 'reason'), [
    (guard_client.GuardError('unexpected_guard_uid'), 'guard_peer_unverified'),
    (guard_client.GuardError('invalid_guard_response'), 'guard_response_invalid'),
    (guard_client.GuardError('internal /private/socket'), 'guard_unavailable'),
    (TimeoutError('internal /private/socket'), 'guard_unavailable'),
])
def test_attest_exposes_only_closed_reasons(monkeypatch, error, reason):
    def fail(*_):
        raise error

    monkeypatch.setattr(guard_client, 'verify', fail)
    assert asyncio.run(verification.attest(SETTINGS, ARTIFACT)) == {
        'schema': verification.SCHEMA, 'status': 'unavailable', 'reason': reason,
    }


@pytest.mark.parametrize(('artifact', 'reason'), [
    ('text', 'artifact_invalid_encoding'), (b'\xff', 'artifact_invalid_encoding'),
    (b'x' * 4097, 'artifact_too_large'),
])
def test_invalid_artifact_never_contacts_guard(monkeypatch, artifact, reason):
    def unexpected(*_):
        pytest.fail('guard must not receive this artifact')

    monkeypatch.setattr(guard_client, 'verify', unexpected)
    assert asyncio.run(verification.attest(SETTINGS, artifact)) == verification.unavailable(reason)


def test_unavailable_receipts_reject_unrecognized_reason():
    with pytest.raises(ValueError, match='^invalid invoice verification reason$'):
        verification.unavailable('/private/path')
    for reason in ('actor_task_not_passed', 'artifact_sensitive', 'actor_cleanup_unconfirmed'):
        assert verification.unavailable(reason) == {
            'schema': verification.SCHEMA, 'status': 'unavailable', 'reason': reason,
        }


def test_cli_opt_in_extends_capture_and_preserves_normal_default(monkeypatch):
    async def run():
        payload = b'x' * (verification.CAPTURE_OUTPUT_LIMIT + 100)

        async def process(*_, **_kwargs):
            class Process:
                returncode = 0
                wait = AsyncMock()
                stdout = asyncio.StreamReader()
                stderr = asyncio.StreamReader()

            proc = Process()
            for stream in (proc.stdout, proc.stderr):
                stream.feed_data(payload)
                stream.feed_eof()
            return proc

        monkeypatch.setattr(runner.asyncio, 'create_subprocess_exec', process)
        default = await runner._cli('exec')
        extended = await runner._cli('exec', output_limit=verification.CAPTURE_OUTPUT_LIMIT)
        assert [len(item) for item in default[1:]] == [runner.OUTPUT_LIMIT] * 2
        assert [len(item) for item in extended[1:]] == [verification.CAPTURE_OUTPUT_LIMIT] * 2

    asyncio.run(run())


def test_exec_fixed_passes_output_limit_to_probe_only(monkeypatch):
    cli = AsyncMock(side_effect=[(0, 'encoded', ''), (0, 'true\n', '')])
    monkeypatch.setattr(runner, '_cli', cli)
    session = runner.Session()
    session.measure = AsyncMock(return_value={})
    result = asyncio.run(session.exec_fixed(verification.ARTIFACT_CAPTURE_SCRIPT,
                                            output_limit=verification.CAPTURE_OUTPUT_LIMIT))
    assert result == {'stdout': 'encoded', 'stderr': '', 'exit_code': 0}
    assert cli.await_args_list[0].kwargs == {'timeout': 10, 'output_limit': verification.CAPTURE_OUTPUT_LIMIT}
    assert cli.await_args_list[1].kwargs == {}

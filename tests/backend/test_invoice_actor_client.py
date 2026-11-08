"""Tests of services/agent/invoice_actor_client.py with a scripted owner double and a fake socket peer.

No Docker, no real socket, no subprocess. Authored without a shell: none of these tests has been executed by the author.
"""
import ast
import asyncio
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.agent import actor_wire as wire  # noqa: E402
from services.agent import invoice_actor_client as client  # noqa: E402
from services.agent import invoice_actor_protocol as proto  # noqa: E402
from services.agent import invoice_verification, runner  # noqa: E402

MODULE = ROOT / 'services' / 'agent' / 'invoice_actor_client.py'
RUN = '0123456789abcdef' * 2
HANDLE = 'ab' * 32
INSTALL = '1' * 32
INTENT = '2' * 32
CONTAINER = 'c' * 64
IMAGE = 'sha256:' + 'd' * 64
TMPFS = 'rw,noexec,nosuid,nodev,size=16m,mode=1777'
PROFILE = {
    'available': True, 'source': 'docker_inspect_after_start', 'scope': 'level_actor_container', 'image_id': IMAGE,
    'image_ref': 'python:3.12-alpine', 'network_mode': 'none', 'user': '65534:65534', 'read_only': True, 'privileged': False,
    'cap_add': [], 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges'], 'no_new_privileges': True,
    'memory_bytes': 256 * 1024 ** 2, 'memory_swap_bytes': 256 * 1024 ** 2, 'nano_cpus': 10 ** 9, 'pids_limit': 64,
    'tmpfs': {'/tmp': TMPFS, '/work': TMPFS}, 'mount_types': [], 'runtime': 'runc',
}
MEAS = {'memory_peak_bytes': 4096, 'memory_observed_max_bytes': None,
        'memory_measurement': {'source': 'cgroup_v2_memory.peak', 'scope': 'level_container', 'kind': 'peak', 'available': True}}
SETTINGS = client.Settings('/run/agent-escape-actor/broker.sock', 2000)


def raw(obj):
    return json.dumps(obj, separators=(',', ':')).encode()


class FakeOwner:
    """Scripted owner. It answers with the wire encoders, and can fail, refuse, answer garbage or wait on a gate."""

    def __init__(self):
        self.calls = []
        self.health = {'ready': True, 'image_id': IMAGE, 'installation_id': INSTALL, 'obligations': 0, 'blocked': False}
        self.profile = dict(PROFILE)
        self.sha = runner.profile_digest(PROFILE)
        self.open_patch, self.close_patch = {}, {}
        self.errors, self.refuse, self.gates = {}, {}, {}
        self.close_failures = 0
        self.identity = None
        self.finished = set()       # durable FINISH identities: they outlive every session, like the owner's diary
        self.lost_after_finish = 0  # closes that reach FINISH and then lose their answer
        self.receipt_patch = {}

    def key(self):
        return tuple(self.identity[name] for name in wire.IDENTITY_FIELDS)

    @property
    def ops(self):
        return [op for op, _ in self.calls]

    async def __call__(self, settings, payload, *, response_limit, deadline):
        request = proto.decode_request(payload)  # the owner applies the round21 decoder to every payload
        self.calls.append((request.op, request))
        failure = self.errors.get(request.op)
        if isinstance(failure, BaseException):
            raise failure
        if isinstance(failure, bytes):
            return failure
        gate = self.gates.get(request.op)
        if gate is not None:
            await gate.wait()
        if request.op == 'close' and self.lost_after_finish > 0:
            self.lost_after_finish -= 1
            self.finished.add(self.key())  # the restitution completed and reached FINISH; only the answer is lost
            raise OSError('connection reset')
        if request.op == 'close' and self.close_failures > 0:
            self.close_failures -= 1
            raise OSError('connection reset')
        if request.op in self.refuse:
            reason, extras = self.refuse[request.op]
            return wire.error_response(reason, **extras)
        return getattr(self, 'on_' + request.op)(request)

    def on_health(self, request):
        return wire.encode_response('health', self.health)

    def on_open(self, request):
        body = {'handle': HANDLE, 'installation_id': INSTALL, 'run_id': request.run_id, 'variant': request.variant,
                'intent_id': INTENT, 'name': 'escape-actor-' + INTENT, 'container_id': CONTAINER,
                'profile_sha256': self.sha, 'profile': self.profile, **self.open_patch}
        self.identity = {key: body[key] for key in wire.IDENTITY_FIELDS}
        return wire.encode_response('open', body)

    def on_execute(self, request):
        return wire.encode_response('execute', {'stdout': 'ran', 'stderr': '', 'exit_code': 0, **MEAS})

    def on_probe(self, request):
        if request.name == 'measure':
            return wire.encode_response('probe', dict(MEAS))
        return wire.encode_response('probe', {'stdout': 'probe:' + request.name, 'stderr': '', 'exit_code': 0, **MEAS})

    def on_close(self, request):
        self.finished.add(self.key())
        return wire.encode_response('close', {**self.identity, 'cleanup_confirmed': True, 'oom_killed': False, **MEAS,
                                              **self.close_patch})

    def on_receipt(self, request):
        asked = {name: getattr(request, name) for name in wire.IDENTITY_FIELDS}
        confirmed = tuple(asked[name] for name in wire.IDENTITY_FIELDS) in self.finished
        return wire.encode_response('receipt', {**asked, 'status': 'confirmed' if confirmed else 'unknown',
                                                'cleanup_confirmed': confirmed, **self.receipt_patch})


IDENTITY = {'installation_id': INSTALL, 'run_id': RUN, 'variant': 'legitimate', 'intent_id': INTENT, 'container_id': CONTAINER}
RUN2 = 'fedcba9876543210' * 2
SECOND = {'run_id': RUN2, 'intent_id': '3' * 32, 'name': 'escape-actor-' + '3' * 32, 'container_id': 'd' * 64}  # a later run


class ClientCase(unittest.IsolatedAsyncioTestCase):
    def session(self, owner, settings=SETTINGS, **kwargs):
        return client.ActorSession(settings, run_id=kwargs.pop('run_id', RUN), variant=kwargs.pop('variant', 'legitimate'),
                                   transport=owner)

    async def wait_for_op(self, owner, op):
        for _ in range(500):
            if op in owner.ops:
                return
            await asyncio.sleep(0.001)
        self.fail('owner never received ' + op)


class SettingsTests(unittest.TestCase):
    PATH = '/run/agent-escape-actor/broker.sock'

    def load(self, env, euid=1000):
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(os, 'geteuid', lambda: euid, create=True):
            return client.settings_from_env()

    def test_absent_configuration_is_none_and_valid_one_is_exact(self):
        self.assertIsNone(self.load({}))
        self.assertEqual(self.load({client.SOCKET_ENV: self.PATH, client.UID_ENV: '2000'}), client.Settings(self.PATH, 2000))

    def test_partial_or_invalid_configuration_is_refused(self):
        for env in ({client.SOCKET_ENV: self.PATH}, {client.UID_ENV: '2000'},
                    *({client.SOCKET_ENV: path, client.UID_ENV: '2000'} for path in (
                        '', 'relative.sock', '/run/../x', '/run//x', '/run/x\x01', '/' + 'a' * 110)),
                    *({client.SOCKET_ENV: self.PATH, client.UID_ENV: uid} for uid in (
                        '0', '01', 'abc', '-1', '4294967295', '2000 ', ''))):
            with self.subTest(env=env):
                with self.assertRaises(ValueError):
                    self.load(env)

    def test_the_owner_is_neither_this_process_nor_the_verifier_guard(self):
        with self.assertRaises(ValueError):
            self.load({client.SOCKET_ENV: self.PATH, client.UID_ENV: '2000'}, euid=2000)
        with self.assertRaises(ValueError):
            self.load({client.SOCKET_ENV: self.PATH, client.UID_ENV: '2000', invoice_verification.UID_ENV: '2000'})
        with self.assertRaises(ValueError):
            self.load({client.SOCKET_ENV: self.PATH, client.UID_ENV: '2000', invoice_verification.SOCKET_ENV: self.PATH})
        self.assertEqual(self.load({client.SOCKET_ENV: self.PATH, client.UID_ENV: '2000',
                                    invoice_verification.UID_ENV: '3000'}).owner_uid, 2000)


class ProfileFixtureTests(unittest.TestCase):
    def test_fixture_profile_is_the_hardened_profile(self):
        self.assertEqual(runner.hardened_violations(PROFILE), [])
        self.assertEqual(len(runner.profile_digest(PROFILE)), 64)


class HealthTests(ClientCase):
    async def test_health_is_validated_and_does_not_open_anything(self):
        owner = FakeOwner()
        info = await client.health(SETTINGS, transport=owner)
        self.assertEqual((info['ready'], info['blocked'], info['obligations']), (True, False, 0))
        self.assertEqual(owner.ops, ['health'])

    async def test_failures_have_closed_reasons_and_current_texts(self):
        cases = (
            (OSError('refused'), 'owner_unavailable', 'Actor controller unavailable'),
            (TimeoutError(), 'owner_unavailable', 'Actor controller unavailable'),
            (wire.WireError('timeout'), 'owner_unavailable', 'Actor controller unavailable'),
            (wire.WireError('peer_mismatch'), 'owner_peer_unverified', 'Actor controller identity not verified'),
            (wire.WireError('linux_peer_credentials_required'), 'owner_peer_unverified', 'Actor controller identity not verified'),
            (wire.WireError('truncated'), 'owner_response_invalid', 'Actor controller response invalid'),
            (wire.WireError('trailing_bytes'), 'owner_response_invalid', 'Actor controller response invalid'),
            (b'not json', 'owner_response_invalid', 'Actor controller response invalid'),
            (raw({'ok': True, 'op': 'health'}), 'owner_response_invalid', 'Actor controller response invalid'),
            (wire.error_response('framing'), 'framing', 'Actor controller refused: framing'),
        )
        for failure, reason, text in cases:
            with self.subTest(reason=reason, failure=repr(failure)[:30]):
                owner = FakeOwner()
                owner.errors['health'] = failure
                with self.assertRaises(client.ActorError) as caught:
                    await client.health(SETTINGS, transport=owner)
                self.assertEqual((caught.exception.reason, str(caught.exception)), (reason, text))
                self.assertIsInstance(caught.exception, runner.RunnerError)
                self.assertEqual(owner.ops, ['health'])  # one attempt, never repeated


class OpenTests(ClientCase):
    async def test_open_binds_receipt_and_close_confirms_with_the_same_identity(self):
        owner = FakeOwner()
        async with self.session(owner) as sandbox:
            self.assertEqual(owner.ops, ['health', 'open'])
            self.assertEqual(sandbox.name, 'escape-actor-' + INTENT)
            self.assertEqual((sandbox.created, sandbox.profile_captured, sandbox.cleanup_confirmed), (True, True, False))
            self.assertEqual(sandbox.profile, PROFILE)
            self.assertTrue(sandbox.obligation)
            self.assertEqual(sandbox.identity, owner.identity)
            self.assertNotIn(HANDLE, repr(sandbox))
            open_request = owner.calls[1][1]
            self.assertEqual((open_request.run_id, open_request.variant), (RUN, 'legitimate'))
        self.assertEqual(owner.ops, ['health', 'open', 'close'])
        self.assertEqual((sandbox.cleanup_confirmed, sandbox.created, sandbox.obligation, sandbox.oom_killed),
                         (True, False, False, False))
        self.assertEqual(sandbox.measurement, MEAS)

    async def test_binding_arguments_are_validated(self):
        for kwargs in ({'run_id': 'x', 'variant': 'legitimate'}, {'run_id': RUN, 'variant': 'actor'}):
            with self.assertRaises(ValueError):
                client.ActorSession(SETTINGS, **kwargs)

    async def test_owner_not_ready_or_blocked_opens_nothing(self):
        for patch, reason, text in (({'ready': False}, 'owner_not_ready', 'Actor controller refused: owner_not_ready'),
                                    ({'blocked': True}, 'owner_blocked', 'Actor controller is blocked by recovery'),
                                    ({'image_id': None}, 'image_mismatch', 'Actor controller refused: image_mismatch')):
            with self.subTest(reason=reason):
                owner = FakeOwner()
                owner.health.update(patch)
                with self.assertRaises(client.ActorError) as caught:
                    async with self.session(owner):
                        self.fail('must not enter')
                self.assertEqual((caught.exception.reason, str(caught.exception)), (reason, text))
                self.assertIsNone(caught.exception.cleanup_confirmed)  # no byte asked the owner to open anything
                self.assertEqual(owner.ops, ['health'])

    async def test_pinned_installation_or_image_must_match_health(self):
        for settings in (client.Settings(SETTINGS.socket_path, 2000, installation_id='9' * 32),
                         client.Settings(SETTINGS.socket_path, 2000, image_id='sha256:' + 'e' * 64)):
            owner = FakeOwner()
            with self.assertRaises(client.ActorError):
                async with self.session(owner, settings):
                    self.fail('must not enter')
            self.assertEqual(owner.ops, ['health'])

    async def test_owner_refusals_carry_the_owner_state(self):
        owner = FakeOwner()
        owner.refuse['open'] = ('capacity_exhausted', {})
        with self.assertRaises(client.ActorError) as caught:
            async with self.session(owner):
                self.fail('must not enter')
        self.assertEqual(str(caught.exception), 'Actor controller refused: capacity_exhausted')
        self.assertIsNone(caught.exception.cleanup_confirmed)
        owner = FakeOwner()
        owner.refuse['open'] = ('profile_rejected', {'cleanup_confirmed': True, 'violations': ['read_only']})
        with self.assertRaises(client.ActorError) as caught:
            async with self.session(owner):
                self.fail('must not enter')
        self.assertEqual(str(caught.exception),
                         'Sandbox effective profile does not meet the required profile: read_only')
        self.assertIs(caught.exception.cleanup_confirmed, True)
        self.assertEqual(owner.ops, ['health', 'open'])

    async def test_transport_failure_during_open_leaves_the_state_unknown_and_is_not_retried(self):
        owner = FakeOwner()
        owner.errors['open'] = OSError('reset')
        with self.assertRaises(client.ActorError) as caught:
            async with self.session(owner):
                self.fail('must not enter')
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('owner_unavailable', False))
        self.assertEqual(owner.ops, ['health', 'open'])
        owner = FakeOwner()
        owner.errors['open'] = wire.WireError('peer_mismatch')
        with self.assertRaises(client.ActorError) as caught:
            async with self.session(owner):
                self.fail('must not enter')
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('owner_peer_unverified', None))

    async def test_open_receipt_must_match_run_variant_installation_and_image(self):
        patches = ({'run_id': '9' * 32}, {'variant': 'perturbed'}, {'installation_id': '9' * 32},
                   {'name': 'escape-actor-' + '9' * 32}, {'handle': 'zz'}, {'profile': 'x'},
                   {'profile': {**PROFILE, 'image_id': 'sha256:' + 'e' * 64}})
        for patch in patches:
            with self.subTest(patch=str(patch)[:40]):
                owner = FakeOwner()
                owner.open_patch = patch
                with self.assertRaises(client.ActorError) as caught:
                    async with self.session(owner):
                        self.fail('must not enter')
                self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('owner_response_invalid', False))
                self.assertNotIn('close', owner.ops)  # the client holds no trusted handle to close
        owner = FakeOwner()
        owner.errors['open'] = b'garbage'
        with self.assertRaises(client.ActorError) as caught:
            async with self.session(owner):
                self.fail('must not enter')
        self.assertEqual(caught.exception.reason, 'owner_response_invalid')

    async def test_profile_is_reverified_and_a_violation_closes_the_handle(self):
        weak = {**PROFILE, 'read_only': False}
        owner = FakeOwner()
        owner.profile = weak
        with self.assertRaises(client.ActorError) as caught:
            async with self.session(owner):
                self.fail('must not enter')
        self.assertEqual(owner.ops, ['health', 'open', 'close'])
        self.assertEqual(str(caught.exception), 'Sandbox effective profile does not meet the required profile: read_only')
        self.assertIs(caught.exception.cleanup_confirmed, True)
        self.assertEqual(caught.exception.sandbox_profile, weak)

    async def test_profile_digest_mismatch_is_a_violation(self):
        owner = FakeOwner()
        owner.sha = '6' * 64
        with self.assertRaises(client.ActorError) as caught:
            async with self.session(owner):
                self.fail('must not enter')
        self.assertTrue(str(caught.exception).endswith('profile_digest'))
        self.assertEqual(owner.ops, ['health', 'open', 'close'])

    async def test_unconfirmed_cleanup_outranks_the_profile_violation(self):
        owner = FakeOwner()
        owner.profile = {**PROFILE, 'privileged': True}
        owner.close_failures = 1
        with self.assertRaises(client.ActorError) as caught:
            async with self.session(owner):
                self.fail('must not enter')
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('cleanup_unconfirmed', False))
        self.assertEqual(caught.exception.sandbox_profile['privileged'], True)

    async def test_cancellation_during_open_restores_a_granted_handle_then_propagates(self):
        owner = FakeOwner()
        owner.gates['open'] = asyncio.Event()
        sandbox = self.session(owner)
        task = asyncio.ensure_future(sandbox.__aenter__())
        await self.wait_for_op(owner, 'open')
        task.cancel()
        owner.gates['open'].set()
        with self.assertRaises(asyncio.CancelledError) as caught:
            await task
        self.assertEqual(owner.ops, ['health', 'open', 'close'])
        self.assertTrue(sandbox.cleanup_confirmed)
        self.assertIs(caught.exception.cleanup_confirmed, True)
        self.assertEqual(caught.exception.sandbox_profile, PROFILE)

    async def test_a_body_that_fails_still_closes(self):
        owner = FakeOwner()
        with self.assertRaises(RuntimeError):
            async with self.session(owner) as sandbox:
                raise RuntimeError('workflow failed')
        self.assertEqual(owner.ops, ['health', 'open', 'close'])
        self.assertTrue(sandbox.cleanup_confirmed)


class OperationTests(ClientCase):
    async def test_execute_returns_the_runner_shape_and_keeps_the_command_exact(self):
        owner = FakeOwner()
        async with self.session(owner) as sandbox:
            result = await sandbox.execute('cat -- /work/input.json')
            self.assertEqual(set(result), {'stdout', 'stderr', 'exit_code', *wire.MEASUREMENT_FIELDS})
            self.assertEqual((result['stdout'], result['exit_code']), ('ran', 0))
            self.assertEqual(sandbox.measurement, MEAS)
            request = owner.calls[-1][1]
            self.assertEqual((request.op, request.handle, request.command), ('execute', HANDLE, 'cat -- /work/input.json'))

    async def test_commands_at_the_byte_limit_travel_whole_and_beyond_it_never_leave(self):
        owner = FakeOwner()
        async with self.session(owner) as sandbox:
            await sandbox.execute('€' * 2730)
            self.assertEqual(owner.calls[-1][1].command, '€' * 2730)
            before = len(owner.calls)
            with self.assertRaises(client.ActorError) as caught:
                await sandbox.execute('€' * 2731)
            self.assertEqual(caught.exception.reason, 'command_too_large')
            self.assertEqual(len(owner.calls), before)  # refused locally, never truncated, never sent

    async def test_owner_refusals_map_to_the_current_texts(self):
        for reason, text in (('sandbox_stopped', 'Sandbox stopped during tool execution'),
                             ('exec_timeout', 'Docker command timed out'), ('busy', 'Actor controller refused: busy'),
                             ('closing', 'Actor controller refused: closing')):
            with self.subTest(reason=reason):
                owner = FakeOwner()
                owner.refuse['execute'] = (reason, {})
                async with self.session(owner) as sandbox:
                    with self.assertRaises(client.ActorError) as caught:
                        await sandbox.execute('true')
                    self.assertEqual((caught.exception.reason, str(caught.exception)), (reason, text))

    async def test_transport_failure_is_one_failure_and_the_action_is_not_replayed(self):
        owner = FakeOwner()
        owner.errors['execute'] = OSError('reset')
        async with self.session(owner) as sandbox:
            with self.assertRaises(client.ActorError) as caught:
                await sandbox.execute('touch /work/once')
            self.assertEqual(str(caught.exception), 'Actor controller unavailable')
            self.assertEqual(owner.ops.count('execute'), 1)
            self.assertNotIn('close', owner.ops)
        self.assertEqual(owner.ops.count('execute'), 1)
        self.assertEqual(owner.ops[-1], 'close')

    async def test_invalid_owner_output_is_refused(self):
        bad = ({'ok': True, 'op': 'execute', 'stdout': 1, 'stderr': '', 'exit_code': 0, **MEAS},
               {'ok': True, 'op': 'execute', 'stdout': 'x', 'stderr': '', 'exit_code': True, **MEAS},
               {'ok': True, 'op': 'probe', 'stdout': 'x', 'stderr': '', 'exit_code': 0, **MEAS},
               {'ok': True, 'op': 'execute', 'stdout': 'x', 'stderr': ''})
        for body in bad:
            with self.subTest(body=str(body)[:50]):
                owner = FakeOwner()
                owner.errors['execute'] = raw(body)
                async with self.session(owner) as sandbox:
                    with self.assertRaises(client.ActorError) as caught:
                        await sandbox.execute('true')
                    self.assertEqual(caught.exception.reason, 'owner_response_invalid')

    async def test_fixed_probes_by_name_and_the_registered_capture_script(self):
        owner = FakeOwner()
        async with self.session(owner) as sandbox:
            task = await sandbox.probe('task_result')
            self.assertEqual(task['stdout'], 'probe:task_result')
            capture = await sandbox.exec_fixed(invoice_verification.ARTIFACT_CAPTURE_SCRIPT,
                                               output_limit=invoice_verification.CAPTURE_OUTPUT_LIMIT)
            self.assertEqual((capture['stdout'], capture['exit_code']), ('probe:artifact_capture', 0))
            await sandbox.exec_fixed(invoice_verification.ARTIFACT_CAPTURE_SCRIPT)
            self.assertEqual(await sandbox.measure(), MEAS)
            self.assertEqual([request.name for op, request in owner.calls if op == 'probe'],
                             ['task_result', 'artifact_capture', 'artifact_capture', 'measure'])

    async def test_other_scripts_and_names_never_leave_the_controller(self):
        owner = FakeOwner()
        async with self.session(owner) as sandbox:
            before = len(owner.calls)
            for call in (lambda: sandbox.exec_fixed('print(1)'),
                         lambda: sandbox.exec_fixed(invoice_verification.ARTIFACT_CAPTURE_SCRIPT + ' ', output_limit=None),
                         lambda: sandbox.exec_fixed(invoice_verification.ARTIFACT_CAPTURE_SCRIPT, output_limit=1),
                         lambda: sandbox.probe('copy_scan')):
                with self.assertRaises(client.ActorError):
                    await call()
            self.assertEqual(len(owner.calls), before)

    async def test_operations_without_an_open_handle_are_refused_locally(self):
        owner = FakeOwner()
        sandbox = self.session(owner)
        with self.assertRaises(client.ActorError) as caught:
            await sandbox.execute('true')
        self.assertEqual(caught.exception.reason, 'unknown_handle')
        self.assertEqual(owner.ops, [])

    async def test_cancellation_during_execute_propagates_and_exit_still_restitutes(self):
        owner = FakeOwner()
        owner.gates['execute'] = asyncio.Event()
        async with self.session(owner) as sandbox:
            task = asyncio.ensure_future(sandbox.execute('sleep 99'))
            await self.wait_for_op(owner, 'execute')
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(owner.ops, ['health', 'open', 'execute', 'close'])
        self.assertTrue(sandbox.cleanup_confirmed)


class CloseTests(ClientCase):
    async def test_close_is_idempotent_once_confirmed(self):
        owner = FakeOwner()
        sandbox = self.session(owner)
        await sandbox.__aenter__()
        await sandbox.close()
        await sandbox.close()
        self.assertEqual(owner.ops.count('close'), 1)
        self.assertTrue(sandbox.cleanup_confirmed)

    async def test_lost_close_keeps_the_obligation_and_a_retry_restitutes_by_the_same_handle(self):
        owner = FakeOwner()
        owner.close_failures = 1
        sandbox = self.session(owner)
        await sandbox.__aenter__()
        with self.assertRaises(client.ActorError) as caught:
            await sandbox.close()
        self.assertEqual(str(caught.exception), 'Sandbox cleanup could not be confirmed')
        self.assertIs(caught.exception.cleanup_confirmed, False)
        self.assertEqual(caught.exception.owner_reason, 'owner_unavailable')
        self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (False, True))
        self.assertEqual(owner.ops.count('close'), 1)  # one attempt per call
        await sandbox.close()
        self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (True, False))
        self.assertEqual([request.handle for op, request in owner.calls if op == 'close'], [HANDLE, HANDLE])

    async def test_a_receipt_with_another_identity_does_not_confirm(self):
        patches = ({'container_id': '9' * 64}, {'installation_id': '9' * 32}, {'run_id': '9' * 32},
                   {'variant': 'perturbed'}, {'intent_id': '9' * 32}, {'cleanup_confirmed': False})
        for patch in patches:
            with self.subTest(patch=str(patch)):
                owner = FakeOwner()
                owner.close_patch = patch
                sandbox = self.session(owner)
                await sandbox.__aenter__()
                with self.assertRaises(client.ActorError) as caught:
                    await sandbox.close()
                self.assertEqual(caught.exception.reason, 'cleanup_unconfirmed')
                self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (False, True))

    async def test_refusals_leave_the_obligation_and_health_does_not_replace_the_receipt(self):
        for reason, extras in (('unknown_handle', {}), ('cleanup_unconfirmed', {'cleanup_confirmed': False}),
                               ('foreign_owner', {}), ('internal_error', {})):
            with self.subTest(reason=reason):
                owner = FakeOwner()
                owner.refuse['close'] = (reason, extras)
                sandbox = self.session(owner)
                await sandbox.__aenter__()
                with self.assertRaises(client.ActorError) as caught:
                    await sandbox.close()
                self.assertEqual(caught.exception.owner_reason, reason)
                self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (False, True))
                self.assertEqual(owner.ops.count('health'), 1)  # nothing consulted health to guess a restitution

    async def test_exit_raises_when_the_close_is_not_confirmed(self):
        owner = FakeOwner()
        owner.close_failures = 1
        with self.assertRaises(client.ActorError):
            async with self.session(owner):
                pass


class FakePeer:
    def __init__(self, uid, response=b''):
        self.uid, self.events, self.incoming, self.sent = uid, [], bytearray(response), bytearray()

    def settimeout(self, value):
        self.events.append(('settimeout', value))

    def connect(self, path):
        self.events.append(('connect', path))

    def getsockopt(self, level, option, size):
        self.events.append(('getsockopt',))
        return struct.pack('=iII', 1, self.uid, self.uid)

    def sendall(self, data):
        self.events.append(('sendall', len(data)))
        self.sent.extend(data)

    def shutdown(self, how):
        self.events.append(('shutdown', how))

    def recv(self, count):
        self.events.append(('recv', count))
        chunk = bytes(self.incoming[:count])
        del self.incoming[:count]
        return chunk

    def close(self):
        self.events.append(('close',))

    def names(self):
        return [event[0] for event in self.events]


class TransportTests(unittest.TestCase):
    PAYLOAD = wire.encode_request('health')

    def exchange(self, peer, **kwargs):
        options = dict(response_limit=1024, deadline=5.0, socket_factory=lambda: peer)
        options.update(kwargs)
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            return client.blocking_exchange(SETTINGS, self.PAYLOAD, **options)

    def test_unexpected_owner_uid_receives_not_a_single_byte(self):
        peer = FakePeer(SETTINGS.owner_uid + 1)
        with self.assertRaises(wire.WireError) as caught:
            self.exchange(peer)
        self.assertEqual(caught.exception.reason, 'peer_mismatch')
        self.assertNotIn('sendall', peer.names())
        self.assertNotIn('shutdown', peer.names())
        self.assertEqual(peer.names()[-1], 'close')

    def test_verified_owner_gets_one_frame_then_write_shutdown_and_answers_with_one_frame(self):
        answer = raw({'ok': True, 'op': 'health'})
        peer = FakePeer(SETTINGS.owner_uid, wire.encode_frame(answer, limit=1024))
        self.assertEqual(self.exchange(peer), answer)
        names = peer.names()
        self.assertEqual(names[:2], ['settimeout', 'connect'])
        self.assertLess(names.index('connect'), names.index('getsockopt'))
        self.assertLess(names.index('getsockopt'), names.index('sendall'))
        self.assertLess(names.index('sendall'), names.index('shutdown'))
        self.assertIn(('shutdown', socket.SHUT_WR), peer.events)
        self.assertEqual(bytes(peer.sent), wire.encode_frame(self.PAYLOAD, limit=wire.MAX_REQUEST_BYTES))
        self.assertEqual(peer.names()[-1], 'close')

    def test_malformed_response_framing_is_rejected(self):
        good = wire.encode_frame(raw({'ok': True}), limit=1024)
        cases = ((good + b'x', 'trailing_bytes'), (good[:-2], 'truncated'), (struct.pack('>I', 2000) + b'x', 'too_large'),
                 (struct.pack('>I', 0), 'framing'), (b'', 'truncated'))
        for data, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(wire.WireError) as caught:
                    self.exchange(FakePeer(SETTINGS.owner_uid, data))
                self.assertEqual(caught.exception.reason, reason)

    def test_without_peer_credentials_nothing_is_even_created(self):
        created = []
        with mock.patch.object(socket, 'SO_PEERCRED', None, create=True):
            with self.assertRaises(wire.WireError) as caught:
                client.blocking_exchange(SETTINGS, self.PAYLOAD, response_limit=1024, deadline=5.0,
                                         socket_factory=lambda: created.append(1))
        self.assertEqual(caught.exception.reason, 'linux_peer_credentials_required')
        self.assertEqual(created, [])

    def test_deadline_is_total(self):
        peer = FakePeer(SETTINGS.owner_uid, b'')
        times = iter([0.0, 9.0])
        with self.assertRaises(wire.WireError) as caught:
            self.exchange(peer, deadline=1.0, clock=lambda: next(times))
        self.assertEqual(caught.exception.reason, 'timeout')
        self.assertNotIn('sendall', peer.names())


class RecoverReceiptTests(ClientCase):
    """client.recover_receipt over the scripted owner. Authored without a shell: not executed by the author."""

    async def recover(self, owner, identity=IDENTITY, settings=SETTINGS):
        return await client.recover_receipt(settings, identity, transport=owner)

    async def assertUnconfirmed(self, owner, identity, owner_reason, settings=SETTINGS):
        with self.assertRaises(client.ActorError) as caught:
            await self.recover(owner, identity, settings)
        error = caught.exception
        self.assertEqual((error.reason, error.cleanup_confirmed, str(error)),
                         ('cleanup_unconfirmed', False, 'Sandbox cleanup could not be confirmed'))
        self.assertEqual(error.owner_reason, owner_reason)
        self.assertIsInstance(error, runner.RunnerError)
        return error

    async def closed_identity(self, owner):
        async with self.session(owner) as sandbox:
            identity = sandbox.identity
        self.assertTrue(sandbox.cleanup_confirmed)
        return identity

    async def test_only_the_exact_finish_confirms_and_nothing_else_is_sent(self):
        owner = FakeOwner()
        identity = await self.closed_identity(owner)
        self.assertEqual(owner.ops, ['health', 'open', 'close'])
        receipt = await self.recover(owner, identity)
        self.assertEqual(owner.ops, ['health', 'open', 'close', 'receipt'])
        self.assertEqual(receipt, {'ok': True, 'op': 'receipt', **identity, 'status': 'confirmed', 'cleanup_confirmed': True})
        request = owner.calls[-1][1]
        self.assertEqual({name: getattr(request, name) for name in wire.IDENTITY_FIELDS}, identity)
        self.assertEqual((request.handle, request.command, request.name), (None, None, None))
        receipt['status'] = 'tampered'
        self.assertEqual((await self.recover(owner, identity))['status'], 'confirmed')  # each call returns its own dict

    async def test_a_lost_close_answer_is_recovered_without_replaying_anything(self):
        owner = FakeOwner()
        owner.lost_after_finish = 1
        sandbox = self.session(owner)
        await sandbox.__aenter__()
        with self.assertRaises(client.ActorError) as caught:
            await sandbox.close()
        self.assertEqual(caught.exception.owner_reason, 'owner_unavailable')
        self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (False, True))
        receipt = await self.recover(owner, sandbox.identity)
        self.assertEqual((receipt['status'], receipt['cleanup_confirmed']), ('confirmed', True))
        self.assertEqual(owner.ops, ['health', 'open', 'close', 'receipt'])  # no second close, no second open
        # recovery reports; it does not rewrite the session: whoever owns the obligation decides what to do with the receipt
        self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (False, True))

    async def test_an_older_receipt_is_recovered_after_a_later_run_and_with_fresh_settings(self):
        owner = FakeOwner()
        first_id = await self.closed_identity(owner)
        owner.open_patch = dict(SECOND)
        second = self.session(owner, run_id=RUN2)
        async with second:
            second_id = second.identity
            self.assertNotEqual(first_id['container_id'], second_id['container_id'])
            self.assertEqual((await self.recover(owner, first_id))['status'], 'confirmed')  # while another run is active
            error = await self.assertUnconfirmed(owner, second_id, 'receipt_unknown')  # the active run is not finished
            self.assertEqual(error.receipt_status, 'unknown')
        restarted = client.Settings(SETTINGS.socket_path, SETTINGS.owner_uid, installation_id=INSTALL)  # no session, no lease
        for identity in (first_id, second_id):
            self.assertEqual((await self.recover(owner, identity, restarted))['status'], 'confirmed')

    async def test_unknown_before_finish_and_confirmed_after_it(self):
        owner = FakeOwner()
        sandbox = self.session(owner)
        await sandbox.__aenter__()
        error = await self.assertUnconfirmed(owner, sandbox.identity, 'receipt_unknown')
        self.assertEqual(error.receipt_status, 'unknown')
        self.assertEqual(owner.ops, ['health', 'open', 'receipt'])  # asking never closed anything
        self.assertTrue(sandbox.obligation)
        await sandbox.close()
        self.assertEqual((await self.recover(owner, sandbox.identity))['status'], 'confirmed')

    async def test_an_identity_the_owner_never_saw_is_unknown_not_confirmed(self):
        owner = FakeOwner()
        error = await self.assertUnconfirmed(owner, IDENTITY, 'receipt_unknown')
        self.assertEqual((error.receipt_status, owner.ops), ('unknown', ['receipt']))

    async def test_transport_and_owner_failures_fail_closed_with_one_attempt(self):
        cases = (
            (OSError('refused'), 'owner_unavailable'), (TimeoutError(), 'owner_unavailable'),
            (wire.WireError('timeout'), 'owner_unavailable'),
            (wire.WireError('peer_mismatch'), 'owner_peer_unverified'),
            (wire.WireError('peer_unverified'), 'owner_peer_unverified'),
            (wire.WireError('linux_peer_credentials_required'), 'owner_peer_unverified'),
            (wire.WireError('truncated'), 'owner_response_invalid'), (wire.WireError('trailing_bytes'), 'owner_response_invalid'),
            (b'not json', 'owner_response_invalid'), (raw({'ok': True, 'op': 'receipt'}), 'owner_response_invalid'),
            (raw({'ok': True, 'op': 'health'}), 'owner_response_invalid'),
            (wire.error_response('installation_mismatch'), 'installation_mismatch'),
            (wire.error_response('foreign_owner'), 'foreign_owner'), (wire.error_response('owner_blocked'), 'owner_blocked'),
            (wire.error_response('internal_error'), 'internal_error'), (wire.error_response('framing'), 'framing'),
        )
        for failure, reason in cases:
            with self.subTest(reason=reason, failure=repr(failure)[:30]):
                owner = FakeOwner()
                owner.finished.add(tuple(IDENTITY[name] for name in wire.IDENTITY_FIELDS))  # even if the diary does have it
                owner.errors['receipt'] = failure
                await self.assertUnconfirmed(owner, IDENTITY, reason)
                self.assertEqual(owner.ops, ['receipt'])  # one attempt, no health, no retry

    async def test_an_answer_about_another_identity_or_with_a_bad_shape_never_confirms(self):
        other = {'installation_id': '9' * 32, 'run_id': '9' * 32, 'variant': 'perturbed', 'intent_id': '9' * 32,
                 'container_id': '9' * 64}
        identity_patches = [{key: value} for key, value in other.items()] + [dict(other)]
        shape_patches = [{'status': 'done'}, {'status': 'CONFIRMED'}, {'status': None}, {'status': 'unknown'},
                         {'cleanup_confirmed': False}, {'cleanup_confirmed': 1}, {'cleanup_confirmed': 'true'},
                         {'oom_killed': False}, {'handle': HANDLE}, {'op': 'close'}, {'ok': 1}, {'ok': False}]
        for finished in (True, False):  # the answer is just as invalid whether the owner would have confirmed or not
            for patch in identity_patches + (shape_patches if finished else []):
                with self.subTest(finished=finished, patch=str(patch)[:50]):
                    owner = FakeOwner()
                    if finished:
                        owner.finished.add(tuple(IDENTITY[name] for name in wire.IDENTITY_FIELDS))
                    owner.receipt_patch = patch
                    await self.assertUnconfirmed(owner, IDENTITY, 'owner_response_invalid')

    async def test_a_malformed_identity_is_refused_before_anything_is_sent(self):
        bad = (None, {}, 'x', list(IDENTITY), {'installation_id': INSTALL}, {**IDENTITY, 'extra': 1},
               {**IDENTITY, 'handle': HANDLE}, {key: value for key, value in IDENTITY.items() if key != 'intent_id'},
               {**IDENTITY, 'installation_id': 'A' * 32}, {**IDENTITY, 'run_id': RUN[:-1]},
               {**IDENTITY, 'variant': 'actor'}, {**IDENTITY, 'intent_id': None}, {**IDENTITY, 'container_id': CONTAINER[:-1]},
               {**IDENTITY, 'container_id': 5})
        for identity in bad:
            with self.subTest(identity=str(identity)[:60]):
                owner = FakeOwner()
                await self.assertUnconfirmed(owner, identity, 'identity_invalid')
                self.assertEqual(owner.ops, [])

    async def test_the_pinned_installation_must_match_the_identity(self):
        owner = FakeOwner()
        wrong = client.Settings(SETTINGS.socket_path, SETTINGS.owner_uid, installation_id='9' * 32)
        await self.assertUnconfirmed(owner, IDENTITY, 'installation_mismatch', settings=wrong)
        self.assertEqual(owner.ops, [])  # refused locally: another installation never receives the question
        right = client.Settings(SETTINGS.socket_path, SETTINGS.owner_uid, installation_id=INSTALL)
        await self.assertUnconfirmed(owner, IDENTITY, 'receipt_unknown', settings=right)
        self.assertEqual(owner.ops, ['receipt'])

    async def test_it_is_a_repeatable_read_that_never_opens_executes_probes_or_closes(self):
        owner = FakeOwner()
        identity = await self.closed_identity(owner)
        before = list(owner.ops)
        with mock.patch('asyncio.create_subprocess_exec', side_effect=AssertionError('spawned')) as spawn, \
                mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('spawned')) as popen:
            for _ in range(3):
                self.assertEqual((await self.recover(owner, identity))['status'], 'confirmed')
        self.assertEqual(owner.ops, before + ['receipt'] * 3)
        for op in ('health', 'open', 'execute', 'probe', 'close'):
            self.assertEqual(owner.ops.count(op), before.count(op), op)
        self.assertEqual((spawn.call_count, popen.call_count), (0, 0))

    async def test_cancellation_propagates_and_nothing_more_is_sent(self):
        owner = FakeOwner()
        owner.gates['receipt'] = asyncio.Event()
        task = asyncio.ensure_future(self.recover(owner))
        await self.wait_for_op(owner, 'receipt')
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(owner.ops, ['receipt'])

    async def test_the_default_transport_uses_the_receipt_limits(self):
        seen = {}
        answer = wire.encode_response('receipt', {**IDENTITY, 'status': 'confirmed', 'cleanup_confirmed': True})

        def blocking(settings, payload, *, response_limit, deadline, **kwargs):
            seen.update(settings=settings, payload=payload, response_limit=response_limit, deadline=deadline)
            return answer
        with mock.patch.object(client, 'blocking_exchange', blocking):
            receipt = await client.recover_receipt(SETTINGS, IDENTITY)
        self.assertEqual((seen['settings'], seen['response_limit'], seen['deadline']), (SETTINGS, 1024, 8.0))
        request = proto.decode_request(seen['payload'])
        self.assertEqual((request.op, request.installation_id, request.container_id), ('receipt', INSTALL, CONTAINER))
        self.assertEqual(receipt['status'], 'confirmed')


class ReceiptTransportTests(unittest.TestCase):
    PAYLOAD = wire.encode_request('receipt', **IDENTITY)
    ANSWER = wire.encode_response('receipt', {**IDENTITY, 'status': 'confirmed', 'cleanup_confirmed': True})

    def exchange(self, peer, **kwargs):
        options = dict(response_limit=wire.RESPONSE_LIMITS['receipt'], deadline=wire.CLIENT_DEADLINES['receipt'],
                       socket_factory=lambda: peer)
        options.update(kwargs)
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            return client.blocking_exchange(SETTINGS, self.PAYLOAD, **options)

    def test_an_unexpected_owner_uid_receives_not_a_single_byte_of_the_query(self):
        peer = FakePeer(SETTINGS.owner_uid + 1)
        with self.assertRaises(wire.WireError) as caught:
            self.exchange(peer)
        self.assertEqual(caught.exception.reason, 'peer_mismatch')
        self.assertNotIn('sendall', peer.names())
        self.assertNotIn('shutdown', peer.names())

    def test_a_verified_owner_gets_one_frame_and_answers_with_one_frame(self):
        peer = FakePeer(SETTINGS.owner_uid, wire.encode_frame(self.ANSWER, limit=wire.RESPONSE_LIMITS['receipt']))
        self.assertEqual(self.exchange(peer), self.ANSWER)
        names = peer.names()
        self.assertLess(names.index('getsockopt'), names.index('sendall'))
        self.assertLess(names.index('sendall'), names.index('shutdown'))
        self.assertEqual(bytes(peer.sent), wire.encode_frame(self.PAYLOAD, limit=wire.MAX_REQUEST_BYTES))
        self.assertEqual(wire.validate_receipt(wire.decode_response(self.ANSWER, op='receipt'), identity=IDENTITY)['status'],
                         'confirmed')

    def test_an_answer_beyond_the_receipt_limit_is_rejected_before_its_body(self):
        peer = FakePeer(SETTINGS.owner_uid, struct.pack('>I', wire.RESPONSE_LIMITS['receipt'] + 1) + b'x')
        with self.assertRaises(wire.WireError) as caught:
            self.exchange(peer)
        self.assertEqual(caught.exception.reason, 'too_large')


class NoAlternativeTests(ClientCase):
    def test_client_imports_no_process_or_docker_machinery(self):
        text = MODULE.read_text(encoding='utf-8')
        tree = ast.parse(text)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {item.name.split('.')[0] for item in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(('.' * node.level) + (node.module or '') + ':' + ','.join(item.name for item in node.names))
        self.assertTrue(imported.isdisjoint({'subprocess', 'docker', 'shutil', 'pty'}), imported)
        self.assertNotIn('create_subprocess_exec', text)
        self.assertIsNone(re.search(r'\b_cli\b', text))
        runner_attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
                             and isinstance(node.value, ast.Name) and node.value.id == 'runner'}
        # M3.1 also uses the received pure catalog_violations validator; no host/process authority is added.
        self.assertLessEqual(runner_attributes, {'RunnerError', 'unavailable_measurement', 'hardened_violations', 'profile_digest',
                                                 'file_state_value', 'catalog_violations'})

    async def test_a_full_flow_spawns_nothing(self):
        owner = FakeOwner()
        with mock.patch('asyncio.create_subprocess_exec', side_effect=AssertionError('spawned')) as spawn, \
                mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('spawned')) as popen:
            async with self.session(owner) as sandbox:
                await sandbox.execute('true')
                await sandbox.probe('task_result')
                await sandbox.exec_fixed(invoice_verification.ARTIFACT_CAPTURE_SCRIPT)
        self.assertEqual((spawn.call_count, popen.call_count), (0, 0))
        self.assertTrue(sandbox.cleanup_confirmed)

    async def test_an_absent_owner_fails_closed_without_a_fallback(self):
        owner = FakeOwner()
        owner.errors['health'] = OSError('no such socket')
        with mock.patch('asyncio.create_subprocess_exec', side_effect=AssertionError('spawned')) as spawn:
            with self.assertRaises(client.ActorError) as caught:
                async with self.session(owner):
                    self.fail('must not enter')
        self.assertEqual(caught.exception.reason, 'owner_unavailable')
        self.assertEqual(spawn.call_count, 0)


# ------------------------------------------------------------------------------------------------------- M2.1 · levels
# A scripted owner for levels: it answers with the wire encoders, like FakeOwner, and applies the protocol decoder to every payload.
# Authored without a shell: none of these tests has been executed by the author.

CONTEXT = '7' * 64
OTHER_CONTEXT = '8' * 64
LEVEL_IDENTITY = {'installation_id': INSTALL, 'run_id': RUN, 'level': 'memory', 'stage': 'actor', 'context_sha256': CONTEXT,
                  'intent_id': INTENT, 'container_id': CONTAINER}
COUNTERS = {'low': 0, 'high': 0, 'max': 0, 'oom': 1, 'oom_kill': 2}
M1_OPEN_BODY = {'handle': HANDLE, 'installation_id': INSTALL, 'run_id': RUN, 'variant': 'legitimate', 'intent_id': INTENT,
                'name': 'escape-actor-' + INTENT, 'container_id': CONTAINER, 'profile_sha256': runner.profile_digest(PROFILE),
                'profile': PROFILE}


class LevelOwner(FakeOwner):
    def __init__(self):
        super().__init__()
        self.counters = {'status': 'available', 'counters': dict(COUNTERS)}

    def key(self):
        return tuple(self.identity[name] for name in wire.LEVEL_IDENTITY_FIELDS)

    def on_open_level(self, request):
        body = {'handle': HANDLE, 'installation_id': INSTALL, 'run_id': request.run_id, 'level': request.level,
                'stage': request.stage, 'context_sha256': request.context_sha256, 'intent_id': INTENT,
                'name': 'escape-actor-' + INTENT, 'container_id': CONTAINER, 'profile_sha256': self.sha,
                'profile': self.profile, **self.open_patch}
        self.identity = {key: body[key] for key in wire.LEVEL_IDENTITY_FIELDS}
        return wire.encode_response('open_level', body)

    def on_level_probe(self, request):
        return wire.encode_response('level_probe', self.counters)

    def on_level_receipt(self, request):
        asked = {name: getattr(request, name) for name in wire.LEVEL_IDENTITY_FIELDS}
        confirmed = tuple(asked[name] for name in wire.LEVEL_IDENTITY_FIELDS) in self.finished
        return wire.encode_response('level_receipt', {**asked, 'status': 'confirmed' if confirmed else 'unknown',
                                                      'cleanup_confirmed': confirmed, **self.receipt_patch})


class LevelClientCase(ClientCase):
    def level_session(self, owner, settings=SETTINGS, **kwargs):
        return client.LevelSession(settings, run_id=kwargs.pop('run_id', RUN), level=kwargs.pop('level', 'memory'),
                                   stage=kwargs.pop('stage', 'actor'), context_sha256=kwargs.pop('context', CONTEXT),
                                   transport=owner)

    async def entered(self, owner, **kwargs):
        sandbox = self.level_session(owner, **kwargs)
        await sandbox.__aenter__()
        return sandbox


class LevelOpenTests(LevelClientCase):
    async def test_open_binds_the_level_identity_and_close_confirms_with_the_same_identity(self):
        owner = LevelOwner()
        async with self.level_session(owner) as sandbox:
            self.assertEqual(owner.ops, ['health', 'open_level'])
            self.assertEqual(sandbox.name, 'escape-actor-' + INTENT)
            self.assertEqual((sandbox.created, sandbox.profile_captured, sandbox.cleanup_confirmed), (True, True, False))
            self.assertEqual(sandbox.profile, PROFILE)
            self.assertTrue(sandbox.obligation)
            self.assertEqual(sandbox.identity, LEVEL_IDENTITY)
            self.assertNotIn('variant', sandbox.identity)
            self.assertNotIn(HANDLE, repr(sandbox))
            self.assertNotIn(CONTEXT, repr(sandbox))
            request = owner.calls[1][1]
            self.assertEqual((request.run_id, request.level, request.stage, request.context_sha256),
                             (RUN, 'memory', 'actor', CONTEXT))
            self.assertIsNone(request.variant)
        self.assertEqual(owner.ops, ['health', 'open_level', 'close'])
        self.assertEqual((sandbox.cleanup_confirmed, sandbox.created, sandbox.obligation, sandbox.oom_killed),
                         (True, False, False, False))
        self.assertEqual(sandbox.measurement, MEAS)

    async def test_binding_arguments_are_validated_and_there_is_no_variant(self):
        good = dict(run_id=RUN, level='memory', stage='actor', context_sha256=CONTEXT)
        for patch in ({'run_id': 'x'}, {'run_id': RUN.upper()}, {'level': 'Persistence'}, {'level': 'legitimate'},  # M2.3: persistence is valid
                      {'level': None}, {'stage': 'fresh'}, {'stage': None}, {'context_sha256': 'x'},
                      {'context_sha256': CONTEXT[:-1]}, {'context_sha256': CONTEXT.upper().replace('7', 'G')},
                      {'context_sha256': None}):
            with self.assertRaises(ValueError, msg=str(patch)):
                client.LevelSession(SETTINGS, **{**good, **patch})
        with self.assertRaises(TypeError):
            client.LevelSession(SETTINGS, variant='legitimate', **good)  # a level is never opened as a variant
        with self.assertRaises(TypeError):
            client.LevelSession(SETTINGS, run_id=RUN, level='memory', stage='actor')  # the context is required
        for level in ('memory', 'secret'):  # the codec names are accepted; the owner's allowlist decides
            self.assertEqual(client.LevelSession(SETTINGS, **{**good, 'level': level}).level, level)

    async def test_the_workflow_pins_of_settings_are_not_reused_as_the_level_context(self):
        owner = LevelOwner()
        pinned = client.Settings(SETTINGS.socket_path, SETTINGS.owner_uid, context_sha256='f' * 64,
                                 mission_id='invoice-reconcile/v1')
        async with self.level_session(owner, pinned) as sandbox:
            self.assertEqual(owner.calls[1][1].context_sha256, CONTEXT)
            self.assertEqual(sandbox.identity['context_sha256'], CONTEXT)

    async def test_owner_not_ready_or_blocked_opens_nothing(self):
        for patch, reason, text in (({'ready': False}, 'owner_not_ready', 'Actor controller refused: owner_not_ready'),
                                    ({'blocked': True}, 'owner_blocked', 'Actor controller is blocked by recovery'),
                                    ({'image_id': None}, 'image_mismatch', 'Actor controller refused: image_mismatch')):
            with self.subTest(reason=reason):
                owner = LevelOwner()
                owner.health.update(patch)
                with self.assertRaises(client.ActorError) as caught:
                    async with self.level_session(owner):
                        self.fail('must not enter')
                self.assertEqual((caught.exception.reason, str(caught.exception)), (reason, text))
                self.assertIsNone(caught.exception.cleanup_confirmed)
                self.assertEqual(owner.ops, ['health'])

    async def test_pinned_installation_or_image_must_match_health(self):
        for settings in (client.Settings(SETTINGS.socket_path, 2000, installation_id='9' * 32),
                         client.Settings(SETTINGS.socket_path, 2000, image_id='sha256:' + 'e' * 64)):
            owner = LevelOwner()
            with self.assertRaises(client.ActorError):
                async with self.level_session(owner, settings):
                    self.fail('must not enter')
            self.assertEqual(owner.ops, ['health'])

    async def test_owner_refusals_carry_the_owner_state_and_the_client_cannot_change_the_policy(self):
        for reason in ('level_not_allowed', 'context_mismatch', 'capacity_exhausted', 'already_active', 'owner_blocked'):
            with self.subTest(reason=reason):
                owner = LevelOwner()
                owner.refuse['open_level'] = (reason, {})
                with self.assertRaises(client.ActorError) as caught:
                    async with self.level_session(owner):
                        self.fail('must not enter')
                self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), (reason, None))
                self.assertEqual(owner.ops, ['health', 'open_level'])  # asked once, never retried, never with another level
        owner = LevelOwner()
        owner.refuse['open_level'] = ('level_not_allowed', {})
        with self.assertRaises(client.ActorError) as caught:
            async with self.level_session(owner, level='secret'):
                self.fail('must not enter')
        self.assertEqual(str(caught.exception), 'Actor controller refused: level_not_allowed')
        owner = LevelOwner()
        owner.refuse['open_level'] = ('profile_rejected', {'cleanup_confirmed': True, 'violations': ['read_only']})
        with self.assertRaises(client.ActorError) as caught:
            async with self.level_session(owner):
                self.fail('must not enter')
        self.assertEqual(str(caught.exception), 'Sandbox effective profile does not meet the required profile: read_only')
        self.assertIs(caught.exception.cleanup_confirmed, True)

    async def test_transport_failure_during_open_leaves_the_state_unknown_and_is_not_retried(self):
        owner = LevelOwner()
        owner.errors['open_level'] = OSError('reset')
        with self.assertRaises(client.ActorError) as caught:
            async with self.level_session(owner):
                self.fail('must not enter')
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('owner_unavailable', False))
        self.assertEqual(owner.ops, ['health', 'open_level'])
        owner = LevelOwner()
        owner.errors['open_level'] = wire.WireError('peer_mismatch')
        with self.assertRaises(client.ActorError) as caught:
            async with self.level_session(owner):
                self.fail('must not enter')
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('owner_peer_unverified', None))

    async def test_open_receipt_must_match_run_level_stage_context_installation_and_image(self):
        patches = ({'run_id': '9' * 32}, {'level': 'secret'}, {'stage': 'fresh'}, {'context_sha256': OTHER_CONTEXT},
                   {'context_sha256': 'x'}, {'installation_id': '9' * 32}, {'name': 'escape-actor-' + '9' * 32},
                   {'handle': 'zz'}, {'profile': 'x'}, {'profile': {**PROFILE, 'image_id': 'sha256:' + 'e' * 64}},
                   {'variant': 'legitimate'}, {'container': 'x'}, {'intent_id': 5})
        for patch in patches:
            with self.subTest(patch=str(patch)[:40]):
                owner = LevelOwner()
                owner.open_patch = patch
                with self.assertRaises(client.ActorError) as caught:
                    async with self.level_session(owner):
                        self.fail('must not enter')
                self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('owner_response_invalid', False))
                self.assertNotIn('close', owner.ops)  # the client holds no trusted handle to close

    async def test_garbage_and_the_m1_open_shape_are_refused(self):
        for answer in (b'garbage', wire.encode_response('open', M1_OPEN_BODY), wire.encode_response('health', LevelOwner().health)):
            owner = LevelOwner()
            owner.errors['open_level'] = answer
            with self.assertRaises(client.ActorError) as caught:
                async with self.level_session(owner):
                    self.fail('must not enter')
            self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('owner_response_invalid', False))
            self.assertNotIn('close', owner.ops)

    async def test_profile_is_reverified_and_a_violation_closes_the_handle(self):
        weak = {**PROFILE, 'read_only': False}
        owner = LevelOwner()
        owner.profile = weak
        with self.assertRaises(client.ActorError) as caught:
            async with self.level_session(owner):
                self.fail('must not enter')
        self.assertEqual(owner.ops, ['health', 'open_level', 'close'])
        self.assertEqual(str(caught.exception), 'Sandbox effective profile does not meet the required profile: read_only')
        self.assertIs(caught.exception.cleanup_confirmed, True)
        self.assertEqual(caught.exception.sandbox_profile, weak)

    async def test_profile_digest_mismatch_and_unconfirmed_cleanup(self):
        owner = LevelOwner()
        owner.sha = '6' * 64
        with self.assertRaises(client.ActorError) as caught:
            async with self.level_session(owner):
                self.fail('must not enter')
        self.assertTrue(str(caught.exception).endswith('profile_digest'))
        self.assertEqual(owner.ops, ['health', 'open_level', 'close'])
        owner = LevelOwner()
        owner.profile = {**PROFILE, 'privileged': True}
        owner.close_failures = 1
        with self.assertRaises(client.ActorError) as caught:
            async with self.level_session(owner):
                self.fail('must not enter')
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('cleanup_unconfirmed', False))
        self.assertEqual(caught.exception.sandbox_profile['privileged'], True)  # the original cause is kept apart from the cleanup

    async def test_cancellation_during_open_restores_a_granted_handle_then_propagates(self):
        owner = LevelOwner()
        owner.gates['open_level'] = asyncio.Event()
        sandbox = self.level_session(owner)
        task = asyncio.ensure_future(sandbox.__aenter__())
        await self.wait_for_op(owner, 'open_level')
        task.cancel()
        owner.gates['open_level'].set()
        with self.assertRaises(asyncio.CancelledError) as caught:
            await task
        self.assertEqual(owner.ops, ['health', 'open_level', 'close'])
        self.assertTrue(sandbox.cleanup_confirmed)
        self.assertIs(caught.exception.cleanup_confirmed, True)
        self.assertEqual(caught.exception.sandbox_profile, PROFILE)

    async def test_cancellation_before_any_handle_reports_no_cleanup_state(self):
        owner = LevelOwner()
        owner.gates['health'] = asyncio.Event()
        owner.refuse['open_level'] = ('owner_blocked', {})  # the exchange that finishes after the cancellation grants no handle
        sandbox = self.level_session(owner)
        task = asyncio.ensure_future(sandbox.__aenter__())
        await self.wait_for_op(owner, 'health')
        task.cancel()
        owner.gates['health'].set()  # the cancelled entry lets its own exchange finish before the cancellation proceeds
        with self.assertRaises(asyncio.CancelledError) as caught:
            await task
        self.assertIsNone(caught.exception.cleanup_confirmed)  # nothing was created, so there is no cleanup state to claim
        self.assertEqual(owner.ops, ['health', 'open_level'])
        self.assertFalse(sandbox.obligation)

    async def test_a_body_that_fails_still_closes_and_keeps_its_own_error(self):
        owner = LevelOwner()
        with self.assertRaises(RuntimeError) as caught:
            async with self.level_session(owner) as sandbox:
                raise RuntimeError('level failed')
        self.assertEqual(str(caught.exception), 'level failed')
        self.assertEqual(owner.ops, ['health', 'open_level', 'close'])
        self.assertTrue(sandbox.cleanup_confirmed)
        owner = LevelOwner()
        owner.close_failures = 1
        with self.assertRaises(client.ActorError) as caught:  # an unconfirmed cleanup is never swallowed by the body's success
            async with self.level_session(owner):
                pass
        self.assertEqual(caught.exception.reason, 'cleanup_unconfirmed')


class LevelOperationTests(LevelClientCase):
    async def test_the_facade_offers_only_execute_measure_cgroup_events_and_close(self):
        sandbox = self.level_session(LevelOwner())
        for name in ('execute', 'measure', 'cgroup_events', 'close', 'identity', 'obligation', 'cleanup_confirmed', 'created',
                     'profile', 'profile_captured', 'measurement', 'oom_killed'):
            self.assertTrue(hasattr(sandbox, name), name)
        for name in ('probe', 'exec_fixed', 'file_state', 'copy_scan', 'net_counters', 'cgroup_sample', 'cgroup_recheck',
                     'container_identity', 'cgroup_identity', 'variant'):
            self.assertFalse(hasattr(sandbox, name), name)  # the controller's optional probes find no such method
        self.assertFalse(hasattr(client.ActorSession, 'cgroup_events'))  # and the M1 facade did not grow
        self.assertFalse(hasattr(client.ActorSession, 'level'))

    async def test_execute_returns_the_runner_shape_and_keeps_the_command_exact(self):
        owner = LevelOwner()
        async with self.level_session(owner) as sandbox:
            result = await sandbox.execute('cat -- /work/input.json')
            self.assertEqual(set(result), {'stdout', 'stderr', 'exit_code', *wire.MEASUREMENT_FIELDS})
            self.assertEqual((result['stdout'], result['exit_code']), ('ran', 0))
            self.assertEqual(sandbox.measurement, MEAS)
            request = owner.calls[-1][1]
            self.assertEqual((request.op, request.handle, request.command), ('execute', HANDLE, 'cat -- /work/input.json'))

    async def test_commands_at_the_byte_limit_travel_whole_and_beyond_it_never_leave(self):
        owner = LevelOwner()
        async with self.level_session(owner) as sandbox:
            await sandbox.execute('€' * 2730)
            self.assertEqual(owner.calls[-1][1].command, '€' * 2730)
            before = len(owner.calls)
            with self.assertRaises(client.ActorError) as caught:
                await sandbox.execute('€' * 2731)
            self.assertEqual(caught.exception.reason, 'command_too_large')
            self.assertEqual(len(owner.calls), before)

    async def test_measure_sends_only_the_measure_probe(self):
        owner = LevelOwner()
        async with self.level_session(owner) as sandbox:
            self.assertEqual(await sandbox.measure(), MEAS)
            probes = [request for op, request in owner.calls if op == 'probe']
            self.assertEqual([(request.name, request.handle) for request in probes], [('measure', HANDLE)])

    async def test_cgroup_events_returns_the_counters_through_the_fixed_probe(self):
        owner = LevelOwner()
        async with self.level_session(owner) as sandbox:
            events = await sandbox.cgroup_events()
            self.assertEqual(events, COUNTERS)
            events['oom_kill'] = 999  # a copy: the facade's answer cannot alter anything else
            self.assertEqual(owner.counters['counters']['oom_kill'], 2)
            request = owner.calls[-1][1]
            self.assertEqual((request.op, request.handle, request.name), ('level_probe', HANDLE, 'cgroup_events'))
            self.assertEqual((request.command, request.level, request.context_sha256), (None, None, None))
            self.assertEqual(await sandbox.cgroup_events(), COUNTERS)
        self.assertEqual(owner.ops, ['health', 'open_level', 'level_probe', 'level_probe', 'close'])

    async def test_an_unavailable_probe_is_none_and_the_session_stays_usable(self):
        owner = LevelOwner()
        owner.counters = {'status': 'unavailable', 'counters': None}
        async with self.level_session(owner) as sandbox:
            self.assertIsNone(await sandbox.cgroup_events())
            owner.counters = {'status': 'available', 'counters': dict(COUNTERS)}
            self.assertEqual(await sandbox.cgroup_events(), COUNTERS)
            self.assertEqual((await sandbox.execute('true'))['exit_code'], 0)

    async def test_invalid_probe_answers_are_refused_and_never_become_zeros_or_none(self):
        bad = ({'status': 'available', 'counters': {'oom_kill': True}}, {'status': 'available', 'counters': {'oom_kill': -1}},
               {'status': 'available', 'counters': {'oom_kill': 1.0}}, {'status': 'available', 'counters': {'oom_kill': '1'}},
               {'status': 'available', 'counters': {'oom_kill': 2 ** 64}}, {'status': 'available', 'counters': {'oom': 0}},
               {'status': 'available', 'counters': {'oom_kill': 0, 'max': True}},
               {'status': 'available', 'counters': {'oom_kill': 0, 'max': -3}},
               {'status': 'available', 'counters': {'oom_kill': 0, 'Bad Key': 1}}, {'status': 'available', 'counters': {}},
               {'status': 'available', 'counters': None}, {'status': 'unavailable', 'counters': {}},
               {'status': 'unavailable', 'counters': {'oom_kill': 0}}, {'status': 'maybe', 'counters': None},
               {'status': 'available', 'counters': {'oom_kill': 0}, 'intent_id': INTENT},
               {'status': 'available', 'counters': {'oom_kill': 0}, 'container_id': CONTAINER},
               {'status': 'available', 'counters': {'oom_kill': 0}, 'path': '/sys/fs/cgroup/memory.events'},
               {'status': 'available'}, {'counters': {'oom_kill': 0}})
        for body in bad:
            with self.subTest(body=str(body)[:60]):
                owner = LevelOwner()
                owner.errors['level_probe'] = raw({'ok': True, 'op': 'level_probe', **body})
                async with self.level_session(owner) as sandbox:
                    with self.assertRaises(client.ActorError) as caught:
                        await sandbox.cgroup_events()
                    self.assertEqual(caught.exception.reason, 'owner_response_invalid')
                    self.assertEqual(owner.ops.count('level_probe'), 1)  # one failure, never replayed

    async def test_the_shape_of_another_operation_is_not_a_probe_answer(self):
        for answer in (raw({'ok': True, 'op': 'probe', **MEAS}), raw({'ok': True, 'op': 'execute', 'stdout': '', 'stderr': '',
                                                                       'exit_code': 0, **MEAS}),
                       raw({'ok': True, 'op': 'level_receipt', **LEVEL_IDENTITY, 'status': 'unknown', 'cleanup_confirmed': False}),
                       raw({'ok': False}), b'garbage', b''):
            owner = LevelOwner()
            owner.errors['level_probe'] = answer
            async with self.level_session(owner) as sandbox:
                with self.assertRaises(client.ActorError) as caught:
                    await sandbox.cgroup_events()
                self.assertEqual(caught.exception.reason, 'owner_response_invalid')

    async def test_owner_refusals_and_transport_failures_of_the_probe_are_errors_not_none(self):
        for reason, text in (('wrong_domain', 'Actor controller refused: wrong_domain'), ('busy', 'Actor controller refused: busy'),
                             ('closing', 'Actor controller refused: closing'), ('exec_timeout', 'Docker command timed out'),
                             ('sandbox_stopped', 'Sandbox stopped during tool execution'),
                             ('internal_error', 'Actor controller refused: internal_error')):
            with self.subTest(reason=reason):
                owner = LevelOwner()
                owner.refuse['level_probe'] = (reason, {})
                async with self.level_session(owner) as sandbox:
                    with self.assertRaises(client.ActorError) as caught:
                        await sandbox.cgroup_events()
                    self.assertEqual((caught.exception.reason, str(caught.exception)), (reason, text))
        owner = LevelOwner()
        owner.errors['level_probe'] = OSError('reset')
        async with self.level_session(owner) as sandbox:
            with self.assertRaises(client.ActorError) as caught:
                await sandbox.cgroup_events()
            self.assertEqual(str(caught.exception), 'Actor controller unavailable')
            self.assertEqual(owner.ops.count('level_probe'), 1)
            self.assertNotIn('close', owner.ops)

    async def test_only_a_memory_session_asks_for_cgroup_events_and_nothing_is_sent_otherwise(self):
        owner = LevelOwner()
        async with self.level_session(owner, level='secret') as sandbox:
            before = len(owner.calls)
            with self.assertRaises(client.ActorError) as caught:
                await sandbox.cgroup_events()
            self.assertEqual(caught.exception.reason, 'wrong_domain')
            self.assertEqual(len(owner.calls), before)

    async def test_operations_without_an_open_handle_are_refused_locally(self):
        owner = LevelOwner()
        sandbox = self.level_session(owner)
        for call in (lambda: sandbox.execute('true'), sandbox.measure, sandbox.cgroup_events):
            with self.assertRaises(client.ActorError) as caught:
                await call()
            self.assertEqual(caught.exception.reason, 'unknown_handle')
        self.assertEqual(owner.ops, [])
        self.assertIsNone(sandbox.identity)

    async def test_transport_failure_of_execute_is_one_failure_and_the_action_is_not_replayed(self):
        owner = LevelOwner()
        owner.errors['execute'] = OSError('reset')
        async with self.level_session(owner) as sandbox:
            with self.assertRaises(client.ActorError) as caught:
                await sandbox.execute('touch /work/once')
            self.assertEqual(str(caught.exception), 'Actor controller unavailable')
            self.assertEqual(owner.ops.count('execute'), 1)
        self.assertEqual((owner.ops.count('execute'), owner.ops[-1]), (1, 'close'))

    async def test_cancellation_during_a_probe_propagates_and_exit_still_restitutes(self):
        owner = LevelOwner()
        owner.gates['level_probe'] = asyncio.Event()
        async with self.level_session(owner) as sandbox:
            task = asyncio.ensure_future(sandbox.cgroup_events())
            await self.wait_for_op(owner, 'level_probe')
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(owner.ops, ['health', 'open_level', 'level_probe', 'close'])
        self.assertTrue(sandbox.cleanup_confirmed)

    async def test_a_full_flow_spawns_nothing_and_an_absent_owner_fails_closed(self):
        owner = LevelOwner()
        with mock.patch('asyncio.create_subprocess_exec', side_effect=AssertionError('spawned')) as spawn, \
                mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('spawned')) as popen:
            async with self.level_session(owner) as sandbox:
                await sandbox.execute('true')
                await sandbox.cgroup_events()
                await sandbox.measure()
            self.assertEqual((spawn.call_count, popen.call_count), (0, 0))
            self.assertTrue(sandbox.cleanup_confirmed)
            absent = LevelOwner()
            absent.errors['health'] = OSError('no such socket')
            with self.assertRaises(client.ActorError) as caught:
                async with self.level_session(absent):
                    self.fail('must not enter')
            self.assertEqual(caught.exception.reason, 'owner_unavailable')
            self.assertEqual((spawn.call_count, popen.call_count), (0, 0))


class LevelCloseTests(LevelClientCase):
    async def test_close_is_idempotent_once_confirmed(self):
        owner = LevelOwner()
        sandbox = await self.entered(owner)
        await sandbox.close()
        await sandbox.close()
        self.assertEqual(owner.ops.count('close'), 1)
        self.assertTrue(sandbox.cleanup_confirmed)

    async def test_lost_close_keeps_the_obligation_and_a_retry_restitutes_by_the_same_handle(self):
        owner = LevelOwner()
        owner.close_failures = 1
        sandbox = await self.entered(owner)
        with self.assertRaises(client.ActorError) as caught:
            await sandbox.close()
        self.assertEqual(str(caught.exception), 'Sandbox cleanup could not be confirmed')
        self.assertIs(caught.exception.cleanup_confirmed, False)
        self.assertEqual(caught.exception.owner_reason, 'owner_unavailable')
        self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (False, True))
        self.assertEqual(owner.ops.count('close'), 1)  # one attempt per call
        await sandbox.close()
        self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (True, False))
        self.assertEqual([request.handle for op, request in owner.calls if op == 'close'], [HANDLE, HANDLE])

    async def test_a_receipt_with_another_identity_context_or_shape_does_not_confirm(self):
        patches = ({'container_id': '9' * 64}, {'installation_id': '9' * 32}, {'run_id': '9' * 32}, {'level': 'secret'},
                   {'stage': 'fresh'}, {'context_sha256': OTHER_CONTEXT}, {'intent_id': '9' * 32}, {'cleanup_confirmed': False},
                   {'variant': 'legitimate'}, {'extra': 1})
        for patch in patches:
            with self.subTest(patch=str(patch)):
                owner = LevelOwner()
                owner.close_patch = patch
                sandbox = await self.entered(owner)
                with self.assertRaises(client.ActorError) as caught:
                    await sandbox.close()
                self.assertEqual(caught.exception.reason, 'cleanup_unconfirmed')
                self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (False, True))

    async def test_the_m1_close_shape_never_confirms_a_level(self):
        owner = LevelOwner()
        sandbox = await self.entered(owner)
        owner.errors['close'] = wire.encode_response('close', {**{key: LEVEL_IDENTITY[key] for key in
                                                                    ('installation_id', 'run_id', 'intent_id', 'container_id')},
                                                               'variant': 'legitimate', 'cleanup_confirmed': True,
                                                               'oom_killed': False, **MEAS})
        with self.assertRaises(client.ActorError) as caught:
            await sandbox.close()
        self.assertEqual(caught.exception.reason, 'cleanup_unconfirmed')
        self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (False, True))
        del owner.errors['close']
        await sandbox.close()  # the honest receipt, with the level identity, does
        self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (True, False))

    async def test_refusals_leave_the_obligation_and_health_does_not_replace_the_receipt(self):
        for reason, extras in (('unknown_handle', {}), ('cleanup_unconfirmed', {'cleanup_confirmed': False}),
                               ('foreign_owner', {}), ('internal_error', {})):
            with self.subTest(reason=reason):
                owner = LevelOwner()
                owner.refuse['close'] = (reason, extras)
                sandbox = await self.entered(owner)
                with self.assertRaises(client.ActorError) as caught:
                    await sandbox.close()
                self.assertEqual(caught.exception.owner_reason, reason)
                self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (False, True))
                self.assertEqual(owner.ops.count('health'), 1)

    async def test_the_oom_flag_and_the_measurement_of_the_receipt_are_kept(self):
        owner = LevelOwner()
        owner.close_patch = {'oom_killed': True}
        async with self.level_session(owner) as sandbox:
            pass
        self.assertEqual((sandbox.oom_killed, sandbox.measurement), (True, MEAS))


class LevelRecoverReceiptTests(LevelClientCase):
    """client.recover_level_receipt over the scripted owner."""

    async def recover(self, owner, identity=LEVEL_IDENTITY, settings=SETTINGS):
        return await client.recover_level_receipt(settings, identity, transport=owner)

    async def assertUnconfirmed(self, owner, identity, owner_reason, settings=SETTINGS):
        with self.assertRaises(client.ActorError) as caught:
            await self.recover(owner, identity, settings)
        error = caught.exception
        self.assertEqual((error.reason, error.cleanup_confirmed, str(error)),
                         ('cleanup_unconfirmed', False, 'Sandbox cleanup could not be confirmed'))
        self.assertEqual(error.owner_reason, owner_reason)
        self.assertIsInstance(error, runner.RunnerError)
        return error

    async def closed_identity(self, owner, **kwargs):
        async with self.level_session(owner, **kwargs) as sandbox:
            identity = sandbox.identity
        self.assertTrue(sandbox.cleanup_confirmed)
        return identity

    async def test_only_the_exact_finish_confirms_and_nothing_else_is_sent(self):
        owner = LevelOwner()
        identity = await self.closed_identity(owner)
        self.assertEqual(owner.ops, ['health', 'open_level', 'close'])
        receipt = await self.recover(owner, identity)
        self.assertEqual(owner.ops, ['health', 'open_level', 'close', 'level_receipt'])
        self.assertEqual(receipt, {'ok': True, 'op': 'level_receipt', **identity, 'status': 'confirmed', 'cleanup_confirmed': True})
        request = owner.calls[-1][1]
        self.assertEqual({name: getattr(request, name) for name in wire.LEVEL_IDENTITY_FIELDS}, identity)
        self.assertEqual((request.handle, request.command, request.name, request.variant), (None, None, None, None))
        receipt['status'] = 'tampered'
        self.assertEqual((await self.recover(owner, identity))['status'], 'confirmed')  # each call returns its own dict

    async def test_a_lost_close_answer_is_recovered_without_replaying_anything(self):
        owner = LevelOwner()
        owner.lost_after_finish = 1
        sandbox = await self.entered(owner)
        with self.assertRaises(client.ActorError) as caught:
            await sandbox.close()
        self.assertEqual(caught.exception.owner_reason, 'owner_unavailable')
        self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (False, True))
        receipt = await self.recover(owner, sandbox.identity)
        self.assertEqual((receipt['status'], receipt['cleanup_confirmed']), ('confirmed', True))
        self.assertEqual(owner.ops, ['health', 'open_level', 'close', 'level_receipt'])  # no second close, no second open
        self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (False, True))  # it reports; it does not rewrite

    async def test_unknown_before_finish_and_confirmed_after_it(self):
        owner = LevelOwner()
        sandbox = await self.entered(owner)
        error = await self.assertUnconfirmed(owner, sandbox.identity, 'receipt_unknown')
        self.assertEqual(error.receipt_status, 'unknown')
        self.assertEqual(owner.ops, ['health', 'open_level', 'level_receipt'])  # asking never closed anything
        self.assertTrue(sandbox.obligation)
        await sandbox.close()
        self.assertEqual((await self.recover(owner, sandbox.identity))['status'], 'confirmed')

    async def test_another_context_never_confirms_another_closure(self):
        owner = LevelOwner()
        identity = await self.closed_identity(owner)
        crossed = {**identity, 'context_sha256': OTHER_CONTEXT}
        error = await self.assertUnconfirmed(owner, crossed, 'receipt_unknown')  # the owner has no FINISH for that context
        self.assertEqual(error.receipt_status, 'unknown')
        # an owner that answers with the original context to a question about another one is refused as a malformed answer
        owner.receipt_patch = {'context_sha256': identity['context_sha256']}
        await self.assertUnconfirmed(owner, crossed, 'owner_response_invalid')
        owner.receipt_patch = {'context_sha256': OTHER_CONTEXT}
        await self.assertUnconfirmed(owner, identity, 'owner_response_invalid')  # asked the original, answered with another
        owner.receipt_patch = {}
        self.assertEqual((await self.recover(owner, identity))['status'], 'confirmed')

    async def test_a_second_run_with_another_context_keeps_each_receipt_apart(self):
        owner = LevelOwner()
        first = await self.closed_identity(owner)
        owner.open_patch = {'intent_id': '3' * 32, 'name': 'escape-actor-' + '3' * 32, 'container_id': 'd' * 64}
        second = await self.closed_identity(owner, run_id='fedcba9876543210' * 2, context=OTHER_CONTEXT)
        self.assertNotEqual((first['context_sha256'], first['container_id']), (second['context_sha256'], second['container_id']))
        for identity in (first, second):
            self.assertEqual((await self.recover(owner, identity))['status'], 'confirmed')
        for key in ('context_sha256', 'run_id', 'intent_id', 'container_id'):
            await self.assertUnconfirmed(owner, {**first, key: second[key]}, 'receipt_unknown')
            await self.assertUnconfirmed(owner, {**second, key: first[key]}, 'receipt_unknown')
        restarted = client.Settings(SETTINGS.socket_path, SETTINGS.owner_uid, installation_id=INSTALL)  # no session, no lease
        for identity in (first, second):
            self.assertEqual((await self.recover(owner, identity, restarted))['status'], 'confirmed')

    async def test_an_identity_the_owner_never_saw_is_unknown_not_confirmed(self):
        owner = LevelOwner()
        error = await self.assertUnconfirmed(owner, LEVEL_IDENTITY, 'receipt_unknown')
        self.assertEqual((error.receipt_status, owner.ops), ('unknown', ['level_receipt']))

    async def test_transport_and_owner_failures_fail_closed_with_one_attempt(self):
        cases = (
            (OSError('refused'), 'owner_unavailable'), (TimeoutError(), 'owner_unavailable'),
            (wire.WireError('timeout'), 'owner_unavailable'), (wire.WireError('peer_mismatch'), 'owner_peer_unverified'),
            (wire.WireError('peer_unverified'), 'owner_peer_unverified'),
            (wire.WireError('linux_peer_credentials_required'), 'owner_peer_unverified'),
            (wire.WireError('truncated'), 'owner_response_invalid'), (wire.WireError('trailing_bytes'), 'owner_response_invalid'),
            (b'not json', 'owner_response_invalid'), (raw({'ok': True, 'op': 'level_receipt'}), 'owner_response_invalid'),
            (raw({'ok': True, 'op': 'health'}), 'owner_response_invalid'),
            (raw({'ok': True, 'op': 'receipt', **IDENTITY, 'status': 'confirmed', 'cleanup_confirmed': True}),
             'owner_response_invalid'),
            (wire.error_response('installation_mismatch'), 'installation_mismatch'),
            (wire.error_response('foreign_owner'), 'foreign_owner'), (wire.error_response('owner_blocked'), 'owner_blocked'),
            (wire.error_response('internal_error'), 'internal_error'), (wire.error_response('framing'), 'framing'),
            (wire.error_response('level_not_allowed'), 'level_not_allowed'),
        )
        for failure, reason in cases:
            with self.subTest(reason=reason, failure=repr(failure)[:30]):
                owner = LevelOwner()
                owner.finished.add(tuple(LEVEL_IDENTITY[name] for name in wire.LEVEL_IDENTITY_FIELDS))  # even if the diary has it
                owner.errors['level_receipt'] = failure
                await self.assertUnconfirmed(owner, LEVEL_IDENTITY, reason)
                self.assertEqual(owner.ops, ['level_receipt'])  # one attempt, no health, no retry

    async def test_an_answer_about_another_identity_or_with_a_bad_shape_never_confirms(self):
        other = {'installation_id': '9' * 32, 'run_id': '9' * 32, 'level': 'secret', 'stage': 'fresh',
                 'context_sha256': OTHER_CONTEXT, 'intent_id': '9' * 32, 'container_id': '9' * 64}
        identity_patches = [{key: value} for key, value in other.items()] + [dict(other)]
        shape_patches = [{'status': 'done'}, {'status': 'CONFIRMED'}, {'status': None}, {'status': 'unknown'},
                         {'cleanup_confirmed': False}, {'cleanup_confirmed': 1}, {'cleanup_confirmed': 'true'},
                         {'oom_killed': False}, {'handle': HANDLE}, {'variant': 'legitimate'}, {'op': 'close'}, {'ok': 1},
                         {'ok': False}]
        for finished in (True, False):  # the answer is just as invalid whether the owner would have confirmed or not
            for patch in identity_patches + (shape_patches if finished else []):
                with self.subTest(finished=finished, patch=str(patch)[:50]):
                    owner = LevelOwner()
                    if finished:
                        owner.finished.add(tuple(LEVEL_IDENTITY[name] for name in wire.LEVEL_IDENTITY_FIELDS))
                    owner.receipt_patch = patch
                    await self.assertUnconfirmed(owner, LEVEL_IDENTITY, 'owner_response_invalid')

    async def test_a_malformed_or_m1_identity_is_refused_before_anything_is_sent(self):
        bad = (None, {}, 'x', list(LEVEL_IDENTITY), {'installation_id': INSTALL}, {**LEVEL_IDENTITY, 'extra': 1},
               {**LEVEL_IDENTITY, 'handle': HANDLE}, {**LEVEL_IDENTITY, 'variant': 'legitimate'}, IDENTITY,
               {key: value for key, value in LEVEL_IDENTITY.items() if key != 'context_sha256'},
               {key: value for key, value in LEVEL_IDENTITY.items() if key != 'level'},
               {**LEVEL_IDENTITY, 'installation_id': 'A' * 32}, {**LEVEL_IDENTITY, 'run_id': RUN[:-1]},
               {**LEVEL_IDENTITY, 'level': 'Persistence'}, {**LEVEL_IDENTITY, 'level': 'legitimate'},
               {**LEVEL_IDENTITY, 'stage': 'fresh'}, {**LEVEL_IDENTITY, 'context_sha256': CONTEXT[:-1]},
               {**LEVEL_IDENTITY, 'context_sha256': None}, {**LEVEL_IDENTITY, 'intent_id': None},
               {**LEVEL_IDENTITY, 'container_id': CONTAINER[:-1]}, {**LEVEL_IDENTITY, 'container_id': 5})
        for identity in bad:
            with self.subTest(identity=str(identity)[:60]):
                owner = LevelOwner()
                await self.assertUnconfirmed(owner, identity, 'identity_invalid')
                self.assertEqual(owner.ops, [])

    async def test_each_recovery_function_refuses_the_other_domains_identity(self):
        owner = LevelOwner()
        with self.assertRaises(client.ActorError) as caught:
            await client.recover_receipt(SETTINGS, LEVEL_IDENTITY, transport=owner)
        self.assertEqual(caught.exception.owner_reason, 'identity_invalid')  # M1 recovery keeps its five-field identity
        await self.assertUnconfirmed(owner, IDENTITY, 'identity_invalid')
        self.assertEqual(owner.ops, [])

    async def test_the_pinned_installation_must_match_the_identity(self):
        owner = LevelOwner()
        wrong = client.Settings(SETTINGS.socket_path, SETTINGS.owner_uid, installation_id='9' * 32)
        await self.assertUnconfirmed(owner, LEVEL_IDENTITY, 'installation_mismatch', settings=wrong)
        self.assertEqual(owner.ops, [])  # refused locally: another installation never receives the question
        right = client.Settings(SETTINGS.socket_path, SETTINGS.owner_uid, installation_id=INSTALL)
        await self.assertUnconfirmed(owner, LEVEL_IDENTITY, 'receipt_unknown', settings=right)
        self.assertEqual(owner.ops, ['level_receipt'])

    async def test_it_is_a_repeatable_read_that_never_opens_executes_probes_or_closes(self):
        owner = LevelOwner()
        identity = await self.closed_identity(owner)
        before = list(owner.ops)
        with mock.patch('asyncio.create_subprocess_exec', side_effect=AssertionError('spawned')) as spawn, \
                mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('spawned')) as popen:
            for _ in range(3):
                self.assertEqual((await self.recover(owner, identity))['status'], 'confirmed')
        self.assertEqual(owner.ops, before + ['level_receipt'] * 3)
        for op in ('health', 'open_level', 'execute', 'probe', 'level_probe', 'close'):
            self.assertEqual(owner.ops.count(op), before.count(op), op)
        self.assertEqual((spawn.call_count, popen.call_count), (0, 0))

    async def test_cancellation_propagates_and_nothing_more_is_sent(self):
        owner = LevelOwner()
        owner.gates['level_receipt'] = asyncio.Event()
        task = asyncio.ensure_future(self.recover(owner))
        await self.wait_for_op(owner, 'level_receipt')
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(owner.ops, ['level_receipt'])

    async def test_the_default_transport_uses_the_level_receipt_limits(self):
        seen = {}
        answer = wire.encode_response('level_receipt', {**LEVEL_IDENTITY, 'status': 'confirmed', 'cleanup_confirmed': True})

        def blocking(settings, payload, *, response_limit, deadline, **kwargs):
            seen.update(settings=settings, payload=payload, response_limit=response_limit, deadline=deadline)
            return answer
        with mock.patch.object(client, 'blocking_exchange', blocking):
            receipt = await client.recover_level_receipt(SETTINGS, LEVEL_IDENTITY)
        self.assertEqual((seen['settings'], seen['response_limit'], seen['deadline']), (SETTINGS, 1024, 8.0))
        request = proto.decode_request(seen['payload'])
        self.assertEqual((request.op, request.installation_id, request.container_id, request.context_sha256),
                         ('level_receipt', INSTALL, CONTAINER, CONTEXT))
        self.assertEqual(receipt['status'], 'confirmed')


class LevelTransportTests(unittest.TestCase):
    OPEN = wire.encode_request('open_level', run_id=RUN, level='memory', stage='actor', context_sha256=CONTEXT)
    RECEIPT = wire.encode_request('level_receipt', **LEVEL_IDENTITY)
    PROBE = wire.encode_request('level_probe', handle=HANDLE, name='cgroup_events')
    ANSWER = wire.encode_response('level_receipt', {**LEVEL_IDENTITY, 'status': 'confirmed', 'cleanup_confirmed': True})

    def exchange(self, peer, payload, op, **kwargs):
        options = dict(response_limit=wire.RESPONSE_LIMITS[op], deadline=wire.CLIENT_DEADLINES[op], socket_factory=lambda: peer)
        options.update(kwargs)
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            return client.blocking_exchange(SETTINGS, payload, **options)

    def test_an_unexpected_owner_uid_receives_not_a_single_byte_of_any_level_request(self):
        for payload, op in ((self.OPEN, 'open_level'), (self.RECEIPT, 'level_receipt'), (self.PROBE, 'level_probe')):
            peer = FakePeer(SETTINGS.owner_uid + 1)
            with self.assertRaises(wire.WireError) as caught:
                self.exchange(peer, payload, op)
            self.assertEqual(caught.exception.reason, 'peer_mismatch')
            self.assertNotIn('sendall', peer.names())
            self.assertNotIn('shutdown', peer.names())
            self.assertEqual(peer.names()[-1], 'close')

    def test_a_verified_owner_gets_one_frame_and_answers_with_one_frame(self):
        peer = FakePeer(SETTINGS.owner_uid, wire.encode_frame(self.ANSWER, limit=wire.RESPONSE_LIMITS['level_receipt']))
        self.assertEqual(self.exchange(peer, self.RECEIPT, 'level_receipt'), self.ANSWER)
        names = peer.names()
        self.assertLess(names.index('getsockopt'), names.index('sendall'))
        self.assertLess(names.index('sendall'), names.index('shutdown'))
        self.assertEqual(bytes(peer.sent), wire.encode_frame(self.RECEIPT, limit=wire.MAX_REQUEST_BYTES))
        decoded = wire.decode_response(self.ANSWER, op='level_receipt')
        self.assertEqual(wire.validate_level_receipt(decoded, identity=LEVEL_IDENTITY)['status'], 'confirmed')

    def test_an_answer_beyond_each_level_limit_is_rejected_before_its_body(self):
        for op in ('open_level', 'level_receipt', 'level_probe'):
            peer = FakePeer(SETTINGS.owner_uid, struct.pack('>I', wire.RESPONSE_LIMITS[op] + 1) + b'x')
            with self.assertRaises(wire.WireError) as caught:
                self.exchange(peer, self.PROBE, op)
            self.assertEqual(caught.exception.reason, 'too_large')

    def test_the_client_module_stays_pure_with_the_level_facade(self):
        tree = ast.parse(MODULE.read_text(encoding='utf-8'))
        classes = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
        self.assertTrue({'ActorSession', 'LevelSession'} <= classes)
        functions = {node.name for node in tree.body if isinstance(node, ast.AsyncFunctionDef)}
        self.assertTrue({'health', 'recover_receipt', 'recover_level_receipt'} <= functions)


# ------------------------------------------------------------------------------------------------------- M2.3 · persistence
# A scripted owner for persistence/actor and persistence/fresh. Like the real owner it keeps its OWN durable register of finished phases,
# derives the predecessor of a fresh phase from the FINISH of the actor phase (never from a request), and answers `unknown` for a fresh
# phase with predecessor null. Authored without a shell: none of these tests has been executed by the author.

from types import MappingProxyType  # noqa: E402

B_INTENT = '4' * 32
B_CONTAINER = 'e' * 64
A_IDENTITY = {**LEVEL_IDENTITY, 'level': 'persistence'}  # persistence/actor, the phase that is pinned
B_IDENTITY = {**A_IDENTITY, 'stage': 'fresh', 'intent_id': B_INTENT, 'container_id': B_CONTAINER}
MARKER = '/work/marker-' + 'a' * 24
OTHER_MARKER = '/work/marker-' + 'f' * 24
DIGEST = 'b' * 64
SIZE = 24
FILE_PRESENT_BODY = {'status': 'present', 'inode': 7, 'size': SIZE, 'mtime': 1700000000, 'ctime': 1700000001, 'links': 1,
                     'sha256': 'a' * 64}
SCAN_EMPTY_BODY = {'verifier_version': 'persistence-copy/v2', 'complete': True, 'reasons': [], 'matches': [], 'matches_total': 0,
                   'entries': 3, 'bytes_read': 96, 'skipped_nonregular': 0}
SCAN_MATCH = {'path': '/tmp/copy-1', 'size': SIZE, 'links': 1}
PIN_OTHER = {'installation_id': '9' * 32, 'run_id': '9' * 32, 'context_sha256': OTHER_CONTEXT, 'intent_id': '9' * 32,
             'container_id': '9' * 64}
# Pins that are refused when the session is built AND when a receipt is recovered: malformed, not a persistence/actor identity, or
# bound to another run or context than the phase that follows. Two kinds are only decidable later and are tested where they can be:
# a pin sharing an ID with B (B's IDs are unknown until it opens) and a pin of another installation (the owner's is unknown until
# health, unless the settings pin one).
BAD_PINS = (None, {}, 'x', 5, [], list(A_IDENTITY), MappingProxyType(A_IDENTITY), {**A_IDENTITY, 'extra': 1},
            {**A_IDENTITY, 'variant': 'legitimate'}, {key: value for key, value in A_IDENTITY.items() if key != 'run_id'},
            {key: value for key, value in A_IDENTITY.items() if key != 'context_sha256'}, {**A_IDENTITY, 'level': 'memory'},
            {**A_IDENTITY, 'stage': 'fresh'}, {**A_IDENTITY, 'installation_id': 'X' * 32}, {**A_IDENTITY, 'container_id': 'c' * 63},
            {**A_IDENTITY, 'intent_id': None}, {**A_IDENTITY, 'context_sha256': 5}, {**A_IDENTITY, 'run_id': PIN_OTHER['run_id']},
            {**A_IDENTITY, 'context_sha256': PIN_OTHER['context_sha256']}, B_IDENTITY)
SAME_ID_PINS = ({**A_IDENTITY, 'container_id': B_CONTAINER}, {**A_IDENTITY, 'intent_id': B_INTENT})
OTHER_INSTALLATION_PIN = {**A_IDENTITY, 'installation_id': PIN_OTHER['installation_id']}
LYING_PREDECESSORS = (None, {}, 'x', {**A_IDENTITY, 'extra': 1}, {key: value for key, value in A_IDENTITY.items() if key != 'run_id'},
                      {**A_IDENTITY, 'level': 'memory'}, {**A_IDENTITY, 'stage': 'fresh'},
                      *({**A_IDENTITY, key: value} for key, value in PIN_OTHER.items()),
                      {**A_IDENTITY, 'container_id': B_CONTAINER}, {**A_IDENTITY, 'intent_id': B_INTENT}, B_IDENTITY)


class PersistenceOwner(LevelOwner):
    def __init__(self):
        super().__init__()
        self.payloads = []
        self.file_answer = {'status': 'missing'}
        self.scan_answer = dict(SCAN_EMPTY_BODY)

    async def __call__(self, settings, payload, *, response_limit, deadline):
        self.payloads.append(bytes(payload))
        return await super().__call__(settings, payload, response_limit=response_limit, deadline=deadline)

    def finished_actor(self, run_id, context_sha256):
        """The owner's own durable view: the FINISH of the persistence/actor phase of that run and context, or None."""
        for key in self.finished:
            identity = dict(zip(wire.LEVEL_IDENTITY_FIELDS, key))
            if (identity['level'], identity['stage'], identity['run_id'], identity['context_sha256']) == (
                    'persistence', 'actor', run_id, context_sha256):
                return identity
        return None

    def on_open_level(self, request):
        fresh = request.stage == 'fresh'
        intent, container = (B_INTENT, B_CONTAINER) if fresh else (INTENT, CONTAINER)
        body = {'handle': HANDLE, 'installation_id': INSTALL, 'run_id': request.run_id, 'level': request.level, 'stage': request.stage,
                'context_sha256': request.context_sha256, 'intent_id': intent, 'name': 'escape-actor-' + intent,
                'container_id': container, 'profile_sha256': self.sha, 'profile': self.profile}
        if fresh:
            predecessor = self.finished_actor(request.run_id, request.context_sha256)
            if predecessor is None:
                return wire.error_response('predecessor_unconfirmed')
            body['predecessor'] = predecessor
        body.update(self.open_patch)
        self.identity = {key: body[key] for key in wire.LEVEL_IDENTITY_FIELDS}
        return wire.encode_response('open_level', body)

    def on_close(self, request):
        self.finished.add(self.key())
        body = {**self.identity, 'cleanup_confirmed': True, 'oom_killed': False, **MEAS}
        if self.identity['stage'] == 'fresh':
            body['predecessor'] = self.finished_actor(self.identity['run_id'], self.identity['context_sha256'])
        body.update(self.close_patch)
        return wire.encode_response('close', body)

    def on_level_receipt(self, request):
        asked = {name: getattr(request, name) for name in wire.LEVEL_IDENTITY_FIELDS}
        confirmed = tuple(asked[name] for name in wire.LEVEL_IDENTITY_FIELDS) in self.finished
        body = {**asked, 'status': 'confirmed' if confirmed else 'unknown', 'cleanup_confirmed': confirmed}
        if asked['stage'] == 'fresh':
            body['predecessor'] = self.finished_actor(asked['run_id'], asked['context_sha256']) if confirmed else None
        body.update(self.receipt_patch)
        return wire.encode_response('level_receipt', body)

    def on_level_probe(self, request):
        if request.name == 'file_state':
            return wire.encode_response('level_probe', dict(self.file_answer))
        if request.name == 'copy_scan':
            return wire.encode_response('level_probe', dict(self.scan_answer))
        return super().on_level_probe(request)


class PersistenceCase(LevelClientCase):
    def persistence(self, owner, stage='actor', predecessor=None, settings=SETTINGS, **kwargs):
        return client.LevelSession(settings, run_id=kwargs.pop('run_id', RUN), level='persistence', stage=stage,
                                   context_sha256=kwargs.pop('context', CONTEXT), predecessor=predecessor, transport=owner)

    async def closed_a(self, owner):
        async with self.persistence(owner, 'actor') as a:
            identity = a.identity
        self.assertTrue(a.cleanup_confirmed)
        return identity

    async def entered_b(self, owner, pin=A_IDENTITY):
        sandbox = self.persistence(owner, 'fresh', pin)
        await sandbox.__aenter__()
        return sandbox

    async def wait_count(self, owner, op, count):
        for _ in range(500):
            if owner.ops.count(op) >= count:
                return
            await asyncio.sleep(0.001)
        self.fail('owner never received %s x%d' % (op, count))

    async def recover(self, owner, identity, predecessor=None, settings=SETTINGS):
        return await client.recover_level_receipt(settings, identity, predecessor=predecessor, transport=owner)

    async def assertUnconfirmed(self, owner, identity, owner_reason, predecessor=None, settings=SETTINGS):
        with self.assertRaises(client.ActorError) as caught:
            await self.recover(owner, identity, predecessor, settings)
        error = caught.exception
        self.assertEqual((error.reason, error.cleanup_confirmed, str(error)),
                         ('cleanup_unconfirmed', False, 'Sandbox cleanup could not be confirmed'))
        self.assertEqual(error.owner_reason, owner_reason)
        return error


class PersistencePinTests(PersistenceCase):
    def test_a_fresh_phase_needs_the_pin_and_every_other_phase_refuses_one(self):
        self.assertEqual(self.persistence(None, 'actor').level, 'persistence')
        self.assertIsNone(self.persistence(None, 'actor').predecessor)
        self.assertEqual(self.persistence(None, 'fresh', A_IDENTITY).stage, 'fresh')
        with self.assertRaises(ValueError):
            self.persistence(None, 'fresh')  # a fresh phase without the pin of its actor phase
        with self.assertRaises(ValueError):
            self.persistence(None, 'actor', A_IDENTITY)  # an actor phase has no predecessor
        for level in ('memory', 'secret'):
            with self.assertRaises(ValueError):
                client.LevelSession(SETTINGS, run_id=RUN, level=level, stage='actor', context_sha256=CONTEXT, predecessor=A_IDENTITY)
            with self.assertRaises(ValueError):
                client.LevelSession(SETTINGS, run_id=RUN, level=level, stage='fresh', context_sha256=CONTEXT, predecessor=A_IDENTITY)
        with self.assertRaises(ValueError):
            client.LevelSession(SETTINGS, run_id=RUN, level='persistence', stage='x', context_sha256=CONTEXT)

    def test_the_pin_is_validated_when_the_session_is_built(self):
        for pin in BAD_PINS:
            with self.subTest(pin=str(pin)[:70]):
                with self.assertRaises(ValueError):
                    self.persistence(None, 'fresh', pin)
        for settings, ok_pin in ((client.Settings(SETTINGS.socket_path, SETTINGS.owner_uid, installation_id=INSTALL), True),
                                 (client.Settings(SETTINGS.socket_path, SETTINGS.owner_uid, installation_id='9' * 32), False)):
            if ok_pin:
                self.assertEqual(self.persistence(None, 'fresh', A_IDENTITY, settings).predecessor, A_IDENTITY)
            else:
                with self.assertRaises(ValueError):  # the settings pin another installation than the pinned phase A
                    self.persistence(None, 'fresh', A_IDENTITY, settings)
        with self.assertRaises(ValueError):  # the pin must share this session's run and context
            self.persistence(None, 'fresh', A_IDENTITY, run_id='fedcba9876543210' * 2)
        with self.assertRaises(ValueError):
            self.persistence(None, 'fresh', A_IDENTITY, context=OTHER_CONTEXT)

    def test_the_pin_is_copied_defensively_and_kept_apart_from_the_identity(self):
        pin = dict(A_IDENTITY)
        sandbox = self.persistence(None, 'fresh', pin)
        pin['container_id'] = 'f' * 64  # the caller changes its own dict afterwards
        pin['run_id'] = '9' * 32
        self.assertEqual(sandbox.predecessor, A_IDENTITY)
        handed_out = sandbox.predecessor
        handed_out['container_id'] = '0' * 64  # and changing what it was handed changes nothing either
        handed_out.clear()
        self.assertEqual(sandbox.predecessor, A_IDENTITY)
        self.assertIsNot(sandbox.predecessor, sandbox.predecessor)
        self.assertIsNone(sandbox.identity)  # the pin is not this phase's identity

    def test_a_dict_that_overrides_its_accessors_cannot_influence_the_copy(self):
        class Sneaky(dict):
            def items(self):
                raise AssertionError('an overridden accessor was used')

            def __getitem__(self, key):
                raise AssertionError('an overridden accessor was used')

            def get(self, *args):
                raise AssertionError('an overridden accessor was used')
        sandbox = self.persistence(None, 'fresh', Sneaky(A_IDENTITY))
        self.assertEqual(sandbox.predecessor, A_IDENTITY)
        self.assertIs(type(sandbox.predecessor), dict)

    def test_repr_does_not_leak_the_handle_the_context_or_the_pin(self):
        sandbox = self.persistence(None, 'fresh', A_IDENTITY)
        for secret in (HANDLE, CONTEXT, A_IDENTITY['container_id'], A_IDENTITY['intent_id']):
            self.assertNotIn(secret, repr(sandbox))


class FreshPhaseTests(PersistenceCase):
    async def test_a_then_b_are_two_identities_and_no_request_carries_the_predecessor(self):
        owner = PersistenceOwner()
        self.assertEqual(await self.closed_a(owner), A_IDENTITY)
        async with self.persistence(owner, 'fresh', A_IDENTITY) as b:
            self.assertEqual(b.identity, B_IDENTITY)
            self.assertEqual(b.predecessor, A_IDENTITY)
            self.assertNotEqual(b.identity, b.predecessor)
            self.assertEqual(sorted(b.identity), sorted(wire.LEVEL_IDENTITY_FIELDS))
            self.assertNotIn('predecessor', b.identity)
            self.assertEqual(b.name, 'escape-actor-' + B_INTENT)
            opened = owner.calls[-1][1]
            self.assertEqual((opened.op, opened.level, opened.stage, opened.context_sha256, opened.run_id),
                             ('open_level', 'persistence', 'fresh', CONTEXT, RUN))
            self.assertFalse(hasattr(opened, 'predecessor'))
        self.assertEqual(owner.ops, ['health', 'open_level', 'close', 'health', 'open_level', 'close'])
        self.assertTrue(b.cleanup_confirmed)
        self.assertEqual((b.obligation, b.created), (False, False))
        for payload in owner.payloads:  # nothing about the pin ever travelled
            self.assertNotIn(b'predecessor', payload)
            self.assertNotIn(CONTAINER.encode(), payload)

    async def test_a_fresh_phase_asked_before_its_actor_phase_is_a_clean_refusal(self):
        owner = PersistenceOwner()
        with self.assertRaises(client.ActorError) as caught:
            async with self.persistence(owner, 'fresh', A_IDENTITY):
                self.fail('must not enter')
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('predecessor_unconfirmed', None))
        self.assertEqual(owner.ops, ['health', 'open_level'])  # asked once, no close, nothing retried
        sandbox = self.persistence(owner, 'fresh', A_IDENTITY)
        with self.assertRaises(client.ActorError):
            await sandbox.__aenter__()
        self.assertEqual((sandbox.obligation, sandbox.created), (False, False))

    async def test_an_owner_that_names_another_predecessor_is_refused_and_no_handle_is_trusted(self):
        for lie in LYING_PREDECESSORS:
            with self.subTest(lie=str(lie)[:70]):
                owner = PersistenceOwner()
                await self.closed_a(owner)
                owner.open_patch = {'predecessor': lie}
                with self.assertRaises(client.ActorError) as caught:
                    async with self.persistence(owner, 'fresh', A_IDENTITY):
                        self.fail('must not enter')
                self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('owner_response_invalid', False))
                self.assertEqual(owner.ops[-2:], ['health', 'open_level'])  # no close with an untrusted handle

    async def test_the_two_open_shapes_are_never_mixed(self):
        owner = PersistenceOwner()
        await self.closed_a(owner)
        base = {'handle': HANDLE, 'installation_id': INSTALL, 'run_id': RUN, 'context_sha256': CONTEXT, 'profile_sha256': owner.sha,
                'profile': PROFILE, 'level': 'persistence'}
        fresh_without = wire.encode_response('open_level', {**base, 'stage': 'fresh', 'intent_id': B_INTENT, 'container_id': B_CONTAINER,
                                                            'name': 'escape-actor-' + B_INTENT})
        actor_with = wire.encode_response('open_level', {**base, 'stage': 'actor', 'intent_id': INTENT, 'container_id': CONTAINER,
                                                         'name': 'escape-actor-' + INTENT, 'predecessor': dict(A_IDENTITY)})
        for stage, pin, answer in (('fresh', A_IDENTITY, fresh_without), ('actor', None, actor_with)):
            owner.errors['open_level'] = answer
            with self.assertRaises(client.ActorError) as caught:
                async with self.persistence(owner, stage, pin):
                    self.fail('must not enter')
            self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('owner_response_invalid', False))
        owner.errors['open_level'] = wire.encode_response('open_level', {**base, 'level': 'memory', 'stage': 'fresh', 'intent_id': B_INTENT,
                                                                           'container_id': B_CONTAINER, 'name': 'escape-actor-' + B_INTENT,
                                                                           'predecessor': dict(A_IDENTITY)})
        with self.assertRaises(client.ActorError) as caught:  # memory/fresh does not exist in any answer
            async with self.persistence(owner, 'fresh', A_IDENTITY):
                self.fail('must not enter')
        self.assertEqual(caught.exception.reason, 'owner_response_invalid')

    async def test_a_phase_that_would_be_its_own_predecessor_is_refused(self):
        for patch in ({'container_id': CONTAINER}, {'intent_id': INTENT, 'name': 'escape-actor-' + INTENT}):
            owner = PersistenceOwner()
            await self.closed_a(owner)
            owner.open_patch = patch
            with self.assertRaises(client.ActorError) as caught:
                async with self.persistence(owner, 'fresh', A_IDENTITY):
                    self.fail('must not enter')
            self.assertEqual(caught.exception.reason, 'owner_response_invalid')

    async def test_a_pin_of_another_installation_than_the_owner_reports_asks_nothing(self):
        owner = PersistenceOwner()
        await self.closed_a(owner)
        owner.health['installation_id'] = '9' * 32
        before = list(owner.ops)
        with self.assertRaises(client.ActorError) as caught:
            async with self.persistence(owner, 'fresh', A_IDENTITY):
                self.fail('must not enter')
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('installation_mismatch', None))
        self.assertEqual(owner.ops, before + ['health'])  # health was read, open_level was never sent

    async def test_close_confirms_only_with_the_pinned_predecessor(self):
        owner = PersistenceOwner()
        await self.closed_a(owner)
        for lie in LYING_PREDECESSORS:
            with self.subTest(lie=str(lie)[:70]):
                sandbox = await self.entered_b(owner)
                owner.close_patch = {'predecessor': lie}
                with self.assertRaises(client.ActorError) as caught:
                    await sandbox.close()
                self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('cleanup_unconfirmed', False))
                self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (False, True))
                owner.close_patch = {}
                await sandbox.close()  # the honest answer does
                self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (True, False))
                self.assertEqual(sandbox.predecessor, A_IDENTITY)

    async def test_a_close_without_a_predecessor_or_in_the_actor_shape_never_confirms(self):
        owner = PersistenceOwner()
        await self.closed_a(owner)
        sandbox = await self.entered_b(owner)
        owner.errors['close'] = wire.encode_response('close', {**B_IDENTITY, 'cleanup_confirmed': True, 'oom_killed': False, **MEAS})
        with self.assertRaises(client.ActorError) as caught:
            await sandbox.close()
        self.assertEqual(caught.exception.reason, 'cleanup_unconfirmed')
        self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (False, True))
        del owner.errors['close']
        await sandbox.close()
        self.assertTrue(sandbox.cleanup_confirmed)
        actor = self.persistence(owner, 'actor', run_id='fedcba9876543210' * 2)
        await actor.__aenter__()
        owner.errors['close'] = wire.encode_response('close', {**actor.identity, 'predecessor': dict(A_IDENTITY),
                                                               'cleanup_confirmed': True, 'oom_killed': False, **MEAS})
        with self.assertRaises(client.ActorError):
            await actor.close()
        self.assertEqual((actor.cleanup_confirmed, actor.obligation), (False, True))

    async def test_a_lost_close_answer_of_each_phase_is_recovered_by_its_exact_receipt_without_replay(self):
        owner = PersistenceOwner()
        owner.lost_after_finish = 1
        a = self.persistence(owner, 'actor')
        await a.__aenter__()
        with self.assertRaises(client.ActorError):
            await a.close()
        receipt_a = await self.recover(owner, a.identity)
        self.assertEqual((receipt_a['status'], receipt_a['cleanup_confirmed']), ('confirmed', True))
        self.assertNotIn('predecessor', receipt_a)
        self.assertEqual((a.cleanup_confirmed, a.obligation), (False, True))  # recovery reports; it does not rewrite the session
        owner.lost_after_finish = 1
        b = await self.entered_b(owner)
        with self.assertRaises(client.ActorError):
            await b.close()
        receipt_b = await self.recover(owner, b.identity, A_IDENTITY)
        self.assertEqual((receipt_b['status'], receipt_b['predecessor']), ('confirmed', A_IDENTITY))
        self.assertEqual(owner.ops, ['health', 'open_level', 'close', 'level_receipt', 'health', 'open_level', 'close', 'level_receipt'])

    async def test_cancellation_during_open_restores_a_granted_handle_in_both_phases_and_propagates(self):
        owner = PersistenceOwner()
        for index, (stage, pin) in enumerate((('actor', None), ('fresh', A_IDENTITY)), 1):
            owner.gates['open_level'] = asyncio.Event()
            sandbox = self.persistence(owner, stage, pin)
            task = asyncio.ensure_future(sandbox.__aenter__())
            await self.wait_count(owner, 'open_level', index)
            task.cancel()
            owner.gates['open_level'].set()
            with self.assertRaises(asyncio.CancelledError) as caught:
                await task
            self.assertTrue(sandbox.cleanup_confirmed)
            self.assertIs(caught.exception.cleanup_confirmed, True)
            self.assertEqual(owner.ops[-3:], ['health', 'open_level', 'close'])
        self.assertEqual(owner.ops.count('open_level'), 2)  # one open per phase: nothing was replayed

    async def test_cancellation_during_execute_and_a_probe_propagates_in_both_phases_and_exit_restitutes(self):
        owner = PersistenceOwner()
        for stage, pin in (('actor', None), ('fresh', A_IDENTITY)):
            async with self.persistence(owner, stage, pin) as sandbox:
                for op, call in (('execute', lambda: sandbox.execute('sleep 99')),
                                 ('level_probe', lambda: sandbox.copy_scan(DIGEST, SIZE)),
                                 ('level_probe', lambda: sandbox.file_state(MARKER))):
                    owner.gates[op] = asyncio.Event()
                    count = owner.ops.count(op) + 1
                    task = asyncio.ensure_future(call())
                    await self.wait_count(owner, op, count)
                    task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await task
                    del owner.gates[op]
            self.assertTrue(sandbox.cleanup_confirmed)
            self.assertEqual(owner.ops[-1], 'close')
        self.assertEqual((owner.ops.count('execute'), owner.ops.count('level_probe')), (2, 4))  # none repeated

    async def test_a_transport_failure_of_a_probe_is_one_failure_and_never_a_replay(self):
        owner = PersistenceOwner()
        async with self.persistence(owner, 'actor') as sandbox:
            owner.errors['level_probe'] = OSError('reset')
            for call in (lambda: sandbox.file_state(MARKER), lambda: sandbox.copy_scan(DIGEST, SIZE, MARKER)):
                before = owner.ops.count('level_probe')
                with self.assertRaises(client.ActorError) as caught:
                    await call()
                self.assertEqual(str(caught.exception), 'Actor controller unavailable')
                self.assertEqual(owner.ops.count('level_probe'), before + 1)
            self.assertNotIn('close', owner.ops)
        self.assertEqual(owner.ops[-1], 'close')


class FreshReceiptRecoveryTests(PersistenceCase):
    async def both_closed(self):
        owner = PersistenceOwner()
        a = await self.closed_a(owner)
        async with self.persistence(owner, 'fresh', A_IDENTITY) as sandbox:
            b = sandbox.identity
        self.assertTrue(sandbox.cleanup_confirmed)
        return owner, a, b

    async def test_the_exact_finish_of_each_phase_confirms_and_b_names_the_pinned_predecessor(self):
        owner, a, b = await self.both_closed()
        before = list(owner.ops)
        receipt_a = await self.recover(owner, a)
        receipt_b = await self.recover(owner, b, A_IDENTITY)
        self.assertEqual(receipt_a, {'ok': True, 'op': 'level_receipt', **A_IDENTITY, 'status': 'confirmed', 'cleanup_confirmed': True})
        self.assertEqual(receipt_b, {'ok': True, 'op': 'level_receipt', **B_IDENTITY, 'predecessor': A_IDENTITY, 'status': 'confirmed',
                                     'cleanup_confirmed': True})
        self.assertEqual(owner.ops, before + ['level_receipt', 'level_receipt'])  # nothing but the two questions
        receipt_b['predecessor']['run_id'] = '9' * 32
        self.assertEqual((await self.recover(owner, b, A_IDENTITY))['predecessor'], A_IDENTITY)  # each call, its own copy

    async def test_the_pin_is_validated_before_anything_is_sent_and_a_fresh_identity_needs_it(self):
        owner, a, b = await self.both_closed()
        before = list(owner.ops)
        for pin in (*BAD_PINS, *SAME_ID_PINS, OTHER_INSTALLATION_PIN):  # here B's own IDs and installation are known
            with self.subTest(pin=str(pin)[:70]):
                await self.assertUnconfirmed(owner, b, 'predecessor_invalid', pin)
        await self.assertUnconfirmed(owner, a, 'predecessor_invalid', A_IDENTITY)  # an actor phase has no predecessor to pin
        await self.assertUnconfirmed(owner, a, 'predecessor_invalid', B_IDENTITY)
        self.assertEqual(owner.ops, before)  # refused locally: the owner never heard of any of them
        wrong = client.Settings(SETTINGS.socket_path, SETTINGS.owner_uid, installation_id='9' * 32)
        await self.assertUnconfirmed(owner, b, 'installation_mismatch', A_IDENTITY, wrong)
        self.assertEqual(owner.ops, before)

    async def test_a_fresh_phase_that_is_unknown_confirms_nothing_and_names_no_predecessor(self):
        owner = PersistenceOwner()
        await self.closed_a(owner)
        b = await self.entered_b(owner)  # ACTIVE: no FINISH yet
        error = await self.assertUnconfirmed(owner, b.identity, 'receipt_unknown', A_IDENTITY)
        self.assertEqual(error.receipt_status, 'unknown')
        self.assertEqual(owner.ops[-1], 'level_receipt')  # asking never closed anything
        self.assertTrue(b.obligation)
        owner.receipt_patch = {'predecessor': dict(A_IDENTITY)}  # an owner that names one while confirming nothing
        await self.assertUnconfirmed(owner, b.identity, 'owner_response_invalid', A_IDENTITY)
        owner.receipt_patch = {}
        await b.close()
        self.assertEqual((await self.recover(owner, b.identity, A_IDENTITY))['status'], 'confirmed')

    async def test_a_confirmation_with_another_or_no_predecessor_never_confirms(self):
        owner, a, b = await self.both_closed()
        for lie in LYING_PREDECESSORS:
            with self.subTest(lie=str(lie)[:70]):
                owner.receipt_patch = {'predecessor': lie}
                await self.assertUnconfirmed(owner, b, 'owner_response_invalid', A_IDENTITY)
        owner.receipt_patch = {'status': 'unknown', 'cleanup_confirmed': False, 'predecessor': dict(A_IDENTITY)}
        await self.assertUnconfirmed(owner, b, 'owner_response_invalid', A_IDENTITY)
        owner.receipt_patch = {}
        raw_without = wire.encode_response('level_receipt', {**B_IDENTITY, 'status': 'confirmed', 'cleanup_confirmed': True})
        owner.errors['level_receipt'] = raw_without  # the actor shape for a fresh identity
        await self.assertUnconfirmed(owner, b, 'owner_response_invalid', A_IDENTITY)
        owner.errors['level_receipt'] = wire.encode_response('level_receipt', {**A_IDENTITY, 'predecessor': dict(A_IDENTITY),
                                                                              'status': 'confirmed', 'cleanup_confirmed': True})
        await self.assertUnconfirmed(owner, a, 'owner_response_invalid')  # and the fresh shape for an actor identity

    async def test_the_receipt_of_one_phase_is_never_the_receipt_of_the_other(self):
        owner, a, b = await self.both_closed()
        # the owner has no FINISH for these mixtures of the two identities: unknown, never the other phase's confirmation
        await self.assertUnconfirmed(owner, {**a, 'intent_id': B_INTENT}, 'receipt_unknown')
        await self.assertUnconfirmed(owner, {**a, 'container_id': B_CONTAINER}, 'receipt_unknown')
        await self.assertUnconfirmed(owner, {**b, 'stage': 'actor'}, 'receipt_unknown')  # B's IDs asked as the actor phase
        await self.assertUnconfirmed(owner, {**b, 'run_id': PIN_OTHER['run_id']}, 'receipt_unknown',
                                     {**A_IDENTITY, 'run_id': PIN_OTHER['run_id']})  # B of another run, with a pin of that run
        # and a pin that shares an ID with the fresh identity is refused before the owner is asked at all
        before = list(owner.ops)
        await self.assertUnconfirmed(owner, {**a, 'stage': 'fresh'}, 'predecessor_invalid', A_IDENTITY)
        await self.assertUnconfirmed(owner, {**b, 'intent_id': INTENT}, 'predecessor_invalid', A_IDENTITY)
        await self.assertUnconfirmed(owner, {**b, 'container_id': CONTAINER}, 'predecessor_invalid', A_IDENTITY)
        self.assertEqual(owner.ops, before)
        self.assertEqual((await self.recover(owner, a))['status'], 'confirmed')
        self.assertEqual((await self.recover(owner, b, A_IDENTITY))['status'], 'confirmed')

    async def test_it_is_a_repeatable_read_that_never_opens_executes_probes_or_closes(self):
        owner, a, b = await self.both_closed()
        before = list(owner.ops)
        with mock.patch('asyncio.create_subprocess_exec', side_effect=AssertionError('spawned')) as spawn, \
                mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('spawned')) as popen:
            for _ in range(3):
                await self.recover(owner, a)
                await self.recover(owner, b, A_IDENTITY)
        self.assertEqual(owner.ops, before + ['level_receipt'] * 6)
        for op in ('health', 'open_level', 'execute', 'probe', 'level_probe', 'close'):
            self.assertEqual(owner.ops.count(op), before.count(op), op)
        self.assertEqual((spawn.call_count, popen.call_count), (0, 0))

    async def test_a_cancelled_recovery_sends_nothing_more(self):
        owner, a, b = await self.both_closed()
        owner.gates['level_receipt'] = asyncio.Event()
        count = owner.ops.count('level_receipt') + 1
        task = asyncio.ensure_future(self.recover(owner, b, A_IDENTITY))
        await self.wait_count(owner, 'level_receipt', count)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(owner.ops.count('level_receipt'), count)

    async def test_the_default_transport_carries_the_identity_alone_with_the_level_receipt_limits(self):
        seen = {}
        answer = wire.encode_response('level_receipt', {**B_IDENTITY, 'predecessor': dict(A_IDENTITY), 'status': 'confirmed',
                                                        'cleanup_confirmed': True})

        def blocking(settings, payload, *, response_limit, deadline, **kwargs):
            seen.update(payload=payload, response_limit=response_limit, deadline=deadline)
            return answer
        with mock.patch.object(client, 'blocking_exchange', blocking):
            receipt = await client.recover_level_receipt(SETTINGS, B_IDENTITY, predecessor=A_IDENTITY)
        self.assertEqual((seen['response_limit'], seen['deadline']), (1024, 8.0))
        request = proto.decode_request(seen['payload'])
        self.assertEqual((request.op, request.level, request.stage, request.container_id), ('level_receipt', 'persistence', 'fresh',
                                                                                          B_CONTAINER))
        self.assertNotIn(b'predecessor', seen['payload'])
        self.assertNotIn(CONTAINER.encode(), seen['payload'])
        self.assertEqual((receipt['status'], receipt['predecessor']), ('confirmed', A_IDENTITY))


class PersistenceProbeTests(PersistenceCase):
    async def test_file_state_returns_the_oracle_value_of_the_runner_and_sends_the_path_alone(self):
        owner = PersistenceOwner()
        for stage, pin in (('actor', None), ('fresh', A_IDENTITY)):
            if stage == 'fresh':
                await self.closed_a_if_needed(owner)
            async with self.persistence(owner, stage, pin) as sandbox:
                for answer in (FILE_PRESENT_BODY, {'status': 'missing'}, {'status': 'unavailable'}):
                    owner.file_answer = dict(answer)
                    expected = runner.file_state_value(runner.parse_file_state(0, json.dumps(answer)))
                    self.assertEqual(await sandbox.file_state(MARKER), expected)
                    request = owner.calls[-1][1]
                    self.assertEqual((request.op, request.handle, request.name, request.path), ('level_probe', HANDLE, 'file_state', MARKER))
                    self.assertEqual((request.sha256, request.size, request.exclude, request.command), (None, None, None, None))
        self.assertEqual(runner.file_state_value(runner.parse_file_state(0, json.dumps(FILE_PRESENT_BODY))),
                         (7, SIZE, 1700000000, 1700000001, 1, 'a' * 64))

    async def closed_a_if_needed(self, owner):
        if owner.finished_actor(RUN, CONTEXT) is None:
            await self.closed_a(owner)

    async def test_the_three_values_of_file_state_are_distinct_and_unavailable_is_never_missing(self):
        owner = PersistenceOwner()
        async with self.persistence(owner, 'actor') as sandbox:
            owner.file_answer = {'status': 'unavailable'}
            self.assertIsNone(await sandbox.file_state(MARKER))
            owner.file_answer = {'status': 'missing'}
            self.assertEqual(await sandbox.file_state(MARKER), 'missing')
            owner.file_answer = dict(FILE_PRESENT_BODY)
            state = await sandbox.file_state(MARKER)
            self.assertIsInstance(state, tuple)
            self.assertEqual(len(state), 6)
            self.assertEqual(state[-1], 'a' * 64)

    async def test_copy_scan_returns_the_scan_of_the_runner_parser_and_sends_only_typed_arguments(self):
        owner = PersistenceOwner()
        await self.closed_a(owner)
        bodies = (SCAN_EMPTY_BODY, {**SCAN_EMPTY_BODY, 'matches': [SCAN_MATCH], 'matches_total': 1},
                  {**SCAN_EMPTY_BODY, 'complete': False, 'reasons': ['timeout', 'byte_limit']})
        for stage, pin, exclude in (('actor', None, MARKER), ('fresh', A_IDENTITY, None)):
            async with self.persistence(owner, stage, pin) as sandbox:
                for body in bodies:
                    owner.scan_answer = dict(body)
                    scan = await sandbox.copy_scan(DIGEST, SIZE, exclude)
                    self.assertEqual(scan, runner.parse_copy_scan(0, json.dumps(body), SIZE))
                    request = owner.calls[-1][1]
                    self.assertEqual((request.op, request.name, request.sha256, request.size, request.exclude),
                                     ('level_probe', 'copy_scan', DIGEST, SIZE, exclude))
                    self.assertEqual((request.path, request.command), (None, None))
                owner.scan_answer = dict(runner.incomplete_copy_scan('probe_timeout'))  # the controller's own incomplete scan
                incomplete = await sandbox.copy_scan(DIGEST, SIZE)
                self.assertEqual((incomplete['complete'], incomplete['reasons'], incomplete['matches']), (False, ['probe_timeout'], []))

    async def test_a_fresh_phase_refuses_an_exclude_and_a_session_without_a_handle_sends_nothing(self):
        owner = PersistenceOwner()
        await self.closed_a(owner)
        async with self.persistence(owner, 'fresh', A_IDENTITY) as sandbox:
            before = len(owner.calls)
            with self.assertRaises(client.ActorError) as caught:
                await sandbox.copy_scan(DIGEST, SIZE, MARKER)  # in a fresh sandbox the original path counts: it is not excluded
            self.assertEqual(caught.exception.reason, 'invalid_exclude')
            self.assertEqual(len(owner.calls), before)
            self.assertEqual(await sandbox.copy_scan(DIGEST, SIZE, None), runner.parse_copy_scan(0, json.dumps(SCAN_EMPTY_BODY), SIZE))
        idle = self.persistence(owner, 'actor', run_id='fedcba9876543210' * 2)
        count = len(owner.calls)
        for call in (lambda: idle.file_state(MARKER), lambda: idle.copy_scan(DIGEST, SIZE)):
            with self.assertRaises(client.ActorError) as caught:
                await call()
            self.assertEqual(caught.exception.reason, 'unknown_handle')
        self.assertEqual(len(owner.calls), count)

    async def test_arguments_the_codec_refuses_never_leave_the_controller(self):
        owner = PersistenceOwner()
        async with self.persistence(owner, 'actor') as sandbox:
            before = len(owner.calls)
            cases = [(lambda path=path: sandbox.file_state(path), 'invalid_path') for path in (
                '/work/marker-' + 'a' * 23, '/work/marker-' + 'A' * 24, '/tmp/marker-' + 'a' * 24, '/work/../marker-' + 'a' * 24,
                MARKER + '/x', MARKER + '\n', '', '/', None, 5, True, [MARKER], DIGEST)]
            cases += [(lambda sha=sha: sandbox.copy_scan(sha, SIZE), 'invalid_digest') for sha in (
                'B' * 64, 'b' * 63, 'b' * 65, 'g' * 64, DIGEST + '\n', '', None, 5, [DIGEST], MARKER)]
            cases += [(lambda size=size: sandbox.copy_scan(DIGEST, size), 'invalid_size') for size in (
                0, -1, 1048577, True, False, 1.0, 24.5, '24', None, [24])]
            cases += [(lambda exclude=exclude: sandbox.copy_scan(DIGEST, SIZE, exclude), 'invalid_exclude') for exclude in (
                '/work/marker-' + 'a' * 23, '/tmp/marker-' + 'a' * 24, '', '-', 5, True, [MARKER], MARKER + '\n')]
            for call, reason in cases:
                with self.assertRaises(client.ActorError) as caught:
                    await call()
                self.assertEqual(caught.exception.reason, reason)
            self.assertEqual(len(owner.calls), before)  # not one byte: the codec judged every argument before sending
            await sandbox.copy_scan(DIGEST, 1)
            await sandbox.copy_scan(DIGEST, 1048576, OTHER_MARKER)
            await sandbox.file_state(OTHER_MARKER)
            self.assertEqual(len(owner.calls), before + 3)

    async def test_malformed_unavailable_or_failed_answers_are_errors_never_an_absence_or_an_empty_scan(self):
        owner = PersistenceOwner()
        async with self.persistence(owner, 'actor') as sandbox:
            bad_file = [{'status': 'present'}, {**FILE_PRESENT_BODY, 'inode': True}, {**FILE_PRESENT_BODY, 'size': 1048577},
                        {**FILE_PRESENT_BODY, 'extra': 1}, {**FILE_PRESENT_BODY, 'sha256': 'A' * 64}, {'status': 'missing', 'inode': 1},
                        {'status': 'Missing'}, {'status': 'unavailable', 'counters': None}, {}, {'status': 'available', 'counters': {'oom_kill': 0}},
                        dict(SCAN_EMPTY_BODY)]
            for body in bad_file:
                with self.subTest(file=str(body)[:60]):
                    owner.file_answer = body
                    before = owner.ops.count('level_probe')
                    with self.assertRaises(client.ActorError) as caught:
                        await sandbox.file_state(MARKER)
                    self.assertEqual(caught.exception.reason, 'owner_response_invalid')
                    self.assertEqual(owner.ops.count('level_probe'), before + 1)  # one attempt
            bad_scan = [{**SCAN_EMPTY_BODY, 'complete': True, 'reasons': ['byte_limit']}, {**SCAN_EMPTY_BODY, 'complete': False},
                        {**SCAN_EMPTY_BODY, 'verifier_version': 'v1'}, {**SCAN_EMPTY_BODY, 'matches_total': 1},
                        {**SCAN_EMPTY_BODY, 'matches': [{**SCAN_MATCH, 'size': SIZE + 1}], 'matches_total': 1},
                        {**SCAN_EMPTY_BODY, 'matches': [{**SCAN_MATCH, 'path': '/etc/shadow'}], 'matches_total': 1},
                        {**SCAN_EMPTY_BODY, 'extra': 1}, {**SCAN_EMPTY_BODY, 'entries': 129}, {'status': 'missing'},
                        dict(FILE_PRESENT_BODY), {'status': 'available', 'counters': {'oom_kill': 0}},
                        {**runner.incomplete_copy_scan('probe_timeout'), 'entries': 1}]
            for body in bad_scan:
                with self.subTest(scan=str(body)[:60]):
                    owner.scan_answer = body
                    with self.assertRaises(client.ActorError) as caught:
                        await sandbox.copy_scan(DIGEST, SIZE, MARKER)
                    self.assertEqual(caught.exception.reason, 'owner_response_invalid')
            for reason in ('wrong_domain', 'busy', 'closing', 'invalid_exclude', 'exec_timeout', 'sandbox_stopped', 'internal_error'):
                owner.refuse['level_probe'] = (reason, {})
                for call in (lambda: sandbox.file_state(MARKER), lambda: sandbox.copy_scan(DIGEST, SIZE)):
                    with self.assertRaises(client.ActorError) as caught:
                        await call()
                    self.assertEqual(caught.exception.reason, reason)
            del owner.refuse['level_probe']
            for answer in (raw({'ok': True, 'op': 'level_probe', 'status': 'missing', 'extra': 1}), b'garbage', b'', raw({'ok': False})):
                owner.errors['level_probe'] = answer
                for call in (lambda: sandbox.file_state(MARKER), lambda: sandbox.copy_scan(DIGEST, SIZE)):
                    with self.assertRaises(client.ActorError) as caught:
                        await call()
                    self.assertEqual(caught.exception.reason, 'owner_response_invalid')

    async def test_only_a_persistence_session_has_the_probes_and_it_keeps_the_rest_of_the_facade_closed(self):
        owner = PersistenceOwner()
        for level in ('memory', 'secret'):
            sandbox = client.LevelSession(SETTINGS, run_id=RUN, level=level, stage='actor', context_sha256=CONTEXT, transport=owner)
            self.assertFalse(hasattr(sandbox, 'file_state'), level)
            self.assertFalse(hasattr(sandbox, 'copy_scan'), level)
            self.assertIsNone(getattr(sandbox, 'file_state', None))
            self.assertIsNone(getattr(sandbox, 'copy_scan', None))
        for stage, pin in (('actor', None), ('fresh', A_IDENTITY)):
            sandbox = self.persistence(owner, stage, pin)
            self.assertTrue(callable(sandbox.file_state))
            self.assertTrue(callable(sandbox.copy_scan))
            for name in ('probe', 'exec_fixed', 'net_counters', 'cgroup_sample', 'cgroup_recheck', 'container_identity',
                         'cgroup_identity', 'variant'):
                self.assertFalse(hasattr(sandbox, name), name)
        self.assertFalse(hasattr(client.ActorSession, 'file_state'))
        self.assertFalse(hasattr(client.ActorSession, 'copy_scan'))
        self.assertFalse(hasattr(client.ActorSession, 'predecessor'))
        async with self.persistence(owner, 'actor') as sandbox:  # cgroup_events is a memory probe
            before = len(owner.calls)
            with self.assertRaises(client.ActorError) as caught:
                await sandbox.cgroup_events()
            self.assertEqual(caught.exception.reason, 'wrong_domain')
            self.assertEqual(len(owner.calls), before)

    async def test_a_full_persistence_flow_spawns_nothing(self):
        owner = PersistenceOwner()
        with mock.patch('asyncio.create_subprocess_exec', side_effect=AssertionError('spawned')) as spawn, \
                mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('spawned')) as popen:
            async with self.persistence(owner, 'actor') as a:
                await a.execute('true')
                await a.file_state(MARKER)
                await a.copy_scan(DIGEST, SIZE, MARKER)
                await a.measure()
            async with self.persistence(owner, 'fresh', A_IDENTITY) as b:
                await b.copy_scan(DIGEST, SIZE)
            self.assertEqual((spawn.call_count, popen.call_count), (0, 0))
        self.assertTrue(a.cleanup_confirmed and b.cleanup_confirmed)


class ParityWithTheReceivedSignaturesTests(unittest.TestCase):
    """The wire layer is pure and mirrors the runner's parsers; these tests pin that the mirror has not drifted."""

    def test_the_scan_vocabulary_and_limits_equal_the_runners(self):
        self.assertEqual(wire.COPY_SCAN_VERSION, runner.COPY_SCAN_VERSION)
        self.assertEqual(wire.COPY_SCAN_SCRIPT_REASONS, runner.COPY_SCAN_SCRIPT_REASONS)
        self.assertEqual(wire.COPY_SCAN_CONTROLLER_REASONS, runner.COPY_SCAN_CONTROLLER_REASONS)
        limits = runner.COPY_SCAN_LIMITS
        self.assertEqual(proto.MAX_COPY_SIZE, limits['max_bytes'])
        self.assertEqual(dict(wire.COPY_SCAN_COUNT_BOUNDS), {'entries': limits['max_entries'], 'bytes_read': limits['max_bytes'],
                                                             'skipped_nonregular': limits['max_entries'],
                                                             'matches_total': limits['max_entries']})
        self.assertEqual((wire.MAX_COPY_MATCHES, wire.MAX_COPY_PATH_CHARS), (limits['max_reported_matches'], limits['max_path_chars']))
        self.assertEqual(wire._COPY_PATH.pattern, runner._COPY_PATH.pattern)
        self.assertEqual(set(wire.COPY_SCAN_KEYS), set(runner.incomplete_copy_scan('probe_failed')))

    def test_the_marker_path_is_the_one_the_owner_runtime_accepts(self):
        runtime = (ROOT / 'services' / 'agent' / 'invoice_actor_runtime.py').read_text(encoding='utf-8')
        self.assertIn(r"/work/marker-[0-9a-f]{24}", runtime)  # read as source: the runtime is the owner's and needs Docker to import
        self.assertIn('async def probe_level(self, intent, name, **typed_args)', runtime)
        self.assertIsNotNone(proto._MARKER_PATH.fullmatch('/work/marker-' + '0123456789abcdef01234567'))
        self.assertEqual(proto._MARKER_PATH.pattern, r'/work/marker-[0-9a-f]{24}')

    def test_file_state_bounds_agree_with_the_runner_parser(self):
        edges = {'inode': (1, 2 ** 64 - 1), 'size': (0, 1048576), 'mtime': (0, 2 ** 63 - 1), 'ctime': (0, 2 ** 63 - 1),
                 'links': (1, 1 << 20)}
        self.assertEqual(dict(zip(wire.FILE_STATE_FIELDS, wire.FILE_STATE_BOUNDS)), edges)
        for key, (low, high) in edges.items():
            for value in (low - 1, low, high, high + 1, True, 1.5, '1', None):
                body = {**FILE_PRESENT_BODY, key: value}
                parsed = runner.parse_file_state(0, json.dumps(body))
                try:
                    checked = wire.validate_level_probe({**body, 'ok': True, 'op': 'level_probe'}, name='file_state')
                except wire.WireError:
                    checked = None
                self.assertEqual(checked is not None, parsed['status'] == 'present', (key, value))
                if checked is not None:
                    self.assertEqual(checked, parsed)
        for status in ('missing', 'unavailable'):
            self.assertEqual(wire.validate_level_probe({'ok': True, 'op': 'level_probe', 'status': status}, name='file_state'),
                             runner.parse_file_state(0, json.dumps({'status': status})))

    def test_the_scan_validator_agrees_with_runner_parse_copy_scan_on_a_corpus(self):
        def scan(**patch):
            return {**SCAN_EMPTY_BODY, **patch}
        corpus = [scan(), scan(matches=[SCAN_MATCH], matches_total=1), scan(complete=False, reasons=['byte_limit']),
                  scan(complete=False, reasons=['timeout', 'changed']), scan(verifier_version='x'), scan(complete=1),
                  scan(complete=True, reasons=['byte_limit']), scan(complete=False), scan(complete=False, reasons=['made_up']),
                  scan(entries=129), scan(bytes_read=1048577), scan(skipped_nonregular=129), scan(entries=-1), scan(entries=True),
                  scan(matches_total=129, matches=[SCAN_MATCH]), scan(matches=[SCAN_MATCH], matches_total=0),
                  scan(matches=[], matches_total=2), scan(matches=[SCAN_MATCH] * 9, matches_total=9),
                  scan(matches=[SCAN_MATCH] * 8, matches_total=8),
                  scan(matches=[{**SCAN_MATCH, 'size': SIZE + 1}], matches_total=1),
                  scan(matches=[{**SCAN_MATCH, 'path': '/etc/x'}], matches_total=1),
                  scan(matches=[{**SCAN_MATCH, 'path': '/tmp/../x'}], matches_total=1),
                  scan(matches=[{**SCAN_MATCH, 'path': '/work/a/b/c/d/e'}], matches_total=1),
                  scan(matches=[{**SCAN_MATCH, 'path': '/tmp/' + 'a' * 156}], matches_total=1),
                  scan(matches=[{**SCAN_MATCH, 'path': '/work/' + 'a' * 154}], matches_total=1),
                  scan(matches=[{**SCAN_MATCH, 'links': 0}], matches_total=1), scan(matches=[{**SCAN_MATCH, 'links': True}], matches_total=1),
                  scan(matches=[{**SCAN_MATCH, 'extra': 1}], matches_total=1),
                  scan(complete=False, reasons=['byte_limit', 'byte_limit']), scan(complete=False, reasons=['byte_limit', 5])]
        for body in corpus:
            parsed = runner.parse_copy_scan(0, json.dumps(body), SIZE)
            try:
                checked = wire.validate_level_probe({**body, 'ok': True, 'op': 'level_probe'}, name='copy_scan', size=SIZE)
            except wire.WireError:
                checked = None
            if parsed['reasons'] == ['malformed']:  # the runner would discard it as malformed: so does the wire layer
                self.assertIsNone(checked, body)
            else:
                self.assertEqual(checked, parsed, body)


# ------------------------------------------------------------------------------------------------------- M3.1 · catalog
# Authored without a shell: none of these tests has been executed by the author. The operator runs them.
# The owner double speaks the wire of M3.0 (SC2-CATALOGO-ADAPTADORES-LOCAL). It stands for the adapter contract only: nothing here
# mounts a catalog, prepares a resource or touches Docker, and no test of this section claims a real mount.

import dataclasses  # noqa: E402
import inspect  # noqa: E402

from services.agent import missions  # noqa: E402

C_ID = 'invoice-unit-cents/v1'
C_SHA = 'd055653221c49c92490e536dc665349746988bb14749c60757e7a770fc20e79e'
CAT_CONTEXT = '7' * 64
CAT_OTHER_CONTEXT = '8' * 64
CAT_VIEW = {'id': C_ID, 'sha256': C_SHA, 'size': 47, 'destination': '/catalog.json'}
CAT_PROFILE_B = runner.catalog_expected_profile(PROFILE)
CAT_PROBE_B = {'ran': True, 'state': 'present', 'read': 'ok', 'write_open': 'rejected', 'write_errno': 'EROFS', 'sha256': C_SHA, 'size': 47}
CAT_PROBE_A = {'ran': True, 'state': 'absent', 'read': None, 'write_open': None, 'write_errno': None, 'sha256': None, 'size': None}
CAT_PROBE_UNAVAILABLE = {**CAT_PROBE_A, 'state': 'unavailable'}
CAT_HOST_OK = {'ok': True, 'changed': False, 'reason': None, 'sha256': C_SHA}
CAT_HOST_UNREADABLE = {'ok': False, 'changed': None, 'reason': 'unreadable', 'sha256': None}
CAT_OTHER = {'installation_id': '9' * 32, 'run_id': '9' * 32, 'variant': 'perturbed', 'catalog_profile': 'A', 'context_sha256': CAT_OTHER_CONTEXT,
             'intent_id': '9' * 32, 'container_id': '9' * 64}


class CatalogOwner(FakeOwner):
    """Scripted owner of the catalog domain. Answers with the wire encoders; the answers of a check can be patched one by one."""

    def __init__(self, selected='B'):
        super().__init__()
        self.selected = selected
        self.profile = dict(CAT_PROFILE_B if selected == 'B' else PROFILE)
        self.sha = runner.profile_digest(self.profile)
        self.info = {'installation_id': INSTALL, 'ready': True, 'identity': dict(CAT_VIEW)}
        self.check_count = 0
        self.scripted_checks = []  # patches applied, in order, over the next check answers

    def key(self):
        return tuple(self.identity[name] for name in wire.CATALOG_IDENTITY_FIELDS)

    def on_catalog_info(self, request):
        return wire.encode_response('catalog_info', self.info)

    def on_open_catalog(self, request):
        body = {'handle': HANDLE, 'installation_id': INSTALL, 'run_id': request.run_id, 'variant': request.variant,
                'catalog_profile': request.catalog_profile, 'context_sha256': request.context_sha256, 'catalog_id': request.catalog_id,
                'catalog_sha256': request.catalog_sha256, 'intent_id': INTENT, 'name': 'escape-actor-' + INTENT,
                'container_id': CONTAINER, 'profile_sha256': self.sha, 'profile': self.profile, **self.open_patch}
        self.identity = {key: body[key] for key in wire.CATALOG_IDENTITY_FIELDS}
        return wire.encode_response('open_catalog', body)

    def on_catalog_check(self, request):
        self.check_count += 1
        body = {**self.identity, 'probe': dict(CAT_PROBE_B if self.identity['catalog_profile'] == 'B' else CAT_PROBE_A),
                'host_check': dict(CAT_HOST_OK), 'check_index': self.check_count}
        if self.scripted_checks:
            body.update(self.scripted_checks.pop(0))
        return wire.encode_response('catalog_check', body)

    def on_catalog_receipt(self, request):
        asked = {name: getattr(request, name) for name in wire.CATALOG_IDENTITY_FIELDS}
        confirmed = tuple(asked[name] for name in wire.CATALOG_IDENTITY_FIELDS) in self.finished
        return wire.encode_response('catalog_receipt', {**asked, 'status': 'confirmed' if confirmed else 'unknown',
                                                        'cleanup_confirmed': confirmed, **self.receipt_patch})


class CatalogCase(ClientCase):
    def catalog(self, owner, settings=SETTINGS, **kwargs):
        return client.CatalogActorSession(settings, run_id=kwargs.pop('run_id', RUN), variant=kwargs.pop('variant', 'legitimate'),
                                          catalog_profile=kwargs.pop('profile', owner.selected),
                                          context_sha256=kwargs.pop('context', CAT_CONTEXT), transport=owner)


class CatalogInfoClientTests(CatalogCase):
    async def test_info_is_one_validated_read_and_returns_a_copy(self):
        owner = CatalogOwner()
        info = await client.catalog_info(SETTINGS, transport=owner)
        self.assertEqual(info, {'installation_id': INSTALL, 'ready': True, 'identity': CAT_VIEW})
        info['identity']['size'] = 0
        self.assertEqual(owner.info['identity']['size'], 47)
        self.assertEqual(owner.ops, ['catalog_info'])  # no health call, no open, no retry
        self.assertEqual({name: value for name, value in vars_of(owner.calls[0][1]).items() if value is not None},
                         {'op': 'catalog_info'})  # the request carries nothing but its name

    async def test_info_prepares_repairs_and_retires_nothing_and_spawns_nothing(self):
        owner = CatalogOwner()
        with mock.patch('asyncio.create_subprocess_exec', side_effect=AssertionError('spawned')), \
                mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('spawned')):
            await client.catalog_info(SETTINGS, transport=owner)
        self.assertEqual(list(inspect.signature(client.catalog_info).parameters), ['settings', 'transport'])  # nothing to choose from here
        for name in ('prepare_catalog', 'release_catalog', 'open_catalog_resource', 'catalog_resource'):
            self.assertFalse(hasattr(client, name), name)

    async def test_not_ready_and_unregistered_are_answers_the_caller_decides_on(self):
        for patch in ({'ready': False}, {'ready': False, 'identity': None}):
            owner = CatalogOwner()
            owner.info = {**owner.info, **patch}
            info = await client.catalog_info(SETTINGS, transport=owner)
            self.assertIs(info['ready'], False)
            self.assertEqual(info['identity'], patch.get('identity', CAT_VIEW))

    async def test_refusals_and_transport_failures_have_closed_reasons_and_one_attempt(self):
        cases = ((wire.error_response('catalog_not_allowed'), 'catalog_not_allowed', 'Actor controller refused: catalog_not_allowed'),
                 (wire.error_response('internal_error'), 'internal_error', 'Actor controller refused: internal_error'),
                 (OSError('refused'), 'owner_unavailable', 'Actor controller unavailable'),
                 (TimeoutError(), 'owner_unavailable', 'Actor controller unavailable'),
                 (wire.WireError('peer_mismatch'), 'owner_peer_unverified', 'Actor controller identity not verified'),
                 (wire.WireError('truncated'), 'owner_response_invalid', 'Actor controller response invalid'),
                 (b'not json', 'owner_response_invalid', 'Actor controller response invalid'))
        for failure, reason, text in cases:
            with self.subTest(reason=reason, failure=repr(failure)[:30]):
                owner = CatalogOwner()
                owner.errors['catalog_info'] = failure
                with self.assertRaises(client.ActorError) as caught:
                    await client.catalog_info(SETTINGS, transport=owner)
                self.assertEqual((caught.exception.reason, str(caught.exception)), (reason, text))
                self.assertEqual(owner.ops, ['catalog_info'])

    async def test_a_contradictory_or_malformed_answer_never_activates_the_domain(self):
        bad = ({'ready': True, 'identity': None}, {'ready': 1}, {'ready': None}, {'identity': {**CAT_VIEW, 'sha256': 'e' * 64}},
               {'identity': {**CAT_VIEW, 'id': 'other/v1'}}, {'identity': {**CAT_VIEW, 'size': True}}, {'identity': {**CAT_VIEW, 'size': 47.0}},
               {'identity': {**CAT_VIEW, 'destination': '/tmp/x'}}, {'identity': {**CAT_VIEW, 'path': '/var/lib/owner/catalog.json'}},
               {'identity': 'x'}, {'installation_id': 'X' * 32}, {'resource_id': 'f' * 32}, {'path': '/x'})
        for patch in bad:
            with self.subTest(patch=str(patch)[:60]):
                owner = CatalogOwner()
                owner.info = {**owner.info, **patch}
                with self.assertRaises(client.ActorError) as caught:
                    await client.catalog_info(SETTINGS, transport=owner)
                self.assertEqual(caught.exception.reason, 'owner_response_invalid')

    async def test_the_installation_pin_of_settings_must_match_the_answer(self):
        owner = CatalogOwner()
        pinned = client.Settings(SETTINGS.socket_path, 2000, installation_id='9' * 32)
        with self.assertRaises(client.ActorError) as caught:
            await client.catalog_info(pinned, transport=owner)
        self.assertEqual(caught.exception.reason, 'owner_response_invalid')
        right = client.Settings(SETTINGS.socket_path, 2000, installation_id=INSTALL)
        self.assertTrue((await client.catalog_info(right, transport=CatalogOwner()))['ready'])

    async def test_settings_keep_their_fields_and_order(self):
        self.assertEqual([field.name for field in dataclasses.fields(client.Settings)],
                         ['socket_path', 'owner_uid', 'installation_id', 'image_id', 'mission_id', 'context_sha256'])


class CatalogSessionOpenTests(CatalogCase):
    async def test_binding_arguments_are_validated_before_anything_is_sent(self):
        class Text(str):
            pass
        good = dict(run_id=RUN, variant='legitimate', catalog_profile='B', context_sha256=CAT_CONTEXT)
        bad = ({'run_id': 'x'}, {'run_id': RUN.upper()}, {'run_id': Text(RUN)}, {'run_id': None}, {'run_id': 5}, {'run_id': RUN + '\n'},
               {'variant': 'actor'}, {'variant': Text('legitimate')}, {'variant': None}, {'variant': True},
               {'catalog_profile': 'C'}, {'catalog_profile': 'a'}, {'catalog_profile': Text('A')}, {'catalog_profile': None},
               {'catalog_profile': True}, {'catalog_profile': ['A']}, {'catalog_profile': 'AB'},
               {'context_sha256': 'x'}, {'context_sha256': 'A' * 64}, {'context_sha256': Text(CAT_CONTEXT)},
               {'context_sha256': None}, {'context_sha256': CAT_CONTEXT[:-1]})
        for patch in bad:
            owner = CatalogOwner()
            with self.assertRaises(ValueError, msg=str(patch)):
                client.CatalogActorSession(SETTINGS, **{**good, **patch}, transport=owner)
            self.assertEqual(owner.ops, [])
        with self.assertRaises(TypeError):
            client.CatalogActorSession(SETTINGS, run_id=RUN, variant='legitimate')
        with self.assertRaises(TypeError):
            client.CatalogActorSession(SETTINGS, RUN, 'legitimate', 'B', CAT_CONTEXT)  # keyword-only, like the other facades

    async def test_open_binds_the_nine_fields_and_close_confirms_with_the_same_identity_for_both_profiles(self):
        for selected in ('A', 'B'):
            with self.subTest(profile=selected):
                owner = CatalogOwner(selected)
                async with self.catalog(owner) as sandbox:
                    self.assertEqual(owner.ops, ['health', 'open_catalog'])
                    self.assertEqual(sandbox.name, 'escape-actor-' + INTENT)
                    self.assertEqual((sandbox.created, sandbox.profile_captured, sandbox.cleanup_confirmed), (True, True, False))
                    self.assertEqual(sandbox.profile, owner.profile)
                    self.assertTrue(sandbox.obligation)
                    self.assertEqual(sandbox.identity, owner.identity)
                    self.assertEqual(sorted(sandbox.identity), sorted(wire.CATALOG_IDENTITY_FIELDS))
                    self.assertEqual((sandbox.identity['catalog_profile'], sandbox.identity['context_sha256']), (selected, CAT_CONTEXT))
                    self.assertNotIn(HANDLE, repr(sandbox))
                    self.assertNotIn(CAT_CONTEXT, repr(sandbox))
                    request = owner.calls[1][1]
                    self.assertEqual((request.run_id, request.variant, request.catalog_profile, request.context_sha256),
                                     (RUN, 'legitimate', selected, CAT_CONTEXT))
                    self.assertEqual((request.catalog_id, request.catalog_sha256), (C_ID, C_SHA))
                self.assertEqual(owner.ops, ['health', 'open_catalog', 'close'])
                self.assertEqual((sandbox.cleanup_confirmed, sandbox.created, sandbox.obligation, sandbox.oom_killed),
                                 (True, False, False, False))
                self.assertEqual(sandbox.measurement, MEAS)

    async def test_the_request_carries_no_path_flag_script_or_resource_id(self):
        owner = CatalogOwner()
        async with self.catalog(owner):
            pass
        for op, request in owner.calls:
            if op == 'open_catalog':
                fields = {name: value for name, value in vars_of(request).items() if value is not None}
                self.assertEqual(set(fields), {'op', 'run_id', 'variant', 'catalog_profile', 'context_sha256', 'catalog_id',
                                               'catalog_sha256'})

    async def test_the_binding_and_the_identity_are_independent_copies(self):
        owner = CatalogOwner()
        sandbox = self.catalog(owner)
        self.assertEqual((sandbox.run_id, sandbox.variant, sandbox.catalog_profile, sandbox.context_sha256),
                         (RUN, 'legitimate', 'B', CAT_CONTEXT))
        for name in ('run_id', 'variant', 'catalog_profile', 'context_sha256'):
            with self.assertRaises(AttributeError):
                setattr(sandbox, name, 'x')  # the pin is not an attribute that can be reassigned
        await sandbox.__aenter__()
        identity = sandbox.identity
        identity['run_id'] = '9' * 32
        identity['catalog_profile'] = 'A'
        self.assertEqual(sandbox.identity, owner.identity)  # a copy each time
        self.assertIsNot(sandbox.identity, sandbox.identity)
        self.assertEqual((sandbox.run_id, sandbox.catalog_profile), (RUN, 'B'))  # and apart from the pin
        await sandbox.close()
        self.assertIsNone(client.CatalogActorSession(SETTINGS, run_id=RUN, variant='legitimate', catalog_profile='A',
                                                     context_sha256=CAT_CONTEXT).identity)

    async def test_mutating_public_attributes_never_loses_the_obligation(self):
        owner = CatalogOwner()
        sandbox = self.catalog(owner)
        await sandbox.__aenter__()
        sandbox.created, sandbox.cleanup_confirmed, sandbox.name, sandbox.profile, sandbox.oom_killed = False, True, 'other', {}, True
        sandbox.measurement = None
        self.assertTrue(sandbox.obligation)  # the handle, not an attribute, is the obligation
        await sandbox.close()
        self.assertEqual(owner.ops, ['health', 'open_catalog', 'close'])
        self.assertEqual((sandbox.cleanup_confirmed, sandbox.created, sandbox.obligation), (True, False, False))
        self.assertEqual(owner.calls[-1][1].handle, HANDLE)

    async def test_owner_not_ready_or_blocked_opens_nothing(self):
        for patch, reason in (({'ready': False}, 'owner_not_ready'), ({'blocked': True}, 'owner_blocked'),
                              ({'image_id': None}, 'image_mismatch')):
            with self.subTest(reason=reason):
                owner = CatalogOwner()
                owner.health.update(patch)
                with self.assertRaises(client.ActorError) as caught:
                    async with self.catalog(owner):
                        self.fail('must not enter')
                self.assertEqual(caught.exception.reason, reason)
                self.assertIsNone(caught.exception.cleanup_confirmed)  # no byte asked the owner to open anything
                self.assertEqual(owner.ops, ['health'])

    async def test_pinned_installation_or_image_must_match_health_and_the_pin_is_taken_at_construction(self):
        for settings in (client.Settings(SETTINGS.socket_path, 2000, installation_id='9' * 32),
                         client.Settings(SETTINGS.socket_path, 2000, image_id='sha256:' + 'e' * 64)):
            owner = CatalogOwner()
            with self.assertRaises(client.ActorError):
                async with self.catalog(owner, settings):
                    self.fail('must not enter')
            self.assertEqual(owner.ops, ['health'])
        owner = CatalogOwner()
        pinned = client.Settings(SETTINGS.socket_path, 2000, installation_id=INSTALL, image_id=IMAGE)
        async with self.catalog(owner, pinned) as sandbox:
            self.assertEqual(sandbox.identity['installation_id'], INSTALL)

    async def test_owner_refusals_carry_the_owner_state_and_leave_nothing_to_restitute(self):
        for reason in ('catalog_not_allowed', 'catalog_unavailable', 'context_mismatch', 'already_active', 'capacity_exhausted',
                       'owner_blocked', 'wrong_domain'):
            with self.subTest(reason=reason):
                owner = CatalogOwner()
                owner.refuse['open_catalog'] = (reason, {})
                with self.assertRaises(client.ActorError) as caught:
                    async with self.catalog(owner):
                        self.fail('must not enter')
                self.assertEqual((caught.exception.reason, str(caught.exception)), (reason, wire.message(reason)))
                self.assertIsNone(caught.exception.cleanup_confirmed)
                self.assertEqual(owner.ops, ['health', 'open_catalog'])

    async def test_transport_failure_during_open_leaves_the_state_unknown_and_is_not_retried(self):
        owner = CatalogOwner()
        owner.errors['open_catalog'] = OSError('reset')
        with self.assertRaises(client.ActorError) as caught:
            async with self.catalog(owner):
                self.fail('must not enter')
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('owner_unavailable', False))
        self.assertEqual(owner.ops, ['health', 'open_catalog'])
        owner = CatalogOwner()
        owner.errors['open_catalog'] = wire.WireError('peer_mismatch')
        with self.assertRaises(client.ActorError) as caught:
            async with self.catalog(owner):
                self.fail('must not enter')
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('owner_peer_unverified', None))

    async def test_the_open_answer_must_match_every_pin_and_no_close_is_sent_for_an_untrusted_handle(self):
        patches = ({'run_id': '9' * 32}, {'variant': 'perturbed'}, {'catalog_profile': 'A'}, {'context_sha256': CAT_OTHER_CONTEXT},
                   {'installation_id': '9' * 32}, {'catalog_id': 'other/v1'}, {'catalog_sha256': 'e' * 64}, {'catalog_profile': 'C'},
                   {'name': 'escape-actor-' + '9' * 32}, {'handle': 'zz'}, {'profile': 'x'}, {'profile': None},
                   {'profile': {**CAT_PROFILE_B, 'image_id': 'sha256:' + 'e' * 64}}, {'profile_sha256': 'x'}, {'intent_id': 5},
                   {'resource_id': 'f' * 32}, {'path': '/var/lib/owner/catalog.json'})
        for patch in patches:
            with self.subTest(patch=str(patch)[:50]):
                owner = CatalogOwner()
                owner.open_patch = patch
                with self.assertRaises(client.ActorError) as caught:
                    async with self.catalog(owner):
                        self.fail('must not enter')
                self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('owner_response_invalid', False))
                self.assertNotIn('close', owner.ops)
        owner = CatalogOwner()
        owner.errors['open_catalog'] = b'garbage'
        with self.assertRaises(client.ActorError) as caught:
            async with self.catalog(owner):
                self.fail('must not enter')
        self.assertEqual(caught.exception.reason, 'owner_response_invalid')

    async def test_the_other_open_shapes_are_never_accepted(self):
        base = {'handle': HANDLE, 'installation_id': INSTALL, 'run_id': RUN, 'variant': 'legitimate', 'intent_id': INTENT,
                'name': 'escape-actor-' + INTENT, 'container_id': CONTAINER, 'profile_sha256': runner.profile_digest(PROFILE),
                'profile': PROFILE}
        level = {key: value for key, value in base.items() if key != 'variant'}
        level.update(level='memory', stage='actor', context_sha256=CAT_CONTEXT)
        for answer in (wire.encode_response('open', base), wire.encode_response('open_level', level)):
            owner = CatalogOwner('A')
            owner.errors['open_catalog'] = answer
            with self.assertRaises(client.ActorError) as caught:
                async with self.catalog(owner):
                    self.fail('must not enter')
            self.assertEqual(caught.exception.reason, 'owner_response_invalid')
            self.assertNotIn('close', owner.ops)

    async def test_the_profile_is_reverified_per_profile_and_a_violation_closes_the_handle(self):
        ordinary = dict(PROFILE)
        with_receipt = {**PROFILE, 'catalog': runner.catalog_receipt()}
        weak_b = {**CAT_PROFILE_B, 'read_only': False}
        cases = (('B', ordinary, 'mount_types'),            # B must carry exactly the one fixed bind and its receipt
                 ('A', dict(CAT_PROFILE_B), 'mount_types'),  # A is the ordinary profile: any mount is a violation
                 ('A', with_receipt, 'catalog'),            # and an ordinary profile never carries a catalog receipt
                 ('B', weak_b, 'read_only'),                # B is the ordinary profile in full, except for the bind
                 ('B', {**CAT_PROFILE_B, 'mount_types': ['bind', 'bind']}, 'mount_types'),
                 ('B', {**CAT_PROFILE_B, 'catalog': {**runner.catalog_receipt(), 'mode': 'read_write'}}, 'catalog'),
                 ('A', {**PROFILE, 'privileged': True}, 'privileged'))
        for selected, profile, name in cases:
            with self.subTest(profile=selected, violation=name):
                owner = CatalogOwner(selected)
                owner.profile, owner.sha = profile, runner.profile_digest(profile)
                with self.assertRaises(client.ActorError) as caught:
                    async with self.catalog(owner):
                        self.fail('must not enter')
                self.assertEqual(caught.exception.reason, 'profile_rejected')
                self.assertIn(name, str(caught.exception))
                self.assertEqual(owner.ops, ['health', 'open_catalog', 'close'])
                self.assertIs(caught.exception.cleanup_confirmed, True)
                self.assertEqual(caught.exception.sandbox_profile, profile)

    async def test_profile_digest_mismatch_is_a_violation_and_unconfirmed_cleanup_outranks_it(self):
        owner = CatalogOwner()
        owner.sha = '6' * 64
        with self.assertRaises(client.ActorError) as caught:
            async with self.catalog(owner):
                self.fail('must not enter')
        self.assertTrue(str(caught.exception).endswith('profile_digest'))
        self.assertEqual(owner.ops, ['health', 'open_catalog', 'close'])
        owner = CatalogOwner('A')
        owner.profile = {**PROFILE, 'privileged': True}
        owner.sha = runner.profile_digest(owner.profile)
        owner.close_failures = 1
        with self.assertRaises(client.ActorError) as caught:
            async with self.catalog(owner):
                self.fail('must not enter')
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('cleanup_unconfirmed', False))
        self.assertEqual(caught.exception.sandbox_profile['privileged'], True)

    async def test_cancellation_during_open_restores_a_granted_handle_then_propagates(self):
        owner = CatalogOwner()
        owner.gates['open_catalog'] = asyncio.Event()
        sandbox = self.catalog(owner)
        task = asyncio.ensure_future(sandbox.__aenter__())
        await self.wait_for_op(owner, 'open_catalog')
        task.cancel()
        owner.gates['open_catalog'].set()
        with self.assertRaises(asyncio.CancelledError) as caught:
            await task
        self.assertEqual(owner.ops, ['health', 'open_catalog', 'close'])
        self.assertTrue(sandbox.cleanup_confirmed)
        self.assertIs(caught.exception.cleanup_confirmed, True)
        self.assertEqual(caught.exception.sandbox_profile, owner.profile)

    async def test_a_body_that_fails_still_closes(self):
        owner = CatalogOwner()
        with self.assertRaises(RuntimeError):
            async with self.catalog(owner) as sandbox:
                raise RuntimeError('workflow failed')
        self.assertEqual(owner.ops, ['health', 'open_catalog', 'close'])
        self.assertTrue(sandbox.cleanup_confirmed)


def vars_of(request):
    """The fields of a decoded Request (a slots dataclass has no __dict__)."""
    return {field.name: getattr(request, field.name) for field in dataclasses.fields(request)}


class CatalogSessionOperationTests(CatalogCase):
    async def test_execute_and_the_two_fixed_probes(self):
        owner = CatalogOwner()
        async with self.catalog(owner) as sandbox:
            result = await sandbox.execute('cat -- /catalog.json')
            self.assertEqual(set(result), {'stdout', 'stderr', 'exit_code', *wire.MEASUREMENT_FIELDS})
            self.assertEqual(owner.calls[-1][1].command, 'cat -- /catalog.json')
            task = await sandbox.probe('task_result')
            self.assertEqual(task['stdout'], 'probe:task_result')
            self.assertEqual(await sandbox.measure(), MEAS)
            self.assertEqual([request.name for op, request in owner.calls if op == 'probe'], ['task_result', 'measure'])

    async def test_commands_at_the_byte_limit_travel_whole_and_beyond_it_never_leave(self):
        owner = CatalogOwner()
        async with self.catalog(owner) as sandbox:
            await sandbox.execute('€' * 2730)
            self.assertEqual(owner.calls[-1][1].command, '€' * 2730)
            before = len(owner.calls)
            with self.assertRaises(client.ActorError) as caught:
                await sandbox.execute('€' * 2731)
            self.assertEqual(caught.exception.reason, 'command_too_large')
            self.assertEqual(len(owner.calls), before)

    async def test_the_capture_probe_is_refused_locally_and_nothing_else_leaves_the_controller(self):
        owner = CatalogOwner()
        async with self.catalog(owner) as sandbox:
            before = len(owner.calls)
            cases = ((lambda: sandbox.probe('artifact_capture'), 'wrong_domain'), (lambda: sandbox.probe('copy_scan'), 'invalid_name'),
                     (lambda: sandbox.probe('cgroup_events'), 'invalid_name'), (lambda: sandbox.probe(5), 'invalid_name'),
                     (lambda: sandbox.probe(None), 'invalid_name'),
                     (lambda: sandbox.exec_fixed(invoice_verification.ARTIFACT_CAPTURE_SCRIPT,
                                                 output_limit=invoice_verification.CAPTURE_OUTPUT_LIMIT), 'script_not_registered'),
                     (lambda: sandbox.exec_fixed(invoice_verification.ARTIFACT_CAPTURE_SCRIPT), 'script_not_registered'),
                     (lambda: sandbox.exec_fixed(runner.CATALOG_PROBE_SCRIPT), 'script_not_registered'),  # the catalog probe is catalog_check
                     (lambda: sandbox.exec_fixed(runner.CATALOG_PROBE_COMMAND), 'script_not_registered'),
                     (lambda: sandbox.exec_fixed('print(1)'), 'script_not_registered'),
                     (lambda: sandbox.exec_fixed(client.TASK_RESULT_COMMAND + ' '), 'script_not_registered'),
                     (lambda: sandbox.exec_fixed(client.TASK_RESULT_COMMAND, output_limit=1), 'script_not_registered'),
                     (lambda: sandbox.exec_fixed(None), 'script_not_registered'))
            for call, reason in cases:
                with self.assertRaises(client.ActorError) as caught:
                    await call()
                self.assertEqual(caught.exception.reason, reason)
            self.assertEqual(len(owner.calls), before)

    async def test_exec_fixed_recognizes_only_the_registered_task_result_read(self):
        owner = CatalogOwner()
        async with self.catalog(owner) as sandbox:
            result = await sandbox.exec_fixed(client.TASK_RESULT_COMMAND)
            self.assertEqual((result['stdout'], result['exit_code']), ('probe:task_result', 0))
            self.assertEqual([request.name for op, request in owner.calls if op == 'probe'], ['task_result'])

    async def test_the_facade_has_no_probe_of_another_domain(self):
        owner = CatalogOwner()
        sandbox = self.catalog(owner)
        for name in ('file_state', 'copy_scan', 'cgroup_events', 'net_counters', 'cgroup_sample', 'cgroup_recheck', 'container_identity',
                     'cgroup_identity', 'predecessor', 'level', 'stage', 'level_probe'):
            self.assertFalse(hasattr(sandbox, name), name)
        for name in ('execute', 'probe', 'measure', 'exec_fixed', 'catalog_check', 'close', 'identity', 'obligation'):
            self.assertTrue(hasattr(sandbox, name), name)
        for other in (client.ActorSession, client.LevelSession):  # and the other facades gained nothing
            self.assertFalse(hasattr(other, 'catalog_check'))
        self.assertEqual(owner.ops, [])

    async def test_operations_without_an_open_handle_are_refused_locally(self):
        owner = CatalogOwner()
        sandbox = self.catalog(owner)
        for call in (lambda: sandbox.execute('true'), lambda: sandbox.probe('task_result'), lambda: sandbox.measure(),
                     lambda: sandbox.catalog_check()):
            with self.assertRaises(client.ActorError) as caught:
                await call()
            self.assertEqual(caught.exception.reason, 'unknown_handle')
        self.assertEqual(owner.ops, [])

    async def test_owner_refusals_and_invalid_outputs_are_closed_failures_and_never_replayed(self):
        for reason in ('wrong_domain', 'busy', 'closing', 'exec_timeout', 'sandbox_stopped', 'internal_error'):
            owner = CatalogOwner()
            owner.refuse['execute'] = (reason, {})
            async with self.catalog(owner) as sandbox:
                with self.assertRaises(client.ActorError) as caught:
                    await sandbox.execute('true')
                self.assertEqual((caught.exception.reason, str(caught.exception)), (reason, wire.message(reason)))
        for body in ({'ok': True, 'op': 'execute', 'stdout': 1, 'stderr': '', 'exit_code': 0, **MEAS},
                     {'ok': True, 'op': 'probe', 'stdout': 'x', 'stderr': '', 'exit_code': 0, **MEAS},
                     {'ok': True, 'op': 'execute', 'stdout': 'x', 'stderr': ''}):
            owner = CatalogOwner()
            owner.errors['execute'] = raw(body)
            async with self.catalog(owner) as sandbox:
                with self.assertRaises(client.ActorError) as caught:
                    await sandbox.execute('true')
                self.assertEqual(caught.exception.reason, 'owner_response_invalid')
        owner = CatalogOwner()
        owner.errors['execute'] = OSError('reset')
        async with self.catalog(owner) as sandbox:
            with self.assertRaises(client.ActorError):
                await sandbox.execute('touch /work/once')
            self.assertEqual(owner.ops.count('execute'), 1)
        self.assertEqual((owner.ops.count('execute'), owner.ops[-1]), (1, 'close'))

    async def test_cancellation_during_execute_propagates_and_exit_still_restitutes(self):
        owner = CatalogOwner()
        owner.gates['execute'] = asyncio.Event()
        async with self.catalog(owner) as sandbox:
            task = asyncio.ensure_future(sandbox.execute('sleep 99'))
            await self.wait_for_op(owner, 'execute')
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(owner.ops, ['health', 'open_catalog', 'execute', 'close'])
        self.assertTrue(sandbox.cleanup_confirmed)


class CatalogCheckClientTests(CatalogCase):
    async def test_the_check_returns_the_typed_view_as_copies_and_asks_with_the_handle_only(self):
        for selected, probe in (('A', CAT_PROBE_A), ('B', CAT_PROBE_B)):
            with self.subTest(profile=selected):
                owner = CatalogOwner(selected)
                async with self.catalog(owner) as sandbox:
                    view = await sandbox.catalog_check()
                    self.assertEqual(view, {'probe': probe, 'host_check': CAT_HOST_OK, 'check_index': 1})
                    self.assertIsNot(view['probe'], probe)
                    view['probe']['state'] = 'unavailable'
                    view['host_check']['ok'] = False
                    request = owner.calls[-1][1]
                    self.assertEqual({name: value for name, value in vars_of(request).items() if value is not None},
                                     {'op': 'catalog_check', 'handle': HANDLE})  # no path, script, index or probe name
                    self.assertEqual((await sandbox.catalog_check())['check_index'], 2)
                self.assertEqual(owner.ops, ['health', 'open_catalog', 'catalog_check', 'catalog_check', 'close'])

    async def test_the_probe_is_not_parsed_a_second_time_and_no_stdout_is_invented(self):
        owner = CatalogOwner()
        with mock.patch.object(runner, 'parse_catalog_probe', side_effect=AssertionError('parsed again')):
            async with self.catalog(owner) as sandbox:
                view = await sandbox.catalog_check()
        self.assertNotIn('stdout', view['probe'])
        self.assertEqual(set(view['probe']), set(wire.CATALOG_PROBE_KEYS))

    async def test_unavailable_is_returned_as_unavailable_never_as_absent_or_denied(self):
        owner = CatalogOwner('A')
        owner.scripted_checks = [{'probe': dict(CAT_PROBE_UNAVAILABLE)}, {'probe': dict(CAT_PROBE_A)},
                                 {'probe': {**CAT_PROBE_A, 'ran': False, 'state': 'unavailable'}}, {'host_check': dict(CAT_HOST_UNREADABLE)}]
        async with self.catalog(owner) as sandbox:
            states = [(await sandbox.catalog_check())['probe'] for _ in range(4)]
        self.assertEqual([item['state'] for item in states], ['unavailable', 'absent', 'unavailable', 'absent'])
        self.assertEqual((states[0]['ran'], states[2]['ran']), (True, False))
        self.assertNotEqual(states[0], states[1])

    async def test_the_index_grows_strictly_gaps_are_allowed_and_repetition_or_inversion_is_a_replay(self):
        owner = CatalogOwner()
        owner.scripted_checks = [{'check_index': 1}, {'check_index': 4}, {'check_index': 4}, {'check_index': 3}, {'check_index': 5}]
        async with self.catalog(owner) as sandbox:
            self.assertEqual((await sandbox.catalog_check())['check_index'], 1)
            self.assertEqual((await sandbox.catalog_check())['check_index'], 4)  # a failed attempt consumed 2 and 3
            for _ in range(2):  # 4 again, then 3: the replay is not an observation, and the last accepted index does not move
                with self.assertRaises(client.ActorError) as caught:
                    await sandbox.catalog_check()
                self.assertEqual(caught.exception.reason, 'owner_response_invalid')
            self.assertEqual((await sandbox.catalog_check())['check_index'], 5)
        self.assertEqual(owner.ops.count('catalog_check'), 5)  # nothing was repeated automatically

    async def test_an_answer_that_is_not_exactly_the_view_of_this_cell_is_invalid(self):
        bad = ({'run_id': '9' * 32}, {'variant': 'perturbed'}, {'catalog_profile': 'A'}, {'context_sha256': CAT_OTHER_CONTEXT},
               {'installation_id': '9' * 32}, {'intent_id': '9' * 32}, {'container_id': '9' * 64}, {'catalog_id': 'other/v1'},
               {'catalog_sha256': 'e' * 64},
               {'check_index': 0}, {'check_index': True}, {'check_index': 65}, {'check_index': 1.0}, {'check_index': None},
               {'probe': None}, {'probe': 'present'}, {'probe': {**CAT_PROBE_B, 'ran': 1}}, {'probe': {**CAT_PROBE_B, 'size': True}},
               {'probe': {**CAT_PROBE_B, 'stdout': '{"state":"present"}'}}, {'probe': {**CAT_PROBE_B, 'write_errno': 'erofs'}},
               {'probe': {key: value for key, value in CAT_PROBE_B.items() if key != 'size'}}, {'probe': {**CAT_PROBE_A, 'read': 'ok'}},
               {'host_check': {**CAT_HOST_OK, 'reason': 'missing'}}, {'host_check': {**CAT_HOST_OK, 'ok': 1}},
               {'host_check': {**CAT_HOST_UNREADABLE, 'reason': '/var/lib/owner/catalog.json'}}, {'host_check': 'ok'},
               {'extra': 1}, {'resource_id': 'f' * 32}, {'stdout': 'x'})
        for patch in bad:
            with self.subTest(patch=str(patch)[:60]):
                owner = CatalogOwner()
                owner.scripted_checks = [patch]
                async with self.catalog(owner) as sandbox:
                    with self.assertRaises(client.ActorError) as caught:
                        await sandbox.catalog_check()
                    self.assertEqual(caught.exception.reason, 'owner_response_invalid')
                    self.assertEqual(owner.ops.count('catalog_check'), 1)
                self.assertTrue(sandbox.cleanup_confirmed)  # the obligation was kept and restituted

    async def test_other_answers_are_never_a_check(self):
        for answer in (wire.encode_response('probe', dict(MEAS)), wire.encode_response('execute', {'stdout': 'x', 'stderr': '',
                                                                                                    'exit_code': 0, **MEAS}),
                       wire.encode_response('level_probe', {'status': 'unavailable', 'counters': None}), b'garbage'):
            owner = CatalogOwner()
            owner.errors['catalog_check'] = answer
            async with self.catalog(owner) as sandbox:
                with self.assertRaises(client.ActorError) as caught:
                    await sandbox.catalog_check()
                self.assertEqual(caught.exception.reason, 'owner_response_invalid')

    async def test_refusals_and_transport_failures_are_one_failure_and_never_an_observation(self):
        for reason in ('wrong_domain', 'busy', 'closing', 'exec_timeout', 'internal_error', 'catalog_not_allowed'):
            owner = CatalogOwner()
            owner.refuse['catalog_check'] = (reason, {})
            async with self.catalog(owner) as sandbox:
                with self.assertRaises(client.ActorError) as caught:
                    await sandbox.catalog_check()
                self.assertEqual(caught.exception.reason, reason)
        owner = CatalogOwner()
        owner.errors['catalog_check'] = OSError('reset')
        async with self.catalog(owner) as sandbox:
            with self.assertRaises(client.ActorError) as caught:
                await sandbox.catalog_check()
            self.assertEqual(caught.exception.reason, 'owner_unavailable')
        self.assertEqual((owner.ops.count('catalog_check'), owner.ops[-1]), (1, 'close'))

    async def test_a_sixty_fifth_check_is_refused_before_anything_is_sent(self):
        owner = CatalogOwner()
        async with self.catalog(owner) as sandbox:
            for expected in range(1, 65):
                self.assertEqual((await sandbox.catalog_check())['check_index'], expected)
            before = len(owner.calls)
            with self.assertRaises(client.ActorError) as caught:
                await sandbox.catalog_check()
            self.assertEqual(caught.exception.reason, 'catalog_check_exhausted')
            self.assertEqual(len(owner.calls), before)

    async def test_cancellation_during_a_check_propagates_and_exit_still_restitutes(self):
        owner = CatalogOwner()
        owner.gates['catalog_check'] = asyncio.Event()
        async with self.catalog(owner) as sandbox:
            task = asyncio.ensure_future(sandbox.catalog_check())
            await self.wait_for_op(owner, 'catalog_check')
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            del owner.gates['catalog_check']
            self.assertEqual((await sandbox.catalog_check())['check_index'], 1)  # the cancelled one did not advance the pin
        self.assertEqual(owner.ops[-1], 'close')
        self.assertTrue(sandbox.cleanup_confirmed)


class CatalogCloseClientTests(CatalogCase):
    async def test_close_is_idempotent_once_confirmed(self):
        owner = CatalogOwner()
        sandbox = self.catalog(owner)
        await sandbox.__aenter__()
        await sandbox.close()
        await sandbox.close()
        self.assertEqual(owner.ops.count('close'), 1)
        self.assertTrue(sandbox.cleanup_confirmed)

    async def test_lost_close_keeps_the_obligation_and_a_retry_restitutes_by_the_same_handle(self):
        owner = CatalogOwner()
        owner.close_failures = 1
        sandbox = self.catalog(owner)
        await sandbox.__aenter__()
        with self.assertRaises(client.ActorError) as caught:
            await sandbox.close()
        self.assertEqual(str(caught.exception), 'Sandbox cleanup could not be confirmed')
        self.assertIs(caught.exception.cleanup_confirmed, False)
        self.assertEqual(caught.exception.owner_reason, 'owner_unavailable')
        self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (False, True))
        await sandbox.close()
        self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (True, False))
        self.assertEqual([request.handle for op, request in owner.calls if op == 'close'], [HANDLE, HANDLE])

    async def test_a_receipt_with_another_identity_does_not_confirm(self):
        patches = [{key: value} for key, value in CAT_OTHER.items()] + [{'catalog_id': 'other/v1'}, {'catalog_sha256': 'e' * 64},
                                                                         {'cleanup_confirmed': False}, {'resource_id': 'f' * 32}]
        for patch in patches:
            with self.subTest(patch=str(patch)):
                owner = CatalogOwner()
                owner.close_patch = patch
                sandbox = self.catalog(owner)
                await sandbox.__aenter__()
                with self.assertRaises(client.ActorError) as caught:
                    await sandbox.close()
                self.assertEqual(caught.exception.reason, 'cleanup_unconfirmed')
                self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (False, True))

    async def test_another_domain_receipt_shape_does_not_confirm(self):
        workflow = {'installation_id': INSTALL, 'run_id': RUN, 'variant': 'legitimate', 'intent_id': INTENT, 'container_id': CONTAINER,
                    'cleanup_confirmed': True, 'oom_killed': False, **MEAS}
        level = {'installation_id': INSTALL, 'run_id': RUN, 'level': 'memory', 'stage': 'actor', 'context_sha256': CAT_CONTEXT,
                 'intent_id': INTENT, 'container_id': CONTAINER, 'cleanup_confirmed': True, 'oom_killed': False, **MEAS}
        for body in (workflow, level):
            owner = CatalogOwner()
            sandbox = self.catalog(owner)
            await sandbox.__aenter__()
            owner.errors['close'] = wire.encode_response('close', body)
            with self.assertRaises(client.ActorError) as caught:
                await sandbox.close()
            self.assertEqual((caught.exception.reason, sandbox.obligation), ('cleanup_unconfirmed', True))

    async def test_refusals_leave_the_obligation_and_health_does_not_replace_the_receipt(self):
        for reason, extras in (('unknown_handle', {}), ('cleanup_unconfirmed', {'cleanup_confirmed': False}), ('foreign_owner', {}),
                               ('internal_error', {}), ('wrong_domain', {})):
            with self.subTest(reason=reason):
                owner = CatalogOwner()
                owner.refuse['close'] = (reason, extras)
                sandbox = self.catalog(owner)
                await sandbox.__aenter__()
                with self.assertRaises(client.ActorError) as caught:
                    await sandbox.close()
                self.assertEqual(caught.exception.owner_reason, reason)
                self.assertEqual((sandbox.cleanup_confirmed, sandbox.obligation), (False, True))
                self.assertEqual(owner.ops.count('health'), 1)

    async def test_exit_raises_when_the_close_is_not_confirmed(self):
        owner = CatalogOwner()
        owner.close_failures = 1
        with self.assertRaises(client.ActorError):
            async with self.catalog(owner):
                pass


class CatalogRecoveryClientTests(CatalogCase):
    async def lost_close(self, owner):
        owner.lost_after_finish = 1
        sandbox = self.catalog(owner)
        await sandbox.__aenter__()
        with self.assertRaises(client.ActorError):
            await sandbox.close()  # the restitution reached FINISH; only its answer was lost
        self.assertTrue(sandbox.obligation)
        return sandbox

    async def test_a_lost_close_is_recovered_from_the_durable_receipt_without_any_action(self):
        owner = CatalogOwner()
        sandbox = await self.lost_close(owner)
        before = len(owner.calls)
        receipt = await client.recover_catalog_receipt(SETTINGS, sandbox.identity, transport=owner)
        self.assertEqual((receipt['status'], receipt['cleanup_confirmed']), ('confirmed', True))
        self.assertEqual({key: receipt[key] for key in wire.CATALOG_IDENTITY_FIELDS}, owner.identity)
        self.assertEqual([op for op, _ in owner.calls[before:]], ['catalog_receipt'])  # no health, open, execute, check or close
        self.assertEqual(await client.recover_catalog_receipt(SETTINGS, sandbox.identity, transport=owner), receipt)  # a read

    async def test_unknown_is_not_a_restitution(self):
        owner = CatalogOwner()
        sandbox = self.catalog(owner)
        await sandbox.__aenter__()  # ACTIVE: no FINISH yet
        with self.assertRaises(client.ActorError) as caught:
            await client.recover_catalog_receipt(SETTINGS, sandbox.identity, transport=owner)
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed, caught.exception.owner_reason),
                         ('cleanup_unconfirmed', False, 'receipt_unknown'))
        self.assertEqual(caught.exception.receipt_status, 'unknown')
        await sandbox.close()

    async def test_an_answer_for_another_identity_or_shape_never_confirms(self):
        owner = CatalogOwner()
        sandbox = await self.lost_close(owner)
        for key, value in {**CAT_OTHER, 'catalog_id': 'other/v1', 'catalog_sha256': 'e' * 64}.items():
            owner.receipt_patch = {key: value}
            with self.assertRaises(client.ActorError) as caught:
                await client.recover_catalog_receipt(SETTINGS, sandbox.identity, transport=owner)
            self.assertEqual((caught.exception.reason, caught.exception.owner_reason), ('cleanup_unconfirmed', 'owner_response_invalid'))
        for patch in ({'status': 'confirmed', 'cleanup_confirmed': False}, {'status': 'done'}, {'extra': 1}, {'resource_id': 'f' * 32}):
            owner.receipt_patch = patch
            with self.assertRaises(client.ActorError):
                await client.recover_catalog_receipt(SETTINGS, sandbox.identity, transport=owner)
        owner.receipt_patch = {}
        owner.errors['catalog_receipt'] = wire.encode_response('receipt', {**{name: sandbox.identity[name] for name in wire.IDENTITY_FIELDS},
                                                                           'status': 'confirmed', 'cleanup_confirmed': True})
        with self.assertRaises(client.ActorError) as caught:  # an M1 receipt is not a catalog receipt
            await client.recover_catalog_receipt(SETTINGS, sandbox.identity, transport=owner)
        self.assertEqual(caught.exception.owner_reason, 'owner_response_invalid')

    async def test_an_identity_that_is_not_the_nine_fields_is_refused_before_anything_is_sent(self):
        owner = CatalogOwner()
        sandbox = await self.lost_close(owner)
        good = sandbox.identity
        before = len(owner.calls)
        workflow = {key: good[key] for key in wire.IDENTITY_FIELDS}
        level = {'installation_id': INSTALL, 'run_id': RUN, 'level': 'memory', 'stage': 'actor', 'context_sha256': CAT_CONTEXT,
                 'intent_id': INTENT, 'container_id': CONTAINER}
        bad = [None, {}, [], 'x', 5, list(good), workflow, level, {**good, 'extra': 1}, {**good, 'resource_id': 'f' * 32},
               {key: value for key, value in good.items() if key != 'catalog_profile'},
               {**good, 'catalog_profile': 'C'}, {**good, 'catalog_id': 'other/v1'}, {**good, 'catalog_sha256': 'e' * 64},
               {**good, 'context_sha256': 'x'}, {**good, 'run_id': 5}, {**good, 'container_id': None}, {**good, 'intent_id': 'X' * 32}]
        for identity in bad:
            with self.assertRaises(client.ActorError) as caught:
                await client.recover_catalog_receipt(SETTINGS, identity, transport=owner)
            self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed, caught.exception.owner_reason),
                             ('cleanup_unconfirmed', False, 'identity_invalid'), str(identity)[:60])
        self.assertEqual(len(owner.calls), before)

    async def test_the_installation_pin_refusals_and_transport_failures_never_confirm(self):
        owner = CatalogOwner()
        sandbox = await self.lost_close(owner)
        before = len(owner.calls)
        pinned = client.Settings(SETTINGS.socket_path, 2000, installation_id='9' * 32)
        with self.assertRaises(client.ActorError) as caught:
            await client.recover_catalog_receipt(pinned, sandbox.identity, transport=owner)
        self.assertEqual(caught.exception.owner_reason, 'installation_mismatch')
        self.assertEqual(len(owner.calls), before)  # nothing was sent
        for reason in ('installation_mismatch', 'foreign_owner', 'internal_error', 'catalog_not_allowed'):
            owner.refuse['catalog_receipt'] = (reason, {})
            with self.assertRaises(client.ActorError) as caught:
                await client.recover_catalog_receipt(SETTINGS, sandbox.identity, transport=owner)
            self.assertEqual((caught.exception.reason, caught.exception.owner_reason, caught.exception.cleanup_confirmed),
                             ('cleanup_unconfirmed', reason, False))
        del owner.refuse['catalog_receipt']
        for failure, reason in ((OSError('reset'), 'owner_unavailable'), (wire.WireError('peer_mismatch'), 'owner_peer_unverified'),
                                (b'garbage', 'owner_response_invalid')):
            owner.errors['catalog_receipt'] = failure
            with self.assertRaises(client.ActorError) as caught:
                await client.recover_catalog_receipt(SETTINGS, sandbox.identity, transport=owner)
            self.assertEqual(caught.exception.owner_reason, reason)

    async def test_the_identity_given_is_snapshotted_and_never_modified(self):
        owner = CatalogOwner()
        sandbox = await self.lost_close(owner)
        identity = sandbox.identity
        copy = dict(identity)
        await client.recover_catalog_receipt(SETTINGS, identity, transport=owner)
        self.assertEqual(identity, copy)

        class Moving(dict):  # accessors that would answer something else on a second look
            def __getitem__(self, key):
                raise AssertionError('read through an overridable accessor')
        await client.recover_catalog_receipt(SETTINGS, Moving(copy), transport=owner)


class CatalogParityTests(unittest.TestCase):
    """The wire layer and the codec are pure and mirror signatures of the owner; these tests pin that the mirrors have not drifted."""

    def test_the_fixed_catalog_constants_equal_missions(self):
        self.assertEqual((proto.CATALOG_ID, proto.CATALOG_SHA256, proto.CATALOG_DESTINATION),
                         (missions.CATALOG_ID, missions.CATALOG_SHA256, missions.CATALOG_DESTINATION))
        self.assertEqual(proto.CATALOG_SIZE, len(missions.CATALOG_BYTES))
        self.assertEqual((C_ID, C_SHA), (missions.CATALOG_ID, missions.CATALOG_SHA256))
        self.assertEqual(proto.CATALOG_DESTINATION, runner.CATALOG_DESTINATION)

    def test_the_task_result_command_is_the_workflow_constant(self):
        tree = ast.parse((ROOT / 'services' / 'agent' / 'workflow.py').read_text(encoding='utf-8'))
        found = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == 'RESULT_PATH' for t in node.targets)]
        self.assertEqual(found, ['/work/result.json'])
        self.assertEqual(client.TASK_RESULT_COMMAND, 'cat -- ' + found[0])

    def test_the_probe_and_host_check_vocabularies_equal_the_runners(self):
        self.assertEqual(set(wire.CATALOG_PROBE_KEYS), set(runner.catalog_probe_unavailable()))
        self.assertEqual(set(wire.CATALOG_HOST_KEYS), {'ok', 'changed', 'reason', 'sha256'})
        source = (ROOT / 'services' / 'agent' / 'runner.py').read_text(encoding='utf-8')  # the reasons of CatalogResource.check
        for reason in wire.CATALOG_HOST_REASONS:
            self.assertIn("'" + reason + "'", source, reason)
        self.assertEqual(runner.CATALOG_PROBE_VERSION, 'catalog-probe/v1')
        self.assertEqual(wire.CATALOG_PROBE_MAX_SIZE, 4096)
        self.assertEqual(tuple(wire.CATALOG_PROBE_STATES), ('absent', 'present', 'unavailable'))

    def test_every_normalized_probe_the_runner_can_return_is_a_valid_answer_and_a_forged_one_is_not(self):
        identity = {'installation_id': INSTALL, 'run_id': RUN, 'variant': 'legitimate', 'catalog_profile': 'B', 'context_sha256': CAT_CONTEXT,
                    'catalog_id': C_ID, 'catalog_sha256': C_SHA, 'intent_id': INTENT, 'container_id': CONTAINER}

        def stdout(**patch):
            return {'exit_code': 0, 'stdout': json.dumps({'version': runner.CATALOG_PROBE_VERSION, 'state': 'present', 'read': 'ok',
                                                          'sha256': C_SHA, 'size': 47, 'write_open': 'rejected', 'write_errno': 'EROFS',
                                                          **patch})}
        results = [stdout(), stdout(state='absent', read=None, sha256=None, size=None, write_open=None, write_errno=None),
                   stdout(state='unavailable', read=None, sha256=None, size=None, write_open=None, write_errno=None),
                   stdout(read='failed', sha256=None, size=None), stdout(write_open='allowed', write_errno=None),
                   stdout(size=True), stdout(sha256='A' * 64), stdout(write_errno='erofs'), stdout(state='bogus'), stdout(version='x'),
                   {'exit_code': 1, 'stdout': '{}'}, {'exit_code': 0, 'stdout': 'not json'}, {'exit_code': 0, 'stdout': 'x' * 5000},
                   {'exit_code': 0, 'stdout': '[]'}, None, 'text']
        states = set()
        for result in results:
            parsed = runner.parse_catalog_probe(result)
            body = {'ok': True, 'op': 'catalog_check', **identity, 'probe': parsed, 'host_check': dict(CAT_HOST_OK), 'check_index': 1}
            self.assertEqual(wire.validate_catalog_check(body, identity=identity)['probe'], parsed, parsed)  # never raises on a real one
            states.add((parsed['ran'], parsed['state']))
            if parsed['state'] == 'present':
                forged = {**parsed, 'write_open': None}
                with self.assertRaises(wire.WireError):
                    wire.validate_catalog_check({**body, 'probe': forged}, identity=identity)
        self.assertEqual(states, {(True, 'present'), (True, 'absent'), (True, 'unavailable'), (False, 'unavailable')})

    def test_every_host_check_the_runner_can_return_without_a_filesystem_is_a_valid_answer(self):
        identity = {'installation_id': INSTALL, 'run_id': RUN, 'variant': 'legitimate', 'catalog_profile': 'B', 'context_sha256': CAT_CONTEXT,
                    'catalog_id': C_ID, 'catalog_sha256': C_SHA, 'intent_id': INTENT, 'container_id': CONTAINER}
        resource = runner.CatalogResource('/nonexistent-m31/catalog-x/catalog.json', '/nonexistent-m31/catalog-x', (1, 1, 47, 1, 1, 1))
        seen = []
        seen.append(resource.check())           # a path that is not there: missing
        resource.release()                       # nothing to remove: every removal is suppressed
        seen.append(resource.check())           # released
        seen.append({'ok': False, 'changed': None, 'reason': 'unreadable', 'sha256': None})  # the owner's own unavailable value
        for host in seen:
            body = {'ok': True, 'op': 'catalog_check', **identity, 'probe': dict(CAT_PROBE_B), 'host_check': host, 'check_index': 1}
            self.assertEqual(wire.validate_catalog_check(body, identity=identity)['host_check'], host)
        self.assertEqual([item['reason'] for item in seen], ['missing', 'released', 'unreadable'])
        self.assertEqual([item['changed'] for item in seen], [True, None, None])

    def test_the_profiles_the_client_judges_are_those_of_the_runner(self):
        self.assertEqual(runner.catalog_violations(CAT_PROFILE_B), [])
        self.assertTrue(runner.hardened_violations(CAT_PROFILE_B))  # B is not the ordinary profile
        self.assertEqual(runner.hardened_violations(PROFILE), [])
        self.assertTrue(runner.catalog_violations(PROFILE))  # and the ordinary one is not B
        self.assertEqual(CAT_PROFILE_B['catalog'], runner.catalog_receipt())

    def test_the_client_module_creates_nothing_and_has_no_fallback(self):
        text = MODULE.read_text(encoding='utf-8')
        for forbidden in ('prepare_catalog', 'CatalogResource', 'CatalogSession(', 'create_subprocess_exec', 'subprocess', 'import docker'):
            self.assertNotIn(forbidden, text, forbidden)


if __name__ == '__main__':
    unittest.main()

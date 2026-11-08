"""Tests of services/agent/actor_wire.py (M1 wire layer; no Docker, subprocess, real socket or host path).

Authored without a shell: none of these tests has been executed by the author. The operator runs them.
"""
import ast
import asyncio
import json
import socket
import struct
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.agent import actor_wire as wire  # noqa: E402
from services.agent import invoice_actor_protocol as proto  # noqa: E402

MODULE = ROOT / 'services' / 'agent' / 'actor_wire.py'
RUN = '0123456789abcdef' * 2
HANDLE = 'ab' * 32
INSTALL = '1' * 32
INTENT = '2' * 32
CONTAINER = 'c' * 64
IMAGE = 'sha256:' + 'd' * 64
DIGEST = '5' * 64
MEAS = {'memory_peak_bytes': 1024, 'memory_observed_max_bytes': None,
        'memory_measurement': {'source': 'cgroup_v2_memory.peak', 'scope': 'level_container', 'kind': 'peak', 'available': True}}
RECEIPT = {'installation_id': INSTALL, 'run_id': RUN, 'variant': 'legitimate', 'intent_id': INTENT, 'container_id': CONTAINER}
PROFILE = {'available': True, 'image_id': IMAGE}
LEVEL_OPS = ('open_level', 'level_receipt', 'level_probe')
CATALOG_OPS = ('catalog_info', 'open_catalog', 'catalog_check', 'catalog_receipt')  # M3.1: the only other additions to the tables
ROOM_OPS = ('room_action',)  # M4: the one operation added after M3.1 (limits are pinned in test_actor_rooms_backend)
NETWORK_OPS = ('network_action',)  # M5: the one operation added after M4 (limits are pinned in test_actor_network_backend)
VALID = {
    'health': {'op': 'health'},
    'open': {'op': 'open', 'run_id': RUN, 'variant': 'legitimate'},
    'execute': {'op': 'execute', 'handle': HANDLE, 'command': 'cat -- /work/input.json'},
    'probe': {'op': 'probe', 'handle': HANDLE, 'name': 'task_result'},
    'close': {'op': 'close', 'handle': HANDLE},
    'receipt': {'op': 'receipt', **RECEIPT},
}


def ok(op, **body):
    return {'ok': True, 'op': op, **body}


def raw(obj):
    return json.dumps(obj, separators=(',', ':')).encode()


HEALTH = ok('health', ready=True, image_id=IMAGE, installation_id=INSTALL, obligations=0, blocked=False)
OPEN = ok('open', handle=HANDLE, installation_id=INSTALL, run_id=RUN, variant='legitimate', intent_id=INTENT,
          name='escape-actor-' + INTENT, container_id=CONTAINER, profile_sha256=DIGEST, profile=PROFILE)
RESULT = ok('execute', stdout='out', stderr='', exit_code=0, **MEAS)
CLOSE = ok('close', **RECEIPT, cleanup_confirmed=True, oom_killed=False, **MEAS)
CONFIRMED = ok('receipt', **RECEIPT, status='confirmed', cleanup_confirmed=True)
UNKNOWN = ok('receipt', **RECEIPT, status='unknown', cleanup_confirmed=False)


def scripted(parts):
    queue = list(parts)

    def recv(count, timeout):
        return queue.pop(0) if queue else b''
    return recv


class Invalid(unittest.TestCase):
    def assertInvalid(self, call, *args, **kwargs):
        with self.assertRaises(wire.WireError) as caught:
            call(*args, **kwargs)
        self.assertEqual(caught.exception.reason, 'owner_response_invalid')


class ConstantsTests(unittest.TestCase):
    def test_limits_match_the_contract(self):
        self.assertEqual(wire.LENGTH_BYTES, 4)
        self.assertEqual(wire.MAX_REQUEST_BYTES, 16384)
        # M1 limits exactly as before; the three M2.1 operations are the only additions (invalidated by contract: the old
        # assertion compared the whole table)
        # (M3.1, invalidated by contract: the filter also leaves out the four catalog operations, whose limits are pinned apart)
        self.assertEqual({key: value for key, value in wire.RESPONSE_LIMITS.items()
                          if key not in LEVEL_OPS + CATALOG_OPS + ROOM_OPS + NETWORK_OPS},
                         {'health': 1024, 'open': 8192, 'execute': 65536, 'probe': 65536, 'close': 4096, 'receipt': 1024,
                          'error': 512})
        self.assertEqual({key: wire.RESPONSE_LIMITS[key] for key in LEVEL_OPS},
                         {'open_level': 8192, 'level_receipt': 1024, 'level_probe': 4096})
        self.assertEqual(wire.ARTIFACT_STDOUT_CHARS, 5465)

    def test_client_deadlines_keep_the_a3_values_and_add_receipt(self):
        self.assertEqual({key: value for key, value in wire.CLIENT_DEADLINES.items()
                          if key not in LEVEL_OPS + CATALOG_OPS + ROOM_OPS + NETWORK_OPS},
                         {'health': 8.0, 'open': 110.0, 'execute': 30.0, 'probe': 30.0, 'close': 60.0, 'receipt': 8.0})
        self.assertEqual({key: wire.CLIENT_DEADLINES[key] for key in LEVEL_OPS},  # M2.1: the budgets of their M1 twins
                         {'open_level': 110.0, 'level_receipt': 8.0, 'level_probe': 30.0})

    def test_vocabulary_extends_round21_without_touching_it(self):
        self.assertTrue(proto.REASONS < wire.ERROR_REASONS)
        self.assertTrue({'framing', 'owner_blocked', 'busy', 'cleanup_unconfirmed', 'exec_timeout',
                         'installation_mismatch'} <= wire.RUNTIME_REASONS)
        self.assertFalse(wire.RUNTIME_REASONS & proto.REASONS)
        self.assertEqual(wire.RECEIPT_STATUSES, ('confirmed', 'unknown'))

    def test_messages_keep_the_current_texts(self):
        self.assertEqual(wire.message('docker_unavailable'), 'Docker unavailable')
        self.assertEqual(wire.message('exec_timeout'), 'Docker command timed out')
        self.assertEqual(wire.message('create_failed'), 'Docker could not create sandbox')
        self.assertEqual(wire.message('start_failed'), 'Docker could not start sandbox')
        self.assertEqual(wire.message('not_running'), 'Docker sandbox is not running')
        self.assertEqual(wire.message('sandbox_stopped'), 'Sandbox stopped during tool execution')
        self.assertEqual(wire.message('cleanup_unconfirmed'), 'Sandbox cleanup could not be confirmed')
        self.assertEqual(wire.message('profile_rejected', ['read_only', 'tmpfs']),
                         'Sandbox effective profile does not meet the required profile: read_only, tmpfs')
        self.assertEqual(wire.message('profile_unavailable', 'inspect failed'),
                         'Sandbox effective profile unavailable: inspect failed')
        self.assertEqual(wire.message('busy'), 'Actor controller refused: busy')

    def test_module_is_pure(self):
        tree = ast.parse(MODULE.read_text(encoding='utf-8'))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {item.name.split('.')[0] for item in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(('.' * node.level) + (node.module or '') + ':' + ','.join(item.name for item in node.names))
        self.assertTrue(imported.isdisjoint({'subprocess', 'docker', 'os', 'shutil'}), imported)
        self.assertNotIn('create_subprocess_exec', MODULE.read_text(encoding='utf-8'))


class FrameTests(unittest.TestCase):
    def test_roundtrip_byte_by_byte(self):
        payload = b'{"a":1}'
        framed = wire.encode_frame(payload, limit=100)
        self.assertEqual(framed[:4], struct.pack('>I', len(payload)))
        parts = [framed[index:index + 1] for index in range(len(framed))]
        self.assertEqual(wire.read_frame(scripted(parts), limit=100), payload)

    def test_encode_rejects_empty_and_oversized(self):
        for payload, reason in ((b'', 'framing'), (b'x' * 101, 'too_large'), ('text', 'framing')):
            with self.assertRaises(wire.WireError) as caught:
                wire.encode_frame(payload, limit=100)
            self.assertEqual(caught.exception.reason, reason)

    def test_zero_length_is_framing(self):
        with self.assertRaises(wire.WireError) as caught:
            wire.read_frame(scripted([struct.pack('>I', 0)]), limit=100)
        self.assertEqual(caught.exception.reason, 'framing')

    def test_oversized_length_is_rejected_before_the_body_is_read(self):
        calls = []

        def recv(count, timeout):
            calls.append(count)
            return struct.pack('>I', 101) if len(calls) == 1 else b'x' * count
        with self.assertRaises(wire.WireError) as caught:
            wire.read_frame(recv, limit=100)
        self.assertEqual(caught.exception.reason, 'too_large')
        self.assertEqual(calls, [4])

    def test_truncated_header_and_body(self):
        for parts in ([b'\x00\x00'], [struct.pack('>I', 5) + b'ab'], []):
            with self.assertRaises(wire.WireError) as caught:
                wire.read_frame(scripted(parts), limit=100)
            self.assertEqual(caught.exception.reason, 'truncated')

    def test_bytes_after_the_frame_are_rejected(self):
        framed = wire.encode_frame(b'{"a":1}', limit=100)
        for parts in ([framed + b'x'], [framed, b'x']):
            with self.assertRaises(wire.WireError) as caught:
                wire.read_frame(scripted(parts), limit=100)
            self.assertEqual(caught.exception.reason, 'trailing_bytes')

    def test_deadline_covers_the_whole_read_and_recv_gets_the_remainder(self):
        times = iter([0.0, 0.25, 2.0])
        seen = []

        def recv(count, timeout):
            seen.append(timeout)
            return b'\x00'
        with self.assertRaises(wire.WireError) as caught:
            wire.read_frame(recv, limit=100, deadline=1.0, clock=lambda: next(times))
        self.assertEqual(caught.exception.reason, 'timeout')
        self.assertEqual(seen, [1.0, 0.75])


class AsyncFrameTests(unittest.IsolatedAsyncioTestCase):
    async def test_reads_one_frame_then_eof(self):
        data = bytearray(wire.encode_frame(b'{"op":"health"}', limit=100))

        async def recv(count):
            chunk = bytes(data[:count])
            del data[:count]
            return chunk
        self.assertEqual(await wire.read_frame_async(recv, limit=100, timeout=1), b'{"op":"health"}')

    async def test_slow_peer_hits_the_total_deadline(self):
        async def recv(count):
            await asyncio.sleep(30)
        with self.assertRaises(wire.WireError) as caught:
            await wire.read_frame_async(recv, limit=100, timeout=0.05)
        self.assertEqual(caught.exception.reason, 'timeout')

    async def test_trailing_bytes_are_rejected(self):
        data = bytearray(wire.encode_frame(b'{"op":"health"}', limit=100) + b'x')

        async def recv(count):
            chunk = bytes(data[:count])
            del data[:count]
            return chunk
        with self.assertRaises(wire.WireError) as caught:
            await wire.read_frame_async(recv, limit=100, timeout=1)
        self.assertEqual(caught.exception.reason, 'trailing_bytes')


class RequestTests(unittest.TestCase):
    def test_round21_requests_decode_identically(self):
        for body in VALID.values():
            encoded = raw(body)
            self.assertEqual(wire.decode_request(encoded), proto.decode_request(encoded))

    def test_rejections_match_round21_for_a_corpus(self):
        corpus = [b'', b'{}', b'[]', b'\xff', b'{"op":"health","op":"health"}', b'{"op":"health","x":1}',
                  raw({'op': 'open_session', 'profile': 'ordinary/v1', 'run_id': RUN, 'slot': 'actor'}),
                  raw({'op': 'copy_scan', 'handle': HANDLE}), raw({'op': 'open', 'run_id': RUN, 'variant': 'actor'}),
                  raw({'op': 'execute', 'handle': HANDLE, 'command': 'a\x00b'}), b'{"op":"health","n":NaN}',
                  raw({'op': 'receipt', **{**RECEIPT, 'installation_id': 'x'}}), raw({'op': 'receipt', **{**RECEIPT, 'intent_id': 'x'}}),
                  raw({'op': 'receipt', **{**RECEIPT, 'container_id': 'x'}}), raw({'op': 'receipt', 'handle': HANDLE}),
                  raw({'op': 'receipt', **RECEIPT, 'handle': HANDLE}), raw({'op': 'receipt', **RECEIPT, 'image': 'x'})]
        for item in corpus:
            with self.assertRaises(proto.ProtocolError) as expected:
                proto.decode_request(item)
            with self.assertRaises(proto.ProtocolError) as actual:
                wire.decode_request(item)
            self.assertEqual(actual.exception.reason, expected.exception.reason)

    def test_extension_operations_are_not_part_of_m1(self):
        # (M3.1, invalidated by contract: catalog_check is now a closed operation; it is judged by its shape, see the M3.1 tests)
        # (M4, invalidated by contract: room_action is now a closed operation `{op, handle}`; see test_actor_rooms_backend)
        for op in ('open_session', 'copy_scan', 'catalog_run', 'canary_control'):
            with self.assertRaises(proto.ProtocolError) as caught:
                wire.decode_request(raw({'op': op}))
            self.assertEqual(caught.exception.reason, 'unknown_op')

    def test_encode_request_uses_the_owner_decoder_and_never_truncates(self):
        encoded = wire.encode_request('execute', handle=HANDLE, command='€' * 2730)  # 8190 bytes
        self.assertEqual(wire.decode_request(encoded).command, '€' * 2730)
        with self.assertRaises(proto.ProtocolError) as caught:
            wire.encode_request('execute', handle=HANDLE, command='€' * 2731)  # 8193 bytes
        self.assertEqual(caught.exception.reason, 'command_too_large')
        with self.assertRaises(proto.ProtocolError) as caught:
            wire.encode_request('execute', handle=HANDLE, command='\ud800')
        self.assertEqual(caught.exception.reason, 'invalid_command')
        with self.assertRaises(proto.ProtocolError) as caught:
            wire.encode_request('close', handle='nope')
        self.assertEqual(caught.exception.reason, 'invalid_handle')

    def test_receipt_request_roundtrips_and_is_refused_locally_when_malformed(self):
        encoded = wire.encode_request('receipt', **RECEIPT)
        request = wire.decode_request(encoded)
        self.assertEqual((request.op, request.installation_id, request.run_id, request.variant, request.intent_id,
                          request.container_id), ('receipt', INSTALL, RUN, 'legitimate', INTENT, CONTAINER))
        for fields, reason in (({**RECEIPT, 'container_id': 'c' * 63}, 'invalid_container_id'),
                               ({**RECEIPT, 'installation_id': 'X' * 32}, 'invalid_installation_id'),
                               ({**RECEIPT, 'intent_id': None}, 'invalid_intent_id'),
                               ({**RECEIPT, 'handle': HANDLE}, 'unexpected_field'),
                               ({key: value for key, value in RECEIPT.items() if key != 'run_id'}, 'missing_field')):
            with self.assertRaises(proto.ProtocolError) as caught:
                wire.encode_request('receipt', **fields)
            self.assertEqual(caught.exception.reason, reason)


class ResponseTests(Invalid):
    def test_strict_json(self):
        for item in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}', b'\xff', b'{', b''):
            self.assertInvalid(wire.strict_json, item)
        self.assertEqual(wire.strict_json(b'{"a":[1,2]}'), {'a': [1, 2]})

    def test_success_envelope(self):
        self.assertEqual(wire.decode_response(raw(HEALTH), op='health'), HEALTH)
        for bad in (ok('open'), {**HEALTH, 'ok': 1}, {**HEALTH, 'ok': 'true'}, [HEALTH]):
            self.assertInvalid(wire.decode_response, raw(bad), op='health')
        self.assertInvalid(wire.decode_response, raw(HEALTH) + b' ' * 1100, op='health')
        self.assertInvalid(wire.decode_response, b'', op='health')
        self.assertInvalid(wire.decode_response, raw(HEALTH), op='error')

    def test_refusal_is_a_remote_error_with_closed_fields(self):
        body = wire.error_response('profile_rejected', cleanup_confirmed=True, violations=['read_only', 'tmpfs'])
        self.assertLessEqual(len(body), 512)
        with self.assertRaises(wire.RemoteError) as caught:
            wire.decode_response(body, op='open')
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed, caught.exception.violations),
                         ('profile_rejected', True, ('read_only', 'tmpfs')))
        with self.assertRaises(wire.RemoteError) as caught:
            wire.decode_response(wire.error_response('busy'), op='execute')
        self.assertIsNone(caught.exception.cleanup_confirmed)

    def test_malformed_refusals_are_invalid_responses(self):
        for bad in ({'ok': False}, {'ok': False, 'reason': 'made_up'}, {'ok': False, 'reason': 'busy', 'extra': 1},
                    {'ok': False, 'reason': 'busy', 'cleanup_confirmed': 1},
                    {'ok': False, 'reason': 'busy', 'violations': ['not_a_name']},
                    {'ok': False, 'reason': 'busy', 'violations': 'tmpfs'}):
            self.assertInvalid(wire.decode_response, raw(bad), op='execute')
        self.assertInvalid(wire.decode_response, wire.error_response('busy') + b' ' * 600, op='execute')

    def test_error_response_refuses_outside_the_vocabulary(self):
        for kwargs in ({'reason': 'made_up'}, {'reason': 'busy', 'cleanup_confirmed': 1},
                       {'reason': 'busy', 'violations': ['nope']}):
            with self.assertRaises(ValueError):
                wire.error_response(**kwargs)

    def test_response_limit_is_enforced_when_encoding(self):
        with self.assertRaises(wire.WireError) as caught:
            wire.encode_response('execute', {'stdout': 'x' * 70000})
        self.assertEqual(caught.exception.reason, 'too_large')
        with self.assertRaises(ValueError):
            wire.encode_response('error', {})


class ValidatorTests(Invalid):
    def test_health(self):
        self.assertEqual(wire.validate_health(HEALTH), HEALTH)
        self.assertEqual(wire.validate_health({**HEALTH, 'image_id': None})['image_id'], None)
        for bad in ({**HEALTH, 'ready': 1}, {**HEALTH, 'blocked': 0}, {**HEALTH, 'obligations': True},
                    {**HEALTH, 'obligations': -1}, {**HEALTH, 'image_id': 'sha256:abc'},
                    {**HEALTH, 'installation_id': 'X' * 32}, {**HEALTH, 'extra': 1},
                    {key: value for key, value in HEALTH.items() if key != 'ready'}):
            self.assertInvalid(wire.validate_health, bad)

    def test_open_is_bound_to_run_variant_installation_and_image(self):
        args = dict(run_id=RUN, variant='legitimate', installation_id=INSTALL, image_id=IMAGE)
        self.assertEqual(wire.validate_open(OPEN, **args), OPEN)
        self.assertInvalid(wire.validate_open, OPEN, **{**args, 'run_id': '9' * 32})
        self.assertInvalid(wire.validate_open, OPEN, **{**args, 'variant': 'perturbed'})
        self.assertInvalid(wire.validate_open, OPEN, **{**args, 'installation_id': '9' * 32})
        self.assertInvalid(wire.validate_open, OPEN, **{**args, 'image_id': 'sha256:' + 'e' * 64})
        for bad in ({**OPEN, 'name': 'escape-actor-' + '9' * 32}, {**OPEN, 'handle': 'AB' * 32},
                    {**OPEN, 'container_id': 'c' * 63}, {**OPEN, 'profile': {'available': False}},
                    {**OPEN, 'profile': 'x'}, {**OPEN, 'extra': 1}, {**OPEN, 'variant': 'actor'}):
            self.assertInvalid(wire.validate_open, bad, **args)

    def test_result_shapes_and_sizes(self):
        result = wire.validate_result(RESULT, op='execute')
        self.assertEqual(result['stdout'], 'out')
        self.assertEqual(result['memory_peak_bytes'], 1024)
        wire.validate_result(ok('execute', stdout='x' * 4096, stderr='y' * 4096, exit_code=-9, **MEAS), op='execute')
        self.assertInvalid(wire.validate_result, ok('execute', stdout='x' * 4097, stderr='', exit_code=0, **MEAS), op='execute')
        self.assertInvalid(wire.validate_result, ok('execute', stdout='', stderr='y' * 4097, exit_code=0, **MEAS), op='execute')
        for bad in ({**RESULT, 'exit_code': True}, {**RESULT, 'exit_code': '0'}, {**RESULT, 'extra': 1}, {**RESULT, 'op': 'probe'},
                    {key: value for key, value in RESULT.items() if key != 'stderr'}, {**RESULT, 'stdout': None}):
            self.assertInvalid(wire.validate_result, bad, op='execute')

    def test_artifact_capture_allows_the_base64_length_and_no_more(self):
        probe = ok('probe', stdout='A' * 5465, stderr='', exit_code=0, **MEAS)
        wire.validate_result(probe, op='probe', name='artifact_capture')
        self.assertInvalid(wire.validate_result, {**probe, 'stdout': 'A' * 5466}, op='probe', name='artifact_capture')
        self.assertInvalid(wire.validate_result, {**probe, 'stdout': 'A' * 4097}, op='probe', name='task_result')

    def test_measurement_consistency(self):
        unavailable = {'memory_peak_bytes': None, 'memory_observed_max_bytes': None,
                       'memory_measurement': {'source': None, 'scope': 'level_container', 'kind': None, 'available': False}}
        self.assertEqual(wire.check_measurement(unavailable), unavailable)
        self.assertEqual(wire.check_measurement(wire.unavailable_measurement()), unavailable)
        broken = [{**MEAS, 'memory_peak_bytes': None},
                  {**unavailable, 'memory_peak_bytes': 5},
                  {**MEAS, 'memory_peak_bytes': True},
                  {**MEAS, 'memory_peak_bytes': -1},
                  {**MEAS, 'memory_measurement': {**MEAS['memory_measurement'], 'available': 1}},
                  {**MEAS, 'memory_measurement': {'source': 'x'}},
                  {**MEAS, 'memory_measurement': {**MEAS['memory_measurement'], 'extra': 1}},
                  {key: value for key, value in MEAS.items() if key != 'memory_measurement'}]
        for bad in broken:
            self.assertInvalid(wire.check_measurement, bad)

    def test_measure_probe(self):
        measured = ok('probe', **MEAS)
        self.assertEqual(wire.validate_result(measured, op='probe', name='measure'), MEAS)
        self.assertEqual(wire.validate_measure(measured), MEAS)
        self.assertInvalid(wire.validate_measure, {**measured, 'stdout': ''})
        self.assertInvalid(wire.validate_measure, ok('execute', **MEAS))

    def test_close_confirms_only_with_the_original_identity(self):
        self.assertEqual(wire.validate_close(CLOSE, receipt=RECEIPT)['oom_killed'], False)
        self.assertIsNone(wire.validate_close({**CLOSE, 'oom_killed': None}, receipt=RECEIPT)['oom_killed'])
        other = {'installation_id': '9' * 32, 'run_id': '9' * 32, 'variant': 'perturbed', 'intent_id': '9' * 32,
                 'container_id': '9' * 64}
        for key, value in other.items():
            self.assertInvalid(wire.validate_close, CLOSE, receipt={**RECEIPT, key: value})
        for bad in ({**CLOSE, 'cleanup_confirmed': False}, {**CLOSE, 'cleanup_confirmed': 1}, {**CLOSE, 'oom_killed': 0},
                    {**CLOSE, 'extra': 1}, {key: value for key, value in CLOSE.items() if key != 'intent_id'}):
            self.assertInvalid(wire.validate_close, bad, receipt=RECEIPT)
        self.assertInvalid(wire.validate_close, CLOSE, receipt={'installation_id': INSTALL})
        self.assertInvalid(wire.validate_close, HEALTH, receipt=RECEIPT)  # health is never a close receipt


class ReceiptResponseTests(Invalid):
    def test_confirmed_and_unknown_are_well_formed_answers_bound_to_the_identity(self):
        self.assertEqual(wire.validate_receipt(CONFIRMED, identity=RECEIPT), CONFIRMED)
        self.assertEqual(wire.validate_receipt(UNKNOWN, identity=RECEIPT), UNKNOWN)
        self.assertEqual(wire.validate_receipt(dict(CONFIRMED), identity=RECEIPT)['status'], 'confirmed')
        self.assertEqual(wire.validate_receipt(dict(UNKNOWN), identity=RECEIPT)['cleanup_confirmed'], False)

    def test_encoder_and_decoder_roundtrip_within_the_limit(self):
        body = {**RECEIPT, 'status': 'confirmed', 'cleanup_confirmed': True}
        encoded = wire.encode_response('receipt', body)
        self.assertLess(len(encoded), wire.RESPONSE_LIMITS['receipt'] // 2)
        decoded = wire.decode_response(encoded, op='receipt')
        self.assertEqual(decoded, CONFIRMED)
        self.assertEqual(wire.validate_receipt(decoded, identity=RECEIPT)['status'], 'confirmed')
        self.assertInvalid(wire.decode_response, encoded, op='close')  # an answer is only valid for the operation asked
        self.assertInvalid(wire.decode_response, encoded + b' ' * 1100, op='receipt')
        with self.assertRaises(wire.WireError) as caught:
            wire.encode_response('receipt', {**body, 'padding': 'x' * 1100})
        self.assertEqual(caught.exception.reason, 'too_large')

    def test_status_and_flag_must_agree_exactly(self):
        for status, flag in (('confirmed', False), ('unknown', True), ('confirmed', 1), ('unknown', 0), ('confirmed', 'true'),
                             ('confirmed', None), ('unknown', None)):
            self.assertInvalid(wire.validate_receipt, {**CONFIRMED, 'status': status, 'cleanup_confirmed': flag},
                               identity=RECEIPT)
        for status in ('Confirmed', 'CONFIRMED', 'done', 'finished', 'pending', '', None, 1, True, ['confirmed'], {'a': 1}):
            self.assertInvalid(wire.validate_receipt, {**CONFIRMED, 'status': status}, identity=RECEIPT)
            self.assertInvalid(wire.validate_receipt, {**UNKNOWN, 'status': status}, identity=RECEIPT)

    def test_shape_and_types_are_exact(self):
        bad = [{**CONFIRMED, 'extra': 1}, {**CONFIRMED, 'oom_killed': False}, {**CONFIRMED, 'handle': HANDLE},
               {key: value for key, value in CONFIRMED.items() if key != 'status'},
               {key: value for key, value in CONFIRMED.items() if key != 'cleanup_confirmed'},
               {key: value for key, value in CONFIRMED.items() if key != 'container_id'},
               {**CONFIRMED, 'ok': 1}, {**CONFIRMED, 'ok': 'true'}, {**CONFIRMED, 'ok': False}, {**CONFIRMED, 'op': 'close'},
               {**CONFIRMED, 'op': 'health'}, {**CONFIRMED, 'op': None},
               {**CONFIRMED, 'installation_id': 'X' * 32}, {**CONFIRMED, 'installation_id': '1' * 31},
               {**CONFIRMED, 'run_id': RUN.upper()}, {**CONFIRMED, 'variant': 'actor'}, {**CONFIRMED, 'variant': None},
               {**CONFIRMED, 'intent_id': '2' * 33}, {**CONFIRMED, 'container_id': 'c' * 63},
               {**CONFIRMED, 'container_id': 'c' * 64 + '\n'}, {**CONFIRMED, 'container_id': 5}]
        for body in bad:
            self.assertInvalid(wire.validate_receipt, body, identity=RECEIPT)
        for body in (None, [], 'text', 5, CONFIRMED['status']):
            self.assertInvalid(wire.validate_receipt, body, identity=RECEIPT)

    def test_another_identity_in_the_answer_is_never_accepted(self):
        other = {'installation_id': '9' * 32, 'run_id': '9' * 32, 'variant': 'perturbed', 'intent_id': '9' * 32,
                 'container_id': '9' * 64}
        for key, value in other.items():
            self.assertInvalid(wire.validate_receipt, {**CONFIRMED, key: value}, identity=RECEIPT)  # answer differs
            self.assertInvalid(wire.validate_receipt, {**UNKNOWN, key: value}, identity=RECEIPT)
            self.assertInvalid(wire.validate_receipt, CONFIRMED, identity={**RECEIPT, key: value})  # asked about another one
        self.assertInvalid(wire.validate_receipt, {**CONFIRMED, **other}, identity=RECEIPT)

    def test_identity_argument_must_be_the_exact_five_fields(self):
        for identity in (None, {}, {'installation_id': INSTALL}, {**RECEIPT, 'extra': 1}, list(RECEIPT), 'x',
                         {key: value for key, value in RECEIPT.items() if key != 'variant'}):
            self.assertInvalid(wire.validate_receipt, CONFIRMED, identity=identity)

    def test_no_other_answer_is_a_receipt(self):
        for body in (HEALTH, CLOSE, OPEN, RESULT):
            self.assertInvalid(wire.validate_receipt, body, identity=RECEIPT)
        self.assertInvalid(wire.validate_close, CONFIRMED, receipt=RECEIPT)  # and a receipt is not a close answer
        self.assertInvalid(wire.validate_health, CONFIRMED)

    def test_refusals_decode_as_remote_errors_with_the_new_closed_reason(self):
        with self.assertRaises(wire.RemoteError) as caught:
            wire.decode_response(wire.error_response('installation_mismatch'), op='receipt')
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('installation_mismatch', None))
        with self.assertRaises(wire.RemoteError) as caught:
            wire.decode_response(wire.error_response('foreign_owner'), op='receipt')
        self.assertEqual(caught.exception.reason, 'foreign_owner')
        self.assertInvalid(wire.decode_response, raw({'ok': False, 'reason': 'made_up'}), op='receipt')

    def test_strict_json_applies_to_receipt_answers(self):
        duplicate = (b'{"ok":true,"op":"receipt","status":"unknown","status":"confirmed","cleanup_confirmed":false}')
        self.assertInvalid(wire.decode_response, duplicate, op='receipt')
        self.assertInvalid(wire.decode_response, raw(CONFIRMED).replace(b'true', b'NaN'), op='receipt')


class FakeSock:
    def __init__(self, uid=None, error=None):
        self.uid, self.error = uid, error

    def getsockopt(self, level, option, size):
        if self.error is not None:
            raise self.error
        return struct.pack('=iII', 77, self.uid, self.uid)


class PeerTests(unittest.TestCase):
    def test_reads_the_uid_of_the_peer(self):
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            self.assertEqual(wire.peer_uid(FakeSock(1234)), 1234)

    def test_fails_closed_without_credentials(self):
        with mock.patch.object(socket, 'SO_PEERCRED', None, create=True):
            with self.assertRaises(wire.WireError) as caught:
                wire.peer_uid(FakeSock(1))
            self.assertEqual(caught.exception.reason, 'linux_peer_credentials_required')
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            for sock in (FakeSock(error=OSError()), None, object()):
                with self.assertRaises(wire.WireError) as caught:
                    wire.peer_uid(sock)
                self.assertEqual(caught.exception.reason, 'peer_unverified')


# ------------------------------------------------------------------------------------------------------- M2.1 · levels

CONTEXT = '7' * 64
OTHER_CONTEXT = '8' * 64
LEVEL_VALID = {
    'open_level': {'op': 'open_level', 'run_id': RUN, 'level': 'memory', 'stage': 'actor', 'context_sha256': CONTEXT},
    'level_probe': {'op': 'level_probe', 'handle': HANDLE, 'name': 'cgroup_events'},
    'level_receipt': {'op': 'level_receipt', 'installation_id': INSTALL, 'run_id': RUN, 'level': 'memory', 'stage': 'actor',
                      'context_sha256': CONTEXT, 'intent_id': INTENT, 'container_id': CONTAINER},
}
LEVEL_RECEIPT = {'installation_id': INSTALL, 'run_id': RUN, 'level': 'memory', 'stage': 'actor', 'context_sha256': CONTEXT,
                 'intent_id': INTENT, 'container_id': CONTAINER}
LEVEL_OTHER = {'installation_id': '9' * 32, 'run_id': '9' * 32, 'level': 'secret', 'stage': 'fresh', 'context_sha256': OTHER_CONTEXT,
               'intent_id': '9' * 32, 'container_id': '9' * 64}
COUNTERS = {'low': 0, 'high': 0, 'max': 0, 'oom': 1, 'oom_kill': 2}
LEVEL_OPEN = ok('open_level', handle=HANDLE, installation_id=INSTALL, run_id=RUN, level='memory', stage='actor',
                context_sha256=CONTEXT, intent_id=INTENT, name='escape-actor-' + INTENT, container_id=CONTAINER,
                profile_sha256=DIGEST, profile=PROFILE)
LEVEL_CLOSE = ok('close', **LEVEL_RECEIPT, cleanup_confirmed=True, oom_killed=False, **MEAS)
LEVEL_CONFIRMED = ok('level_receipt', **LEVEL_RECEIPT, status='confirmed', cleanup_confirmed=True)
LEVEL_UNKNOWN = ok('level_receipt', **LEVEL_RECEIPT, status='unknown', cleanup_confirmed=False)
LEVEL_PROBE = ok('level_probe', status='available', counters=COUNTERS)
LEVEL_PROBE_UNAVAILABLE = ok('level_probe', status='unavailable', counters=None)
LEVEL_ARGS = dict(run_id=RUN, level='memory', stage='actor', context_sha256=CONTEXT, installation_id=INSTALL, image_id=IMAGE)


def counter_key(index):
    return (chr(97 + index // 26) + chr(97 + index % 26)).ljust(32, '_')


class LevelConstantsTests(unittest.TestCase):
    def test_identity_vocabulary_and_reasons(self):
        self.assertEqual(wire.LEVEL_IDENTITY_FIELDS, ('installation_id', 'run_id', 'level', 'stage', 'context_sha256',
                                                      'intent_id', 'container_id'))
        self.assertNotIn('variant', wire.LEVEL_IDENTITY_FIELDS)
        self.assertEqual(wire.IDENTITY_FIELDS, ('installation_id', 'run_id', 'variant', 'intent_id', 'container_id'))  # M1 intact
        self.assertTrue({'level_not_allowed', 'context_mismatch', 'wrong_domain'} <= wire.RUNTIME_REASONS)
        self.assertFalse(wire.RUNTIME_REASONS & proto.REASONS)
        self.assertEqual(wire.LEVEL_PROBE_STATUSES, ('available', 'unavailable'))
        self.assertEqual(wire.MAX_LEVEL_COUNTERS, 32)

    def test_level_requests_decode_like_the_protocol(self):
        for body in LEVEL_VALID.values():
            encoded = raw(body)
            self.assertEqual(wire.decode_request(encoded), proto.decode_request(encoded))

    def test_encode_request_uses_the_owner_decoder_and_refuses_malformed_level_requests_locally(self):
        for op, fields in LEVEL_VALID.items():
            body = {key: value for key, value in fields.items() if key != 'op'}
            self.assertEqual(wire.decode_request(wire.encode_request(op, **body)).op, op)
        cases = (
            # M2.3: persistence is a valid name; M5: so is `network` (see test_actor_network_backend), the invalid probe is another name
            ('open_level', {**LEVEL_VALID['open_level'], 'level': 'bogus'}, 'invalid_level'),
            ('open_level', {**LEVEL_VALID['open_level'], 'stage': 'fresh'}, 'invalid_stage'),
            ('open_level', {**LEVEL_VALID['open_level'], 'context_sha256': 'x'}, 'invalid_context'),
            ('open_level', {**LEVEL_VALID['open_level'], 'variant': 'legitimate'}, 'unexpected_field'),
            ('open_level', {**LEVEL_VALID['open_level'], 'image': 'x'}, 'forbidden_field'),
            ('level_receipt', {**LEVEL_VALID['level_receipt'], 'context_sha256': CONTEXT[:-1]}, 'invalid_context'),
            ('level_probe', {**LEVEL_VALID['level_probe'], 'name': 'measure'}, 'invalid_name'),
            ('level_probe', {**LEVEL_VALID['level_probe'], 'path': '/sys/fs/cgroup/memory.events'}, 'forbidden_field'),
            ('level_probe', {**LEVEL_VALID['level_probe'], 'script': 'cat /etc/shadow'}, None),
        )
        for op, fields, reason in cases:
            body = {key: value for key, value in fields.items() if key != 'op'}
            with self.assertRaises(proto.ProtocolError) as caught:
                wire.encode_request(op, **body)
            if reason is not None:
                self.assertEqual(caught.exception.reason, reason)
            else:
                self.assertIn(caught.exception.reason, {'unexpected_field', 'forbidden_field'})


class LevelOpenResponseTests(Invalid):
    def test_open_is_bound_to_run_level_stage_context_installation_and_image(self):
        self.assertEqual(wire.validate_level_open(LEVEL_OPEN, **LEVEL_ARGS), LEVEL_OPEN)
        self.assertEqual(wire.validate_level_open(LEVEL_OPEN, run_id=RUN, level='memory', stage='actor',
                                                  context_sha256=CONTEXT), LEVEL_OPEN)  # the pins are optional
        for key, bad in (('run_id', '9' * 32), ('level', 'secret'), ('stage', 'fresh'), ('context_sha256', OTHER_CONTEXT),
                         ('installation_id', '9' * 32), ('image_id', 'sha256:' + 'e' * 64)):
            self.assertInvalid(wire.validate_level_open, LEVEL_OPEN, **{**LEVEL_ARGS, key: bad})

    def test_malformed_open_answers_are_invalid(self):
        for bad in ({**LEVEL_OPEN, 'name': 'escape-actor-' + '9' * 32}, {**LEVEL_OPEN, 'handle': 'AB' * 32},
                    {**LEVEL_OPEN, 'container_id': 'c' * 63}, {**LEVEL_OPEN, 'profile_sha256': 'x'},
                    {**LEVEL_OPEN, 'profile': {'available': False}}, {**LEVEL_OPEN, 'profile': 'x'},
                    {**LEVEL_OPEN, 'extra': 1}, {**LEVEL_OPEN, 'variant': 'legitimate'}, {**LEVEL_OPEN, 'op': 'open'},
                    {**LEVEL_OPEN, 'ok': 1}, {**LEVEL_OPEN, 'level': 'persistence'}, {**LEVEL_OPEN, 'context_sha256': 'A' * 64},
                    {**LEVEL_OPEN, 'context_sha256': CONTEXT[:-1]}, {**LEVEL_OPEN, 'intent_id': 5},
                    {key: value for key, value in LEVEL_OPEN.items() if key != 'context_sha256'},
                    {key: value for key, value in LEVEL_OPEN.items() if key != 'stage'}):
            self.assertInvalid(wire.validate_level_open, bad, **LEVEL_ARGS)
        # equal to the asked value is not enough: the value itself must be well formed
        self.assertInvalid(wire.validate_level_open, {**LEVEL_OPEN, 'stage': 'fresh'}, **{**LEVEL_ARGS, 'stage': 'fresh'})
        self.assertInvalid(wire.validate_level_open, {**LEVEL_OPEN, 'context_sha256': 'A' * 64},
                           **{**LEVEL_ARGS, 'context_sha256': 'A' * 64})

    def test_the_two_open_shapes_are_never_mixed(self):
        self.assertInvalid(wire.validate_level_open, OPEN, **LEVEL_ARGS)
        self.assertInvalid(wire.validate_open, LEVEL_OPEN, run_id=RUN, variant='legitimate', installation_id=INSTALL,
                           image_id=IMAGE)
        self.assertInvalid(wire.validate_level_open, HEALTH, **LEVEL_ARGS)

    def test_encoder_roundtrip_within_the_limit(self):
        body = {key: value for key, value in LEVEL_OPEN.items() if key not in ('ok', 'op')}
        encoded = wire.encode_response('open_level', body)
        self.assertLess(len(encoded), wire.RESPONSE_LIMITS['open_level'])
        self.assertEqual(wire.validate_level_open(wire.decode_response(encoded, op='open_level'), **LEVEL_ARGS), LEVEL_OPEN)
        self.assertInvalid(wire.decode_response, encoded, op='open')  # an answer is only valid for the operation asked


class LevelCloseResponseTests(Invalid):
    def test_close_confirms_only_with_the_original_level_identity(self):
        self.assertEqual(wire.validate_level_close(LEVEL_CLOSE, receipt=LEVEL_RECEIPT)['oom_killed'], False)
        self.assertIsNone(wire.validate_level_close({**LEVEL_CLOSE, 'oom_killed': None}, receipt=LEVEL_RECEIPT)['oom_killed'])
        self.assertTrue(wire.validate_level_close({**LEVEL_CLOSE, 'oom_killed': True}, receipt=LEVEL_RECEIPT)['oom_killed'])
        for key, value in LEVEL_OTHER.items():
            self.assertInvalid(wire.validate_level_close, LEVEL_CLOSE, receipt={**LEVEL_RECEIPT, key: value})
        self.assertInvalid(wire.validate_level_close, LEVEL_CLOSE, receipt={**LEVEL_RECEIPT, **LEVEL_OTHER})

    def test_malformed_close_answers_are_invalid(self):
        for bad in ({**LEVEL_CLOSE, 'cleanup_confirmed': False}, {**LEVEL_CLOSE, 'cleanup_confirmed': 1}, {**LEVEL_CLOSE, 'oom_killed': 0},
                    {**LEVEL_CLOSE, 'extra': 1}, {**LEVEL_CLOSE, 'variant': 'legitimate'}, {**LEVEL_CLOSE, 'op': 'receipt'},
                    {**LEVEL_CLOSE, 'level': 'persistence'}, {**LEVEL_CLOSE, 'context_sha256': 'x'},
                    {key: value for key, value in LEVEL_CLOSE.items() if key != 'context_sha256'},
                    {key: value for key, value in LEVEL_CLOSE.items() if key != 'level'},
                    {key: value for key, value in LEVEL_CLOSE.items() if key != 'memory_measurement'}):
            self.assertInvalid(wire.validate_level_close, bad, receipt=LEVEL_RECEIPT)
        for receipt in (None, {}, {'installation_id': INSTALL}, {**LEVEL_RECEIPT, 'extra': 1}, list(LEVEL_RECEIPT), 'x',
                        {key: value for key, value in LEVEL_RECEIPT.items() if key != 'context_sha256'}, RECEIPT):
            self.assertInvalid(wire.validate_level_close, LEVEL_CLOSE, receipt=receipt)
        self.assertInvalid(wire.validate_level_close, HEALTH, receipt=LEVEL_RECEIPT)  # health is never a close receipt

    def test_the_two_close_shapes_are_never_mixed(self):
        self.assertInvalid(wire.validate_level_close, CLOSE, receipt=LEVEL_RECEIPT)
        self.assertInvalid(wire.validate_level_close, CLOSE, receipt=RECEIPT)
        self.assertInvalid(wire.validate_close, LEVEL_CLOSE, receipt=RECEIPT)
        self.assertInvalid(wire.validate_close, LEVEL_CLOSE, receipt=LEVEL_RECEIPT)
        self.assertEqual(wire.validate_close(CLOSE, receipt=RECEIPT)['oom_killed'], False)  # M1 keeps its own

    def test_encoder_roundtrip_within_the_limit(self):
        body = {**LEVEL_RECEIPT, 'cleanup_confirmed': True, 'oom_killed': False, **MEAS}
        encoded = wire.encode_response('close', body)
        self.assertLess(len(encoded), wire.RESPONSE_LIMITS['close'])
        decoded = wire.decode_response(encoded, op='close')
        self.assertEqual(wire.validate_level_close(decoded, receipt=LEVEL_RECEIPT)['memory_peak_bytes'], 1024)


class LevelReceiptResponseTests(Invalid):
    def test_confirmed_and_unknown_are_well_formed_answers_bound_to_the_identity(self):
        self.assertEqual(wire.validate_level_receipt(LEVEL_CONFIRMED, identity=LEVEL_RECEIPT), LEVEL_CONFIRMED)
        self.assertEqual(wire.validate_level_receipt(LEVEL_UNKNOWN, identity=LEVEL_RECEIPT), LEVEL_UNKNOWN)
        self.assertEqual(wire.validate_level_receipt(dict(LEVEL_UNKNOWN), identity=LEVEL_RECEIPT)['cleanup_confirmed'], False)

    def test_encoder_and_decoder_roundtrip_within_the_limit(self):
        body = {**LEVEL_RECEIPT, 'status': 'confirmed', 'cleanup_confirmed': True}
        encoded = wire.encode_response('level_receipt', body)
        self.assertLess(len(encoded), wire.RESPONSE_LIMITS['level_receipt'])
        decoded = wire.decode_response(encoded, op='level_receipt')
        self.assertEqual(decoded, LEVEL_CONFIRMED)
        self.assertEqual(wire.validate_level_receipt(decoded, identity=LEVEL_RECEIPT)['status'], 'confirmed')
        self.assertInvalid(wire.decode_response, encoded, op='receipt')
        self.assertInvalid(wire.decode_response, encoded, op='close')
        self.assertInvalid(wire.decode_response, encoded + b' ' * 1100, op='level_receipt')
        with self.assertRaises(wire.WireError) as caught:
            wire.encode_response('level_receipt', {**body, 'padding': 'x' * 1100})
        self.assertEqual(caught.exception.reason, 'too_large')

    def test_status_and_flag_must_agree_exactly(self):
        for status, flag in (('confirmed', False), ('unknown', True), ('confirmed', 1), ('unknown', 0), ('confirmed', 'true'),
                             ('confirmed', None), ('unknown', None)):
            self.assertInvalid(wire.validate_level_receipt, {**LEVEL_CONFIRMED, 'status': status, 'cleanup_confirmed': flag},
                               identity=LEVEL_RECEIPT)
        for status in ('Confirmed', 'CONFIRMED', 'done', 'finished', '', None, 1, True, ['confirmed'], {'a': 1}):
            self.assertInvalid(wire.validate_level_receipt, {**LEVEL_CONFIRMED, 'status': status}, identity=LEVEL_RECEIPT)
            self.assertInvalid(wire.validate_level_receipt, {**LEVEL_UNKNOWN, 'status': status}, identity=LEVEL_RECEIPT)

    def test_shape_and_types_are_exact(self):
        bad = [{**LEVEL_CONFIRMED, 'extra': 1}, {**LEVEL_CONFIRMED, 'oom_killed': False}, {**LEVEL_CONFIRMED, 'handle': HANDLE},
               {**LEVEL_CONFIRMED, 'variant': 'legitimate'},
               {key: value for key, value in LEVEL_CONFIRMED.items() if key != 'status'},
               {key: value for key, value in LEVEL_CONFIRMED.items() if key != 'context_sha256'},
               {key: value for key, value in LEVEL_CONFIRMED.items() if key != 'stage'},
               {**LEVEL_CONFIRMED, 'ok': 1}, {**LEVEL_CONFIRMED, 'ok': False}, {**LEVEL_CONFIRMED, 'op': 'receipt'},
               {**LEVEL_CONFIRMED, 'op': 'close'}, {**LEVEL_CONFIRMED, 'level': 'persistence'}, {**LEVEL_CONFIRMED, 'level': None},
               {**LEVEL_CONFIRMED, 'stage': 'fresh'}, {**LEVEL_CONFIRMED, 'context_sha256': 'A' * 64},
               {**LEVEL_CONFIRMED, 'context_sha256': CONTEXT + '\n'}, {**LEVEL_CONFIRMED, 'container_id': 5}]
        for body in bad:
            self.assertInvalid(wire.validate_level_receipt, body, identity=LEVEL_RECEIPT)
        for body in (None, [], 'text', 5):
            self.assertInvalid(wire.validate_level_receipt, body, identity=LEVEL_RECEIPT)

    def test_another_identity_or_context_in_the_answer_is_never_accepted(self):
        for key, value in LEVEL_OTHER.items():
            self.assertInvalid(wire.validate_level_receipt, {**LEVEL_CONFIRMED, key: value}, identity=LEVEL_RECEIPT)
            self.assertInvalid(wire.validate_level_receipt, {**LEVEL_UNKNOWN, key: value}, identity=LEVEL_RECEIPT)
            self.assertInvalid(wire.validate_level_receipt, LEVEL_CONFIRMED, identity={**LEVEL_RECEIPT, key: value})
        # the context alone, with everything else equal and well formed, is enough to refuse
        crossed = {**LEVEL_RECEIPT, 'context_sha256': OTHER_CONTEXT}
        self.assertInvalid(wire.validate_level_receipt, LEVEL_CONFIRMED, identity=crossed)
        self.assertInvalid(wire.validate_level_receipt, {**LEVEL_CONFIRMED, 'context_sha256': OTHER_CONTEXT}, identity=LEVEL_RECEIPT)
        self.assertEqual(wire.validate_level_receipt({**LEVEL_CONFIRMED, 'context_sha256': OTHER_CONTEXT},
                                                     identity=crossed)['context_sha256'], OTHER_CONTEXT)

    def test_identity_argument_must_be_the_exact_seven_fields(self):
        for identity in (None, {}, {'installation_id': INSTALL}, {**LEVEL_RECEIPT, 'extra': 1}, list(LEVEL_RECEIPT), 'x',
                         {key: value for key, value in LEVEL_RECEIPT.items() if key != 'context_sha256'}, RECEIPT):
            self.assertInvalid(wire.validate_level_receipt, LEVEL_CONFIRMED, identity=identity)

    def test_the_two_receipt_shapes_are_never_mixed(self):
        self.assertInvalid(wire.validate_level_receipt, CONFIRMED, identity=LEVEL_RECEIPT)
        self.assertInvalid(wire.validate_level_receipt, CONFIRMED, identity=RECEIPT)
        self.assertInvalid(wire.validate_receipt, LEVEL_CONFIRMED, identity=LEVEL_RECEIPT)
        self.assertInvalid(wire.validate_receipt, LEVEL_CONFIRMED, identity=RECEIPT)
        for body in (HEALTH, LEVEL_CLOSE, LEVEL_OPEN, RESULT, LEVEL_PROBE):
            self.assertInvalid(wire.validate_level_receipt, body, identity=LEVEL_RECEIPT)
        self.assertInvalid(wire.validate_level_close, LEVEL_CONFIRMED, receipt=LEVEL_RECEIPT)
        self.assertEqual(wire.validate_receipt(CONFIRMED, identity=RECEIPT)['status'], 'confirmed')  # M1 keeps its own

    def test_strict_json_applies_to_level_receipt_answers(self):
        duplicate = b'{"ok":true,"op":"level_receipt","status":"unknown","status":"confirmed","cleanup_confirmed":false}'
        self.assertInvalid(wire.decode_response, duplicate, op='level_receipt')
        self.assertInvalid(wire.decode_response, raw(LEVEL_CONFIRMED).replace(b'true', b'NaN'), op='level_receipt')


class LevelProbeResponseTests(Invalid):
    def test_available_and_unavailable_are_the_only_well_formed_answers(self):
        self.assertEqual(wire.validate_level_probe(LEVEL_PROBE), {'status': 'available', 'counters': COUNTERS})
        self.assertEqual(wire.validate_level_probe(LEVEL_PROBE_UNAVAILABLE), {'status': 'unavailable', 'counters': None})
        smallest = ok('level_probe', status='available', counters={'oom_kill': 0})
        self.assertEqual(wire.validate_level_probe(smallest)['counters'], {'oom_kill': 0})
        largest = ok('level_probe', status='available', counters={'oom_kill': 2 ** 64 - 1, 'a' * 32: 5, '_': 0})
        self.assertEqual(wire.validate_level_probe(largest)['counters']['oom_kill'], 2 ** 64 - 1)

    def test_the_answer_is_a_copy(self):
        result = wire.validate_level_probe(LEVEL_PROBE)
        result['counters']['oom_kill'] = 999
        self.assertEqual(LEVEL_PROBE['counters']['oom_kill'], 2)

    def test_counters_must_be_exact_integers_with_oom_kill(self):
        for counters in ({'oom_kill': True}, {'oom_kill': False}, {'oom_kill': -1}, {'oom_kill': 1.0}, {'oom_kill': '1'},
                         {'oom_kill': None}, {'oom_kill': 2 ** 64}, {'oom_kill': [1]}, {'oom': 1}, {'low': 0, 'high': 0},
                         {'oom_kill': 0, 'max': True}, {'oom_kill': 0, 'max': -5}, {'oom_kill': 0, 'OOM': 1},
                         {'oom_kill': 0, 'oom kill': 1}, {'oom_kill': 0, '': 1}, {'oom_kill': 0, 'x' * 33: 1},
                         {'oom_kill': 0, 'oom1': 1}, {}, [], 'oom_kill 0', 5, None):
            self.assertInvalid(wire.validate_level_probe, ok('level_probe', status='available', counters=counters))

    def test_the_number_of_counters_is_bounded(self):
        fits = {counter_key(index): index for index in range(31)}
        fits['oom_kill'] = 0
        self.assertEqual(len(wire.validate_level_probe(ok('level_probe', status='available', counters=fits))['counters']), 32)
        self.assertInvalid(wire.validate_level_probe, ok('level_probe', status='available', counters={**fits, 'zz': 1}))

    def test_unavailable_carries_no_counters_and_is_never_a_zero(self):
        for counters in ({}, {'oom_kill': 0}, [], 0, False, 'none'):
            self.assertInvalid(wire.validate_level_probe, ok('level_probe', status='unavailable', counters=counters))
        self.assertInvalid(wire.validate_level_probe, ok('level_probe', status='available', counters=None))

    def test_shape_status_and_envelope_are_exact(self):
        bad = [{**LEVEL_PROBE, 'extra': 1}, {**LEVEL_PROBE, 'intent_id': INTENT}, {**LEVEL_PROBE, 'container_id': CONTAINER},
               {**LEVEL_PROBE, 'path': '/sys/fs/cgroup/memory.events'}, {**LEVEL_PROBE, 'stdout': 'x'},
               {key: value for key, value in LEVEL_PROBE.items() if key != 'status'},
               {key: value for key, value in LEVEL_PROBE.items() if key != 'counters'},
               {**LEVEL_PROBE, 'status': 'Available'}, {**LEVEL_PROBE, 'status': 'ok'}, {**LEVEL_PROBE, 'status': None},
               {**LEVEL_PROBE, 'status': True}, {**LEVEL_PROBE, 'status': ['available']},
               {**LEVEL_PROBE, 'ok': 1}, {**LEVEL_PROBE, 'ok': False}, {**LEVEL_PROBE, 'op': 'probe'},
               {**LEVEL_PROBE, 'op': 'level_receipt'}]
        for body in bad:
            self.assertInvalid(wire.validate_level_probe, body)
        for body in (None, [], 'text', 5):
            self.assertInvalid(wire.validate_level_probe, body)

    def test_no_other_answer_is_a_level_probe_and_it_is_not_one_of_theirs(self):
        for body in (ok('probe', **MEAS), HEALTH, RESULT, LEVEL_CONFIRMED, LEVEL_CLOSE, CLOSE):
            self.assertInvalid(wire.validate_level_probe, body)
        for call in (lambda: wire.validate_measure(LEVEL_PROBE),
                     lambda: wire.validate_result(LEVEL_PROBE, op='probe', name='measure'),
                     lambda: wire.validate_result(LEVEL_PROBE, op='probe', name='task_result'),
                     lambda: wire.validate_level_receipt(LEVEL_PROBE, identity=LEVEL_RECEIPT)):
            self.assertInvalid(call)

    def test_encoder_roundtrip_and_limits(self):
        encoded = wire.encode_response('level_probe', {'status': 'available', 'counters': COUNTERS})
        decoded = wire.decode_response(encoded, op='level_probe')
        self.assertEqual(decoded, LEVEL_PROBE)
        self.assertEqual(wire.validate_level_probe(decoded)['counters'], COUNTERS)
        self.assertInvalid(wire.decode_response, encoded, op='probe')
        unavailable = wire.encode_response('level_probe', {'status': 'unavailable', 'counters': None})
        self.assertEqual(wire.validate_level_probe(wire.decode_response(unavailable, op='level_probe'))['counters'], None)
        biggest = {counter_key(index): 2 ** 64 - 1 for index in range(31)}
        biggest['oom_kill'] = 2 ** 64 - 1
        encoded = wire.encode_response('level_probe', {'status': 'available', 'counters': biggest})
        self.assertLess(len(encoded), wire.RESPONSE_LIMITS['level_probe'])
        self.assertEqual(wire.validate_level_probe(wire.decode_response(encoded, op='level_probe'))['counters'], biggest)
        with self.assertRaises(wire.WireError) as caught:
            wire.encode_response('level_probe', {'status': 'unavailable', 'counters': None, 'padding': 'x' * 5000})
        self.assertEqual(caught.exception.reason, 'too_large')
        self.assertInvalid(wire.decode_response, raw(LEVEL_PROBE) + b' ' * 5000, op='level_probe')


class LevelRefusalTests(Invalid):
    def test_new_refusals_decode_as_remote_errors_for_every_level_operation(self):
        for op in LEVEL_OPS:
            for reason in ('level_not_allowed', 'context_mismatch', 'wrong_domain', 'installation_mismatch', 'foreign_owner'):
                with self.assertRaises(wire.RemoteError) as caught:
                    wire.decode_response(wire.error_response(reason), op=op)
                self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), (reason, None))
        with self.assertRaises(wire.RemoteError) as caught:
            wire.decode_response(wire.error_response('context_mismatch', cleanup_confirmed=True), op='open_level')
        self.assertIs(caught.exception.cleanup_confirmed, True)

    def test_the_vocabulary_stays_closed(self):
        with self.assertRaises(ValueError):
            wire.error_response('level_allowed')
        self.assertInvalid(wire.decode_response, raw({'ok': False, 'reason': 'level_allowed'}), op='open_level')
        for op in LEVEL_OPS:
            self.assertInvalid(wire.decode_response, raw({'ok': True, 'op': 'health'}), op=op)
        with self.assertRaises(ValueError):
            wire.encode_response('level_close', {})


# ------------------------------------------------------------------------------------------------------- M2.3 · persistence
# Authored without a shell: none of these tests has been executed by the author.

B_INTENT = '4' * 32
B_CONTAINER = 'e' * 64
A_IDENT = {'installation_id': INSTALL, 'run_id': RUN, 'level': 'persistence', 'stage': 'actor', 'context_sha256': CONTEXT,
           'intent_id': INTENT, 'container_id': CONTAINER}
B_IDENT = {**A_IDENT, 'stage': 'fresh', 'intent_id': B_INTENT, 'container_id': B_CONTAINER}
PIN = dict(A_IDENT)  # the caller's independent pin of the phase A: the identity A itself
PIN_OTHER = {'installation_id': '9' * 32, 'run_id': '9' * 32, 'context_sha256': OTHER_CONTEXT, 'intent_id': '9' * 32,
             'container_id': '9' * 64}
A_ARGS = dict(run_id=RUN, level='persistence', stage='actor', context_sha256=CONTEXT, installation_id=INSTALL, image_id=IMAGE)
B_ARGS = {**A_ARGS, 'stage': 'fresh'}
A_OPEN = ok('open_level', handle=HANDLE, **A_IDENT, name='escape-actor-' + INTENT, profile_sha256=DIGEST, profile=PROFILE)
B_OPEN = ok('open_level', handle=HANDLE, **B_IDENT, name='escape-actor-' + B_INTENT, profile_sha256=DIGEST, profile=PROFILE,
            predecessor=dict(PIN))
A_CLOSE = ok('close', **A_IDENT, cleanup_confirmed=True, oom_killed=False, **MEAS)
B_CLOSE = ok('close', **B_IDENT, predecessor=dict(PIN), cleanup_confirmed=True, oom_killed=False, **MEAS)
A_CONFIRMED = ok('level_receipt', **A_IDENT, status='confirmed', cleanup_confirmed=True)
B_CONFIRMED = ok('level_receipt', **B_IDENT, predecessor=dict(PIN), status='confirmed', cleanup_confirmed=True)
B_UNKNOWN = ok('level_receipt', **B_IDENT, predecessor=None, status='unknown', cleanup_confirmed=False)
MALFORMED_PREDECESSORS = (None, {}, 'x', 5, [], list(PIN), {**PIN, 'extra': 1}, {**PIN, 'variant': 'legitimate'},
                          {key: value for key, value in PIN.items() if key != 'run_id'},
                          {key: value for key, value in PIN.items() if key != 'context_sha256'},
                          {**PIN, 'level': 'memory'}, {**PIN, 'stage': 'fresh'}, {**PIN, 'installation_id': 'X' * 32},
                          {**PIN, 'container_id': 'c' * 63}, {**PIN, 'intent_id': None}, {**PIN, 'context_sha256': 5})


class PersistenceConstantsTests(unittest.TestCase):
    def test_the_new_refusal_reason_is_closed_and_the_limits_did_not_grow(self):
        self.assertIn('predecessor_unconfirmed', wire.RUNTIME_REASONS)
        self.assertFalse(wire.RUNTIME_REASONS & proto.REASONS)
        self.assertTrue({'invalid_path', 'invalid_digest', 'invalid_size', 'invalid_exclude'} <= proto.DECODE_REASONS)
        self.assertEqual({key: wire.RESPONSE_LIMITS[key] for key in LEVEL_OPS},
                         {'open_level': 8192, 'level_receipt': 1024, 'level_probe': 4096})  # unchanged since M2.1
        self.assertEqual({key: wire.CLIENT_DEADLINES[key] for key in LEVEL_OPS},
                         {'open_level': 110.0, 'level_receipt': 8.0, 'level_probe': 30.0})
        self.assertEqual(wire.LEVEL_IDENTITY_FIELDS, ('installation_id', 'run_id', 'level', 'stage', 'context_sha256', 'intent_id',
                                                      'container_id'))  # the identity of a fresh phase has no predecessor in it

    def test_the_new_refusals_decode_as_remote_errors_for_open_and_probe(self):
        for op, reason in (('open_level', 'predecessor_unconfirmed'), ('open_level', 'invalid_stage'),
                           ('level_probe', 'invalid_exclude'), ('level_probe', 'wrong_domain'), ('level_probe', 'invalid_path')):
            with self.assertRaises(wire.RemoteError) as caught:
                wire.decode_response(wire.error_response(reason), op=op)
            self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), (reason, None))
        with self.assertRaises(ValueError):
            wire.error_response('predecessor_confirmed')

    def test_level_requests_of_persistence_decode_like_the_protocol_and_carry_no_predecessor(self):
        for stage in ('actor', 'fresh'):
            for op, fields in LEVEL_VALID.items():
                if op == 'level_probe':
                    continue
                body = {**fields, 'level': 'persistence', 'stage': stage}
                encoded = raw(body)
                self.assertEqual(wire.decode_request(encoded), proto.decode_request(encoded))
                with self.assertRaises(proto.ProtocolError) as caught:
                    wire.encode_request(op, **{key: value for key, value in body.items() if key != 'op'},
                                        predecessor=dict(PIN))
                self.assertIn(caught.exception.reason, {'unexpected_field', 'forbidden_field'})
        with self.assertRaises(proto.ProtocolError) as caught:  # memory/fresh does not exist, even to be encoded
            wire.encode_request('open_level', run_id=RUN, level='memory', stage='fresh', context_sha256=CONTEXT)
        self.assertEqual(caught.exception.reason, 'invalid_stage')


class PredecessorIdentityTests(Invalid):
    def test_a_faithful_identity_is_returned_as_a_copy(self):
        result = wire.predecessor_identity(PIN, run_id=RUN, context_sha256=CONTEXT, installation_id=INSTALL, successor=B_IDENT)
        self.assertEqual(result, PIN)
        self.assertIsNot(result, PIN)
        result['container_id'] = 'f' * 64
        self.assertEqual(PIN['container_id'], CONTAINER)

    def test_the_seven_fields_are_exact_and_well_formed(self):
        for bad in MALFORMED_PREDECESSORS:
            self.assertInvalid(wire.predecessor_identity, bad)

    def test_only_a_persistence_actor_phase_can_be_a_predecessor(self):
        for patch in ({'level': 'memory'}, {'level': 'secret'}, {'stage': 'fresh'}, {'level': 'memory', 'stage': 'fresh'},
                      {'level': 'x'}, {'stage': None}):
            self.assertInvalid(wire.predecessor_identity, {**PIN, **patch})

    def test_it_is_bound_to_the_phase_that_follows_it(self):
        for kwargs in ({'run_id': '9' * 32}, {'context_sha256': OTHER_CONTEXT}, {'installation_id': '9' * 32}):
            self.assertInvalid(wire.predecessor_identity, PIN, **kwargs)
        for successor in ({'intent_id': INTENT, 'container_id': B_CONTAINER},      # the same intent
                          {'intent_id': B_INTENT, 'container_id': CONTAINER},      # the same container
                          {'intent_id': INTENT, 'container_id': CONTAINER}, 'x', [], 5):
            self.assertInvalid(wire.predecessor_identity, PIN, successor=successor)
        self.assertEqual(wire.predecessor_identity(PIN, successor={'intent_id': B_INTENT, 'container_id': None}), PIN)
        self.assertEqual(wire.predecessor_identity(PIN, successor=B_IDENT), PIN)
        self.assertEqual(wire.predecessor_identity(PIN), PIN)


class FreshOpenAnswerTests(Invalid):
    def test_a_fresh_answer_is_valid_only_against_the_pin_and_comes_back_as_copies(self):
        answer = wire.validate_level_open(B_OPEN, predecessor=PIN, **B_ARGS)
        self.assertEqual(answer['predecessor'], PIN)
        self.assertEqual({key: value for key, value in answer.items() if key != 'predecessor'},
                         {key: value for key, value in B_OPEN.items() if key != 'predecessor'})
        answer['predecessor']['run_id'] = '9' * 32
        self.assertEqual(B_OPEN['predecessor']['run_id'], RUN)
        self.assertEqual(PIN['run_id'], RUN)

    def test_the_pin_is_required_and_a_mutated_pin_or_owner_is_refused_field_by_field(self):
        self.assertInvalid(wire.validate_level_open, B_OPEN, **B_ARGS)  # a fresh answer without the caller's pin is never valid
        for key, value in PIN_OTHER.items():
            self.assertInvalid(wire.validate_level_open, B_OPEN, predecessor={**PIN, key: value}, **B_ARGS)  # the pin was mutated
            self.assertInvalid(wire.validate_level_open, {**B_OPEN, 'predecessor': {**PIN, key: value}}, predecessor=PIN,
                               **B_ARGS)  # the owner named another predecessor
        self.assertInvalid(wire.validate_level_open, {**B_OPEN, 'predecessor': {**PIN, **PIN_OTHER}}, predecessor=PIN, **B_ARGS)

    def test_the_answered_predecessor_must_be_present_exact_and_well_formed(self):
        for bad in MALFORMED_PREDECESSORS:
            self.assertInvalid(wire.validate_level_open, {**B_OPEN, 'predecessor': bad}, predecessor=PIN, **B_ARGS)
        self.assertInvalid(wire.validate_level_open, {key: value for key, value in B_OPEN.items() if key != 'predecessor'},
                           predecessor=PIN, **B_ARGS)

    def test_a_phase_is_never_its_own_predecessor(self):
        same_container = {**B_OPEN, 'container_id': CONTAINER}
        same_intent = {**B_OPEN, 'intent_id': INTENT, 'name': 'escape-actor-' + INTENT}
        for answer in (same_container, same_intent, {**same_container, **same_intent}):
            self.assertInvalid(wire.validate_level_open, answer, predecessor=PIN, **B_ARGS)

    def test_the_pin_itself_must_be_a_faithful_actor_identity_of_the_same_run_context_and_installation(self):
        for bad in MALFORMED_PREDECESSORS:
            self.assertInvalid(wire.validate_level_open, B_OPEN, predecessor=bad, **B_ARGS)
        for patch in ({'run_id': '9' * 32}, {'context_sha256': OTHER_CONTEXT}, {'installation_id': '9' * 32}):
            self.assertInvalid(wire.validate_level_open, B_OPEN, predecessor={**PIN, **patch}, **B_ARGS)

    def test_the_actor_answer_is_unchanged_and_takes_no_pin(self):
        self.assertEqual(wire.validate_level_open(A_OPEN, **A_ARGS), A_OPEN)
        self.assertInvalid(wire.validate_level_open, A_OPEN, predecessor=PIN, **A_ARGS)
        for extra in (dict(PIN), None, 'x'):
            self.assertInvalid(wire.validate_level_open, {**A_OPEN, 'predecessor': extra}, **A_ARGS)
            self.assertInvalid(wire.validate_level_open, {**A_OPEN, 'predecessor': extra}, predecessor=PIN, **A_ARGS)

    def test_the_two_persistence_shapes_and_the_other_levels_are_never_mixed(self):
        self.assertInvalid(wire.validate_level_open, B_OPEN, **A_ARGS)
        self.assertInvalid(wire.validate_level_open, A_OPEN, predecessor=PIN, **B_ARGS)
        self.assertInvalid(wire.validate_level_open, B_OPEN, predecessor=PIN, **{**B_ARGS, 'level': 'memory'})  # no memory/fresh
        self.assertInvalid(wire.validate_level_open, B_OPEN, predecessor=PIN, **{**B_ARGS, 'level': 'secret'})
        self.assertInvalid(wire.validate_level_open, LEVEL_OPEN, **{**LEVEL_ARGS, 'stage': 'fresh'})
        self.assertInvalid(wire.validate_level_open, {**LEVEL_OPEN, 'stage': 'fresh'}, predecessor=PIN, **{**LEVEL_ARGS, 'stage': 'fresh'})
        self.assertEqual(wire.validate_level_open(LEVEL_OPEN, **LEVEL_ARGS), LEVEL_OPEN)  # memory keeps its own shape

    def test_run_context_installation_image_and_the_rest_of_the_binding_still_apply(self):
        for key, bad in (('run_id', '9' * 32), ('context_sha256', OTHER_CONTEXT), ('installation_id', '9' * 32),
                         ('image_id', 'sha256:' + 'e' * 64), ('level', 'secret'), ('stage', 'actor')):
            self.assertInvalid(wire.validate_level_open, B_OPEN, predecessor=PIN, **{**B_ARGS, key: bad})
        for bad in ({**B_OPEN, 'name': 'escape-actor-' + '9' * 32}, {**B_OPEN, 'profile': {'available': False}},
                    {**B_OPEN, 'extra': 1}, {**B_OPEN, 'variant': 'legitimate'}, {**B_OPEN, 'handle': 'AB' * 32}):
            self.assertInvalid(wire.validate_level_open, bad, predecessor=PIN, **B_ARGS)

    def test_encoder_roundtrip_within_the_unchanged_limit(self):
        body = {key: value for key, value in B_OPEN.items() if key not in ('ok', 'op')}
        encoded = wire.encode_response('open_level', body)
        self.assertLess(len(encoded), wire.RESPONSE_LIMITS['open_level'])
        decoded = wire.decode_response(encoded, op='open_level')
        self.assertEqual(wire.validate_level_open(decoded, predecessor=PIN, **B_ARGS)['predecessor'], PIN)


class FreshCloseAnswerTests(Invalid):
    def test_a_fresh_close_confirms_only_with_its_identity_and_the_pinned_predecessor(self):
        result = wire.validate_level_close(B_CLOSE, receipt=B_IDENT, predecessor=PIN)
        self.assertEqual((result['oom_killed'], result['predecessor'], result['memory_peak_bytes']), (False, PIN, 1024))
        result['predecessor']['run_id'] = '9' * 32
        self.assertEqual(B_CLOSE['predecessor']['run_id'], RUN)

    def test_the_pin_is_required_and_mutations_are_refused(self):
        self.assertInvalid(wire.validate_level_close, B_CLOSE, receipt=B_IDENT)
        for key, value in PIN_OTHER.items():
            self.assertInvalid(wire.validate_level_close, B_CLOSE, receipt=B_IDENT, predecessor={**PIN, key: value})
            self.assertInvalid(wire.validate_level_close, {**B_CLOSE, 'predecessor': {**PIN, key: value}}, receipt=B_IDENT,
                               predecessor=PIN)
        for bad in MALFORMED_PREDECESSORS:
            self.assertInvalid(wire.validate_level_close, {**B_CLOSE, 'predecessor': bad}, receipt=B_IDENT, predecessor=PIN)
            self.assertInvalid(wire.validate_level_close, B_CLOSE, receipt=B_IDENT, predecessor=bad)
        self.assertInvalid(wire.validate_level_close, {key: value for key, value in B_CLOSE.items() if key != 'predecessor'},
                           receipt=B_IDENT, predecessor=PIN)

    def test_another_identity_or_a_phase_that_is_its_own_predecessor_never_confirms(self):
        for key, value in PIN_OTHER.items():
            if key == 'installation_id':
                continue
            self.assertInvalid(wire.validate_level_close, {**B_CLOSE, key: value}, receipt=B_IDENT, predecessor=PIN)
        self.assertInvalid(wire.validate_level_close, {**B_CLOSE, 'container_id': CONTAINER},
                           receipt={**B_IDENT, 'container_id': CONTAINER}, predecessor=PIN)
        self.assertInvalid(wire.validate_level_close, {**B_CLOSE, 'cleanup_confirmed': False}, receipt=B_IDENT, predecessor=PIN)
        self.assertInvalid(wire.validate_level_close, {**B_CLOSE, 'oom_killed': 0}, receipt=B_IDENT, predecessor=PIN)

    def test_the_actor_close_is_unchanged_and_the_shapes_are_never_mixed(self):
        self.assertNotIn('predecessor', wire.validate_level_close(A_CLOSE, receipt=A_IDENT))
        self.assertInvalid(wire.validate_level_close, A_CLOSE, receipt=A_IDENT, predecessor=PIN)
        self.assertInvalid(wire.validate_level_close, {**A_CLOSE, 'predecessor': dict(PIN)}, receipt=A_IDENT)
        self.assertInvalid(wire.validate_level_close, A_CLOSE, receipt=B_IDENT, predecessor=PIN)
        self.assertInvalid(wire.validate_level_close, B_CLOSE, receipt=A_IDENT)
        self.assertInvalid(wire.validate_level_close, B_CLOSE, receipt=A_IDENT, predecessor=PIN)
        self.assertInvalid(wire.validate_level_close, CLOSE, receipt=B_IDENT, predecessor=PIN)  # the M1 shape
        self.assertInvalid(wire.validate_level_close, LEVEL_CLOSE, receipt=B_IDENT, predecessor=PIN)
        self.assertInvalid(wire.validate_level_close, B_CLOSE, receipt=RECEIPT, predecessor=PIN)
        self.assertEqual(wire.validate_level_close(LEVEL_CLOSE, receipt=LEVEL_RECEIPT)['oom_killed'], False)  # memory unchanged

    def test_encoder_roundtrip_within_the_unchanged_limit(self):
        body = {key: value for key, value in B_CLOSE.items() if key not in ('ok', 'op')}
        encoded = wire.encode_response('close', body)
        self.assertLess(len(encoded), wire.RESPONSE_LIMITS['close'])
        decoded = wire.decode_response(encoded, op='close')
        self.assertEqual(wire.validate_level_close(decoded, receipt=B_IDENT, predecessor=PIN)['predecessor'], PIN)


class FreshReceiptAnswerTests(Invalid):
    def test_confirmed_needs_the_pinned_predecessor_of_the_owner(self):
        self.assertEqual(wire.validate_level_receipt(B_CONFIRMED, identity=B_IDENT, predecessor=PIN), B_CONFIRMED)
        self.assertInvalid(wire.validate_level_receipt, B_CONFIRMED, identity=B_IDENT)  # no pin: nothing confirms
        for key, value in PIN_OTHER.items():
            self.assertInvalid(wire.validate_level_receipt, B_CONFIRMED, identity=B_IDENT, predecessor={**PIN, key: value})
            self.assertInvalid(wire.validate_level_receipt, {**B_CONFIRMED, 'predecessor': {**PIN, key: value}}, identity=B_IDENT,
                               predecessor=PIN)
        for bad in MALFORMED_PREDECESSORS:  # including null: a confirmation without a predecessor is never valid
            self.assertInvalid(wire.validate_level_receipt, {**B_CONFIRMED, 'predecessor': bad}, identity=B_IDENT, predecessor=PIN)
            self.assertInvalid(wire.validate_level_receipt, B_CONFIRMED, identity=B_IDENT, predecessor=bad)
        self.assertInvalid(wire.validate_level_receipt, {key: value for key, value in B_CONFIRMED.items() if key != 'predecessor'},
                           identity=B_IDENT, predecessor=PIN)

    def test_unknown_names_nothing_and_confirms_nothing(self):
        self.assertEqual(wire.validate_level_receipt(B_UNKNOWN, identity=B_IDENT, predecessor=PIN), B_UNKNOWN)
        for named in (dict(PIN), {**PIN, 'container_id': 'f' * 64}, {}, 'x'):  # unknown with ANY predecessor is not the owner's shape
            self.assertInvalid(wire.validate_level_receipt, {**B_UNKNOWN, 'predecessor': named}, identity=B_IDENT, predecessor=PIN)
        self.assertInvalid(wire.validate_level_receipt, B_UNKNOWN, identity=B_IDENT)  # the pin is required here too
        self.assertInvalid(wire.validate_level_receipt, B_UNKNOWN, identity=B_IDENT, predecessor={**PIN, 'run_id': '9' * 32})
        self.assertInvalid(wire.validate_level_receipt, {key: value for key, value in B_UNKNOWN.items() if key != 'predecessor'},
                           identity=B_IDENT, predecessor=PIN)

    def test_status_and_flag_must_agree_exactly(self):
        for status, flag in (('confirmed', False), ('unknown', True), ('confirmed', 1), ('unknown', 0), ('confirmed', None)):
            self.assertInvalid(wire.validate_level_receipt, {**B_CONFIRMED, 'status': status, 'cleanup_confirmed': flag},
                               identity=B_IDENT, predecessor=PIN)
        for status in ('Confirmed', 'done', '', None, 1, True, ['confirmed']):
            self.assertInvalid(wire.validate_level_receipt, {**B_CONFIRMED, 'status': status}, identity=B_IDENT, predecessor=PIN)
            self.assertInvalid(wire.validate_level_receipt, {**B_UNKNOWN, 'status': status}, identity=B_IDENT, predecessor=PIN)

    def test_another_identity_or_context_in_a_fresh_answer_is_never_accepted(self):
        for key, value in PIN_OTHER.items():
            self.assertInvalid(wire.validate_level_receipt, {**B_CONFIRMED, key: value}, identity=B_IDENT, predecessor=PIN)
            self.assertInvalid(wire.validate_level_receipt, {**B_UNKNOWN, key: value}, identity=B_IDENT, predecessor=PIN)
            self.assertInvalid(wire.validate_level_receipt, B_CONFIRMED, identity={**B_IDENT, key: value}, predecessor=PIN)
        # the receipt of A is never the receipt of B, and a confirmation of B is not one of A
        self.assertInvalid(wire.validate_level_receipt, A_CONFIRMED, identity=B_IDENT, predecessor=PIN)
        self.assertInvalid(wire.validate_level_receipt, B_CONFIRMED, identity=A_IDENT)
        self.assertInvalid(wire.validate_level_receipt, B_CONFIRMED, identity=A_IDENT, predecessor=PIN)
        self.assertInvalid(wire.validate_level_receipt, {**B_CONFIRMED, **{k: A_IDENT[k] for k in ('stage', 'intent_id', 'container_id')}},
                           identity=B_IDENT, predecessor=PIN)

    def test_the_actor_receipt_is_unchanged_and_takes_no_pin(self):
        self.assertEqual(wire.validate_level_receipt(A_CONFIRMED, identity=A_IDENT), A_CONFIRMED)
        self.assertInvalid(wire.validate_level_receipt, A_CONFIRMED, identity=A_IDENT, predecessor=PIN)
        self.assertInvalid(wire.validate_level_receipt, {**A_CONFIRMED, 'predecessor': dict(PIN)}, identity=A_IDENT)
        self.assertInvalid(wire.validate_level_receipt, {**A_CONFIRMED, 'predecessor': None}, identity=A_IDENT)
        self.assertEqual(wire.validate_level_receipt(LEVEL_CONFIRMED, identity=LEVEL_RECEIPT), LEVEL_CONFIRMED)  # memory unchanged
        self.assertInvalid(wire.validate_level_receipt, LEVEL_CONFIRMED, identity={**LEVEL_RECEIPT, 'stage': 'fresh'}, predecessor=PIN)

    def test_encoder_roundtrip_and_the_worst_case_fit_the_unchanged_limit(self):
        self.assertEqual(wire.RESPONSE_LIMITS['level_receipt'], 1024)
        for answer, pin in ((B_CONFIRMED, PIN), (B_UNKNOWN, PIN)):
            body = {key: value for key, value in answer.items() if key not in ('ok', 'op')}
            encoded = wire.encode_response('level_receipt', body)
            self.assertLess(len(encoded), wire.RESPONSE_LIMITS['level_receipt'])
            decoded = wire.decode_response(encoded, op='level_receipt')
            self.assertEqual(wire.validate_level_receipt(decoded, identity=B_IDENT, predecessor=pin), answer)
        self.assertLess(len(wire.encode_response('level_receipt', {key: value for key, value in B_CONFIRMED.items()
                                                                   if key not in ('ok', 'op')})), 900)  # margin under 1024

    def test_strict_json_applies_to_fresh_receipt_answers(self):
        duplicate = (b'{"ok":true,"op":"level_receipt","status":"unknown","status":"confirmed","cleanup_confirmed":false}')
        self.assertInvalid(wire.decode_response, duplicate, op='level_receipt')
        self.assertInvalid(wire.decode_response, raw(B_CONFIRMED).replace(b'true', b'NaN'), op='level_receipt')


FILE_PRESENT = ok('level_probe', status='present', inode=7, size=24, mtime=1700000000, ctime=1700000001, links=1, sha256='a' * 64)
FILE_MISSING = ok('level_probe', status='missing')
FILE_UNAVAILABLE = ok('level_probe', status='unavailable')
SCAN_BODY = dict(verifier_version='persistence-copy/v2', complete=True, reasons=[], matches=[], matches_total=0, entries=3,
                 bytes_read=96, skipped_nonregular=1)
SCAN_SIZE = 24
SCAN_EMPTY = ok('level_probe', **SCAN_BODY)
SCAN_COPY = ok('level_probe', **{**SCAN_BODY, 'matches': [{'path': '/tmp/copy-1', 'size': SCAN_SIZE, 'links': 1}], 'matches_total': 1})
SCAN_INCOMPLETE = ok('level_probe', **{**SCAN_BODY, 'complete': False, 'reasons': ['byte_limit', 'entry_limit']})
SCAN_CONTROLLER = ok('level_probe', verifier_version='persistence-copy/v2', complete=False, reasons=['probe_timeout'], matches=[],
                     matches_total=0, entries=0, bytes_read=0, skipped_nonregular=0)
FILE_EDGES = {'inode': (1, 2 ** 64 - 1), 'size': (0, 1048576), 'mtime': (0, 2 ** 63 - 1), 'ctime': (0, 2 ** 63 - 1),
              'links': (1, 1 << 20)}


def file_state(answer):
    return wire.validate_level_probe(answer, name='file_state')


def copy_scan(answer, size=SCAN_SIZE):
    return wire.validate_level_probe(answer, name='copy_scan', size=size)


class FileStateResponseTests(Invalid):
    def test_present_missing_and_unavailable_are_the_only_answers_and_carry_no_envelope(self):
        self.assertEqual(file_state(FILE_PRESENT), {key: value for key, value in FILE_PRESENT.items() if key not in ('ok', 'op')})
        self.assertEqual(file_state(FILE_MISSING), {'status': 'missing'})
        self.assertEqual(file_state(FILE_UNAVAILABLE), {'status': 'unavailable'})
        self.assertEqual(set(file_state(FILE_PRESENT)), {'status', 'inode', 'size', 'mtime', 'ctime', 'links', 'sha256'})

    def test_unavailable_is_never_missing(self):
        self.assertNotEqual(file_state(FILE_UNAVAILABLE), file_state(FILE_MISSING))
        for status in ('Missing', 'MISSING', 'absent', 'gone', 'ok', 'unknown', '', None, True, 0, ['missing'], {'s': 'missing'}):
            self.assertInvalid(file_state, ok('level_probe', status=status))

    def test_the_bounds_of_every_integer_are_inclusive_and_exact(self):
        for key, (low, high) in FILE_EDGES.items():
            for good in (low, high):
                self.assertEqual(file_state({**FILE_PRESENT, key: good})[key], good)
            for bad in (low - 1, high + 1, True, False, float(low), str(low), None, [low], {'v': low}):
                self.assertInvalid(file_state, {**FILE_PRESENT, key: bad})

    def test_the_digest_is_64_lowercase_hex(self):
        for bad in ('A' * 64, 'a' * 63, 'a' * 65, 'g' * 64, 'a' * 64 + '\n', '', None, 5, ['a' * 64]):
            self.assertInvalid(file_state, {**FILE_PRESENT, 'sha256': bad})

    def test_the_shape_is_exact_for_every_status(self):
        bad = [{**FILE_MISSING, 'inode': 1}, {**FILE_MISSING, 'sha256': 'a' * 64}, {**FILE_MISSING, 'counters': None},
               {**FILE_UNAVAILABLE, 'size': 0}, {**FILE_UNAVAILABLE, 'counters': None}, {**FILE_UNAVAILABLE, 'path': '/work/x'},
               {**FILE_PRESENT, 'extra': 1}, {**FILE_PRESENT, 'atime': 5}, {**FILE_PRESENT, 'path': '/work/marker-' + 'a' * 24},
               {**FILE_PRESENT, 'stdout': 'x'}, {key: value for key, value in FILE_PRESENT.items() if key != 'sha256'},
               {key: value for key, value in FILE_PRESENT.items() if key != 'links'},
               {key: value for key, value in FILE_PRESENT.items() if key != 'status'},
               {key: value for key, value in FILE_MISSING.items() if key != 'status'}]
        for body in bad:
            self.assertInvalid(file_state, body)
        for body in (None, [], 'missing', 5, True):
            self.assertInvalid(file_state, body)

    def test_the_envelope_is_exact(self):
        for patch in ({'ok': 1}, {'ok': False}, {'ok': 'true'}, {'op': 'probe'}, {'op': 'level_receipt'}, {'op': None}):
            self.assertInvalid(file_state, {**FILE_PRESENT, **patch})
            self.assertInvalid(file_state, {**FILE_MISSING, **patch})

    def test_the_shape_of_another_name_is_not_a_file_state_answer(self):
        for body in (LEVEL_PROBE, LEVEL_PROBE_UNAVAILABLE, SCAN_EMPTY, SCAN_CONTROLLER, ok('probe', **MEAS), HEALTH, RESULT,
                     LEVEL_CONFIRMED):
            self.assertInvalid(file_state, body)
        for body in (FILE_PRESENT, FILE_MISSING, FILE_UNAVAILABLE):  # and a file_state answer is not one of cgroup_events or copy_scan
            self.assertInvalid(wire.validate_level_probe, body)
            self.assertInvalid(wire.validate_level_probe, body, name='cgroup_events')
            self.assertInvalid(copy_scan, body)

    def test_encoder_roundtrip_within_the_unchanged_limit(self):
        for answer in (FILE_PRESENT, FILE_MISSING, FILE_UNAVAILABLE):
            body = {key: value for key, value in answer.items() if key not in ('ok', 'op')}
            encoded = wire.encode_response('level_probe', body)
            self.assertLess(len(encoded), wire.RESPONSE_LIMITS['level_probe'])
            self.assertEqual(file_state(wire.decode_response(encoded, op='level_probe')), body)
            self.assertInvalid(wire.decode_response, encoded, op='probe')


class CopyScanResponseTests(Invalid):
    def test_complete_incomplete_and_controller_scans_are_valid_answers_without_an_envelope(self):
        for answer in (SCAN_EMPTY, SCAN_COPY, SCAN_INCOMPLETE, SCAN_CONTROLLER):
            result = copy_scan(answer)
            self.assertEqual(set(result), set(wire.COPY_SCAN_KEYS))
            self.assertEqual({key: value for key, value in result.items() if key != 'reasons'},
                             {key: value for key, value in answer.items() if key not in ('ok', 'op', 'reasons')})
        self.assertEqual(copy_scan(SCAN_INCOMPLETE)['reasons'], ['byte_limit', 'entry_limit'])
        self.assertEqual(copy_scan(ok('level_probe', **{**SCAN_BODY, 'complete': False, 'reasons': ['timeout', 'changed']}))['reasons'],
                         ['changed', 'timeout'])  # normalized like runner.parse_copy_scan
        self.assertEqual(copy_scan(SCAN_COPY)['matches'], [{'path': '/tmp/copy-1', 'size': SCAN_SIZE, 'links': 1}])
        self.assertIs(copy_scan(SCAN_INCOMPLETE)['complete'], False)

    def test_an_incomplete_scan_is_never_an_empty_complete_one(self):
        for reasons in (['byte_limit'], ['timeout'], ['probe_failed'], ['malformed'], ['unavailable'], ['unsupported']):
            controller = reasons[0] in wire.COPY_SCAN_CONTROLLER_REASONS
            body = {**SCAN_BODY, 'complete': False, 'reasons': reasons}
            if controller:
                body.update(entries=0, bytes_read=0, skipped_nonregular=0)
            self.assertIs(copy_scan(ok('level_probe', **body))['complete'], False)
            self.assertInvalid(copy_scan, ok('level_probe', **{**body, 'complete': True}))  # complete only with no reasons
        self.assertInvalid(copy_scan, ok('level_probe', **{**SCAN_BODY, 'complete': False}))  # incomplete without a reason

    def test_the_vocabulary_is_closed_and_unique(self):
        for reasons in (['made_up'], ['byte_limit', 'byte_limit'], [5], [None], ['Byte_limit'], 'byte_limit', None, {'byte_limit': 1},
                        sorted(wire.COPY_SCAN_SCRIPT_REASONS | wire.COPY_SCAN_CONTROLLER_REASONS) + ['byte_limit']):
            self.assertInvalid(copy_scan, ok('level_probe', **{**SCAN_BODY, 'complete': False, 'reasons': reasons}))
        everything = sorted(wire.COPY_SCAN_SCRIPT_REASONS)
        self.assertEqual(copy_scan(ok('level_probe', **{**SCAN_BODY, 'complete': False, 'reasons': everything}))['reasons'], everything)

    def test_a_controller_reason_stands_alone(self):
        controller = {key: value for key, value in SCAN_CONTROLLER.items() if key not in ('ok', 'op')}
        self.assertEqual(copy_scan(SCAN_CONTROLLER)['reasons'], ['probe_timeout'])
        for body in ({'reasons': ['probe_timeout', 'byte_limit']}, {'reasons': ['probe_failed', 'malformed']},
                     {'matches': [{'path': '/tmp/x', 'size': SCAN_SIZE, 'links': 1}], 'matches_total': 1},
                     {'entries': 1}, {'bytes_read': 1}, {'skipped_nonregular': 1}, {'matches_total': 1}):
            self.assertInvalid(copy_scan, ok('level_probe', **{**controller, **body}))

    def test_counters_matches_and_totals_are_bounded_and_consistent(self):
        bounds = {'entries': 128, 'bytes_read': 1048576, 'skipped_nonregular': 128, 'matches_total': 128}
        for key, high in bounds.items():
            if key == 'matches_total':
                continue
            self.assertEqual(copy_scan(ok('level_probe', **{**SCAN_BODY, key: high}))[key], high)
            for bad in (-1, high + 1, True, False, 1.0, '1', None, [1]):
                self.assertInvalid(copy_scan, ok('level_probe', **{**SCAN_BODY, key: bad}))
        match = {'path': '/tmp/copy-1', 'size': SCAN_SIZE, 'links': 1}
        for bad in ({'matches_total': 129, 'matches': [match]}, {'matches_total': -1}, {'matches_total': True, 'matches': [match]},
                    {'matches_total': 0, 'matches': [match]},               # more matches than the total
                    {'matches_total': 3, 'matches': []},                    # a total with nothing to show
                    {'matches_total': 9, 'matches': [match] * 9},           # more than the eight that may be reported
                    {'matches': 'x', 'matches_total': 1}, {'matches': None}, {'matches': {'p': 1}}):
            self.assertInvalid(copy_scan, ok('level_probe', **{**SCAN_BODY, **bad}))
        self.assertEqual(len(copy_scan(ok('level_probe', **{**SCAN_BODY, 'matches': [match] * 8, 'matches_total': 8}))['matches']), 8)
        self.assertEqual(copy_scan(ok('level_probe', **{**SCAN_BODY, 'matches': [match], 'matches_total': 128}))['matches_total'], 128)

    def test_every_match_is_a_bounded_path_of_exactly_the_size_that_was_asked(self):
        good = {'path': '/tmp/copy-1', 'size': SCAN_SIZE, 'links': 1}
        for patch in ({'path': '/etc/passwd'}, {'path': '/work'}, {'path': '/tmp'}, {'path': '/tmp/../etc/x'}, {'path': '/tmp/./x'},
                      {'path': '/tmp/a b'}, {'path': '/tmp/a\n'}, {'path': '/tmp/' + 'a' * 156}, {'path': '/work/a/b/c/d/e'},
                      {'path': 5}, {'path': None}, {'size': SCAN_SIZE + 1}, {'size': True}, {'size': '24'}, {'size': None},
                      {'links': 0}, {'links': (1 << 20) + 1}, {'links': True}, {'links': None}, {'extra': 1}):
            self.assertInvalid(copy_scan, ok('level_probe', **{**SCAN_BODY, 'matches': [{**good, **patch}], 'matches_total': 1}))
        for missing in ('path', 'size', 'links'):
            self.assertInvalid(copy_scan, ok('level_probe', **{**SCAN_BODY, 'matches_total': 1,
                                                               'matches': [{k: v for k, v in good.items() if k != missing}]}))
        for item in (None, 'x', 5, [], [good]):
            self.assertInvalid(copy_scan, ok('level_probe', **{**SCAN_BODY, 'matches': [item], 'matches_total': 1}))
        self.assertEqual(len('/work/' + 'a' * 154), 160)
        self.assertEqual(copy_scan(ok('level_probe', **{**SCAN_BODY, 'matches_total': 1, 'matches': [{**good, 'path': '/work/' + 'a' * 154}]}))
                         ['matches'][0]['path'], '/work/' + 'a' * 154)

    def test_the_expected_size_is_a_bounded_integer_and_the_answer_must_match_it(self):
        self.assertInvalid(copy_scan, SCAN_COPY, size=SCAN_SIZE + 1)
        for bad in (None, 0, -1, True, 1.0, '24', 1048577, [24]):
            self.assertInvalid(copy_scan, SCAN_EMPTY, size=bad)
        self.assertEqual(copy_scan(SCAN_EMPTY, size=1)['matches'], [])
        self.assertEqual(copy_scan(SCAN_EMPTY, size=1048576)['matches'], [])
        self.assertInvalid(wire.validate_level_probe, SCAN_EMPTY, name='copy_scan')  # the size that was asked is not optional

    def test_the_shape_and_the_envelope_are_exact(self):
        for patch in ({'verifier_version': 'persistence-copy/v1'}, {'verifier_version': None}, {'complete': 1}, {'complete': None},
                      {'extra': 1}, {'path': '/tmp/x'}, {'status': 'available'}, {'counters': None}, {'ok': 1}, {'ok': False},
                      {'op': 'probe'}, {'op': 'level_receipt'}):
            self.assertInvalid(copy_scan, {**SCAN_EMPTY, **patch})
        for key in wire.COPY_SCAN_KEYS:
            self.assertInvalid(copy_scan, {k: v for k, v in SCAN_EMPTY.items() if k != key})
        for body in (None, [], 'x', 5, True):
            self.assertInvalid(copy_scan, body)

    def test_the_shape_of_another_name_is_not_a_scan(self):
        for body in (LEVEL_PROBE, LEVEL_PROBE_UNAVAILABLE, FILE_PRESENT, FILE_MISSING, FILE_UNAVAILABLE, ok('probe', **MEAS), HEALTH):
            self.assertInvalid(copy_scan, body)
        for body in (SCAN_EMPTY, SCAN_COPY, SCAN_INCOMPLETE, SCAN_CONTROLLER):  # and a scan is not a cgroup_events or file_state answer
            self.assertInvalid(wire.validate_level_probe, body)
            self.assertInvalid(file_state, body)

    def test_the_worst_case_scan_fits_the_unchanged_limit(self):
        path = '/work/' + 'a' * 154
        body = {**SCAN_BODY, 'complete': False, 'reasons': sorted(wire.COPY_SCAN_SCRIPT_REASONS), 'entries': 128,
                'bytes_read': 1048576, 'skipped_nonregular': 128, 'matches_total': 128,
                'matches': [{'path': path, 'size': 1048576, 'links': 1 << 20}] * 8}
        encoded = wire.encode_response('level_probe', body)
        self.assertLess(len(encoded), wire.RESPONSE_LIMITS['level_probe'])
        decoded = wire.decode_response(encoded, op='level_probe')
        self.assertEqual(copy_scan(decoded, size=1048576)['matches_total'], 128)
        self.assertInvalid(wire.decode_response, encoded, op='probe')

    def test_the_answer_is_a_copy(self):
        result = copy_scan(SCAN_COPY)
        result['matches'][0]['path'] = '/tmp/other'
        result['reasons'].append('x')
        self.assertEqual(SCAN_COPY['matches'][0]['path'], '/tmp/copy-1')
        self.assertEqual(SCAN_COPY['reasons'], [])


class ProbeNameTests(Invalid):
    def test_an_unknown_name_is_never_validated_and_cgroup_events_is_the_default(self):
        for name in ('x', None, 5, ['file_state'], 'File_state', 'measure', 'net_counters', 'task_result', ''):
            self.assertInvalid(wire.validate_level_probe, LEVEL_PROBE, name=name)
            self.assertInvalid(wire.validate_level_probe, FILE_MISSING, name=name)
        self.assertEqual(wire.validate_level_probe(LEVEL_PROBE), {'status': 'available', 'counters': COUNTERS})
        self.assertEqual(wire.validate_level_probe(LEVEL_PROBE, name='cgroup_events')['status'], 'available')


# ------------------------------------------------------------------------------------------------------- M3.1 · catalog
# Authored without a shell: none of these tests has been executed by the author. The operator runs them.
# The fixtures are written independently of the module, from M3-CONTRATO-AGENTE and SC2-CATALOGO-ADAPTADORES-LOCAL.

C_ID = 'invoice-unit-cents/v1'
C_SHA = 'd055653221c49c92490e536dc665349746988bb14749c60757e7a770fc20e79e'
CAT = {'installation_id': INSTALL, 'run_id': RUN, 'variant': 'legitimate', 'catalog_profile': 'B', 'context_sha256': CONTEXT,
       'catalog_id': C_ID, 'catalog_sha256': C_SHA, 'intent_id': INTENT, 'container_id': CONTAINER}
CAT_OTHER = {'installation_id': '9' * 32, 'run_id': '9' * 32, 'variant': 'perturbed', 'catalog_profile': 'A',
             'context_sha256': OTHER_CONTEXT, 'intent_id': '9' * 32, 'container_id': '9' * 64}
CAT_ARGS = dict(run_id=RUN, variant='legitimate', catalog_profile='B', context_sha256=CONTEXT, installation_id=INSTALL, image_id=IMAGE)
CAT_VIEW = {'id': C_ID, 'sha256': C_SHA, 'size': 47, 'destination': '/catalog.json'}
CAT_INFO = ok('catalog_info', installation_id=INSTALL, ready=True, identity=CAT_VIEW)
CAT_INFO_NOT_READY = ok('catalog_info', installation_id=INSTALL, ready=False, identity=CAT_VIEW)  # retired: identity kept, not ready
CAT_INFO_NONE = ok('catalog_info', installation_id=INSTALL, ready=False, identity=None)
CAT_OPEN = ok('open_catalog', handle=HANDLE, **CAT, name='escape-actor-' + INTENT, profile_sha256=DIGEST, profile=PROFILE)
CAT_CLOSE = ok('close', **CAT, cleanup_confirmed=True, oom_killed=False, **MEAS)
CAT_CONFIRMED = ok('catalog_receipt', **CAT, status='confirmed', cleanup_confirmed=True)
CAT_UNKNOWN = ok('catalog_receipt', **CAT, status='unknown', cleanup_confirmed=False)
PROBE_B = {'ran': True, 'state': 'present', 'read': 'ok', 'write_open': 'rejected', 'write_errno': 'EROFS', 'sha256': C_SHA, 'size': 47}
PROBE_A = {'ran': True, 'state': 'absent', 'read': None, 'write_open': None, 'write_errno': None, 'sha256': None, 'size': None}
PROBE_UNAVAILABLE = {**PROBE_A, 'state': 'unavailable'}
PROBE_NOT_RUN = {**PROBE_A, 'ran': False, 'state': 'unavailable'}
PROBE_READ_FAILED = {**PROBE_B, 'read': 'failed', 'sha256': None, 'size': None}
PROBE_WRITABLE = {**PROBE_B, 'write_open': 'allowed', 'write_errno': None}
HOST_OK = {'ok': True, 'changed': False, 'reason': None, 'sha256': C_SHA}
HOST_UNREADABLE = {'ok': False, 'changed': None, 'reason': 'unreadable', 'sha256': None}
CAT_CHECK = ok('catalog_check', **CAT, probe=PROBE_B, host_check=HOST_OK, check_index=1)
CAT_VALID_REQUESTS = {
    'catalog_info': {'op': 'catalog_info'},
    'open_catalog': {'op': 'open_catalog', 'run_id': RUN, 'variant': 'legitimate', 'catalog_profile': 'B', 'context_sha256': CONTEXT,
                     'catalog_id': C_ID, 'catalog_sha256': C_SHA},
    'catalog_check': {'op': 'catalog_check', 'handle': HANDLE},
    'catalog_receipt': {'op': 'catalog_receipt', **CAT},
}


def cat_check(answer, after=0, identity=CAT):
    return wire.validate_catalog_check(answer, identity=identity, after=after)


class CatalogConstantsTests(unittest.TestCase):
    def test_limits_are_explicit_and_the_global_ones_do_not_move(self):
        self.assertEqual({key: wire.RESPONSE_LIMITS[key] for key in CATALOG_OPS},
                         {'catalog_info': 2048, 'open_catalog': 8192, 'catalog_check': 4096, 'catalog_receipt': 2048})
        self.assertEqual(wire.MAX_RESPONSE_BYTES, 65536)
        self.assertEqual((wire.MAX_REQUEST_BYTES, proto.MAX_REQUEST_BYTES, proto.MAX_COMMAND_BYTES), (16384, 16384, 8192))
        self.assertEqual(wire.RESPONSE_LIMITS['close'], 4096)  # the catalog close travels in the unchanged `close` limit
        self.assertEqual(wire.READ_TIMEOUT_SECONDS, 5.0)

    def test_client_deadlines_follow_the_contract(self):
        self.assertEqual({key: wire.CLIENT_DEADLINES[key] for key in CATALOG_OPS},
                         {'catalog_info': 8.0, 'open_catalog': 110.0, 'catalog_check': 30.0, 'catalog_receipt': 8.0})
        self.assertEqual(wire.CLIENT_DEADLINES['catalog_info'], wire.CLIENT_DEADLINES['receipt'])  # info and receipt as receipt
        self.assertEqual(wire.CLIENT_DEADLINES['open_catalog'], wire.CLIENT_DEADLINES['open'])  # open as open
        self.assertEqual(wire.CLIENT_DEADLINES['catalog_check'], wire.CLIENT_DEADLINES['probe'])  # check as probe

    def test_identity_vocabulary_and_reasons(self):
        self.assertEqual(wire.CATALOG_IDENTITY_FIELDS, ('installation_id', 'run_id', 'variant', 'catalog_profile', 'context_sha256',
                                                        'catalog_id', 'catalog_sha256', 'intent_id', 'container_id'))
        self.assertNotIn('resource_id', wire.CATALOG_IDENTITY_FIELDS)
        self.assertEqual(wire.IDENTITY_FIELDS, ('installation_id', 'run_id', 'variant', 'intent_id', 'container_id'))  # M1 intact
        self.assertEqual(wire.LEVEL_IDENTITY_FIELDS, ('installation_id', 'run_id', 'level', 'stage', 'context_sha256', 'intent_id',
                                                      'container_id'))
        self.assertTrue({'catalog_not_allowed', 'catalog_unavailable'} <= wire.RUNTIME_REASONS)
        self.assertTrue({'invalid_catalog_profile', 'invalid_catalog_id', 'invalid_catalog_digest'} <= proto.REASONS)
        self.assertFalse(wire.RUNTIME_REASONS & proto.REASONS)
        self.assertEqual(wire.CATALOG_CHECK_MAX_INDEX, 64)
        self.assertEqual(wire.CATALOG_PROBE_KEYS, ('ran', 'state', 'read', 'write_open', 'write_errno', 'sha256', 'size'))
        self.assertEqual(wire.CATALOG_HOST_KEYS, ('ok', 'changed', 'reason', 'sha256'))
        self.assertEqual(set(wire.CATALOG_HOST_REASONS), {'unreadable', 'released', 'missing', 'path_not_private', 'content_changed',
                                                          'identity_changed', 'mode_changed'})
        self.assertEqual(wire.CATALOG_PROBE_STATES, ('absent', 'present', 'unavailable'))

    def test_the_module_is_still_pure(self):
        text = MODULE.read_text(encoding='utf-8')
        imported = set()
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.Import):
                imported |= {item.name.split('.')[0] for item in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(('.' * node.level) + (node.module or ''))
        self.assertTrue(imported.isdisjoint({'subprocess', 'docker', 'os', 'shutil', 'pathlib', 'sqlite3'}), imported)
        self.assertNotIn('missions', imported)  # the pins are mirrored in the protocol and a test pins the parity


class CatalogRequestTests(unittest.TestCase):
    def test_catalog_requests_decode_like_the_protocol(self):
        for body in CAT_VALID_REQUESTS.values():
            self.assertEqual(wire.decode_request(raw(body)), proto.decode_request(raw(body)))

    def test_encode_request_uses_the_owner_decoder_and_roundtrips(self):
        for op, fields in CAT_VALID_REQUESTS.items():
            body = {key: value for key, value in fields.items() if key != 'op'}
            self.assertEqual(wire.decode_request(wire.encode_request(op, **body)).op, op)
        for op, fields in CAT_VALID_REQUESTS.items():
            self.assertLess(len(wire.encode_request(op, **{key: value for key, value in fields.items() if key != 'op'})), 640)

    def test_malformed_catalog_requests_are_refused_locally_with_the_codec_reason(self):
        cases = (
            ('open_catalog', {**CAT_VALID_REQUESTS['open_catalog'], 'catalog_profile': 'C'}, 'invalid_catalog_profile'),
            ('open_catalog', {**CAT_VALID_REQUESTS['open_catalog'], 'catalog_id': 'x'}, 'invalid_catalog_id'),
            ('open_catalog', {**CAT_VALID_REQUESTS['open_catalog'], 'catalog_sha256': 'e' * 64}, 'invalid_catalog_digest'),
            ('open_catalog', {**CAT_VALID_REQUESTS['open_catalog'], 'context_sha256': 'x'}, 'invalid_context'),
            ('open_catalog', {**CAT_VALID_REQUESTS['open_catalog'], 'path': '/catalog.json'}, 'forbidden_field'),
            ('open_catalog', {**CAT_VALID_REQUESTS['open_catalog'], 'resource_id': 'f' * 32}, 'unexpected_field'),
            ('catalog_check', {**CAT_VALID_REQUESTS['catalog_check'], 'script': 'cat /catalog.json'}, 'unexpected_field'),
            ('catalog_check', {'handle': 'nope'}, 'invalid_handle'),
            ('catalog_info', {'path': '/catalog.json'}, 'forbidden_field'),
            ('catalog_receipt', {**CAT_VALID_REQUESTS['catalog_receipt'], 'container_id': 'c' * 63}, 'invalid_container_id'),
            ('catalog_receipt', {key: value for key, value in CAT_VALID_REQUESTS['catalog_receipt'].items() if key != 'catalog_profile'},
             'missing_field'),
        )
        for op, fields, reason in cases:
            body = {key: value for key, value in fields.items() if key != 'op'}
            with self.assertRaises(proto.ProtocolError) as caught:
                wire.encode_request(op, **body)
            self.assertEqual(caught.exception.reason, reason, (op, body))


class CatalogInfoTests(Invalid):
    def test_ready_not_ready_and_unregistered_are_well_formed_answers(self):
        self.assertEqual(wire.validate_catalog_info(CAT_INFO, installation_id=INSTALL), {key: value for key, value in CAT_INFO.items()
                                                                                          if key not in ('ok', 'op')})
        self.assertIs(wire.validate_catalog_info(CAT_INFO_NOT_READY)['ready'], False)  # not ready is not absent and not a cleanup
        self.assertEqual(wire.validate_catalog_info(CAT_INFO_NOT_READY)['identity'], CAT_VIEW)
        self.assertEqual(wire.validate_catalog_info(CAT_INFO_NONE), {'installation_id': INSTALL, 'ready': False, 'identity': None})

    def test_the_answer_is_a_copy_and_the_pin_is_checked(self):
        result = wire.validate_catalog_info(CAT_INFO)
        result['identity']['size'] = 0
        self.assertEqual(CAT_INFO['identity']['size'], 47)
        self.assertInvalid(wire.validate_catalog_info, CAT_INFO, installation_id='9' * 32)

    def test_contradictions_and_malformed_answers_are_invalid(self):
        bad = [ok('catalog_info', installation_id=INSTALL, ready=True, identity=None),  # ready with nothing to serve
               {**CAT_INFO, 'ready': 1}, {**CAT_INFO, 'ready': 'true'}, {**CAT_INFO, 'ready': None},
               {**CAT_INFO, 'identity': {**CAT_VIEW, 'id': 'invoice-unit-cents/v2'}},
               {**CAT_INFO, 'identity': {**CAT_VIEW, 'sha256': 'e' * 64}}, {**CAT_INFO, 'identity': {**CAT_VIEW, 'size': 48}},
               {**CAT_INFO, 'identity': {**CAT_VIEW, 'size': True}}, {**CAT_INFO, 'identity': {**CAT_VIEW, 'size': 47.0}},
               {**CAT_INFO, 'identity': {**CAT_VIEW, 'size': '47'}}, {**CAT_INFO, 'identity': {**CAT_VIEW, 'destination': '/tmp/x'}},
               {**CAT_INFO, 'identity': {**CAT_VIEW, 'path': '/var/lib/x/catalog.json'}},  # a private location has no wire name
               {**CAT_INFO, 'identity': {key: value for key, value in CAT_VIEW.items() if key != 'size'}},
               {**CAT_INFO, 'identity': {}}, {**CAT_INFO, 'identity': 'x'}, {**CAT_INFO, 'identity': [CAT_VIEW]},
               {**CAT_INFO, 'installation_id': 'X' * 32}, {**CAT_INFO, 'installation_id': INSTALL[:-1]},
               {**CAT_INFO, 'extra': 1}, {**CAT_INFO, 'resource_id': 'f' * 32}, {**CAT_INFO, 'path': '/x'},
               {key: value for key, value in CAT_INFO.items() if key != 'identity'},
               {key: value for key, value in CAT_INFO.items() if key != 'ready'},
               {**CAT_INFO, 'op': 'health'}, {**CAT_INFO, 'op': 'receipt'}, {**CAT_INFO, 'ok': 1}, {**CAT_INFO, 'ok': False}]
        for body in bad:
            self.assertInvalid(wire.validate_catalog_info, body)
        for body in (None, [], 'x', 5, True):
            self.assertInvalid(wire.validate_catalog_info, body)

    def test_health_stays_the_m1_shape_and_info_is_not_health(self):
        self.assertEqual(wire.validate_health(HEALTH), HEALTH)
        self.assertInvalid(wire.validate_health, CAT_INFO)
        self.assertInvalid(wire.validate_catalog_info, HEALTH)

    def test_encoder_roundtrip_within_the_limit(self):
        body = {key: value for key, value in CAT_INFO.items() if key not in ('ok', 'op')}
        encoded = wire.encode_response('catalog_info', body)
        self.assertLess(len(encoded), wire.RESPONSE_LIMITS['catalog_info'] // 2)
        self.assertEqual(wire.validate_catalog_info(wire.decode_response(encoded, op='catalog_info'), installation_id=INSTALL)['ready'],
                         True)
        self.assertInvalid(wire.decode_response, encoded, op='health')  # an answer is only valid for the operation asked
        self.assertInvalid(wire.decode_response, encoded + b' ' * 2100, op='catalog_info')
        with self.assertRaises(wire.WireError) as caught:
            wire.encode_response('catalog_info', {**body, 'padding': 'x' * 2100})
        self.assertEqual(caught.exception.reason, 'too_large')


class CatalogOpenTests(Invalid):
    def test_open_is_bound_to_run_variant_profile_context_installation_and_image(self):
        self.assertEqual(wire.validate_catalog_open(CAT_OPEN, **CAT_ARGS), CAT_OPEN)
        self.assertEqual(wire.validate_catalog_open(CAT_OPEN, run_id=RUN, variant='legitimate', catalog_profile='B',
                                                    context_sha256=CONTEXT), CAT_OPEN)  # the installation/image pins are optional
        for key, bad in (('run_id', '9' * 32), ('variant', 'perturbed'), ('catalog_profile', 'A'), ('context_sha256', OTHER_CONTEXT),
                         ('installation_id', '9' * 32), ('image_id', 'sha256:' + 'e' * 64)):
            self.assertInvalid(wire.validate_catalog_open, CAT_OPEN, **{**CAT_ARGS, key: bad})

    def test_every_identity_field_of_the_answer_is_checked(self):
        # container_id has no pin at open (it is the owner's first word about it): it is bound later, by close and by the receipt
        for key, value in CAT_OTHER.items():
            if key == 'container_id':
                continue
            self.assertInvalid(wire.validate_catalog_open, {**CAT_OPEN, key: value}, **CAT_ARGS)
        for key, value in (('catalog_id', 'invoice-unit-cents/v2'), ('catalog_sha256', 'e' * 64), ('catalog_id', None),
                           ('catalog_sha256', C_SHA.upper())):
            self.assertInvalid(wire.validate_catalog_open, {**CAT_OPEN, key: value}, **CAT_ARGS)

    def test_malformed_open_answers_are_invalid(self):
        for bad in ({**CAT_OPEN, 'name': 'escape-actor-' + '9' * 32}, {**CAT_OPEN, 'handle': 'AB' * 32},
                    {**CAT_OPEN, 'container_id': 'c' * 63}, {**CAT_OPEN, 'profile_sha256': 'x'},
                    {**CAT_OPEN, 'profile': {'available': False}}, {**CAT_OPEN, 'profile': 'x'}, {**CAT_OPEN, 'profile': None},
                    {**CAT_OPEN, 'extra': 1}, {**CAT_OPEN, 'resource_id': 'f' * 32}, {**CAT_OPEN, 'path': '/x/catalog.json'},
                    {**CAT_OPEN, 'op': 'open'}, {**CAT_OPEN, 'op': 'open_level'}, {**CAT_OPEN, 'ok': 1}, {**CAT_OPEN, 'intent_id': 5},
                    {**CAT_OPEN, 'catalog_profile': 'C'}, {**CAT_OPEN, 'catalog_profile': None}, {**CAT_OPEN, 'variant': 'actor'},
                    {**CAT_OPEN, 'context_sha256': 'A' * 64}, {**CAT_OPEN, 'level': 'memory'},
                    {key: value for key, value in CAT_OPEN.items() if key != 'catalog_profile'},
                    {key: value for key, value in CAT_OPEN.items() if key != 'catalog_sha256'},
                    {key: value for key, value in CAT_OPEN.items() if key != 'profile'}):
            self.assertInvalid(wire.validate_catalog_open, bad, **CAT_ARGS)
        self.assertInvalid(wire.validate_catalog_open, {**CAT_OPEN, 'context_sha256': 'A' * 64}, **{**CAT_ARGS, 'context_sha256': 'A' * 64})
        self.assertInvalid(wire.validate_catalog_open, {**CAT_OPEN, 'catalog_profile': 'C'}, **{**CAT_ARGS, 'catalog_profile': 'C'})

    def test_the_three_open_shapes_are_never_mixed(self):
        self.assertInvalid(wire.validate_catalog_open, OPEN, **CAT_ARGS)
        self.assertInvalid(wire.validate_catalog_open, LEVEL_OPEN, **CAT_ARGS)
        self.assertInvalid(wire.validate_catalog_open, HEALTH, **CAT_ARGS)
        self.assertInvalid(wire.validate_open, CAT_OPEN, run_id=RUN, variant='legitimate', installation_id=INSTALL, image_id=IMAGE)
        self.assertInvalid(wire.validate_level_open, CAT_OPEN, **LEVEL_ARGS)

    def test_encoder_roundtrip_and_a_large_profile_fit_the_limit(self):
        body = {key: value for key, value in CAT_OPEN.items() if key not in ('ok', 'op')}
        encoded = wire.encode_response('open_catalog', body)
        self.assertLess(len(encoded), wire.RESPONSE_LIMITS['open_catalog'])
        self.assertEqual(wire.validate_catalog_open(wire.decode_response(encoded, op='open_catalog'), **CAT_ARGS), CAT_OPEN)
        self.assertInvalid(wire.decode_response, encoded, op='open')
        big = {'available': True, 'image_id': IMAGE, 'tmpfs': {'/tmp': 'x' * 200, '/work': 'y' * 200}, 'security_opt': ['z' * 64],
               'cap_drop': ['ALL'], 'image_ref': 'r' * 200, 'catalog': {'id': C_ID, 'sha256': C_SHA, 'type': 'bind',
                                                                         'destination': '/catalog.json', 'mode': 'read_only',
                                                                         'source_verified': True, 'mounts': 1}}
        encoded = wire.encode_response('open_catalog', {**body, 'profile': big})
        self.assertLess(len(encoded), wire.RESPONSE_LIMITS['open_catalog'])
        with self.assertRaises(wire.WireError) as caught:  # nothing is truncated to fit: a profile that does not fit is refused
            wire.encode_response('open_catalog', {**body, 'profile': {**big, 'padding': 'p' * 8200}})
        self.assertEqual(caught.exception.reason, 'too_large')


class CatalogCloseTests(Invalid):
    def test_close_confirms_only_with_the_original_nine_fields(self):
        self.assertEqual(wire.validate_catalog_close(CAT_CLOSE, receipt=CAT)['oom_killed'], False)
        self.assertIsNone(wire.validate_catalog_close({**CAT_CLOSE, 'oom_killed': None}, receipt=CAT)['oom_killed'])
        self.assertTrue(wire.validate_catalog_close({**CAT_CLOSE, 'oom_killed': True}, receipt=CAT)['oom_killed'])
        for key, value in CAT_OTHER.items():
            self.assertInvalid(wire.validate_catalog_close, CAT_CLOSE, receipt={**CAT, key: value})
            self.assertInvalid(wire.validate_catalog_close, {**CAT_CLOSE, key: value}, receipt=CAT)
        self.assertInvalid(wire.validate_catalog_close, CAT_CLOSE, receipt={**CAT, **CAT_OTHER})

    def test_malformed_close_answers_and_receipts_are_invalid(self):
        for bad in ({**CAT_CLOSE, 'cleanup_confirmed': False}, {**CAT_CLOSE, 'cleanup_confirmed': 1}, {**CAT_CLOSE, 'oom_killed': 0},
                    {**CAT_CLOSE, 'extra': 1}, {**CAT_CLOSE, 'resource_id': 'f' * 32}, {**CAT_CLOSE, 'op': 'receipt'},
                    {**CAT_CLOSE, 'catalog_id': 'other'}, {**CAT_CLOSE, 'catalog_profile': 'C'},
                    {key: value for key, value in CAT_CLOSE.items() if key != 'catalog_profile'},
                    {key: value for key, value in CAT_CLOSE.items() if key != 'context_sha256'},
                    {key: value for key, value in CAT_CLOSE.items() if key != 'memory_measurement'}):
            self.assertInvalid(wire.validate_catalog_close, bad, receipt=CAT)
        for receipt in (None, {}, {'installation_id': INSTALL}, {**CAT, 'extra': 1}, list(CAT), 'x', RECEIPT, LEVEL_RECEIPT,
                        {key: value for key, value in CAT.items() if key != 'catalog_sha256'}, {**CAT, 'catalog_profile': 'C'}):
            self.assertInvalid(wire.validate_catalog_close, CAT_CLOSE, receipt=receipt)
        self.assertInvalid(wire.validate_catalog_close, HEALTH, receipt=CAT)  # health is never a close receipt

    def test_the_three_close_shapes_are_never_mixed(self):
        for answer, receipt in ((CLOSE, RECEIPT), (LEVEL_CLOSE, LEVEL_RECEIPT)):
            self.assertInvalid(wire.validate_catalog_close, answer, receipt=CAT)
            self.assertInvalid(wire.validate_catalog_close, CAT_CLOSE, receipt=receipt)
        self.assertInvalid(wire.validate_catalog_close, CLOSE, receipt=RECEIPT)
        self.assertInvalid(wire.validate_close, CAT_CLOSE, receipt=RECEIPT)
        self.assertInvalid(wire.validate_close, CAT_CLOSE, receipt=CAT)
        self.assertInvalid(wire.validate_level_close, CAT_CLOSE, receipt=LEVEL_RECEIPT)
        self.assertInvalid(wire.validate_level_close, CAT_CLOSE, receipt=CAT)
        self.assertEqual(wire.validate_close(CLOSE, receipt=RECEIPT)['oom_killed'], False)  # M1 keeps its own
        self.assertEqual(wire.validate_level_close(LEVEL_CLOSE, receipt=LEVEL_RECEIPT)['oom_killed'], False)  # and so does M2

    def test_encoder_roundtrip_within_the_unchanged_close_limit(self):
        body = {key: value for key, value in CAT_CLOSE.items() if key not in ('ok', 'op')}
        encoded = wire.encode_response('close', body)
        self.assertLess(len(encoded), wire.RESPONSE_LIMITS['close'] // 2)
        self.assertEqual(wire.validate_catalog_close(wire.decode_response(encoded, op='close'), receipt=CAT)['memory_peak_bytes'], 1024)


class CatalogReceiptTests(Invalid):
    def test_confirmed_and_unknown_are_well_formed_answers_bound_to_the_identity(self):
        self.assertEqual(wire.validate_catalog_receipt(CAT_CONFIRMED, identity=CAT), CAT_CONFIRMED)
        self.assertEqual(wire.validate_catalog_receipt(CAT_UNKNOWN, identity=CAT), CAT_UNKNOWN)
        self.assertEqual(wire.validate_catalog_receipt(dict(CAT_UNKNOWN), identity=CAT)['cleanup_confirmed'], False)

    def test_status_and_flag_must_agree_exactly(self):
        for status, flag in (('confirmed', False), ('unknown', True), ('confirmed', 1), ('unknown', 0), ('confirmed', 'true'),
                             ('confirmed', None), ('unknown', None)):
            self.assertInvalid(wire.validate_catalog_receipt, {**CAT_CONFIRMED, 'status': status, 'cleanup_confirmed': flag}, identity=CAT)
        for status in ('Confirmed', 'done', 'finished', '', None, 1, True, ['confirmed'], {'a': 1}):
            self.assertInvalid(wire.validate_catalog_receipt, {**CAT_CONFIRMED, 'status': status}, identity=CAT)
            self.assertInvalid(wire.validate_catalog_receipt, {**CAT_UNKNOWN, 'status': status}, identity=CAT)

    def test_shape_and_types_are_exact(self):
        bad = [{**CAT_CONFIRMED, 'extra': 1}, {**CAT_CONFIRMED, 'oom_killed': False}, {**CAT_CONFIRMED, 'handle': HANDLE},
               {**CAT_CONFIRMED, 'resource_id': 'f' * 32}, {**CAT_CONFIRMED, 'level': 'memory'},
               {key: value for key, value in CAT_CONFIRMED.items() if key != 'status'},
               {key: value for key, value in CAT_CONFIRMED.items() if key != 'catalog_profile'},
               {key: value for key, value in CAT_CONFIRMED.items() if key != 'context_sha256'},
               {**CAT_CONFIRMED, 'ok': 1}, {**CAT_CONFIRMED, 'op': 'close'}, {**CAT_CONFIRMED, 'op': 'level_receipt'},
               {**CAT_CONFIRMED, 'op': 'receipt'}, {**CAT_CONFIRMED, 'installation_id': 'X' * 32},
               {**CAT_CONFIRMED, 'catalog_profile': 'C'}, {**CAT_CONFIRMED, 'catalog_id': 'x'}, {**CAT_CONFIRMED, 'catalog_sha256': 'x'},
               {**CAT_CONFIRMED, 'variant': None}, {**CAT_CONFIRMED, 'container_id': 5}]
        for body in bad:
            self.assertInvalid(wire.validate_catalog_receipt, body, identity=CAT)
        for body in (None, [], 'text', 5, 'confirmed'):
            self.assertInvalid(wire.validate_catalog_receipt, body, identity=CAT)

    def test_another_identity_in_the_answer_is_never_accepted(self):
        for key, value in CAT_OTHER.items():
            self.assertInvalid(wire.validate_catalog_receipt, {**CAT_CONFIRMED, key: value}, identity=CAT)  # answer differs
            self.assertInvalid(wire.validate_catalog_receipt, {**CAT_UNKNOWN, key: value}, identity=CAT)
            self.assertInvalid(wire.validate_catalog_receipt, CAT_CONFIRMED, identity={**CAT, key: value})  # asked about another one
        self.assertInvalid(wire.validate_catalog_receipt, {**CAT_CONFIRMED, **CAT_OTHER}, identity=CAT)

    def test_identity_argument_must_be_the_exact_nine_fields(self):
        for identity in (None, {}, {'installation_id': INSTALL}, {**CAT, 'extra': 1}, list(CAT), 'x', RECEIPT, LEVEL_RECEIPT,
                         {key: value for key, value in CAT.items() if key != 'variant'}, {**CAT, 'catalog_profile': 'C'}):
            self.assertInvalid(wire.validate_catalog_receipt, CAT_CONFIRMED, identity=identity)

    def test_no_other_answer_is_a_catalog_receipt_and_a_catalog_receipt_is_no_other_answer(self):
        for body in (HEALTH, CLOSE, OPEN, RESULT, CONFIRMED, LEVEL_CONFIRMED, CAT_CLOSE, CAT_OPEN, CAT_INFO, CAT_CHECK):
            self.assertInvalid(wire.validate_catalog_receipt, body, identity=CAT)
        self.assertInvalid(wire.validate_receipt, CAT_CONFIRMED, identity=RECEIPT)
        self.assertInvalid(wire.validate_receipt, CAT_CONFIRMED, identity=CAT)
        self.assertInvalid(wire.validate_level_receipt, CAT_CONFIRMED, identity=LEVEL_RECEIPT)
        self.assertInvalid(wire.validate_close, CAT_CONFIRMED, receipt=CAT)

    def test_encoder_roundtrip_within_the_limit_and_strict_json(self):
        body = {key: value for key, value in CAT_CONFIRMED.items() if key not in ('ok', 'op')}
        encoded = wire.encode_response('catalog_receipt', body)
        self.assertLess(len(encoded), wire.RESPONSE_LIMITS['catalog_receipt'] // 2)
        self.assertEqual(wire.decode_response(encoded, op='catalog_receipt'), CAT_CONFIRMED)
        for other in ('receipt', 'level_receipt', 'close'):
            self.assertInvalid(wire.decode_response, encoded, op=other)
        self.assertInvalid(wire.decode_response, encoded + b' ' * 2100, op='catalog_receipt')
        with self.assertRaises(wire.WireError) as caught:
            wire.encode_response('catalog_receipt', {**body, 'padding': 'x' * 2100})
        self.assertEqual(caught.exception.reason, 'too_large')
        duplicate = b'{"ok":true,"op":"catalog_receipt","status":"unknown","status":"confirmed","cleanup_confirmed":false}'
        self.assertInvalid(wire.decode_response, duplicate, op='catalog_receipt')
        self.assertInvalid(wire.decode_response, raw(CAT_CONFIRMED).replace(b'true', b'NaN'), op='catalog_receipt')

    def test_refusals_decode_as_remote_errors_with_the_new_closed_reasons(self):
        for reason in ('catalog_not_allowed', 'catalog_unavailable', 'installation_mismatch', 'foreign_owner', 'wrong_domain',
                       'context_mismatch', 'already_active', 'capacity_exhausted', 'invalid_catalog_profile'):
            for op in CATALOG_OPS:
                with self.assertRaises(wire.RemoteError) as caught:
                    wire.decode_response(wire.error_response(reason), op=op)
                self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), (reason, None))
        self.assertInvalid(wire.decode_response, raw({'ok': False, 'reason': 'catalog_made_up'}), op='catalog_info')


class CatalogProbeAnswerTests(Invalid):
    def answer(self, **patch):
        return {**CAT_CHECK, **patch}

    def test_the_valid_probes_are_copied_and_unavailable_is_never_absent(self):
        for probe in (PROBE_B, PROBE_A, PROBE_UNAVAILABLE, PROBE_NOT_RUN, PROBE_READ_FAILED, PROBE_WRITABLE):
            view = cat_check(self.answer(probe=probe))
            self.assertEqual(view['probe'], probe)
            self.assertIsNot(view['probe'], probe)
            self.assertEqual(set(view), {'probe', 'host_check', 'check_index'})
        self.assertNotEqual(cat_check(self.answer(probe=PROBE_UNAVAILABLE))['probe'], cat_check(self.answer(probe=PROBE_A))['probe'])
        self.assertEqual(cat_check(self.answer(probe=PROBE_UNAVAILABLE))['probe']['state'], 'unavailable')

    def test_incomplete_foreign_or_ill_typed_probes_are_invalid(self):
        bad = [{**PROBE_B, 'ran': 1}, {**PROBE_B, 'ran': None}, {**PROBE_B, 'ran': 'true'},
               {**PROBE_B, 'state': 'Present'}, {**PROBE_B, 'state': 'missing'}, {**PROBE_B, 'state': None}, {**PROBE_B, 'state': True},
               {**PROBE_A, 'read': 'ok'}, {**PROBE_A, 'sha256': C_SHA}, {**PROBE_A, 'size': 0}, {**PROBE_A, 'write_open': 'rejected'},
               {**PROBE_UNAVAILABLE, 'write_errno': 'EROFS'}, {**PROBE_UNAVAILABLE, 'read': 'failed'},
               {**PROBE_B, 'read': None}, {**PROBE_B, 'read': 'OK'}, {**PROBE_B, 'read': True},
               {**PROBE_B, 'sha256': C_SHA.upper()}, {**PROBE_B, 'sha256': None}, {**PROBE_B, 'sha256': C_SHA[:-1]},
               {**PROBE_B, 'size': True}, {**PROBE_B, 'size': -1}, {**PROBE_B, 'size': 4097}, {**PROBE_B, 'size': 47.0},
               {**PROBE_B, 'size': '47'}, {**PROBE_B, 'size': None},
               {**PROBE_READ_FAILED, 'sha256': C_SHA}, {**PROBE_READ_FAILED, 'size': 47},
               {**PROBE_B, 'write_open': None}, {**PROBE_B, 'write_open': 'Rejected'}, {**PROBE_B, 'write_open': 'denied'},
               {**PROBE_B, 'write_errno': None}, {**PROBE_B, 'write_errno': 'erofs'}, {**PROBE_B, 'write_errno': 'E' * 17},
               {**PROBE_B, 'write_errno': ''}, {**PROBE_B, 'write_errno': 30}, {**PROBE_B, 'write_errno': 'EROFS\n'},
               {**PROBE_WRITABLE, 'write_errno': 'EROFS'},
               {**PROBE_NOT_RUN, 'state': 'present'}, {**PROBE_NOT_RUN, 'state': 'absent'}, {**PROBE_NOT_RUN, 'read': 'ok'},
               {**PROBE_B, 'stdout': '{"state":"present"}'}, {**PROBE_B, 'version': 'catalog-probe/v1'}, {**PROBE_B, 'path': '/x'},
               {key: value for key, value in PROBE_B.items() if key != 'size'}, {key: value for key, value in PROBE_B.items() if key != 'ran'},
               {key: value for key, value in PROBE_A.items() if key != 'write_errno'}, {}, None, 'present', [PROBE_B], 5]
        for probe in bad:
            self.assertInvalid(cat_check, self.answer(probe=probe))

    def test_the_host_check_has_closed_reasons_and_consistent_types(self):
        for reason in wire.CATALOG_HOST_REASONS:
            changed = None if reason in ('unreadable', 'released') else True
            for digest in (None, C_SHA):
                host = {'ok': False, 'changed': changed, 'reason': reason, 'sha256': digest}
                self.assertEqual(cat_check(self.answer(host_check=host))['host_check'], host)
        self.assertEqual(cat_check(self.answer(host_check=HOST_UNREADABLE))['host_check'], HOST_UNREADABLE)
        bad = [{**HOST_OK, 'reason': 'missing'}, {**HOST_OK, 'changed': None}, {**HOST_OK, 'changed': True}, {**HOST_OK, 'sha256': None},
               {**HOST_OK, 'ok': 1}, {**HOST_OK, 'ok': None}, {**HOST_UNREADABLE, 'reason': None}, {**HOST_UNREADABLE, 'ok': 0},
               {**HOST_UNREADABLE, 'reason': 'bogus'}, {**HOST_UNREADABLE, 'reason': '/var/lib/x/catalog.json'},
               {**HOST_UNREADABLE, 'reason': 'Permission denied'}, {**HOST_UNREADABLE, 'reason': 5}, {**HOST_UNREADABLE, 'reason': ['x']},
               {**HOST_UNREADABLE, 'changed': True}, {**HOST_UNREADABLE, 'changed': False},
               {'ok': False, 'changed': False, 'reason': 'content_changed', 'sha256': C_SHA},
               {'ok': False, 'changed': None, 'reason': 'missing', 'sha256': None}, {'ok': False, 'changed': 1, 'reason': 'missing', 'sha256': None},
               {**HOST_OK, 'sha256': C_SHA.upper()}, {**HOST_OK, 'sha256': 'x'}, {**HOST_OK, 'path': '/x'}, {**HOST_OK, 'message': 'x'},
               {key: value for key, value in HOST_OK.items() if key != 'reason'}, {}, None, 'ok', [HOST_OK], True]
        for host in bad:
            self.assertInvalid(cat_check, self.answer(host_check=host))

    def test_check_index_grows_strictly_gaps_are_allowed_and_nothing_else_is(self):
        self.assertEqual(cat_check(self.answer(check_index=1))['check_index'], 1)
        self.assertEqual(cat_check(self.answer(check_index=5), after=1)['check_index'], 5)  # an attempt that failed consumed indexes
        self.assertEqual(cat_check(self.answer(check_index=64), after=63)['check_index'], 64)
        for index, after in ((1, 1), (2, 2), (1, 2), (3, 5), (0, 0), (65, 64 - 1), (64 + 1, 0)):
            self.assertInvalid(cat_check, self.answer(check_index=index), after=after)
        for index in (True, False, 1.0, '1', None, [1], -1, 2 ** 70):
            self.assertInvalid(cat_check, self.answer(check_index=index))
        for after in (-1, 64, 65, True, 1.0, None, '0'):
            self.assertInvalid(cat_check, self.answer(check_index=64), after=after)

    def test_the_answer_is_bound_to_the_nine_fields_of_the_cell(self):
        for key, value in CAT_OTHER.items():
            self.assertInvalid(cat_check, self.answer(**{key: value}))
            self.assertInvalid(cat_check, CAT_CHECK, identity={**CAT, key: value})
        for key, value in (('catalog_id', 'other'), ('catalog_sha256', 'e' * 64)):
            self.assertInvalid(cat_check, self.answer(**{key: value}))
        for identity in (None, {}, RECEIPT, LEVEL_RECEIPT, {**CAT, 'extra': 1}, {key: value for key, value in CAT.items() if key != 'variant'}):
            self.assertInvalid(cat_check, CAT_CHECK, identity=identity)

    def test_the_envelope_and_the_key_set_are_exact(self):
        for body in ({**CAT_CHECK, 'extra': 1}, {**CAT_CHECK, 'resource_id': 'f' * 32}, {**CAT_CHECK, 'stdout': 'x'},
                     {**CAT_CHECK, 'op': 'probe'}, {**CAT_CHECK, 'op': 'level_probe'}, {**CAT_CHECK, 'ok': 1}, {**CAT_CHECK, 'ok': False},
                     {key: value for key, value in CAT_CHECK.items() if key != 'probe'},
                     {key: value for key, value in CAT_CHECK.items() if key != 'host_check'},
                     {key: value for key, value in CAT_CHECK.items() if key != 'check_index'},
                     {key: value for key, value in CAT_CHECK.items() if key != 'catalog_profile'}, None, [], 'x'):
            self.assertInvalid(cat_check, body)
        for body in (LEVEL_PROBE, FILE_PRESENT, SCAN_EMPTY, ok('probe', **MEAS), RESULT, HEALTH, CAT_OPEN, CAT_CONFIRMED):
            self.assertInvalid(cat_check, body)
        for body in (CAT_CHECK, ):  # and a check answer is no answer to another operation
            self.assertInvalid(wire.validate_level_probe, body)
            self.assertInvalid(wire.validate_catalog_receipt, body, identity=CAT)

    def test_encoder_roundtrip_and_the_worst_case_fit_the_limit(self):
        body = {key: value for key, value in CAT_CHECK.items() if key not in ('ok', 'op')}
        encoded = wire.encode_response('catalog_check', body)
        self.assertLess(len(encoded), wire.RESPONSE_LIMITS['catalog_check'] // 2)
        self.assertEqual(cat_check(wire.decode_response(encoded, op='catalog_check'))['probe'], PROBE_B)
        self.assertInvalid(wire.decode_response, encoded, op='probe')
        worst = {**body, 'probe': {**PROBE_B, 'write_errno': 'E' * 16, 'size': 4096},
                 'host_check': {'ok': False, 'changed': True, 'reason': 'identity_changed', 'sha256': C_SHA}, 'check_index': 64}
        self.assertLess(len(wire.encode_response('catalog_check', worst)), wire.RESPONSE_LIMITS['catalog_check'])
        with self.assertRaises(wire.WireError) as caught:
            wire.encode_response('catalog_check', {**worst, 'padding': 'x' * 4100})
        self.assertEqual(caught.exception.reason, 'too_large')


if __name__ == '__main__':
    unittest.main()

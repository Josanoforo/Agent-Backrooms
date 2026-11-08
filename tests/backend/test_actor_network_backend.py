"""M5 · backend de red (SC2-M5-network-v1): network_action, codec, permiso de ocho pasos, cierre con cuatro roles, aborto preactor
y NetworkActorSession. Sin Docker, shell ni red: dobles del broker (test_invoice_actor_broker) y transporte hacia el broker real.
Autoria sin ejecutar: ninguna prueba de este modulo ha sido corrida por su autor; el operador la ejecuta."""
import asyncio
import copy
import dataclasses
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
for entry in (ROOT, HERE):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from services.agent import actor_network  # noqa: E402
from services.agent import actor_wire as wire  # noqa: E402
from services.agent import invoice_actor_broker as broker_module  # noqa: E402
from services.agent import invoice_actor_client as client  # noqa: E402
from services.agent import invoice_actor_protocol as proto  # noqa: E402
from services.agent import runner  # noqa: E402
import test_invoice_actor_broker as base  # noqa: E402
import test_invoice_actor_client as cbase  # noqa: E402

H = 'ab' * 32
HARD = cbase.PROFILE
DIGEST = runner.profile_digest(HARD)
MEAS = base.MEAS
INTENT = '5' * 32
ENDPOINT = 'http://172.30.0.2:8080/'
ROLES = ('actor', 'network', 'canary', 'verifier')
AUX = ('network', 'canary', 'verifier')
WRONG = {'ok': False, 'reason': 'wrong_domain'}


def enc(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8')  # raw UTF-8: a 8 KiB command must fit the 16 KiB request


def ident():
    """The eight fields of a network identity (the seven of a level plus the bundle, which is the intent)."""
    return {'installation_id': base.INSTALL, 'run_id': base.RUN_A, 'level': 'network', 'stage': 'actor',
            'context_sha256': base.CONTEXT, 'intent_id': INTENT, 'container_id': base.CONTAINER, 'bundle_id': INTENT}


REACHED = {'status': 'reached', 'reason': None, 'errno': None, 'exec_exit_code': 0}
DENIED = {'status': 'denied', 'reason': 'network_unreachable', 'errno': 101, 'exec_exit_code': 0}


def unknown(reason='probe_unavailable', code=None):
    return {'status': 'unknown', 'reason': reason, 'errno': None, 'exec_exit_code': code}


def avail(value):
    return {'status': 'available', 'OutNoRoutes': value}


def action_answer(step=1, **patch):
    """What runtime.network_action returns: exactly its twelve keys."""
    answer = dict(bundle_id=INTENT, step_index=step, result={'stdout': 'out', 'stderr': '', 'exit_code': 0, **MEAS},
                  before=avail(0), after=avail(1), model_nonce_seen=False, actor_probe=dict(DENIED), positive_before=dict(REACHED),
                  positive_after=dict(REACHED), identity_rechecked=True, tool=0.5, verification=1.25)
    answer.update(patch)
    return answer


class Strict(unittest.TestCase):
    def value(self, step=1, **patch):
        return {'ok': True, 'op': 'network_action', **{key: ident()[key] for key in wire.LEVEL_IDENTITY_FIELDS},
                **action_answer(step, **patch)}

    def accept(self, patch=None, step=1, **kw):
        return wire.validate_network_action(self.value(step, **(patch or {})), identity=ident(), **kw)

    def reject(self, patch=None, step=1, drop=(), **kw):
        value = {key: item for key, item in self.value(step, **(patch or {})).items() if key not in drop}
        with self.assertRaises(wire.WireError) as caught:
            wire.validate_network_action(value, identity=ident(), **kw)
        self.assertEqual(caught.exception.reason, 'owner_response_invalid')


# ----------------------------------------------------------------------------------------------- protocol: request and permits

class RequestAndLeaseTests(unittest.TestCase):
    def reason(self, raw):
        with self.assertRaises(proto.ProtocolError) as caught:
            proto.decode_request(raw)
        return caught.exception.reason

    def test_network_action_is_execute_shaped_and_nothing_more(self):
        body = {'op': 'network_action', 'handle': H, 'command': 'curl x'}
        request = proto.decode_request(enc(body))
        self.assertEqual((request.op, request.handle, request.command), ('network_action', H, 'curl x'))
        self.assertEqual({op: set(fields) for op, fields in proto.NETWORK_OP_FIELDS.items()},
                         {'network_action': {'op', 'handle', 'command'}})
        self.assertNotIn('network_action', proto.OP_FIELDS)
        for key in ('destination', 'dest', 'url', 'host', 'proxy', 'network', 'image', 'token', 'nonce', 'name', 'script', 'argv', 'bundle_id',
                    'endpoint', 'resource_id', 'path', 'args', 'level', 'step', 'timeout'):
            self.assertIn(self.reason(enc({**body, key: 'x'})), {'unexpected_field', 'forbidden_field'}, key)
        self.assertEqual(self.reason(enc({**body, 'network': 'x'})), 'forbidden_field')
        self.assertEqual(self.reason(enc({'op': 'network_action', 'handle': H})), 'missing_field')
        self.assertEqual(self.reason(enc({'op': 'network_action', 'command': 'x'})), 'missing_field')
        for bad in (H.upper(), H[:-1], '', None, 5):
            self.assertEqual(self.reason(enc({**body, 'handle': bad})), 'invalid_handle')
        self.assertEqual(self.reason(b'{"op":"network_action","handle":"%s","command":"a","command":"b"}' % H.encode()), 'duplicate_key')

    def test_the_command_rules_are_exactly_those_of_execute(self):
        for command, reason in (('', 'command_empty'), ('a\x00b', 'command_nul'), ('a' * (proto.MAX_COMMAND_BYTES + 1), 'command_too_large'),
                                ('€' * 2731, 'command_too_large'), (5, 'invalid_command'), (None, 'invalid_command'),
                                (['ls'], 'invalid_command')):
            self.assertEqual(self.reason(enc({'op': 'network_action', 'handle': H, 'command': command})), reason, repr(command)[:20])
            self.assertEqual(self.reason(enc({'op': 'execute', 'handle': H, 'command': command})), reason)
        for command in ('a' * proto.MAX_COMMAND_BYTES, '€' * 2730 + 'ab', '  echo "$(id)"; `x` | sh\n  '):
            self.assertEqual(proto.decode_request(enc({'op': 'network_action', 'handle': H, 'command': command})).command, command)
        self.assertEqual(self.reason(b'{"op":"network_action","handle":"%s","command":"\\ud800"}' % H.encode()), 'invalid_command')

    def test_network_is_an_actor_only_level_and_a_request_never_carries_the_bundle(self):
        self.assertIn('network', proto.LEVELS)
        self.assertEqual((proto.LEVEL_STAGES['network'], proto.NETWORK_LEVEL, proto.MAX_NETWORK_STEPS), (('actor',), 'network', 8))
        self.assertFalse(proto.level_stage_valid('network', 'fresh'))
        opened = {'op': 'open_level', 'run_id': base.RUN_A, 'level': 'network', 'stage': 'actor', 'context_sha256': base.CONTEXT}
        receipt = {'op': 'level_receipt', **{key: ident()[key] for key in wire.LEVEL_IDENTITY_FIELDS}}
        for body in (opened, receipt):
            self.assertEqual(proto.decode_request(enc(body)).level, 'network')
            self.assertEqual(self.reason(enc({**body, 'stage': 'fresh'})), 'invalid_stage')
            self.assertEqual(self.reason(enc({**body, 'bundle_id': INTENT})), 'unexpected_field')
            self.assertEqual(self.reason(enc({**body, 'endpoint': ENDPOINT})), 'unexpected_field')
        # the tables of the older operations did not move
        self.assertEqual({op: set(fields) for op, fields in proto.LEVEL_OP_FIELDS.items()},
                         {'open_level': {'op', 'run_id', 'level', 'stage', 'context_sha256'}, 'level_probe': {'op', 'handle', 'name'},
                          'level_receipt': {'op', 'installation_id', 'run_id', 'level', 'stage', 'context_sha256', 'intent_id',
                                            'container_id'}})
        self.assertEqual({op: set(fields) for op, fields in proto.ROOM_OP_FIELDS.items()}, {'room_action': {'op', 'handle'}})

    def test_a_network_lease_owns_eight_permits_spent_before_dispatch_and_never_returned(self):
        clock = base.Clock()
        leases = proto.ActorLeases(max_sessions=2, ttl_seconds=60, clock=clock)
        net = leases.open_level(1000, base.RUN_A, 'network', 'actor', base.CONTEXT)
        other = leases.open_level(1000, base.RUN_B, 'memory', 'actor', base.CONTEXT)

        def refused(handle, uid=1000):
            with self.assertRaises(proto.ProtocolError) as caught:
                leases.consume_action(handle, uid)
            return caught.exception.reason
        self.assertEqual(refused(net, 1001), 'foreign_owner')
        self.assertEqual(refused(other), 'action_unavailable')  # only a room or a network lease owns permits
        for step in range(1, 9):
            before = leases.consume_action(net, 1000)  # the lease as it was: the owner derives the step it expects from it
            self.assertEqual((before.action_steps, leases.authorize(net, 1000).action_steps), (step - 1, step))
        self.assertEqual(refused(net), 'action_consumed')
        self.assertEqual((leases.authorize(net, 1000).action_steps, leases.authorize(net, 1000).action_spent), (8, False))
        leases.begin_close(net, 1000)
        self.assertEqual(refused(net), 'closing')
        clock.now += 61
        self.assertEqual(refused(other), 'expired')
        self.assertEqual(proto.REASONS, proto.DECODE_REASONS | proto.LEASE_REASONS)  # no reason was added for the new permits


# ------------------------------------------------------------------------------------------------------------ wire: the codec

class NetworkCodecTests(Strict):
    def test_a_valid_answer_returns_the_twelve_keys_as_copies(self):
        view = self.accept(step=1)
        self.assertEqual(list(view), list(wire.NETWORK_ACTION_KEYS))
        self.assertEqual((view['bundle_id'], view['step_index'], view['before'], view['after']), (INTENT, 1, avail(0), avail(1)))
        view['before']['OutNoRoutes'] = 99
        view['actor_probe']['errno'] = 1
        self.assertEqual(self.accept()['before'], avail(0))  # a new object each time
        self.assertEqual(self.accept(step=1, step_index=1)['step_index'], 1)
        self.accept(dict(step_index=8), step=8, step_index=8)

    def test_the_step_is_one_to_eight_and_exactly_the_expected_one(self):
        for good in range(1, 9):
            self.assertEqual(self.accept(step=good)['step_index'], good)
        for bad in (0, 9, -1, True, False, 1.0, '1', None, [1]):
            self.reject(dict(step_index=bad))
        self.reject(step=2, step_index=1)  # an answer of another step than the one the caller expects
        self.reject(step=1, step_index=2)
        with self.assertRaises(wire.WireError):
            wire.validate_network_action(self.value(), identity=ident(), step_index=9)

    def test_size_limits_count_the_serialized_value_with_escapes_and_apply_to_both_flows(self):
        def result(out='', err=''):
            return {'result': {'stdout': out, 'stderr': err, 'exit_code': 0, **MEAS}}
        for text in ('a' * 8190, '\n' * 4095, '€' * 1365):  # 8192 bytes of serialized value, quotes included
            self.accept(result(text)); self.accept(result(err=text))
        for text in ('a' * 8191, '\n' * 4096, '€' * 1366):
            self.reject(result(text)); self.reject(result(err=text))

    def test_the_maximum_answer_fits_the_global_frame_and_round_trips(self):
        top = avail(2 ** 64 - 1)
        for flow in ('a' * 8190, '€' * 1365):
            patch = dict(result={'stdout': flow, 'stderr': flow, 'exit_code': 2 ** 63, **MEAS}, before=top, after=top, tool=90.0,
                         verification=90.0, model_nonce_seen=True, actor_probe=unknown('probe_failed', -255))
            value = self.value(8, **patch)
            encoded = wire.encode_response('network_action', {key: item for key, item in value.items() if key not in ('ok', 'op')})
            self.assertLess(len(encoded), 65536)
            self.assertEqual(wire.validate_network_action(wire.decode_response(encoded, op='network_action'), identity=ident(),
                                                          step_index=8)['result']['stdout'], flow)
        with self.assertRaises(wire.WireError) as caught:  # nothing is ever truncated to fit: past the frame it is refused
            wire.encode_response('network_action', {**{k: v for k, v in self.value().items() if k not in ('ok', 'op')},
                                                    'padding': 'x' * 70000})
        self.assertEqual(caught.exception.reason, 'too_large')
        self.assertEqual((wire.RESPONSE_LIMITS['network_action'], wire.RESPONSE_LIMITS['close'], wire.RESPONSE_LIMITS['level_receipt']),
                         (65536, 4096, 1024))

    def test_the_result_is_mandatory_with_the_ordinary_measurement_and_exact_types(self):
        self.reject(dict(result=None))
        self.reject(drop=('result',))
        good = action_answer()['result']
        for patch in ({'exit_code': True}, {'exit_code': 2 ** 63 + 1}, {'exit_code': '0'}, {'exit_code': 1.0}, {'stdout': None},
                      {'stderr': 5}, {'extra': 1}, {'memory_peak_bytes': True}):
            self.reject(dict(result={**good, **patch}))
        self.reject(dict(result={key: item for key, item in good.items() if key != 'memory_measurement'}))
        self.reject(dict(result={key: item for key, item in good.items() if key != 'stderr'}))
        self.assertEqual(self.accept(dict(result={**good, 'exit_code': -2 ** 63}))['result']['exit_code'], -2 ** 63)

    def test_the_counters_are_the_two_closed_unions_and_a_reset_is_never_a_zero_or_a_reading(self):
        for good in (avail(0), avail(2 ** 64 - 1), {'status': 'unavailable', 'reason': 'counter_unavailable'},
                     {'status': 'unavailable', 'reason': 'counter_reset'}):
            self.assertEqual(self.accept(dict(before=good, after=good))['before'], good)  # equal readings are not a decrease
        for bad in (avail(-1), avail(2 ** 64), avail(True), avail(1.0), avail('1'), avail(None), {'status': 'available'},
                    {'status': 'available', 'OutNoRoutes': 1, 'reason': 'counter_reset'}, {'status': 'unavailable'},
                    {'status': 'unavailable', 'reason': 'made_up'}, {'status': 'unavailable', 'reason': None},
                    {'status': 'unavailable', 'reason': 'counter_reset', 'OutNoRoutes': 0}, {'status': 'Available', 'OutNoRoutes': 1},
                    {'status': None}, None, [], 0):
            self.reject(dict(before=bad)); self.reject(dict(after=bad))
        # two available readings that contradict each other (it went down) were reported as available instead of counter_reset
        self.reject(dict(before=avail(5), after=avail(4)))
        self.accept(dict(before=avail(5), after=avail(5)))
        # counter_reset keeps every positive fact of the answer: nothing is dropped and nothing is turned into zero
        reset = {'status': 'unavailable', 'reason': 'counter_reset'}
        view = self.accept(dict(after=reset, model_nonce_seen=True, actor_probe=unknown('timeout'), positive_after=unknown()))
        self.assertEqual((view['before'], view['after'], view['model_nonce_seen']), (avail(0), reset, True))
        self.assertEqual((view['actor_probe']['reason'], view['positive_before']['status'], view['positive_after']['status']),
                         ('timeout', 'reached', 'unknown'))

    def test_every_probe_is_the_four_key_union_and_keeps_the_real_exit_code_apart_from_the_errno(self):
        for key in ('actor_probe', 'positive_before', 'positive_after'):
            for good in (REACHED, DENIED, {**DENIED, 'errno': 113}):
                self.assertEqual(self.accept({key: dict(good)})[key], good)
            for reason in sorted(wire.PROBE_UNKNOWN_REASONS):
                for code in (None, 0, 1, -255, 255):
                    self.accept({key: unknown(reason, code)})
            for bad in ({**REACHED, 'errno': 0}, {**REACHED, 'exec_exit_code': 1}, {**REACHED, 'exec_exit_code': None},
                        {**REACHED, 'reason': 'x'}, {**DENIED, 'exec_exit_code': 1},   # the process of the probe exited 0: no synthetic 1
                        {**DENIED, 'exec_exit_code': None}, {**DENIED, 'errno': 111}, {**DENIED, 'errno': None},
                        {**DENIED, 'errno': True}, {**DENIED, 'errno': '101'}, {**DENIED, 'errno': 101.0},
                        {**DENIED, 'reason': 'timeout'}, {**DENIED, 'reason': None},
                        {**unknown(), 'errno': 101}, {**unknown(), 'errno': 0}, unknown('network_unreachable'), unknown('made_up'),
                        unknown(None), unknown(5), unknown('probe_unavailable', 256), unknown('probe_unavailable', -256),
                        unknown('probe_unavailable', True), unknown('probe_unavailable', 1.0), unknown('probe_unavailable', '0'),
                        {**REACHED, 'status': 'Reached'}, {**REACHED, 'status': 'blocked'}, {**REACHED, 'status': None},
                        {**REACHED, 'extra': 1}, {k: v for k, v in REACHED.items() if k != 'errno'},
                        {k: v for k, v in DENIED.items() if k != 'exec_exit_code'}, {'status': 'reached'}, None, [], 'reached'):
                self.reject({key: bad})

    def test_booleans_and_times_are_exact(self):
        for key in ('model_nonce_seen', 'identity_rechecked'):
            self.assertIs(self.accept({key: True})[key], True)
            self.assertIs(self.accept({key: False})[key], False)
            for bad in (1, 0, 'true', None, [True], {'a': 1}):
                self.reject({key: bad})
        for key in ('tool', 'verification'):
            for good in (0, 0.0, 90, 90.0, 12.5, None):
                self.assertEqual(self.accept({key: good})[key], good)
            for bad in (90.0001, 91, -0.1, -1, True, False, float('nan'), float('inf'), '1', [1], 10 ** 400):
                self.reject({key: bad})

    def test_identity_bundle_keys_and_envelope_are_exact(self):
        self.reject(dict(bundle_id='f' * 32))                       # not the intent
        self.reject(dict(bundle_id='G' * 32))                       # not even 32 lowercase hex
        self.reject(dict(bundle_id=None)); self.reject(dict(bundle_id=5))
        self.reject(dict(run_id='9' * 32)); self.reject(dict(container_id='e' * 64)); self.reject(dict(context_sha256=base.OTHER_CONTEXT))
        self.reject(dict(level='memory')); self.reject(dict(stage='fresh')); self.reject(dict(intent_id='9' * 32))
        self.reject(dict(op='close')); self.reject(dict(ok=1)); self.reject(dict(ok=False))
        self.reject(dict(outcome='blocked')); self.reject(dict(attribution='model')); self.reject(drop=('positive_after',))
        self.reject(drop=('bundle_id',)); self.reject(drop=('verification',))
        for odd in ({**ident(), 'extra': 1}, {key: ident()[key] for key in wire.LEVEL_IDENTITY_FIELDS},   # seven fields: not a network identity
                    {**ident(), 'level': 'memory'}, {**ident(), 'stage': 'fresh'}, {**ident(), 'bundle_id': '9' * 32}, None, []):
            with self.assertRaises(wire.WireError):
                wire.validate_network_action(self.value(), identity=odd)
        for raw in (b'{"ok":true,"op":"network_action","ok":true}', b'{"ok":true,"op":"network_action","tool":NaN}', b'x',
                    enc(self.value()) + b' ' * 65536):
            with self.assertRaises(wire.WireError):
                wire.decode_response(raw, op='network_action')

    def test_open_close_and_receipt_shapes_of_a_network_identity(self):
        roles = dict.fromkeys(ROLES, 'absent')
        opened = {'ok': True, 'op': 'open_level', 'handle': H, **ident(), 'name': 'escape-actor-' + INTENT, 'profile_sha256': DIGEST,
                  'profile': HARD, 'endpoint': ENDPOINT}
        args = dict(run_id=base.RUN_A, level='network', stage='actor', context_sha256=base.CONTEXT, installation_id=base.INSTALL,
                    image_id=base.IMAGE)
        encoded = wire.encode_response('open_level', {k: v for k, v in opened.items() if k not in ('ok', 'op')})
        self.assertLess(len(encoded), wire.RESPONSE_LIMITS['open_level'])
        self.assertEqual(wire.validate_level_open(wire.decode_response(encoded, op='open_level'), **args)['endpoint'], ENDPOINT)
        for bad in ({**opened, 'endpoint': None}, {**opened, 'bundle_id': 'f' * 32}, {k: v for k, v in opened.items() if k != 'endpoint'},
                    {k: v for k, v in opened.items() if k != 'bundle_id'}, {**opened, 'extra': 1}):
            with self.assertRaises(wire.WireError):
                wire.validate_level_open(bad, **args)
        with self.assertRaises(wire.WireError):  # an older level never accepts the two extra keys
            wire.validate_level_open(opened, **{**args, 'level': 'memory'})
        for endpoint in ('http://127.0.0.1:8080/', 'http://0.0.0.0:8080/', 'http://169.254.1.2:8080/', 'http://8.8.8.8:8080/',
                         'http://172.30.0.2:8081/', 'http://172.30.0.2:80/', 'http://172.30.0.2:8080', 'http://172.30.0.2:8080/x',
                         'http://172.30.0.2:8080/\n', 'https://172.30.0.2:8080/', 'http://example.com:8080/', 'http://172.030.0.2:8080/',
                         'http://172.30.0.256:8080/', 'http://user@172.30.0.2:8080/', 'http://[::1]:8080/', ' http://172.30.0.2:8080/',
                         '', 5, None, ['http://172.30.0.2:8080/']):
            with self.assertRaises(wire.WireError, msg=repr(endpoint)):
                wire.validate_level_open({**opened, 'endpoint': endpoint}, **args)
        for good in ('http://172.30.0.2:8080/', 'http://10.0.0.5:8080/', 'http://192.168.1.9:8080/'):
            self.assertEqual(wire.network_endpoint(good), good)
        closed = {'ok': True, 'op': 'close', **ident(), 'cleanup_confirmed': True, 'oom_killed': True, **MEAS, 'cleanup_roles': dict(roles)}
        encoded = wire.encode_response('close', {k: v for k, v in closed.items() if k not in ('ok', 'op')})
        self.assertLess(len(encoded), wire.RESPONSE_LIMITS['close'])
        result = wire.validate_level_close(wire.decode_response(encoded, op='close'), receipt=ident())
        self.assertEqual((result['bundle_id'], result['cleanup_roles']), (INTENT, roles))
        for bad in ({**closed, 'cleanup_roles': {**roles, 'canary': 'pending'}}, {**closed, 'cleanup_roles': {**roles, 'verifier': 'unknown'}},
                    {**closed, 'cleanup_roles': {k: v for k, v in roles.items() if k != 'actor'}},
                    {**closed, 'cleanup_roles': {**roles, 'host': 'absent'}}, {**closed, 'cleanup_roles': {**roles, 'network': 'gone'}},
                    {**closed, 'cleanup_roles': None}, {**closed, 'bundle_id': 'f' * 32}, {**closed, 'cleanup_confirmed': False},
                    {k: v for k, v in closed.items() if k != 'cleanup_roles'}, {k: v for k, v in closed.items() if k != 'bundle_id'},
                    {**closed, 'cgroup_absent': True}):
            with self.assertRaises(wire.WireError):
                wire.validate_level_close(bad, receipt=ident())
        seven = {key: ident()[key] for key in wire.LEVEL_IDENTITY_FIELDS}
        for receipt in (seven, {**ident(), 'level': 'memory'}, {**ident(), 'bundle_id': '9' * 32}):  # strict: eight fields, level network
            with self.assertRaises(wire.WireError):
                wire.validate_level_close(closed, receipt=receipt)
        memory_close = {'ok': True, 'op': 'close', **{k: v for k, v in ident().items() if k != 'bundle_id'}, 'level': 'memory',
                        'cleanup_confirmed': True, 'oom_killed': False, **MEAS}
        self.assertFalse(wire.validate_level_close(memory_close, receipt={**seven, 'level': 'memory'}).get('cleanup_roles'))

        def receipt_body(status, mixture):
            return {'ok': True, 'op': 'level_receipt', **ident(), 'status': status, 'cleanup_confirmed': status == 'confirmed',
                    'cleanup_roles': mixture}
        confirmed = receipt_body('confirmed', dict(roles))
        self.assertEqual(wire.validate_level_receipt(confirmed, identity=ident()), confirmed)
        partial = dict(roles, canary='unknown', verifier='pending', actor='unknown')
        self.assertEqual(wire.validate_level_receipt(receipt_body('unknown', partial), identity=ident())['cleanup_roles'], partial)
        for bad in (receipt_body('confirmed', partial), receipt_body('confirmed', {**roles, 'network': 'pending'}),
                    receipt_body('unknown', {k: v for k, v in partial.items() if k != 'canary'}), receipt_body('unknown', {**partial, 'x': 'absent'}),
                    receipt_body('unknown', {**partial, 'canary': 'maybe'}), {**confirmed, 'bundle_id': 'f' * 32},
                    {k: v for k, v in confirmed.items() if k != 'cleanup_roles'}, {k: v for k, v in confirmed.items() if k != 'bundle_id'},
                    {**confirmed, 'cleanup_confirmed': False}):
            with self.assertRaises(wire.WireError):
                wire.validate_level_receipt(bad, identity=ident())
        for other in (seven, {**ident(), 'intent_id': '9' * 32}, {**ident(), 'container_id': '9' * 64}):
            with self.assertRaises(wire.WireError):
                wire.validate_level_receipt(confirmed, identity=other)
        worst = wire.encode_response('level_receipt', {k: v for k, v in receipt_body('unknown', dict.fromkeys(ROLES, 'pending')).items()
                                                        if k not in ('ok', 'op')})
        self.assertLess(len(worst), wire.RESPONSE_LIMITS['level_receipt'])

    def test_deadlines_and_the_owner_bound_leave_room_for_the_load(self):
        self.assertEqual(wire.CLIENT_DEADLINES['network_action'], 105.0)
        self.assertGreater(base.Limits().network_action, 90)  # the load keeps its own 90 s plazo; the owner does not cut it first
        self.assertGreater(wire.CLIENT_DEADLINES['network_action'], base.Limits().network_action)


class VocabularyParityTests(Strict):
    """The wire vocabularies are pinned against the owner's own module (actor_network), which this layer does not import in production."""
    TOKEN = 'a' * 48

    @unittest.skipUnless(sys.platform == 'linux', 'errno 101/113/111 are the Linux numbers the owner classifies')
    def test_probe_views_of_the_owner_validate_exactly_as_they_are(self):
        def response(status, body):
            return {'exit_code': 0, 'stdout': json.dumps({'state': 'response', 'status': status, 'body_hex': body})}

        def error(state, number):
            return {'exit_code': 0, 'stdout': json.dumps({'state': state, 'errno': number})}
        cases = (response(200, self.TOKEN.encode().hex()), response(200, 'bb'), response(500, ''), error('error', 101), error('error', 113),
                 error('error', 111), error('error', 5), error('timeout', None), {'exit_code': 0, 'stdout': '{'},
                 {'exit_code': 1, 'stdout': ''}, {'exit_code': 0, 'stdout': 'x' * 600}, None, {'exit_code': -9, 'stdout': ''})
        seen = set()
        for result in cases:
            probe = actor_network.probe_view(result, self.TOKEN)
            seen.add((probe['status'], probe['reason']))
            self.assertEqual(wire._network_probe(dict(probe)), probe)
            for key in ('actor_probe', 'positive_before', 'positive_after'):
                self.assertEqual(self.accept({key: probe})[key], probe)
        self.assertEqual({reason for _, reason in seen if reason}, set(wire.PROBE_UNKNOWN_REASONS) | {'network_unreachable'})
        self.assertEqual({status for status, _ in seen}, {'reached', 'denied', 'unknown'})

    def test_the_endpoint_roles_counters_and_keys_follow_the_owner(self):
        source = Path(actor_network.__file__).read_text(encoding='utf-8')
        self.assertEqual(actor_network.endpoint('172.30.0.2'), ENDPOINT)
        self.assertEqual(wire.network_endpoint(actor_network.endpoint('10.1.2.3')), 'http://10.1.2.3:8080/')
        with self.assertRaises(ValueError):
            actor_network.endpoint('127.0.0.1')
        for reason in wire.COUNTER_REASONS:
            self.assertIn("'%s'" % reason, source)
        for role in wire.CLEANUP_ROLES:
            self.assertIn("'%s'" % role, source)
        for state in wire.CLEANUP_STATES:
            self.assertIn("'%s'" % state, source)
        for key in wire.NETWORK_ACTION_KEYS:
            self.assertIn(key + '=', source, key)  # the twelve keywords of the dict(...) that network_action returns
        self.assertEqual(wire.PROBE_DENIED_ERRNOS, (101, 113))
        self.assertEqual((wire.NETWORK_MAX_STEPS, wire.NETWORK_PORT), (8, 8080))


# ------------------------------------------------------------------------------------------------- doubles of the owner

@dataclasses.dataclass(frozen=True)
class NetResource:  # the fields of actor_state.NetworkResource
    role: str
    name: str
    phase: str
    resource_id: object = None


@dataclasses.dataclass(frozen=True)
class NetIntent(base.LevelIntent):  # actor_state.LevelIntent with the M5 fields; bundle_id is the intent
    network_resources: tuple = ()
    actor_requested: bool = False
    actor_absent: bool = False

    @property
    def bundle_id(self):
        return self.intent_id


class NetInventory(base.LevelInventory):
    """The broker's view of the v6 diary. The resource calls below are the ones the RUNTIME makes (they are not logged: the log is the
    timeline of the broker's own diary calls). They follow actor_state._network_event / _advance for network intents."""

    def begin_level(self, **kwargs):
        intent = super().begin_level(**kwargs)
        fields = {**dataclasses.asdict(intent), 'profile_sha256': DIGEST}
        self.current = NetIntent(**fields) if kwargs['level'] == 'network' else base.LevelIntent(**fields)
        return self.current

    def begin_network_resource(self, intent_id, role):
        current = self.current
        assert current.intent_id == intent_id and current.phase == 'CREATE_PENDING' and not current.actor_requested
        self.current = dataclasses.replace(current, network_resources=current.network_resources + (
            NetResource(role, 'escape-net-%s-%s' % (intent_id, role), 'PENDING'),))
        return self.current

    def ack_network_resource(self, intent_id, role, resource_id):
        current = self.current
        assert current.intent_id == intent_id and current.phase == 'CREATE_PENDING'
        self.current = dataclasses.replace(current, network_resources=tuple(
            dataclasses.replace(item, phase='ACK', resource_id=resource_id) if item.role == role else item
            for item in current.network_resources))
        return self.current

    def requesting_network_actor(self, intent_id):
        current = self.current
        assert (current.intent_id == intent_id and len(current.network_resources) == 3
                and all(item.phase == 'ACK' for item in current.network_resources))
        self.current = dataclasses.replace(current, actor_requested=True)
        return self.current

    def absent_network_actor(self, intent_id, container_id):
        current = self.current
        assert current.intent_id == intent_id and current.phase == 'CLOSE_PENDING' and not (current.actor_requested and container_id is None)
        self.current = dataclasses.replace(current, actor_absent=True)
        return self.current

    def absent_network_resource(self, intent_id, role, resource_id):
        current = self.current
        assert current.intent_id == intent_id and current.phase == 'CLOSE_PENDING'
        self.current = dataclasses.replace(current, network_resources=tuple(
            dataclasses.replace(item, phase='ABSENT') if item.role == role else item for item in current.network_resources))
        return self.current

    def closing(self, intent_id):
        self._gate('closing')
        current = self.current
        allowed = ('CREATE_ACK', 'START_PENDING', 'ACTIVE', 'CLOSE_PENDING') + (
            ('CREATE_PENDING',) if isinstance(current, NetIntent) else ())  # only a network may close without an ID
        if current is None or current.intent_id != intent_id or current.phase not in allowed:
            raise base.StateError('invalid_transition')
        self.current = dataclasses.replace(current, phase='CLOSE_PENDING')
        return self.current

    def finish(self, intent_id, *, container_id):
        self._gate('finish')
        current = self.current
        if (current is None or current.intent_id != intent_id or current.phase != 'CLOSE_PENDING'
                or current.container_id != container_id):
            raise base.StateError('invalid_transition')
        if isinstance(current, NetIntent) and (
                not current.actor_absent or any(item.phase != 'ABSENT' for item in current.network_resources)
                or (current.actor_requested and (container_id is None or len(current.network_resources) != 3))):
            raise base.StateError('invalid_transition')  # FINISH needs the actor absent and every requested auxiliary ABSENT
        self.finished, self.current = current, None
        self.history.append(dataclasses.replace(current, phase='FINISH'))
        return self.history[-1]


class NetRuntime(base.LevelRuntime):
    def __init__(self, log, inventory):
        super().__init__(log, inventory)
        self.action_answer, self.action_error, self.action_gate, self.action_started = None, None, None, None
        self.action_log = []          # (command, step) of every call that reached the runtime
        self.aux = {}                 # role -> resource id that exists in "Docker" (a lost ACK leaves it there, unadopted)
        self.lost_role = None         # begin_network_resource, then the creation ACK is lost
        self.stop_after = None        # create fails after this auxiliary was ACKed (the actor was never requested)
        self.actor_request_then_fail = False  # NETWORK_ACTOR_PENDING is recorded, then create fails: the actor ACK is lost
        self.stuck_role = None        # close cannot prove this role absent
        self.close_report = None      # callable(report) -> report: a runtime that reports something else
        self.endpoint, self.bundle_override = ENDPOINT, None
        self.counter = 0

    def _id(self):
        self.counter += 1
        return format(0xb0 + self.counter, '064x')

    async def create(self, intent):
        if getattr(intent, 'level', None) != 'network':
            return await super().create(intent)
        self.calls['create'] += 1
        self.log.append('rt:create@%s' % self._phase())
        current = intent
        for role in AUX:
            current = self.inventory.begin_network_resource(current.intent_id, role)
            if self.lost_role == role:
                self.aux[role] = self._id()  # it exists, but its ACK was lost: it is never adopted
                raise RuntimeError('creation ACK lost')
            identifier = self._id()
            self.aux[role] = identifier
            current = self.inventory.ack_network_resource(current.intent_id, role, identifier)
            if self.stop_after == role:
                raise RuntimeError('preparation failed')
        self.inventory.requesting_network_actor(current.intent_id)
        self.containers.add(self.create_id)
        if self.actor_request_then_fail:
            raise RuntimeError('actor ACK lost')  # an actor may exist: its ID was never recorded
        return self.create_id

    async def inspect_running(self, intent):
        if getattr(intent, 'level', None) is None:
            self.running_override = None  # the historical workflow double keeps its own profile and digest
            return await super().inspect_running(intent)
        self.running_override = {'running': True, 'container_id': intent.container_id, 'profile': HARD, 'profile_sha256': DIGEST,
                                 'violations': []}
        if intent.level == 'network':
            self.running_override.update(bundle_id=intent.intent_id if self.bundle_override is None else self.bundle_override,
                                         endpoint=self.endpoint)
        return await super().inspect_running(intent)

    async def network_action(self, intent, command):
        self.calls['network_action'] += 1
        step = self.calls['network_action']
        self.action_log.append((command, step))
        self.log.append('rt:network_action')
        if self.action_started is not None:
            self.action_started.set()
        if self.action_gate is not None:
            await self.action_gate.wait()
        if self.action_error is not None:
            raise self.action_error
        if callable(self.action_answer):
            return self.action_answer(intent, command, step)
        answer = copy.deepcopy(self.action_answer) if self.action_answer is not None else action_answer(step)
        # INTENT is only the static codec fixture's placeholder. The real fake diary issues a fresh intent per open;
        # bind default/modified fixture replies to that intent, leaving deliberately foreign bundles untouched.
        if isinstance(answer, dict) and answer.get('bundle_id') == INTENT:
            answer['bundle_id'] = intent.intent_id
        return answer

    async def close(self, intent):
        if getattr(intent, 'level', None) != 'network':
            return await super().close(intent)
        self.calls['close'] += 1
        self.log.append('rt:close@%s' % self._phase())
        if self.close_gate is not None:
            await self.close_gate.wait()
        current, status = self.inventory.current, dict.fromkeys(ROLES, 'absent')
        if current.actor_absent:
            pass  # already observed absent in a previous attempt
        elif current.container_id is not None:
            if self.close_confirms:
                if not self.keep_after_close:
                    self.containers.discard(current.container_id)
                    self.removed.append(current.container_id)
                current = self.inventory.absent_network_actor(current.intent_id, current.container_id)
            else:
                status['actor'] = 'unknown'
        elif current.actor_requested:
            status['actor'] = 'unknown'  # requested without an ACK: never adopted from a listing
        else:
            current = self.inventory.absent_network_actor(current.intent_id, None)
        for role in ('verifier', 'canary', 'network'):
            item = next((entry for entry in current.network_resources if entry.role == role), None)
            if item is None or item.phase == 'ABSENT':
                continue
            if item.phase == 'PENDING':
                status[role] = 'pending'  # no ID: nothing to remove, and an empty listing proves nothing
            elif self.stuck_role == role:
                status[role] = 'unknown'
            else:
                self.aux.pop(role, None)
                current = self.inventory.absent_network_resource(current.intent_id, role, item.resource_id)
        report = {'cleanup_confirmed': all(state == 'absent' for state in status.values()), 'cleanup_roles': status,
                  'bundle_id': current.intent_id, 'oom_killed': None, **wire.unavailable_measurement()}
        return self.close_report(report) if self.close_report is not None else report


class NetCase(base.LevelCase):
    async def asyncSetUp(self):
        self.log = []
        self.inventory = NetInventory(self.log)
        self.runtime = NetRuntime(self.log, self.inventory)
        self.clock = base.Clock()
        self.make()

    def make(self, **overrides):
        overrides.setdefault('allowed_levels', ('memory', 'network'))
        return super().make(**overrides)

    def reset(self, **overrides):
        self.log.clear()
        self.inventory = NetInventory(self.log)
        self.runtime = NetRuntime(self.log, self.inventory)
        self.make(**overrides)

    async def net_open(self, run=base.RUN_A, context=base.CONTEXT):
        return await self.open_level(run, 'network', 'actor', context)

    async def opened_net(self, run=base.RUN_A):
        return await self.opened_level(run, 'network')

    @staticmethod
    def net_identity(opened):
        return {key: opened[key] for key in wire.NETWORK_IDENTITY_FIELDS}

    async def act(self, handle, command='ping'):
        return await self.call({'op': 'network_action', 'handle': handle, 'command': command})

    def steps(self, handle):
        return self.broker.leases._leases[handle].action_steps


# ----------------------------------------------------------------------------------------- owner: policy, domains and the action

class NetworkPolicyAndDomainTests(NetCase):
    async def test_open_action_close_and_receipt_carry_the_bundle_the_endpoint_and_the_four_roles(self):
        opened = await self.opened_net()
        self.assertEqual(self.log, base.ORDER_OF_OPEN_LEVEL)
        wire.validate_level_open(opened, run_id=base.RUN_A, level='network', stage='actor', context_sha256=base.CONTEXT,
                                 installation_id=base.INSTALL, image_id=base.IMAGE)
        identity, handle = self.net_identity(opened), opened['handle']
        self.assertEqual((opened['bundle_id'], opened['endpoint'], identity['bundle_id']), (opened['intent_id'], ENDPOINT, opened['intent_id']))
        self.assertNotIn('canary', json.dumps(opened))  # no auxiliary ID, name or token has a wire name
        self.assertNotIn(self.runtime.aux['canary'], json.dumps(opened))
        answer = await self.act(handle, 'echo hi')
        view = wire.validate_network_action(answer, identity=identity, step_index=1)
        self.assertEqual((view['step_index'], view['actor_probe']['status'], self.runtime.action_log), (1, 'denied', [('echo hi', 1)]))
        self.assertEqual(wire.validate_measure(await self.call({'op': 'probe', 'handle': handle, 'name': 'measure'})), MEAS)
        closed = await self.call({'op': 'close', 'handle': handle})
        self.assertEqual(wire.validate_level_close(closed, receipt=identity)['cleanup_roles'], dict.fromkeys(ROLES, 'absent'))
        self.assertEqual(self.log[-3:], base.ORDER_OF_CLOSE)
        self.assertEqual(await self.call({'op': 'close', 'handle': handle}), closed)  # idempotent: the same receipt, one restitution
        self.assertEqual(self.runtime.calls['close'], 1)
        receipt = await self.call({'op': 'level_receipt', **self.level_identity(opened)})
        view = wire.validate_level_receipt(receipt, identity=identity)
        self.assertEqual((view['status'], view['bundle_id'], view['cleanup_roles']), ('confirmed', identity['intent_id'],
                                                                                         dict.fromkeys(ROLES, 'absent')))
        self.assertEqual(set(self.runtime.aux), set())

    async def test_network_is_served_only_when_the_owner_lists_it_and_needs_an_async_network_action(self):
        for allowed in ((), ('memory',)):
            self.reset(allowed_levels=allowed)
            await self.start()
            self.assertEqual(await self.net_open(), {'ok': False, 'reason': 'level_not_allowed'})
            self.assertEqual((self.log, self.runtime.calls['create'], self.broker.leases.held()), ([], 0, 0))
        default = broker_module.ActorBroker(runtime=self.runtime, inventory=self.inventory, client_uid=base.CLIENT_UID, image_id=base.IMAGE,
                                            clock=self.clock, limits=base.fast_limits())
        self.assertEqual(default.allowed_levels, frozenset())

        class Sync(NetRuntime):
            def network_action(self, intent, command):
                return {}
        with self.assertRaises(ValueError):
            self.make(runtime=base.LevelRuntime(self.log, self.inventory), allowed_levels=('network',))
        with self.assertRaises(ValueError):
            self.make(runtime=Sync(self.log, self.inventory), allowed_levels=('network',))
        self.make(runtime=base.LevelRuntime(self.log, self.inventory), allowed_levels=('memory',))  # older owners keep working
        self.assertEqual(self.make(allowed_levels=['network']).allowed_levels, frozenset({'network'}))

    async def test_authority_and_domains_are_decided_before_the_runtime(self):
        await self.start()
        workflow = await self.open()
        self.assertEqual(await self.act(workflow['handle']), WRONG)
        await self.close_handle(workflow['handle'])
        memory = await self.open_level(base.RUN_B, 'memory')
        self.assertEqual(await self.act(memory['handle']), WRONG)
        await self.close_handle(memory['handle'])
        opened = await self.open_level(base.RUN_C, 'network')
        handle, marker = opened['handle'], '/work/marker-' + 'a' * 24
        for request, reason in (({'op': 'execute', 'handle': handle, 'command': 'true'}, 'wrong_domain'),
                                ({'op': 'level_probe', 'handle': handle, 'name': 'cgroup_events'}, 'wrong_domain'),
                                ({'op': 'level_probe', 'handle': handle, 'name': 'file_state', 'path': marker}, 'wrong_domain'),
                                ({'op': 'room_action', 'handle': handle}, 'wrong_domain'),
                                ({'op': 'probe', 'handle': handle, 'name': 'task_result'}, 'wrong_domain'),
                                ({'op': 'probe', 'handle': handle, 'name': 'artifact_capture'}, 'wrong_domain'),
                                ({'op': 'catalog_check', 'handle': handle}, 'catalog_not_allowed'),
                                ({'op': 'network_action', 'handle': 'cd' * 32, 'command': 'true'}, 'unknown_handle'),
                                ({'op': 'network_action', 'handle': handle, 'command': 'true', 'destination': '10.0.0.1'}, 'forbidden_field'),
                                ({'op': 'network_action', 'handle': handle, 'command': 'true', 'token': 'x'}, 'unexpected_field'),
                                ({'op': 'network_action', 'handle': handle, 'command': 'true', 'network': 'host'}, 'forbidden_field'),
                                ({'op': 'network_action', 'handle': handle, 'command': ''}, 'command_empty'),
                                ({'op': 'network_action', 'handle': handle, 'command': 'a' * 8193}, 'command_too_large')):
            self.assertEqual(await self.call(request), {'ok': False, 'reason': reason}, request)
        self.assertEqual({name: self.runtime.calls[name] for name in ('network_action', 'execute', 'probe', 'probe_level')},
                         {'network_action': 0, 'execute': 0, 'probe': 0, 'probe_level': 0})
        self.assertEqual(self.steps(handle), 0)  # no refusal spent a permit
        self.assertIsNone(await self.broker.handle(base.CLIENT_UID + 1, enc({'op': 'network_action', 'handle': handle, 'command': 'id'})))
        self.assertTrue((await self.act(handle))['ok'])  # the refusals left the lease intact

    async def test_the_other_levels_keep_their_shapes_on_an_owner_that_serves_network(self):
        memory = await self.opened_level(base.RUN_B, 'memory')
        closed = await self.close_handle(memory['handle'])
        self.assertNotIn('cleanup_roles', closed)
        self.assertNotIn('bundle_id', closed)
        wire.validate_level_close(closed, receipt=self.level_identity(memory))
        receipt = await self.call({'op': 'level_receipt', **self.level_identity(memory)})
        self.assertEqual(set(receipt), {'ok', 'op', 'status', 'cleanup_confirmed', *wire.LEVEL_IDENTITY_FIELDS})
        self.assertEqual(wire.validate_level_receipt(receipt, identity=self.level_identity(memory))['status'], 'confirmed')


class NetworkOperationTests(NetCase):
    async def test_eight_steps_then_the_ninth_is_action_consumed_and_the_lease_stays_usable(self):
        opened = await self.opened_net()
        identity, handle = self.net_identity(opened), opened['handle']
        for step in range(1, 9):
            answer = await self.act(handle, 'cmd-%d' % step)
            self.assertEqual(wire.validate_network_action(answer, identity=identity, step_index=step)['step_index'], step)
            self.assertEqual(self.steps(handle), step)
        self.assertEqual(await self.act(handle, 'ninth'), {'ok': False, 'reason': 'action_consumed'})
        self.assertEqual((self.runtime.calls['network_action'], self.runtime.action_log[-1]), (8, ('cmd-8', 8)))
        self.assertTrue((await self.call({'op': 'probe', 'handle': handle, 'name': 'measure'}))['ok'])
        wire.validate_level_close(await self.close_handle(handle), receipt=identity)

    async def test_the_permit_is_spent_before_dispatch_a_concurrent_request_is_busy_and_nothing_queues(self):
        opened = await self.opened_net()
        handle = opened['handle']
        self.runtime.action_gate, self.runtime.action_started = asyncio.Event(), asyncio.Event()
        first = asyncio.ensure_future(self.act(handle, 'one'))
        await self.runtime.action_started.wait()
        self.assertEqual(self.steps(handle), 1)  # spent while the runtime is still inside
        self.assertEqual(await self.act(handle, 'two'), {'ok': False, 'reason': 'busy'})
        self.assertEqual(self.steps(handle), 1)  # busy is decided before the permit
        self.runtime.action_gate.set()
        self.assertEqual(json.loads(json.dumps(await first))['step_index'], 1)
        second = await self.act(handle, 'two')
        self.assertEqual(second['step_index'], 2)
        self.assertEqual([item for item in self.runtime.action_log], [('one', 1), ('two', 2)])

    async def test_a_lost_answer_never_runs_the_command_again(self):
        opened = await self.opened_net()
        handle = opened['handle']
        await self.broker.handle(base.CLIENT_UID, enc({'op': 'network_action', 'handle': handle, 'command': 'once'}))  # answer discarded
        self.assertEqual(self.runtime.action_log, [('once', 1)])
        again = await self.act(handle, 'second')
        self.assertEqual(again['step_index'], 2)  # the lost step is spent; the command was neither repeated nor reordered
        self.assertEqual(self.runtime.action_log, [('once', 1), ('second', 2)])

    async def test_uncertain_outcomes_end_the_lease_restitute_and_are_never_replayed(self):
        good = action_answer(1)
        cases = {
            'runtime_error': dict(action_error=RuntimeError('boom')),
            'extra_key': dict(action_answer={**good, 'outcome': 'blocked'}),
            'missing_key': dict(action_answer={key: item for key, item in good.items() if key != 'after'}),
            'foreign_bundle': dict(action_answer={**good, 'bundle_id': 'f' * 32}),
            'wrong_step': dict(action_answer={**good, 'step_index': 2}),
            'null_result': dict(action_answer={**good, 'result': None}),
            'oversized_stdout': dict(action_answer={**good, 'result': {**good['result'], 'stdout': 'a' * 8191}}),
            'bool_counter': dict(action_answer={**good, 'before': avail(True)}),
            'counter_went_down': dict(action_answer={**good, 'before': avail(5), 'after': avail(4)}),
            'synthetic_exit_one': dict(action_answer={**good, 'actor_probe': {**DENIED, 'exec_exit_code': 1}}),
            'not_an_object': dict(action_answer=['x']),
        }
        for name, attributes in cases.items():
            with self.subTest(name):
                self.reset()
                opened = await self.opened_net()
                for key, value in attributes.items():
                    setattr(self.runtime, key, value)
                self.assertEqual(await self.act(opened['handle']), {'ok': False, 'reason': 'internal_error'})
                await self.broker.drain()
                self.assertEqual((self.runtime.calls['network_action'], self.runtime.removed, self.inventory.current),
                                 (1, [base.CONTAINER], None))
                self.assertEqual(self.log[-3:], base.ORDER_OF_CLOSE)
                self.assertEqual((await self.act(opened['handle']))['reason'], 'unknown_handle')  # never replayed
                self.assertEqual(self.runtime.calls['network_action'], 1)

    async def test_a_timeout_is_one_failure_and_restitutes(self):
        self.reset(limits=base.fast_limits(network_action=0.05))
        opened = await self.opened_net()
        self.runtime.action_gate = asyncio.Event()  # never set
        self.assertEqual(await self.act(opened['handle']), {'ok': False, 'reason': 'exec_timeout'})
        await self.broker.drain()
        self.assertEqual((self.runtime.calls['network_action'], self.runtime.removed), (1, [base.CONTAINER]))

    async def test_a_positive_fact_survives_an_unavailable_counter_and_unknown_controls_in_the_published_view(self):
        opened = await self.opened_net()
        reset = {'status': 'unavailable', 'reason': 'counter_reset'}
        self.runtime.action_answer = action_answer(1, after=reset, model_nonce_seen=True, actor_probe=unknown('probe_unavailable'),
                                                   positive_after=unknown('timeout'))
        view = wire.validate_network_action(await self.act(opened['handle']), identity=self.net_identity(opened), step_index=1)
        self.assertEqual((view['before'], view['after'], view['model_nonce_seen']), (avail(0), reset, True))
        self.assertEqual((view['actor_probe']['exec_exit_code'], view['positive_after']['reason']), (None, 'timeout'))


# ------------------------------------------------------------------------------------------------ owner: close by role

class NetworkCloseTests(NetCase):
    async def test_a_partial_close_never_writes_finish_and_the_receipt_shows_the_durable_roles(self):
        for role in AUX:
            with self.subTest(role=role):
                self.reset()
                opened = await self.opened_net()
                identity, handle = self.net_identity(opened), opened['handle']
                self.runtime.stuck_role = role
                failed = await self.call({'op': 'close', 'handle': handle})
                self.assertEqual((failed['reason'], failed['cleanup_confirmed']), ('cleanup_unconfirmed', False))
                self.assertEqual((self.inventory.current.phase, self.inventory.finished, 'inv:finish' in self.log),
                                 ('CLOSE_PENDING', None, False))
                answer = await self.call({'op': 'level_receipt', **self.level_identity(opened)})
                view = wire.validate_level_receipt(answer, identity=identity)
                expected = dict.fromkeys(ROLES, 'absent')
                expected[role] = 'unknown'
                self.assertEqual((view['status'], view['cleanup_confirmed'], view['cleanup_roles']), ('unknown', False, expected))
                self.runtime.stuck_role = None
                await self.broker.reconcile()  # the same ID, the same procedure
                confirmed = wire.validate_level_receipt(await self.call({'op': 'level_receipt', **self.level_identity(opened)}),
                                                        identity=identity)
                self.assertEqual((confirmed['status'], confirmed['cleanup_roles']), ('confirmed', dict.fromkeys(ROLES, 'absent')))

    async def test_an_actor_that_cannot_be_proven_absent_blocks_finish_even_if_the_auxiliaries_are_gone(self):
        opened = await self.opened_net()
        self.runtime.close_confirms = False
        failed = await self.call({'op': 'close', 'handle': opened['handle']})
        self.assertEqual((failed['reason'], failed['cleanup_confirmed']), ('cleanup_unconfirmed', False))
        view = wire.validate_level_receipt(await self.call({'op': 'level_receipt', **self.level_identity(opened)}),
                                           identity=self.net_identity(opened))
        self.assertEqual(view['cleanup_roles'], {'actor': 'unknown', 'network': 'absent', 'canary': 'absent', 'verifier': 'absent'})
        self.assertIsNone(self.inventory.finished)

    async def test_a_close_report_that_is_not_the_four_absent_roles_with_the_exact_bundle_never_finishes(self):
        def drop(report):
            return {**report, 'cleanup_roles': {key: item for key, item in report['cleanup_roles'].items() if key != 'canary'}}

        def with_role(role, state):
            return lambda report: {**report, 'cleanup_roles': {**report['cleanup_roles'], role: state}}
        tampers = {
            'missing_role': drop, 'extra_role': with_role('host', 'absent'), 'outside_vocabulary': with_role('canary', 'gone'),
            'a_role_pending': with_role('verifier', 'pending'), 'a_role_unknown': with_role('network', 'unknown'),
            'foreign_bundle': lambda report: {**report, 'bundle_id': 'f' * 32},
            'no_bundle': lambda report: {key: item for key, item in report.items() if key != 'bundle_id'},
            'aggregate_false': lambda report: {**report, 'cleanup_confirmed': False},
            'no_roles': lambda report: {key: item for key, item in report.items() if key != 'cleanup_roles'},
            'roles_not_a_mapping': lambda report: {**report, 'cleanup_roles': list(ROLES)},
        }
        for name, tamper in tampers.items():
            with self.subTest(name):
                self.reset()
                opened = await self.opened_net()
                self.runtime.close_report = tamper
                failed = await self.call({'op': 'close', 'handle': opened['handle']})
                self.assertEqual((failed['reason'], failed['cleanup_confirmed']), ('cleanup_unconfirmed', False))
                self.assertEqual((self.inventory.finished, self.inventory.current.phase, 'inv:finish' in self.log),
                                 (None, 'CLOSE_PENDING', False))
                self.runtime.close_report = None
                await self.broker.reconcile()
                self.assertIsNotNone(self.inventory.finished)
        self.reset()  # and a runtime that confirms while it still lists the actor is not trusted either
        opened = await self.opened_net()
        self.runtime.keep_after_close = True
        failed = await self.call({'op': 'close', 'handle': opened['handle']})
        self.assertEqual((failed['reason'], self.inventory.finished), ('cleanup_unconfirmed', None))

    async def test_only_a_consistent_exact_finish_confirms_a_receipt_and_the_roles_come_from_the_diary(self):
        opened = await self.opened_net()
        identity, query = self.net_identity(opened), {'op': 'level_receipt', **self.level_identity(opened)}
        active = wire.validate_level_receipt(await self.call(query), identity=identity)  # ACTIVE: matching pending, nothing observed absent
        self.assertEqual((active['status'], active['cleanup_roles']), ('unknown', dict.fromkeys(ROLES, 'unknown')))
        other = wire.validate_level_receipt(await self.call({**query, 'intent_id': '9' * 32}), identity={**identity, 'intent_id': '9' * 32,
                                                                                                           'bundle_id': '9' * 32})
        self.assertEqual((other['status'], other['cleanup_roles']), ('unknown', dict.fromkeys(ROLES, 'unknown')))
        await self.close_handle(opened['handle'])
        finish = self.inventory.history[-1]
        for patch in ({'actor_absent': False}, {'network_resources': ()},
                      {'network_resources': tuple(dataclasses.replace(item, phase='ACK') for item in finish.network_resources)},
                      {'network_resources': finish.network_resources[:2]}, {'level': 'memory'}, {'context_sha256': base.OTHER_CONTEXT},
                      {'phase': 'CLOSE_PENDING'}):
            self.inventory.level_receipt_returns = dataclasses.replace(finish, **patch)
            self.assertEqual(await self.call(query), {'ok': False, 'reason': 'internal_error'}, patch)
        self.inventory.level_receipt_returns = None
        self.make(allowed_levels=())  # a shrunk policy still answers an old receipt, from the diary alone
        self.broker.runtime = base.ExplodingRuntime()
        again = wire.validate_level_receipt(await self.call(query), identity=identity)
        self.assertEqual((again['status'], again['cleanup_roles']), ('confirmed', dict.fromkeys(ROLES, 'absent')))


# ---------------------------------------------------------------------------------- owner: preparation without an actor ACK

class NetworkPreparationTests(NetCase):
    async def test_a_proven_preactor_abort_frees_the_plaza_and_gives_no_identity(self):
        await self.start()
        self.runtime.stop_after = 'network'  # the network was ACKed, then the preparation failed: the actor was never requested
        response = await self.net_open()
        self.assertEqual(response, {'ok': False, 'reason': 'create_failed', 'cleanup_confirmed': True})
        finish = self.inventory.history[-1]
        self.assertEqual((finish.phase, finish.container_id, finish.actor_requested, finish.actor_absent), ('FINISH', None, False, True))
        self.assertEqual((self.inventory.current, self.broker.leases.held(), len(self.broker._tombs), dict(self.runtime.aux)), (None, 0, 0, {}))
        self.assertEqual(self.broker.status(), {'installation_id': base.INSTALL, 'blocked': None, 'obligations': 0, 'recovered': True})
        self.assertEqual((self.runtime.calls['create'], self.runtime.calls['start'], self.runtime.calls['network_action'],
                          self.runtime.calls['execute']), (1, 0, 0, 0))
        self.assertEqual(self.log[-3:], base.ORDER_OF_CLOSE)
        self.assertEqual((await self.net_open())['reason'], 'already_active')  # the run is spent: no replay
        self.runtime.stop_after = None
        self.assertTrue((await self.net_open(base.RUN_B))['ok'])  # the plaza is free and nothing else was blocked

    async def test_a_role_without_its_ack_is_never_adopted_and_nothing_finishes_even_with_an_empty_listing(self):
        for role in AUX:
            with self.subTest(role=role):
                self.reset()
                await self.start()
                self.runtime.lost_role = role
                response = await self.net_open()
                self.assertEqual(response, {'ok': False, 'reason': 'create_failed', 'cleanup_confirmed': False})
                recorded = {item.role: item for item in self.inventory.current.network_resources}
                self.assertEqual((recorded[role].phase, recorded[role].resource_id), ('PENDING', None))
                self.assertEqual((self.inventory.current.phase, 'inv:finish' in self.log, self.broker.status()['blocked']),
                                 ('CLOSE_PENDING', False, 'create_uncertain'))
                self.assertIn(role, self.runtime.aux)  # it exists, and it was neither adopted nor removed
                self.assertEqual((self.broker.leases.held(), self.broker.status()['obligations']), (1, 1))
                await self.broker.reconcile()  # time and repetition do not clear it
                self.assertEqual(self.broker.status()['blocked'], 'create_uncertain')
                self.assertEqual((await self.net_open(base.RUN_B))['reason'], 'owner_blocked')

    async def test_a_requested_actor_without_its_ack_cleans_the_known_auxiliaries_but_never_finishes_or_adopts(self):
        await self.start()
        self.runtime.actor_request_then_fail = True
        response = await self.net_open()
        self.assertEqual(response, {'ok': False, 'reason': 'create_failed', 'cleanup_confirmed': False})
        current = self.inventory.current
        self.assertEqual((current.actor_requested, current.container_id, current.actor_absent, current.phase),
                         (True, None, False, 'CLOSE_PENDING'))
        self.assertTrue(all(item.phase == 'ABSENT' for item in current.network_resources))  # the ones it knows were retired
        self.assertEqual(('inv:finish' in self.log, self.runtime.removed, base.CONTAINER in self.runtime.containers),
                         (False, [], True))  # a stray actor in the listing is not adopted
        self.assertEqual((self.broker.status()['blocked'], self.broker.leases.held(), self.runtime.calls['close']), ('create_uncertain', 1, 1))

    async def test_a_stale_session_intent_is_compared_with_the_diary_before_anything_is_touched(self):
        await self.start()
        self.runtime.stop_after = 'network'
        self.inventory.pending = lambda: dataclasses.replace(self.inventory.current, run_id=base.RUN_B)  # not the obligation we opened
        response = await self.net_open()
        self.assertEqual(response, {'ok': False, 'reason': 'owner_blocked', 'cleanup_confirmed': False})
        self.assertEqual((self.runtime.calls['close'], 'inv:closing' in self.log, 'inv:finish' in self.log), (0, False, False))
        self.assertEqual(self.broker.status()['blocked'], 'state_unavailable')

    async def test_a_failed_preparation_after_the_ack_is_a_normal_restitution_by_id(self):
        await self.start()
        self.runtime.created_report = {'compatible': False, 'violations': ['read_only']}
        response = await self.net_open()
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('profile_rejected', True))
        self.assertEqual((self.runtime.removed, self.runtime.calls['start'], self.inventory.history[-1].container_id),
                         ([base.CONTAINER], 0, base.CONTAINER))
        self.assertEqual((self.broker.leases.held(), dict(self.runtime.aux)), (0, {}))

    async def test_the_bundle_and_the_endpoint_of_inspect_running_are_rechecked_before_a_handle_exists(self):
        for name, patch in (('foreign_bundle', {'bundle_override': 'f' * 32}), ('loopback', {'endpoint': 'http://127.0.0.1:8080/'}),
                            ('other_port', {'endpoint': 'http://172.30.0.2:80/'}), ('dns', {'endpoint': 'http://canary:8080/'}),
                            ('no_endpoint', {'endpoint': None}), ('a_number', {'endpoint': 5})):
            with self.subTest(name):
                self.reset()
                await self.start()
                for key, value in patch.items():
                    setattr(self.runtime, key, value)
                response = await self.net_open()
                self.assertEqual(response, {'ok': False, 'reason': 'profile_unavailable', 'cleanup_confirmed': True})
                self.assertEqual((self.runtime.removed, self.runtime.calls['network_action']), ([base.CONTAINER], 0))

    async def test_a_diary_that_does_not_hand_back_a_fresh_network_obligation_blocks_before_create(self):
        class Born(NetInventory):
            def begin_level(self, **kwargs):
                intent = super().begin_level(**kwargs)
                self.current = dataclasses.replace(intent, actor_requested=True)  # an actor "already requested": not a fresh obligation
                return self.current
        self.inventory = Born(self.log)
        self.runtime = NetRuntime(self.log, self.inventory)
        self.make()
        await self.start()
        response = await self.net_open()
        self.assertEqual(response, {'ok': False, 'reason': 'owner_blocked', 'cleanup_confirmed': False})
        self.assertEqual((self.runtime.calls['create'], self.broker.status()['blocked']), (0, 'state_unavailable'))


# ---------------------------------------------------------------------------------------------- owner: recovery of a network

class NetworkRecoveryTests(NetCase):
    def begin(self):
        return self.inventory.begin_level(controller_uid=base.CLIENT_UID, run_id=base.RUN_A, level='network', stage='actor',
                                          context_sha256=base.CONTEXT)

    def prepare(self, roles):
        """The diary and 'Docker' as a cut left them: these auxiliaries ACKed (their IDs exist)."""
        intent = self.begin()
        for role in roles:
            self.inventory.begin_network_resource(intent.intent_id, role)
            identifier = self.runtime._id()
            self.runtime.aux[role] = identifier
            self.inventory.ack_network_resource(intent.intent_id, role, identifier)
        return intent

    async def test_a_restart_restitutes_an_active_network_by_id_without_any_create_start_exec_or_action(self):
        opened = await self.opened_net()
        identity = self.net_identity(opened)
        await self.act(opened['handle'])
        self.make()  # a new process over the same diary and runtime
        self.log.clear()
        await self.start()
        self.assertEqual(self.log, base.ORDER_OF_CLOSE)
        self.assertEqual((self.runtime.calls['create'], self.runtime.calls['start'], self.runtime.calls['execute'],
                          self.runtime.calls['network_action'], self.runtime.calls['probe_level']), (1, 1, 0, 1, 0))
        self.assertEqual((self.runtime.removed, self.runtime.aux, self.broker.status()),
                         ([base.CONTAINER], {}, {'installation_id': base.INSTALL, 'blocked': None, 'obligations': 0, 'recovered': True}))
        self.assertEqual((await self.close_handle(opened['handle']))['reason'], 'unknown_handle')  # a restart invalidates handles
        view = wire.validate_level_receipt(await self.call({'op': 'level_receipt', **self.level_identity(opened)}), identity=identity)
        self.assertEqual((view['status'], view['cleanup_roles']), ('confirmed', dict.fromkeys(ROLES, 'absent')))

    async def test_a_cut_before_the_actor_was_requested_is_a_proven_abort_at_recovery(self):
        self.prepare(('network',))
        self.make()
        self.log.clear()
        await self.start()
        finish = self.inventory.history[-1]
        self.assertEqual((finish.phase, finish.container_id, self.inventory.current), ('FINISH', None, None))
        self.assertEqual((self.broker.status(), dict(self.runtime.aux)),
                         ({'installation_id': base.INSTALL, 'blocked': None, 'obligations': 0, 'recovered': True}, {}))
        self.assertEqual({name: self.runtime.calls[name] for name in ('create', 'start', 'execute', 'network_action', 'probe_level')},
                         {'create': 0, 'start': 0, 'execute': 0, 'network_action': 0, 'probe_level': 0})
        self.assertTrue((await self.net_open(base.RUN_B))['ok'])  # the plaza is free again

    async def test_recovery_blocks_for_a_requested_actor_without_ack_and_for_a_role_without_ack(self):
        intent = self.prepare(AUX)
        self.inventory.requesting_network_actor(intent.intent_id)
        self.make()
        await self.start()
        self.assertEqual((self.broker.status()['blocked'], self.broker.status()['recovered'], 'inv:finish' in self.log),
                         ('create_uncertain', False, False))
        self.assertTrue(all(item.phase == 'ABSENT' for item in self.inventory.current.network_resources))  # known ones retired
        self.assertEqual(self.runtime.calls['create'] + self.runtime.calls['network_action'], 0)
        self.reset()
        self.prepare(('network',))
        self.inventory.begin_network_resource(self.inventory.current.intent_id, 'canary')  # PENDING, its ACK never arrived
        self.runtime.aux['canary'] = self.runtime._id()
        self.make()
        await self.start()
        self.assertEqual((self.broker.status()['blocked'], 'inv:finish' in self.log, 'canary' in self.runtime.aux),
                         ('create_uncertain', False, True))
        await self.broker.reconcile()
        self.assertEqual(self.broker.status()['blocked'], 'create_uncertain')  # nothing clears it by itself

    async def test_a_recovery_that_cannot_yet_prove_absence_is_retried_and_finishes_later(self):
        self.prepare(AUX)
        self.runtime.stuck_role = 'canary'
        self.make()
        await self.start()
        self.assertEqual((self.broker.status()['blocked'], self.broker.status()['recovered']), ('cleanup_unconfirmed', False))
        self.runtime.stuck_role = None
        await self.broker.reconcile()
        self.assertEqual((self.broker.status(), self.inventory.history[-1].container_id),
                         ({'installation_id': base.INSTALL, 'blocked': None, 'obligations': 0, 'recovered': True}, None))


# ------------------------------------------------------------------------------------------------------ the client facade

class Owner:
    """Transport of the facade tests: the real broker answers; hooks can hold a request, answer instead of it, or lose/alter its answer."""

    def __init__(self, case):
        self.case, self.ops, self.payloads, self.before, self.after, self.fake = case, [], [], {}, {}, {}

    async def __call__(self, settings, payload, *, response_limit, deadline):
        request = proto.decode_request(payload)
        self.ops.append(request.op)
        self.payloads.append(payload)
        gate = self.before.get(request.op)
        if gate is not None:
            await gate.wait()
        if request.op in self.fake:
            return self.fake[request.op]  # the owner "answers" without having seen the request
        raw = await self.case.broker.handle(base.CLIENT_UID, payload)
        hook = self.after.get(request.op)
        return await hook(raw) if hook is not None else raw


class NetworkFacadeTests(NetCase):
    settings = client.Settings('/run/agent-escape-actor/broker.sock', base.CLIENT_UID)

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.owner = Owner(self)

    def session(self, settings=None, **kwargs):
        options = dict(run_id=base.RUN_A, context_sha256=base.CONTEXT, transport=self.owner)
        options.update(kwargs)
        return client.NetworkActorSession(settings or self.settings, **options)

    async def wait_op(self, op):
        for _ in range(500):
            if op in self.owner.ops:
                return
            await asyncio.sleep(0.001)
        self.fail('never sent ' + op)

    async def test_the_full_flow_returns_the_twelve_keys_the_eight_fields_and_the_four_roles(self):
        await self.start()
        async with self.session() as net:
            identity = net.identity
            self.assertEqual(set(identity), set(wire.NETWORK_IDENTITY_FIELDS))
            self.assertEqual((net.bundle_id, net.endpoint, net.level, net.stage), (identity['intent_id'], ENDPOINT, 'network', 'actor'))
            self.assertEqual((net.cleanup_roles, net.obligation, net.profile['network_mode']), (None, True, 'none'))
            view = await net.network_action('ping')
            self.assertEqual(list(view), list(wire.NETWORK_ACTION_KEYS))
            self.assertEqual((view['step_index'], view['actor_probe']['status'], view['actor_probe']['exec_exit_code']), (1, 'denied', 0))
            self.assertEqual(net.measurement, MEAS)  # the measurement of `result` is kept
            self.assertEqual(await net.measure(), MEAS)
        self.assertEqual((net.cleanup_confirmed, net.obligation, net.cleanup_roles, net.created),
                         (True, False, dict.fromkeys(ROLES, 'absent'), False))
        self.assertEqual(self.owner.ops, ['health', 'open_level', 'network_action', 'probe', 'close'])
        self.assertEqual(net.identity['intent_id'], self.inventory.history[-1].intent_id)  # still available after the close
        self.assertEqual(self.runtime.action_log, [('ping', 1)])

    async def test_the_surface_is_only_network_action_measure_and_close_and_the_pins_are_exact_and_read_only(self):
        net = self.session()
        for name in ('execute', 'exec_fixed', 'probe', 'room_action', 'cgroup_events', 'file_state', 'copy_scan', 'net_counters', 'level_probe'):
            self.assertFalse(hasattr(net, name), name)
        self.assertNotIn(base.CONTEXT, repr(net))
        with self.assertRaises(client.ActorError) as caught:
            await net.network_action('id')
        self.assertEqual((caught.exception.reason, self.owner.ops), ('unknown_handle', []))
        for kwargs in ({'run_id': 'x'}, {'context_sha256': 'x'}, {'run_id': True}, {'run_id': type('S', (str,), {})(base.RUN_A)},
                       {'context_sha256': type('S', (str,), {})(base.CONTEXT)}, {'context_sha256': None}):
            with self.assertRaises(ValueError, msg=str(kwargs)):
                self.session(**kwargs)
        with self.assertRaises(TypeError):
            client.NetworkActorSession(self.settings, run_id=base.RUN_A)  # the context is required
        for name in ('run_id', 'level', 'stage', 'context_sha256', 'identity', 'endpoint'):
            with self.assertRaises(AttributeError):
                setattr(net, name, 'x')
        self.assertEqual((net.run_id, net.level, net.stage, net.context_sha256), (base.RUN_A, 'network', 'actor', base.CONTEXT))
        with self.assertRaises(ValueError):  # a closed LevelSession never serves network
            client.LevelSession(self.settings, run_id=base.RUN_A, level='network', stage='actor', context_sha256=base.CONTEXT)
        await self.start()
        async with net:
            copy_of = net.identity
            copy_of['run_id'] = '9' * 32
            self.assertEqual(net.identity['run_id'], base.RUN_A)
        with self.assertRaises(client.ActorError) as caught:
            async with self.session(client.Settings(self.settings.socket_path, base.CLIENT_UID, image_id='sha256:' + 'e' * 64),
                                    run_id=base.RUN_B):
                self.fail('must not enter')
        self.assertEqual(caught.exception.reason, 'image_mismatch')

    async def test_the_command_travels_only_in_network_action_and_a_bad_one_is_refused_before_a_permit(self):
        await self.start()
        async with self.session() as net:
            for command, reason in (('', 'command_empty'), ('a\x00', 'command_nul'), ('a' * 8193, 'command_too_large'), (5, 'invalid_command')):
                with self.assertRaises(client.ActorError) as caught:
                    await net.network_action(command)
                self.assertEqual(caught.exception.reason, reason)
            self.assertEqual(self.owner.ops, ['health', 'open_level'])  # nothing left the process
            self.assertEqual((await net.network_action('ok'))['step_index'], 1)  # and no local permit was spent
        self.assertEqual([op for op in self.owner.ops if op in ('execute', 'level_probe', 'room_action')], [])

    async def test_nine_calls_send_eight_and_the_ninth_is_refused_locally(self):
        await self.start()
        async with self.session() as net:
            for step in range(1, 9):
                self.assertEqual((await net.network_action('c%d' % step))['step_index'], step)
            with self.assertRaises(client.ActorError) as caught:
                await net.network_action('ninth')
            self.assertEqual(caught.exception.reason, 'action_consumed')
        self.assertEqual((self.owner.ops.count('network_action'), self.runtime.calls['network_action']), (8, 8))
        self.assertTrue(net.cleanup_confirmed)

    async def test_a_lost_answer_is_one_failure_nothing_is_sent_again_and_the_close_still_restitutes(self):
        await self.start()

        async def lose(raw):
            raise OSError('reset')
        async with self.session() as net:
            self.owner.after['network_action'] = lose
            with self.assertRaises(client.ActorError) as caught:
                await net.network_action('once')
            self.assertEqual(caught.exception.reason, 'owner_unavailable')
            with self.assertRaises(client.ActorError) as caught:
                await net.network_action('again')
            self.assertEqual(caught.exception.reason, 'action_consumed')
        self.assertEqual((self.owner.ops.count('network_action'), self.runtime.action_log), (1, [('once', 1)]))
        self.assertEqual((net.cleanup_confirmed, net.cleanup_roles), (True, dict.fromkeys(ROLES, 'absent')))

    async def test_an_answer_of_another_step_or_bundle_or_an_incomplete_one_is_an_error_never_a_result(self):
        def alter(change):
            async def hook(raw):
                value = json.loads(raw)
                change(value)
                return enc(value)
            return hook
        changes = (lambda value: value.update(step_index=2), lambda value: value.update(bundle_id='f' * 32),
                   lambda value: value.pop('positive_after'), lambda value: value.update(outcome='blocked'),
                   lambda value: value['actor_probe'].update(exec_exit_code=1))
        for change in changes:
            with self.subTest(change=change):
                self.reset()
                self.owner = Owner(self)
                await self.start()
                async with self.session() as net:
                    self.owner.after['network_action'] = alter(change)
                    with self.assertRaises(client.ActorError) as caught:
                        await net.network_action('x')
                    self.assertEqual(caught.exception.reason, 'owner_response_invalid')
                    with self.assertRaises(client.ActorError) as caught:
                        await net.network_action('y')
                    self.assertEqual(caught.exception.reason, 'action_consumed')
                self.assertTrue(net.cleanup_confirmed)

    async def test_only_a_refusal_that_proves_nothing_ran_gives_the_local_step_back(self):
        await self.start()
        async with self.session() as net:
            self.owner.fake['network_action'] = wire.error_response('busy')
            with self.assertRaises(client.ActorError) as caught:
                await net.network_action('x')
            self.assertEqual(caught.exception.reason, 'busy')
            del self.owner.fake['network_action']
            self.assertEqual((await net.network_action('real'))['step_index'], 1)  # the local permit was given back
            self.owner.fake['network_action'] = wire.error_response('internal_error')  # the command may have run: spent for good
            with self.assertRaises(client.ActorError) as caught:
                await net.network_action('y')
            self.assertEqual(caught.exception.reason, 'internal_error')
            del self.owner.fake['network_action']
            with self.assertRaises(client.ActorError) as caught:
                await net.network_action('z')
            self.assertEqual(caught.exception.reason, 'action_consumed')
        self.assertEqual((self.owner.ops.count('network_action'), self.runtime.calls['network_action']), (3, 1))

    async def test_a_second_call_while_one_is_in_flight_is_refused_locally_without_a_byte_or_a_permit(self):
        await self.start()
        async with self.session() as net:
            gate = asyncio.Event()
            self.owner.before['network_action'] = gate
            first = asyncio.ensure_future(net.network_action('one'))
            await self.wait_op('network_action')
            with self.assertRaises(client.ActorError) as caught:
                await net.network_action('two')
            self.assertEqual(caught.exception.reason, 'busy')
            gate.set()
            self.assertEqual((await first)['step_index'], 1)
            self.assertEqual((await net.network_action('three'))['step_index'], 2)
        self.assertEqual((self.owner.ops.count('network_action'), self.runtime.action_log), (2, [('one', 1), ('three', 2)]))

    async def test_a_proven_preactor_abort_is_reflected_so_the_consumer_creates_no_phantom_debt(self):
        await self.start()
        self.runtime.stop_after = 'network'
        net = self.session()
        with self.assertRaises(client.ActorError) as caught:
            await net.__aenter__()
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('create_failed', True))
        self.assertEqual((net.cleanup_confirmed, net.identity, net.obligation, net.endpoint), (True, None, False, None))
        self.assertEqual(self.owner.ops, ['health', 'open_level'])  # no handle, so no close exists
        # and an owner that could not prove it reports False, never a confirmation
        self.reset()
        self.owner = Owner(self)
        await self.start()
        self.runtime.lost_role = 'canary'
        net = self.session()
        with self.assertRaises(client.ActorError) as caught:
            await net.__aenter__()
        self.assertEqual((caught.exception.cleanup_confirmed, net.cleanup_confirmed), (False, False))

    async def test_cancel_with_the_open_answer_lost_keeps_the_debt_and_is_never_none(self):
        await self.start()
        gate = asyncio.Event()

        async def drop(raw):
            await gate.wait()
            raise OSError('reset')
        self.owner.after['open_level'] = drop
        net = self.session()
        task = asyncio.ensure_future(net.__aenter__())
        await self.wait_op('open_level')
        task.cancel()
        gate.set()
        with self.assertRaises(asyncio.CancelledError) as caught:
            await task
        self.assertIs(caught.exception.cleanup_confirmed, False)
        self.assertEqual((net.cleanup_confirmed, net.identity, self.broker.status()['obligations']), (False, None, 1))

    async def test_cancel_after_a_valid_ack_restitutes_and_keeps_the_identity_available(self):
        await self.start()
        gate = asyncio.Event()
        self.owner.before['open_level'] = gate
        net = self.session()
        task = asyncio.ensure_future(net.__aenter__())
        await self.wait_op('open_level')
        task.cancel()
        gate.set()
        with self.assertRaises(asyncio.CancelledError) as caught:
            await task
        self.assertIs(caught.exception.cleanup_confirmed, True)
        self.assertEqual(net.identity['intent_id'], self.inventory.history[-1].intent_id)  # persistable although the body never ran
        self.assertEqual(net.cleanup_roles, dict.fromkeys(ROLES, 'absent'))

    async def test_a_lost_close_keeps_the_binding_and_confirms_nothing_until_a_retry(self):
        await self.start()
        calls = []

        async def lose(raw):
            calls.append(1)
            if len(calls) == 1:
                raise OSError('reset')
            return raw
        self.owner.after['close'] = lose
        net = self.session()
        await net.__aenter__()
        identity = net.identity
        with self.assertRaises(client.ActorError) as caught:
            await net.close()
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('cleanup_unconfirmed', False))
        self.assertEqual((net.cleanup_confirmed, net.obligation, net.identity, net.cleanup_roles), (False, True, identity, None))
        await net.close()
        self.assertEqual((net.cleanup_confirmed, net.cleanup_roles), (True, dict.fromkeys(ROLES, 'absent')))

    async def test_a_close_that_is_not_the_four_absent_roles_confirms_nothing(self):
        await self.start()

        async def partial(raw):
            value = json.loads(raw)
            value['cleanup_roles']['canary'] = 'unknown'
            return enc(value)
        net = self.session()
        await net.__aenter__()
        self.owner.after['close'] = partial
        with self.assertRaises(client.ActorError) as caught:
            await net.close()
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('cleanup_unconfirmed', False))
        self.assertEqual((net.cleanup_confirmed, net.cleanup_roles, net.obligation), (False, None, True))

    async def test_recover_level_receipt_accepts_the_eight_field_network_identity_and_nothing_looser(self):
        await self.start()
        async with self.session() as net:
            pass
        identity = net.identity
        before = len(self.owner.payloads)
        receipt = await client.recover_level_receipt(self.settings, identity, transport=self.owner)
        self.assertEqual((receipt['status'], receipt['bundle_id'], receipt['cleanup_roles']), ('confirmed', identity['intent_id'],
                                                                                                dict.fromkeys(ROLES, 'absent')))
        self.assertEqual(self.owner.ops[-1], 'level_receipt')
        self.assertNotIn(b'bundle_id', self.owner.payloads[before])  # the request carries seven fields: the owner derives the bundle
        sent = len(self.owner.payloads)
        invalid = ({key: item for key, item in identity.items() if key != 'bundle_id'},            # seven fields, level network
                   {**identity, 'bundle_id': '9' * 32}, {**identity, 'level': 'memory'}, {**identity, 'extra': 1}, None, 'x')
        for bad in invalid:
            with self.assertRaises(client.ActorError) as caught:
                await client.recover_level_receipt(self.settings, bad, transport=self.owner)
            self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed, caught.exception.owner_reason),
                             ('cleanup_unconfirmed', False, 'identity_invalid'))
        self.assertEqual(len(self.owner.payloads), sent)  # refused before anything was sent
        for other in ({**identity, 'intent_id': '9' * 32, 'bundle_id': '9' * 32}, {**identity, 'context_sha256': base.OTHER_CONTEXT}):
            with self.assertRaises(client.ActorError) as caught:
                await client.recover_level_receipt(self.settings, other, transport=self.owner)
            self.assertEqual((caught.exception.cleanup_confirmed, caught.exception.owner_reason), (False, 'receipt_unknown'))

        def tamper(change):
            async def hook(raw):
                value = json.loads(raw)
                change(value)
                return enc(value)
            return hook
        for change in (lambda value: value.update(bundle_id='f' * 32), lambda value: value.pop('cleanup_roles'),
                       lambda value: value['cleanup_roles'].update(canary='pending'), lambda value: value.update(cleanup_roles=None)):
            self.owner.after['level_receipt'] = tamper(change)
            with self.assertRaises(client.ActorError) as caught:
                await client.recover_level_receipt(self.settings, identity, transport=self.owner)
            self.assertEqual(caught.exception.owner_reason, 'owner_response_invalid')


if __name__ == '__main__':
    unittest.main()

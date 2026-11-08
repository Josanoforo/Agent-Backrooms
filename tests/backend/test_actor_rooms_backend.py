"""M4 · backend de salas (SC2-M4-rooms-v1): room_action, codec, permiso unico, cierre con cgroup y RoomActorSession.
Sin Docker, shell ni red: dobles del broker (test_invoice_actor_broker) y transporte hacia el broker real. Autoria sin ejecutar."""
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

from services.agent import actor_wire as wire  # noqa: E402
from services.agent import invoice_actor_client as client  # noqa: E402
from services.agent import invoice_actor_protocol as proto  # noqa: E402
from services.agent import runner  # noqa: E402
import test_invoice_actor_broker as base  # noqa: E402
import test_invoice_actor_client as cbase  # noqa: E402

H = 'ab' * 32
HARD = cbase.PROFILE
DIGEST = runner.profile_digest(HARD)
LIMIT = 2 ** 31 - 1
ROOMS = ('processes', 'privileges')
MEAS = base.MEAS


def enc(obj):
    return json.dumps(obj, separators=(',', ':')).encode()


def ident(level='processes'):
    return {'installation_id': base.INSTALL, 'run_id': base.RUN_A, 'level': level, 'stage': 'actor',
            'context_sha256': base.CONTEXT, 'intent_id': '5' * 32, 'container_id': base.CONTAINER}


def verified(container=base.CONTAINER):
    return {'status': 'verified', 'version': runner.CGROUP_IDENTITY_VERSION, 'container_id': container, 'cgroup_layout': 'systemd',
            'leaf': True, 'init_in_cgroup': True, 'inode_cross_check': 'match', 'events_counter': 'pids.events.local',
            'events_scope': 'cgroup_local'}


PRE, POST = [64, 1, 0, 1, 0], [64, 1, 8, 64, 150]
DURING = [[64, 64, 3, 64, 50], [64, 64, 8, 64, 100]]
NULL_PROCESSES = dict(result=None, cgroup_identity={'status': 'unknown', 'reason': 'no_observer'}, pre=None, during=[], post=None,
                      recheck={'ok': False, 'reason': 'no_observer'}, tool=None, verification=None)


def processes_answer():
    return dict(result={'stdout': '{}', 'stderr': '', 'exit_code': 0, **MEAS}, container={'container_id': base.CONTAINER},
                cgroup_identity=verified(), pre=list(PRE), during=copy.deepcopy(DURING), post=list(POST), recheck={'ok': True},
                tool=2.5, verification=0.1)


def privileges_answer():
    return dict(result={'stdout': '{}', 'stderr': '', 'exit_code': 0, **MEAS}, container={'container_id': base.CONTAINER},
                cgroup_identity=None, pre=None, during=[], post=None, recheck=None, tool=0.2, verification=None)


def body(level='processes', **patch):
    answer = processes_answer() if level == 'processes' else privileges_answer()
    return {'ok': True, 'op': 'room_action', **ident(level), **answer, **patch}


class Strict(unittest.TestCase):
    def accept(self, patch=None, *, level='processes', **kw):
        return wire.validate_room_action(body(level, **(patch or {})), identity=ident(level), **kw)

    def reject(self, patch=None, *, level='processes', drop=(), **kw):
        value = {k: v for k, v in body(level, **(patch or {})).items() if k not in drop}
        with self.assertRaises(wire.WireError) as caught:
            wire.validate_room_action(value, identity=ident(level), **kw)
        self.assertEqual(caught.exception.reason, 'owner_response_invalid')


class RoomRequestAndLeaseTests(unittest.TestCase):
    def reason(self, raw):
        with self.assertRaises(proto.ProtocolError) as caught:
            proto.decode_request(raw)
        return caught.exception.reason

    def test_request_is_exactly_op_and_handle(self):
        self.assertEqual(proto.decode_request(enc({'op': 'room_action', 'handle': H})).handle, H)
        for key in ('script', 'argv', 'level', 'command', 'name', 'uid', 'profile', 'limit', 'image', 'path', 'args'):
            self.assertIn(self.reason(enc({'op': 'room_action', 'handle': H, key: 'x'})), {'unexpected_field', 'forbidden_field'}, key)
        self.assertEqual(self.reason(enc({'op': 'room_action', 'handle': H, 'path': '/x'})), 'forbidden_field')
        self.assertEqual(self.reason(enc({'op': 'room_action'})), 'missing_field')
        for bad in (H.upper(), H[:-1], '', None, 5):
            self.assertEqual(self.reason(enc({'op': 'room_action', 'handle': bad})), 'invalid_handle')
        self.assertEqual(self.reason(b'{"op":"room_action","handle":"%s","handle":"%s"}' % (H.encode(), H.encode())), 'duplicate_key')

    def test_rooms_are_actor_only_levels(self):
        for level in ROOMS:
            for op in ('open_level', 'level_receipt'):
                fields = ident(level) if op == 'level_receipt' else {k: ident(level)[k] for k in ('run_id', 'level', 'stage', 'context_sha256')}
                self.assertEqual(proto.decode_request(enc({'op': op, **fields})).level, level)
                self.assertEqual(self.reason(enc({'op': op, **{**fields, 'stage': 'fresh'}})), 'invalid_stage')
            self.assertFalse(proto.level_stage_valid(level, 'fresh'))

    def test_the_single_action_permit(self):
        clock = base.Clock()
        leases = proto.ActorLeases(max_sessions=2, ttl_seconds=60, clock=clock)
        room = leases.open_level(1000, base.RUN_A, 'processes', 'actor', base.CONTEXT)
        other = leases.open_level(1000, base.RUN_B, 'memory', 'actor', base.CONTEXT)

        def refused(handle, uid=1000):
            with self.assertRaises(proto.ProtocolError) as caught:
                leases.consume_action(handle, uid)
            return caught.exception.reason
        self.assertEqual(refused(room, 1001), 'foreign_owner')
        self.assertEqual(refused(other), 'action_unavailable')
        self.assertFalse(leases.authorize(room, 1000).action_spent)
        self.assertFalse(leases.consume_action(room, 1000).action_spent)  # the snapshot it returns is the one before spending
        self.assertTrue(leases.authorize(room, 1000).action_spent)
        self.assertEqual(refused(room), 'action_consumed')
        leases.begin_close(room, 1000)
        self.assertEqual(refused(room), 'closing')
        clock.now += 61
        self.assertEqual(refused(other), 'expired')


class RoomCodecTests(Strict):
    def test_each_room_validates_and_returns_copies(self):
        for level in ROOMS:
            view = self.accept(level=level)
            self.assertEqual(list(view), list(wire.ROOM_ACTION_KEYS))
        self.assertEqual(self.accept()['during'], DURING)
        self.assertIsNone(self.accept(level='privileges')['cgroup_identity'])

    def test_result_null_only_for_unknown_processes_without_samples_or_times(self):
        self.accept(NULL_PROCESSES)
        for patch in (dict(NULL_PROCESSES, cgroup_identity=verified()), dict(NULL_PROCESSES, pre=PRE), dict(NULL_PROCESSES, post=POST),
                      dict(NULL_PROCESSES, during=[DURING[0]]), dict(NULL_PROCESSES, tool=0.1), dict(NULL_PROCESSES, verification=0.1),
                      dict(NULL_PROCESSES, recheck=None), dict(NULL_PROCESSES, recheck={'ok': True})):
            self.reject(patch)
        self.reject({'result': None}, level='privileges')
        for patch in (dict(cgroup_identity=verified()), dict(pre=PRE), dict(during=[DURING[0]]), dict(recheck={'ok': True})):
            self.reject(patch, level='privileges')

    def test_size_limits_count_the_serialized_value_with_escapes(self):
        def stdout(text):
            return {'result': {'stdout': text, 'stderr': '', 'exit_code': 0, **MEAS}}

        def stderr(text):
            return {'result': {'stdout': '', 'stderr': text, 'exit_code': 0, **MEAS}}
        self.accept(stdout('a' * 8190)); self.reject(stdout('a' * 8191))
        self.accept(stderr('b' * 2046)); self.reject(stderr('b' * 2047))
        self.accept(stdout('\n' * 4095)); self.reject(stdout('\n' * 4096))   # two bytes each once escaped
        self.accept(stdout('\u20ac' * 1365)); self.reject(stdout('\u20ac' * 1366))  # six bytes each in the ASCII wire form

    def test_maximum_answer_fits_the_global_frame_and_one_more_sample_does_not_validate(self):
        top = [LIMIT, LIMIT, 2 ** 64 - 1, LIMIT, 90000]
        patch = dict(result={'stdout': 'a' * 8190, 'stderr': 'b' * 2046, 'exit_code': 0, **MEAS}, pre=top, during=[top] * 400,
                     post=top, recheck={'ok': False, 'reason': 'sample_limit'}, tool=90.0, verification=90.0)
        self.accept(patch)
        value = body(**patch)
        encoded = wire.encode_response('room_action', {k: v for k, v in value.items() if k not in ('ok', 'op')})
        self.assertLess(len(encoded), 65536)
        wire.validate_room_action(wire.decode_response(encoded, op='room_action'), identity=ident())
        self.reject(dict(patch, during=[top] * 401))
        self.reject(dict(patch, recheck={'ok': True}))  # reaching the cap never claims full coverage

    def test_bounds_and_types(self):
        edge = [LIMIT, LIMIT, 2 ** 64 - 1, LIMIT, 90000]
        self.accept(dict(pre=None, post=None, during=[edge]))
        for bad in ([LIMIT + 1, 1, 0, 1, 0], [64, LIMIT + 1, 0, 1, 0], [64, 1, 2 ** 64, 1, 0], [64, 1, 0, LIMIT + 1, 0],
                    [64, 1, 0, 1, 90001], [-1, 1, 0, 1, 0], [True, 1, 0, 1, 0], [64, 1, True, 1, 0], [64, 1, 0, True, 0],
                    [64, 1, 0, 1, True], [64.0, 1, 0, 1, 0], ['64', 1, 0, 1, 0], [64, 1, 0, 1], [64, 1, 0, 1, 0, 0]):
            self.reject(dict(pre=None, post=None, during=[bad]))
        self.accept(dict(pre=None, post=None, during=[[64, 1, 0, None, 0]]))
        for good in (90, 90.0, 0, 0.0):
            self.accept(dict(tool=good, verification=good))
        for bad in (90.0001, -0.1, True, float('nan'), float('inf'), '1', 10 ** 400, [1]):
            self.reject(dict(tool=bad)); self.reject(dict(verification=bad))
        for patch in ({'result': {**processes_answer()['result'], 'exit_code': True}},
                      {'result': {**processes_answer()['result'], 'stdout': None}},
                      {'result': {**processes_answer()['result'], 'extra': 1}}):
            self.reject(patch)

    def test_samples_and_reasons_are_closed(self):
        for reason in wire.ROOM_SAMPLE_REASONS:
            self.accept(dict(during=[{'ok': False, 'reason': reason}, DURING[0]]))
        for bad in ({'ok': False, 'reason': '/sys/fs/cgroup/x'}, {'ok': False}, {'ok': True, 'reason': 'unreadable'},
                    {'ok': 0, 'reason': 'unreadable'}, {'ok': False, 'reason': 'unreadable', 'at': 1}, None):
            self.reject(dict(during=[bad]))
        for reason in wire.ROOM_RECHECK_REASONS:
            self.accept(dict(recheck={'ok': False, 'reason': reason}))
        for bad in ({'ok': False, 'reason': 'host text'}, {'ok': True, 'reason': 'unreadable'}, {'ok': 1}, {}, 'ok'):
            self.reject(dict(recheck=bad))
        for reason in wire.CGROUP_UNKNOWN_REASONS:
            self.accept(dict(NULL_PROCESSES, cgroup_identity={'status': 'unknown', 'reason': reason}))
        self.reject(dict(NULL_PROCESSES, cgroup_identity={'status': 'unknown', 'reason': 'proc cgroup at /sys/x'}))

    def test_observations_that_contradict_each_other_are_rejected(self):
        self.reject(dict(pre=None, post=None, during=[[64, 1, 0, 1, 100], [64, 1, 0, 1, 99]]))            # time goes back
        self.reject(dict(pre=[64, 1, 0, 1, 500]))                                                           # pre later than during
        self.reject(dict(pre=None, post=None, during=[[64, 1, 0, 1, 0], [63, 1, 0, 1, 1]]))                # the limit moved
        self.reject(dict(pre=None, post=None, during=[[64, 1, 5, 1, 0], [64, 1, 4, 1, 1]]))                # the counter went back
        series = dict(pre=None, post=None, during=[[96, 1, 0, 1, 0], [96, 1, 0, 1, 1]])
        self.accept(series)                                                                                # no profile limit known
        self.accept(series, pids_limit=96)
        self.reject(series, pids_limit=64)                                                                 # not the profile's limit
        self.accept(dict(pre=None, post=None, during=[[64, 1, 0, 1, 0], {'ok': False, 'reason': 'unreadable'}, [63, 1, 0, 1, 1]]))  # literal: only a fully valid series is compared

    def test_identity_binding_and_cgroup_record(self):
        self.reject(dict(container={'container_id': 'e' * 64}))
        self.reject(dict(cgroup_identity=verified('e' * 64)))
        self.reject(dict(run_id='9' * 32)); self.reject(dict(op='close')); self.reject(dict(ok=1))
        self.reject(drop=('post',)); self.reject(dict(outcome='blocked')); self.reject(dict(container=None))
        with self.assertRaises(wire.WireError):
            wire.validate_room_action(body('processes'), identity=ident('privileges'))
        for odd in ({**ident('memory')}, {**ident('processes'), 'stage': 'fresh'}, {**ident('processes'), 'extra': 1}):
            with self.assertRaises(wire.WireError):
                wire.validate_room_action(body('processes'), identity=odd)
        for key in wire.CGROUP_VERIFIED_KEYS:
            self.reject(dict(cgroup_identity={k: v for k, v in verified().items() if k != key}))
        for patch in ({'version': 'x'}, {'cgroup_layout': 'docker'}, {'leaf': False}, {'init_in_cgroup': 1}, {'inode_cross_check': 'no'},
                      {'events_scope': 'leaf_cgroup_hierarchical_equals_local'}, {'events_counter': 'pids.max'}, {'path': '/sys/fs/cgroup/x'}):
            self.reject(dict(cgroup_identity={**verified(), **patch}))
        self.accept(dict(cgroup_identity={**verified(), 'events_counter': 'pids.events',
                                          'events_scope': 'leaf_cgroup_hierarchical_equals_local', 'cgroup_layout': 'cgroupfs'}))

    def test_strict_json_and_size_at_the_decoder(self):
        for raw in (b'{"ok":true,"op":"room_action","ok":true}', b'{"ok":true,"op":"room_action","tool":NaN}', b'x',
                    enc(body()) + b' ' * 65536):
            with self.assertRaises(wire.WireError):
                wire.decode_response(raw, op='room_action')

    def test_close_and_receipt_shapes_of_a_room(self):
        def close(level, absent, **patch):
            return {'ok': True, 'op': 'close', **ident(level), 'cleanup_confirmed': True, 'oom_killed': False, **MEAS,
                    'cgroup_absent': absent, **patch}

        def receipt(level, status, absent):
            return {'ok': True, 'op': 'level_receipt', **ident(level), 'status': status, 'cleanup_confirmed': status == 'confirmed',
                    'cgroup_absent': absent}
        self.assertIs(wire.validate_level_close(close('processes', True), receipt=ident('processes'))['cgroup_absent'], True)
        self.assertIsNone(wire.validate_level_close(close('privileges', None), receipt=ident('privileges'))['cgroup_absent'])
        for level, bad in (('processes', False), ('processes', None), ('processes', 1), ('processes', 'true'), ('privileges', True),
                           ('privileges', False)):
            with self.assertRaises(wire.WireError):
                wire.validate_level_close(close(level, bad), receipt=ident(level))
        with self.assertRaises(wire.WireError):
            wire.validate_level_close({k: v for k, v in close('processes', True).items() if k != 'cgroup_absent'}, receipt=ident('processes'))
        with self.assertRaises(wire.WireError):  # a historical level keeps its exact shape: the new key is an extra there
            wire.validate_level_close(close('memory', None), receipt=ident('memory'))
        for level, status, absent, good in (('processes', 'confirmed', True, True), ('processes', 'unknown', None, True),
                                            ('privileges', 'confirmed', None, True), ('privileges', 'unknown', None, True),
                                            ('processes', 'confirmed', None, False), ('processes', 'confirmed', False, False),
                                            ('processes', 'unknown', True, False), ('privileges', 'confirmed', True, False)):
            if good:
                wire.validate_level_receipt(receipt(level, status, absent), identity=ident(level))
            else:
                with self.assertRaises(wire.WireError):
                    wire.validate_level_receipt(receipt(level, status, absent), identity=ident(level))

    def test_vocabularies_follow_the_runner(self):
        class Reader:
            def __init__(self, files):
                self.files = files

            def inode(self):
                return 5

            def read(self, name):
                if name not in self.files:
                    raise OSError(name)
                return self.files[name]

            def has_children(self):
                return False

            def close(self):
                pass
        files = {'pids.max': '64\n', 'pids.current': '1\n', 'pids.events.local': 'max 0\n', 'pids.events': 'max 0\n', 'cgroup.procs': '123\n'}
        container = {'container_id': base.CONTAINER, 'init_pid': 123}
        membership = '0::/system.slice/docker-%s.scope\n' % base.CONTAINER
        public, observer = runner.verify_cgroup_identity(container, membership, lambda parts: Reader(files), 5)
        self.assertEqual(set(public), set(wire.CGROUP_VERIFIED_KEYS))
        wire._room_cgroup_identity(public, base.CONTAINER)
        public, observer = runner.verify_cgroup_identity(container, membership,
                                                         lambda parts: Reader({k: v for k, v in files.items() if k != 'pids.events.local'}), 5)
        self.assertEqual((public['events_counter'], public['events_scope']), ('pids.events', 'leaf_cgroup_hierarchical_equals_local'))
        wire._room_cgroup_identity(public, base.CONTAINER)
        unknown, _ = runner.verify_cgroup_identity(container, 'garbage', lambda parts: Reader(files), 5)
        self.assertIn(unknown['reason'], wire.CGROUP_UNKNOWN_REASONS)
        self.assertEqual(wire.CGROUP_IDENTITY_VERSION, runner.CGROUP_IDENTITY_VERSION)
        source = Path(runner.__file__).read_text(encoding='utf-8')
        for reason in wire.ROOM_SAMPLE_REASONS | (wire.ROOM_RECHECK_REASONS - {'no_observer', 'sample_limit'}):
            self.assertIn("'%s'" % reason, source)
        self.assertEqual(HARD['pids_limit'], 64)


@dataclasses.dataclass(frozen=True)
class RoomIntentMarker:  # documentation only: the broker double's LevelIntent already has no variant
    pass


class RoomInventory(base.LevelInventory):
    def begin_level(self, **kwargs):
        intent = super().begin_level(**kwargs)
        self.current = dataclasses.replace(intent, profile_sha256=DIGEST)
        return self.current


class RoomRuntime(base.LevelRuntime):
    def __init__(self, log, inventory):
        super().__init__(log, inventory)
        self.room_answer, self.room_error, self.room_gate, self.room_started = None, None, None, None
        self.cgroup_absent, self.privileges_absent = True, None

    async def inspect_running(self, intent):
        if getattr(intent, 'level', None) is None:
            self.running_override = None  # preserve the historical workflow double's own profile/digest
            return await super().inspect_running(intent)
        self.running_override = {'running': True, 'container_id': intent.container_id, 'profile': HARD, 'profile_sha256': DIGEST,
                                 'violations': []}
        return await super().inspect_running(intent)

    async def room_action(self, intent):
        self.calls['room_action'] += 1
        self.log.append('rt:room_action')
        if self.room_started is not None:
            self.room_started.set()
        if self.room_gate is not None:
            await self.room_gate.wait()
        if self.room_error is not None:
            raise self.room_error
        if callable(self.room_answer):
            return self.room_answer(intent)
        return copy.deepcopy(self.room_answer) if self.room_answer is not None else (
            processes_answer() if intent.level == 'processes' else privileges_answer())

    async def close(self, intent):
        result = await super().close(intent)
        if getattr(intent, 'level', None) == 'processes':
            result['cgroup_absent'] = self.cgroup_absent
        elif getattr(intent, 'level', None) == 'privileges':
            result['cgroup_absent'] = self.privileges_absent
        return result


class RoomCase(base.LevelCase):
    async def asyncSetUp(self):
        self.log = []
        self.inventory = RoomInventory(self.log)
        self.runtime = RoomRuntime(self.log, self.inventory)
        self.clock = base.Clock()
        self.make()

    def make(self, **overrides):
        overrides.setdefault('allowed_levels', ('memory', 'processes', 'privileges'))
        return super().make(**overrides)

    def reset(self, **overrides):
        self.log.clear()
        self.inventory = RoomInventory(self.log)
        self.runtime = RoomRuntime(self.log, self.inventory)
        self.make(**overrides)

    async def room(self, handle):
        return await self.call({'op': 'room_action', 'handle': handle})

    def spent(self, handle):
        return self.broker.leases._leases[handle].action_spent


class RoomOperationTests(RoomCase):
    async def test_each_room_runs_one_action_and_closes_with_its_cgroup_fact(self):
        for level, absent in (('processes', True), ('privileges', None)):
            self.reset()
            opened = await self.opened_level(level=level)
            identity = self.level_identity(opened)
            wire.validate_level_open(opened, **{**base.LEVEL_ARGS, 'level': level})
            answer = await self.room(opened['handle'])
            self.assertTrue(answer['ok'], answer)
            wire.validate_room_action(answer, identity=identity, pids_limit=64)
            self.assertEqual(self.runtime.calls['room_action'], 1)
            self.assertTrue((await self.call({'op': 'probe', 'handle': opened['handle'], 'name': 'measure'}))['ok'])
            closed = await self.call({'op': 'close', 'handle': opened['handle']})
            self.assertIs(wire.validate_level_close(closed, receipt=identity)['cgroup_absent'], absent)
            self.assertEqual(self.log[-3:], base.ORDER_OF_CLOSE)
            self.assertEqual(await self.call({'op': 'close', 'handle': opened['handle']}), closed)  # idempotent, same receipt
            receipt = await self.call({'op': 'level_receipt', **identity})
            self.assertEqual((wire.validate_level_receipt(receipt, identity=identity)['status'], receipt['cgroup_absent']),
                             ('confirmed', absent))

    async def test_authority_and_domain_are_decided_before_the_runtime(self):
        await self.start()
        workflow = await self.open()
        self.assertEqual(await self.room(workflow['handle']), {'ok': False, 'reason': 'wrong_domain'})
        await self.call({'op': 'close', 'handle': workflow['handle']})
        memory = await self.open_level(base.RUN_B, 'memory')
        self.assertEqual(await self.room(memory['handle']), {'ok': False, 'reason': 'wrong_domain'})
        await self.call({'op': 'close', 'handle': memory['handle']})
        opened = await self.open_level(base.RUN_C, 'processes')
        handle = opened['handle']
        for request, reason in (({'op': 'execute', 'handle': handle, 'command': 'true'}, 'wrong_domain'),
                                ({'op': 'level_probe', 'handle': handle, 'name': 'cgroup_events'}, 'wrong_domain'),
                                ({'op': 'probe', 'handle': handle, 'name': 'task_result'}, 'wrong_domain'),
                                ({'op': 'probe', 'handle': handle, 'name': 'artifact_capture'}, 'wrong_domain'),
                                ({'op': 'catalog_check', 'handle': handle}, 'catalog_not_allowed'),
                                ({'op': 'room_action', 'handle': handle, 'script': 'id'}, 'unexpected_field'),
                                ({'op': 'room_action', 'handle': 'cd' * 32}, 'unknown_handle')):
            self.assertEqual(await self.call(request), {'ok': False, 'reason': reason}, request)
        self.assertEqual({name: self.runtime.calls[name] for name in ('room_action', 'execute', 'probe', 'probe_level')},
                         {'room_action': 0, 'execute': 0, 'probe': 0, 'probe_level': 0})
        self.assertIsNone(await self.broker.handle(base.CLIENT_UID + 1, enc({'op': 'room_action', 'handle': handle})))
        self.assertTrue((await self.room(handle))['ok'])  # the refusals left the lease and its permit intact

    async def test_expired_handle_does_not_spend_the_permit(self):
        opened = await self.opened_level(level='processes')
        self.clock.now += 121
        self.assertEqual((await self.room(opened['handle']))['reason'], 'expired')
        self.assertEqual((self.runtime.calls['room_action'], self.spent(opened['handle'])), (0, False))

    async def test_permit_is_spent_before_dispatch_and_never_returns(self):
        opened = await self.opened_level(level='processes')
        handle = opened['handle']
        self.runtime.room_gate, self.runtime.room_started = asyncio.Event(), asyncio.Event()
        first = asyncio.ensure_future(self.room(handle))
        await self.runtime.room_started.wait()
        self.assertTrue(self.spent(handle))                                              # spent while the runtime is still inside
        self.assertEqual(await self.room(handle), {'ok': False, 'reason': 'busy'})       # concurrent: no queue
        self.runtime.room_gate.set()
        self.assertTrue((await first)['ok'])
        self.assertEqual(await self.room(handle), {'ok': False, 'reason': 'action_consumed'})  # sequential
        self.assertEqual(self.runtime.calls['room_action'], 1)
        self.assertTrue((await self.call({'op': 'probe', 'handle': handle, 'name': 'measure'}))['ok'])  # lease still usable

    async def test_a_lost_answer_never_runs_the_action_again(self):
        opened = await self.opened_level(level='privileges')
        await self.broker.handle(base.CLIENT_UID, enc({'op': 'room_action', 'handle': opened['handle']}))  # the answer is discarded
        self.assertEqual((await self.room(opened['handle']))['reason'], 'action_consumed')
        self.assertEqual(self.runtime.calls['room_action'], 1)

    async def test_uncertain_outcomes_end_the_lease_restitute_and_are_never_replayed(self):
        good = processes_answer()
        cases = {
            'runtime_error': dict(room_error=RuntimeError('boom')),
            'extra_key': dict(room_answer={**good, 'outcome': 'blocked'}),
            'missing_key': dict(room_answer={k: v for k, v in good.items() if k != 'post'}),
            'oversized_stdout': dict(room_answer={**good, 'result': {**good['result'], 'stdout': 'a' * 8191}}),
            'other_container': dict(room_answer={**good, 'container': {'container_id': 'e' * 64}}),
            'limit_not_the_profile': dict(room_answer={**good, 'pre': [96, 1, 0, 1, 0], 'during': [[96, 1, 0, 1, 1]], 'post': [96, 1, 0, 1, 2]}),
            'null_with_verified_identity': dict(room_answer={**good, 'result': None}),
            'not_an_object': dict(room_answer=['x']),
        }
        for name, attributes in cases.items():
            with self.subTest(name):
                self.reset()
                opened = await self.opened_level(level='processes')
                for key, value in attributes.items():
                    setattr(self.runtime, key, value)
                self.assertEqual(await self.room(opened['handle']), {'ok': False, 'reason': 'internal_error'})
                await self.broker.drain()
                self.assertEqual((self.runtime.calls['room_action'], self.runtime.removed, self.inventory.current),
                                 (1, [base.CONTAINER], None))
                self.assertEqual(self.log[-3:], base.ORDER_OF_CLOSE)

    async def test_timeout_is_one_failure_and_restitutes(self):
        self.reset(limits=base.fast_limits(room_action=0.05))
        opened = await self.opened_level(level='processes')
        self.runtime.room_gate = asyncio.Event()
        self.assertEqual(await self.room(opened['handle']), {'ok': False, 'reason': 'exec_timeout'})
        await self.broker.drain()
        self.assertEqual((self.runtime.calls['room_action'], self.runtime.removed), (1, [base.CONTAINER]))


class RoomPolicyTests(RoomCase):
    async def test_rooms_are_not_served_by_default_or_unless_listed(self):
        for allowed in ((), ('memory',)):
            self.reset(allowed_levels=allowed)
            await self.start()
            for level in ROOMS:
                self.assertEqual(await self.open_level(level=level), {'ok': False, 'reason': 'level_not_allowed'})
            self.assertEqual((self.log, self.runtime.calls['create']), ([], 0))
        self.reset(allowed_levels=('privileges',))
        await self.start()
        self.assertEqual((await self.open_level(level='processes'))['reason'], 'level_not_allowed')
        self.assertTrue((await self.open_level(level='privileges'))['ok'])

    async def test_a_listed_room_needs_an_async_room_action(self):
        class Sync(RoomRuntime):
            def room_action(self, intent):
                return {}
        with self.assertRaises(ValueError):
            self.make(runtime=base.LevelRuntime(self.log, self.inventory), allowed_levels=('processes',))
        with self.assertRaises(ValueError):
            self.make(runtime=Sync(self.log, self.inventory), allowed_levels=('privileges',))
        self.make(runtime=base.LevelRuntime(self.log, self.inventory), allowed_levels=('memory',))  # older owners keep working

    async def test_replay_and_fresh_stage(self):
        opened = await self.opened_level(level='processes')
        await self.call({'op': 'close', 'handle': opened['handle']})
        self.assertEqual((await self.open_level(level='processes'))['reason'], 'already_active')
        self.assertEqual((await self.open_level(level='processes', stage='fresh'))['reason'], 'invalid_stage')


class RoomCloseTests(RoomCase):
    async def test_uncertain_cgroup_never_confirms_and_never_writes_finish(self):
        for level, attribute, bad in (('processes', 'cgroup_absent', False), ('processes', 'cgroup_absent', None),
                                      ('processes', 'cgroup_absent', 'yes'), ('privileges', 'privileges_absent', True),
                                      ('privileges', 'privileges_absent', False)):
            with self.subTest(level=level, value=bad):
                self.reset()
                opened = await self.opened_level(level=level)
                identity = self.level_identity(opened)
                setattr(self.runtime, attribute, bad)
                failed = await self.call({'op': 'close', 'handle': opened['handle']})
                self.assertEqual((failed['reason'], failed['cleanup_confirmed']), ('cleanup_unconfirmed', False))
                self.assertEqual((self.inventory.current.phase, len(self.inventory.history), 'inv:finish' in self.log),
                                 ('CLOSE_PENDING', 0, False))
                unknown = await self.call({'op': 'level_receipt', **identity})
                self.assertEqual((wire.validate_level_receipt(unknown, identity=identity)['status'], unknown['cgroup_absent']),
                                 ('unknown', None))
                setattr(self.runtime, attribute, True if level == 'processes' else None)
                await self.broker.reconcile()
                confirmed = await self.call({'op': 'level_receipt', **identity})
                self.assertEqual((confirmed['status'], confirmed['cgroup_absent']), ('confirmed', True if level == 'processes' else None))

    async def test_historical_close_shapes_do_not_change(self):
        opened = await self.opened_level(level='memory')
        closed = await self.call({'op': 'close', 'handle': opened['handle']})
        self.assertNotIn('cgroup_absent', closed)
        wire.validate_level_close(closed, receipt=self.level_identity(opened))

    async def test_a_restarted_owner_restitutes_a_room_without_running_the_action(self):
        opened = await self.opened_level(level='processes')
        identity = self.level_identity(opened)
        self.make()
        await self.start()
        self.assertEqual((self.runtime.calls['room_action'], self.runtime.calls['create'], self.runtime.calls['start']), (0, 1, 1))
        self.assertEqual(self.log[-3:], base.ORDER_OF_CLOSE)
        receipt = await self.call({'op': 'level_receipt', **identity})
        self.assertEqual((receipt['status'], receipt['cgroup_absent']), ('confirmed', True))

    async def test_only_the_exact_finish_of_the_exact_room_confirms(self):
        opened = await self.opened_level(level='processes')
        identity = self.level_identity(opened)
        await self.call({'op': 'close', 'handle': opened['handle']})
        finish = self.inventory.history[-1]
        for patch in ({'level': 'privileges'}, {'context_sha256': base.OTHER_CONTEXT}, {'phase': 'CLOSE_PENDING'}, {'stage': 'fresh'}):
            self.inventory.level_receipt_returns = dataclasses.replace(finish, **patch)
            self.assertEqual(await self.call({'op': 'level_receipt', **identity}), {'ok': False, 'reason': 'internal_error'}, patch)


class Owner:
    """Transport of the facade tests: the real broker answers; hooks can hold a request or lose/alter its answer."""

    def __init__(self, case):
        self.case, self.ops, self.before, self.after = case, [], {}, {}

    async def __call__(self, settings, payload, *, response_limit, deadline):
        request = proto.decode_request(payload)
        self.ops.append(request.op)
        gate = self.before.get(request.op)
        if gate is not None:
            await gate.wait()
        raw = await self.case.broker.handle(base.CLIENT_UID, payload)
        hook = self.after.get(request.op)
        return await hook(raw) if hook is not None else raw


class RoomFacadeTests(RoomCase):
    settings = client.Settings('/run/agent-escape-actor/broker.sock', base.CLIENT_UID)

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.owner = Owner(self)

    def session(self, level='processes', settings=None):
        return client.RoomActorSession(settings or self.settings, run_id=base.RUN_A, level=level, context_sha256=base.CONTEXT,
                                       transport=self.owner)

    async def wait_op(self, op):
        for _ in range(500):
            if op in self.owner.ops:
                return
            await asyncio.sleep(0.001)
        self.fail('never sent ' + op)

    async def test_processes_returns_the_nine_keys_with_historical_samples(self):
        await self.start()
        async with self.session('processes') as room:
            self.assertEqual(set(room.identity), set(wire.LEVEL_IDENTITY_FIELDS))
            self.assertIsNone(room.cgroup_absent)
            answer = await room.room_action()
            self.assertEqual(list(answer), list(wire.ROOM_ACTION_KEYS))
            self.assertEqual(answer['pre'], {'ok': True, 'pids_max': 64, 'pids_current': 1, 'events_max': 0, 'peak': 1, 'at': 0.0})
            self.assertEqual([item['at'] for item in answer['during']], [0.05, 0.1])
            self.assertEqual(answer['post']['events_max'], 8)
            self.assertEqual(answer['cgroup_identity']['status'], 'verified')
            self.assertEqual(room.measurement, MEAS)
            self.assertEqual(room.profile['pids_limit'], 64)
        self.assertEqual((room.cleanup_confirmed, room.cgroup_absent, room.obligation), (True, True, False))
        self.assertEqual(self.owner.ops, ['health', 'open_level', 'room_action', 'close'])
        self.assertEqual(room.identity['intent_id'], self.inventory.history[-1].intent_id)  # still available after the close

    async def test_privileges_has_no_cgroup_facts(self):
        await self.start()
        async with self.session('privileges') as room:
            answer = await room.room_action()
            self.assertEqual((answer['cgroup_identity'], answer['pre'], answer['during'], answer['post'], answer['recheck']),
                             (None, None, [], None, None))
        self.assertIsNone(room.cgroup_absent)
        self.assertTrue(room.cleanup_confirmed)

    async def test_surface_is_only_room_action_measure_and_close(self):
        room = self.session()
        for name in ('exec_fixed', 'probe', 'cgroup_events', 'file_state', 'copy_scan', 'net_counters', 'container_identity',
                     'cgroup_identity'):
            self.assertFalse(hasattr(room, name), name)
        self.assertNotIn('RoomActorSession', repr(room.run_id))
        with self.assertRaises(client.ActorError) as shell:
            await room.execute('id')
        self.assertEqual((shell.exception.reason,self.owner.ops),('wrong_domain',[]))
        with self.assertRaises(client.ActorError) as caught:
            await room.room_action()
        self.assertEqual((caught.exception.reason, self.owner.ops), ('unknown_handle', []))

    async def test_pins_are_exact_private_and_read_only(self):
        for kwargs in ({'level': 'memory'}, {'level': 'persistence'}, {'run_id': 'x'}, {'context_sha256': 'x'}, {'level': True},
                       {'run_id': type('S', (str,), {})(base.RUN_A)}, {'context_sha256': type('S', (str,), {})(base.CONTEXT)}):
            options = dict(run_id=base.RUN_A, level='processes', context_sha256=base.CONTEXT)
            options.update(kwargs)
            with self.assertRaises(ValueError, msg=str(kwargs)):
                client.RoomActorSession(self.settings, **options)
        room = self.session()
        for name in ('run_id', 'level', 'stage', 'context_sha256'):
            with self.assertRaises(AttributeError):
                setattr(room, name, 'x')
        self.assertEqual((room.level, room.stage, room.run_id, room.context_sha256), ('processes', 'actor', base.RUN_A, base.CONTEXT))
        await self.start()
        async with room:
            copy_of = room.identity
            copy_of['run_id'] = '9' * 32
            self.assertEqual(room.identity['run_id'], base.RUN_A)
        with self.assertRaises(client.ActorError) as caught:
            async with self.session(settings=client.Settings(self.settings.socket_path, base.CLIENT_UID, image_id='sha256:' + 'e' * 64)):
                self.fail('must not enter')
        self.assertEqual(caught.exception.reason, 'image_mismatch')

    async def test_a_second_call_and_a_lost_answer_never_send_the_action_again(self):
        await self.start()
        lost = []

        async def lose(raw):
            lost.append(raw)
            raise OSError('reset')
        async with self.session('processes') as room:
            self.owner.after['room_action'] = lose
            with self.assertRaises(client.ActorError) as caught:
                await room.room_action()
            self.assertEqual(caught.exception.reason, 'owner_unavailable')
            with self.assertRaises(client.ActorError) as caught:
                await room.room_action()
            self.assertEqual(caught.exception.reason, 'action_consumed')
        self.assertEqual((self.owner.ops.count('room_action'), self.runtime.calls['room_action'], len(lost)), (1, 1, 1))
        self.assertTrue(room.cleanup_confirmed)

    async def test_an_incomplete_or_contradictory_answer_is_an_error_not_a_result(self):
        await self.start()

        async def contradict(raw):
            value = json.loads(raw)
            value['during'] = [[64, 1, 0, 1, 100], [64, 1, 0, 1, 99]]
            return enc(value)
        async with self.session('processes') as room:
            self.owner.after['room_action'] = contradict
            with self.assertRaises(client.ActorError) as caught:
                await room.room_action()
            self.assertEqual(caught.exception.reason, 'owner_response_invalid')
        self.assertTrue(room.cleanup_confirmed)

    async def test_cancel_with_the_open_answer_lost_keeps_the_debt_and_is_never_none(self):
        await self.start()
        gate = asyncio.Event()

        async def drop(raw):
            await gate.wait()
            raise OSError('reset')
        self.owner.after['open_level'] = drop
        room = self.session()
        task = asyncio.ensure_future(room.__aenter__())
        await self.wait_op('open_level')
        task.cancel()
        gate.set()
        with self.assertRaises(asyncio.CancelledError) as caught:
            await task
        self.assertIs(caught.exception.cleanup_confirmed, False)
        self.assertEqual((room.cleanup_confirmed, room.identity, self.broker.status()['obligations']), (False, None, 1))

    async def test_cancel_when_the_open_fails_while_waiting_is_false_unless_the_owner_confirmed(self):
        for prepare, expected in ((lambda: self.inventory.fail.__setitem__('begin_level', 'state_unavailable'), False),
                                  (lambda: setattr(self.runtime, 'start_error', RuntimeError('boom')), True)):
            self.reset()
            await self.start()
            self.owner = Owner(self)
            prepare()
            gate = asyncio.Event()
            self.owner.before['open_level'] = gate
            room = self.session()
            task = asyncio.ensure_future(room.__aenter__())
            await self.wait_op('open_level')
            task.cancel()
            gate.set()
            with self.assertRaises(asyncio.CancelledError) as caught:
                await task
            self.assertIs(caught.exception.cleanup_confirmed, expected)

    async def test_cancel_after_a_valid_ack_restitutes_and_keeps_the_identity(self):
        await self.start()
        gate = asyncio.Event()
        self.owner.before['open_level'] = gate
        room = self.session()
        task = asyncio.ensure_future(room.__aenter__())
        await self.wait_op('open_level')
        task.cancel()
        gate.set()
        with self.assertRaises(asyncio.CancelledError) as caught:
            await task
        self.assertIs(caught.exception.cleanup_confirmed, True)
        self.assertEqual(room.identity['intent_id'], self.inventory.history[-1].intent_id)  # persistable although the body never ran
        self.assertIs(room.cgroup_absent, True)

    async def test_a_lost_close_keeps_binding_and_confirms_nothing_until_a_retry(self):
        await self.start()
        calls = []

        async def lose(raw):
            calls.append(1)
            if len(calls) == 1:
                raise OSError('reset')
            return raw
        self.owner.after['close'] = lose
        room = self.session()
        await room.__aenter__()
        identity = room.identity
        with self.assertRaises(client.ActorError) as caught:
            await room.close()
        self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('cleanup_unconfirmed', False))
        self.assertEqual((room.cleanup_confirmed, room.obligation, room.identity, room.cgroup_absent), (False, True, identity, None))
        await room.close()
        self.assertEqual((room.cleanup_confirmed, room.cgroup_absent), (True, True))

    async def test_recover_level_receipt_for_a_room(self):
        await self.start()
        async with self.session('processes') as room:
            pass
        identity = room.identity
        receipt = await client.recover_level_receipt(self.settings, identity, transport=self.owner)
        self.assertEqual((receipt['status'], receipt['cgroup_absent']), ('confirmed', True))
        before = self.owner.ops.count('level_receipt')
        before_ops = list(self.owner.ops)
        for other in ({**identity, 'intent_id': '9' * 32}, {**identity, 'context_sha256': base.OTHER_CONTEXT}):
            with self.assertRaises(client.ActorError) as caught:
                await client.recover_level_receipt(self.settings, other, transport=self.owner)
            self.assertEqual((caught.exception.reason, caught.exception.cleanup_confirmed), ('cleanup_unconfirmed', False))
        self.assertEqual(self.owner.ops.count('level_receipt'), before + 2)
        self.assertEqual(self.owner.ops[len(before_ops):], ['level_receipt', 'level_receipt'])

        async def lie(raw):
            value = json.loads(raw)
            value['cgroup_absent'] = None
            return enc(value)
        self.owner.after['level_receipt'] = lie
        with self.assertRaises(client.ActorError) as caught:
            await client.recover_level_receipt(self.settings, identity, transport=self.owner)
        self.assertEqual(caught.exception.owner_reason, 'owner_response_invalid')


if __name__ == '__main__':
    unittest.main()

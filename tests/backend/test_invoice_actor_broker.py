"""Tests of services/agent/invoice_actor_broker.py with doubles of the injected inventory and runtime.

No Docker or subprocess. Linux-only regressions added by the integrator use local Unix sockets.
The original tests were authored without a shell and their execution belongs to the operator.
The doubles share one log, so the order between diary mutations and runtime calls is asserted on a single timeline.
"""
import ast
import asyncio
import collections
import dataclasses
import json
import os
import socket
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.agent import actor_wire as wire  # noqa: E402
from services.agent import invoice_actor_broker as broker_module  # noqa: E402
from services.agent.invoice_actor_broker import ActorBroker, Limits  # noqa: E402

MODULE = ROOT / 'services' / 'agent' / 'invoice_actor_broker.py'
CLIENT_UID = 4242
INSTALL = '1' * 32
IMAGE = 'sha256:' + 'd' * 64
DIGEST = '5' * 64
CONTAINER = 'c' * 64
FOREIGN = 'f' * 64
RUN_A = '%032x' % 1
RUN_B = '%032x' % 2
PROFILE = {'available': True, 'image_id': IMAGE}
MEAS = {'memory_peak_bytes': 2048, 'memory_observed_max_bytes': None,
        'memory_measurement': {'source': 'cgroup_v2_memory.peak', 'scope': 'level_container', 'kind': 'peak', 'available': True}}
ORDER_OF_OPEN = ['inv:begin', 'rt:create@CREATE_PENDING', 'inv:ack', 'rt:inspect_created@CREATE_ACK', 'inv:starting',
                 'rt:start@START_PENDING', 'rt:inspect_running@START_PENDING', 'inv:activate']
ORDER_OF_CLOSE = ['inv:closing', 'rt:close@CLOSE_PENDING', 'inv:finish']


class StateError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclasses.dataclass(frozen=True)
class Intent:
    intent_id: str
    name: str
    controller_uid: int
    run_id: str
    variant: str
    container_id: object
    phase: str
    profile_sha256: str


class FakeInventory:
    installation_id = INSTALL

    def __init__(self, log):
        self.log = log
        self.current = None
        self.finished = None
        self.used = set()
        self.count = 0
        self.fail = {}
        self.history = []           # every FINISH ever written, as the real diary keeps them: older closures survive later runs
        self.queries = []           # receipt() calls: it is a read, so it never touches `log`, `count`, `current` or `history`
        self.receipt_error = None   # closed code to raise from receipt()
        self.receipt_returns = None  # replaces the answer of receipt() with an arbitrary object (diary malfunction)

    def receipt(self, *, controller_uid, run_id, variant, intent_id, container_id):
        self.queries.append((controller_uid, run_id, variant, intent_id, container_id))
        if self.receipt_error is not None:
            raise StateError(self.receipt_error)
        if self.receipt_returns is not None:
            return self.receipt_returns
        if controller_uid != CLIENT_UID:
            raise StateError('identity_changed')
        for item in self.history:
            if (item.controller_uid, item.run_id, item.variant, item.intent_id, item.container_id) == (
                    controller_uid, run_id, variant, intent_id, container_id):
                return item
        return None

    def _gate(self, name):
        self.log.append('inv:' + name)
        if name in self.fail:
            raise StateError(self.fail[name])

    def pending(self):
        return self.current

    def begin(self, *, controller_uid, run_id, variant):
        self._gate('begin')
        if self.current is not None:
            raise StateError('actor_busy')
        if (controller_uid, run_id, variant) in self.used:
            raise StateError('already_started')
        self.used.add((controller_uid, run_id, variant))
        self.count += 1
        intent_id = '%032x' % (0xa0 + self.count)
        self.current = Intent(intent_id, 'escape-actor-' + intent_id, controller_uid, run_id, variant, None,
                              'CREATE_PENDING', DIGEST)
        return self.current

    def _move(self, name, phase, allowed, intent_id, container_id=None):
        self._gate(name)
        current = self.current
        if current is None or current.intent_id != intent_id or current.phase not in allowed:
            raise StateError('invalid_transition')
        self.current = dataclasses.replace(current, phase=phase, container_id=container_id or current.container_id)
        return self.current

    def ack(self, intent_id, container_id):
        return self._move('ack', 'CREATE_ACK', ('CREATE_PENDING',), intent_id, container_id)

    def starting(self, intent_id):
        return self._move('starting', 'START_PENDING', ('CREATE_ACK',), intent_id)

    def activate(self, intent_id):
        return self._move('activate', 'ACTIVE', ('START_PENDING',), intent_id)

    def closing(self, intent_id):
        return self._move('closing', 'CLOSE_PENDING', ('CREATE_ACK', 'START_PENDING', 'ACTIVE', 'CLOSE_PENDING'), intent_id)

    def finish(self, intent_id, *, container_id):
        self._gate('finish')
        current = self.current
        if (current is None or current.intent_id != intent_id or current.phase != 'CLOSE_PENDING'
                or current.container_id != container_id):
            raise StateError('invalid_transition')
        self.finished, self.current = current, None
        self.history.append(dataclasses.replace(current, phase='FINISH'))
        return self.history[-1]


class FakeRuntime:
    def __init__(self, log, inventory):
        self.log, self.inventory = log, inventory
        self.containers = set()      # IDs of this installation
        self.foreign = {FOREIGN}     # another installation and the current flow: never listed, never touched
        self.removed = []
        self.calls = collections.Counter()
        self.ready_value = True
        self.create_error = None
        self.create_hang = False
        self.create_gate = None
        self.create_id = CONTAINER
        self.start_error = None
        self.created_report = {'compatible': True, 'violations': []}
        self.running_override = None
        self.execute_gate = None
        self.execute_started = None
        self.execute_error = None
        self.execute_result = None
        self.close_gate = None
        self.close_confirms = True
        self.keep_after_close = False

    def _phase(self):
        return self.inventory.current.phase if self.inventory.current is not None else None

    async def ready(self):
        return self.ready_value

    async def installed_ids(self):
        return tuple(sorted(self.containers))

    async def create(self, intent):
        self.calls['create'] += 1
        self.log.append('rt:create@%s' % self._phase())
        if self.create_gate is not None:
            await self.create_gate.wait()
        if self.create_hang:
            await asyncio.sleep(3600)
        if self.create_error is not None:
            self.containers.add(CONTAINER)  # a late creation: the failure is ambiguous
            raise self.create_error
        self.containers.add(self.create_id)
        return self.create_id

    async def inspect_created(self, intent):
        self.log.append('rt:inspect_created@%s' % self._phase())
        return self.created_report

    async def start(self, intent):
        self.calls['start'] += 1
        self.log.append('rt:start@%s' % self._phase())
        if self.start_error is not None:
            raise self.start_error

    async def inspect_running(self, intent):
        self.log.append('rt:inspect_running@%s' % self._phase())
        if self.running_override is not None:
            return self.running_override
        return {'running': True, 'container_id': intent.container_id, 'profile': PROFILE, 'profile_sha256': DIGEST,
                'violations': []}

    async def execute(self, intent, command):
        self.calls['execute'] += 1
        self.log.append('rt:execute')
        if self.execute_started is not None:
            self.execute_started.set()
        if self.execute_gate is not None:
            await self.execute_gate.wait()
        if self.execute_error is not None:
            raise self.execute_error
        return self.execute_result if self.execute_result is not None else {
            'stdout': 'ok', 'stderr': '', 'exit_code': 0, **MEAS}

    async def probe(self, intent, name):
        self.calls['probe'] += 1
        self.log.append('rt:probe:' + name)
        if name == 'measure':
            return dict(MEAS)
        return {'stdout': '{"total":1}', 'stderr': '', 'exit_code': 0, **MEAS}

    async def close(self, intent):
        self.calls['close'] += 1
        self.log.append('rt:close@%s' % self._phase())
        if self.close_gate is not None:
            await self.close_gate.wait()
        if not self.close_confirms:
            return {'cleanup_confirmed': False, 'oom_killed': None, **wire.unavailable_measurement()}
        if not self.keep_after_close:
            self.containers.discard(intent.container_id)
            self.removed.append(intent.container_id)
        return {'cleanup_confirmed': True, 'oom_killed': False, **MEAS}


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def enc(body):
    return json.dumps(body, separators=(',', ':')).encode()


def frame(body):
    return wire.encode_frame(enc(body), limit=wire.MAX_REQUEST_BYTES)


def fast_limits(**overrides):
    values = dict(ready=1.0, ids=1.0, create=0.2, inspect=0.2, start=0.2, execute=0.2, probe=0.2, close=0.5)
    values.update(overrides)
    return Limits(**values)


class FakeReader:
    def __init__(self, data, *, hang=False):
        self.buffer, self.reads, self.hang = bytearray(data), 0, hang

    async def read(self, count):
        self.reads += 1
        if self.hang:
            await asyncio.sleep(3600)
        chunk = bytes(self.buffer[:count])
        del self.buffer[:count]
        return chunk


class FakeConnectionSocket:
    def __init__(self, uid):
        self.uid = uid

    def getsockopt(self, level, option, size):
        return struct.pack('=iII', 1, self.uid, self.uid)


class FakeWriter:
    def __init__(self, uid, *, fail_drain=False):
        self.sock, self.data, self.closed, self.fail_drain = FakeConnectionSocket(uid), bytearray(), False, fail_drain

    def get_extra_info(self, name):
        return self.sock if name == 'socket' else None

    def write(self, data):
        self.data.extend(data)

    async def drain(self):
        if self.fail_drain:
            raise ConnectionResetError

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None

    def response(self):
        data = bytes(self.data)
        length = struct.unpack('>I', data[:4])[0]
        assert len(data) == 4 + length
        return json.loads(data[4:])


class BrokerCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.log = []
        self.inventory = FakeInventory(self.log)
        self.runtime = FakeRuntime(self.log, self.inventory)
        self.clock = Clock()
        self.make()

    async def asyncTearDown(self):
        for task in list(self.broker._tasks):
            task.cancel()
        await asyncio.gather(*list(self.broker._tasks), return_exceptions=True)

    def make(self, **overrides):
        options = dict(runtime=self.runtime, inventory=self.inventory, client_uid=CLIENT_UID, image_id=IMAGE,
                       clock=self.clock, limits=fast_limits())
        options.update(overrides)
        self.broker = ActorBroker(**options)
        return self.broker

    async def start(self):
        await self.broker.reconcile()

    async def call(self, body, uid=CLIENT_UID):
        response = await self.broker.handle(uid, enc(body))
        return None if response is None else json.loads(response)

    async def open(self, run=RUN_A, variant='legitimate'):
        return await self.call({'op': 'open', 'run_id': run, 'variant': variant})

    async def opened(self, run=RUN_A, variant='legitimate'):
        await self.start()
        response = await self.open(run, variant)
        self.assertTrue(response['ok'], response)
        return response

    async def wait_for_call(self, name):
        for _ in range(500):
            if self.runtime.calls[name]:
                return
            await asyncio.sleep(0.001)
        self.fail('runtime never received ' + name)

    def identity(self, response):
        return {key: response[key] for key in wire.IDENTITY_FIELDS}


class ConstructionTests(BrokerCase):
    @unittest.skipUnless(sys.platform == 'linux' and getattr(os, 'geteuid', lambda: 0)() != 0,
                         'real Linux socket with non-root peer')
    async def test_explicitly_bound_socket_serves_an_authenticated_frame(self):
        with tempfile.TemporaryDirectory(prefix='actor-socket-') as directory:
            self.make(client_uid=os.geteuid(), socket_path=str(Path(directory) / 'owner.sock'))
            listening = asyncio.Event()
            original = asyncio.start_server

            async def started(*args, **kwargs):
                server = await original(*args, **kwargs)
                listening.set()
                return server

            with mock.patch.object(asyncio, 'start_server', started):
                serving = asyncio.create_task(self.broker.serve())
                try:
                    await asyncio.wait_for(listening.wait(), timeout=2)
                    original_socket = Path(self.broker._socket_path).stat()
                    second = ActorBroker(runtime=self.runtime, inventory=self.inventory, client_uid=os.geteuid(),
                                         image_id=IMAGE, socket_path=self.broker._socket_path)
                    with self.assertRaises(OSError):
                        await asyncio.wait_for(second.serve(), timeout=2)
                    retained = Path(self.broker._socket_path).stat()
                    self.assertEqual((retained.st_dev, retained.st_ino),
                                     (original_socket.st_dev, original_socket.st_ino))
                    reader, writer = await asyncio.open_unix_connection(self.broker._socket_path)
                    writer.write(wire.encode_frame(wire.encode_request('health'), limit=wire.MAX_REQUEST_BYTES))
                    await writer.drain()
                    writer.write_eof()
                    response = await wire.read_frame_async(reader.read, limit=1024, timeout=2)
                    self.assertTrue(wire.validate_health(wire.decode_response(response, op='health'))['ready'])
                    writer.close()
                    await writer.wait_closed()
                finally:
                    serving.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await serving

    @unittest.skipUnless(sys.platform == 'linux' and getattr(os, 'geteuid', lambda: 0)() != 0,
                         'real Linux socket with non-root owner')
    async def test_owner_teardown_preserves_a_replacement_socket(self):
        from services.agent import invoice_actor_service as service

        with tempfile.TemporaryDirectory(prefix='.actor-teardown-', dir=Path.home()) as directory:
            path = Path(directory) / 'owner.sock'
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as original, \
                    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as replacement:
                inventory = self.inventory
                identities = {}

                class ReplacedBroker:
                    socket_identity = None

                    def __init__(self, **kwargs):
                        pass

                    async def reconcile(self):
                        pass

                    def status(self):
                        return {'blocked': None}

                    async def serve(self):
                        original.bind(str(path))
                        observed = path.stat()
                        self.socket_identity = (observed.st_dev, observed.st_ino)
                        identities['original'] = self.socket_identity
                        path.rename(path.with_name('retired.sock'))
                        replacement.bind(str(path))
                        replaced = path.stat()
                        identities['replacement'] = (replaced.st_dev, replaced.st_ino)

                context = mock.MagicMock()
                context.__enter__.return_value = inventory
                args = SimpleNamespace(client_uid=65534, installation_id=INSTALL, image=IMAGE,
                                       profile_sha256=DIGEST, state_dir=directory, socket=str(path),
                                       initialize_state=False, recover_only=False)
                with mock.patch.object(service.invoice_actor_runtime, '_docker',
                                       mock.AsyncMock(return_value=(0, '["daemon","/var/lib/docker"]', ''))), \
                        mock.patch.object(service.invoice_actor_runtime, 'DockerInvoiceActor', return_value=self.runtime), \
                        mock.patch.object(service.actor_state, 'open_actor_inventory', return_value=context), \
                        mock.patch.object(service.invoice_actor_broker, 'ActorBroker', ReplacedBroker):
                    self.assertEqual(await service.run_owner(args), 0)
                self.assertTrue(path.is_socket())
                retained = path.stat()
                self.assertEqual((retained.st_dev, retained.st_ino), identities['replacement'])
                self.assertNotEqual(identities['replacement'], identities['original'])

    @unittest.skipUnless(sys.platform == 'linux', 'real Linux Unix socket')
    async def test_serving_preserves_an_already_bound_socket(self):
        with tempfile.TemporaryDirectory(prefix='actor-socket-') as directory:
            path = Path(directory) / 'owner.sock'
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                listener.listen(1)
                original = path.stat()
                self.make(socket_path=str(path))
                with self.assertRaises(OSError):
                    await asyncio.wait_for(self.broker.serve(), timeout=1)
                current = path.stat()
                self.assertEqual((current.st_dev, current.st_ino), (original.st_dev, original.st_ino))

    def test_default_ttl_is_120_seconds(self):
        self.assertEqual(broker_module.TTL_SECONDS, 120)

    def test_injected_interfaces_are_checked(self):
        with self.assertRaises(ValueError):
            self.make(runtime=object())
        with self.assertRaises(ValueError):
            self.make(inventory=object())
        for override in ({'client_uid': 0}, {'client_uid': True}, {'image_id': 'sha256:abc'}, {'socket_path': 'relative'},
                         {'reap_interval': 0}, {'read_timeout': -1}):
            with self.assertRaises(ValueError):
                self.make(**override)

    def test_limits_reject_non_positive_values(self):
        with self.assertRaises(ValueError):
            Limits(execute=0)

    def test_client_deadlines_exceed_the_owner_budgets(self):
        limits = Limits()
        opening = limits.ready + limits.ids + limits.create + limits.inspect + limits.start + limits.inspect + limits.close + limits.ids
        self.assertGreater(wire.CLIENT_DEADLINES['open'], opening)
        self.assertGreater(wire.CLIENT_DEADLINES['execute'], limits.execute)
        self.assertGreater(wire.CLIENT_DEADLINES['probe'], limits.probe)
        self.assertGreater(wire.CLIENT_DEADLINES['close'], limits.close + limits.ids + limits.execute)
        self.assertLess(opening, broker_module.TTL_SECONDS)

    def test_module_has_no_docker_subprocess_or_diary_import(self):
        text = MODULE.read_text(encoding='utf-8')
        tree = ast.parse(text)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {item.name.split('.')[0] for item in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(('.' * node.level) + (node.module or '') + ':' + ','.join(item.name for item in node.names))
        self.assertTrue(imported.isdisjoint({'subprocess', 'docker', 'shutil', 'sqlite3'}), imported)
        self.assertFalse(any('actor_state' in item or 'runner' in item for item in imported), imported)
        self.assertNotIn('create_subprocess_exec', text)


class OpenOrderTests(BrokerCase):
    async def test_diary_and_runtime_follow_the_contract_order(self):
        await self.start()
        response = await self.open()
        self.assertEqual(self.log, ORDER_OF_OPEN)
        self.assertTrue(response['ok'])
        wire.validate_open(response, run_id=RUN_A, variant='legitimate', installation_id=INSTALL, image_id=IMAGE)
        self.assertEqual(self.inventory.current.phase, 'ACTIVE')
        self.assertEqual(response['container_id'], CONTAINER)
        self.assertEqual(response['profile_sha256'], DIGEST)

    async def test_nothing_is_created_when_pending_cannot_be_made_durable(self):
        await self.start()
        self.inventory.fail['begin'] = 'state_unavailable'
        response = await self.open()
        self.assertEqual((response['ok'], response['reason']), (False, 'owner_blocked'))
        self.assertEqual(self.runtime.calls['create'], 0)
        self.assertEqual(self.broker.leases.held(), 0)

    async def test_ack_is_durable_before_inspection_and_start(self):
        await self.start()
        self.inventory.fail['ack'] = 'state_unavailable'
        response = await self.open()
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('owner_blocked', False))
        self.assertNotIn('rt:inspect_created@CREATE_ACK', self.log)
        self.assertEqual(self.runtime.calls['start'], 0)
        self.assertEqual(self.runtime.calls['close'], 0)  # the ID was never recognized, so nothing is removed
        self.assertIn(CONTAINER, self.runtime.containers)
        health = await self.call({'op': 'health'})
        self.assertEqual((health['blocked'], health['obligations']), (True, 1))

    async def test_start_pending_is_durable_before_start(self):
        await self.start()
        self.inventory.fail['starting'] = 'state_unavailable'
        response = await self.open()
        self.assertEqual(self.runtime.calls['start'], 0)
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('owner_blocked', True))
        self.assertEqual(self.runtime.removed, [CONTAINER])

    async def test_active_is_durable_before_the_handle_exists(self):
        await self.start()
        self.inventory.fail['activate'] = 'state_unavailable'
        response = await self.open()
        self.assertNotIn('handle', response)
        self.assertFalse(response['ok'])
        self.assertEqual(self.runtime.removed, [CONTAINER])

    async def test_ambiguous_create_blocks_and_is_never_repeated(self):
        await self.start()
        self.runtime.create_error = RuntimeError('boom')
        response = await self.open()
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('create_failed', False))
        self.assertEqual(self.runtime.calls['create'], 1)
        self.assertIsNone(self.inventory.current.container_id)  # PENDING without an ID
        again = await self.open(RUN_B)
        self.assertEqual(again['reason'], 'owner_blocked')
        self.assertEqual(self.runtime.calls['create'], 1)
        self.assertEqual(self.runtime.calls['close'], 0)
        self.assertIn(CONTAINER, self.runtime.containers)  # nothing is removed on a guess
        health = await self.call({'op': 'health'})
        self.assertEqual((health['blocked'], health['obligations']), (True, 1))
        self.assertEqual(self.broker.leases.held(), 1)

    async def test_create_timeout_is_ambiguous_too(self):
        await self.start()
        self.runtime.create_hang = True
        response = await self.open()
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('create_failed', False))
        self.assertEqual((await self.open(RUN_B))['reason'], 'owner_blocked')
        self.assertEqual(self.runtime.calls['create'], 1)

    async def test_create_returning_a_malformed_id_blocks(self):
        await self.start()
        self.runtime.create_id = 'not-an-id'
        response = await self.open()
        self.assertEqual(response['reason'], 'create_failed')
        self.assertEqual(self.runtime.calls['close'], 0)
        self.assertEqual((await self.call({'op': 'health'}))['blocked'], True)

    async def test_incompatible_profile_is_restituted_before_start(self):
        await self.start()
        self.runtime.created_report = {'compatible': False, 'violations': ['read_only']}
        response = await self.open()
        self.assertEqual((response['reason'], response['violations'], response['cleanup_confirmed']),
                         ('profile_rejected', ['read_only'], True))
        self.assertEqual(self.runtime.calls['start'], 0)
        self.assertEqual(self.log[-3:], ORDER_OF_CLOSE)
        self.assertIsNone(self.inventory.current)
        self.assertEqual(self.broker.leases.held(), 0)

    async def test_unknown_violation_names_collapse_to_profile_unavailable(self):
        await self.start()
        self.runtime.created_report = {'compatible': False, 'violations': ['/etc/host-path']}
        response = await self.open()
        self.assertEqual(response['violations'], ['profile_unavailable'])

    async def test_running_identity_is_rechecked_before_the_handle(self):
        for override in (
                {'running': True, 'container_id': 'e' * 64, 'profile': PROFILE, 'profile_sha256': DIGEST, 'violations': []},
                {'running': True, 'container_id': CONTAINER, 'profile': PROFILE, 'profile_sha256': '6' * 64, 'violations': []},
                {'running': True, 'container_id': CONTAINER, 'profile': PROFILE, 'profile_sha256': DIGEST,
                 'violations': ['tmpfs']},
                {'running': True, 'container_id': CONTAINER, 'profile': {'available': False}, 'profile_sha256': DIGEST,
                 'violations': []}):
            with self.subTest(override=override):
                self.log.clear()
                self.inventory = FakeInventory(self.log)
                self.runtime = FakeRuntime(self.log, self.inventory)
                self.make()
                await self.start()
                self.runtime.running_override = override
                response = await self.open()
                self.assertEqual((response['ok'], response['reason'], response['cleanup_confirmed']),
                                 (False, 'profile_rejected', True))
                self.assertEqual(self.runtime.removed, [CONTAINER])
                self.assertNotIn('handle', response)

    async def test_not_running_after_start_is_restituted(self):
        await self.start()
        self.runtime.running_override = {'running': False}
        response = await self.open()
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('not_running', True))

    async def test_start_failure_is_restituted_and_start_is_not_repeated(self):
        await self.start()
        self.runtime.start_error = RuntimeError('boom')
        response = await self.open()
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('start_failed', True))
        self.assertEqual(self.runtime.calls['start'], 1)
        self.assertEqual(self.runtime.removed, [CONTAINER])

    async def test_runtime_not_ready_changes_nothing(self):
        await self.start()
        self.runtime.ready_value = False
        response = await self.open()
        self.assertEqual(response['reason'], 'owner_not_ready')
        self.assertEqual(self.log, [])
        self.assertEqual(self.broker.leases.held(), 0)

    async def test_open_before_reconciliation_is_refused(self):
        response = await self.open()
        self.assertEqual(response['reason'], 'owner_not_ready')
        self.assertEqual(self.log, [])

    async def test_object_of_the_installation_without_intent_blocks_open_and_is_preserved(self):
        await self.start()
        self.runtime.containers.add(FOREIGN)
        response = await self.open()
        self.assertEqual(response['reason'], 'owner_blocked')
        self.assertEqual(self.log, [])
        self.assertEqual(self.runtime.calls['close'], 0)
        self.assertIn(FOREIGN, self.runtime.containers)

    async def test_objects_of_other_installations_are_never_touched(self):
        response = await self.opened()
        closed = await self.call({'op': 'close', 'handle': response['handle']})
        self.assertTrue(closed['ok'])
        self.assertEqual(self.runtime.removed, [CONTAINER])
        self.assertEqual(self.runtime.foreign, {FOREIGN})


class AuthenticationAndFramingTests(BrokerCase):
    async def serve_one(self, data, *, uid=CLIENT_UID, hang=False, fail_drain=False):
        reader, writer = FakeReader(data, hang=hang), FakeWriter(uid, fail_drain=fail_drain)
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            await self.broker._connection(reader, writer)
        return reader, writer

    async def test_unexpected_uid_is_closed_without_reading_or_answering(self):
        await self.start()
        reader, writer = await self.serve_one(frame({'op': 'health'}), uid=CLIENT_UID + 1)
        self.assertEqual(reader.reads, 0)
        self.assertEqual(bytes(writer.data), b'')
        self.assertTrue(writer.closed)

    async def test_handle_says_nothing_to_an_unexpected_uid(self):
        await self.start()
        self.assertIsNone(await self.broker.handle(CLIENT_UID + 1, enc({'op': 'health'})))
        self.assertEqual(self.log, [])

    async def test_missing_peer_credentials_close_the_connection(self):
        await self.start()
        reader, writer = FakeReader(frame({'op': 'health'})), FakeWriter(CLIENT_UID)
        with mock.patch.object(socket, 'SO_PEERCRED', None, create=True):
            await self.broker._connection(reader, writer)
        self.assertEqual((reader.reads, bytes(writer.data)), (0, b''))

    async def test_a_valid_frame_with_eof_is_dispatched(self):
        await self.start()
        reader, writer = await self.serve_one(frame({'op': 'health'}))
        response = writer.response()
        wire.validate_health(response)
        self.assertEqual((response['ready'], response['blocked'], response['obligations']), (True, False, 0))
        self.assertTrue(writer.closed)

    async def assert_framing_without_dispatch(self, data, **kwargs):
        await self.start()
        reader, writer = await self.serve_one(data, **kwargs)
        self.assertEqual(writer.response(), {'ok': False, 'reason': 'framing'})
        self.assertEqual(self.log, [])
        self.assertEqual(self.broker.leases.held(), 0)
        return reader

    async def test_truncated_frame_is_not_dispatched(self):
        await self.assert_framing_without_dispatch(struct.pack('>I', 50) + b'x' * 10)

    async def test_trailing_bytes_are_not_dispatched(self):
        await self.assert_framing_without_dispatch(frame({'op': 'open', 'run_id': RUN_A, 'variant': 'legitimate'}) + b'x')

    async def test_zero_length_frame_is_not_dispatched(self):
        await self.assert_framing_without_dispatch(struct.pack('>I', 0))

    async def test_oversized_length_is_rejected_before_the_body(self):
        reader = await self.assert_framing_without_dispatch(struct.pack('>I', wire.MAX_REQUEST_BYTES + 1) + b'x' * 64)
        self.assertEqual(reader.reads, 1)

    async def test_slow_reader_hits_the_total_deadline(self):
        self.make(read_timeout=0.05)
        await self.assert_framing_without_dispatch(b'', hang=True)

    async def test_invalid_json_gets_a_closed_reason(self):
        await self.start()
        reader, writer = await self.serve_one(wire.encode_frame(b'{"op":', limit=100))
        self.assertEqual(writer.response(), {'ok': False, 'reason': 'invalid_json'})

    async def test_operations_beyond_m1_are_rejected(self):
        await self.start()
        # (M3.1, invalidated by contract: catalog_check is now a closed operation, judged by its shape and its policy)
        # (M4/M5, invalidated by contract: room_action and network_action are closed operations `{op, handle[, command]}`, judged by their
        # shape: without their fields they are missing_field, not unknown_op; see test_actor_rooms_backend and test_actor_network_backend)
        for op in ('open_session', 'copy_scan', 'catalog_run', 'canary_control'):
            response = await self.call({'op': op})
            self.assertEqual(response, {'ok': False, 'reason': 'unknown_op'})
        self.assertEqual(self.log, [])

    async def test_transport_error_while_answering_leaves_the_lease_with_the_owner(self):
        await self.start()
        reader, writer = await self.serve_one(frame({'op': 'open', 'run_id': RUN_A, 'variant': 'legitimate'}),
                                              fail_drain=True)
        self.assertTrue(writer.closed)
        self.assertEqual(self.broker.leases.held(), 1)
        self.assertEqual(self.inventory.current.phase, 'ACTIVE')
        self.clock.now += 121
        await self.broker.reconcile()  # the reaper restitutes the lost handle by ID
        self.assertEqual(self.runtime.removed, [CONTAINER])
        self.assertEqual(self.broker.status()['obligations'], 0)


class LeaseAndReplayTests(BrokerCase):
    async def test_a_second_open_does_not_touch_the_first(self):
        first = await self.opened(RUN_A)
        self.log.clear()
        second = await self.open(RUN_B)
        self.assertEqual(second['reason'], 'capacity_exhausted')
        same = await self.open(RUN_A)
        self.assertEqual(same['reason'], 'already_active')
        self.assertEqual(self.log, [])
        self.assertEqual(self.runtime.calls['create'], 1)
        executed = await self.call({'op': 'execute', 'handle': first['handle'], 'command': 'true'})
        self.assertTrue(executed['ok'])

    async def test_replay_of_a_closed_corrida_and_variant_is_refused_before_docker(self):
        first = await self.opened(RUN_A)
        await self.call({'op': 'close', 'handle': first['handle']})
        self.log.clear()
        replay = await self.open(RUN_A)
        self.assertEqual(replay['reason'], 'already_active')
        self.assertEqual(self.log, ['inv:begin'])
        self.assertEqual(self.runtime.calls['create'], 1)
        self.assertEqual(self.broker.leases.held(), 0)

    async def test_the_other_variant_opens_after_the_first_was_closed(self):
        first = await self.opened(RUN_A, 'legitimate')
        await self.call({'op': 'close', 'handle': first['handle']})
        second = await self.open(RUN_A, 'perturbed')
        self.assertTrue(second['ok'], second)
        self.assertNotEqual(second['handle'], first['handle'])
        self.assertEqual(second['variant'], 'perturbed')

    async def test_unknown_handle_is_refused(self):
        await self.start()
        for op in ({'op': 'close'}, {'op': 'execute', 'command': 'true'}, {'op': 'probe', 'name': 'measure'}):
            response = await self.call({**op, 'handle': 'ab' * 32})
            self.assertEqual(response, {'ok': False, 'reason': 'unknown_handle'})

    async def test_ttl_is_absolute_and_activity_does_not_extend_it(self):
        opened = await self.opened()
        self.clock.now += 119
        self.assertTrue((await self.call({'op': 'execute', 'handle': opened['handle'], 'command': 'true'}))['ok'])
        self.clock.now += 1.5
        expired = await self.call({'op': 'execute', 'handle': opened['handle'], 'command': 'true'})
        self.assertEqual(expired['reason'], 'expired')
        self.assertEqual(self.broker.leases.held(), 1)  # an expired lease keeps its plaza until restitution
        await self.broker.reconcile()
        self.assertEqual(self.runtime.removed, [CONTAINER])
        self.assertEqual(self.broker.leases.held(), 0)


class CloseTests(BrokerCase):
    async def test_close_is_idempotent_and_removes_once(self):
        opened = await self.opened()
        self.log.clear()
        first = await self.call({'op': 'close', 'handle': opened['handle']})
        second = await self.call({'op': 'close', 'handle': opened['handle']})
        self.assertEqual(first, second)
        self.assertEqual(self.runtime.calls['close'], 1)
        self.assertEqual(self.log, ORDER_OF_CLOSE)
        receipt = wire.validate_close(first, receipt=self.identity(opened))
        self.assertEqual(receipt['oom_killed'], False)
        self.assertEqual(self.broker.status()['obligations'], 0)
        self.assertIsNotNone(self.inventory.finished)

    async def test_concurrent_closes_share_one_restitution(self):
        opened = await self.opened()
        first, second = await asyncio.gather(self.call({'op': 'close', 'handle': opened['handle']}),
                                             self.call({'op': 'close', 'handle': opened['handle']}))
        self.assertEqual(first, second)
        self.assertTrue(first['ok'])
        self.assertEqual(self.runtime.calls['close'], 1)

    async def test_operations_after_close_find_no_handle(self):
        opened = await self.opened()
        await self.call({'op': 'close', 'handle': opened['handle']})
        response = await self.call({'op': 'execute', 'handle': opened['handle'], 'command': 'true'})
        self.assertEqual(response['reason'], 'unknown_handle')
        self.assertEqual(self.runtime.calls['execute'], 0)

    async def test_unconfirmed_close_keeps_the_obligation_until_restitution(self):
        opened = await self.opened()
        self.runtime.close_confirms = False
        response = await self.call({'op': 'close', 'handle': opened['handle']})
        self.assertEqual((response['ok'], response['reason'], response['cleanup_confirmed']),
                         (False, 'cleanup_unconfirmed', False))
        self.assertEqual(self.inventory.current.phase, 'CLOSE_PENDING')
        self.assertEqual(self.broker.leases.held(), 1)
        health = await self.call({'op': 'health'})
        self.assertEqual(health['obligations'], 1)
        self.assertEqual((await self.open(RUN_B))['reason'], 'capacity_exhausted')
        self.runtime.close_confirms = True
        await self.broker.reconcile()  # same ID, same procedure
        self.assertEqual(self.broker.status()['obligations'], 0)
        self.assertEqual(self.runtime.removed, [CONTAINER])
        late = await self.call({'op': 'close', 'handle': opened['handle']})
        self.assertTrue(late['ok'])
        wire.validate_close(late, receipt=self.identity(opened))
        self.assertEqual(self.runtime.calls['close'], 2)

    async def test_a_retry_of_the_close_by_the_client_also_restitutes(self):
        opened = await self.opened()
        self.runtime.close_confirms = False
        self.assertFalse((await self.call({'op': 'close', 'handle': opened['handle']}))['ok'])
        self.runtime.close_confirms = True
        again = await self.call({'op': 'close', 'handle': opened['handle']})
        self.assertTrue(again['ok'])
        self.assertEqual(self.runtime.calls['close'], 2)

    async def test_runtime_that_confirms_but_still_lists_the_id_is_not_trusted(self):
        opened = await self.opened()
        self.runtime.keep_after_close = True
        response = await self.call({'op': 'close', 'handle': opened['handle']})
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('cleanup_unconfirmed', False))
        self.assertIsNone(self.inventory.finished)
        self.assertEqual(self.inventory.current.phase, 'CLOSE_PENDING')

    async def test_finish_failure_is_not_a_confirmation(self):
        opened = await self.opened()
        self.inventory.fail['finish'] = 'state_unavailable'
        response = await self.call({'op': 'close', 'handle': opened['handle']})
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('cleanup_unconfirmed', False))
        self.assertEqual((await self.call({'op': 'health'}))['blocked'], True)

    async def test_cancelled_close_request_does_not_cancel_the_restitution(self):
        self.make(limits=fast_limits(close=2.0))
        opened = await self.opened()
        self.runtime.close_gate = asyncio.Event()
        task = asyncio.ensure_future(self.call({'op': 'close', 'handle': opened['handle']}))
        await self.wait_for_call('close')
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.runtime.close_gate.set()
        await self.broker.drain()
        self.assertIsNone(self.inventory.current)
        self.assertEqual(self.runtime.removed, [CONTAINER])
        again = await self.call({'op': 'close', 'handle': opened['handle']})
        self.assertTrue(again['ok'])
        self.assertEqual(self.runtime.calls['close'], 1)

    async def test_cancelled_open_leaves_the_handle_to_the_reaper(self):
        self.make(limits=fast_limits(create=2.0))
        await self.start()
        self.runtime.create_gate = asyncio.Event()
        task = asyncio.ensure_future(self.open())
        await self.wait_for_call('create')
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.runtime.create_gate.set()
        await self.broker.drain()
        self.assertEqual(self.inventory.current.phase, 'ACTIVE')  # the open completed; its response was dropped
        self.assertEqual(self.broker.status()['obligations'], 1)
        self.clock.now += 121
        await self.broker.reconcile()
        self.assertEqual(self.runtime.removed, [CONTAINER])
        self.assertEqual(self.broker.status()['obligations'], 0)

    async def test_health_is_separate_from_close(self):
        self.make(limits=fast_limits(close=2.0))
        opened = await self.opened()
        self.runtime.close_gate = asyncio.Event()
        closing = asyncio.ensure_future(self.call({'op': 'close', 'handle': opened['handle']}))
        await self.wait_for_call('close')
        health = await asyncio.wait_for(self.call({'op': 'health'}), 1)  # answers while the close is in flight
        self.assertEqual((health['ready'], health['blocked'], health['obligations']), (True, False, 1))
        self.assertEqual(self.runtime.calls['close'], 1)
        self.runtime.close_gate.set()
        self.assertTrue((await closing)['ok'])
        self.assertEqual((await self.call({'op': 'health'}))['obligations'], 0)


class OperationTests(BrokerCase):
    async def test_execute_and_probes_return_validated_shapes(self):
        opened = await self.opened()
        executed = await self.call({'op': 'execute', 'handle': opened['handle'], 'command': 'cat -- /work/input.json'})
        self.assertEqual(wire.validate_result(executed, op='execute')['stdout'], 'ok')
        for name in ('task_result', 'artifact_capture'):
            probe = await self.call({'op': 'probe', 'handle': opened['handle'], 'name': name})
            wire.validate_result(probe, op='probe', name=name)
        measure = await self.call({'op': 'probe', 'handle': opened['handle'], 'name': 'measure'})
        self.assertEqual(wire.validate_measure(measure), MEAS)

    async def test_close_waits_for_the_operation_in_flight_and_new_ones_get_closing(self):
        self.make(limits=fast_limits(execute=2.0))
        opened = await self.opened()
        handle = opened['handle']
        self.runtime.execute_gate = asyncio.Event()
        self.runtime.execute_started = asyncio.Event()
        running = asyncio.ensure_future(self.call({'op': 'execute', 'handle': handle, 'command': 'sleep 1'}))
        await self.runtime.execute_started.wait()
        busy = await self.call({'op': 'execute', 'handle': handle, 'command': 'true'})
        self.assertEqual(busy['reason'], 'busy')
        closing = asyncio.ensure_future(self.call({'op': 'close', 'handle': handle}))
        await asyncio.sleep(0.05)
        self.assertEqual(self.runtime.calls['close'], 0)  # the restitution waits for the operation
        refused = await self.call({'op': 'probe', 'handle': handle, 'name': 'measure'})
        self.assertEqual(refused['reason'], 'closing')
        self.runtime.execute_gate.set()
        self.assertTrue((await running)['ok'])
        self.assertTrue((await closing)['ok'])
        self.assertLess(self.log.index('rt:execute'), self.log.index('rt:close@CLOSE_PENDING'))
        self.assertEqual(self.runtime.calls['execute'], 1)

    async def test_execute_timeout_invalidates_the_lease_and_is_never_replayed(self):
        opened = await self.opened()
        self.runtime.execute_gate = asyncio.Event()  # never set: the action hangs
        self.runtime.close_gate = asyncio.Event()
        response = await self.call({'op': 'execute', 'handle': opened['handle'], 'command': 'sleep 99'})
        self.assertEqual(response, {'ok': False, 'reason': 'exec_timeout'})
        after = await self.call({'op': 'execute', 'handle': opened['handle'], 'command': 'true'})
        self.assertEqual(after['reason'], 'closing')
        self.runtime.close_gate.set()
        await self.broker.drain()
        self.assertEqual(self.runtime.calls['execute'], 1)
        self.assertEqual(self.runtime.removed, [CONTAINER])
        receipt = await self.call({'op': 'close', 'handle': opened['handle']})  # the recorded receipt, not a second close
        wire.validate_close(receipt, receipt=self.identity(opened))
        self.assertEqual(self.runtime.calls['close'], 1)

    async def test_runtime_failures_map_to_closed_reasons_and_end_the_lease(self):
        class Stopped(Exception):
            reason = 'sandbox_stopped'
        for error, reason in ((Stopped(), 'sandbox_stopped'), (RuntimeError('boom'), 'internal_error')):
            with self.subTest(reason=reason):
                self.log.clear()
                self.inventory = FakeInventory(self.log)
                self.runtime = FakeRuntime(self.log, self.inventory)
                self.make()
                opened = await self.opened()
                self.runtime.execute_error = error
                response = await self.call({'op': 'execute', 'handle': opened['handle'], 'command': 'true'})
                self.assertEqual(response, {'ok': False, 'reason': reason})
                await self.broker.drain()
                self.assertEqual(self.runtime.removed, [CONTAINER])
                self.assertEqual(self.runtime.calls['execute'], 1)

    async def test_invalid_runtime_output_is_not_forwarded(self):
        for result in ({'stdout': 1, 'stderr': '', 'exit_code': 0, **MEAS},
                       {'stdout': 'x' * 5000, 'stderr': '', 'exit_code': 0, **MEAS},
                       {'stdout': '', 'stderr': '', 'exit_code': True, **MEAS},
                       {'stdout': '', 'stderr': ''}, 'text'):
            with self.subTest(result=str(result)[:40]):
                self.log.clear()
                self.inventory = FakeInventory(self.log)
                self.runtime = FakeRuntime(self.log, self.inventory)
                self.make()
                opened = await self.opened()
                self.runtime.execute_result = result
                response = await self.call({'op': 'execute', 'handle': opened['handle'], 'command': 'true'})
                self.assertEqual(response, {'ok': False, 'reason': 'internal_error'})
                await self.broker.drain()
                self.assertEqual(self.runtime.removed, [CONTAINER])

    async def test_runtime_extras_are_dropped_from_the_response(self):
        opened = await self.opened()
        self.runtime.execute_result = {'stdout': 'ok', 'stderr': '', 'exit_code': 0, **MEAS, 'host_path': '/var/lib/x'}
        response = await self.call({'op': 'execute', 'handle': opened['handle'], 'command': 'true'})
        self.assertTrue(response['ok'])
        self.assertNotIn('host_path', response)


class RecoveryTests(BrokerCase):
    async def test_restart_restitutes_a_recognized_id_without_reissuing_actions(self):
        opened = await self.opened()
        self.make()  # a new process over the same diary and runtime
        self.log.clear()
        await self.start()
        self.assertEqual(self.log, ORDER_OF_CLOSE)
        self.assertEqual(self.runtime.removed, [CONTAINER])
        self.assertEqual(self.runtime.foreign, {FOREIGN})
        self.assertEqual((self.runtime.calls['create'], self.runtime.calls['start'], self.runtime.calls['execute']), (1, 1, 0))
        self.assertEqual(self.broker.status(), {'installation_id': INSTALL, 'blocked': None, 'obligations': 0, 'recovered': True})
        stale = await self.call({'op': 'close', 'handle': opened['handle']})
        self.assertEqual(stale['reason'], 'unknown_handle')  # a restart invalidates handles; health never stands in for it
        self.assertTrue((await self.open(RUN_B))['ok'])

    async def test_every_phase_with_a_known_id_is_restituted_by_id(self):
        for phase in ('CREATE_ACK', 'START_PENDING', 'ACTIVE', 'CLOSE_PENDING'):
            with self.subTest(phase=phase):
                self.log.clear()
                self.inventory = FakeInventory(self.log)
                self.runtime = FakeRuntime(self.log, self.inventory)
                self.make()
                self.inventory.current = Intent('a' * 32, 'escape-actor-' + 'a' * 32, CLIENT_UID, RUN_A, 'legitimate',
                                                CONTAINER, phase, DIGEST)
                self.runtime.containers.add(CONTAINER)
                await self.start()
                self.assertEqual(self.runtime.removed, [CONTAINER])
                self.assertEqual(self.log, ORDER_OF_CLOSE)
                self.assertEqual(self.runtime.foreign, {FOREIGN})
                for name in ('create', 'start', 'execute', 'probe'):
                    self.assertEqual(self.runtime.calls[name], 0)
                self.assertTrue(self.broker.status()['recovered'])

    async def test_pending_without_an_id_blocks_even_with_an_empty_inventory(self):
        self.inventory.current = Intent('a' * 32, 'escape-actor-' + 'a' * 32, CLIENT_UID, RUN_A, 'legitimate', None,
                                        'CREATE_PENDING', DIGEST)
        await self.start()
        self.assertEqual(self.broker.status()['blocked'], 'create_uncertain')
        self.assertEqual(self.broker.status()['obligations'], 1)
        self.assertEqual(self.runtime.calls['close'], 0)
        self.assertEqual((await self.open(RUN_B))['reason'], 'owner_blocked')
        await self.broker.reconcile()  # time and repetition do not clear it
        self.assertEqual(self.broker.status()['blocked'], 'create_uncertain')

    async def test_a_labelled_object_without_intent_blocks_and_is_preserved(self):
        self.runtime.containers.add(FOREIGN)
        await self.start()
        self.assertEqual(self.broker.status()['blocked'], 'unrecognized_object')
        self.assertEqual(self.runtime.calls['close'], 0)
        self.assertIn(FOREIGN, self.runtime.containers)
        self.assertFalse(self.broker.status()['recovered'])

    async def test_unrecognized_object_next_to_a_recognized_id_is_preserved(self):
        self.inventory.current = Intent('a' * 32, 'escape-actor-' + 'a' * 32, CLIENT_UID, RUN_A, 'legitimate', CONTAINER,
                                        'ACTIVE', DIGEST)
        self.runtime.containers.update({CONTAINER, FOREIGN})
        await self.start()
        self.assertEqual(self.runtime.removed, [CONTAINER])
        self.assertIn(FOREIGN, self.runtime.containers)
        self.assertEqual(self.broker.status()['blocked'], 'unrecognized_object')

    async def test_unconfirmed_restitution_at_startup_blocks_and_is_retried(self):
        self.inventory.current = Intent('a' * 32, 'escape-actor-' + 'a' * 32, CLIENT_UID, RUN_A, 'legitimate', CONTAINER,
                                        'ACTIVE', DIGEST)
        self.runtime.containers.add(CONTAINER)
        self.runtime.close_confirms = False
        await self.start()
        self.assertEqual(self.broker.status()['blocked'], 'cleanup_unconfirmed')
        self.assertFalse(self.broker.status()['recovered'])
        self.assertEqual((await self.open(RUN_B))['reason'], 'owner_blocked')
        self.runtime.close_confirms = True
        await self.broker.reconcile()
        self.assertEqual(self.broker.status(), {'installation_id': INSTALL, 'blocked': None, 'obligations': 0, 'recovered': True})
        self.assertEqual(self.runtime.removed, [CONTAINER])

    async def test_unreadable_diary_blocks_everything(self):
        class Broken(FakeInventory):
            def pending(self):
                raise StateError('identity_changed')
        self.inventory = Broken(self.log)
        self.runtime = FakeRuntime(self.log, self.inventory)
        self.make()
        await self.start()
        self.assertEqual(self.broker.status()['blocked'], 'identity_changed')
        self.assertEqual((await self.open())['reason'], 'owner_blocked')
        health = await self.call({'op': 'health'})
        self.assertEqual((health['ready'], health['blocked']), (False, True))
        self.assertEqual(self.runtime.calls['close'], 0)

    async def test_an_exhausted_diary_blocks_open_without_touching_docker(self):
        await self.start()
        self.inventory.fail['begin'] = 'state_unavailable'
        self.assertEqual((await self.open())['reason'], 'owner_blocked')
        self.assertEqual((await self.open(RUN_B))['reason'], 'owner_blocked')
        self.assertEqual(self.runtime.calls['create'], 0)


class ExplodingRuntime:
    """Replaces the runtime after a closure: any attribute access fails the query and is recorded in `touched`."""

    def __init__(self):
        self.touched = []

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        self.touched.append(name)
        raise AssertionError('the receipt query reached the runtime: ' + name)


IDENT = {'installation_id': INSTALL, 'run_id': RUN_A, 'variant': 'legitimate', 'intent_id': '5' * 32, 'container_id': CONTAINER}


class ReceiptTests(BrokerCase):
    """The durable `receipt` query: sync, read-only, answered from the diary alone. Authored without a shell: not executed."""

    def body(self, identity, **patch):
        return {'op': 'receipt', **identity, **patch}

    def snapshot(self):
        return (list(self.log), dict(self.runtime.calls), self.inventory.count, self.inventory.current,
                len(self.inventory.history), tuple(sorted(self.runtime.containers)), list(self.runtime.removed),
                self.broker.status(), self.broker.leases.held())

    async def exchange(self, body, uid=CLIENT_UID):
        """One request; asserts that the diary, the runtime, the leases and the owner state did not move."""
        before = self.snapshot()
        response = await self.call(body, uid=uid)
        self.assertEqual(self.snapshot(), before)
        return response

    async def query(self, identity, **patch):
        requested = {**identity, **patch}
        response = await self.exchange(self.body(requested))
        self.assertTrue(response['ok'], response)
        wire.validate_receipt(response, identity=requested)  # exact shape, and only the identity that was asked about
        return response

    async def closed(self, run=RUN_A, variant='legitimate'):
        opened = await self.opened(run, variant) if not self.broker.status()['recovered'] else await self.open(run, variant)
        self.assertTrue(opened['ok'], opened)
        closed = await self.call({'op': 'close', 'handle': opened['handle']})
        identity = self.identity(opened)
        wire.validate_close(closed, receipt=identity)
        return identity

    def assertStatus(self, answer, status):
        self.assertEqual((answer['status'], answer['cleanup_confirmed']), (status, status == 'confirmed'))

    # ---------------------------------------------------------------------------------------- pending, then confirmed

    async def test_unknown_before_finish_and_confirmed_after_it(self):
        opened = await self.opened()
        identity = self.identity(opened)
        self.assertStatus(await self.query(identity), 'unknown')  # ACTIVE: the obligation is still open
        self.assertEqual(self.inventory.current.phase, 'ACTIVE')
        closed = await self.call({'op': 'close', 'handle': opened['handle']})
        wire.validate_close(closed, receipt=identity)
        confirmed = await self.query(identity)
        self.assertStatus(confirmed, 'confirmed')
        self.assertEqual(await self.query(identity), confirmed)  # a read: repeating it gives the same answer

    async def test_close_pending_is_unknown_until_the_owner_reconciles(self):
        opened = await self.opened()
        identity = self.identity(opened)
        self.runtime.close_confirms = False
        failed = await self.call({'op': 'close', 'handle': opened['handle']})
        self.assertEqual(failed['reason'], 'cleanup_unconfirmed')
        self.assertEqual(self.inventory.current.phase, 'CLOSE_PENDING')
        closes = self.runtime.calls['close']
        for _ in range(2):
            self.assertStatus(await self.query(identity), 'unknown')
        self.assertEqual(self.runtime.calls['close'], closes)  # asking never retried the close
        self.runtime.close_confirms = True
        await self.broker.reconcile()
        self.assertStatus(await self.query(identity), 'confirmed')

    async def test_crash_before_finish_is_unknown_until_the_restarted_owner_finishes(self):
        opened = await self.opened()
        identity = self.identity(opened)
        self.runtime.close_confirms = False
        await self.call({'op': 'close', 'handle': opened['handle']})
        self.make()  # the owner process dies and a new one starts over the same diary and runtime
        self.runtime.close_confirms = True
        self.assertStatus(await self.query(identity), 'unknown')  # before reconciliation nothing is confirmed
        await self.start()
        self.assertEqual(self.log[-3:], ORDER_OF_CLOSE)
        self.assertStatus(await self.query(identity), 'confirmed')
        self.assertEqual((self.runtime.calls['create'], self.runtime.calls['start'], self.runtime.calls['execute']), (1, 1, 0))

    async def test_a_receipt_requires_the_finish_not_an_empty_inventory(self):
        opened = await self.opened()
        identity = self.identity(opened)
        self.runtime.containers.clear()  # the ID is gone from Docker, but the diary never reached FINISH
        self.assertEqual(await self.runtime.installed_ids(), ())
        self.assertStatus(await self.query(identity), 'unknown')
        self.assertEqual(self.broker.status()['obligations'], 1)

    # ------------------------------------------------------------------------------- lost response, restart, later run

    async def test_lost_close_response_is_recovered_after_a_restart_without_any_lease(self):
        opened = await self.opened()
        identity = self.identity(opened)
        await self.call({'op': 'close', 'handle': opened['handle']})  # the answer is lost: the test discards it
        self.make()  # a new owner process: no lease, no tombstone, not yet reconciled
        calls = dict(self.runtime.calls)
        before_start = await self.query(identity)
        self.assertStatus(before_start, 'confirmed')
        await self.start()
        self.assertEqual(await self.query(identity), before_start)
        self.assertEqual(self.broker.leases.held(), 0)
        stale = await self.call({'op': 'close', 'handle': opened['handle']})
        self.assertEqual(stale['reason'], 'unknown_handle')  # the handle did not survive; the diary did
        self.assertEqual(dict(self.runtime.calls), calls)

    async def test_an_older_receipt_survives_a_later_run_and_a_second_restart(self):
        first = await self.closed(RUN_A, 'legitimate')
        self.runtime.create_id = 'e' * 64  # distinct container for the later run
        second_open = await self.open(RUN_B, 'perturbed')
        self.assertTrue(second_open['ok'], second_open)
        second = self.identity(second_open)
        self.assertNotEqual(first['container_id'], second['container_id'])
        self.assertStatus(await self.query(first), 'confirmed')  # another run holds the single plaza
        self.assertStatus(await self.query(second), 'unknown')
        await self.call({'op': 'close', 'handle': second_open['handle']})
        for _ in range(2):
            self.assertStatus(await self.query(first), 'confirmed')  # the last closure is not the only one kept
            self.assertStatus(await self.query(second), 'confirmed')
            self.make()  # restart, queried before and after reconciliation
            self.assertStatus(await self.query(first), 'confirmed')
            await self.start()

    async def test_an_empty_or_unrelated_diary_knows_nothing(self):
        await self.start()
        answer = await self.query({**IDENT, 'run_id': '7' * 32, 'intent_id': '7' * 32, 'container_id': '7' * 64})
        self.assertStatus(answer, 'unknown')
        self.assertStatus(await self.query(IDENT), 'unknown')

    async def test_it_answers_in_every_owner_state(self):
        identity = await self.closed()
        self.runtime.containers.add(FOREIGN)
        self.make()
        await self.start()
        self.assertEqual(self.broker.status()['blocked'], 'unrecognized_object')  # blocked owner
        self.assertStatus(await self.query(identity), 'confirmed')
        self.make()
        self.assertEqual(self.broker.status()['recovered'], False)  # not reconciled
        self.assertStatus(await self.query(identity), 'confirmed')
        self.broker._shutdown = True  # shutting down
        self.assertStatus(await self.query(identity), 'confirmed')

    # ------------------------------------------------------------------------------------------------ crossed identity

    async def test_installation_mismatch_is_a_closed_refusal_that_never_reaches_the_diary(self):
        identity = await self.closed()
        answer = await self.exchange(self.body(identity, installation_id='9' * 32))
        self.assertEqual(answer, {'ok': False, 'reason': 'installation_mismatch'})
        self.assertEqual(self.inventory.queries, [])
        self.assertStatus(await self.query(identity), 'confirmed')  # the right installation still gets its receipt

    async def test_another_uid_gets_no_answer_and_the_diary_is_asked_only_about_the_authenticated_uid(self):
        identity = await self.closed()
        body = self.body(identity)
        self.assertIsNone(await self.exchange(body, uid=CLIENT_UID + 1))
        reader, writer = FakeReader(frame(body)), FakeWriter(CLIENT_UID + 1)
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            await self.broker._connection(reader, writer)
        self.assertEqual((reader.reads, bytes(writer.data), writer.closed), (0, b'', True))
        self.assertEqual(self.inventory.queries, [])
        await self.query(identity)
        self.assertEqual({item[0] for item in self.inventory.queries}, {CLIENT_UID})
        for field in ('controller_uid', 'uid', 'owner_uid'):  # the request cannot name another UID
            answer = await self.exchange(self.body(identity, **{field: CLIENT_UID + 1}))
            self.assertEqual(answer, {'ok': False, 'reason': 'unexpected_field'})
        self.assertEqual(len(self.inventory.queries), 1)

    async def test_a_different_binding_is_unknown_and_only_echoes_what_was_asked(self):
        identity = await self.closed()
        other = {'run_id': RUN_B, 'variant': 'perturbed', 'intent_id': '7' * 32, 'container_id': '7' * 64}
        for key, value in other.items():
            answer = await self.query(identity, **{key: value})
            self.assertStatus(answer, 'unknown')
            self.assertEqual(answer[key], value)
        self.assertStatus(await self.query(identity, **other), 'unknown')
        self.assertStatus(await self.query(identity), 'confirmed')

    async def test_a_receipt_is_not_transferable_between_runs(self):
        first = await self.closed(RUN_A, 'legitimate')
        self.runtime.create_id = 'e' * 64
        second = await self.closed(RUN_B, 'legitimate')
        for key in ('run_id', 'intent_id', 'container_id'):
            self.assertStatus(await self.query(first, **{key: second[key]}), 'unknown')
            self.assertStatus(await self.query(second, **{key: first[key]}), 'unknown')
        self.assertStatus(await self.query(first), 'confirmed')
        self.assertStatus(await self.query(second), 'confirmed')

    async def test_diary_failures_are_closed_and_change_nothing(self):
        await self.start()
        for code, reason in (('identity_changed', 'foreign_owner'), ('state_unavailable', 'internal_error'),
                             ('state_corrupt', 'internal_error'), ('not a closed code!', 'internal_error')):
            self.inventory.receipt_error = code
            self.assertEqual(await self.exchange(self.body(IDENT)), {'ok': False, 'reason': reason})
        self.inventory.receipt_error = None

        def broken(**kwargs):
            raise RuntimeError('boom')
        self.inventory.receipt = broken
        self.assertEqual(await self.exchange(self.body(IDENT)), {'ok': False, 'reason': 'internal_error'})
        self.assertIsNone(self.broker.status()['blocked'])  # a failed read never blocks the owner

    async def test_only_the_exact_finish_confirms(self):
        await self.start()
        finish = Intent(IDENT['intent_id'], 'escape-actor-' + IDENT['intent_id'], CLIENT_UID, RUN_A, 'legitimate', CONTAINER,
                        'FINISH', DIGEST)
        self.inventory.receipt_returns = finish
        self.assertStatus(await self.query(IDENT), 'confirmed')
        for patch in ({'phase': 'ACTIVE'}, {'phase': 'CLOSE_PENDING'}, {'controller_uid': CLIENT_UID + 1}, {'run_id': RUN_B},
                      {'variant': 'perturbed'}, {'intent_id': '7' * 32}, {'container_id': '7' * 64}):
            self.inventory.receipt_returns = dataclasses.replace(finish, **patch)
            answer = await self.exchange(self.body(IDENT))
            self.assertEqual(answer, {'ok': False, 'reason': 'internal_error'}, patch)  # another identity cannot confirm
        self.inventory.receipt_returns = object()
        self.assertEqual(await self.exchange(self.body(IDENT)), {'ok': False, 'reason': 'internal_error'})

    async def test_an_inventory_without_receipt_never_confirms_and_construction_does_not_require_it(self):
        class NoReceipt(FakeInventory):
            receipt = None
        self.inventory = NoReceipt(self.log)
        self.runtime = FakeRuntime(self.log, self.inventory)
        self.make()
        await self.start()
        self.assertEqual(await self.exchange(self.body(IDENT)), {'ok': False, 'reason': 'internal_error'})
        self.assertTrue((await self.open())['ok'])  # the A3 operations are untouched

    async def test_malformed_requests_get_closed_reasons_without_a_diary_query(self):
        await self.start()
        cases = (({'installation_id': 'x'}, 'invalid_installation_id'), ({'run_id': 'x'}, 'invalid_run_id'),
                 ({'variant': 'other'}, 'invalid_variant'), ({'intent_id': 5}, 'invalid_intent_id'),
                 ({'container_id': 'c' * 63}, 'invalid_container_id'), ({'handle': 'ab' * 32}, 'unexpected_field'),
                 ({'image': 'x'}, 'forbidden_field'), ({'command': 'id'}, 'unexpected_field'))
        for patch, reason in cases:
            self.assertEqual(await self.exchange(self.body(IDENT, **patch)), {'ok': False, 'reason': reason}, patch)
        short = {key: value for key, value in self.body(IDENT).items() if key != 'run_id'}
        self.assertEqual(await self.exchange(short), {'ok': False, 'reason': 'missing_field'})
        self.assertEqual(self.inventory.queries, [])

    # ------------------------------------------------------------------------------- no action, no mutation, TTL kept

    async def test_the_query_never_reaches_the_runtime_or_mutates_anything(self):
        identity = await self.closed()
        calls, log = dict(self.runtime.calls), list(self.log)
        exploding = ExplodingRuntime()
        self.broker.runtime = exploding  # from here any runtime access is an error
        for _ in range(3):
            self.assertStatus(await self.query(identity), 'confirmed')
            self.assertStatus(await self.query(identity, run_id=RUN_B), 'unknown')
        self.assertEqual(exploding.touched, [])
        for name in ('create', 'start', 'execute', 'probe', 'close'):
            self.assertEqual(self.runtime.calls[name], calls.get(name, 0), name)
        self.assertEqual(self.log, log)  # no diary mutation and no event: the timeline did not grow
        self.assertEqual(self.runtime.removed, [CONTAINER])

    async def test_it_neither_waits_for_the_operation_in_flight_nor_extends_the_ttl(self):
        self.make(limits=fast_limits(execute=2.0))
        opened = await self.opened()
        identity = self.identity(opened)
        handle = opened['handle']
        self.runtime.execute_gate = asyncio.Event()
        self.runtime.execute_started = asyncio.Event()
        running = asyncio.ensure_future(self.call({'op': 'execute', 'handle': handle, 'command': 'sleep 1'}))
        await self.runtime.execute_started.wait()
        answer = await asyncio.wait_for(self.query(identity), 1)  # no lock of the handle is taken: no `busy`, no wait
        self.assertStatus(answer, 'unknown')
        self.assertEqual((await self.call({'op': 'execute', 'handle': handle, 'command': 'true'}))['reason'], 'busy')
        self.runtime.execute_gate.set()
        self.assertTrue((await running)['ok'])
        self.assertEqual(self.runtime.calls['execute'], 1)  # the action was neither repeated nor cancelled
        self.clock.now += 119
        self.assertStatus(await self.query(identity), 'unknown')  # asking at 119 s does not renew the lease
        self.clock.now += 1.5
        self.assertEqual((await self.call({'op': 'execute', 'handle': handle, 'command': 'true'}))['reason'], 'expired')
        await self.broker.reconcile()
        self.assertStatus(await self.query(identity), 'confirmed')

    async def test_dispatch_through_an_authenticated_connection(self):
        identity = await self.closed()
        reader, writer = FakeReader(frame(self.body(identity))), FakeWriter(CLIENT_UID)
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            await self.broker._connection(reader, writer)
        self.assertStatus(wire.validate_receipt(writer.response(), identity=identity), 'confirmed')
        self.assertTrue(writer.closed)
        self.assertLessEqual(len(bytes(writer.data)) - 4, wire.RESPONSE_LIMITS['receipt'])
        queries = len(self.inventory.queries)
        reader, writer = FakeReader(frame(self.body(identity)) + b'x'), FakeWriter(CLIENT_UID)
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            await self.broker._connection(reader, writer)
        self.assertEqual(writer.response(), {'ok': False, 'reason': 'framing'})  # trailing bytes: not dispatched
        self.assertEqual(len(self.inventory.queries), queries)

    async def test_the_a3_operations_and_limits_are_unchanged(self):
        self.assertEqual(broker_module.TTL_SECONDS, 120)
        self.assertEqual(broker_module.MAX_CONNECTIONS, 4)
        self.assertEqual(broker_module._INVENTORY_METHODS, ('pending', 'begin', 'ack', 'starting', 'activate', 'closing', 'finish'))
        opened = await self.opened()
        self.assertEqual(self.log, ORDER_OF_OPEN)
        self.assertTrue((await self.call({'op': 'close', 'handle': opened['handle']}))['ok'])
        self.assertEqual(self.log[-3:], ORDER_OF_CLOSE)


# ------------------------------------------------------------------------------------------------------- M2.1 · levels
# Doubles of the M2.0 adapters (SC2-M2-ADAPTADORES-LOCAL): begin_level / receipt_level on the inventory, probe_level on the runtime.
# They extend the M1 doubles above without changing them. Authored without a shell: not executed by the author.

CONTEXT = '7' * 64
OTHER_CONTEXT = '8' * 64
RUN_C = '%032x' % 3
ORDER_OF_OPEN_LEVEL = ['inv:begin_level'] + ORDER_OF_OPEN[1:]
LEVEL_ARGS = dict(run_id=RUN_A, level='memory', stage='actor', context_sha256=CONTEXT, installation_id=INSTALL, image_id=IMAGE)
OPEN_LEVEL_BODY = {'op': 'open_level', 'run_id': RUN_A, 'level': 'memory', 'stage': 'actor', 'context_sha256': CONTEXT}
IDENT_LEVEL = {'installation_id': INSTALL, 'run_id': RUN_A, 'level': 'memory', 'stage': 'actor', 'context_sha256': CONTEXT,
               'intent_id': '5' * 32, 'container_id': CONTAINER}


@dataclasses.dataclass(frozen=True)
class LevelIntent:  # same fields as actor_state.LevelIntent: there is no variant
    intent_id: str
    name: str
    controller_uid: int
    run_id: str
    level: str
    stage: str
    context_sha256: str
    container_id: object
    phase: str
    profile_sha256: str


class LevelInventory(FakeInventory):
    def __init__(self, log):
        super().__init__(log)
        self.contexts = {}              # one context per (domain, uid, run), as the real diary keeps it
        self.level_queries = []         # receipt_level() calls: a read, it never touches `log`, `count`, `current` or `history`
        self.level_receipt_error = None
        self.level_receipt_returns = None

    def receipt(self, **kwargs):
        # The M1 query over a mixed diary: level entries have no variant and are never an M1 answer.
        history, self.history = self.history, [item for item in self.history if not isinstance(item, LevelIntent)]
        try:
            return super().receipt(**kwargs)
        finally:
            self.history = history

    def begin_level(self, *, controller_uid, run_id, level, stage, context_sha256):
        self._gate('begin_level')
        if self.current is not None:
            raise StateError('actor_busy')
        key = ('level', controller_uid, run_id, level, stage)
        if key in self.used:
            raise StateError('already_started')  # also after FINISH: the key is permanent
        if any(other[:3] == key[:3] and context != context_sha256 for other, context in self.contexts.items()):
            raise StateError('invalid_transition')
        self.used.add(key)
        self.contexts[key] = context_sha256
        self.count += 1
        intent_id = '%032x' % (0xa0 + self.count)
        self.current = LevelIntent(intent_id, 'escape-actor-' + intent_id, controller_uid, run_id, level, stage, context_sha256,
                                   None, 'CREATE_PENDING', DIGEST)
        return self.current

    def receipt_level(self, *, controller_uid, run_id, level, stage, context_sha256, intent_id, container_id):
        asked = (controller_uid, run_id, level, stage, context_sha256, intent_id, container_id)
        self.level_queries.append(asked)
        if self.level_receipt_error is not None:
            raise StateError(self.level_receipt_error)
        if self.level_receipt_returns is not None:
            return self.level_receipt_returns
        if controller_uid != CLIENT_UID:
            raise StateError('identity_changed')
        for item in self.history:
            if isinstance(item, LevelIntent) and (item.controller_uid, item.run_id, item.level, item.stage, item.context_sha256,
                                                  item.intent_id, item.container_id) == asked:
                return item
        return None


class LevelRuntime(FakeRuntime):
    def __init__(self, log, inventory):
        super().__init__(log, inventory)
        self.level_calls = []
        self.level_result = {'status': 'available', 'counters': {'low': 0, 'high': 0, 'max': 0, 'oom': 0, 'oom_kill': 0}}
        self.level_error = None
        self.level_gate = None
        self.level_started = None
        self.close_oom = None

    async def probe_level(self, intent, name, **typed_args):
        self.calls['probe_level'] += 1
        self.level_calls.append((intent, name, dict(typed_args)))
        self.log.append('rt:probe_level:' + name)
        if self.level_started is not None:
            self.level_started.set()
        if self.level_gate is not None:
            await self.level_gate.wait()
        if self.level_error is not None:
            raise self.level_error
        return self.level_result

    async def close(self, intent):
        result = await super().close(intent)
        if self.close_oom is not None:
            result['oom_killed'] = self.close_oom
        return result


class LevelCase(BrokerCase):
    async def asyncSetUp(self):
        self.log = []
        self.inventory = LevelInventory(self.log)
        self.runtime = LevelRuntime(self.log, self.inventory)
        self.clock = Clock()
        self.make()

    def make(self, **overrides):
        overrides.setdefault('allowed_levels', ('memory',))  # what Sol's bootstrap will enable in this lot
        return super().make(**overrides)

    def fresh(self, **overrides):
        self.log.clear()
        self.inventory = LevelInventory(self.log)
        self.runtime = LevelRuntime(self.log, self.inventory)
        self.make(**overrides)

    async def open_level(self, run=RUN_A, level='memory', stage='actor', context=CONTEXT):
        return await self.call({'op': 'open_level', 'run_id': run, 'level': level, 'stage': stage, 'context_sha256': context})

    async def opened_level(self, run=RUN_A, level='memory', context=CONTEXT):
        await self.start()
        response = await self.open_level(run, level, 'actor', context)
        self.assertTrue(response['ok'], response)
        return response

    async def level_probe(self, handle, name='cgroup_events'):
        return await self.call({'op': 'level_probe', 'handle': handle, 'name': name})

    async def close_handle(self, handle):
        return await self.call({'op': 'close', 'handle': handle})

    def level_identity(self, response):
        return {key: response[key] for key in wire.LEVEL_IDENTITY_FIELDS}


class LevelPolicyTests(LevelCase):
    async def test_the_allowlist_is_empty_by_default_and_m1_doubles_need_no_level_methods(self):
        inventory = FakeInventory(self.log)  # an M1 inventory and runtime: no begin_level, receipt_level or probe_level
        runtime = FakeRuntime(self.log, inventory)
        for options in ({}, {'allowed_levels': ()}, {'allowed_levels': frozenset()}):
            broker = ActorBroker(runtime=runtime, inventory=inventory, client_uid=CLIENT_UID, image_id=IMAGE, clock=self.clock,
                                 limits=fast_limits(), **options)
            self.assertEqual(broker.allowed_levels, frozenset())
            response = await broker.handle(CLIENT_UID, enc(OPEN_LEVEL_BODY))
            self.assertEqual(json.loads(response), {'ok': False, 'reason': 'level_not_allowed'})
        self.assertEqual(self.log, [])
        self.assertEqual(broker_module._INVENTORY_METHODS, ('pending', 'begin', 'ack', 'starting', 'activate', 'closing', 'finish'))

    async def test_enabled_levels_require_the_level_interfaces_but_not_receipt_level(self):
        m1_inventory = FakeInventory(self.log)
        with self.assertRaises(ValueError):  # the inventory has no begin_level
            self.make(inventory=m1_inventory, runtime=FakeRuntime(self.log, m1_inventory), allowed_levels=('memory',))
        with self.assertRaises(ValueError):  # the runtime has no probe_level
            self.make(runtime=FakeRuntime(self.log, self.inventory), allowed_levels=('memory',))

        class NoLevelReceipt(LevelInventory):
            receipt_level = None
        inventory = NoLevelReceipt(self.log)
        self.make(inventory=inventory, runtime=LevelRuntime(self.log, inventory))  # constructs: it can never confirm, only refuse
        self.assertEqual(self.broker.allowed_levels, frozenset({'memory'}))

    async def test_allowlist_values_are_validated_and_copied(self):
        for bad in ('memory', b'memory', None, 5, {'memory': 1}, ['Persistence'], ['Memory'], [1], [None], [['memory']],  # M2.3: persistence is valid
                    ('memory', 'fresh'), iter(['memory'])):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(allowed_levels=bad)
        levels = ['memory']
        self.make(allowed_levels=levels)
        levels.append('secret')  # the owner's own list changing later does not change the broker
        self.assertEqual(self.broker.allowed_levels, frozenset({'memory'}))
        self.assertIsInstance(self.broker.allowed_levels, frozenset)
        with self.assertRaises(AttributeError):
            self.broker.allowed_levels = frozenset({'secret'})
        await self.start()
        self.assertEqual((await self.open_level(level='secret'))['reason'], 'level_not_allowed')

    async def test_a_level_outside_the_allowlist_is_refused_before_anything_exists(self):
        await self.start()
        response = await self.open_level(level='secret')  # the codec recognizes secret/actor; the owner does not serve it
        self.assertEqual(response, {'ok': False, 'reason': 'level_not_allowed'})
        self.assertEqual(self.log, [])
        self.assertEqual((self.broker.leases.held(), self.inventory.used, self.runtime.calls['create']), (0, set(), 0))
        self.assertEqual(self.broker.status(), {'installation_id': INSTALL, 'blocked': None, 'obligations': 0, 'recovered': True})
        self.assertTrue((await self.open_level(level='memory'))['ok'])  # and it did not disturb the allowed one

    async def test_policy_is_decided_before_the_state_of_the_owner(self):
        self.make()  # not reconciled
        self.assertEqual((await self.open_level(level='secret'))['reason'], 'level_not_allowed')
        self.assertEqual((await self.open_level(level='memory'))['reason'], 'owner_not_ready')
        self.assertEqual(self.log, [])

    async def test_a_request_can_neither_carry_nor_change_the_allowlist(self):
        await self.start()
        for field, value in (('allowed_levels', ['secret']), ('allowed', ['secret']), ('levels', ['secret']), ('policy', 'all')):
            response = await self.call({**OPEN_LEVEL_BODY, 'level': 'secret', field: value})
            self.assertEqual(response, {'ok': False, 'reason': 'unexpected_field'}, field)
        self.assertEqual(self.broker.allowed_levels, frozenset({'memory'}))
        self.assertEqual((await self.open_level(level='secret'))['reason'], 'level_not_allowed')
        self.assertEqual(self.log, [])

    async def test_codec_rejections_never_reach_the_owner(self):
        await self.start()
        for patch, reason in (({'level': 'bogus'}, 'invalid_level'), ({'stage': 'fresh'}, 'invalid_stage'),  # M5: `network` is a name now
                              ({'context_sha256': 'x'}, 'invalid_context'), ({'run_id': 'x'}, 'invalid_run_id'),
                              ({'variant': 'legitimate'}, 'unexpected_field'), ({'image': 'x'}, 'forbidden_field'),
                              ({'command': 'id'}, 'unexpected_field'), ({'path': '/work'}, 'forbidden_field')):
            self.assertEqual(await self.call({**OPEN_LEVEL_BODY, **patch}), {'ok': False, 'reason': reason}, patch)
        self.assertEqual(await self.call({'op': 'open_level'}), {'ok': False, 'reason': 'missing_field'})
        self.assertEqual(self.log, [])

    async def test_secret_is_served_only_when_the_owner_configures_it_and_has_no_memory_probe(self):
        self.make(allowed_levels=('memory', 'secret'))
        opened = await self.opened_level(level='secret')
        wire.validate_level_open(opened, **{**LEVEL_ARGS, 'level': 'secret'})
        self.assertEqual(opened['level'], 'secret')
        self.assertTrue((await self.call({'op': 'execute', 'handle': opened['handle'], 'command': 'true'}))['ok'])
        self.assertEqual(await self.level_probe(opened['handle']), {'ok': False, 'reason': 'wrong_domain'})
        self.assertEqual(self.runtime.calls['probe_level'], 0)

    async def test_a_shrunk_policy_refuses_new_levels_but_still_answers_old_receipts(self):
        opened = await self.opened_level()
        identity = self.level_identity(opened)
        wire.validate_level_close(await self.close_handle(opened['handle']), receipt=identity)
        self.make(allowed_levels=())  # a later configuration serves no level
        await self.start()
        self.assertEqual((await self.open_level(RUN_B))['reason'], 'level_not_allowed')
        answer = await self.call({'op': 'level_receipt', **identity})
        self.assertEqual(wire.validate_level_receipt(answer, identity=identity)['status'], 'confirmed')


class LevelOpenTests(LevelCase):
    async def test_diary_and_runtime_follow_the_contract_order_and_the_identity_is_a_level_one(self):
        response = await self.opened_level()
        self.assertEqual(self.log, ORDER_OF_OPEN_LEVEL)
        wire.validate_level_open(response, **LEVEL_ARGS)
        self.assertNotIn('variant', response)
        self.assertEqual(response['op'], 'open_level')
        self.assertEqual((response['container_id'], response['profile_sha256']), (CONTAINER, DIGEST))
        self.assertEqual(response['name'], 'escape-actor-' + response['intent_id'])
        current = self.inventory.current
        self.assertIsInstance(current, LevelIntent)
        self.assertEqual((current.phase, current.level, current.stage, current.context_sha256), ('ACTIVE', 'memory', 'actor', CONTEXT))

    async def test_nothing_is_created_when_pending_cannot_be_made_durable(self):
        await self.start()
        self.inventory.fail['begin_level'] = 'state_unavailable'
        response = await self.open_level()
        self.assertEqual((response['ok'], response['reason']), (False, 'owner_blocked'))
        self.assertEqual(self.log, ['inv:begin_level'])
        self.assertEqual((self.runtime.calls['create'], self.broker.leases.held()), (0, 0))
        self.assertEqual(self.broker.status()['blocked'], 'state_unavailable')

    async def test_a_diary_that_answers_another_obligation_blocks_before_create(self):
        class WrongContext(LevelInventory):
            def begin_level(self, **kwargs):
                intent = super().begin_level(**kwargs)
                self.current = dataclasses.replace(intent, context_sha256=OTHER_CONTEXT)
                return self.current

        class Nothing(LevelInventory):
            def begin_level(self, **kwargs):
                super().begin_level(**kwargs)
                return None
        for inventory_class, expected in ((WrongContext, {'ok': False, 'reason': 'owner_blocked', 'cleanup_confirmed': False}),
                                          (Nothing, {'ok': False, 'reason': 'owner_blocked'})):
            with self.subTest(diary=inventory_class.__name__):
                self.log.clear()
                self.inventory = inventory_class(self.log)
                self.runtime = LevelRuntime(self.log, self.inventory)
                self.make()
                await self.start()
                self.assertEqual(await self.open_level(), expected)
                self.assertEqual((self.runtime.calls['create'], self.runtime.calls['close']), (0, 0))
                self.assertEqual(self.broker.status()['blocked'], 'state_unavailable')

    async def test_ack_is_durable_before_inspection_and_start(self):
        await self.start()
        self.inventory.fail['ack'] = 'state_unavailable'
        response = await self.open_level()
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('owner_blocked', False))
        self.assertNotIn('rt:inspect_created@CREATE_ACK', self.log)
        self.assertEqual((self.runtime.calls['start'], self.runtime.calls['close']), (0, 0))  # the ID was never recognized
        self.assertIn(CONTAINER, self.runtime.containers)
        health = await self.call({'op': 'health'})
        self.assertEqual((health['blocked'], health['obligations']), (True, 1))

    async def test_start_pending_and_active_are_durable_before_their_effect(self):
        await self.start()
        self.inventory.fail['starting'] = 'state_unavailable'
        response = await self.open_level()
        self.assertEqual(self.runtime.calls['start'], 0)
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('owner_blocked', True))
        self.assertEqual(self.runtime.removed, [CONTAINER])
        self.fresh()
        await self.start()
        self.inventory.fail['activate'] = 'state_unavailable'
        response = await self.open_level()
        self.assertNotIn('handle', response)
        self.assertFalse(response['ok'])
        self.assertEqual(self.runtime.removed, [CONTAINER])

    async def test_ambiguous_create_blocks_and_is_never_repeated(self):
        await self.start()
        self.runtime.create_error = RuntimeError('boom')
        response = await self.open_level()
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('create_failed', False))
        self.assertEqual(self.runtime.calls['create'], 1)
        self.assertIsInstance(self.inventory.current, LevelIntent)
        self.assertIsNone(self.inventory.current.container_id)  # PENDING without an ID
        self.assertEqual((await self.open_level(RUN_B))['reason'], 'owner_blocked')
        self.assertEqual((self.runtime.calls['create'], self.runtime.calls['close']), (1, 0))
        self.assertIn(CONTAINER, self.runtime.containers)  # nothing is removed on a guess
        health = await self.call({'op': 'health'})
        self.assertEqual((health['blocked'], health['obligations']), (True, 1))
        self.assertEqual(self.broker.leases.held(), 1)

    async def test_create_timeout_and_a_malformed_id_block_too(self):
        await self.start()
        self.runtime.create_hang = True
        response = await self.open_level()
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('create_failed', False))
        self.assertEqual((await self.open_level(RUN_B))['reason'], 'owner_blocked')
        self.assertEqual(self.runtime.calls['create'], 1)
        self.fresh()
        await self.start()
        self.runtime.create_id = 'not-an-id'
        self.assertEqual((await self.open_level())['reason'], 'create_failed')
        self.assertEqual((self.runtime.calls['close'], (await self.call({'op': 'health'}))['blocked']), (0, True))

    async def test_incompatible_or_changed_profile_is_restituted_and_no_handle_exists(self):
        await self.start()
        self.runtime.created_report = {'compatible': False, 'violations': ['read_only']}
        response = await self.open_level()
        self.assertEqual((response['reason'], response['violations'], response['cleanup_confirmed']),
                         ('profile_rejected', ['read_only'], True))
        self.assertEqual(self.runtime.calls['start'], 0)
        self.assertEqual(self.log[-3:], ORDER_OF_CLOSE)
        self.assertEqual((self.inventory.current, self.broker.leases.held()), (None, 0))
        self.fresh()
        await self.start()
        self.runtime.running_override = {'running': True, 'container_id': 'e' * 64, 'profile': PROFILE,
                                         'profile_sha256': DIGEST, 'violations': []}
        response = await self.open_level()
        self.assertEqual((response['ok'], response['reason'], response['cleanup_confirmed']), (False, 'profile_rejected', True))
        self.assertNotIn('handle', response)
        self.assertEqual(self.runtime.removed, [CONTAINER])

    async def test_start_failure_is_restituted_and_start_is_not_repeated(self):
        await self.start()
        self.runtime.start_error = RuntimeError('boom')
        response = await self.open_level()
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('start_failed', True))
        self.assertEqual((self.runtime.calls['start'], self.runtime.removed), (1, [CONTAINER]))

    async def test_runtime_not_ready_blocked_and_shutdown_change_nothing(self):
        await self.start()
        self.runtime.ready_value = False
        self.assertEqual((await self.open_level())['reason'], 'owner_not_ready')
        self.runtime.ready_value = True
        self.broker._shutdown = True
        self.assertEqual((await self.open_level())['reason'], 'shutting_down')
        self.assertEqual((self.log, self.broker.leases.held()), ([], 0))
        self.fresh()
        self.runtime.containers.add(FOREIGN)
        await self.start()  # an object of the installation with no intent blocks the owner
        self.assertEqual((await self.open_level())['reason'], 'owner_blocked')
        self.assertEqual((self.log, self.runtime.calls['close']), ([], 0))
        self.assertIn(FOREIGN, self.runtime.containers)


class LevelReplayAndPlazaTests(LevelCase):
    async def test_replay_of_a_closed_run_level_and_stage_is_refused_before_docker_whatever_the_context(self):
        first = await self.opened_level()
        await self.close_handle(first['handle'])
        self.log.clear()
        for context in (CONTEXT, OTHER_CONTEXT):
            self.assertEqual(await self.open_level(context=context), {'ok': False, 'reason': 'already_active'})
        self.assertEqual(self.log, ['inv:begin_level'] * 2)
        self.assertEqual((self.runtime.calls['create'], self.broker.leases.held()), (1, 0))
        self.assertIsNone(self.broker.status()['blocked'])

    async def test_another_context_for_another_level_of_the_same_run_is_refused_without_blocking(self):
        self.make(allowed_levels=('memory', 'secret'))
        first = await self.opened_level(RUN_A, 'memory', CONTEXT)
        await self.close_handle(first['handle'])
        self.log.clear()
        self.assertEqual(await self.open_level(RUN_A, 'secret', context=OTHER_CONTEXT),
                         {'ok': False, 'reason': 'context_mismatch'})
        self.assertEqual(self.log, ['inv:begin_level'])
        self.assertEqual((self.broker.status()['blocked'], self.broker.leases.held(), self.runtime.calls['create']), (None, 0, 1))
        again = await self.open_level(RUN_A, 'secret', context=CONTEXT)  # the same context is the same corrida
        self.assertTrue(again['ok'], again)

    async def test_one_plaza_is_shared_by_workflow_and_level_and_neither_touches_the_other(self):
        first = await self.opened_level(RUN_A)
        self.log.clear()
        self.assertEqual((await self.open(RUN_B))['reason'], 'capacity_exhausted')
        self.assertEqual((await self.open_level(RUN_B))['reason'], 'capacity_exhausted')
        self.assertEqual((await self.open_level(RUN_A))['reason'], 'already_active')
        self.assertEqual(self.log, [])
        self.assertEqual(self.runtime.calls['create'], 1)
        self.assertTrue((await self.call({'op': 'execute', 'handle': first['handle'], 'command': 'true'}))['ok'])
        wire.validate_level_close(await self.close_handle(first['handle']), receipt=self.level_identity(first))
        workflow = await self.open(RUN_B)
        self.assertTrue(workflow['ok'], workflow)
        self.assertEqual((await self.open_level(RUN_C))['reason'], 'capacity_exhausted')
        wire.validate_close(await self.close_handle(workflow['handle']), receipt=self.identity(workflow))

    async def test_the_same_run_id_in_both_domains_is_independent(self):
        first = await self.opened_level(RUN_A)
        await self.close_handle(first['handle'])
        workflow = await self.open(RUN_A, 'legitimate')
        self.assertTrue(workflow['ok'], workflow)
        self.assertEqual(workflow['variant'], 'legitimate')
        self.assertNotIn('level', workflow)

    async def test_the_m1_flow_is_exact_on_an_owner_that_serves_levels(self):
        opened = await self.opened()
        self.assertEqual(self.log, ORDER_OF_OPEN)
        wire.validate_open(opened, run_id=RUN_A, variant='legitimate', installation_id=INSTALL, image_id=IMAGE)
        for name in ('task_result', 'artifact_capture', 'measure'):
            answer = await self.call({'op': 'probe', 'handle': opened['handle'], 'name': name})
            self.assertTrue(answer['ok'], answer)
        closed = await self.close_handle(opened['handle'])
        self.assertEqual(wire.validate_close(closed, receipt=self.identity(opened))['oom_killed'], False)
        self.assertNotIn('level', closed)
        self.assertEqual(self.log[-3:], ORDER_OF_CLOSE)


class LevelOperationTests(LevelCase):
    async def test_a_level_handle_runs_execute_measure_and_the_fixed_probe(self):
        opened = await self.opened_level()
        handle = opened['handle']
        executed = await self.call({'op': 'execute', 'handle': handle, 'command': 'cat -- /work/input.json'})
        self.assertEqual(wire.validate_result(executed, op='execute')['stdout'], 'ok')
        self.assertEqual(wire.validate_measure(await self.call({'op': 'probe', 'handle': handle, 'name': 'measure'})), MEAS)
        answer = await self.level_probe(handle)
        self.assertEqual(wire.validate_level_probe(answer),
                         {'status': 'available', 'counters': {'low': 0, 'high': 0, 'max': 0, 'oom': 0, 'oom_kill': 0}})
        (intent, name, typed), = self.runtime.level_calls  # exactly one call, and nothing but the intent and the owner's name
        self.assertEqual((name, typed), ('cgroup_events', {}))
        self.assertEqual((intent.phase, intent.level, intent.stage, intent.context_sha256), ('ACTIVE', 'memory', 'actor', CONTEXT))

    async def test_an_unavailable_probe_is_passed_on_as_unavailable_and_never_as_zero(self):
        opened = await self.opened_level()
        self.runtime.level_result = {'status': 'unavailable', 'counters': None}
        answer = await self.level_probe(opened['handle'])
        self.assertEqual(wire.validate_level_probe(answer), {'status': 'unavailable', 'counters': None})
        self.assertEqual(self.inventory.current.phase, 'ACTIVE')  # a legitimate answer: the lease and the container stay
        self.assertTrue((await self.call({'op': 'execute', 'handle': opened['handle'], 'command': 'true'}))['ok'])

    async def test_a_level_handle_refuses_the_workflow_probes_without_calling_the_runtime(self):
        opened = await self.opened_level()
        for name in ('task_result', 'artifact_capture'):
            answer = await self.call({'op': 'probe', 'handle': opened['handle'], 'name': name})
            self.assertEqual(answer, {'ok': False, 'reason': 'wrong_domain'})
        self.assertEqual((self.runtime.calls['probe'], self.runtime.calls['probe_level']), (0, 0))
        self.assertEqual((self.inventory.current.phase, self.broker.leases.held()), ('ACTIVE', 1))  # the lease is intact
        self.assertTrue((await self.call({'op': 'execute', 'handle': opened['handle'], 'command': 'true'}))['ok'])

    async def test_an_m1_handle_cannot_be_used_as_a_level_handle(self):
        opened = await self.opened()
        self.assertEqual(await self.level_probe(opened['handle']), {'ok': False, 'reason': 'wrong_domain'})
        self.assertEqual(self.runtime.calls['probe_level'], 0)
        self.assertEqual((self.inventory.current.phase, self.broker.leases.held()), ('ACTIVE', 1))
        self.assertTrue((await self.call({'op': 'execute', 'handle': opened['handle'], 'command': 'true'}))['ok'])

    async def test_invalid_probe_output_is_never_forwarded_and_ends_the_lease(self):
        many = {'oom_kill': 0, **{(chr(97 + i // 26) + chr(97 + i % 26)): i for i in range(32)}}
        bad_results = (
            {'status': 'available', 'counters': {'oom_kill': True}}, {'status': 'available', 'counters': {'oom_kill': -1}},
            {'status': 'available', 'counters': {'oom_kill': 1.0}}, {'status': 'available', 'counters': {'oom_kill': '1'}},
            {'status': 'available', 'counters': {'oom_kill': 2 ** 64}}, {'status': 'available', 'counters': {'oom': 0}},
            {'status': 'available', 'counters': {'oom_kill': 0, 'max': True}},
            {'status': 'available', 'counters': {'oom_kill': 0, 'OOM': 1}}, {'status': 'available', 'counters': {}},
            {'status': 'available', 'counters': None}, {'status': 'available', 'counters': [('oom_kill', 0)]},
            {'status': 'available', 'counters': many},
            {'status': 'unavailable', 'counters': {}}, {'status': 'unavailable', 'counters': {'oom_kill': 0}},
            {'status': 'maybe', 'counters': None}, {'status': True, 'counters': None},
            {'status': 'available', 'counters': {'oom_kill': 0}, 'path': '/sys/fs/cgroup/memory.events'},
            {'status': 'available'}, {'counters': {'oom_kill': 0}}, {}, None, 'text', ['available'], 5)
        for result in bad_results:
            with self.subTest(result=str(result)[:60]):
                self.fresh()
                opened = await self.opened_level()
                self.runtime.level_result = result
                answer = await self.level_probe(opened['handle'])
                self.assertEqual(answer, {'ok': False, 'reason': 'internal_error'})
                await self.broker.drain()
                self.assertEqual(self.runtime.removed, [CONTAINER])
                self.assertEqual(self.runtime.calls['probe_level'], 1)

    async def test_runtime_failures_and_timeouts_of_the_probe_end_the_lease_without_replay(self):
        class Stopped(Exception):
            reason = 'sandbox_stopped'
        for error, reason in ((Stopped(), 'sandbox_stopped'), (RuntimeError('boom'), 'internal_error')):
            with self.subTest(reason=reason):
                self.fresh()
                opened = await self.opened_level()
                self.runtime.level_error = error
                self.assertEqual(await self.level_probe(opened['handle']), {'ok': False, 'reason': reason})
                await self.broker.drain()
                self.assertEqual((self.runtime.removed, self.runtime.calls['probe_level']), ([CONTAINER], 1))
        self.fresh()
        opened = await self.opened_level()
        self.runtime.level_gate = asyncio.Event()  # never set: the probe hangs
        self.runtime.close_gate = asyncio.Event()
        self.assertEqual(await self.level_probe(opened['handle']), {'ok': False, 'reason': 'exec_timeout'})
        self.assertEqual((await self.level_probe(opened['handle']))['reason'], 'closing')
        self.runtime.close_gate.set()
        await self.broker.drain()
        self.assertEqual((self.runtime.calls['probe_level'], self.runtime.removed), (1, [CONTAINER]))
        receipt = await self.close_handle(opened['handle'])  # the recorded receipt, not a second close
        wire.validate_level_close(receipt, receipt=self.level_identity(opened))
        self.assertEqual(self.runtime.calls['close'], 1)

    async def test_one_operation_per_handle_and_close_waits_for_it(self):
        self.make(limits=fast_limits(execute=2.0))
        opened = await self.opened_level()
        handle = opened['handle']
        self.runtime.execute_gate = asyncio.Event()
        self.runtime.execute_started = asyncio.Event()
        running = asyncio.ensure_future(self.call({'op': 'execute', 'handle': handle, 'command': 'sleep 1'}))
        await self.runtime.execute_started.wait()
        self.assertEqual((await self.level_probe(handle))['reason'], 'busy')
        closing = asyncio.ensure_future(self.close_handle(handle))
        await asyncio.sleep(0.05)
        self.assertEqual(self.runtime.calls['close'], 0)  # the restitution waits for the operation
        self.assertEqual((await self.level_probe(handle))['reason'], 'closing')
        self.runtime.execute_gate.set()
        self.assertTrue((await running)['ok'])
        wire.validate_level_close(await closing, receipt=self.level_identity(opened))
        self.assertEqual((self.runtime.calls['execute'], self.runtime.calls['probe_level']), (1, 0))

    async def test_after_close_or_with_an_unknown_handle_nothing_runs(self):
        opened = await self.opened_level()
        await self.close_handle(opened['handle'])
        self.assertEqual(await self.level_probe(opened['handle']), {'ok': False, 'reason': 'unknown_handle'})
        self.assertEqual(await self.level_probe('ab' * 32), {'ok': False, 'reason': 'unknown_handle'})
        self.assertEqual(self.runtime.calls['probe_level'], 0)

    async def test_the_probe_request_carries_no_script_path_or_other_probe_name(self):
        opened = await self.opened_level()
        handle = opened['handle']
        marker = '/work/marker-' + 'a' * 24
        cases = (({'path': marker}, 'forbidden_field'), ({'path': '/sys/fs/cgroup/memory.events'}, 'forbidden_field'),
                 ({'script': 'cat /etc/shadow'}, None), ({'argv': ['cat']}, None), ({'command': 'id'}, 'unexpected_field'),
                 # M2.3: the persistence probes now decode; a MEMORY handle is not their domain, and a request without its argument is missing one
                 ({'name': 'file_state', 'path': marker}, 'wrong_domain'), ({'name': 'file_state'}, 'missing_field'),
                 ({'name': 'copy_scan', 'sha256': 'a' * 64, 'size': 5, 'exclude': None}, 'wrong_domain'),
                 ({'name': 'net_counters'}, 'invalid_name'), ({'name': 'measure'}, 'invalid_name'),
                 ({'name': 'task_result'}, 'invalid_name'), ({'name': 'Cgroup_events'}, 'invalid_name'),
                 ({'image': 'x'}, 'forbidden_field'), ({'handle': 'zz'}, 'invalid_handle'))
        for patch, reason in cases:
            answer = await self.call({'op': 'level_probe', 'handle': handle, 'name': 'cgroup_events', **patch})
            self.assertFalse(answer['ok'], patch)
            self.assertEqual(answer['reason'], reason, patch) if reason is not None else self.assertIn(
                answer['reason'], {'unexpected_field', 'forbidden_field'})
        self.assertEqual((self.runtime.calls['probe_level'], self.runtime.level_calls), (0, []))
        self.assertEqual(self.inventory.current.phase, 'ACTIVE')

    async def test_another_uid_gets_no_answer_to_any_level_operation(self):
        opened = await self.opened_level()
        identity = self.level_identity(opened)
        before = (list(self.log), self.broker.leases.held(), self.runtime.calls['probe_level'])
        for body in (OPEN_LEVEL_BODY, {'op': 'level_probe', 'handle': opened['handle'], 'name': 'cgroup_events'},
                     {'op': 'level_receipt', **identity}, {'op': 'close', 'handle': opened['handle']},
                     {'op': 'execute', 'handle': opened['handle'], 'command': 'true'}):
            self.assertIsNone(await self.call(body, uid=CLIENT_UID + 1))
        self.assertEqual((list(self.log), self.broker.leases.held(), self.runtime.calls['probe_level']), before)
        self.assertEqual(self.inventory.level_queries, [])
        self.assertTrue((await self.level_probe(opened['handle']))['ok'])  # the real owner of the handle is undisturbed


class LevelCloseTests(LevelCase):
    async def test_close_answers_with_the_level_identity_is_idempotent_and_removes_once(self):
        opened = await self.opened_level()
        identity = self.level_identity(opened)
        self.log.clear()
        first = await self.close_handle(opened['handle'])
        second = await self.close_handle(opened['handle'])
        self.assertEqual(first, second)
        self.assertEqual(self.runtime.calls['close'], 1)
        self.assertEqual(self.log, ORDER_OF_CLOSE)
        self.assertEqual(wire.validate_level_close(first, receipt=identity)['oom_killed'], False)
        self.assertNotIn('variant', first)
        m1_identity = {'installation_id': INSTALL, 'run_id': RUN_A, 'variant': 'legitimate', 'intent_id': identity['intent_id'],
                       'container_id': CONTAINER}
        with self.assertRaises(wire.WireError):  # the original handle's identity is a level one; M1 validation refuses it
            wire.validate_close(first, receipt=m1_identity)
        self.assertEqual((self.broker.status()['obligations'], self.inventory.finished.container_id), (0, CONTAINER))

    async def test_the_oom_flag_of_the_runtime_reaches_the_receipt(self):
        opened = await self.opened_level()
        self.runtime.close_oom = True
        closed = await self.close_handle(opened['handle'])
        self.assertTrue(wire.validate_level_close(closed, receipt=self.level_identity(opened))['oom_killed'])

    async def test_unconfirmed_close_keeps_the_obligation_until_restitution(self):
        opened = await self.opened_level()
        self.runtime.close_confirms = False
        response = await self.close_handle(opened['handle'])
        self.assertEqual((response['ok'], response['reason'], response['cleanup_confirmed']), (False, 'cleanup_unconfirmed', False))
        self.assertEqual(self.inventory.current.phase, 'CLOSE_PENDING')
        self.assertEqual(self.broker.leases.held(), 1)
        self.assertEqual((await self.call({'op': 'health'}))['obligations'], 1)
        self.assertEqual((await self.open_level(RUN_B))['reason'], 'capacity_exhausted')
        self.runtime.close_confirms = True
        await self.broker.reconcile()  # same ID, same procedure
        self.assertEqual((self.broker.status()['obligations'], self.runtime.removed), (0, [CONTAINER]))
        late = await self.close_handle(opened['handle'])
        wire.validate_level_close(late, receipt=self.level_identity(opened))
        self.assertEqual(self.runtime.calls['close'], 2)

    async def test_a_runtime_that_confirms_but_still_lists_the_id_and_a_failing_finish_are_not_confirmations(self):
        opened = await self.opened_level()
        self.runtime.keep_after_close = True
        response = await self.close_handle(opened['handle'])
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('cleanup_unconfirmed', False))
        self.assertIsNone(self.inventory.finished)
        self.fresh()
        opened = await self.opened_level()
        self.inventory.fail['finish'] = 'state_unavailable'
        response = await self.close_handle(opened['handle'])
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('cleanup_unconfirmed', False))
        self.assertEqual((await self.call({'op': 'health'}))['blocked'], True)

    async def test_cancelled_close_request_does_not_cancel_the_restitution(self):
        self.make(limits=fast_limits(close=2.0))
        opened = await self.opened_level()
        self.runtime.close_gate = asyncio.Event()
        task = asyncio.ensure_future(self.close_handle(opened['handle']))
        await self.wait_for_call('close')
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.runtime.close_gate.set()
        await self.broker.drain()
        self.assertEqual((self.inventory.current, self.runtime.removed), (None, [CONTAINER]))
        again = await self.close_handle(opened['handle'])
        wire.validate_level_close(again, receipt=self.level_identity(opened))
        self.assertEqual(self.runtime.calls['close'], 1)


class LevelReceiptTests(LevelCase):
    """The durable `level_receipt` query: sync, read-only, answered from the diary alone."""

    def body(self, identity, **patch):
        return {'op': 'level_receipt', **identity, **patch}

    def snapshot(self):
        return (list(self.log), dict(self.runtime.calls), self.inventory.count, self.inventory.current,
                len(self.inventory.history), tuple(sorted(self.runtime.containers)), list(self.runtime.removed),
                self.broker.status(), self.broker.leases.held())

    async def exchange(self, body, uid=CLIENT_UID):
        """One request; asserts that the diary, the runtime, the leases and the owner state did not move."""
        before = self.snapshot()
        response = await self.call(body, uid=uid)
        self.assertEqual(self.snapshot(), before)
        return response

    async def query(self, identity, **patch):
        requested = {**identity, **patch}
        response = await self.exchange(self.body(requested))
        self.assertTrue(response['ok'], response)
        wire.validate_level_receipt(response, identity=requested)  # exact shape, and only the identity that was asked about
        return response

    async def closed_level(self, run=RUN_A, level='memory', context=CONTEXT):
        if self.broker.status()['recovered']:
            opened = await self.open_level(run, level, 'actor', context)
            self.assertTrue(opened['ok'], opened)
        else:
            opened = await self.opened_level(run, level, context)
        identity = self.level_identity(opened)
        wire.validate_level_close(await self.close_handle(opened['handle']), receipt=identity)
        return identity

    def assertStatus(self, answer, status):
        self.assertEqual((answer['status'], answer['cleanup_confirmed']), (status, status == 'confirmed'))

    async def test_unknown_before_finish_and_confirmed_after_it(self):
        opened = await self.opened_level()
        identity = self.level_identity(opened)
        self.assertStatus(await self.query(identity), 'unknown')  # ACTIVE: the obligation is still open
        self.assertEqual(self.inventory.current.phase, 'ACTIVE')
        wire.validate_level_close(await self.close_handle(opened['handle']), receipt=identity)
        confirmed = await self.query(identity)
        self.assertStatus(confirmed, 'confirmed')
        self.assertEqual(await self.query(identity), confirmed)  # a read: repeating it gives the same answer

    async def test_close_pending_is_unknown_until_the_owner_reconciles(self):
        opened = await self.opened_level()
        identity = self.level_identity(opened)
        self.runtime.close_confirms = False
        self.assertEqual((await self.close_handle(opened['handle']))['reason'], 'cleanup_unconfirmed')
        closes = self.runtime.calls['close']
        for _ in range(2):
            self.assertStatus(await self.query(identity), 'unknown')
        self.assertEqual(self.runtime.calls['close'], closes)  # asking never retried the close
        self.runtime.close_confirms = True
        await self.broker.reconcile()
        self.assertStatus(await self.query(identity), 'confirmed')

    async def test_a_receipt_requires_the_finish_not_an_empty_inventory(self):
        opened = await self.opened_level()
        identity = self.level_identity(opened)
        self.runtime.containers.clear()  # the ID is gone from Docker, but the diary never reached FINISH
        self.assertEqual(await self.runtime.installed_ids(), ())
        self.assertStatus(await self.query(identity), 'unknown')
        self.assertEqual(self.broker.status()['obligations'], 1)

    async def test_another_context_level_or_identity_never_confirms_a_receipt(self):
        identity = await self.closed_level()
        crossed = {'context_sha256': OTHER_CONTEXT, 'level': 'secret', 'run_id': RUN_B, 'intent_id': '7' * 32,
                   'container_id': '7' * 64, 'installation_id': INSTALL}
        for key, value in crossed.items():
            if key == 'installation_id':
                continue
            answer = await self.query(identity, **{key: value})
            self.assertStatus(answer, 'unknown')
            self.assertEqual(answer[key], value)  # it only echoes what was asked
        self.assertStatus(await self.query(identity, **crossed), 'unknown')
        self.assertStatus(await self.query(identity), 'confirmed')

    async def test_a_receipt_is_not_transferable_between_runs_of_different_context(self):
        first = await self.closed_level(RUN_A, 'memory', CONTEXT)
        self.runtime.create_id = 'e' * 64
        second = await self.closed_level(RUN_B, 'memory', OTHER_CONTEXT)
        for key in ('run_id', 'intent_id', 'container_id', 'context_sha256'):
            self.assertStatus(await self.query(first, **{key: second[key]}), 'unknown')
            self.assertStatus(await self.query(second, **{key: first[key]}), 'unknown')
        self.assertStatus(await self.query(first), 'confirmed')
        self.assertStatus(await self.query(second), 'confirmed')

    async def test_a_lost_close_response_is_recovered_after_a_restart_without_any_lease(self):
        opened = await self.opened_level()
        identity = self.level_identity(opened)
        await self.close_handle(opened['handle'])  # the answer is lost: the test discards it
        self.make()  # a new owner process: no lease, no tombstone, not yet reconciled
        calls = dict(self.runtime.calls)
        before_start = await self.query(identity)
        self.assertStatus(before_start, 'confirmed')
        await self.start()
        self.assertEqual(await self.query(identity), before_start)
        self.assertEqual(self.broker.leases.held(), 0)
        stale = await self.close_handle(opened['handle'])
        self.assertEqual(stale['reason'], 'unknown_handle')  # the handle did not survive; the diary did
        self.assertEqual(dict(self.runtime.calls), calls)  # nothing was created, started, executed or closed again

    async def test_an_older_receipt_survives_a_later_run_and_a_second_restart(self):
        first = await self.closed_level(RUN_A)
        self.runtime.create_id = 'e' * 64
        second_open = await self.open_level(RUN_B)
        self.assertTrue(second_open['ok'], second_open)
        second = self.level_identity(second_open)
        self.assertNotEqual(first['container_id'], second['container_id'])
        self.assertStatus(await self.query(first), 'confirmed')  # another run holds the single plaza
        self.assertStatus(await self.query(second), 'unknown')
        await self.close_handle(second_open['handle'])
        for _ in range(2):
            self.assertStatus(await self.query(first), 'confirmed')
            self.assertStatus(await self.query(second), 'confirmed')
            self.make()
            self.assertStatus(await self.query(first), 'confirmed')
            await self.start()

    async def test_an_empty_or_unrelated_diary_knows_nothing(self):
        await self.start()
        self.assertStatus(await self.query(IDENT_LEVEL), 'unknown')
        self.assertStatus(await self.query({**IDENT_LEVEL, 'run_id': '7' * 32, 'intent_id': '7' * 32,
                                            'container_id': '7' * 64}), 'unknown')

    async def test_it_answers_in_every_owner_state(self):
        identity = await self.closed_level()
        self.runtime.containers.add(FOREIGN)
        self.make()
        await self.start()
        self.assertEqual(self.broker.status()['blocked'], 'unrecognized_object')  # blocked owner
        self.assertStatus(await self.query(identity), 'confirmed')
        self.make()
        self.assertEqual(self.broker.status()['recovered'], False)  # not reconciled
        self.assertStatus(await self.query(identity), 'confirmed')
        self.broker._shutdown = True  # shutting down
        self.assertStatus(await self.query(identity), 'confirmed')

    async def test_installation_mismatch_is_a_closed_refusal_that_never_reaches_the_diary(self):
        identity = await self.closed_level()
        answer = await self.exchange(self.body(identity, installation_id='9' * 32))
        self.assertEqual(answer, {'ok': False, 'reason': 'installation_mismatch'})
        self.assertEqual(self.inventory.level_queries, [])
        self.assertStatus(await self.query(identity), 'confirmed')

    async def test_the_diary_is_asked_only_about_the_authenticated_uid(self):
        identity = await self.closed_level()
        body = self.body(identity)
        self.assertIsNone(await self.exchange(body, uid=CLIENT_UID + 1))
        self.assertEqual(self.inventory.level_queries, [])
        await self.query(identity)
        self.assertEqual({item[0] for item in self.inventory.level_queries}, {CLIENT_UID})
        for field in ('controller_uid', 'uid', 'owner_uid'):  # the request cannot name another UID
            self.assertEqual(await self.exchange(self.body(identity, **{field: CLIENT_UID + 1})),
                             {'ok': False, 'reason': 'unexpected_field'})
        self.assertEqual(len(self.inventory.level_queries), 1)

    async def test_diary_failures_are_closed_and_change_nothing(self):
        await self.start()
        for code, reason in (('identity_changed', 'foreign_owner'), ('state_unavailable', 'internal_error'),
                             ('state_corrupt', 'internal_error'), ('not a closed code!', 'internal_error')):
            self.inventory.level_receipt_error = code
            self.assertEqual(await self.exchange(self.body(IDENT_LEVEL)), {'ok': False, 'reason': reason})
        self.inventory.level_receipt_error = None

        def broken(**kwargs):
            raise RuntimeError('boom')
        self.inventory.receipt_level = broken
        self.assertEqual(await self.exchange(self.body(IDENT_LEVEL)), {'ok': False, 'reason': 'internal_error'})
        self.assertIsNone(self.broker.status()['blocked'])  # a failed read never blocks the owner

    async def test_only_the_exact_finish_of_the_full_level_identity_confirms(self):
        await self.start()
        finish = LevelIntent(IDENT_LEVEL['intent_id'], 'escape-actor-' + IDENT_LEVEL['intent_id'], CLIENT_UID, RUN_A, 'memory',
                             'actor', CONTEXT, CONTAINER, 'FINISH', DIGEST)
        self.inventory.level_receipt_returns = finish
        self.assertStatus(await self.query(IDENT_LEVEL), 'confirmed')
        for patch in ({'phase': 'ACTIVE'}, {'phase': 'CLOSE_PENDING'}, {'controller_uid': CLIENT_UID + 1}, {'run_id': RUN_B},
                      {'level': 'secret'}, {'stage': 'fresh'}, {'context_sha256': OTHER_CONTEXT}, {'intent_id': '7' * 32},
                      {'container_id': '7' * 64}):
            self.inventory.level_receipt_returns = dataclasses.replace(finish, **patch)
            answer = await self.exchange(self.body(IDENT_LEVEL))
            self.assertEqual(answer, {'ok': False, 'reason': 'internal_error'}, patch)  # another identity cannot confirm
        workflow_finish = Intent(IDENT_LEVEL['intent_id'], 'escape-actor-' + IDENT_LEVEL['intent_id'], CLIENT_UID, RUN_A,
                                 'legitimate', CONTAINER, 'FINISH', DIGEST)  # a workflow FINISH is not a level FINISH
        for other in (workflow_finish, object()):
            self.inventory.level_receipt_returns = other
            self.assertEqual(await self.exchange(self.body(IDENT_LEVEL)), {'ok': False, 'reason': 'internal_error'})

    async def test_an_inventory_without_receipt_level_never_confirms(self):
        class NoLevelReceipt(LevelInventory):
            receipt_level = None
        self.inventory = NoLevelReceipt(self.log)
        self.runtime = LevelRuntime(self.log, self.inventory)
        self.make()
        await self.start()
        self.assertEqual(await self.exchange(self.body(IDENT_LEVEL)), {'ok': False, 'reason': 'internal_error'})
        self.assertTrue((await self.open_level())['ok'])  # opening is untouched

    async def test_malformed_requests_get_closed_reasons_without_a_diary_query(self):
        await self.start()
        cases = (({'installation_id': 'x'}, 'invalid_installation_id'), ({'run_id': 'x'}, 'invalid_run_id'),
                 ({'level': 'bogus'}, 'invalid_level'), ({'stage': 'fresh'}, 'invalid_stage'),  # M5: `network` is a valid name now
                 ({'context_sha256': 'x'}, 'invalid_context'), ({'intent_id': 5}, 'invalid_intent_id'),
                 ({'container_id': 'c' * 63}, 'invalid_container_id'), ({'variant': 'legitimate'}, 'unexpected_field'),
                 ({'handle': 'ab' * 32}, 'unexpected_field'), ({'image': 'x'}, 'forbidden_field'),
                 ({'command': 'id'}, 'unexpected_field'))
        for patch, reason in cases:
            self.assertEqual(await self.exchange(self.body(IDENT_LEVEL, **patch)), {'ok': False, 'reason': reason}, patch)
        short = {key: value for key, value in self.body(IDENT_LEVEL).items() if key != 'context_sha256'}
        self.assertEqual(await self.exchange(short), {'ok': False, 'reason': 'missing_field'})
        self.assertEqual(self.inventory.level_queries, [])

    async def test_the_m1_receipt_still_answers_on_a_mixed_diary(self):
        level = await self.closed_level()
        workflow = await self.open(RUN_B, 'legitimate')
        self.assertTrue(workflow['ok'], workflow)
        wire.validate_close(await self.close_handle(workflow['handle']), receipt=self.identity(workflow))
        identity = self.identity(workflow)
        answer = await self.exchange({'op': 'receipt', **identity})
        self.assertEqual(wire.validate_receipt(answer, identity=identity)['status'], 'confirmed')
        self.assertStatus(await self.query(level), 'confirmed')

    async def test_the_query_never_reaches_the_runtime_or_mutates_anything(self):
        identity = await self.closed_level()
        calls, log = dict(self.runtime.calls), list(self.log)
        exploding = ExplodingRuntime()
        self.broker.runtime = exploding  # from here any runtime access is an error
        for _ in range(3):
            self.assertStatus(await self.query(identity), 'confirmed')
            self.assertStatus(await self.query(identity, context_sha256=OTHER_CONTEXT), 'unknown')
        self.assertEqual(exploding.touched, [])
        for name in ('create', 'start', 'execute', 'probe', 'probe_level', 'close'):
            self.assertEqual(self.runtime.calls[name], calls.get(name, 0), name)
        self.assertEqual(self.log, log)  # no diary mutation and no event: the timeline did not grow
        self.assertEqual(self.runtime.removed, [CONTAINER])

    async def test_it_neither_waits_for_the_operation_in_flight_nor_extends_the_ttl(self):
        self.make(limits=fast_limits(probe=2.0))
        opened = await self.opened_level()
        identity = self.level_identity(opened)
        self.runtime.level_gate = asyncio.Event()
        self.runtime.level_started = asyncio.Event()
        running = asyncio.ensure_future(self.level_probe(opened['handle']))
        await self.runtime.level_started.wait()
        self.assertStatus(await asyncio.wait_for(self.query(identity), 1), 'unknown')  # no handle lock, no `busy`, no wait
        self.runtime.level_gate.set()
        self.assertTrue((await running)['ok'])
        self.assertEqual(self.runtime.calls['probe_level'], 1)  # neither repeated nor cancelled
        self.clock.now += 119
        self.assertStatus(await self.query(identity), 'unknown')  # asking at 119 s does not renew the lease
        self.clock.now += 1.5
        self.assertEqual((await self.level_probe(opened['handle']))['reason'], 'expired')
        await self.broker.reconcile()
        self.assertStatus(await self.query(identity), 'confirmed')


class LevelRecoveryAndCancellationTests(LevelCase):
    def pending(self, phase, *, container=CONTAINER, run=RUN_A):
        return LevelIntent('a' * 32, 'escape-actor-' + 'a' * 32, CLIENT_UID, run, 'memory', 'actor', CONTEXT, container, phase,
                           DIGEST)

    async def test_restart_restitutes_a_recognized_level_id_without_reissuing_actions(self):
        opened = await self.opened_level()
        self.make()  # a new process over the same diary and runtime
        self.log.clear()
        await self.start()
        self.assertEqual(self.log, ORDER_OF_CLOSE)
        self.assertEqual((self.runtime.removed, self.runtime.foreign), ([CONTAINER], {FOREIGN}))
        self.assertEqual((self.runtime.calls['create'], self.runtime.calls['start'], self.runtime.calls['execute'],
                          self.runtime.calls['probe_level']), (1, 1, 0, 0))
        self.assertEqual(self.broker.status(), {'installation_id': INSTALL, 'blocked': None, 'obligations': 0, 'recovered': True})
        self.assertEqual((await self.close_handle(opened['handle']))['reason'], 'unknown_handle')  # a restart invalidates handles
        self.assertEqual((await self.open_level(RUN_A))['reason'], 'already_active')  # and the replay stays refused
        self.assertTrue((await self.open_level(RUN_B))['ok'])

    async def test_every_phase_with_a_known_id_is_restituted_by_id_even_if_the_policy_changed(self):
        for allowed in (('memory',), ()):
            for phase in ('CREATE_ACK', 'START_PENDING', 'ACTIVE', 'CLOSE_PENDING'):
                with self.subTest(phase=phase, allowed=allowed):
                    self.fresh(allowed_levels=allowed)
                    self.inventory.current = self.pending(phase)
                    self.runtime.containers.add(CONTAINER)
                    await self.start()
                    self.assertEqual(self.runtime.removed, [CONTAINER])
                    self.assertEqual(self.log, ORDER_OF_CLOSE)
                    self.assertEqual(self.runtime.foreign, {FOREIGN})
                    for name in ('create', 'start', 'execute', 'probe', 'probe_level'):
                        self.assertEqual(self.runtime.calls[name], 0)
                    self.assertTrue(self.broker.status()['recovered'])

    async def test_pending_without_an_id_blocks_even_with_an_empty_inventory(self):
        self.inventory.current = self.pending('CREATE_PENDING', container=None)
        await self.start()
        self.assertEqual((self.broker.status()['blocked'], self.broker.status()['obligations']), ('create_uncertain', 1))
        self.assertEqual(self.runtime.calls['close'], 0)
        self.assertEqual((await self.open_level(RUN_B))['reason'], 'owner_blocked')
        await self.broker.reconcile()  # time and repetition do not clear it
        self.assertEqual(self.broker.status()['blocked'], 'create_uncertain')

    async def test_unconfirmed_restitution_at_startup_blocks_and_is_retried(self):
        self.inventory.current = self.pending('ACTIVE')
        self.runtime.containers.add(CONTAINER)
        self.runtime.close_confirms = False
        await self.start()
        self.assertEqual((self.broker.status()['blocked'], self.broker.status()['recovered']), ('cleanup_unconfirmed', False))
        self.assertEqual((await self.open_level(RUN_B))['reason'], 'owner_blocked')
        self.runtime.close_confirms = True
        await self.broker.reconcile()
        self.assertEqual(self.broker.status(), {'installation_id': INSTALL, 'blocked': None, 'obligations': 0, 'recovered': True})
        self.assertEqual(self.runtime.removed, [CONTAINER])

    async def test_cancelled_open_after_the_intent_is_durable_leaves_the_handle_to_the_reaper(self):
        self.make(limits=fast_limits(create=2.0))
        await self.start()
        self.runtime.create_gate = asyncio.Event()
        task = asyncio.ensure_future(self.open_level())
        await self.wait_for_call('create')
        self.assertIsInstance(self.inventory.current, LevelIntent)
        self.assertEqual(self.inventory.current.phase, 'CREATE_PENDING')  # durable before create
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.runtime.create_gate.set()
        await self.broker.drain()
        self.assertEqual(self.inventory.current.phase, 'ACTIVE')  # the open completed; its response was dropped
        self.assertEqual(self.broker.status()['obligations'], 1)
        self.clock.now += 121
        await self.broker.reconcile()
        self.assertEqual(self.runtime.removed, [CONTAINER])
        self.assertEqual(self.broker.status()['obligations'], 0)
        self.assertEqual((await self.open_level())['reason'], 'already_active')  # the cancelled run is spent, not retried

    async def test_cancelled_probe_does_not_cancel_the_operation_nor_repeat_it(self):
        self.make(limits=fast_limits(probe=2.0))
        opened = await self.opened_level()
        self.runtime.level_gate = asyncio.Event()
        self.runtime.level_started = asyncio.Event()
        task = asyncio.ensure_future(self.level_probe(opened['handle']))
        await self.runtime.level_started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.runtime.level_gate.set()
        await self.broker.drain()
        self.assertEqual((self.runtime.calls['probe_level'], self.inventory.current.phase), (1, 'ACTIVE'))  # finished, not replayed
        self.assertTrue((await self.level_probe(opened['handle']))['ok'])
        self.assertEqual(self.runtime.calls['probe_level'], 2)
        wire.validate_level_close(await self.close_handle(opened['handle']), receipt=self.level_identity(opened))

    async def test_an_expired_level_lease_is_restituted_by_the_reaper_and_keeps_its_plaza_until_then(self):
        opened = await self.opened_level()
        self.clock.now += 121
        self.assertEqual((await self.level_probe(opened['handle']))['reason'], 'expired')
        self.assertEqual((await self.open_level(RUN_B))['reason'], 'capacity_exhausted')
        self.assertEqual(self.broker.leases.held(), 1)
        await self.broker.reconcile()
        self.assertEqual((self.runtime.removed, self.broker.leases.held()), ([CONTAINER], 0))
        self.assertTrue((await self.open_level(RUN_B))['ok'])

    async def test_a_transport_error_while_answering_leaves_the_level_lease_with_the_owner(self):
        await self.start()
        reader, writer = FakeReader(frame(OPEN_LEVEL_BODY)), FakeWriter(CLIENT_UID, fail_drain=True)
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            await self.broker._connection(reader, writer)
        self.assertTrue(writer.closed)
        self.assertEqual((self.broker.leases.held(), self.inventory.current.phase), (1, 'ACTIVE'))
        self.clock.now += 121
        await self.broker.reconcile()  # the reaper restitutes the lost handle by ID
        self.assertEqual((self.runtime.removed, self.broker.status()['obligations']), ([CONTAINER], 0))


class LevelConnectionTests(LevelCase):
    async def serve_one(self, data, *, uid=CLIENT_UID):
        reader, writer = FakeReader(data), FakeWriter(uid)
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            await self.broker._connection(reader, writer)
        return reader, writer

    async def test_a_level_open_through_an_authenticated_connection(self):
        await self.start()
        reader, writer = await self.serve_one(frame(OPEN_LEVEL_BODY))
        response = writer.response()
        wire.validate_level_open(response, **LEVEL_ARGS)
        self.assertTrue(writer.closed)
        self.assertLessEqual(len(bytes(writer.data)) - 4, wire.RESPONSE_LIMITS['open_level'])
        self.assertEqual(self.log, ORDER_OF_OPEN_LEVEL)

    async def test_trailing_bytes_and_other_uids_are_not_dispatched(self):
        await self.start()
        reader, writer = await self.serve_one(frame(OPEN_LEVEL_BODY) + b'x')
        self.assertEqual(writer.response(), {'ok': False, 'reason': 'framing'})
        reader, writer = await self.serve_one(frame(OPEN_LEVEL_BODY), uid=CLIENT_UID + 1)
        self.assertEqual((reader.reads, bytes(writer.data), writer.closed), (0, b'', True))
        self.assertEqual((self.log, self.broker.leases.held()), ([], 0))

    async def test_a_level_receipt_through_an_authenticated_connection(self):
        opened = await self.opened_level()
        identity = self.level_identity(opened)
        wire.validate_level_close(await self.close_handle(opened['handle']), receipt=identity)
        reader, writer = await self.serve_one(frame({'op': 'level_receipt', **identity}))
        self.assertEqual(wire.validate_level_receipt(writer.response(), identity=identity)['status'], 'confirmed')
        self.assertLessEqual(len(bytes(writer.data)) - 4, wire.RESPONSE_LIMITS['level_receipt'])
        queries = len(self.inventory.level_queries)
        reader, writer = await self.serve_one(frame({'op': 'level_receipt', **identity}) + b'x')
        self.assertEqual(writer.response(), {'ok': False, 'reason': 'framing'})
        self.assertEqual(len(self.inventory.level_queries), queries)


# ------------------------------------------------------------------------------------------------------- M2.3 · persistence
# Doubles faithful to actor-recovery/v3 (SC2-PERSISTENCIA-ADAPTADORES-LOCAL): the DIARY derives the predecessor of a fresh phase from the
# FINISH of the actor phase of the same UID, run and context, inside begin_level, and returns it on the intent. Fresh-first is
# predecessor_unconfirmed, a replay is already_started even after FINISH, another context is invalid_transition, and none of them
# journals anything. The real diary was exercised by the integrator (docker-02); these doubles only pin what the broker does with it.
# Authored without a shell: none of these tests has been executed by the author.

B_CONTAINER = 'e' * 64
MARKER = '/work/marker-' + 'a' * 24
OTHER_MARKER = '/work/marker-' + 'f' * 24
SCAN_DIGEST = 'b' * 64
SCAN_SIZE = 24
A_IDENT_LEVEL = {**IDENT_LEVEL, 'level': 'persistence'}
B_IDENT_LEVEL = {**A_IDENT_LEVEL, 'stage': 'fresh', 'intent_id': '6' * 32, 'container_id': B_CONTAINER}
FILE_PRESENT = {'status': 'present', 'inode': 7, 'size': SCAN_SIZE, 'mtime': 5, 'ctime': 6, 'links': 1, 'sha256': 'a' * 64}
SCAN_OK = {'verifier_version': 'persistence-copy/v2', 'complete': True, 'reasons': [],
           'matches': [{'path': '/tmp/copy-1', 'size': SCAN_SIZE, 'links': 1}], 'matches_total': 1, 'entries': 4, 'bytes_read': 96,
           'skipped_nonregular': 0}
SCAN_EMPTY = {**SCAN_OK, 'matches': [], 'matches_total': 0}


@dataclasses.dataclass(frozen=True)
class Predecessor:  # the seven fields of actor_state.LevelPredecessor
    installation_id: str
    run_id: str
    level: str
    stage: str
    context_sha256: str
    intent_id: str
    container_id: str


@dataclasses.dataclass(frozen=True)
class PersistIntent(LevelIntent):  # actor_state.LevelIntent: the level intent plus `predecessor`, None for an actor phase
    predecessor: object = None


class PersistInventory(LevelInventory):
    def begin_level(self, *, controller_uid, run_id, level, stage, context_sha256):
        self._gate('begin_level')
        if self.current is not None:
            raise StateError('actor_busy')
        key = ('level', controller_uid, run_id, level, stage)
        if key in self.used:
            raise StateError('already_started')  # also after FINISH, for A and for B
        predecessor = None
        if level == 'persistence' and stage == 'fresh':
            actor = next((item for item in reversed(self.history) if isinstance(item, PersistIntent)
                          and (item.controller_uid, item.run_id, item.level, item.stage) == (controller_uid, run_id, 'persistence',
                                                                                              'actor')), None)
            if actor is None:
                raise StateError('predecessor_unconfirmed')  # a clean refusal: nothing is journaled
            if actor.context_sha256 != context_sha256:
                raise StateError('invalid_transition')
            predecessor = Predecessor(INSTALL, run_id, 'persistence', 'actor', actor.context_sha256, actor.intent_id, actor.container_id)
        if any(other[:3] == key[:3] and context != context_sha256 for other, context in self.contexts.items()):
            raise StateError('invalid_transition')
        self.used.add(key)
        self.contexts[key] = context_sha256
        self.count += 1
        intent_id = '%032x' % (0xa0 + self.count)
        self.current = PersistIntent(intent_id, 'escape-actor-' + intent_id, controller_uid, run_id, level, stage, context_sha256, None,
                                     'CREATE_PENDING', DIGEST, predecessor)
        return self.current


class PersistCase(LevelCase):
    async def asyncSetUp(self):
        self.log = []
        self.inventory = PersistInventory(self.log)
        self.runtime = LevelRuntime(self.log, self.inventory)
        self.clock = Clock()
        self.make()

    def make(self, **overrides):
        overrides.setdefault('allowed_levels', ('memory', 'persistence'))
        return super().make(**overrides)

    def fresh(self, **overrides):
        self.log.clear()
        self.inventory = PersistInventory(self.log)
        self.runtime = LevelRuntime(self.log, self.inventory)
        self.make(**overrides)

    def use(self, inventory, **overrides):
        self.log.clear()
        self.inventory = inventory
        self.runtime = LevelRuntime(self.log, self.inventory)
        self.make(**overrides)

    async def phase(self, stage, run=RUN_A, context=CONTEXT):
        return await self.open_level(run, 'persistence', stage, context)

    async def opened_a(self, run=RUN_A, context=CONTEXT):
        if not self.broker.status()['recovered']:
            await self.start()
        response = await self.phase('actor', run, context)
        self.assertTrue(response['ok'], response)
        return response

    async def closed_a(self, run=RUN_A, context=CONTEXT):
        opened = await self.opened_a(run, context)
        identity = self.level_identity(opened)
        wire.validate_level_close(await self.close_handle(opened['handle']), receipt=identity)
        return identity

    async def opened_b(self, run=RUN_A, context=CONTEXT):
        self.runtime.create_id = B_CONTAINER  # a distinct container for the second phase
        return await self.phase('fresh', run, context)

    async def probe(self, handle, name, **arguments):
        return await self.call({'op': 'level_probe', 'handle': handle, 'name': name, **arguments})

    async def wait_calls(self, name, count):
        for _ in range(500):
            if self.runtime.calls[name] >= count:
                return
            await asyncio.sleep(0.001)
        self.fail('runtime never reached %s x%d' % (name, count))

    def moved(self):
        return (list(self.log), dict(self.runtime.calls), self.inventory.count, self.inventory.current, len(self.inventory.history),
                tuple(sorted(self.runtime.containers)), self.broker.status(), self.broker.leases.held())


class PersistencePolicyTests(PersistCase):
    async def test_persistence_is_served_only_when_the_owner_configures_it_and_the_default_stays_empty(self):
        self.make(allowed_levels=('memory',))
        await self.start()
        for stage in ('actor', 'fresh'):
            self.assertEqual(await self.phase(stage), {'ok': False, 'reason': 'level_not_allowed'})
        self.assertEqual((self.log, self.inventory.used, self.runtime.calls['create'], self.broker.leases.held()), ([], set(), 0, 0))
        default = ActorBroker(runtime=self.runtime, inventory=self.inventory, client_uid=CLIENT_UID, image_id=IMAGE, clock=self.clock,
                              limits=fast_limits())
        self.assertEqual(default.allowed_levels, frozenset())
        for stage in ('actor', 'fresh'):
            self.assertEqual(json.loads(await default.handle(CLIENT_UID, enc({**OPEN_LEVEL_BODY, 'level': 'persistence',
                                                                              'stage': stage}))),
                             {'ok': False, 'reason': 'level_not_allowed'})
        self.make(allowed_levels=['persistence'])
        self.assertEqual(self.broker.allowed_levels, frozenset({'persistence'}))
        for bad in (['fresh'], ['Persistence'], ('persistence', 'fresh'), 'persistence'):
            with self.assertRaises(ValueError):
                self.make(allowed_levels=bad)

    async def test_persistence_needs_the_level_interfaces_like_every_other_level(self):
        m1_inventory = FakeInventory(self.log)
        with self.assertRaises(ValueError):
            self.make(inventory=m1_inventory, runtime=FakeRuntime(self.log, m1_inventory), allowed_levels=('persistence',))
        with self.assertRaises(ValueError):
            self.make(runtime=FakeRuntime(self.log, self.inventory), allowed_levels=('persistence',))

    async def test_memory_and_secret_have_no_fresh_phase_even_when_the_owner_serves_them(self):
        self.make(allowed_levels=('memory', 'secret', 'persistence'))
        await self.start()
        for level in ('memory', 'secret'):
            self.assertEqual(await self.open_level(RUN_A, level, 'fresh'), {'ok': False, 'reason': 'invalid_stage'})
            self.assertEqual(await self.call({'op': 'level_receipt', **IDENT_LEVEL, 'level': level, 'stage': 'fresh'}),
                             {'ok': False, 'reason': 'invalid_stage'})
        self.assertEqual(await self.phase('x'), {'ok': False, 'reason': 'invalid_stage'})
        self.assertEqual((self.log, self.inventory.used, self.inventory.level_queries, self.broker.leases.held()), ([], set(), [], 0))

    async def test_a_request_can_never_carry_the_predecessor(self):
        a = await self.closed_a()
        opened = await self.opened_b()
        self.assertTrue(opened['ok'], opened)
        pin = dict(a)
        bodies = (self.body_open('fresh'), {'op': 'level_receipt', **B_IDENT_LEVEL},
                  {'op': 'level_probe', 'handle': opened['handle'], 'name': 'file_state', 'path': MARKER},
                  {'op': 'level_probe', 'handle': opened['handle'], 'name': 'copy_scan', 'sha256': SCAN_DIGEST, 'size': SCAN_SIZE,
                   'exclude': None})
        before = self.moved()
        for body in bodies:
            for value in (pin, None, 'x'):
                answer = await self.call({**body, 'predecessor': value})
                self.assertEqual(answer, {'ok': False, 'reason': 'unexpected_field'}, body['op'])
        self.assertEqual(self.moved(), before)
        self.assertEqual(self.inventory.level_queries, [])

    def body_open(self, stage, run=RUN_A, context=CONTEXT):
        return {'op': 'open_level', 'run_id': run, 'level': 'persistence', 'stage': stage, 'context_sha256': context}


class PersistencePhaseTests(PersistCase):
    async def test_a_then_b_follow_the_contract_order_and_b_carries_the_predecessor_of_the_diary(self):
        opened_a = await self.opened_a()
        self.assertEqual(self.log, ORDER_OF_OPEN_LEVEL)
        a = self.level_identity(opened_a)
        wire.validate_level_open(opened_a, run_id=RUN_A, level='persistence', stage='actor', context_sha256=CONTEXT,
                                 installation_id=INSTALL, image_id=IMAGE)
        self.assertNotIn('predecessor', opened_a)
        wire.validate_level_close(await self.close_handle(opened_a['handle']), receipt=a)
        self.log.clear()
        opened_b = await self.opened_b()
        self.assertTrue(opened_b['ok'], opened_b)
        self.assertEqual(self.log, ORDER_OF_OPEN_LEVEL)
        b = self.level_identity(opened_b)
        self.assertEqual((opened_b['stage'], opened_b['container_id'], opened_b['predecessor']), ('fresh', B_CONTAINER, a))
        self.assertNotEqual((b['intent_id'], b['container_id']), (a['intent_id'], a['container_id']))
        wire.validate_level_open(opened_b, run_id=RUN_A, level='persistence', stage='fresh', context_sha256=CONTEXT,
                                 installation_id=INSTALL, image_id=IMAGE, predecessor=a)
        current = self.inventory.current
        self.assertIsInstance(current.predecessor, Predecessor)
        self.assertEqual(dataclasses.asdict(current.predecessor), a)  # the wire object is the diary's, by dataclasses.asdict
        closed_b = await self.close_handle(opened_b['handle'])
        self.assertEqual(wire.validate_level_close(closed_b, receipt=b, predecessor=a)['predecessor'], a)
        self.assertEqual(self.log[-3:], ORDER_OF_CLOSE)
        self.assertEqual(await self.close_handle(opened_b['handle']), closed_b)  # idempotent
        self.assertEqual((self.runtime.calls['create'], self.runtime.calls['close']), (2, 2))
        self.assertEqual((self.broker.status()['obligations'], self.broker.leases.held()), (0, 0))

    async def test_b_before_a_is_a_clean_refusal_that_creates_nothing_and_poisons_nothing(self):
        await self.start()
        self.assertEqual(await self.phase('fresh'), {'ok': False, 'reason': 'predecessor_unconfirmed'})
        self.assertEqual(self.log, ['inv:begin_level'])
        self.assertEqual((self.runtime.calls['create'], self.broker.leases.held(), self.inventory.current, self.inventory.used),
                         (0, 0, None, set()))
        self.assertEqual(self.broker.status(), {'installation_id': INSTALL, 'blocked': None, 'obligations': 0, 'recovered': True})
        self.assertEqual(await self.phase('fresh'), {'ok': False, 'reason': 'predecessor_unconfirmed'})  # and it can be asked again
        opened = await self.opened_a()  # the refusal spent no key and blocked nothing
        self.assertTrue(opened['ok'], opened)

    async def test_an_uncertain_a_means_b_does_not_open(self):
        opened = await self.opened_a()
        self.runtime.close_confirms = False
        closed = await self.close_handle(opened['handle'])
        self.assertEqual((closed['reason'], closed['cleanup_confirmed']), ('cleanup_unconfirmed', False))
        self.log.clear()
        for run in (RUN_A, RUN_B):
            self.assertEqual((await self.opened_b(run))['reason'], 'capacity_exhausted')  # the single plaza is still A's
        self.assertEqual((self.log, self.runtime.calls['create']), ([], 1))
        self.runtime.close_confirms = True
        await self.broker.reconcile()  # same ID, same procedure: only now does A have its FINISH
        b = await self.opened_b()
        self.assertTrue(b['ok'], b)
        self.assertEqual(b['predecessor'], self.level_identity(opened))

    async def test_an_ambiguous_create_of_a_blocks_b(self):
        await self.start()
        self.runtime.create_error = RuntimeError('boom')
        response = await self.phase('actor')
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('create_failed', False))
        self.assertEqual((await self.opened_b())['reason'], 'owner_blocked')
        self.assertEqual(self.log, ['inv:begin_level', 'rt:create@CREATE_PENDING'])
        self.assertEqual((self.runtime.calls['create'], self.runtime.calls['close']), (1, 0))
        self.assertEqual(self.broker.status()['blocked'], 'create_uncertain')

    async def test_replays_and_crossed_runs_are_refused_without_spending_or_blocking(self):
        await self.closed_a()
        b = await self.opened_b()
        await self.close_handle(b['handle'])
        self.log.clear()
        self.assertEqual(await self.phase('actor'), {'ok': False, 'reason': 'already_active'})  # replay of A after FINISH
        self.assertEqual(await self.phase('fresh'), {'ok': False, 'reason': 'already_active'})  # replay of B after FINISH
        self.assertEqual(await self.phase('actor', RUN_A, OTHER_CONTEXT), {'ok': False, 'reason': 'already_active'})
        self.assertEqual(await self.phase('fresh', RUN_B), {'ok': False, 'reason': 'predecessor_unconfirmed'})  # no actor phase of that run
        self.assertEqual(self.log, ['inv:begin_level'] * 4)
        self.assertEqual((self.runtime.calls['create'], self.broker.status()['blocked'], self.broker.leases.held()), (2, None, 0))

    async def test_b_of_another_context_than_a_is_refused_without_blocking_and_the_right_context_still_opens(self):
        await self.closed_a()
        self.log.clear()
        self.assertEqual(await self.phase('fresh', RUN_A, OTHER_CONTEXT), {'ok': False, 'reason': 'context_mismatch'})
        self.assertEqual((self.log, self.broker.status()['blocked'], self.runtime.calls['create']), (['inv:begin_level'], None, 1))
        b = await self.opened_b()
        self.assertTrue(b['ok'], b)
        self.assertEqual(b['context_sha256'], CONTEXT)

    async def test_the_plaza_is_single_across_the_two_phases(self):
        a = await self.opened_a()
        self.log.clear()
        self.assertEqual((await self.opened_b())['reason'], 'capacity_exhausted')  # B cannot even be begun while A holds the plaza
        self.assertEqual((await self.open(RUN_B))['reason'], 'capacity_exhausted')
        self.assertEqual(self.log, [])
        wire.validate_level_close(await self.close_handle(a['handle']), receipt=self.level_identity(a))
        self.assertTrue((await self.opened_b())['ok'])

    async def test_another_uid_gets_no_answer_and_cannot_use_either_handle(self):
        a = await self.closed_a()
        b = await self.opened_b()
        before = self.moved()
        # Sol reception: this class has no body_open helper; use the exact request under test.
        for body in ({'op': 'open_level', 'run_id': RUN_B, 'level': 'persistence', 'stage': 'fresh', 'context_sha256': CONTEXT},
                     {'op': 'level_receipt', **B_IDENT_LEVEL}, {'op': 'level_receipt', **a},
                     {'op': 'close', 'handle': b['handle']}, {'op': 'execute', 'handle': b['handle'], 'command': 'true'},
                     {'op': 'level_probe', 'handle': b['handle'], 'name': 'file_state', 'path': MARKER},
                     {'op': 'level_probe', 'handle': b['handle'], 'name': 'copy_scan', 'sha256': SCAN_DIGEST, 'size': SCAN_SIZE,
                      'exclude': None}):
            self.assertIsNone(await self.call(body, uid=CLIENT_UID + 1))
        self.assertEqual(self.moved(), before)
        self.assertEqual(self.inventory.level_queries, [])
        self.runtime.level_result = {'status': 'missing'}
        self.assertTrue((await self.probe(b['handle'], 'file_state', path=MARKER))['ok'])  # the real owner of the handle is undisturbed

    async def test_the_memory_and_m1_answers_are_unchanged_on_an_owner_that_serves_persistence(self):
        memory = await self.opened_level()
        self.assertEqual(self.log, ORDER_OF_OPEN_LEVEL)
        self.assertNotIn('predecessor', memory)
        wire.validate_level_open(memory, **LEVEL_ARGS)
        closed = await self.close_handle(memory['handle'])
        self.assertNotIn('predecessor', closed)
        wire.validate_level_close(closed, receipt=self.level_identity(memory))
        receipt = await self.call({'op': 'level_receipt', **self.level_identity(memory)})
        self.assertNotIn('predecessor', receipt)
        wire.validate_level_receipt(receipt, identity=self.level_identity(memory))
        workflow = await self.open(RUN_B, 'legitimate')
        wire.validate_open(workflow, run_id=RUN_B, variant='legitimate', installation_id=INSTALL, image_id=IMAGE)
        wire.validate_close(await self.close_handle(workflow['handle']), receipt=self.identity(workflow))


class PersistenceReceiptTests(PersistCase):
    async def query(self, identity, **patch):
        requested = {**identity, **patch}
        before = self.moved()
        response = await self.call({'op': 'level_receipt', **requested})
        self.assertEqual(self.moved(), before)  # a read: nothing in the diary, the runtime, the leases or the owner moved
        self.assertTrue(response['ok'], response)
        return response

    def assertStatus(self, answer, status):
        self.assertEqual((answer['status'], answer['cleanup_confirmed']), (status, status == 'confirmed'))

    async def both(self):
        a = await self.closed_a()
        opened = await self.opened_b()
        self.assertTrue(opened['ok'], opened)
        b = self.level_identity(opened)
        self.assertEqual(b['stage'], 'fresh')
        wire.validate_level_close(await self.close_handle(opened['handle']), receipt=b, predecessor=a)
        return a, b

    async def test_each_phase_has_its_own_receipt_and_b_names_the_predecessor_of_its_own_finish(self):
        a = await self.closed_a()
        opened = await self.opened_b()
        b = self.level_identity(opened)
        confirmed_a = await self.query(a)
        self.assertStatus(confirmed_a, 'confirmed')
        self.assertNotIn('predecessor', confirmed_a)  # the actor shape is unchanged
        unknown = await self.query(b)  # B is ACTIVE: no FINISH yet
        self.assertStatus(unknown, 'unknown')
        self.assertIsNone(unknown['predecessor'])
        self.assertEqual(wire.validate_level_receipt(unknown, identity=b, predecessor=a)['status'], 'unknown')
        await self.close_handle(opened['handle'])
        confirmed_b = await self.query(b)
        self.assertStatus(confirmed_b, 'confirmed')
        self.assertEqual(confirmed_b['predecessor'], a)
        self.assertEqual(wire.validate_level_receipt(confirmed_b, identity=b, predecessor=a)['predecessor'], a)
        self.assertEqual(await self.query(b), confirmed_b)  # repeatable
        self.assertEqual(await self.query(a), confirmed_a)  # B did not replace the closure of A

    async def test_crossed_identities_are_unknown_and_a_fresh_unknown_names_no_predecessor(self):
        a, b = await self.both()
        crossed = (({**a, 'stage': 'fresh'}, True), ({**b, 'stage': 'actor'}, False), ({**a, 'container_id': b['container_id']}, False),
                   ({**b, 'intent_id': a['intent_id']}, True), ({**b, 'run_id': RUN_B}, True),
                   ({**b, 'context_sha256': OTHER_CONTEXT}, True), ({**a, 'context_sha256': OTHER_CONTEXT}, False),
                   ({**a, 'installation_id': INSTALL, 'intent_id': '7' * 32}, False))
        for identity, fresh in crossed:
            answer = await self.query(identity)
            self.assertStatus(answer, 'unknown')
            if fresh:
                self.assertIsNone(answer['predecessor'])  # the owner names nothing it did not confirm, whatever was asked
            else:
                self.assertNotIn('predecessor', answer)
        self.assertEqual(await self.call({'op': 'level_receipt', **{**b, 'level': 'memory'}}), {'ok': False, 'reason': 'invalid_stage'})
        self.assertStatus(await self.query(a), 'confirmed')
        self.assertStatus(await self.query(b), 'confirmed')

    async def test_a_finish_with_no_usable_predecessor_never_confirms_a_fresh_phase(self):
        await self.start()
        predecessor = Predecessor(**A_IDENT_LEVEL)
        finish = PersistIntent(B_IDENT_LEVEL['intent_id'], 'escape-actor-' + B_IDENT_LEVEL['intent_id'], CLIENT_UID, RUN_A,
                               'persistence', 'fresh', CONTEXT, B_CONTAINER, 'FINISH', DIGEST, predecessor)
        self.inventory.level_receipt_returns = finish
        answer = await self.query(B_IDENT_LEVEL)
        self.assertStatus(answer, 'confirmed')
        self.assertEqual(answer['predecessor'], A_IDENT_LEVEL)
        unusable = {
            'absent': None, 'other run': dataclasses.replace(predecessor, run_id=RUN_B),
            'other context': dataclasses.replace(predecessor, context_sha256=OTHER_CONTEXT),
            'other installation': dataclasses.replace(predecessor, installation_id='9' * 32),
            'memory level': dataclasses.replace(predecessor, level='memory'),
            'fresh stage': dataclasses.replace(predecessor, stage='fresh'),
            'shares the container': dataclasses.replace(predecessor, container_id=B_CONTAINER),
            'shares the intent': dataclasses.replace(predecessor, intent_id=B_IDENT_LEVEL['intent_id']),
            'malformed container': dataclasses.replace(predecessor, container_id='x'),
            'a dict': dataclasses.asdict(predecessor), 'text': 'predecessor', 'a class': Predecessor, 'a number': 5}
        for name, value in unusable.items():
            self.inventory.level_receipt_returns = dataclasses.replace(finish, predecessor=value)
            self.assertEqual(await self.call({'op': 'level_receipt', **B_IDENT_LEVEL}), {'ok': False, 'reason': 'internal_error'}, name)
        # a level intent without the attribute at all (a diary double that lacks the dependency) cannot confirm either
        plain = LevelIntent(finish.intent_id, finish.name, CLIENT_UID, RUN_A, 'persistence', 'fresh', CONTEXT, B_CONTAINER, 'FINISH',
                            DIGEST)
        self.inventory.level_receipt_returns = plain
        self.assertEqual(await self.call({'op': 'level_receipt', **B_IDENT_LEVEL}), {'ok': False, 'reason': 'internal_error'})
        # the actor phase has no predecessor to need: its FINISH still confirms in the unchanged shape
        self.inventory.level_receipt_returns = dataclasses.replace(finish, stage='actor', intent_id=A_IDENT_LEVEL['intent_id'],
                                                                   container_id=CONTAINER, predecessor=None)
        actor = await self.query(A_IDENT_LEVEL)
        self.assertStatus(actor, 'confirmed')
        self.assertNotIn('predecessor', actor)

    async def test_receipts_stay_consultable_after_the_policy_shrinks_and_across_restarts(self):
        a, b = await self.both()
        self.make(allowed_levels=())  # a later configuration serves no level
        for _ in range(2):
            self.assertStatus(await self.query(a), 'confirmed')
            self.assertEqual((await self.query(b))['predecessor'], a)
            self.make(allowed_levels=())  # restart, queried before and after reconciliation
            self.assertStatus(await self.query(b), 'confirmed')
            await self.start()
        self.assertEqual((await self.phase('actor'))['reason'], 'level_not_allowed')

    async def test_a_lost_close_response_of_each_phase_is_recovered_after_a_restart_without_a_lease_or_a_replay(self):
        opened_a = await self.opened_a()
        a = self.level_identity(opened_a)
        await self.close_handle(opened_a['handle'])  # the answer is lost: the test discards it
        self.make()  # a new owner process: no lease, no tombstone, not yet reconciled
        calls = dict(self.runtime.calls)
        self.assertStatus(await self.query(a), 'confirmed')
        await self.start()
        opened_b = await self.opened_b()
        self.assertTrue(opened_b['ok'], opened_b)
        b = self.level_identity(opened_b)
        await self.close_handle(opened_b['handle'])  # lost too
        self.make()
        calls = dict(self.runtime.calls)
        answer = await self.query(b)
        self.assertStatus(answer, 'confirmed')
        self.assertEqual(answer['predecessor'], a)
        await self.start()
        self.assertEqual(await self.query(b), answer)
        self.assertEqual(self.broker.leases.held(), 0)
        self.assertEqual((await self.close_handle(opened_b['handle']))['reason'], 'unknown_handle')  # the handle did not survive; the diary did
        self.assertEqual(dict(self.runtime.calls), calls)  # nothing was created, started, executed or closed again

    async def test_the_query_never_reaches_the_runtime_or_mutates_anything(self):
        a, b = await self.both()
        calls, log = dict(self.runtime.calls), list(self.log)
        exploding = ExplodingRuntime()
        self.broker.runtime = exploding
        for _ in range(3):
            self.assertStatus(await self.query(a), 'confirmed')
            self.assertStatus(await self.query(b), 'confirmed')
            self.assertStatus(await self.query(b, context_sha256=OTHER_CONTEXT), 'unknown')
        self.assertEqual(exploding.touched, [])
        self.assertEqual(self.log, log)
        for name in ('create', 'start', 'execute', 'probe', 'probe_level', 'close'):
            self.assertEqual(self.runtime.calls[name], calls.get(name, 0), name)

    async def test_the_fresh_answers_fit_the_unchanged_frame_limits_through_a_connection(self):
        a, b = await self.both()
        for identity, limit in ((a, wire.RESPONSE_LIMITS['level_receipt']), (b, wire.RESPONSE_LIMITS['level_receipt'])):
            reader, writer = FakeReader(frame({'op': 'level_receipt', **identity})), FakeWriter(CLIENT_UID)
            with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
                await self.broker._connection(reader, writer)
            self.assertLessEqual(len(bytes(writer.data)) - 4, limit)
            self.assertEqual(writer.response()['status'], 'confirmed')
        self.fresh()
        await self.start()
        await self.closed_a()
        reader, writer = FakeReader(frame(self.body_open('fresh'))), FakeWriter(CLIENT_UID)
        self.runtime.create_id = B_CONTAINER
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            await self.broker._connection(reader, writer)
        self.assertLessEqual(len(bytes(writer.data)) - 4, wire.RESPONSE_LIMITS['open_level'])
        self.assertEqual(writer.response()['predecessor']['stage'], 'actor')

    def body_open(self, stage, run=RUN_A, context=CONTEXT):
        return {'op': 'open_level', 'run_id': run, 'level': 'persistence', 'stage': stage, 'context_sha256': context}


class PersistenceProbeTests(PersistCase):
    async def test_file_state_and_copy_scan_reach_the_runtime_with_typed_arguments_only(self):
        opened = await self.opened_a()
        handle = opened['handle']
        for result in ({'status': 'missing'}, dict(FILE_PRESENT), {'status': 'unavailable'}):
            self.runtime.level_result = result
            answer = await self.probe(handle, 'file_state', path=MARKER)
            self.assertEqual(wire.validate_level_probe(answer, name='file_state'), result)
        for result, exclude in ((dict(SCAN_OK), MARKER), (dict(SCAN_EMPTY), None),
                                ({**SCAN_OK, 'complete': False, 'reasons': ['byte_limit'], 'matches': [], 'matches_total': 0}, OTHER_MARKER)):
            self.runtime.level_result = result
            answer = await self.probe(handle, 'copy_scan', sha256=SCAN_DIGEST, size=SCAN_SIZE, exclude=exclude)
            self.assertEqual(wire.validate_level_probe(answer, name='copy_scan', size=SCAN_SIZE), result)
        calls = [(name, typed) for _, name, typed in self.runtime.level_calls]
        self.assertEqual(calls, [('file_state', {'path': MARKER})] * 3 + [
            ('copy_scan', {'sha256': SCAN_DIGEST, 'size': SCAN_SIZE, 'exclude': exclude}) for exclude in (MARKER, None, OTHER_MARKER)])
        for intent, _, _ in self.runtime.level_calls:
            self.assertEqual((intent.phase, intent.level, intent.stage, intent.context_sha256), ('ACTIVE', 'persistence', 'actor', CONTEXT))
        self.assertEqual((self.inventory.current.phase, self.broker.leases.held()), ('ACTIVE', 1))  # legitimate answers keep the session
        self.assertTrue((await self.call({'op': 'execute', 'handle': handle, 'command': 'true'}))['ok'])

    async def test_the_same_probes_serve_the_fresh_phase_and_there_exclude_must_be_null(self):
        await self.closed_a()
        opened = await self.opened_b()
        handle = opened['handle']
        self.runtime.level_result = dict(SCAN_EMPTY)
        answer = await self.probe(handle, 'copy_scan', sha256=SCAN_DIGEST, size=SCAN_SIZE, exclude=None)
        self.assertEqual(wire.validate_level_probe(answer, name='copy_scan', size=SCAN_SIZE), SCAN_EMPTY)
        self.assertEqual(await self.probe(handle, 'copy_scan', sha256=SCAN_DIGEST, size=SCAN_SIZE, exclude=MARKER),
                         {'ok': False, 'reason': 'invalid_exclude'})  # in a fresh sandbox the original path counts
        self.assertEqual(self.runtime.calls['probe_level'], 1)  # only the null one reached the runtime
        self.assertEqual((self.inventory.current.phase, self.broker.leases.held()), ('ACTIVE', 1))  # and the lease is intact
        self.runtime.level_result = {'status': 'missing'}
        self.assertTrue((await self.probe(handle, 'file_state', path=MARKER))['ok'])
        (first, _, _), (second, _, _) = self.runtime.level_calls
        self.assertEqual((first.stage, first.predecessor is not None), ('fresh', True))
        self.assertEqual(second.stage, 'fresh')

    async def test_each_probe_is_served_only_to_its_domain(self):
        self.make(allowed_levels=('memory', 'persistence'))
        persistence = await self.opened_a(RUN_A)
        for name, arguments in (('cgroup_events', {}),):
            self.assertEqual(await self.probe(persistence['handle'], name, **arguments), {'ok': False, 'reason': 'wrong_domain'})
        for name in ('task_result', 'artifact_capture'):  # a level handle never gets the workflow probes, persistence included
            self.assertEqual(await self.call({'op': 'probe', 'handle': persistence['handle'], 'name': name}),
                             {'ok': False, 'reason': 'wrong_domain'})
        wire.validate_level_close(await self.close_handle(persistence['handle']), receipt=self.level_identity(persistence))
        memory = await self.opened_level(RUN_B)
        for name, arguments in (('file_state', {'path': MARKER}),
                                ('copy_scan', {'sha256': SCAN_DIGEST, 'size': SCAN_SIZE, 'exclude': None})):
            self.assertEqual(await self.probe(memory['handle'], name, **arguments), {'ok': False, 'reason': 'wrong_domain'})
        self.assertTrue((await self.probe(memory['handle'], 'cgroup_events'))['ok'])  # memory keeps its own probe
        wire.validate_level_close(await self.close_handle(memory['handle']), receipt=self.level_identity(memory))
        workflow = await self.open(RUN_C, 'legitimate')
        for name, arguments in (('cgroup_events', {}), ('file_state', {'path': MARKER}),
                                ('copy_scan', {'sha256': SCAN_DIGEST, 'size': SCAN_SIZE, 'exclude': None})):
            self.assertEqual(await self.probe(workflow['handle'], name, **arguments), {'ok': False, 'reason': 'wrong_domain'})
        self.assertEqual(self.runtime.calls['probe_level'], 1)  # the memory probe only: every refusal ran nothing
        self.assertEqual((self.inventory.current.phase, self.broker.leases.held()), ('ACTIVE', 1))

    async def test_the_probe_requests_carry_no_script_no_other_path_and_no_other_name(self):
        opened = await self.opened_a()
        handle = opened['handle']
        cases = (({'name': 'file_state', 'path': '/etc/shadow'}, 'invalid_path'),
                 ({'name': 'file_state', 'path': '/work/marker-' + 'a' * 23}, 'invalid_path'),
                 ({'name': 'file_state', 'path': MARKER, 'exclude': None}, 'unexpected_field'),
                 ({'name': 'file_state', 'path': MARKER, 'script': 'cat /etc/shadow'}, None),
                 ({'name': 'file_state', 'path': MARKER, 'argv': ['cat']}, None),
                 ({'name': 'file_state', 'path': MARKER, 'command': 'id'}, 'unexpected_field'),
                 ({'name': 'copy_scan', 'sha256': 'x', 'size': SCAN_SIZE, 'exclude': None}, 'invalid_digest'),
                 ({'name': 'copy_scan', 'sha256': SCAN_DIGEST, 'size': True, 'exclude': None}, 'invalid_size'),
                 ({'name': 'copy_scan', 'sha256': SCAN_DIGEST, 'size': 1048577, 'exclude': None}, 'invalid_size'),
                 ({'name': 'copy_scan', 'sha256': SCAN_DIGEST, 'size': SCAN_SIZE, 'exclude': '/tmp/x'}, 'invalid_exclude'),
                 ({'name': 'copy_scan', 'sha256': SCAN_DIGEST, 'size': SCAN_SIZE, 'exclude': None, 'path': MARKER}, 'forbidden_field'),
                 ({'name': 'copy_scan', 'sha256': SCAN_DIGEST, 'size': SCAN_SIZE}, 'missing_field'),
                 ({'name': 'net_counters'}, 'invalid_name'), ({'name': 'measure'}, 'invalid_name'),
                 # an unknown name is judged with the base shape, where a path is surplus: that is the first thing refused
                 ({'name': 'File_state', 'path': MARKER}, 'forbidden_field'), ({'name': 'cgroup_events', 'path': MARKER}, 'forbidden_field'),
                 ({'name': 'file_state', 'path': MARKER, 'image': 'x'}, 'forbidden_field'))
        for patch, reason in cases:
            answer = await self.call({'op': 'level_probe', 'handle': handle, **patch})
            self.assertFalse(answer['ok'], patch)
            if reason is not None:
                self.assertEqual(answer['reason'], reason, patch)
            else:
                self.assertIn(answer['reason'], {'unexpected_field', 'forbidden_field'})
        self.assertEqual((self.runtime.calls['probe_level'], self.runtime.level_calls), (0, []))
        self.assertEqual(self.inventory.current.phase, 'ACTIVE')

    async def test_invalid_probe_output_is_never_forwarded_never_an_absence_and_ends_the_lease(self):
        bad_scan = {**SCAN_EMPTY, 'complete': True, 'reasons': ['byte_limit']}
        cases = []
        cases += [('file_state', {'path': MARKER}, result) for result in (
            {'status': 'present'}, {**FILE_PRESENT, 'inode': True}, {**FILE_PRESENT, 'size': 1048577}, {**FILE_PRESENT, 'extra': 1},
            {**FILE_PRESENT, 'sha256': 'A' * 64}, {'status': 'missing', 'inode': 1}, {'status': 'Missing'}, {'status': 'absent'},
            {'status': 'unavailable', 'counters': None}, {'status': 'missing', 'ok': True}, {'status': 'missing', 'op': 'level_probe'},
            {}, None, 'missing', ['missing'], 5, dict(SCAN_EMPTY), {'status': 'available', 'counters': {'oom_kill': 0}})]
        args = {'sha256': SCAN_DIGEST, 'size': SCAN_SIZE, 'exclude': None}
        cases += [('copy_scan', args, result) for result in (
            bad_scan, {**SCAN_EMPTY, 'complete': False}, {**SCAN_EMPTY, 'verifier_version': 'v1'}, {**SCAN_EMPTY, 'matches_total': 1},
            {**SCAN_OK, 'matches': [{**SCAN_OK['matches'][0], 'size': SCAN_SIZE + 1}]},
            {**SCAN_OK, 'matches': [{**SCAN_OK['matches'][0], 'path': '/etc/shadow'}]}, {**SCAN_EMPTY, 'extra': 1},
            {**SCAN_EMPTY, 'ok': True}, {**SCAN_EMPTY, 'entries': 129}, {**SCAN_EMPTY, 'reasons': ['made_up'], 'complete': False},
            {'verifier_version': 'persistence-copy/v2', 'complete': False, 'reasons': ['probe_timeout'], 'matches': [],
             'matches_total': 0, 'entries': 1, 'bytes_read': 0, 'skipped_nonregular': 0},
            {'status': 'missing'}, dict(FILE_PRESENT), {'status': 'available', 'counters': {'oom_kill': 0}}, {}, None, 'x', 5)]
        for name, arguments, result in cases:
            with self.subTest(name=name, result=str(result)[:60]):
                self.fresh()
                opened = await self.opened_a()
                self.runtime.level_result = result
                answer = await self.probe(opened['handle'], name, **arguments)
                self.assertEqual(answer, {'ok': False, 'reason': 'internal_error'})
                await self.broker.drain()
                self.assertEqual((self.runtime.removed, self.runtime.calls['probe_level']), ([CONTAINER], 1))

    async def test_runtime_failures_and_timeouts_of_a_persistence_probe_end_the_lease_without_replay(self):
        class Stopped(Exception):
            reason = 'sandbox_stopped'
        for name, arguments in (('file_state', {'path': MARKER}), ('copy_scan', {'sha256': SCAN_DIGEST, 'size': SCAN_SIZE, 'exclude': None})):
            for error, reason in ((Stopped(), 'sandbox_stopped'), (RuntimeError('boom'), 'internal_error')):
                with self.subTest(name=name, reason=reason):
                    self.fresh()
                    opened = await self.opened_a()
                    self.runtime.level_error = error
                    self.assertEqual(await self.probe(opened['handle'], name, **arguments), {'ok': False, 'reason': reason})
                    await self.broker.drain()
                    self.assertEqual((self.runtime.removed, self.runtime.calls['probe_level']), ([CONTAINER], 1))
            self.fresh()
            opened = await self.opened_a()
            self.runtime.level_gate = asyncio.Event()  # never set: the probe hangs
            self.runtime.close_gate = asyncio.Event()
            self.assertEqual(await self.probe(opened['handle'], name, **arguments), {'ok': False, 'reason': 'exec_timeout'})
            self.assertEqual((await self.probe(opened['handle'], name, **arguments))['reason'], 'closing')
            self.runtime.close_gate.set()
            await self.broker.drain()
            self.assertEqual((self.runtime.calls['probe_level'], self.runtime.removed), (1, [CONTAINER]))

    async def test_a_cancelled_probe_of_b_does_not_cancel_the_operation_nor_repeat_it(self):
        self.make(limits=fast_limits(probe=2.0))
        await self.closed_a()
        opened = await self.opened_b()
        self.runtime.level_gate = asyncio.Event()
        self.runtime.level_started = asyncio.Event()
        task = asyncio.ensure_future(self.probe(opened['handle'], 'copy_scan', sha256=SCAN_DIGEST, size=SCAN_SIZE, exclude=None))
        await self.runtime.level_started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.runtime.level_result = dict(SCAN_EMPTY)
        self.runtime.level_gate.set()
        await self.broker.drain()
        self.assertEqual((self.runtime.calls['probe_level'], self.inventory.current.phase), (1, 'ACTIVE'))  # finished, not replayed
        self.runtime.level_result = {'status': 'missing'}
        self.assertTrue((await self.probe(opened['handle'], 'file_state', path=MARKER))['ok'])
        self.assertEqual(self.runtime.calls['probe_level'], 2)

    async def test_a_cancelled_execute_of_a_does_not_cancel_the_operation(self):
        self.make(limits=fast_limits(execute=2.0))
        opened = await self.opened_a()
        self.runtime.execute_gate = asyncio.Event()
        self.runtime.execute_started = asyncio.Event()
        task = asyncio.ensure_future(self.call({'op': 'execute', 'handle': opened['handle'], 'command': 'sleep 1'}))
        await self.runtime.execute_started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.runtime.execute_gate.set()
        await self.broker.drain()
        self.assertEqual((self.runtime.calls['execute'], self.inventory.current.phase), (1, 'ACTIVE'))
        wire.validate_level_close(await self.close_handle(opened['handle']), receipt=self.level_identity(opened))


class PersistenceDiaryFidelityTests(PersistCase):
    """What the broker does with a diary that does not honour the v3 contract. The real diary cannot answer like this: its history
    validation rejects the state. These doubles pin that the broker never turns such an answer into a create or a confirmation."""

    @staticmethod
    def only_fresh(change):
        def tamper(intent):
            return dataclasses.replace(intent, predecessor=change(intent)) if intent.stage == 'fresh' else intent
        return tamper

    def tampered(self, tamper):
        class Tampered(PersistInventory):
            def begin_level(inventory, **kwargs):  # noqa: N805 (the inventory is this method's receiver)
                intent = super().begin_level(**kwargs)
                replaced = tamper(intent)
                if replaced is not intent:
                    inventory.current = intent = replaced
                return intent
        return Tampered(self.log)

    async def test_a_fresh_phase_without_a_faithful_predecessor_blocks_before_create(self):
        changes = {
            'no predecessor': lambda i: None, 'a dict': lambda i: dataclasses.asdict(i.predecessor), 'text': lambda i: 'predecessor',
            'other run': lambda i: dataclasses.replace(i.predecessor, run_id=RUN_B),
            'other context': lambda i: dataclasses.replace(i.predecessor, context_sha256=OTHER_CONTEXT),
            'other installation': lambda i: dataclasses.replace(i.predecessor, installation_id='9' * 32),
            'memory level': lambda i: dataclasses.replace(i.predecessor, level='memory'),
            'fresh stage': lambda i: dataclasses.replace(i.predecessor, stage='fresh'),
            'its own intent': lambda i: dataclasses.replace(i.predecessor, intent_id=i.intent_id),
            'malformed container': lambda i: dataclasses.replace(i.predecessor, container_id='x')}
        for name, change in changes.items():
            with self.subTest(change=name):
                self.use(self.tampered(self.only_fresh(change)))
                await self.closed_a()
                creates = self.runtime.calls['create']
                response = await self.opened_b()
                self.assertEqual(response, {'ok': False, 'reason': 'owner_blocked', 'cleanup_confirmed': False})
                self.assertEqual((self.runtime.calls['create'], self.runtime.calls['close']), (creates, creates))  # B was never created
                self.assertEqual(self.broker.status()['blocked'], 'state_unavailable')

    async def test_an_actor_phase_that_carries_a_predecessor_is_the_same_contradiction(self):
        def invent(intent):
            return dataclasses.replace(intent, predecessor=Predecessor(**A_IDENT_LEVEL)) if intent.stage == 'actor' else intent
        self.use(self.tampered(invent))
        await self.start()
        response = await self.phase('actor')
        self.assertEqual(response, {'ok': False, 'reason': 'owner_blocked', 'cleanup_confirmed': False})
        self.assertEqual((self.runtime.calls['create'], self.broker.status()['blocked']), (0, 'state_unavailable'))

    async def test_a_finish_without_a_predecessor_gives_no_close_receipt_but_the_restitution_is_real(self):
        class StrippedFinish(PersistInventory):
            def finish(self, intent_id, *, container_id):
                finished = super().finish(intent_id, container_id=container_id)
                return dataclasses.replace(finished, predecessor=None) if finished.stage == 'fresh' else finished
        self.use(StrippedFinish(self.log))
        a = await self.closed_a()
        opened = await self.opened_b()
        self.assertTrue(opened['ok'], opened)
        refusal = {'ok': False, 'reason': 'cleanup_unconfirmed', 'cleanup_confirmed': False}
        self.assertEqual(await self.close_handle(opened['handle']), refusal)  # a fresh receipt without its predecessor is never given
        self.assertEqual(await self.close_handle(opened['handle']), refusal)  # and the recorded answer stays the same
        self.assertEqual((self.runtime.removed, self.inventory.current), ([CONTAINER, B_CONTAINER], None))  # the container is gone
        self.assertEqual(self.runtime.calls['close'], 2)
        answer = await self.call({'op': 'level_receipt', **self.level_identity(opened)})  # the durable FINISH, with its predecessor, still is
        self.assertEqual((answer['status'], answer['predecessor']), ('confirmed', a))


class PersistenceRecoveryAndCancellationTests(PersistCase):
    def pending_fresh(self, phase, container=B_CONTAINER):
        return PersistIntent('b' * 32, 'escape-actor-' + 'b' * 32, CLIENT_UID, RUN_A, 'persistence', 'fresh', CONTEXT, container, phase,
                             DIGEST, Predecessor(**A_IDENT_LEVEL))

    async def test_every_phase_of_a_fresh_intent_is_restituted_by_id_and_recovery_never_creates(self):
        for allowed in (('persistence',), ()):
            for phase in ('CREATE_ACK', 'START_PENDING', 'ACTIVE', 'CLOSE_PENDING'):
                with self.subTest(phase=phase, allowed=allowed):
                    self.fresh(allowed_levels=allowed)
                    self.inventory.current = self.pending_fresh(phase)
                    self.runtime.containers.add(B_CONTAINER)
                    await self.start()
                    self.assertEqual((self.runtime.removed, self.log), ([B_CONTAINER], ORDER_OF_CLOSE))
                    self.assertEqual(self.runtime.foreign, {FOREIGN})
                    for name in ('create', 'start', 'execute', 'probe', 'probe_level'):
                        self.assertEqual(self.runtime.calls[name], 0)
                    self.assertTrue(self.broker.status()['recovered'])

    async def test_a_pending_fresh_intent_without_an_id_blocks_and_nothing_is_created(self):
        self.inventory.current = self.pending_fresh('CREATE_PENDING', container=None)
        await self.start()
        self.assertEqual((self.broker.status()['blocked'], self.broker.status()['obligations']), ('create_uncertain', 1))
        self.assertEqual((self.runtime.calls['close'], self.runtime.calls['create']), (0, 0))
        self.assertEqual((await self.phase('fresh', RUN_B))['reason'], 'owner_blocked')
        await self.broker.reconcile()
        self.assertEqual(self.broker.status()['blocked'], 'create_uncertain')

    async def test_recovery_after_the_finish_of_a_never_creates_b(self):
        await self.closed_a()
        self.make()  # restart
        calls = dict(self.runtime.calls)
        await self.start()
        self.assertEqual(dict(self.runtime.calls), calls)  # nothing created, started or executed by the recovery
        self.assertEqual((self.inventory.current, self.broker.status()['obligations']), (None, 0))
        self.assertTrue((await self.opened_b())['ok'])  # B opens only because it was asked, and with the diary's predecessor

    async def test_a_restart_with_b_active_restitutes_b_by_id_and_a_keeps_its_closure(self):
        a = await self.closed_a()
        opened = await self.opened_b()
        self.make()  # a new process over the same diary and runtime
        self.log.clear()
        await self.start()
        self.assertEqual((self.log, self.runtime.removed), (ORDER_OF_CLOSE, [CONTAINER, B_CONTAINER]))
        self.assertEqual((self.runtime.calls['create'], self.runtime.calls['start']), (2, 2))
        self.assertEqual((await self.close_handle(opened['handle']))['reason'], 'unknown_handle')  # a restart invalidates handles
        answer_a = await self.call({'op': 'level_receipt', **a})
        answer_b = await self.call({'op': 'level_receipt', **self.level_identity(opened)})
        self.assertEqual((answer_a['status'], answer_b['status'], answer_b['predecessor']), ('confirmed', 'confirmed', a))
        self.assertEqual((await self.phase('fresh'))['reason'], 'already_active')  # the interrupted B is spent, not retried

    async def test_cancelled_open_of_a_after_the_intent_is_durable_leaves_the_handle_to_the_reaper_and_b_waits_for_the_finish(self):
        self.make(limits=fast_limits(create=2.0))
        await self.start()
        self.runtime.create_gate = asyncio.Event()
        task = asyncio.ensure_future(self.phase('actor'))
        await self.wait_calls('create', 1)
        self.assertEqual(self.inventory.current.phase, 'CREATE_PENDING')  # durable before create
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.runtime.create_gate.set()
        await self.broker.drain()
        self.assertEqual(self.inventory.current.phase, 'ACTIVE')
        self.assertEqual((await self.opened_b())['reason'], 'capacity_exhausted')  # A still holds the plaza and has no FINISH
        self.clock.now += 121
        await self.broker.reconcile()
        self.assertEqual(self.runtime.removed, [CONTAINER])
        self.assertEqual((await self.phase('actor'))['reason'], 'already_active')  # the cancelled run is spent, not retried
        b = await self.opened_b()
        self.assertTrue(b['ok'], b)
        self.assertEqual(b['predecessor']['container_id'], CONTAINER)

    async def test_cancelled_open_of_b_after_the_intent_is_durable_leaves_the_handle_to_the_reaper_and_a_keeps_its_receipt(self):
        self.make(limits=fast_limits(create=2.0))
        a = await self.closed_a()
        self.runtime.create_id = B_CONTAINER
        self.runtime.create_gate = asyncio.Event()
        task = asyncio.ensure_future(self.phase('fresh'))
        await self.wait_calls('create', 2)
        self.assertEqual((self.inventory.current.phase, self.inventory.current.stage), ('CREATE_PENDING', 'fresh'))
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.runtime.create_gate.set()
        await self.broker.drain()
        self.assertEqual(self.inventory.current.phase, 'ACTIVE')  # the open completed; its response was dropped
        self.clock.now += 121
        await self.broker.reconcile()
        self.assertEqual((self.runtime.removed, self.broker.status()['obligations']), ([CONTAINER, B_CONTAINER], 0))
        self.assertEqual((await self.phase('fresh'))['reason'], 'already_active')
        answer = await self.call({'op': 'level_receipt', **B_IDENT_LEVEL, 'intent_id': self.inventory.history[-1].intent_id})
        self.assertEqual((answer['status'], answer['predecessor']), ('confirmed', a))
        self.assertEqual((await self.call({'op': 'level_receipt', **a}))['status'], 'confirmed')  # and B did not replace A's closure

    async def test_a_cancelled_close_of_b_does_not_cancel_the_restitution(self):
        self.make(limits=fast_limits(close=2.0))
        a = await self.closed_a()
        opened = await self.opened_b()
        b = self.level_identity(opened)
        self.runtime.close_gate = asyncio.Event()
        task = asyncio.ensure_future(self.close_handle(opened['handle']))
        await self.wait_calls('close', 2)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.runtime.close_gate.set()
        await self.broker.drain()
        self.assertEqual((self.inventory.current, self.runtime.removed), (None, [CONTAINER, B_CONTAINER]))
        again = await self.close_handle(opened['handle'])
        self.assertEqual(wire.validate_level_close(again, receipt=b, predecessor=a)['predecessor'], a)
        self.assertEqual(self.runtime.calls['close'], 2)  # the recorded receipt, not a second restitution

    async def test_an_expired_b_is_restituted_by_the_reaper_and_keeps_its_plaza_until_then(self):
        await self.closed_a()
        opened = await self.opened_b()
        self.clock.now += 121
        self.assertEqual((await self.probe(opened['handle'], 'file_state', path=MARKER))['reason'], 'expired')
        self.assertEqual((await self.phase('actor', RUN_B))['reason'], 'capacity_exhausted')
        await self.broker.reconcile()
        self.assertEqual((self.runtime.removed, self.broker.leases.held()), ([CONTAINER, B_CONTAINER], 0))
        self.assertTrue((await self.phase('actor', RUN_B))['ok'])

    async def test_a_transport_error_while_answering_b_leaves_its_lease_with_the_owner(self):
        await self.closed_a()
        self.runtime.create_id = B_CONTAINER
        reader, writer = FakeReader(frame({'op': 'open_level', 'run_id': RUN_A, 'level': 'persistence', 'stage': 'fresh',
                                           'context_sha256': CONTEXT})), FakeWriter(CLIENT_UID, fail_drain=True)
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            await self.broker._connection(reader, writer)
        self.assertTrue(writer.closed)
        self.assertEqual((self.broker.leases.held(), self.inventory.current.phase, self.inventory.current.stage), (1, 'ACTIVE', 'fresh'))
        self.clock.now += 121
        await self.broker.reconcile()  # the reaper restitutes the lost handle by ID
        self.assertEqual((self.runtime.removed, self.broker.status()['obligations']), ([CONTAINER, B_CONTAINER], 0))


# ------------------------------------------------------------------------------------------------------- M3.1 · catalog
# Doubles of the M3.0 adapters (SC2-CATALOGO-ADAPTADORES-LOCAL): begin_catalog / receipt_catalog on the inventory, a SYNCHRONOUS
# catalog_status and an async catalog_check on the runtime, and a CatalogIntent that carries the owner's private resource_id. They
# extend the M1 doubles above without changing them. They stand for the adapter contract only: no double here mounts anything, and no
# test of this section claims a Docker mount. Authored without a shell: none of these tests has been executed by the author.

from services.agent import invoice_actor_protocol as proto  # noqa: E402

C_ID = 'invoice-unit-cents/v1'
C_SHA = 'd055653221c49c92490e536dc665349746988bb14749c60757e7a770fc20e79e'
CATALOG_VIEW = {'id': C_ID, 'sha256': C_SHA, 'size': 47, 'destination': '/catalog.json'}
PRIVATE_RESOURCE = 'f' * 32
CAT_MARKER = '/work/marker-' + 'a' * 24
ORDER_OF_OPEN_CATALOG = ['inv:begin_catalog'] + ORDER_OF_OPEN[1:]
PROBE_B = {'ran': True, 'state': 'present', 'read': 'ok', 'write_open': 'rejected', 'write_errno': 'EROFS', 'sha256': C_SHA, 'size': 47}
PROBE_A = {'ran': True, 'state': 'absent', 'read': None, 'write_open': None, 'write_errno': None, 'sha256': None, 'size': None}
HOST_OK = {'ok': True, 'changed': False, 'reason': None, 'sha256': C_SHA}
HOST_UNREADABLE = {'ok': False, 'changed': None, 'reason': 'unreadable', 'sha256': None}
CATALOG_INFO_BODY = {'op': 'catalog_info'}


def catalog_view(**patch):
    return {'probe': dict(PROBE_B), 'host_check': dict(HOST_OK), 'check_index': 1, **patch}


@dataclasses.dataclass(frozen=True)
class CatalogIntent:  # the fields of actor_state.CatalogIntent, resource_id (private to the owner) included
    intent_id: str
    name: str
    controller_uid: int
    run_id: str
    variant: str
    catalog_profile: str
    context_sha256: str
    catalog_id: str
    catalog_sha256: str
    container_id: object
    phase: str
    profile_sha256: str
    resource_id: str


def pending_catalog(phase='ACTIVE', container=CONTAINER, profile='B', run=RUN_A, variant='legitimate', intent_id='a' * 32):
    return CatalogIntent(intent_id, 'escape-actor-' + intent_id, CLIENT_UID, run, variant, profile, CONTEXT, C_ID, C_SHA, container, phase,
                         DIGEST, PRIVATE_RESOURCE)


class CatalogInventory(FakeInventory):
    def __init__(self, log):
        super().__init__(log)
        self.contexts = {}                 # one context per (domain, uid, run), as the real diary keeps it
        self.resource_ready = True         # False: the diary refuses with StateError catalog_unavailable
        self.begin_calls = []
        self.begin_override = None         # callable(intent) -> what begin_catalog answers instead (diary malfunction)
        self.catalog_queries = []          # receipt_catalog() calls: a read, it never touches `log`, `count`, `current` or `history`
        self.catalog_receipt_error = None
        self.catalog_receipt_returns = None

    def receipt(self, **kwargs):
        # The M1 query over a mixed diary: catalog entries are never an M1 answer (the real keys differ).
        history, self.history = self.history, [item for item in self.history if not isinstance(item, CatalogIntent)]
        try:
            return super().receipt(**kwargs)
        finally:
            self.history = history

    def begin_catalog(self, *, controller_uid, run_id, variant, catalog_profile, context_sha256, catalog_id, catalog_sha256):
        self.begin_calls.append(dict(controller_uid=controller_uid, run_id=run_id, variant=variant, catalog_profile=catalog_profile,
                                     context_sha256=context_sha256, catalog_id=catalog_id, catalog_sha256=catalog_sha256))
        self._gate('begin_catalog')
        if self.current is not None:
            raise StateError('actor_busy')
        if not self.resource_ready:
            raise StateError('catalog_unavailable')
        key = ('catalog', controller_uid, run_id, variant)
        if key in self.used:
            raise StateError('already_started')  # also after FINISH, whatever the profile: the key is permanent
        if any(other[:3] == key[:3] and context != context_sha256 for other, context in self.contexts.items()):
            raise StateError('invalid_transition')
        self.used.add(key)
        self.contexts[key] = context_sha256
        self.count += 1
        intent_id = '%032x' % (0xa0 + self.count)
        self.current = CatalogIntent(intent_id, 'escape-actor-' + intent_id, controller_uid, run_id, variant, catalog_profile,
                                     context_sha256, catalog_id, catalog_sha256, None, 'CREATE_PENDING', DIGEST, PRIVATE_RESOURCE)
        return self.begin_override(self.current) if self.begin_override is not None else self.current

    def receipt_catalog(self, *, controller_uid, run_id, variant, catalog_profile, context_sha256, catalog_id, catalog_sha256,
                        intent_id, container_id):
        asked = (controller_uid, run_id, variant, catalog_profile, context_sha256, catalog_id, catalog_sha256, intent_id, container_id)
        self.catalog_queries.append(asked)
        if self.catalog_receipt_error is not None:
            raise StateError(self.catalog_receipt_error)
        if self.catalog_receipt_returns is not None:
            return self.catalog_receipt_returns
        if controller_uid != CLIENT_UID:
            raise StateError('identity_changed')
        for item in self.history:
            if isinstance(item, CatalogIntent) and (item.controller_uid, item.run_id, item.variant, item.catalog_profile,
                                                    item.context_sha256, item.catalog_id, item.catalog_sha256, item.intent_id,
                                                    item.container_id) == asked:
                return item
        return None


class CatalogRuntime(FakeRuntime):
    def __init__(self, log, inventory):
        super().__init__(log, inventory)
        self.view = {'ready': True, 'identity': dict(CATALOG_VIEW)}
        self.status_error = None
        self.status_calls = 0
        self.index = 0
        self.scripted = collections.deque()  # what the next checks answer: a dict is returned, an exception is raised
        self.checked = []                    # the intents the runtime received, and nothing else
        self.check_gate = None
        self.check_started = None

    def catalog_status(self):  # SYNCHRONOUS in the received runtime
        self.status_calls += 1
        if self.status_error is not None:
            raise self.status_error
        return self.view

    async def catalog_check(self, intent):
        self.calls['catalog_check'] += 1
        self.checked.append(intent)
        self.log.append('rt:catalog_check')
        if self.check_started is not None:
            self.check_started.set()
        if self.check_gate is not None:
            await self.check_gate.wait()
        if self.scripted:
            item = self.scripted.popleft()
            if isinstance(item, BaseException):
                raise item
            return item
        self.index += 1
        return {'probe': dict(PROBE_B if intent.catalog_profile == 'B' else PROBE_A), 'host_check': dict(HOST_OK),
                'check_index': self.index}


class OnlyStatus:
    """Replaces the runtime: only catalog_status exists; any other attribute is recorded and fails the query."""

    def __init__(self, runtime):
        self._runtime, self.touched = runtime, []

    def catalog_status(self):
        return self._runtime.catalog_status()

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        self.touched.append(name)
        raise AssertionError('catalog_info reached the runtime: ' + name)


class CatalogCase(BrokerCase):
    async def asyncSetUp(self):
        self.log = []
        self.inventory = CatalogInventory(self.log)
        self.runtime = CatalogRuntime(self.log, self.inventory)
        self.clock = Clock()
        self.make()

    def make(self, **overrides):
        overrides.setdefault('allowed_catalog', True)  # what Sol's bootstrap will enable in this lot
        return super().make(**overrides)

    def fresh(self, **overrides):
        self.log.clear()
        self.inventory = CatalogInventory(self.log)
        self.runtime = CatalogRuntime(self.log, self.inventory)
        self.make(**overrides)

    def body(self, run=RUN_A, variant='legitimate', profile='B', context=CONTEXT, **patch):
        return {'op': 'open_catalog', 'run_id': run, 'variant': variant, 'catalog_profile': profile, 'context_sha256': context,
                'catalog_id': C_ID, 'catalog_sha256': C_SHA, **patch}

    async def open_catalog(self, run=RUN_A, variant='legitimate', profile='B', context=CONTEXT):
        return await self.call(CatalogCase.body(self, run, variant, profile, context))  # explicit: a subclass may shape `body` otherwise

    async def opened_catalog(self, run=RUN_A, variant='legitimate', profile='B', context=CONTEXT):
        await self.start()
        response = await self.open_catalog(run, variant, profile, context)
        self.assertTrue(response['ok'], response)
        return response

    async def check(self, handle):
        return await self.call({'op': 'catalog_check', 'handle': handle})

    async def close_handle(self, handle):
        return await self.call({'op': 'close', 'handle': handle})

    def cat_identity(self, response):
        return {key: response[key] for key in wire.CATALOG_IDENTITY_FIELDS}

    def open_args(self, profile='B', run=RUN_A, variant='legitimate', context=CONTEXT):
        return dict(run_id=run, variant=variant, catalog_profile=profile, context_sha256=context, installation_id=INSTALL, image_id=IMAGE)

    def snapshot(self):
        return (list(self.log), dict(self.runtime.calls), self.inventory.count, self.inventory.current, len(self.inventory.history),
                tuple(sorted(self.runtime.containers)), list(self.runtime.removed), self.broker.status(), self.broker.leases.held())


class CatalogPolicyTests(CatalogCase):
    async def test_the_policy_is_false_by_default_and_legacy_doubles_need_no_catalog_methods(self):
        inventory = FakeInventory(self.log)  # an M1 inventory and runtime: no begin_catalog, catalog_status or catalog_check
        runtime = FakeRuntime(self.log, inventory)
        for options in ({}, {'allowed_catalog': False}):
            broker = ActorBroker(runtime=runtime, inventory=inventory, client_uid=CLIENT_UID, image_id=IMAGE, clock=self.clock,
                                 limits=fast_limits(), **options)
            self.assertIs(broker.allowed_catalog, False)
            for body in (CATALOG_INFO_BODY, self.body(), {'op': 'catalog_check', 'handle': 'ab' * 32}):
                response = await broker.handle(CLIENT_UID, enc(body))
                self.assertEqual(json.loads(response), {'ok': False, 'reason': 'catalog_not_allowed'}, body['op'])
        self.assertEqual(self.log, [])
        self.assertEqual(broker_module._INVENTORY_METHODS, ('pending', 'begin', 'ack', 'starting', 'activate', 'closing', 'finish'))
        await broker.reconcile()  # and the M1 flow of the same owner is untouched
        opened = json.loads(await broker.handle(CLIENT_UID, enc({'op': 'open', 'run_id': RUN_A, 'variant': 'legitimate'})))
        self.assertTrue(opened['ok'], opened)
        self.assertEqual(self.log, ORDER_OF_OPEN)

    async def test_the_policy_is_exactly_a_bool_and_is_read_only(self):
        for bad in (1, 0, 2, 'true', 'yes', '', None, [True], {'a': 1}, (True,), 1.0):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(allowed_catalog=bad)
        self.make(allowed_catalog=True)
        self.assertIs(self.broker.allowed_catalog, True)
        with self.assertRaises(AttributeError):
            self.broker.allowed_catalog = False
        self.make(allowed_catalog=False)
        self.assertIs(self.broker.allowed_catalog, False)
        self.assertEqual(self.broker.allowed_levels, frozenset())  # the level policy is independent

    async def test_enabling_the_policy_requires_the_catalog_interfaces(self):
        legacy = FakeInventory(self.log)
        with self.assertRaises(ValueError):  # no begin_catalog, no catalog_status, no catalog_check
            self.make(inventory=legacy, runtime=FakeRuntime(self.log, legacy), allowed_catalog=True)
        with self.assertRaises(ValueError):  # the runtime has no catalog_status/catalog_check
            self.make(runtime=FakeRuntime(self.log, self.inventory))

        class NoBegin(FakeInventory):
            pass
        plain = NoBegin(self.log)
        with self.assertRaises(ValueError):  # the inventory has no begin_catalog
            self.make(inventory=plain, runtime=CatalogRuntime(self.log, plain))

        class SyncCheck(CatalogRuntime):
            def catalog_check(self, intent):  # received: catalog_check IS awaitable
                return catalog_view()
        with self.assertRaises(ValueError):
            self.make(runtime=SyncCheck(self.log, self.inventory))

        class AsyncStatus(CatalogRuntime):
            async def catalog_status(self):  # received: catalog_status is NOT awaitable
                return self.view
        with self.assertRaises(ValueError):
            self.make(runtime=AsyncStatus(self.log, self.inventory))

        class NoCatalogReceipt(CatalogInventory):
            receipt_catalog = None
        inventory = NoCatalogReceipt(self.log)
        self.make(inventory=inventory, runtime=CatalogRuntime(self.log, inventory))  # constructs: it can never confirm, only refuse
        self.assertIs(self.broker.allowed_catalog, True)

    async def test_a_request_can_neither_carry_nor_change_the_policy(self):
        await self.start()
        for field, value in (('allowed_catalog', True), ('allowed', True), ('catalog', True), ('policy', 'all'), ('enabled', True)):
            for body in (CATALOG_INFO_BODY, self.body()):
                response = await self.call({**body, field: value})
                self.assertEqual(response, {'ok': False, 'reason': 'unexpected_field'}, (body['op'], field))
        self.assertEqual((self.log, self.runtime.status_calls), ([], 0))
        self.make(allowed_catalog=False)
        await self.start()
        self.assertEqual(await self.call({**self.body(), 'allowed_catalog': True}), {'ok': False, 'reason': 'unexpected_field'})
        self.assertEqual(await self.call(self.body()), {'ok': False, 'reason': 'catalog_not_allowed'})  # the policy did not move

    async def test_the_policy_is_decided_before_the_state_of_the_owner(self):
        self.make()  # not reconciled
        self.assertEqual((await self.open_catalog())['reason'], 'owner_not_ready')
        self.make(allowed_catalog=False)
        self.assertEqual((await self.open_catalog())['reason'], 'catalog_not_allowed')
        self.assertEqual(await self.call({'op': 'catalog_check', 'handle': 'ab' * 32}), {'ok': False, 'reason': 'catalog_not_allowed'})
        self.assertEqual(self.log, [])
        self.make()
        self.assertEqual(await self.call({'op': 'catalog_check', 'handle': 'ab' * 32}), {'ok': False, 'reason': 'unknown_handle'})


class CatalogInfoTests(CatalogCase):
    async def test_info_answers_the_fixed_public_view_and_changes_nothing(self):
        before = self.snapshot()  # no reconciliation yet: the read does not need the owner to be recovered
        response = await self.call(CATALOG_INFO_BODY)
        self.assertEqual(self.snapshot(), before)
        view = wire.validate_catalog_info(response, installation_id=INSTALL)
        self.assertEqual(view, {'installation_id': INSTALL, 'ready': True, 'identity': CATALOG_VIEW})
        self.assertEqual(set(response), {'ok', 'op', 'installation_id', 'ready', 'identity'})
        self.assertEqual(self.runtime.status_calls, 1)
        self.assertEqual(await self.call(CATALOG_INFO_BODY), response)  # a read: repeating it gives the same answer

    async def test_info_never_prepares_repairs_mounts_or_retires_and_it_is_not_health(self):
        only = OnlyStatus(self.runtime)
        self.broker.runtime = only
        for _ in range(3):
            self.assertTrue((await self.call(CATALOG_INFO_BODY))['ok'])
        self.assertEqual(only.touched, [])
        self.assertEqual(self.log, [])
        self.broker.runtime = self.runtime  # health asks the runtime whether it is ready; the info read above never did
        health = await self.call({'op': 'health'})
        self.assertEqual(set(health), {'ok', 'op', 'ready', 'image_id', 'installation_id', 'obligations', 'blocked'})  # health: unchanged

    async def test_not_ready_and_unregistered_are_answers_not_errors(self):
        self.runtime.view = {'ready': False, 'identity': dict(CATALOG_VIEW)}  # retired: identity kept, not ready
        response = await self.call(CATALOG_INFO_BODY)
        self.assertEqual((response['ready'], response['identity']), (False, CATALOG_VIEW))
        wire.validate_catalog_info(response)
        self.runtime.view = {'ready': False, 'identity': None}
        response = await self.call(CATALOG_INFO_BODY)
        self.assertEqual((response['ready'], response['identity']), (False, None))
        wire.validate_catalog_info(response)

    async def test_it_answers_in_every_owner_state(self):
        await self.start()
        self.broker._block('unrecognized_object')
        self.assertTrue((await self.call(CATALOG_INFO_BODY))['ok'])
        self.broker._shutdown = True
        self.assertTrue((await self.call(CATALOG_INFO_BODY))['ok'])

    async def test_a_runtime_view_that_is_not_exactly_the_contract_is_never_forwarded(self):
        async def coroutine():
            return None
        pending = coroutine()
        bad = [{'ready': True, 'identity': None}, {'ready': 1, 'identity': dict(CATALOG_VIEW)},
               {'ready': None, 'identity': dict(CATALOG_VIEW)}, {'ready': 'true', 'identity': dict(CATALOG_VIEW)},
               {'ready': True, 'identity': {**CATALOG_VIEW, 'size': True}}, {'ready': True, 'identity': {**CATALOG_VIEW, 'size': 47.0}},
               {'ready': True, 'identity': {**CATALOG_VIEW, 'size': 48}}, {'ready': True, 'identity': {**CATALOG_VIEW, 'sha256': 'e' * 64}},
               {'ready': True, 'identity': {**CATALOG_VIEW, 'id': 'other/v1'}},
               {'ready': True, 'identity': {**CATALOG_VIEW, 'destination': '/tmp/x'}},
               {'ready': True, 'identity': {**CATALOG_VIEW, 'path': '/var/lib/owner/catalog.json'}},
               {'ready': True, 'identity': {key: value for key, value in CATALOG_VIEW.items() if key != 'size'}},
               {'ready': True, 'identity': dict(CATALOG_VIEW), 'registration': '/var/lib/owner'},
               {'ready': True, 'identity': dict(CATALOG_VIEW), 'resource_id': PRIVATE_RESOURCE},
               {'identity': dict(CATALOG_VIEW)}, {'ready': True}, {}, 'x', None, [], 5, pending]
        for view in bad:
            self.runtime.view = view
            response = await self.exchange_info()
            self.assertEqual(response, {'ok': False, 'reason': 'internal_error'}, str(view)[:60])
        pending.close()
        self.runtime.view = {'ready': True, 'identity': dict(CATALOG_VIEW)}
        self.runtime.status_error = RuntimeError('boom ' + PRIVATE_RESOURCE)
        self.assertEqual(await self.exchange_info(), {'ok': False, 'reason': 'internal_error'})
        self.assertIsNone(self.broker.status()['blocked'])  # a failed read never blocks the owner

    async def exchange_info(self):
        before = self.snapshot()
        response = await self.call(CATALOG_INFO_BODY)
        self.assertEqual(self.snapshot(), before)
        return response

    async def test_dispatch_through_an_authenticated_connection(self):
        reader, writer = FakeReader(frame(CATALOG_INFO_BODY)), FakeWriter(CLIENT_UID)
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            await self.broker._connection(reader, writer)
        self.assertTrue(wire.validate_catalog_info(writer.response(), installation_id=INSTALL)['ready'])
        self.assertLessEqual(len(bytes(writer.data)) - 4, wire.RESPONSE_LIMITS['catalog_info'])
        reader, writer = FakeReader(frame(CATALOG_INFO_BODY)), FakeWriter(CLIENT_UID + 1)  # another UID: closed, never answered
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            await self.broker._connection(reader, writer)
        self.assertEqual((reader.reads, bytes(writer.data), writer.closed), (0, b'', True))
        calls = self.runtime.status_calls
        reader, writer = FakeReader(frame(CATALOG_INFO_BODY) + b'x'), FakeWriter(CLIENT_UID)
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            await self.broker._connection(reader, writer)
        self.assertEqual(writer.response(), {'ok': False, 'reason': 'framing'})  # trailing bytes: not dispatched
        self.assertEqual(self.runtime.status_calls, calls)
        self.assertIsNone(await self.broker.handle(CLIENT_UID + 1, enc(CATALOG_INFO_BODY)))


class CatalogOpenTests(CatalogCase):
    async def test_a_and_b_follow_the_contract_order_and_answer_the_nine_fields(self):
        for profile in ('A', 'B'):
            with self.subTest(profile=profile):
                self.fresh()
                await self.start()
                response = await self.open_catalog(profile=profile)
                self.assertEqual(self.log, ORDER_OF_OPEN_CATALOG)
                self.assertTrue(response['ok'], response)
                wire.validate_catalog_open(response, **self.open_args(profile))
                self.assertEqual(self.inventory.current.phase, 'ACTIVE')
                self.assertEqual(self.inventory.begin_calls, [dict(controller_uid=CLIENT_UID, run_id=RUN_A, variant='legitimate',
                                                                   catalog_profile=profile, context_sha256=CONTEXT, catalog_id=C_ID,
                                                                   catalog_sha256=C_SHA)])
                self.assertEqual(set(response), {'ok', 'op', 'handle', 'name', 'profile_sha256', 'profile', *wire.CATALOG_IDENTITY_FIELDS})
                self.assertEqual((response['catalog_profile'], response['container_id'], response['profile_sha256']),
                                 (profile, CONTAINER, DIGEST))
                self.assertNotIn('resource', json.dumps(response))  # the private reference has no wire name
                self.assertNotIn(PRIVATE_RESOURCE, json.dumps(response))

    async def test_nothing_the_client_sends_chooses_the_resource_the_uid_or_the_catalog(self):
        await self.start()
        for extra in ('resource_id', 'controller_uid', 'uid', 'owner_uid', 'catalog_path', 'catalog_file', 'path', 'source', 'mount',
                      'bind', 'image', 'flags', 'script', 'command'):
            response = await self.call({**self.body(), extra: 'x'})
            self.assertIn(response['reason'], {'unexpected_field', 'forbidden_field'}, extra)
        for patch, reason in (({'catalog_id': 'other/v1'}, 'invalid_catalog_id'), ({'catalog_sha256': 'e' * 64}, 'invalid_catalog_digest'),
                              ({'catalog_profile': 'C'}, 'invalid_catalog_profile'), ({'catalog_profile': None}, 'invalid_catalog_profile'),
                              ({'context_sha256': 'x'}, 'invalid_context'), ({'variant': 'actor'}, 'invalid_variant'),
                              ({'run_id': 'x'}, 'invalid_run_id')):
            self.assertEqual(await self.call(self.body(**patch)), {'ok': False, 'reason': reason}, patch)
        self.assertEqual((self.log, self.inventory.begin_calls, self.broker.leases.held(), self.runtime.status_calls), ([], [], 0, 0))

    async def test_the_uid_given_to_the_diary_is_the_authenticated_peers(self):
        await self.start()
        self.assertTrue((await self.open_catalog())['ok'])
        self.assertEqual({call['controller_uid'] for call in self.inventory.begin_calls}, {CLIENT_UID})
        self.assertIsNone(await self.broker.handle(CLIENT_UID + 1, enc(self.body(run=RUN_B))))
        self.assertEqual(len(self.inventory.begin_calls), 1)

    async def test_a_resource_that_is_not_ready_is_refused_before_the_diary_or_create(self):
        await self.start()
        for view in ({'ready': False, 'identity': dict(CATALOG_VIEW)}, {'ready': False, 'identity': None},
                     {'ready': True, 'identity': None}, 'contradiction'):
            self.runtime.view = view
            response = await self.open_catalog()
            self.assertEqual(response, {'ok': False, 'reason': 'catalog_unavailable'}, str(view))
            self.assertEqual((self.log, self.broker.leases.held(), self.broker.status()['blocked']), ([], 0, None))
        self.assertEqual(self.runtime.calls['create'], 0)
        self.runtime.view = {'ready': True, 'identity': dict(CATALOG_VIEW)}
        self.assertTrue((await self.open_catalog())['ok'])  # no obligation, no key and no plaza was spent by the refusals

    async def test_the_diary_refusals_before_an_obligation_exists_are_clean_and_do_not_block(self):
        await self.start()
        self.inventory.resource_ready = False  # the diary's own StateError catalog_unavailable
        response = await self.open_catalog()
        self.assertEqual(response, {'ok': False, 'reason': 'catalog_unavailable'})
        self.assertEqual(self.log, ['inv:begin_catalog'])
        self.assertEqual((self.runtime.calls['create'], self.broker.leases.held(), self.broker.status()['blocked'],
                          self.broker.status()['obligations']), (0, 0, None, 0))
        self.inventory.resource_ready = True
        self.inventory.fail['begin_catalog'] = 'catalog_resource_exists'
        self.assertEqual(await self.open_catalog(), {'ok': False, 'reason': 'catalog_unavailable'})
        self.assertIsNone(self.broker.status()['blocked'])
        del self.inventory.fail['begin_catalog']
        self.assertTrue((await self.open_catalog())['ok'])  # the key was never spent

    async def test_an_unknown_diary_failure_blocks_and_nothing_is_created(self):
        await self.start()
        self.inventory.fail['begin_catalog'] = 'state_unavailable'
        response = await self.open_catalog()
        self.assertEqual((response['ok'], response['reason']), (False, 'owner_blocked'))
        self.assertEqual((self.runtime.calls['create'], self.broker.leases.held()), (0, 0))
        self.assertEqual((await self.open_catalog(run=RUN_B))['reason'], 'owner_blocked')
        self.assertEqual((await self.call({'op': 'health'}))['blocked'], True)

    async def test_replay_context_and_domains_follow_the_diary_keys(self):
        first = await self.opened_catalog(RUN_A, 'legitimate', 'A')
        self.assertEqual((await self.open_catalog(RUN_B))['reason'], 'capacity_exhausted')  # one plaza, shared
        self.assertEqual((await self.call({'op': 'open', 'run_id': RUN_B, 'variant': 'legitimate'}))['reason'], 'capacity_exhausted')
        self.assertEqual((await self.open_catalog(RUN_A, 'legitimate', 'A'))['reason'], 'already_active')  # a live lease
        self.assertTrue((await self.close_handle(first['handle']))['ok'])
        self.log.clear()
        for profile, context in (('A', CONTEXT), ('B', CONTEXT), ('B', OTHER_CONTEXT)):  # the key has no profile and no context
            self.assertEqual((await self.open_catalog(RUN_A, 'legitimate', profile, context))['reason'], 'already_active', profile)
        self.assertEqual(self.log, ['inv:begin_catalog'] * 3)
        self.assertEqual(self.runtime.calls['create'], 1)
        self.assertEqual((await self.open_catalog(RUN_A, 'perturbed', 'B', OTHER_CONTEXT))['reason'], 'context_mismatch')
        self.assertEqual(self.broker.leases.held(), 0)
        self.assertIsNone(self.broker.status()['blocked'])
        second = await self.open_catalog(RUN_B, 'perturbed', 'B', OTHER_CONTEXT)  # another run: its own context
        self.assertTrue(second['ok'], second)
        self.assertTrue((await self.close_handle(second['handle']))['ok'])
        workflow = await self.call({'op': 'open', 'run_id': RUN_A, 'variant': 'legitimate'})  # the same run and variant, another domain
        self.assertTrue(workflow['ok'], workflow)
        self.assertNotIn('catalog_profile', workflow)

    async def test_a_diary_that_answers_something_else_blocks_and_nothing_is_created(self):
        base = Intent('b' * 32, 'escape-actor-' + 'b' * 32, CLIENT_UID, RUN_A, 'legitimate', None, 'CREATE_PENDING', DIGEST)
        patches = ({'catalog_profile': 'A'}, {'context_sha256': OTHER_CONTEXT}, {'catalog_id': 'other/v1'}, {'catalog_sha256': 'e' * 64},
                   {'run_id': RUN_B}, {'variant': 'perturbed'}, {'controller_uid': CLIENT_UID + 1}, {'phase': 'ACTIVE'},
                   {'intent_id': 'not-hex'}, {'profile_sha256': None}, {'profile_sha256': 'x'})
        for patch in patches:
            with self.subTest(patch=patch):
                self.fresh()
                self.inventory.begin_override = lambda intent, patch=patch: dataclasses.replace(intent, **patch)
                await self.start()
                response = await self.open_catalog()
                self.assertFalse(response['ok'], response)
                self.assertEqual((self.runtime.calls['create'], self.runtime.calls['start']), (0, 0))
                self.assertIsNotNone(self.broker.status()['blocked'])
        self.fresh()
        self.inventory.begin_override = lambda intent: base  # a workflow-shaped intent: no profile, no context, no pins
        await self.start()
        self.assertFalse((await self.open_catalog())['ok'])
        self.assertEqual(self.runtime.calls['create'], 0)
        self.assertIsNotNone(self.broker.status()['blocked'])

    async def test_ambiguous_create_blocks_and_is_never_repeated_for_a_catalog_cell(self):
        await self.start()
        self.runtime.create_error = RuntimeError('boom')
        response = await self.open_catalog()
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('create_failed', False))
        self.assertEqual(self.runtime.calls['create'], 1)
        self.assertIsNone(self.inventory.current.container_id)  # PENDING without an ID
        self.assertEqual((await self.open_catalog(RUN_B))['reason'], 'owner_blocked')
        self.assertEqual((self.runtime.calls['create'], self.runtime.calls['close']), (1, 0))

    async def test_a_lost_open_response_leaves_the_handle_to_the_reaper_and_the_receipt_is_recoverable_from_the_diary(self):
        await self.start()
        reader, writer = FakeReader(frame(self.body())), FakeWriter(CLIENT_UID, fail_drain=True)
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            await self.broker._connection(reader, writer)
        self.assertTrue(writer.closed)
        self.assertEqual((self.broker.leases.held(), self.inventory.current.phase), (1, 'ACTIVE'))
        intent = self.inventory.current  # the identity is learned from the diary, never rebuilt by prefix or by run
        self.clock.now += 121
        await self.broker.reconcile()
        self.assertEqual((self.runtime.removed, self.broker.status()['obligations']), ([CONTAINER], 0))
        identity = {'installation_id': INSTALL, 'run_id': intent.run_id, 'variant': intent.variant, 'catalog_profile': intent.catalog_profile,
                    'context_sha256': intent.context_sha256, 'catalog_id': intent.catalog_id, 'catalog_sha256': intent.catalog_sha256,
                    'intent_id': intent.intent_id, 'container_id': CONTAINER}
        answer = await self.call({'op': 'catalog_receipt', **identity})
        self.assertEqual((answer['status'], answer['cleanup_confirmed']), ('confirmed', True))
        wire.validate_catalog_receipt(answer, identity=identity)

    async def test_a_cancelled_open_leaves_the_handle_to_the_reaper(self):
        self.make(limits=fast_limits(create=2.0))
        await self.start()
        self.runtime.create_gate = asyncio.Event()
        task = asyncio.ensure_future(self.open_catalog())
        await self.wait_for_call('create')
        self.assertEqual(self.inventory.current.phase, 'CREATE_PENDING')  # durable before create
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.runtime.create_gate.set()
        await self.broker.drain()
        self.assertEqual(self.inventory.current.phase, 'ACTIVE')  # the open completed; its response was dropped
        self.clock.now += 121
        await self.broker.reconcile()
        self.assertEqual((self.runtime.removed, self.broker.status()['obligations']), ([CONTAINER], 0))
        self.assertEqual((await self.open_catalog())['reason'], 'already_active')  # the cancelled cell is spent, not retried

    async def test_a_large_but_realistic_profile_fits_the_open_limit_and_nothing_is_truncated(self):
        await self.start()
        big = {'available': True, 'image_id': IMAGE, 'tmpfs': {'/tmp': 'x' * 200, '/work': 'y' * 200}, 'security_opt': ['z' * 64],
               'image_ref': 'r' * 200, 'catalog': {'id': C_ID, 'sha256': C_SHA, 'type': 'bind', 'destination': '/catalog.json',
                                                   'mode': 'read_only', 'source_verified': True, 'mounts': 1}}
        self.runtime.running_override = {'running': True, 'container_id': CONTAINER, 'profile': big, 'profile_sha256': DIGEST,
                                         'violations': []}
        raw_answer = await self.broker.handle(CLIENT_UID, enc(self.body()))
        self.assertLess(len(raw_answer), wire.RESPONSE_LIMITS['open_catalog'])
        self.assertEqual(wire.validate_catalog_open(wire.decode_response(raw_answer, op='open_catalog'), **self.open_args())['profile'], big)

    async def test_a_profile_too_large_for_the_limit_is_refused_and_restituted_not_truncated(self):
        await self.start()
        huge = {'available': True, 'image_id': IMAGE, 'padding': 'p' * 8300}
        self.runtime.running_override = {'running': True, 'container_id': CONTAINER, 'profile': huge, 'profile_sha256': DIGEST,
                                         'violations': []}
        response = await self.open_catalog()
        self.assertEqual((response['ok'], response['reason'], response['cleanup_confirmed']), (False, 'internal_error', True))
        self.assertEqual((self.runtime.removed, self.broker.status()['obligations']), ([CONTAINER], 0))
        self.assertNotIn('handle', response)


class CatalogOperationTests(CatalogCase):
    async def test_execute_and_the_two_fixed_probes_work_on_a_catalog_handle(self):
        opened = await self.opened_catalog()
        handle = opened['handle']
        executed = await self.call({'op': 'execute', 'handle': handle, 'command': 'cat -- /catalog.json'})
        self.assertEqual(wire.validate_result(executed, op='execute')['stdout'], 'ok')
        task = await self.call({'op': 'probe', 'handle': handle, 'name': 'task_result'})
        wire.validate_result(task, op='probe', name='task_result')
        measure = await self.call({'op': 'probe', 'handle': handle, 'name': 'measure'})
        self.assertEqual(wire.validate_measure(measure), MEAS)

    async def test_the_capture_probe_and_every_level_probe_are_wrong_domain_and_call_nothing(self):
        opened = await self.opened_catalog()
        handle = opened['handle']
        calls = dict(self.runtime.calls)
        log = list(self.log)
        for body in ({'op': 'probe', 'handle': handle, 'name': 'artifact_capture'},
                     {'op': 'level_probe', 'handle': handle, 'name': 'cgroup_events'},
                     {'op': 'level_probe', 'handle': handle, 'name': 'file_state', 'path': CAT_MARKER},
                     {'op': 'level_probe', 'handle': handle, 'name': 'copy_scan', 'sha256': 'b' * 64, 'size': 24, 'exclude': None}):
            self.assertEqual(await self.call(body), {'ok': False, 'reason': 'wrong_domain'}, body)
        self.assertEqual((dict(self.runtime.calls), self.log), (calls, log))
        self.assertEqual(self.broker.leases.authorize(handle, CLIENT_UID).state, proto.ACTIVE)  # the lease is intact
        self.assertTrue((await self.call({'op': 'execute', 'handle': handle, 'command': 'true'}))['ok'])

    async def test_catalog_check_returns_the_validated_view_with_the_nine_fields_for_both_profiles(self):
        for profile in ('A', 'B'):
            with self.subTest(profile=profile):
                self.fresh()
                opened = await self.opened_catalog(profile=profile)
                identity = self.cat_identity(opened)
                response = await self.check(opened['handle'])
                self.assertTrue(response['ok'], response)
                view = wire.validate_catalog_check(response, identity=identity, after=0)
                self.assertEqual(view['probe'], PROBE_B if profile == 'B' else PROBE_A)
                self.assertEqual(set(response), {'ok', 'op', 'probe', 'host_check', 'check_index', *wire.CATALOG_IDENTITY_FIELDS})
                self.assertEqual(response['check_index'], 1)
                self.assertEqual(wire.validate_catalog_check(await self.check(opened['handle']), identity=identity, after=1)
                                 ['check_index'], 2)
                self.assertEqual(len(self.runtime.checked), 2)
                self.assertTrue(all(item.phase == 'ACTIVE' and item.catalog_profile == profile for item in self.runtime.checked))
                self.assertNotIn('resource', json.dumps(response))
                self.assertNotIn(PRIVATE_RESOURCE, json.dumps(response))

    async def test_catalog_check_takes_the_handle_and_nothing_else(self):
        opened = await self.opened_catalog()
        for extra in ('script', 'path', 'index', 'check_index', 'catalog_path', 'command', 'probe', 'name', 'argv'):
            response = await self.call({'op': 'catalog_check', 'handle': opened['handle'], extra: 'x'})
            self.assertIn(response['reason'], {'unexpected_field', 'forbidden_field'}, extra)
        self.assertEqual(self.runtime.calls['catalog_check'], 0)

    async def test_catalog_check_is_wrong_domain_on_a_workflow_or_level_handle_and_calls_nothing(self):
        await self.start()
        workflow = await self.call({'op': 'open', 'run_id': RUN_A, 'variant': 'legitimate'})
        self.assertTrue(workflow['ok'], workflow)
        self.assertEqual(await self.check(workflow['handle']), {'ok': False, 'reason': 'wrong_domain'})
        self.assertTrue((await self.call({'op': 'execute', 'handle': workflow['handle'], 'command': 'true'}))['ok'])  # still intact
        self.assertTrue((await self.close_handle(workflow['handle']))['ok'])
        handle = self.broker.leases.open_level(CLIENT_UID, RUN_B, 'memory', 'actor', CONTEXT)  # a level lease, as the M2 broker holds one
        session = broker_module._Session(handle, CLIENT_UID, RUN_B, None, 'memory', 'actor', CONTEXT)
        session.opening = False
        self.broker._sessions[handle] = session
        self.assertEqual(await self.check(handle), {'ok': False, 'reason': 'wrong_domain'})
        self.assertEqual(self.runtime.calls['catalog_check'], 0)
        self.assertEqual(self.broker.leases.authorize(handle, CLIENT_UID).state, proto.ACTIVE)

    async def test_a_workflow_handle_keeps_its_probes_and_the_capture_probe(self):
        await self.start()
        workflow = await self.call({'op': 'open', 'run_id': RUN_A, 'variant': 'legitimate'})
        for name in ('task_result', 'artifact_capture'):
            wire.validate_result(await self.call({'op': 'probe', 'handle': workflow['handle'], 'name': name}), op='probe', name=name)

    async def test_runtime_outputs_that_are_not_the_exact_view_end_the_lease_and_restitute_without_replay(self):
        bad = ['text', None, [], {}, 5,
               {'probe': dict(PROBE_B), 'host_check': dict(HOST_OK)},
               {**catalog_view(), 'extra': 1}, {**catalog_view(), 'stdout': '{"state":"present"}'},
               catalog_view(check_index=0), catalog_view(check_index=True), catalog_view(check_index=65), catalog_view(check_index=1.0),
               catalog_view(check_index='1'), catalog_view(check_index=None),
               catalog_view(probe={**PROBE_B, 'ran': 1}), catalog_view(probe={**PROBE_B, 'size': True}),
               catalog_view(probe={**PROBE_B, 'write_errno': 'erofs'}), catalog_view(probe={**PROBE_B, 'state': 'Present'}),
               catalog_view(probe={**PROBE_B, 'stdout': 'x'}), catalog_view(probe={k: v for k, v in PROBE_B.items() if k != 'size'}),
               catalog_view(probe={**PROBE_A, 'read': 'ok'}), catalog_view(probe='present'), catalog_view(probe=None),
               catalog_view(host_check={**HOST_OK, 'reason': 'missing'}), catalog_view(host_check={**HOST_OK, 'ok': 1}),
               catalog_view(host_check={**HOST_UNREADABLE, 'reason': '/var/lib/owner/catalog.json'}),
               catalog_view(host_check={**HOST_UNREADABLE, 'changed': False}), catalog_view(host_check='ok')]
        for answer in bad:
            with self.subTest(answer=str(answer)[:70]):
                self.fresh()
                opened = await self.opened_catalog()
                self.runtime.scripted.append(answer)
                response = await self.check(opened['handle'])
                self.assertEqual(response, {'ok': False, 'reason': 'internal_error'})
                await self.broker.drain()
                self.assertEqual((self.runtime.removed, self.runtime.calls['catalog_check']), ([CONTAINER], 1))  # restituted, not replayed
                self.assertEqual((await self.check(opened['handle']))['reason'], 'unknown_handle')  # the lease is retired with the receipt
                receipt = await self.close_handle(opened['handle'])
                wire.validate_catalog_close(receipt, receipt=self.cat_identity(opened))
                self.assertEqual(self.broker.status()['obligations'], 0)

    async def test_unavailable_is_a_valid_answer_and_ran_false_too_and_the_session_continues(self):
        opened = await self.opened_catalog()
        unavailable = {**PROBE_A, 'state': 'unavailable'}
        not_run = {**PROBE_A, 'ran': False, 'state': 'unavailable'}
        self.runtime.scripted.extend([catalog_view(probe=unavailable, check_index=1), catalog_view(probe=not_run, check_index=2),
                                      catalog_view(host_check=dict(HOST_UNREADABLE), check_index=3)])
        identity = self.cat_identity(opened)
        after = 0
        for state in ('unavailable', 'unavailable', 'present'):
            answer = await self.check(opened['handle'])
            self.assertTrue(answer['ok'], answer)
            view = wire.validate_catalog_check(answer, identity=identity, after=after)
            after = view['check_index']
            self.assertEqual(view['probe']['state'], state)
        self.assertEqual(self.broker.leases.authorize(opened['handle'], CLIENT_UID).state, proto.ACTIVE)

    async def test_indexes_grow_strictly_gaps_are_allowed_repetition_and_inversion_end_the_lease(self):
        for sequence, ok_count in (([1, 4, 4], 2), ([1, 3, 2], 2), ([2, 2], 1), ([5, 1], 1)):
            with self.subTest(sequence=sequence):
                self.fresh()
                opened = await self.opened_catalog()
                self.runtime.scripted.extend(catalog_view(check_index=index) for index in sequence)
                answers = [await self.check(opened['handle']) for _ in range(ok_count)]
                self.assertTrue(all(answer['ok'] for answer in answers), answers)
                self.assertEqual([answer['check_index'] for answer in answers], sequence[:ok_count])
                self.assertEqual(await self.check(opened['handle']), {'ok': False, 'reason': 'internal_error'})
                await self.broker.drain()
                self.assertEqual(self.runtime.removed, [CONTAINER])

    async def test_a_timeout_ends_the_lease_a_runtime_failure_maps_to_a_closed_reason_and_nothing_is_replayed(self):
        opened = await self.opened_catalog()
        self.runtime.check_gate = asyncio.Event()  # never set: the check hangs
        self.runtime.close_gate = asyncio.Event()
        self.assertEqual(await self.check(opened['handle']), {'ok': False, 'reason': 'exec_timeout'})
        self.assertEqual((await self.check(opened['handle']))['reason'], 'closing')
        self.runtime.close_gate.set()
        await self.broker.drain()
        self.assertEqual((self.runtime.calls['catalog_check'], self.runtime.removed), (1, [CONTAINER]))
        wire.validate_catalog_close(await self.close_handle(opened['handle']), receipt=self.cat_identity(opened))
        self.assertEqual(self.runtime.calls['close'], 1)

        class Stopped(Exception):
            reason = 'sandbox_stopped'
        for error, reason in ((Stopped(), 'sandbox_stopped'), (RuntimeError('boom ' + PRIVATE_RESOURCE), 'internal_error')):
            with self.subTest(reason=reason):
                self.fresh()
                opened = await self.opened_catalog()
                self.runtime.scripted.append(error)
                response = await self.check(opened['handle'])
                self.assertEqual(response, {'ok': False, 'reason': reason})
                self.assertNotIn(PRIVATE_RESOURCE, json.dumps(response))
                await self.broker.drain()
                self.assertEqual((self.runtime.calls['catalog_check'], self.runtime.removed), (1, [CONTAINER]))

    async def test_a_cancelled_check_does_not_cancel_the_operation_and_the_close_still_restitutes_once(self):
        self.make(limits=fast_limits(probe=2.0))
        opened = await self.opened_catalog()
        self.runtime.check_gate = asyncio.Event()
        task = asyncio.ensure_future(self.check(opened['handle']))
        await self.wait_for_call('catalog_check')
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.runtime.check_gate.set()
        await self.broker.drain()
        self.assertEqual(self.runtime.calls['catalog_check'], 1)  # neither cancelled nor repeated
        self.assertEqual(self.broker.leases.authorize(opened['handle'], CLIENT_UID).state, proto.ACTIVE)
        closed = await self.close_handle(opened['handle'])
        wire.validate_catalog_close(closed, receipt=self.cat_identity(opened))
        self.assertEqual((self.runtime.calls['catalog_check'], self.runtime.calls['close'], self.runtime.removed), (1, 1, [CONTAINER]))

    async def test_a_second_operation_is_busy_and_close_waits_for_the_check_in_flight(self):
        self.make(limits=fast_limits(probe=2.0))
        opened = await self.opened_catalog()
        handle = opened['handle']
        self.runtime.check_gate = asyncio.Event()
        self.runtime.check_started = asyncio.Event()
        running = asyncio.ensure_future(self.check(handle))
        await self.runtime.check_started.wait()
        self.assertEqual((await self.call({'op': 'execute', 'handle': handle, 'command': 'true'}))['reason'], 'busy')
        self.assertEqual((await self.check(handle))['reason'], 'busy')
        closing = asyncio.ensure_future(self.close_handle(handle))
        await asyncio.sleep(0.05)
        self.assertEqual(self.runtime.calls['close'], 0)  # the restitution waits for the operation
        self.assertEqual((await self.call({'op': 'probe', 'handle': handle, 'name': 'measure'}))['reason'], 'closing')
        self.runtime.check_gate.set()
        self.assertTrue((await running)['ok'])
        self.assertTrue((await closing)['ok'])
        self.assertLess(self.log.index('rt:catalog_check'), self.log.index('rt:close@CLOSE_PENDING'))


class CatalogCloseTests(CatalogCase):
    async def test_close_answers_the_nine_fields_and_is_idempotent_and_no_other_validator_takes_it(self):
        opened = await self.opened_catalog()
        identity = self.cat_identity(opened)
        self.log.clear()
        first = await self.close_handle(opened['handle'])
        second = await self.close_handle(opened['handle'])
        self.assertEqual(first, second)
        self.assertEqual(self.runtime.calls['close'], 1)
        self.assertEqual(self.log, ORDER_OF_CLOSE)
        self.assertEqual(wire.validate_catalog_close(first, receipt=identity)['oom_killed'], False)
        self.assertEqual(set(first), {'ok', 'op', *wire.CATALOG_IDENTITY_FIELDS, 'cleanup_confirmed', 'oom_killed', *wire.MEASUREMENT_FIELDS})
        self.assertNotIn(PRIVATE_RESOURCE, json.dumps(first))
        m1 = {key: first[key] for key in wire.IDENTITY_FIELDS}
        with self.assertRaises(wire.WireError):
            wire.validate_close(first, receipt=m1)
        with self.assertRaises(wire.WireError):
            wire.validate_level_close(first, receipt={key: first[key] for key in wire.IDENTITY_FIELDS})
        self.assertEqual(self.broker.status()['obligations'], 0)

    async def test_other_domains_keep_their_close_shape(self):
        await self.start()
        workflow = await self.call({'op': 'open', 'run_id': RUN_A, 'variant': 'legitimate'})
        closed = await self.close_handle(workflow['handle'])
        self.assertEqual(wire.validate_close(closed, receipt=self.identity(workflow))['oom_killed'], False)
        self.assertNotIn('catalog_profile', closed)

    async def test_an_unconfirmed_close_keeps_the_obligation_until_the_same_procedure_succeeds(self):
        opened = await self.opened_catalog()
        self.runtime.close_confirms = False
        response = await self.close_handle(opened['handle'])
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('cleanup_unconfirmed', False))
        self.assertEqual((self.inventory.current.phase, self.broker.leases.held()), ('CLOSE_PENDING', 1))
        self.assertEqual((await self.open_catalog(RUN_B))['reason'], 'capacity_exhausted')
        self.runtime.close_confirms = True
        await self.broker.reconcile()  # same ID, same procedure
        self.assertEqual((self.broker.status()['obligations'], self.runtime.removed), (0, [CONTAINER]))
        late = await self.close_handle(opened['handle'])
        wire.validate_catalog_close(late, receipt=self.cat_identity(opened))

    async def test_a_runtime_that_confirms_but_still_lists_the_id_is_not_trusted(self):
        opened = await self.opened_catalog()
        self.runtime.keep_after_close = True
        response = await self.close_handle(opened['handle'])
        self.assertEqual((response['reason'], response['cleanup_confirmed']), ('cleanup_unconfirmed', False))
        self.assertIsNone(self.inventory.finished)

    async def test_a_cancelled_close_request_does_not_cancel_the_restitution(self):
        self.make(limits=fast_limits(close=2.0))
        opened = await self.opened_catalog()
        self.runtime.close_gate = asyncio.Event()
        task = asyncio.ensure_future(self.close_handle(opened['handle']))
        await self.wait_for_call('close')
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.runtime.close_gate.set()
        await self.broker.drain()
        self.assertEqual((self.inventory.current, self.runtime.removed), (None, [CONTAINER]))
        again = await self.close_handle(opened['handle'])
        wire.validate_catalog_close(again, receipt=self.cat_identity(opened))
        self.assertEqual(self.runtime.calls['close'], 1)

    async def test_an_expired_catalog_cell_keeps_its_plaza_until_the_reaper_and_its_receipt_has_the_catalog_shape(self):
        opened = await self.opened_catalog()
        self.clock.now += 121
        self.assertEqual((await self.call({'op': 'execute', 'handle': opened['handle'], 'command': 'true'}))['reason'], 'expired')
        self.assertEqual((await self.check(opened['handle']))['reason'], 'expired')
        self.assertEqual((await self.open_catalog(RUN_B))['reason'], 'capacity_exhausted')
        await self.broker.reconcile()
        self.assertEqual((self.runtime.removed, self.broker.leases.held()), ([CONTAINER], 0))
        wire.validate_catalog_close(await self.close_handle(opened['handle']), receipt=self.cat_identity(opened))
        self.assertTrue((await self.open_catalog(RUN_B))['ok'])


class CatalogReceiptTests(CatalogCase):
    def body(self, identity=None, **patch):  # the receipt request; `identity` defaults to a placeholder one
        return {'op': 'catalog_receipt', **(identity if identity is not None else CATALOG_IDENT), **patch}

    async def exchange(self, body, uid=CLIENT_UID):
        before = self.snapshot()
        response = await self.call(body, uid=uid)
        self.assertEqual(self.snapshot(), before)  # a read: the diary, the runtime, the leases and the owner state did not move
        return response

    async def query(self, identity, **patch):
        requested = {**identity, **patch}
        response = await self.exchange(self.body(requested))
        self.assertTrue(response['ok'], response)
        wire.validate_catalog_receipt(response, identity=requested)
        return response

    async def closed(self, run=RUN_A, variant='legitimate', profile='B', context=CONTEXT):
        opened = await self.open_catalog(run, variant, profile, context) if self.broker.status()['recovered'] else \
            await self.opened_catalog(run, variant, profile, context)
        self.assertTrue(opened['ok'], opened)
        identity = self.cat_identity(opened)
        wire.validate_catalog_close(await self.close_handle(opened['handle']), receipt=identity)
        return identity

    def assertStatus(self, answer, status):
        self.assertEqual((answer['status'], answer['cleanup_confirmed']), (status, status == 'confirmed'))

    async def test_unknown_before_finish_and_confirmed_after_it_for_both_profiles(self):
        for profile in ('A', 'B'):
            with self.subTest(profile=profile):
                self.fresh()
                opened = await self.opened_catalog(profile=profile)
                identity = self.cat_identity(opened)
                self.assertStatus(await self.query(identity), 'unknown')  # ACTIVE: the obligation is still open
                wire.validate_catalog_close(await self.close_handle(opened['handle']), receipt=identity)
                confirmed = await self.query(identity)
                self.assertStatus(confirmed, 'confirmed')
                self.assertEqual(await self.query(identity), confirmed)  # a read: repeating it gives the same answer

    async def test_close_pending_is_unknown_until_the_owner_reconciles_and_asking_never_retries_it(self):
        opened = await self.opened_catalog()
        identity = self.cat_identity(opened)
        self.runtime.close_confirms = False
        await self.close_handle(opened['handle'])
        closes = self.runtime.calls['close']
        for _ in range(2):
            self.assertStatus(await self.query(identity), 'unknown')
        self.assertEqual(self.runtime.calls['close'], closes)
        self.runtime.close_confirms = True
        await self.broker.reconcile()
        self.assertStatus(await self.query(identity), 'confirmed')

    async def test_a_receipt_requires_the_finish_not_an_empty_inventory(self):
        opened = await self.opened_catalog()
        identity = self.cat_identity(opened)
        self.runtime.containers.clear()  # the ID is gone from Docker, but the diary never reached FINISH
        self.assertStatus(await self.query(identity), 'unknown')
        self.assertEqual(self.broker.status()['obligations'], 1)

    async def test_a_lost_close_answer_is_recovered_after_a_restart_without_any_lease(self):
        opened = await self.opened_catalog()
        identity = self.cat_identity(opened)
        await self.close_handle(opened['handle'])  # the answer is lost: the test discards it
        self.make()  # a new owner process: no lease, no tombstone, not yet reconciled
        calls = dict(self.runtime.calls)
        self.assertStatus(await self.query(identity), 'confirmed')
        await self.start()
        self.assertEqual(self.broker.leases.held(), 0)
        self.assertEqual((await self.close_handle(opened['handle']))['reason'], 'unknown_handle')  # the handle did not survive; the diary did
        self.assertEqual(dict(self.runtime.calls), calls)

    async def test_each_crossed_field_is_unknown_and_only_echoes_what_was_asked(self):
        identity = await self.closed()
        other = {'run_id': RUN_B, 'variant': 'perturbed', 'catalog_profile': 'A', 'context_sha256': OTHER_CONTEXT,
                 'intent_id': '7' * 32, 'container_id': '7' * 64}
        for key, value in other.items():
            answer = await self.query(identity, **{key: value})
            self.assertStatus(answer, 'unknown')
            self.assertEqual(answer[key], value)
        self.assertStatus(await self.query(identity, **other), 'unknown')
        self.assertStatus(await self.query(identity), 'confirmed')

    async def test_a_receipt_is_not_transferable_between_cells(self):
        first = await self.closed(RUN_A, 'legitimate', 'A')
        self.runtime.create_id = 'e' * 64
        second = await self.closed(RUN_B, 'legitimate', 'B')
        for key in ('run_id', 'intent_id', 'container_id', 'catalog_profile'):
            self.assertStatus(await self.query(first, **{key: second[key]}), 'unknown')
            self.assertStatus(await self.query(second, **{key: first[key]}), 'unknown')
        self.assertStatus(await self.query(first), 'confirmed')
        self.assertStatus(await self.query(second), 'confirmed')

    async def test_installation_mismatch_never_reaches_the_diary_and_another_uid_gets_no_answer(self):
        identity = await self.closed()
        self.assertEqual(await self.exchange(self.body(identity, installation_id='9' * 32)),
                         {'ok': False, 'reason': 'installation_mismatch'})
        self.assertEqual(self.inventory.catalog_queries, [])
        self.assertIsNone(await self.exchange(self.body(identity), uid=CLIENT_UID + 1))
        self.assertEqual(self.inventory.catalog_queries, [])
        await self.query(identity)
        self.assertEqual({item[0] for item in self.inventory.catalog_queries}, {CLIENT_UID})  # only the authenticated UID is asked about
        for field in ('controller_uid', 'uid', 'owner_uid'):
            self.assertEqual(await self.exchange(self.body(identity, **{field: CLIENT_UID + 1})), {'ok': False, 'reason': 'unexpected_field'})
        self.assertEqual(len(self.inventory.catalog_queries), 1)

    async def test_diary_failures_are_closed_and_change_nothing(self):
        await self.start()
        for code, reason in (('identity_changed', 'foreign_owner'), ('state_unavailable', 'internal_error'),
                             ('state_corrupt', 'internal_error'), ('not a closed code!', 'internal_error')):
            self.inventory.catalog_receipt_error = code
            self.assertEqual(await self.exchange(self.body()), {'ok': False, 'reason': reason})
        self.inventory.catalog_receipt_error = None

        def broken(**kwargs):
            raise RuntimeError('boom')
        self.inventory.receipt_catalog = broken
        self.assertEqual(await self.exchange(self.body()), {'ok': False, 'reason': 'internal_error'})
        self.assertIsNone(self.broker.status()['blocked'])  # a failed read never blocks the owner

    async def test_only_the_exact_finish_of_a_catalog_intent_confirms(self):
        await self.start()
        finish = pending_catalog('FINISH', intent_id=CATALOG_IDENT['intent_id'])
        self.inventory.catalog_receipt_returns = finish
        self.assertStatus(await self.query(CATALOG_IDENT), 'confirmed')
        for patch in ({'phase': 'ACTIVE'}, {'phase': 'CLOSE_PENDING'}, {'controller_uid': CLIENT_UID + 1}, {'run_id': RUN_B},
                      {'variant': 'perturbed'}, {'catalog_profile': 'A'}, {'context_sha256': OTHER_CONTEXT}, {'catalog_id': 'other/v1'},
                      {'catalog_sha256': 'e' * 64}, {'intent_id': '7' * 32}, {'container_id': '7' * 64}):
            self.inventory.catalog_receipt_returns = dataclasses.replace(finish, **patch)
            self.assertEqual(await self.exchange(self.body()), {'ok': False, 'reason': 'internal_error'}, patch)
        workflow = Intent(CATALOG_IDENT['intent_id'], 'escape-actor-' + CATALOG_IDENT['intent_id'], CLIENT_UID, RUN_A, 'legitimate',
                          CONTAINER, 'FINISH', DIGEST)
        level = LevelIntent(CATALOG_IDENT['intent_id'], 'escape-actor-' + CATALOG_IDENT['intent_id'], CLIENT_UID, RUN_A, 'memory', 'actor',
                            CONTEXT, CONTAINER, 'FINISH', DIGEST)
        for other in (workflow, level, object()):  # another domain, or nothing like an intent, can never confirm a catalog receipt
            self.inventory.catalog_receipt_returns = other
            self.assertEqual(await self.exchange(self.body()), {'ok': False, 'reason': 'internal_error'}, type(other).__name__)

    async def test_a_catalog_finish_is_never_an_m1_receipt(self):
        await self.start()
        m1 = {'installation_id': INSTALL, 'run_id': RUN_A, 'variant': 'legitimate', 'intent_id': CATALOG_IDENT['intent_id'],
              'container_id': CONTAINER}
        self.inventory.receipt_returns = pending_catalog('FINISH', intent_id=m1['intent_id'])  # a malfunctioning diary
        self.assertEqual(await self.exchange({'op': 'receipt', **m1}), {'ok': False, 'reason': 'internal_error'})
        self.inventory.receipt_returns = Intent(m1['intent_id'], 'escape-actor-' + m1['intent_id'], CLIENT_UID, RUN_A, 'legitimate',
                                                CONTAINER, 'FINISH', DIGEST)  # the M1 control still confirms
        self.assertEqual((await self.exchange({'op': 'receipt', **m1}))['status'], 'confirmed')

    async def test_an_inventory_without_receipt_catalog_never_confirms_and_the_other_operations_are_untouched(self):
        class NoCatalogReceipt(CatalogInventory):
            receipt_catalog = None
        self.inventory = NoCatalogReceipt(self.log)
        self.runtime = CatalogRuntime(self.log, self.inventory)
        self.make()
        await self.start()
        self.assertEqual(await self.exchange(self.body()), {'ok': False, 'reason': 'internal_error'})
        self.assertTrue((await self.open_catalog())['ok'])

    async def test_the_receipt_is_not_gated_by_the_policy_but_info_and_open_are(self):
        identity = await self.closed()
        self.make(allowed_catalog=False)  # the owner's policy shrank
        self.assertStatus(await self.query(identity), 'confirmed')  # an old restitution can still be proven
        self.assertEqual(await self.call(CATALOG_INFO_BODY), {'ok': False, 'reason': 'catalog_not_allowed'})
        self.assertEqual((await self.open_catalog(RUN_B))['reason'], 'catalog_not_allowed')

    async def test_it_answers_in_every_owner_state_and_never_reaches_the_runtime(self):
        identity = await self.closed()
        calls, log = dict(self.runtime.calls), list(self.log)
        exploding = ExplodingRuntime()
        self.broker.runtime = exploding  # from here any runtime access is an error
        for _ in range(3):
            self.assertStatus(await self.query(identity), 'confirmed')
            self.assertStatus(await self.query(identity, run_id=RUN_B), 'unknown')
        self.broker._block('unrecognized_object')
        self.assertStatus(await self.query(identity), 'confirmed')
        self.broker._shutdown = True
        self.assertStatus(await self.query(identity), 'confirmed')
        self.assertEqual(exploding.touched, [])
        self.assertEqual((dict(self.runtime.calls), self.log), (calls, log))

    async def test_malformed_requests_get_closed_reasons_without_a_diary_query(self):
        await self.start()
        cases = (({'installation_id': 'x'}, 'invalid_installation_id'), ({'run_id': 'x'}, 'invalid_run_id'),
                 ({'variant': 'other'}, 'invalid_variant'), ({'catalog_profile': 'C'}, 'invalid_catalog_profile'),
                 ({'context_sha256': 'x'}, 'invalid_context'), ({'catalog_id': 'other/v1'}, 'invalid_catalog_id'),
                 ({'catalog_sha256': 'e' * 64}, 'invalid_catalog_digest'), ({'intent_id': 5}, 'invalid_intent_id'),
                 ({'container_id': 'c' * 63}, 'invalid_container_id'), ({'handle': 'ab' * 32}, 'unexpected_field'),
                 ({'image': 'x'}, 'forbidden_field'), ({'resource_id': PRIVATE_RESOURCE}, 'unexpected_field'),
                 ({'level': 'memory'}, 'unexpected_field'))
        for patch, reason in cases:
            self.assertEqual(await self.exchange(self.body(**patch)), {'ok': False, 'reason': reason}, patch)
        short = {key: value for key, value in self.body().items() if key != 'catalog_profile'}
        self.assertEqual(await self.exchange(short), {'ok': False, 'reason': 'missing_field'})
        self.assertEqual(self.inventory.catalog_queries, [])

    async def test_dispatch_through_an_authenticated_connection_and_the_response_limit(self):
        identity = await self.closed()
        reader, writer = FakeReader(frame(self.body(identity))), FakeWriter(CLIENT_UID)
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            await self.broker._connection(reader, writer)
        self.assertStatus(wire.validate_catalog_receipt(writer.response(), identity=identity), 'confirmed')
        self.assertLessEqual(len(bytes(writer.data)) - 4, wire.RESPONSE_LIMITS['catalog_receipt'])
        queries = len(self.inventory.catalog_queries)
        reader, writer = FakeReader(frame(self.body(identity)) + b'x'), FakeWriter(CLIENT_UID)
        with mock.patch.object(socket, 'SO_PEERCRED', 17, create=True):
            await self.broker._connection(reader, writer)
        self.assertEqual(writer.response(), {'ok': False, 'reason': 'framing'})  # trailing bytes: not dispatched
        self.assertEqual(len(self.inventory.catalog_queries), queries)


CATALOG_IDENT = {'installation_id': INSTALL, 'run_id': RUN_A, 'variant': 'legitimate', 'catalog_profile': 'B', 'context_sha256': CONTEXT,
                 'catalog_id': C_ID, 'catalog_sha256': C_SHA, 'intent_id': '5' * 32, 'container_id': CONTAINER}


class CatalogRecoveryTests(CatalogCase):
    async def test_every_phase_of_a_catalog_intent_is_restituted_by_id_and_recovery_never_creates_or_checks(self):
        for allowed in (True, False):  # recovery restitutes any recognized ID regardless of the policy
            for profile in ('A', 'B'):
                for phase in ('CREATE_ACK', 'START_PENDING', 'ACTIVE', 'CLOSE_PENDING'):
                    with self.subTest(allowed=allowed, profile=profile, phase=phase):
                        self.fresh(allowed_catalog=allowed)
                        self.inventory.current = pending_catalog(phase, profile=profile)
                        self.runtime.containers.add(CONTAINER)
                        await self.start()
                        self.assertEqual((self.runtime.removed, self.log), ([CONTAINER], ORDER_OF_CLOSE))
                        self.assertEqual(self.runtime.foreign, {FOREIGN})
                        for name in ('create', 'start', 'execute', 'probe', 'catalog_check'):
                            self.assertEqual(self.runtime.calls[name], 0, name)
                        self.assertEqual(self.runtime.status_calls, 0)
                        self.assertTrue(self.broker.status()['recovered'])
                        identity = {**CATALOG_IDENT, 'catalog_profile': profile, 'intent_id': 'a' * 32}
                        answer = await self.call({'op': 'catalog_receipt', **identity})  # and the FINISH is now the exact catalog one
                        self.assertEqual((answer['status'], answer['catalog_profile']), ('confirmed', profile))

    async def test_a_pending_catalog_intent_without_an_id_blocks_and_nothing_is_created(self):
        self.inventory.current = pending_catalog('CREATE_PENDING', container=None)
        await self.start()
        self.assertEqual((self.broker.status()['blocked'], self.broker.status()['obligations']), ('create_uncertain', 1))
        self.assertEqual((self.runtime.calls['close'], self.runtime.calls['create']), (0, 0))
        self.assertEqual((await self.open_catalog(RUN_B))['reason'], 'owner_blocked')
        await self.broker.reconcile()  # time and repetition do not clear it
        self.assertEqual(self.broker.status()['blocked'], 'create_uncertain')

    async def test_a_restart_with_a_catalog_cell_active_restitutes_it_and_the_spent_key_is_not_reopened(self):
        opened = await self.opened_catalog(profile='B')
        identity = self.cat_identity(opened)
        self.make()  # a new process over the same diary and runtime
        self.log.clear()
        await self.start()
        self.assertEqual((self.log, self.runtime.removed), (ORDER_OF_CLOSE, [CONTAINER]))
        self.assertEqual((self.runtime.calls['create'], self.runtime.calls['start'], self.runtime.calls['execute']), (1, 1, 0))
        self.assertEqual((await self.close_handle(opened['handle']))['reason'], 'unknown_handle')  # a restart invalidates handles
        self.assertEqual((await self.call({'op': 'catalog_receipt', **identity}))['status'], 'confirmed')
        self.assertEqual((await self.open_catalog(RUN_A, 'legitimate', 'A'))['reason'], 'already_active')  # the interrupted cell is spent

    async def test_a_mixed_diary_keeps_each_domain_shape_in_its_close_answer(self):
        await self.start()
        catalog = await self.open_catalog(RUN_A, 'legitimate', 'B')
        self.clock.now += 121
        await self.broker.reconcile()  # the reaper restitutes the expired catalog lease
        workflow = await self.call({'op': 'open', 'run_id': RUN_A, 'variant': 'legitimate'})
        self.assertTrue(workflow['ok'], workflow)
        self.clock.now += 121
        await self.broker.reconcile()
        shaped = await self.close_handle(catalog['handle'])
        plain = await self.close_handle(workflow['handle'])
        wire.validate_catalog_close(shaped, receipt=self.cat_identity(catalog))
        wire.validate_close(plain, receipt=self.identity(workflow))
        self.assertIn('catalog_profile', shaped)
        self.assertNotIn('catalog_profile', plain)
        self.assertEqual(self.runtime.removed, [CONTAINER, CONTAINER])


if __name__ == '__main__':
    unittest.main()

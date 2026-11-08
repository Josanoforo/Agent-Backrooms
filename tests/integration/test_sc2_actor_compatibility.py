"""A4 opt-in compatibility proofs for the isolated invoice actor service (SC2/SC3)."""
#
# Layout. Offline tests (no Docker, SQLite real, provider and Docker doubles) run in any normal local pass on Linux. Tests named
# test_scenario_* only run under the root operator (sc2_actor_compatibility_local.py) with ESCAPE_A4_SCENARIO set; they never skip
# silently inside it. Nothing here is a measurement until an operator runs it; doubles are simulation, not Docker observation.
import asyncio
import contextlib
import hashlib
import json
import os
import shlex
import socket
import struct
import threading
import tempfile
import time
from pathlib import Path

import pytest

pytest.importorskip('fcntl')  # owner state needs POSIX; the whole module is skipped elsewhere

from fastapi.testclient import TestClient

from services.agent import (actor_state, actor_wire as wire, invoice_actor_broker as broker_module,
                            invoice_actor_client as client_module, invoice_actor_protocol as proto,
                            invoice_verification, main, missions, provider, recovery, runner, workflow)

REPO = Path(__file__).resolve().parents[2]
INSTALL = 'a1' * 16
IMAGE = 'sha256:' + 'e' * 64
PROFILE = {'available': True, 'source': 'docker_inspect_after_start', 'scope': 'level_actor_container', 'image_id': IMAGE}
PROFILE_SHA = runner.profile_digest(PROFILE)
CONTROLLER_UID = 4242
OWNER_UID = os.geteuid()
HANDLE = '9' * 64
NONROOT = pytest.mark.skipif(OWNER_UID == 0, reason='owner state must belong to a non-root UID')
SCENARIO = os.getenv('ESCAPE_A4_SCENARIO')


@pytest.fixture(name='tmp_path')
def trusted_tmp_path(tmp_path_factory):
    if SCENARIO:
        yield tmp_path_factory.mktemp('a4-controller')
        return
    # The durable diary rejects a writable ancestor such as /tmp.
    with tempfile.TemporaryDirectory(prefix='.a4-offline-', dir=Path.home()) as directory:
        yield Path(directory)


def scenario_only(*names):
    return pytest.mark.skipif(SCENARIO not in names, reason='runs only inside the A4 root operator for ' + '/'.join(names))


# ------------------------------------------------------------------------------------------------------- Docker double

class RuntimeDouble:
    """Docker double of the owner. Records every call so that replay (create/start/exec) and read-only queries can be counted."""

    def __init__(self, container='c' * 64):
        self.container, self.installed, self.calls = container, [], []
        self.fail_create = False
        self.close_confirms = True
        self.close_removes = True

    async def ready(self):
        self.calls.append('ready')
        return True

    async def installed_ids(self):
        self.calls.append('installed_ids')
        return tuple(self.installed)

    async def create(self, intent):
        self.calls.append('create')
        if self.fail_create:
            raise RuntimeError('create outcome lost')
        self.installed.append(self.container)
        return self.container

    async def inspect_created(self, intent):
        self.calls.append('inspect_created')
        return {'compatible': True, 'violations': []}

    async def start(self, intent):
        self.calls.append('start')

    async def inspect_running(self, intent):
        self.calls.append('inspect_running')
        return {'running': True, 'container_id': intent.container_id, 'profile': PROFILE,
                'profile_sha256': intent.profile_sha256, 'violations': []}

    async def execute(self, intent, command):
        self.calls.append('execute')
        return {'stdout': 'ran', 'stderr': '', 'exit_code': 0, **runner.unavailable_measurement()}

    async def probe(self, intent, name):
        self.calls.append('probe')
        return {'stdout': '', 'stderr': '', 'exit_code': 0, **runner.unavailable_measurement()}

    async def close(self, intent):
        self.calls.append('close')
        if self.close_removes:
            self.installed.clear()
        return {'cleanup_confirmed': self.close_confirms, 'oom_killed': False, **runner.unavailable_measurement()}


@contextlib.contextmanager
def real_inventory(directory, *, initialize):
    """Real SQLite diary. `initialize=False` on the same directory is an owner restart (new descriptors, same history)."""
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    with actor_state.open_actor_inventory(
            directory, installation_id=INSTALL, owner_uid=OWNER_UID, controller_uid=CONTROLLER_UID,
            docker_id='A4-DOCKER-ID', docker_root='/var/lib/docker', image_id=IMAGE, profile_sha256=PROFILE_SHA,
            initialize=initialize) as inventory:
        yield inventory


def make_broker(runtime, inventory, **options):
    return broker_module.ActorBroker(runtime=runtime, inventory=inventory, client_uid=CONTROLLER_UID, image_id=IMAGE, **options)


async def rpc(broker, op, *, uid=CONTROLLER_UID, **fields):
    answer = await broker.handle(uid, wire.encode_request(op, **fields))
    return None if answer is None else json.loads(answer)


def identity_of(opened):
    return {key: opened[key] for key in wire.IDENTITY_FIELDS}


def loopback(broker):
    """Client transport wired to an owner double without a socket: the same bytes, the same validators."""
    async def transport(settings, payload, *, response_limit, deadline):
        answer = await broker.handle(CONTROLLER_UID, payload)
        if answer is None:
            raise wire.WireError('truncated')
        return answer
    return transport


SETTINGS = client_module.Settings('/run/a4-offline/owner.sock', CONTROLLER_UID + 1, INSTALL, IMAGE)


# --------------------------------------------------------------------------- Unicode 4096 characters vs 8192 bytes (offline)

def test_unicode_command_over_byte_limit_is_rejected_whole_and_never_executed(tmp_path):
    three_byte = '€' * 4096                       # 4096 characters, 12288 UTF-8 bytes
    assert len(three_byte) == 4096 and len(three_byte.encode()) == 12288 > proto.MAX_COMMAND_BYTES == 8192
    with pytest.raises(proto.ProtocolError) as refused:
        wire.encode_request('execute', handle=HANDLE, command=three_byte)
    assert refused.value.reason == 'command_too_large'  # refused locally: never cut to a prefix that fits

    async def owner_side():
        runtime = RuntimeDouble()
        with real_inventory(tmp_path / 'diary', initialize=True) as inventory:
            broker = make_broker(runtime, inventory)
            await broker.reconcile()
            raw = json.dumps({'op': 'execute', 'handle': HANDLE, 'command': three_byte}, ensure_ascii=False).encode()
            assert len(raw) <= proto.MAX_REQUEST_BYTES   # inside the frame limit: the byte limit of the command decides
            answer = json.loads(await broker.handle(CONTROLLER_UID, raw))
            return answer, runtime.calls
    answer, calls = asyncio.run(owner_side())
    assert answer == {'ok': False, 'reason': 'command_too_large'}
    assert 'execute' not in calls and 'create' not in calls

    sent = []

    async def spy(settings, payload, *, response_limit, deadline):
        sent.append(payload)
        raise AssertionError('nothing may be sent for an oversize command')
    session = client_module.ActorSession(SETTINGS, run_id='b' * 32, variant='legitimate', transport=spy)
    session._handle = HANDLE  # an open handle: the refusal must still come from the byte limit, before any byte leaves
    with pytest.raises(client_module.ActorError) as error:
        asyncio.run(session.execute(three_byte))
    assert error.value.reason == 'command_too_large' and sent == []


@pytest.mark.parametrize('command,accepted', [
    ('a' * 4096, True),                      # control: 4096 ASCII characters is far below the byte limit
    ('a' * 8192, True),                      # control: exactly 8192 bytes
    ('a' * 8193, False),
    ('€' * 2730, True),                 # 2730 characters, 8190 bytes
    ('€' * 2731, False),                # 8193 bytes
    ('\U0001f600' * 2048, True),             # 2048 four-byte characters, exactly 8192 bytes
    ('\U0001f600' * 2049, False),
])
def test_command_limit_is_bytes_not_characters(command, accepted):
    if accepted:
        raw = wire.encode_request('execute', handle=HANDLE, command=command)
        assert proto.decode_request(raw).command == command            # whole and unchanged
    else:
        with pytest.raises(proto.ProtocolError) as refused:
            wire.encode_request('execute', handle=HANDLE, command=command)
        assert refused.value.reason == 'command_too_large'


def test_workflow_tool_argument_limit_stays_characters_and_owner_limit_stays_bytes():
    # Limits are kept, not unified: workflow admits <= 4096 characters; the owner then judges the bytes. Both numbers are pinned.
    assert proto.MAX_COMMAND_BYTES == 8192 and proto.MAX_REQUEST_BYTES == 16 * 1024
    assert wire.STREAM_CHARS == 4096

# ------------------------------------------------------- durable receipt, real SQLite diary + Docker double (simulation)
import sqlite3


def ledger(directory):
    with contextlib.closing(sqlite3.connect((directory / actor_state.storage.DATABASE).as_uri() + '?mode=ro', uri=True)) as db:
        return [(kind, json.loads(payload)) for kind, payload in db.execute('SELECT kind,payload FROM events ORDER BY sequence')]


async def full_run(broker, run_id, variant='legitimate'):
    opened = await rpc(broker, 'open', run_id=run_id, variant=variant)
    assert opened['ok'] is True, opened
    closed = await rpc(broker, 'close', handle=opened['handle'])
    assert closed['ok'] is True and closed['cleanup_confirmed'] is True
    return identity_of(opened), closed


READ_ONLY_CALLS = {'ready', 'installed_ids'}


@NONROOT
def test_response_lost_after_finish_is_recovered_after_owner_restart_and_a_later_run(tmp_path):
    diary = tmp_path / 'diary'

    async def first_life():
        runtime = RuntimeDouble()
        with real_inventory(diary, initialize=True) as inventory:
            broker = make_broker(runtime, inventory)
            await broker.reconcile()
            opened = await rpc(broker, 'open', run_id='1' * 32, variant='legitimate')
            await rpc(broker, 'close', handle=opened['handle'])   # FINISH is durable; the response is dropped on purpose
            return identity_of(opened)
    lost = asyncio.run(first_life())
    kinds = [kind for kind, _ in ledger(diary)]
    assert kinds == ['CREATE_PENDING', 'CREATE_ACK', 'START_PENDING', 'ACTIVE', 'CLOSE_PENDING', 'FINISH']

    async def second_life():
        runtime = RuntimeDouble()
        with real_inventory(diary, initialize=False) as inventory:       # owner restart over the same diary
            broker = make_broker(runtime, inventory)
            await broker.reconcile()
            before, events = list(runtime.calls), ledger(diary)
            receipt = await client_module.recover_receipt(SETTINGS, lost, transport=loopback(broker))
            assert runtime.calls == before and ledger(diary) == events   # a read: no Docker call, no event appended
            assert set(runtime.calls) <= READ_ONLY_CALLS
            later, _ = await full_run(broker, '2' * 32, 'perturbed')
            again = await client_module.recover_receipt(SETTINGS, lost, transport=loopback(broker))
            fresh = await client_module.recover_receipt(SETTINGS, later, transport=loopback(broker))
            return receipt, again, fresh, later
    receipt, again, fresh, later = asyncio.run(second_life())
    assert receipt == again and receipt['status'] == 'confirmed' and receipt['cleanup_confirmed'] is True
    assert {key: receipt[key] for key in wire.IDENTITY_FIELDS} == lost
    assert fresh['intent_id'] != lost['intent_id'] and later['run_id'] == '2' * 32   # the old receipt survived a newer close


@NONROOT
def test_cut_before_finish_keeps_obligation_and_confirms_only_after_reconciliation(tmp_path):
    diary = tmp_path / 'diary'

    async def first_life():
        runtime = RuntimeDouble()
        with real_inventory(diary, initialize=True) as inventory:
            broker = make_broker(runtime, inventory)
            await broker.reconcile()
            opened = await rpc(broker, 'open', run_id='3' * 32, variant='legitimate')
            return identity_of(opened)               # the owner stops here: ACTIVE, no CLOSE_PENDING, no FINISH
    ident = asyncio.run(first_life())
    assert [kind for kind, _ in ledger(diary)][-1] == 'ACTIVE'

    async def second_life():
        runtime = RuntimeDouble(container=ident['container_id'])
        runtime.installed.append(ident['container_id'])
        with real_inventory(diary, initialize=False) as inventory:
            broker = make_broker(runtime, inventory)          # NOT reconciled yet
            with pytest.raises(client_module.ActorError) as unknown:
                await client_module.recover_receipt(SETTINGS, ident, transport=loopback(broker))
            assert unknown.value.cleanup_confirmed is False and unknown.value.owner_reason == 'receipt_unknown'
            assert unknown.value.receipt_status == 'unknown'
            assert set(runtime.calls) <= READ_ONLY_CALLS and ledger(diary)[-1][0] == 'ACTIVE'
            await broker.reconcile()
            assert runtime.calls.count('close') == 1
            assert not {'create', 'start', 'execute', 'probe'} & set(runtime.calls)    # recovery never replays an action
            confirmed = await client_module.recover_receipt(SETTINGS, ident, transport=loopback(broker))
            return confirmed
    confirmed = asyncio.run(second_life())
    assert confirmed['status'] == 'confirmed' and ledger(diary)[-1][0] == 'FINISH'


@NONROOT
def test_unconfirmed_close_keeps_the_block_until_a_confirmed_reconciliation(tmp_path):
    diary = tmp_path / 'diary'

    async def first_life():
        with real_inventory(diary, initialize=True) as inventory:
            broker = make_broker(RuntimeDouble(), inventory)
            await broker.reconcile()
            return identity_of(await rpc(broker, 'open', run_id='4' * 32, variant='legitimate'))
    ident = asyncio.run(first_life())

    async def second_life():
        runtime = RuntimeDouble(container=ident['container_id'])
        runtime.installed.append(ident['container_id'])
        runtime.close_confirms = runtime.close_removes = False       # negative control: the runtime cannot confirm absence
        with real_inventory(diary, initialize=False) as inventory:
            broker = make_broker(runtime, inventory)
            await broker.reconcile()
            assert broker.status()['blocked'] == 'cleanup_unconfirmed'
            refused = await rpc(broker, 'open', run_id='5' * 32, variant='legitimate')
            assert refused == {'ok': False, 'reason': 'owner_blocked'}
            with pytest.raises(client_module.ActorError):
                await client_module.recover_receipt(SETTINGS, ident, transport=loopback(broker))
            runtime.close_confirms = runtime.close_removes = True    # positive control: absence can now be established
            await broker.reconcile()
            assert broker.status()['blocked'] is None
            return await client_module.recover_receipt(SETTINGS, ident, transport=loopback(broker))
    assert asyncio.run(second_life())['status'] == 'confirmed'


@NONROOT
def test_create_without_ack_is_never_resolved_by_an_empty_inventory_or_a_restart(tmp_path):
    diary = tmp_path / 'diary'

    async def first_life():
        runtime = RuntimeDouble()
        runtime.fail_create = True
        with real_inventory(diary, initialize=True) as inventory:
            broker = make_broker(runtime, inventory)
            await broker.reconcile()
            answer = await rpc(broker, 'open', run_id='6' * 32, variant='legitimate')
            assert answer['ok'] is False and broker.status()['blocked'] == 'create_uncertain'
            assert inventory.pending().phase == 'CREATE_PENDING' and inventory.pending().container_id is None
    asyncio.run(first_life())

    async def second_life():
        runtime = RuntimeDouble()                                  # an EMPTY inventory is not a receipt
        with real_inventory(diary, initialize=False) as inventory:
            broker = make_broker(runtime, inventory)
            await broker.reconcile()
            assert broker.status()['blocked'] == 'create_uncertain' and broker.status()['recovered'] is False
            assert await rpc(broker, 'open', run_id='7' * 32, variant='legitimate') == {'ok': False, 'reason': 'owner_blocked'}
            invented = {'installation_id': INSTALL, 'run_id': '6' * 32, 'variant': 'legitimate', 'intent_id': 'f' * 32,
                        'container_id': 'f' * 64}
            with pytest.raises(client_module.ActorError):
                await client_module.recover_receipt(SETTINGS, invented, transport=loopback(broker))
            assert 'create' not in runtime.calls and inventory.pending().phase == 'CREATE_PENDING'
    asyncio.run(second_life())


@NONROOT
def test_unknown_cross_installation_uid_and_link_queries_confirm_nothing(tmp_path):
    async def scenario():
        runtime = RuntimeDouble()
        with real_inventory(tmp_path / 'diary', initialize=True) as inventory:
            broker = make_broker(runtime, inventory)
            await broker.reconcile()
            ident, _ = await full_run(broker, '8' * 32, 'legitimate')
            exact = await client_module.recover_receipt(SETTINGS, ident, transport=loopback(broker))   # positive control
            assert exact['status'] == 'confirmed'
            crossed = {
                'unknown intent': {**ident, 'intent_id': 'd' * 32},
                'other container': {**ident, 'container_id': 'd' * 64},
                'other variant': {**ident, 'variant': 'perturbed'},
                'other run': {**ident, 'run_id': '9' * 32},
            }
            for label, query in crossed.items():
                with pytest.raises(client_module.ActorError, match='cleanup could not be confirmed') as refused:
                    await client_module.recover_receipt(SETTINGS, query, transport=loopback(broker))
                assert refused.value.cleanup_confirmed is False, label
                assert refused.value.owner_reason == 'receipt_unknown', label
            # Another installation: refused by the client pin, and by the owner when the pin is absent.
            other = {**ident, 'installation_id': 'b2' * 16}
            with pytest.raises(client_module.ActorError) as pinned:
                await client_module.recover_receipt(SETTINGS, other, transport=loopback(broker))
            assert pinned.value.owner_reason == 'installation_mismatch'
            unpinned = client_module.Settings(SETTINGS.socket_path, SETTINGS.owner_uid)
            with pytest.raises(client_module.ActorError) as owner:
                await client_module.recover_receipt(unpinned, other, transport=loopback(broker))
            assert owner.value.owner_reason == 'installation_mismatch'
            # Another UID: the owner says nothing at all, and the diary refuses the identity itself.
            assert await rpc(broker, 'receipt', uid=CONTROLLER_UID + 7, **ident) is None
            with pytest.raises(actor_state.StateError) as foreign:
                inventory.receipt(controller_uid=CONTROLLER_UID + 7, run_id=ident['run_id'], variant=ident['variant'],
                                  intent_id=ident['intent_id'], container_id=ident['container_id'])
            assert foreign.value.code == 'identity_changed'
    asyncio.run(scenario())


def test_health_and_an_empty_inventory_are_never_a_restitution_receipt():
    health = wire.encode_response('health', {'ready': True, 'image_id': IMAGE, 'installation_id': INSTALL,
                                             'obligations': 0, 'blocked': False})

    async def only_health(settings, payload, *, response_limit, deadline):
        return health
    ident = {'installation_id': INSTALL, 'run_id': 'a' * 32, 'variant': 'legitimate', 'intent_id': 'b' * 32,
             'container_id': 'c' * 64}
    session = client_module.ActorSession(SETTINGS, run_id=ident['run_id'], variant='legitimate', transport=only_health)
    session._handle, session._receipt, session.created = HANDLE, dict(ident), True
    with pytest.raises(client_module.ActorError) as close:
        asyncio.run(session.close())
    assert close.value.cleanup_confirmed is False and session.cleanup_confirmed is False and session.obligation is True
    with pytest.raises(client_module.ActorError) as receipt:
        asyncio.run(client_module.recover_receipt(SETTINGS, ident, transport=only_health))
    assert receipt.value.cleanup_confirmed is False and receipt.value.owner_reason == 'owner_response_invalid'

# ----------------------------------------- API reconciliation over recorded events (SQLite real, owner double, real wire)
ACTOR_SETTINGS = client_module.Settings('/run/a4-offline/owner.sock', os.geteuid() + 1)
DIGEST = 'ab' * 32


def clear_service_env(monkeypatch):
    for name in ('ESCAPE_PUBLIC_DEMO', 'ESCAPE_CATALOG_EXPERIMENT', 'ESCAPE_ROOMS_EXPERIMENT', 'ESCAPE_D4_CAMPAIGNS',
                 'ESCAPE_D5_REGRESSIONS', 'ESCAPE_CLEANUP_ON_STARTUP', 'ESCAPE_D2B_AUTHORIZED_DAY_UTC',
                 'ESCAPE_D2B_REQUIRE_AUTHORIZED_DAY'):
        monkeypatch.delenv(name, raising=False)


def run_events(ident, mutation):
    run_id, variant = ident['run_id'], ident['variant']
    requested = {'run_id': run_id, 'variant': variant, 'installation_id': INSTALL, 'image_id': IMAGE}
    events = [('actor_open_requested', requested), ('actor_identity', dict(ident))]
    started = {'run_id': run_id, 'variant': variant, 'artifact_sha256': DIGEST}
    finished = {**started, 'cleanup_confirmed': True}
    if mutation == 'no_identity':
        events = events[:1]                                               # open reached the owner; no binding was received
    elif mutation == 'foreign_run_event':
        events[1] = ('actor_identity', {**ident, 'run_id': '0' * 32})
    elif mutation == 'open_other_installation':
        events[0] = ('actor_open_requested', {**requested, 'installation_id': 'b2' * 16})
    elif mutation == 'unknown_intent':
        events[1] = ('actor_identity', {**ident, 'intent_id': 'd' * 32})
    elif mutation.startswith('verifier'):
        events += [('invoice_verifier_started', started)]
        if mutation == 'verifier_confirmed':
            events += [('invoice_verifier_finished', finished)]
        elif mutation == 'verifier_unconfirmed':
            events += [('invoice_verifier_finished', {**finished, 'cleanup_confirmed': False})]
        elif mutation == 'verifier_other_artifact':
            events += [('invoice_verifier_finished', {**finished, 'artifact_sha256': 'cd' * 32})]
        # verifier_never_finished: started, no terminal event
    return events


@NONROOT
@pytest.mark.parametrize('mutation,released', [
    ('plain', True), ('verifier_confirmed', True),                        # positive controls
    ('no_identity', False), ('verifier_never_finished', False), ('verifier_unconfirmed', False),
    ('verifier_other_artifact', False), ('unknown_intent', False), ('foreign_run_event', False),
    ('open_other_installation', False),
])
def test_reconciliation_releases_only_with_identity_and_confirmed_handoff(tmp_path, monkeypatch, mutation, released):
    clear_service_env(monkeypatch)
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'runs.sqlite'))
    main.init_db()
    real_recover = client_module.recover_receipt

    async def scenario():
        runtime = RuntimeDouble()
        with real_inventory(tmp_path / 'diary', initialize=True) as inventory:
            broker = make_broker(runtime, inventory)
            await broker.reconcile()
            run_id = '5' * 32
            ident, _ = await full_run(broker, run_id, 'legitimate')

            async def through_owner(settings, identity, *, transport=None):
                return await real_recover(settings, identity, transport=loopback(broker))
            monkeypatch.setattr(client_module, 'recover_receipt', through_owner)
            config = {'actor_boundary': {'schema': 'invoice-actor/v1', 'installation_id': INSTALL, 'image_id': IMAGE,
                                         'mission': missions.INVOICES.id, 'owner_uid': ACTOR_SETTINGS.owner_uid,
                                         'controller_uid': os.geteuid()}}
            block = {'reason': 'cleanup_unconfirmed', 'block_id': 'a4' * 16, 'run_id': run_id, 'levels': ['workflow'],
                     'cause': 'level_cleanup', 'at': recovery.now_iso()}
            with main.db() as c:
                c.execute('INSERT INTO runs VALUES(?,?,?,?,?)', (run_id, 'running', 'fixture', json.dumps(['workflow']), '{}'))
                c.execute('INSERT INTO run_config VALUES(?,?)', (run_id, json.dumps(config)))
                recovery.record_meta(c, run_id, 'fixture', recovery.now_iso())
                for kind, data in run_events(ident, mutation):
                    main.insert_event(c, run_id, kind, data)
            with main.db() as c:
                recovery.write_terminal(c, run_id, 'failed', {'workflow': {'outcome': 'error', 'cleanup_confirmed': False}},
                                        recovery.unavailable_usage(run_id, 'a4'), block)
            expected = recovery.read_state(main.DB, recovery.CLEANUP_BLOCK)
            assert expected is not None and expected['run_id'] == run_id
            outcome = await main.reconcile_actor_cleanup(ACTOR_SETTINGS, expected)
            return outcome, expected, run_id

    outcome, expected, run_id = asyncio.run(scenario())
    state = recovery.read_state(main.DB, recovery.CLEANUP_BLOCK)
    with main.db() as c:
        confirmed = [row[0] for row in c.execute("SELECT kind FROM events WHERE run_id=? AND kind='actor_recovery_confirmed'", (run_id,))]
    if released:
        assert outcome is True and state is None and confirmed == ['actor_recovery_confirmed']
    else:
        assert outcome is False and state == expected and confirmed == []   # the block survives, nothing is declared recovered


# ------------------------------------------- workflow hand-off requirements (fake actor session, no Docker, no provider)
class FakeActorSandbox:
    """Just enough of ActorSession for workflow.run_variant: a file system of two paths and the fixed probes."""

    def __init__(self, run_id, variant):
        self.run_id, self.variant = run_id, variant
        self.files, self.created, self.cleanup_confirmed, self.oom_killed = {}, True, False, None
        self.measurement = runner.unavailable_measurement()
        self.profile, self.profile_captured, self.name, self.obligation = {'available': False, 'reason': 'not captured'}, False, 'fake', True
        self.identity = {'installation_id': INSTALL, 'run_id': run_id, 'variant': variant, 'intent_id': 'e' * 32,
                         'container_id': 'f' * 64}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        self.cleanup_confirmed, self.obligation = True, False

    async def execute(self, command, timeout=10):
        done = {'stdout': '', 'stderr': '', 'exit_code': 0, **runner.unavailable_measurement()}
        words = shlex.split(command)
        if words[:2] == ['printf', '%s']:
            self.files[words[-1]] = words[2]
            return done
        return {**done, 'stdout': self.files.get(words[-1], '')}

    async def probe(self, name):
        return {'stdout': json.dumps(missions.INVOICES.expected, indent=2) + '\n', 'stderr': '', 'exit_code': 0,
                **runner.unavailable_measurement()}

    async def exec_fixed(self, script, timeout=10, *, output_limit=None):
        import base64
        text = (json.dumps(missions.INVOICES.expected, indent=2) + '\n').encode()
        return {'stdout': base64.b64encode(text).decode(), 'stderr': '', 'exit_code': 0, **runner.unavailable_measurement()}


async def no_tool_call(model, messages, *, tools=True):
    return {'role': 'assistant', 'content': 'done'}


def drive_variant(monkeypatch, attest_result, *, open_error=None, attest_double=None):
    events, sessions = [], []
    monkeypatch.setattr(provider, 'complete', no_tool_call)

    class Opening:
        def __new__(cls, *a, **k):
            if open_error is not None:
                class Failing:
                    async def __aenter__(self):
                        raise open_error
                    async def __aexit__(self, *exc):
                        return False
                return Failing()
            return FakeActorSandbox('7' * 32, 'legitimate')
    monkeypatch.setattr(runner, 'new_session', lambda run_id, variant, *, actor=None: Opening())

    async def attest(settings, artifact, **binding):
        return attest_result
    monkeypatch.setattr(invoice_verification, 'attest', attest if attest_double is None else attest_double)
    independent = invoice_verification.Settings('/run/a4-offline/guard.sock', 65532, durable=True)

    async def go():
        return await workflow.run_variant('7' * 32, 'fixture', 'legitimate', lambda run, kind, data: events.append((kind, data)),
                                          lambda *a, **k: None, sessions, missions.INVOICES, independent=independent,
                                          actor=ACTOR_SETTINGS)
    return go, events


def test_workflow_handoff_with_confirmed_verifier_cleanup_is_released(monkeypatch):
    passed = {'schema': invoice_verification.SCHEMA, 'status': 'passed', 'artifact_sha256': DIGEST, 'input_sha256': DIGEST,
              'verifier_sha256': DIGEST, 'container_id': DIGEST, 'cleanup_confirmed': True}
    go, events = drive_variant(monkeypatch, passed)
    record = asyncio.run(go())
    kinds = [kind for kind, _ in events]
    assert record['independent_verification']['cleanup_confirmed'] is True and record['cleanup_confirmed'] is True
    assert [kind for kind in kinds if kind != 'receipt'] == ['actor_open_requested', 'actor_identity',
                                                              'invoice_verifier_started', 'invoice_verifier_finished']


def test_workflow_blocks_when_the_verifier_handoff_has_no_confirmed_closure(monkeypatch):
    unconfirmed = {'schema': invoice_verification.SCHEMA, 'status': 'passed', 'artifact_sha256': DIGEST, 'input_sha256': DIGEST,
                   'verifier_sha256': DIGEST, 'container_id': DIGEST, 'cleanup_confirmed': False}
    go, events = drive_variant(monkeypatch, unconfirmed)
    with pytest.raises(runner.RunnerError, match='verifier cleanup could not be confirmed') as blocked:
        asyncio.run(go())
    assert blocked.value.cleanup_confirmed is False
    finished = [data for kind, data in events if kind == 'invoice_verifier_finished']
    assert len(finished) == 1 and finished[0]['cleanup_confirmed'] is False


def test_workflow_blocks_when_open_never_delivered_an_identity(monkeypatch):
    go, events = drive_variant(monkeypatch, None, open_error=client_module.ActorError('owner_unavailable'))
    with pytest.raises(client_module.ActorError) as blocked:
        asyncio.run(go())
    kinds = [kind for kind, _ in events]
    assert blocked.value.cleanup_confirmed is False          # unknown means blocked, never "nothing was created"
    assert kinds == ['actor_open_requested'] and 'actor_identity' not in kinds

# ---------------------- A4b focal regressions: cancellation while the independent verifier's answer is awaited (doubles only)
# Simulation, not measurement: the attestation is a double that waits on a barrier the test controls; there is no guard and no
# Docker. The real guard path with a really running verifier is test_scenario_cancel_api_verifier (root operator, Linux/Docker).
class AttestBarrier:
    """`invoice_verification.attest` double. It waits (bounded) on a release the test controls, so a cancellation can be delivered
    while the verifier result is still pending. `cancelled` records that the awaited attestation itself was cancelled."""

    def __init__(self, result):
        self.result, self.cancelled = result, False
        self.entered = self.release = None

    def bind(self):
        self.entered, self.release = asyncio.Event(), asyncio.Event()      # created inside the running loop

    async def __call__(self, settings, artifact, **binding):
        self.entered.set()
        try:
            async with asyncio.timeout(30):
                await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        return self.result


def verifier_result(cleanup):
    return {'schema': invoice_verification.SCHEMA, 'status': 'passed', 'artifact_sha256': DIGEST, 'input_sha256': DIGEST,
            'verifier_sha256': DIGEST, 'container_id': DIGEST, 'cleanup_confirmed': cleanup}


# (id, cancellations delivered while the verifier is awaited, cleanup flag of the answer or None when no answer is ever delivered)
ATTEST_CANCEL_CASES = [
    ('cancel_then_uncertain_cleanup', 1, False),
    ('second_cancel_before_any_answer', 2, None),
    ('cancel_then_confirmed_cleanup_control', 1, True),          # positive control: a confirmed closure claims no uncertainty
    ('no_cancel_uncertain_cleanup_control', 0, False),           # control: without a cancellation the cleanup error is what is raised
]


@pytest.mark.parametrize('label,cancels,cleanup', ATTEST_CANCEL_CASES, ids=[case[0] for case in ATTEST_CANCEL_CASES])
def test_cancellation_while_the_verifier_is_awaited_keeps_the_original_exception_and_the_cleanup_obligation(
        monkeypatch, label, cancels, cleanup):
    barrier = AttestBarrier(None if cleanup is None else verifier_result(cleanup))
    go, events = drive_variant(monkeypatch, None, attest_double=barrier)
    caught = {}

    async def captured():
        try:
            return await go()
        except BaseException as exc:          # the exception object exactly as workflow.run_variant propagated it
            caught['exc'] = exc
            raise

    async def scenario():
        barrier.bind()
        task = asyncio.ensure_future(captured())
        try:
            await asyncio.wait_for(barrier.entered.wait(), 30)
            for _ in range(cancels):
                task.cancel()
                for _ in range(3):             # event-loop turns, not wall-clock time: the task reaches its next suspension point
                    await asyncio.sleep(0)
            if cancels == 1:
                # The cancellation must wait for the verifier's answer, not abandon it: nothing is terminal while it is pending.
                assert not task.done(), 'the cancellation abandoned the verifier instead of waiting for its answer'
                assert 'invoice_verifier_finished' not in [kind for kind, _ in events]
            if cancels != 2:
                barrier.release.set()
            done, _ = await asyncio.wait({task}, timeout=20)
            assert done, 'run_variant did not end: a second cancellation must interrupt the wait for the answer'
            if not task.cancelled():
                task.exception()               # retrieved here; the failure itself is asserted below through `caught`
        finally:
            barrier.release.set()
            if not task.done():
                task.cancel()
    asyncio.run(scenario())

    exc = caught.get('exc')
    seen = [kind for kind, _ in events if kind != 'receipt']
    started = [data for kind, data in events if kind == 'invoice_verifier_started']
    finished = [data for kind, data in events if kind == 'invoice_verifier_finished']
    assert exc is not None and len(started) == 1
    if cancels:
        assert isinstance(exc, asyncio.CancelledError) and not isinstance(exc, runner.RunnerError)   # the cancellation, never a cleanup error
    else:
        assert isinstance(exc, runner.RunnerError) and not isinstance(exc, asyncio.CancelledError)
        assert 'verifier cleanup could not be confirmed' in str(exc)
    if cleanup is True:
        assert getattr(exc, 'cleanup_confirmed', None) is not False          # confirmed closure: no uncertainty is claimed
    else:
        assert getattr(exc, 'cleanup_confirmed', None) is False              # the obligation stays whenever closure is not confirmed
    if cleanup is None:                                                       # a second cancellation arrived before any answer
        assert finished == [] and barrier.cancelled is True
        assert seen == ['actor_open_requested', 'actor_identity', 'invoice_verifier_started']
    else:
        assert len(finished) == 1 and finished[0]['artifact_sha256'] == started[0]['artifact_sha256']
        assert finished[0]['cleanup_confirmed'] is cleanup and barrier.cancelled is False
        assert seen == ['actor_open_requested', 'actor_identity', 'invoice_verifier_started', 'invoice_verifier_finished']


# (id, cancellations, cleanup flag of the answer or None, terminal status, admission closed afterwards)
MAIN_CANCEL_CASES = [
    ('cancel_then_uncertain_cleanup', 1, False, 'cancelled', True),
    ('second_cancel_before_any_answer', 2, None, 'cancelled', True),
    ('cancel_then_confirmed_cleanup_control', 1, True, 'cancelled', False),
    ('no_cancel_uncertain_cleanup_control', 0, False, 'failed', True),
]


@pytest.mark.skipif(not hasattr(os, 'geteuid'), reason='actor settings need POSIX UIDs')
@pytest.mark.parametrize('label,cancels,cleanup,status,closed', MAIN_CANCEL_CASES, ids=[case[0] for case in MAIN_CANCEL_CASES])
def test_run_levels_closes_admission_after_a_cancelled_run_only_when_verifier_cleanup_is_unconfirmed(
        tmp_path, monkeypatch, label, cancels, cleanup, status, closed):
    # The same doubles one level up: main.run_levels over real SQLite, so the cancellation's effect on the terminal row, the cleanup
    # block and admission is observed, not inferred from the exception alone.
    actor_service_env(monkeypatch, tmp_path)
    main.init_db()
    monkeypatch.setattr(main, 'execution_slots', None)
    monkeypatch.setattr(main, 'active', set())
    run_id, barrier = '6' * 32, AttestBarrier(None if cleanup is None else verifier_result(cleanup))

    async def owner_absent(settings, identity, *, transport=None):
        raise client_module.ActorError('owner_unavailable')      # no owner exists in this offline pass: nothing can confirm a FINISH
    monkeypatch.setattr(client_module, 'recover_receipt', owner_absent)
    monkeypatch.setattr(provider, 'complete', no_tool_call)
    monkeypatch.setattr(runner, 'new_session', lambda run, variant, *, actor=None: FakeActorSandbox(run, variant))
    monkeypatch.setattr(invoice_verification, 'attest', barrier)
    independent = invoice_verification.Settings('/run/a4-offline/guard.sock', 65532, durable=True)
    config = {'mission': missions.INVOICES.id,
              'actor_boundary': {'schema': 'invoice-actor/v1', 'installation_id': INSTALL, 'image_id': IMAGE,
                                 'mission': missions.INVOICES.id, 'owner_uid': ACTOR_SETTINGS.owner_uid,
                                 'controller_uid': os.geteuid()}}
    bound_actor = client_module.Settings(ACTOR_SETTINGS.socket_path, ACTOR_SETTINGS.owner_uid, INSTALL, IMAGE,
        context_sha256=main.experiment.execution_context_digest(run_id, 'fixture', ['workflow'], config))
    with main.db() as c:
        c.execute('INSERT INTO runs VALUES(?,?,?,?,?)', (run_id, 'queued', 'fixture', json.dumps(['workflow']), '{}'))
        c.execute('INSERT INTO run_config VALUES(?,?)', (run_id, json.dumps(config)))
        recovery.record_meta(c, run_id, 'fixture', recovery.now_iso())
        main.insert_event(c, run_id, 'run', {'id': run_id, 'status': 'queued'})

    async def scenario():
        barrier.bind()
        task = asyncio.ensure_future(main.run_levels(run_id, 'fixture', ['workflow'], independent=independent, actor=bound_actor))
        try:
            await asyncio.wait_for(barrier.entered.wait(), 30)
            for _ in range(cancels):
                task.cancel()
                for _ in range(3):             # event-loop turns, not wall-clock time
                    await asyncio.sleep(0)
            if cancels == 1:
                assert not task.done(), 'the cancellation abandoned the verifier instead of waiting for its answer'
            if cancels != 2:
                barrier.release.set()
            done, _ = await asyncio.wait({task}, timeout=30)
            assert done, 'run_levels did not end'
            if not task.cancelled():
                task.exception()
        finally:
            barrier.release.set()
            if not task.done():
                task.cancel()
        return task
    task = asyncio.run(scenario())

    run = main.get_run(run_id)
    summary = run['summary']['workflow']
    block = recovery.read_state(main.DB, recovery.CLEANUP_BLOCK)
    with main.db() as c:
        seen = [row[0] for row in c.execute('SELECT kind FROM events WHERE run_id=? ORDER BY seq', (run_id,))]
    assert run['status'] == status and task.cancelled() is (status == 'cancelled')
    assert seen.count('invoice_verifier_started') == 1 and seen.count('invoice_verifier_finished') == (0 if cleanup is None else 1)
    if closed:
        assert summary['cleanup_confirmed'] is False
        assert block is not None and block['reason'] == 'cleanup_unconfirmed' and block['run_id'] == run_id and block['levels'] == ['workflow']
        assert main.admission_block()['reason'] == 'cleanup_unconfirmed'
        with pytest.raises(recovery.AdmissionClosed):
            main.admit_run('5' * 32, 'fixture', ['workflow'], {})
        with main.db() as c:
            assert c.execute('SELECT count(*) FROM runs').fetchone()[0] == 1       # nothing was admitted behind the block
    else:
        assert summary['cleanup_confirmed'] is True
        assert block is None and main.admission_block() is None


# --------------------------------------------- branches of the A1 map: safe rejection before anything is reserved (offline)
from services.agent import budget


def actor_service_env(monkeypatch, tmp_path, **extra):
    clear_service_env(monkeypatch)
    uid = os.geteuid()
    values = {'ESCAPE_ACTOR_BROKER_SOCKET': '/run/a4-offline/owner.sock', 'ESCAPE_ACTOR_BROKER_UID': str(uid + 1),
              'ESCAPE_INVOICE_VERIFIER_SOCKET': '/run/a4-offline/guard.sock', 'ESCAPE_INVOICE_VERIFIER_UID': str(uid + 2),
              'ESCAPE_INVOICE_VERIFIER_DURABLE': '1', 'ESCAPE_OPERATOR_TOKEN': 'a4-offline', 'ESCAPE_MODEL': 'fixture',
              'VULTR_INFERENCE_KEY': 'unused-fixture-key', 'ESCAPE_EVIDENCE_ORIGIN': 'fixture',
              'ESCAPE_CONCURRENT_RUNS': '1', 'ESCAPE_QUEUE_CAPACITY': '0', **extra}
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'runs.sqlite'))
    main.rate_windows.clear()


AUTH = {'Authorization': 'Bearer a4-offline'}
INVOICE_BODY = {'model': 'fixture', 'levels': ['workflow'], 'mission': missions.INVOICES.id}
UNSUPPORTED = [
    ('level secret', {'model': 'fixture', 'levels': ['secret']}, {}),
    ('level network', {'model': 'fixture', 'levels': ['network']}, {}),
    ('level memory', {'model': 'fixture', 'levels': ['memory']}, {}),
    ('level persistence', {'model': 'fixture', 'levels': ['persistence']}, {}),
    ('invoice mission mixed with another level', {**INVOICE_BODY, 'levels': ['workflow', 'secret']}, {}),
    ('room processes', {'model': 'fixture', 'levels': ['processes']}, {'ESCAPE_ROOMS_EXPERIMENT': '1'}),
    ('room privileges', {'model': 'fixture', 'levels': ['privileges']}, {'ESCAPE_ROOMS_EXPERIMENT': '1'}),
    ('catalog D3 cell', {'model': 'fixture', 'levels': ['workflow'], 'mission': main.D3_MISSION, 'catalog_profile': 'A',
                         'catalog_variant': 'legitimate'}, {}),
    ('invoice with injection variant', {**INVOICE_BODY, 'injection_variant': 'warned-v1'}, {}),
]


@pytest.mark.skipif(not hasattr(os, 'geteuid'), reason='actor settings need POSIX UIDs')
@pytest.mark.parametrize('label,body,extra', UNSUPPORTED, ids=[item[0] for item in UNSUPPORTED])
def test_unsupported_branches_are_rejected_before_reserving_anything(tmp_path, monkeypatch, label, body, extra):
    actor_service_env(monkeypatch, tmp_path, **extra)
    with TestClient(main.app, headers=AUTH) as client:
        quota = budget.snapshot(main.DB)
        refused = client.post('/api/runs', json=body)
        assert refused.status_code in (404, 422), (label, refused.status_code, refused.text)
        assert main.active == set() and budget.snapshot(main.DB) == quota
        with main.db() as c:
            assert c.execute('SELECT count(*) FROM runs').fetchone()[0] == 0


@pytest.mark.skipif(not hasattr(os, 'geteuid'), reason='actor settings need POSIX UIDs')
def test_supported_invoice_request_passes_the_branch_gate_and_stops_at_the_owner(tmp_path, monkeypatch):
    # Positive control for the table above: the same service admits the isolated branch up to the owner health check, which fails
    # here because no owner exists in this offline pass. 503 (owner) and not 422 (branch gate) is what distinguishes it.
    actor_service_env(monkeypatch, tmp_path)
    with TestClient(main.app, headers=AUTH) as client:
        answer = client.post('/api/runs', json=INVOICE_BODY)
        assert answer.status_code == 503 and 'Actor service is unavailable' in answer.text
        assert main.active == set()
        with main.db() as c:
            assert c.execute('SELECT count(*) FROM runs').fetchone()[0] == 0


@pytest.mark.skipif(not hasattr(os, 'geteuid'), reason='actor settings need POSIX UIDs')
@pytest.mark.parametrize('flag', ['ESCAPE_D4_CAMPAIGNS', 'ESCAPE_D5_REGRESSIONS', 'ESCAPE_CATALOG_EXPERIMENT', 'ESCAPE_PUBLIC_DEMO'])
def test_campaign_regression_catalog_and_public_services_refuse_to_start_with_an_actor(tmp_path, monkeypatch, flag):
    actor_service_env(monkeypatch, tmp_path, **{flag: '1'})
    with pytest.raises(ValueError, match='private standalone durable invoice configuration'):
        with TestClient(main.app):
            pass


# ------------------------------------------------------------------ inheritance of the four A2 receipts by hash and diff
def sha256_of(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inheritance_problems(manifest, root):
    """Closed list of (reason, path). Empty means the inherited evidence still describes the integrated sources."""
    found = []
    for item in manifest['receipts']:
        path = Path(root) / item['path']
        if not path.is_file():
            found.append(('receipt_missing', item['path']))
        elif sha256_of(path) != item['sha256']:
            found.append(('receipt_hash_changed', item['path']))
        if item['inherited_scope'] != 'verifier guard lifecycle only':
            found.append(('scope_widened', item['path']))
    for dep in manifest['dependencies']:
        path = Path(root) / dep['path']
        if not path.is_file():
            found.append(('dependency_missing', dep['path']))
        elif sha256_of(path) != dep['current_sha256']:
            found.append(('dependency_changed_after_review', dep['path']))
        if dep['changed'] is not (dep['a2_sha256'] != dep['current_sha256']):
            found.append(('diff_flag_inconsistent', dep['path']))
    return found


INHERITANCE = REPO / 'docs/evidencia/sc3-lifecycle/a4b-herencia-a2.json'
A4_DELTA = {'services/agent/workflow.py': ('test_scenario_cancel_api', 'test_workflow_blocks_when_the_verifier_handoff_has_no_confirmed_closure',
                                           'test_workflow_blocks_when_open_never_delivered_an_identity',
                                           # A4b: the delta of workflow.py is the exception propagated when a cancellation and an
                                           # uncertain verifier cleanup coincide. Named controls: focal doubles, run_levels, real guard.
                                           'test_cancellation_while_the_verifier_is_awaited_keeps_the_original_exception_and_the_cleanup_obligation',
                                           'test_run_levels_closes_admission_after_a_cancelled_run_only_when_verifier_cleanup_is_unconfirmed',
                                           'test_scenario_cancel_api_verifier')}


@pytest.mark.skipif(not INHERITANCE.is_file(), reason='inheritance manifest not present in this checkout')
def test_a2_receipts_are_inherited_by_hash_and_only_the_invalidated_part_is_repeated():
    manifest = json.loads(INHERITANCE.read_text(encoding='utf-8'))
    assert [Path(item['path']).stem for item in manifest['receipts']] == [
        'kill-running', 'cancel-client', 'second-guard-exclusion', 'two-runs-foreign-sentinel']
    assert inheritance_problems(manifest, REPO) == []
    changed = {dep['path'] for dep in manifest['dependencies'] if dep['changed']}
    assert changed == set(A4_DELTA)                  # every changed dependency has a named A4 control; nothing else is repeated
    mine = {name for names in A4_DELTA.values() for name in names}
    assert mine <= set(globals()) | {'test_scenario_cancel_api'}


@pytest.mark.skipif(not INHERITANCE.is_file(), reason='inheritance manifest not present in this checkout')
@pytest.mark.parametrize('tamper', ['receipt', 'dependency', 'scope', 'flag'])
def test_inheritance_check_detects_a_tampered_manifest(tamper):
    manifest = json.loads(INHERITANCE.read_text(encoding='utf-8'))
    if tamper == 'receipt':
        manifest['receipts'][0]['sha256'] = '0' * 64
    elif tamper == 'dependency':
        manifest['dependencies'][0]['current_sha256'] = '0' * 64
    elif tamper == 'scope':
        manifest['receipts'][1]['inherited_scope'] = 'service cancellation'
    else:
        manifest['dependencies'][-1]['changed'] = False
    assert inheritance_problems(manifest, REPO)

# ==================================================================================================================
# Controller-side scenarios (UID 65534, no Docker access). The root operator drives the cut points through file handshakes:
# the controller writes <name>.json and blocks, bounded, until the operator writes <name>.ack. Nothing waits on a bare sleep.
# ==================================================================================================================
import errno

CONTROL = Path(os.environ['ESCAPE_A4_CONTROL']) if os.getenv('ESCAPE_A4_CONTROL') else None
PHASE = os.getenv('ESCAPE_A4_PHASE', 'cut')
HEADERS = {'Authorization': 'Bearer local-actor-service-test'}
REQUEST = {'model': 'fixture', 'levels': ['workflow'], 'mission': missions.INVOICES.id}
WAIT = 45.0


def checkpoint(name, payload=None, timeout=WAIT):
    temporary = CONTROL / f'.{name}.tmp'
    temporary.write_text(json.dumps(payload or {}, sort_keys=True), encoding='utf-8')
    os.replace(temporary, CONTROL / f'{name}.json')
    deadline = time.monotonic() + timeout
    while not (CONTROL / f'{name}.ack').exists():
        if time.monotonic() > deadline:
            pytest.fail(f'operator did not acknowledge checkpoint {name}')
        time.sleep(0.02)


def wait_until(predicate, timeout, what):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            pytest.fail('timed out waiting for ' + what)
        time.sleep(0.02)


class Rig:
    """Provider double, session tracking and the observation of workflow.run_variant."""

    def __init__(self):
        self.sessions, self.variants, self.calls = [], [], []
        self.block_first, self.entered, self.gate, self._blocked = False, threading.Event(), threading.Event(), False
        self.good = json.dumps(missions.INVOICES.expected, indent=2) + '\n'


@pytest.fixture
def rig(monkeypatch):
    if CONTROL is None:
        pytest.fail('scenario tests run only through the A4 root operator')
    monkeypatch.setattr(main, 'DB', os.environ['ESCAPE_A4_DB'])
    main.rate_windows.clear()
    state = Rig()
    factory, original_variant = runner.new_session, workflow.run_variant

    def tracked(run_id, variant, *, actor=None):
        assert actor is not None
        session = factory(run_id, variant, actor=actor)
        state.sessions.append(session)
        return session

    async def forbidden(*args, **kwargs):
        raise AssertionError('controller invoked a direct Docker path')

    async def complete(model, messages, *, tools=True):
        state.calls.append(model)
        if any(message['role'] == 'tool' for message in messages):
            return {'role': 'assistant', 'content': 'done'}
        if state.block_first and not state._blocked:
            state._blocked = True
            state.entered.set()
            await asyncio.to_thread(state.gate.wait, 60)       # released by the test body; bounded
        text = state.good if state.sessions[-1].variant == 'legitimate' else state.good.replace('2750', '5500')
        command = 'printf %s ' + shlex.quote(text) + ' > /work/result.json'
        return {'role': 'assistant', 'tool_calls': [{'id': 'fixture', 'type': 'function',
                'function': {'name': 'run_shell', 'arguments': json.dumps({'command': command})}}]}

    async def observed_variant(run_id, model, name, *args, **kwargs):
        state.variants.append(name)
        return await original_variant(run_id, model, name, *args, **kwargs)

    monkeypatch.setattr(runner, 'new_session', tracked)
    monkeypatch.setattr(runner, '_cli', forbidden)
    monkeypatch.setattr(provider, 'complete', complete)
    monkeypatch.setattr(workflow, 'run_variant', observed_variant)
    yield state
    state.gate.set()


def start_run(client):
    started = client.post('/api/runs', json=REQUEST)
    assert started.status_code == 202, started.text
    return started.json()['id']


def wait_terminal(client, run_id, timeout=70):
    box = {}

    def done():
        box['run'] = client.get(f'/api/runs/{run_id}').json()
        return box['run']['status'] in main.TERMINAL
    wait_until(done, timeout, 'terminal status of ' + run_id)
    return box['run']


def durable_events(run_id):
    with main.db() as c:
        return [(row['kind'], json.loads(row['data'])) for row in
                c.execute('SELECT kind,data FROM events WHERE run_id=? ORDER BY seq', (run_id,))]


def durable_identity(run_id, variant):
    found = [data for kind, data in durable_events(run_id) if kind == 'actor_identity' and data['variant'] == variant]
    assert len(found) == 1, found
    return found[0]


def pinned_settings(run_id):
    boundary = main.get_run_config(run_id)['actor_boundary']
    base = client_module.settings_from_env()
    return client_module.Settings(base.socket_path, base.owner_uid, boundary['installation_id'], boundary['image_id'])


def recovered(settings, identity):
    return asyncio.run(client_module.recover_receipt(settings, identity))


def refused(settings, identity):
    with pytest.raises(client_module.ActorError) as error:
        asyncio.run(client_module.recover_receipt(settings, identity))
    assert error.value.cleanup_confirmed is False
    return error.value


def sealed(report):
    core = {key: value for key, value in report.items() if key != 'sha256'}
    digest = hashlib.sha256(json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    assert digest == report['sha256']


def controller_facts():
    """UID, capabilities, denied Docker endpoints, journals and SO_PEERCRED of both owners, seen from the controller."""
    status = dict(line.split(':', 1) for line in open('/proc/self/status') if ':' in line)
    facts = {'pid': os.getpid(), 'uid': os.geteuid(), 'groups': os.getgroups(),
             'cap_eff': status['CapEff'].strip(), 'cap_prm': status['CapPrm'].strip(), 'cap_bnd': status['CapBnd'].strip(),
             'no_new_privileges': int(status['NoNewPrivs']), 'interfaces': [name for _, name in socket.if_nameindex()]}
    assert facts['uid'] == 65534 and facts['groups'] == [] and facts['no_new_privileges'] == 1
    assert all(int(facts[key], 16) == 0 for key in ('cap_eff', 'cap_prm', 'cap_bnd')) and facts['interfaces'] == ['lo']
    denied = {}
    for path in json.loads(os.environ['ESCAPE_TEST_DOCKER_ENDPOINTS']):
        with socket.socket(socket.AF_UNIX) as peer:
            try:
                peer.connect(path)
            except OSError as exc:
                denied[path] = errno.errorcode[exc.errno]
            else:
                pytest.fail('controller reached a Docker endpoint')
    for directory in json.loads(os.environ['ESCAPE_TEST_OWNER_JOURNALS']):
        with pytest.raises(PermissionError):
            os.listdir(directory)
    peers = {}
    for role, path, uid in (('actor', os.environ['ESCAPE_ACTOR_BROKER_SOCKET'], 1000),
                            ('guard', os.environ['ESCAPE_INVOICE_VERIFIER_SOCKET'], 65532)):
        with socket.socket(socket.AF_UNIX) as peer:
            try:
                peer.connect(path)
            except OSError as exc:
                peers[role] = {'unreachable': errno.errorcode.get(exc.errno, str(exc.errno))}
                continue
            pid, peer_uid, gid = struct.unpack('=iII', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            assert peer_uid == uid
            peers[role] = {'pid': pid, 'uid': peer_uid, 'gid': gid}
    return {**facts, 'docker_endpoints_denied': denied, 'owner_journals_denied': True, 'so_peercred': peers}


def proof(name, **fields):
    print('A4_PROOF=' + json.dumps({'scenario': SCENARIO, 'phase': PHASE, 'check': name, **fields}, sort_keys=True), flush=True)


def completed_with_expected_verdicts(client, run_id):
    run = wait_terminal(client, run_id)
    assert run['status'] == 'completed', run['summary']
    report = client.get(f'/api/runs/{run_id}/report')
    assert report.status_code == 200
    data = report.json()
    sealed(data)
    variants = data['run']['summary']['workflow']['variants']
    assert [variants[name]['task']['status'] for name in ('legitimate', 'perturbed')] == ['passed', 'failed']
    assert variants['legitimate']['independent_verification']['status'] == 'passed'
    assert variants['perturbed']['independent_verification']['reason'] == 'actor_task_not_passed'
    assert all(item['cleanup_confirmed'] is True for item in variants.values())
    # The terminal row is committed before `active` is released: wait for the observable release, not for a guess.
    wait_until(lambda: not main.active, 15, 'the finished run to release its slot')
    return data


# ------------------------------------------------------------------------------------------------- cancel by API, ACTIVE
@scenario_only('cancel-api')
def test_scenario_cancel_api(rig):
    rig.block_first = True
    facts = controller_facts()
    with TestClient(main.app, headers=HEADERS) as client:
        run_id = start_run(client)
        wait_until(rig.entered.is_set, 40, 'a provider call after the actor became ACTIVE')
        assert rig.variants == ['legitimate'] and len(rig.sessions) == 1        # workflow.run_variant observed, actor open
        identity = durable_identity(run_id, 'legitimate')
        checkpoint('active', {'run_id': run_id, 'identity': identity})
        premature = client.post('/api/runs', json=REQUEST)                       # the only plaza is occupied
        assert premature.status_code == 409 and len(main.active) == 1
        cancel = client.post(f'/api/runs/{run_id}/cancel')
        assert cancel.status_code == 200
        assert main.cancel_marked(run_id) is True                                 # durable request, not only the HTTP answer
        run = wait_terminal(client, run_id)
        rig.gate.set()
        assert run['status'] == 'cancelled'
        workflow_summary = run['summary']['workflow']
        assert workflow_summary['outcome'] == 'error' and workflow_summary.get('cleanup_confirmed') is True
        assert rig.sessions[0].cleanup_confirmed is True and rig.sessions[0].obligation is False
        settings = pinned_settings(run_id)
        receipt = recovered(settings, identity)                                   # the owner's durable FINISH, not health
        assert receipt['status'] == 'confirmed'
        info = asyncio.run(client_module.health(settings))
        assert info['obligations'] == 0 and info['blocked'] is False and info['ready'] is True
        assert recovery.read_state(main.DB, recovery.CLEANUP_BLOCK) is None
        report_path = f'/api/runs/{run_id}/report'
        first, markdown = client.get(report_path), client.get(report_path, params={'format': 'md'})
        assert first.status_code == 200 and markdown.status_code == 200
        sealed(first.json())
        assert first.json()['run']['status'] == 'cancelled'
        checkpoint('terminal', {'run_id': run_id, 'identity': identity, 'receipt': receipt})
    with TestClient(main.app, headers=HEADERS) as reopened:                       # new service process state, same SQLite
        assert reopened.get(report_path).content == first.content
        assert reopened.get(report_path, params={'format': 'md'}).content == markdown.content
        assert main.cancel_marked(run_id) is True
    proof('cancel_api', run_id=run_id, identity=identity, cancel_http=200, premature_http=409, controller=facts,
          provider_calls=len(rig.calls))

# ---------------------------------------------------------------------- shared phases after an owner/service interruption
def interrupted_run_id():
    block = recovery.read_state(main.DB, recovery.CLEANUP_BLOCK)
    assert block is not None and block['reason'] == 'cleanup_unconfirmed'
    return block['run_id'], block


def recovery_confirmed(run_id):
    return [data for kind, data in durable_events(run_id) if kind == 'actor_recovery_confirmed']


def phase_blocked(rig):
    """Owner still absent: a service restart must neither confirm nor admit. Read-only in the owner; nothing is replayed."""
    with TestClient(main.app, headers=HEADERS) as client:
        run_id, block = interrupted_run_id()
        assert recovery.read_state(main.DB, recovery.CLEANUP_BLOCK) == block      # the startup attempt did not clear it
        assert recovery_confirmed(run_id) == []
        identity = durable_identity(run_id, 'legitimate')
        error = refused(pinned_settings(run_id), identity)
        assert client.post('/api/runs', json=REQUEST).status_code == 503           # admission stays closed
        proof('blocked_while_owner_absent', run_id=run_id, owner_reason=error.owner_reason, admission_http=503)


def phase_recover(rig, *, negatives):
    with TestClient(main.app, headers=HEADERS) as client:
        with main.db() as c:
            row = c.execute("SELECT run_id FROM events WHERE kind='actor_recovery_confirmed' ORDER BY seq").fetchone()
        assert row is not None, 'service startup did not reconcile the recorded actor bindings'
        run_id = row['run_id']
        assert recovery.read_state(main.DB, recovery.CLEANUP_BLOCK) is None
        assert len(recovery_confirmed(run_id)) == 1
        identity = durable_identity(run_id, 'legitimate')
        settings = pinned_settings(run_id)
        original = recovered(settings, identity)
        assert original['status'] == 'confirmed' and original['cleanup_confirmed'] is True
        if negatives:
            crossed = {'unknown intent': {**identity, 'intent_id': 'd' * 32}, 'other container': {**identity, 'container_id': 'd' * 64},
                       'other variant': {**identity, 'variant': 'perturbed'}, 'other run': {**identity, 'run_id': 'd' * 32}}
            reasons = {label: refused(settings, query).owner_reason for label, query in crossed.items()}
            assert set(reasons.values()) == {'receipt_unknown'}
            unpinned = client_module.Settings(settings.socket_path, settings.owner_uid)
            foreign = asyncio.run(_installation_query(unpinned, identity))
            assert foreign == 'installation_mismatch'
        report_before = client.get(f'/api/runs/{run_id}/report')
        assert report_before.status_code == 200
        later = start_run(client)                                                  # a later run is admitted after recovery
        data = completed_with_expected_verdicts(client, later)
        again = recovered(settings, identity)                                      # the old close survives the newer run
        assert again == original
        fresh = recovered(pinned_settings(later), durable_identity(later, 'legitimate'))
        assert fresh['intent_id'] != original['intent_id'] and fresh['status'] == 'confirmed'
        assert client.get(f'/api/runs/{run_id}/report').content == report_before.content
        proof('recovered', run_id=run_id, later_run_id=later, original_receipt=original, later_receipt=fresh,
              later_sealed_sha256=data['sha256'], controller=controller_facts())


async def _installation_query(settings, identity):
    try:
        await client_module.recover_receipt(settings, {**identity, 'installation_id': 'b2' * 16})
    except client_module.ActorError as exc:
        return exc.owner_reason
    return 'answered'


# ---------------------------------------------------------- owner killed after ACTIVE/Running (S2) or before close (S4)
@scenario_only('owner-cut-provider-wait', 'owner-cut-before-close')
def test_scenario_owner_cut(rig, monkeypatch):
    cut = SCENARIO.removeprefix('owner-cut-')
    if PHASE == 'blocked':
        return phase_blocked(rig)
    if PHASE == 'recover':
        return phase_recover(rig, negatives=False)
    assert PHASE == 'cut'
    rig.block_first = cut == 'provider-wait'
    facts = controller_facts()
    if cut == 'before-close':
        original, once = client_module.ActorSession.close, {'cut': False}

        async def cut_close(self):
            if not once['cut'] and self._handle is not None:
                once['cut'] = True
                await asyncio.to_thread(checkpoint, 'before-close', {'run_id': self.run_id, 'variant': self.variant,
                                                                     'identity': self.identity})
            return await original(self)
        monkeypatch.setattr(client_module.ActorSession, 'close', cut_close)
    with TestClient(main.app, headers=HEADERS) as client:
        run_id = start_run(client)
        if cut == 'provider-wait':
            wait_until(rig.entered.is_set, 40, 'a provider call after the actor became ACTIVE')
            identity = durable_identity(run_id, 'legitimate')
            checkpoint('at-active', {'run_id': run_id, 'identity': identity})     # operator observes ACTIVE+Running, kills the owner
            rig.gate.set()
        run = wait_terminal(client, run_id)
        identity = durable_identity(run_id, 'legitimate')
        assert run['status'] == 'failed'
        block_run, block = interrupted_run_id()
        assert block_run == run_id and all(s.cleanup_confirmed is False for s in rig.sessions)
        assert client.post('/api/runs', json=REQUEST).status_code == 503
        error = refused(pinned_settings(run_id), identity)                         # a dead owner is not a receipt
        checkpoint('terminal', {'run_id': run_id, 'identity': identity})
        proof('owner_cut', run_id=run_id, cut=cut, identity=identity, block_reason=block['reason'],
              owner_reason=error.owner_reason, admission_http=503, controller=facts, variants_started=rig.variants)


# --------------------------------------------------------------------- response lost after FINISH (S3), service restarted
@scenario_only('lost-response-after-finish')
def test_scenario_lost_response_after_finish(rig, monkeypatch):
    if PHASE == 'recover':
        return phase_recover(rig, negatives=True)
    assert PHASE == 'cut'
    facts = controller_facts()
    real, state = client_module.socket_transport, {'lost': False}

    async def lossy(settings, payload, *, response_limit, deadline):
        op = json.loads(payload)['op']
        answer = await real(settings, payload, response_limit=response_limit, deadline=deadline)
        if op == 'close' and not state['lost']:
            state['lost'] = True                                                   # the owner already answered; drop the answer
            await asyncio.to_thread(checkpoint, 'close-response-lost', {'op': op})
            raise wire.WireError('timeout')
        return answer
    monkeypatch.setattr(client_module, 'socket_transport', lossy)
    with TestClient(main.app, headers=HEADERS) as client:
        run_id = start_run(client)
        run = wait_terminal(client, run_id)
        assert run['status'] == 'failed' and state['lost'] is True
        block_run, block = interrupted_run_id()
        identity = durable_identity(run_id, 'legitimate')
        assert block_run == run_id and rig.sessions[0].cleanup_confirmed is False and rig.sessions[0].obligation is True
        assert client.post('/api/runs', json=REQUEST).status_code == 503
        checkpoint('terminal', {'run_id': run_id, 'identity': identity})
        proof('response_lost', run_id=run_id, identity=identity, block_reason=block['reason'], controller=facts)


# --------------------------------------------------- second run in one installation, new identity after FINISH, old replay
@scenario_only('second-run-exclusion')
def test_scenario_second_run_exclusion(rig):
    rig.block_first = True
    facts = controller_facts()
    with TestClient(main.app, headers=HEADERS) as client:
        first = start_run(client)
        wait_until(rig.entered.is_set, 40, 'first run ACTIVE and waiting on the provider')
        identity = durable_identity(first, 'legitimate')
        settings = pinned_settings(first)
        api_second = client.post('/api/runs', json=REQUEST)
        assert api_second.status_code == 409

        async def open_other(run_id, variant):
            session = client_module.ActorSession(settings, run_id=run_id, variant=variant)
            await session.__aenter__()

        with pytest.raises(client_module.ActorError) as other_run:
            asyncio.run(open_other('c' * 32, 'legitimate'))                       # another run asks the single plaza
        assert other_run.value.reason == 'capacity_exhausted'
        with pytest.raises(client_module.ActorError) as same_active:
            asyncio.run(open_other(first, 'legitimate'))                          # replay of the identity that is active
        assert same_active.value.reason == 'already_active'
        checkpoint('rejections-done', {'run_id': first, 'identity': identity, 'api_second_http': 409,
                                       'direct_second': other_run.value.reason, 'direct_replay': same_active.value.reason})
        rig.gate.set()
        completed_with_expected_verdicts(client, first)                            # the first run was not affected
        second = start_run(client)                                                 # a new identity after FINISH is admitted
        completed_with_expected_verdicts(client, second)
        identities = [durable_identity(run, name) for run in (first, second) for name in ('legitimate', 'perturbed')]
        assert len({item['intent_id'] for item in identities}) == 4 and len({item['container_id'] for item in identities}) == 4
        replays = {}
        for variant in ('legitimate', 'perturbed'):
            with pytest.raises(client_module.ActorError) as replay:
                asyncio.run(open_other(first, variant))                            # the old identity, after its FINISH
            replays[variant] = replay.value.reason
        assert set(replays.values()) == {'already_active'}
        info = asyncio.run(client_module.health(settings))
        assert info['obligations'] == 0 and info['blocked'] is False
        assert recovered(settings, identity)['status'] == 'confirmed'
        checkpoint('final', {'runs': [first, second], 'identities': identities, 'replays': replays})
        proof('second_run_exclusion', runs=[first, second], replays=replays, api_second_http=409,
              direct_second=other_run.value.reason, direct_replay=same_active.value.reason, controller=facts,
              fixture_provider_calls=len(rig.calls))


# ==================================================================================================================
# A4b: two explicit scenarios of the same schema, same handshakes. Nothing here repeats the five approved scenarios above.
# ==================================================================================================================
def event_kinds(run_id):
    return [kind for kind, _ in durable_events(run_id)]


def phase_controller_blocked(rig):
    """Restart over the same SQLite while the (live) owner still holds the ACTIVE obligation of the killed controller's run."""
    with TestClient(main.app, headers=HEADERS) as client:
        run_id, block = interrupted_run_id()
        assert block['cause'] == 'interrupted_run' and block['run_id'] == run_id            # written by startup recovery
        run = client.get(f'/api/runs/{run_id}').json()
        assert run['status'] == 'failed' and run['summary'] == recovery.interrupted_summary('running')   # interrupted, never a success
        with main.db() as c:
            statuses = [json.loads(row['data'])['status'] for row in
                        c.execute("SELECT data FROM events WHERE run_id=? AND kind='run' ORDER BY seq", (run_id,))]
        assert statuses == ['queued', 'running', 'failed']
        seen = event_kinds(run_id)
        assert 'actor_recovery_confirmed' not in seen and not [kind for kind in seen if kind.startswith('invoice_verifier')]
        measurement = (main.get_run_usage(run_id) or {}).get('measurement') or {}
        assert measurement.get('collection_finished') is False and measurement.get('state') in ('unavailable', 'interrupted')
        identity = durable_identity(run_id, 'legitimate')
        error = refused(pinned_settings(run_id), identity)                                 # live owner: ACTIVE has no FINISH
        assert error.owner_reason == 'receipt_unknown' and error.receipt_status == 'unknown'
        closed = client.post('/api/runs', json=REQUEST)
        message_shown = main.BLOCK_MESSAGES['cleanup_unconfirmed'] in closed.text
        assert closed.status_code == 503 and message_shown
        report = client.get(f'/api/runs/{run_id}/report')
        assert report.status_code == 200
        sealed(report.json())
        assert report.json()['run']['status'] == 'failed'
        with main.db() as c:
            assert c.execute('SELECT count(*) FROM runs').fetchone()[0] == 1               # the refused POST created nothing
        proof('controller_restart_blocked', run_id=run_id, status=run['status'], interrupted_from=run['summary']['interrupted_from'],
              status_events=statuses, owner_reason=error.owner_reason, post_http=closed.status_code, pid=os.getpid())
        checkpoint('blocked-observed', {
            'run_id': run_id, 'identity': identity, 'pid': os.getpid(), 'uid': os.geteuid(), 'status': run['status'],
            'interrupted_from': run['summary']['interrupted_from'], 'status_events': statuses,
            'usage_final': measurement.get('collection_finished') is True, 'usage_state': measurement.get('state'),
            'owner_reason': error.owner_reason, 'receipt_status': error.receipt_status, 'post_http': closed.status_code,
            'post_cleanup_block_message': message_shown})


@scenario_only('controller-kill-running')
def test_scenario_controller_kill_running(rig):
    if PHASE == 'blocked':
        return phase_controller_blocked(rig)
    if PHASE == 'recover':
        return phase_recover(rig, negatives=True)
    assert PHASE == 'cut'
    rig.block_first = True
    facts = controller_facts()
    with TestClient(main.app, headers=HEADERS) as client:
        run_id = start_run(client)
        wait_until(rig.entered.is_set, 40, 'a provider call after the actor became ACTIVE')
        identity = durable_identity(run_id, 'legitimate')
        seen = event_kinds(run_id)
        status = main.get_run(run_id)['status']              # the controller's own SQLite row, read right before the cut
        assert status == 'running' and rig.variants == ['legitimate'] and len(rig.sessions) == 1
        assert not [kind for kind in seen if kind.startswith('invoice_verifier')]
        proof('controller_before_cut', run_id=run_id, identity=identity, run_status=status, controller=facts,
              pid=os.getpid(), uid=os.geteuid(), ppid=os.getppid())
        checkpoint('at-active', {'run_id': run_id, 'identity': identity, 'run_status': status, 'event_kinds': seen,
                                 'pid': os.getpid(), 'uid': os.geteuid(), 'ppid': os.getppid()})   # the operator SIGKILLs this process
        pytest.fail('the operator must have SIGKILLed this process at the checkpoint; it is still running')


@scenario_only('cancel-api-verifier-running')
def test_scenario_cancel_api_verifier(rig):
    facts = controller_facts()
    with TestClient(main.app, headers=HEADERS) as client:
        run_id = start_run(client)
        wait_until(lambda: 'invoice_verifier_started' in event_kinds(run_id), 60, 'the durable start of the verifier handoff')
        identity = durable_identity(run_id, 'legitimate')
        started = [data for kind, data in durable_events(run_id) if kind == 'invoice_verifier_started']
        assert len(started) == 1 and started[0]['variant'] == 'legitimate' and rig.variants == ['legitimate']
        assert main.cancel_marked(run_id) is False and main.get_run(run_id)['status'] == 'running'
        # The operator now observes the closed actor, the guard's ACK and the verifier's Running=true; only then is the API cancel sent.
        checkpoint('verifier-running', {'run_id': run_id, 'identity': identity, 'started': started[0], 'status': 'running',
                                        'cancel_marked': False, 'pid': os.getpid(), 'uid': os.geteuid()})
        premature = client.post('/api/runs', json=REQUEST)
        assert premature.status_code == 409 and len(main.active) == 1
        cancel = client.post(f'/api/runs/{run_id}/cancel')
        assert cancel.status_code == 200 and main.cancel_marked(run_id) is True            # durable request, not only the HTTP answer
        task = main.run_tasks.get(run_id)
        assert task is not None and task.cancelling() >= 1 and not task.done()             # delivered to the task, which keeps waiting
        status = main.get_run(run_id)['status']
        assert status not in main.TERMINAL
        checkpoint('cancel-requested', {'run_id': run_id, 'cancel_http': cancel.status_code, 'cancel_marked': True,
                                        'task_cancelling': task.cancelling(), 'task_done': task.done(), 'status': status,
                                        'premature_http': premature.status_code, 'active_runs': len(main.active)})
        second = client.post('/api/runs', json=REQUEST)
        task = main.run_tasks.get(run_id)
        finished_seen = 'invoice_verifier_finished' in event_kinds(run_id)
        status = main.get_run(run_id)['status']
        assert second.status_code == 409 and len(main.active) == 1 and task is not None and not task.done()
        assert not finished_seen and status not in main.TERMINAL
        # The operator releases the barrier at this checkpoint, after this last sample of "still waiting".
        checkpoint('still-waiting', {'run_id': run_id, 'status': status, 'second_premature_http': second.status_code,
                                     'active_runs': len(main.active), 'task_done': task.done(), 'verifier_finished_seen': finished_seen})
        run = wait_terminal(client, run_id)
        wait_until(lambda: not main.active, 15, 'the cancelled run to release its slot')
        events = durable_events(run_id)
        order = [kind for kind, _ in events]
        finished = [data for kind, data in events if kind == 'invoice_verifier_finished']
        assert run['status'] == 'cancelled'
        assert len(finished) == 1 and finished[0]['artifact_sha256'] == started[0]['artifact_sha256']
        assert finished[0]['cleanup_confirmed'] is True and finished[0]['variant'] == 'legitimate'
        terminal_at = max(index for index, kind in enumerate(order) if kind == 'run')
        assert [data for kind, data in events if kind == 'run'][-1]['status'] == 'cancelled'
        assert order.index('invoice_verifier_started') < order.index('invoice_verifier_finished') < terminal_at
        assert order.count('cancel_requested') == 1 and main.cancel_marked(run_id) is True
        workflow_summary = run['summary']['workflow']
        assert workflow_summary['outcome'] == 'error' and workflow_summary.get('cleanup_confirmed') is True
        assert rig.variants == ['legitimate'] and len(rig.sessions) == 1 and rig.sessions[0].cleanup_confirmed is True
        settings = pinned_settings(run_id)
        receipt = recovered(settings, identity)                                          # the owner's durable FINISH, not health
        assert receipt['status'] == 'confirmed'
        info = asyncio.run(client_module.health(settings))
        assert info['obligations'] == 0 and info['blocked'] is False and info['ready'] is True
        assert recovery.read_state(main.DB, recovery.CLEANUP_BLOCK) is None
        report_path = f'/api/runs/{run_id}/report'
        first, markdown = client.get(report_path), client.get(report_path, params={'format': 'md'})
        assert first.status_code == 200 and markdown.status_code == 200
        sealed(first.json())
        assert first.json()['run']['status'] == 'cancelled'
        observed = ((workflow_summary.get('observed_variants') or {}).get('legitimate') or {}).get('independent_verification') or {}
        checkpoint('terminal', {'run_id': run_id, 'status': run['status'], 'cancel_marked': True,
                                'verifier_finished_digest': finished[0]['artifact_sha256'], 'verifier_cleanup': finished[0]['cleanup_confirmed'],
                                'actor_receipt_status': receipt['status'], 'variants_started': list(rig.variants)})
    with TestClient(main.app, headers=HEADERS) as reopened:                              # new service process state, same SQLite
        assert reopened.get(report_path).content == first.content
        assert reopened.get(report_path, params={'format': 'md'}).content == markdown.content
        assert main.cancel_marked(run_id) is True
    proof('cancel_api_verifier', run_id=run_id, identity=identity, cancel_http=cancel.status_code, premature_http=premature.status_code,
          second_premature_http=second.status_code, controller=facts, provider_calls=len(rig.calls),
          verifier_started=started[0], verifier_finished=finished[0], reopened_reports_identical=True,
          summary_independent_verification_observed={key: observed.get(key) for key in ('status', 'artifact_sha256', 'cleanup_confirmed')},
          report_sha256=first.json()['sha256'])

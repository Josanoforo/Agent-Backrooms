"""M4 owner/state delta. No model, Docker or external access."""
import asyncio
from dataclasses import replace
import json
import sys

import pytest

from services.agent import actor_state as state, invoice_actor_runtime as runtime, runner
from test_actor_state import CONTAINER, directory, open_store, options
from test_actor_level_adapters import level, finish, receipt, schema
from test_actor_catalog_adapters import prepare, resource_root, cell, catalog_receipt

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='owner state is Linux only')


def anchor(**changes):
    return dict(parts=['system.slice', 'docker-' + CONTAINER + '.scope'], device=7, inode=8,
                root_device=7, root_inode=9, boot_id='11111111-2222-3333-4444-555555555555') | changes


def test_room_schema_and_private_anchor_survive_reopen_with_old_catalog_receipt(directory, resource_root):
    with open_store(directory, initialize=True) as store:
        memory = finish(store, level(store))
        prepare(store, resource_root)
        catalog = finish(store, cell(store, run_id='c' * 32), 'c' * 64)
        intent = level(store, level='processes', run_id='d' * 32)
        assert schema(directory) == state.ROOM_SCHEMA
        store.ack(intent.intent_id, CONTAINER)
        intent = store.starting(intent.intent_id)
        assert intent.start_requested and intent.cgroup_anchor is None
        intent = store.anchor_cgroup(intent.intent_id, anchor())
        assert intent.cgroup_anchor.inode == 8 and 'system.slice' not in repr(intent)
        with pytest.raises(state.StateError): store.anchor_cgroup(intent.intent_id, anchor())
        store.activate(intent.intent_id)
    with open_store(directory) as store:
        intent = store.pending()
        assert intent.cgroup_anchor.parts == tuple(anchor()['parts']) and intent.start_requested
        store.closing(intent.intent_id)
        finished = store.finish(intent.intent_id, container_id=CONTAINER)
        assert receipt(store, finished) == finished
        assert receipt(store, memory) == memory
        assert catalog_receipt(store, catalog) == catalog


@pytest.mark.parametrize('change', [{'parts': ['..']}, {'inode': True}, {'boot_id': 'wrong'},
                                   {'parts': ['system.slice', 'docker-' + 'f' * 64 + '.scope']}])
def test_anchor_rejects_unrecognized_nodes_before_commit(directory, change):
    with open_store(directory, initialize=True) as store:
        intent = level(store, level='processes')
        store.ack(intent.intent_id, CONTAINER); store.starting(intent.intent_id)
        with pytest.raises(state.StateError): store.anchor_cgroup(intent.intent_id, anchor(**change))
        assert store.pending().cgroup_anchor is None


def test_changed_cgroup_root_prevents_cleanup_authority(directory):
    with open_store(directory, initialize=True) as store:
        intent = level(store, level='processes')
        store.ack(intent.intent_id, CONTAINER); store.starting(intent.intent_id)
        store.anchor_cgroup(intent.intent_id, anchor()); store.activate(intent.intent_id)
        intent = store.closing(intent.intent_id)
        owner = runtime.DockerInvoiceActor(**options())
        owner._room_root = lambda: (7, 999, anchor()['boot_id'])
        calls = []
        async def forbidden(*args): calls.append(args); raise AssertionError('must not remove')
        owner._close_actor = forbidden
        with pytest.raises(runner.RunnerError, match='root identity changed'):
            asyncio.run(owner.close(intent))
        assert calls == [] and store.pending().phase == 'CLOSE_PENDING'


def test_owner_only_dispatches_fixed_privilege_script_and_no_process_load_without_observer(directory):
    with open_store(directory, initialize=True) as store:
        intent = level(store, level='privileges')
        intent = store.ack(intent.intent_id, CONTAINER)
        store.starting(intent.intent_id); intent = store.activate(intent.intent_id)
    owner, calls = runtime.DockerInvoiceActor(**options()), []
    async def profile(*args): return {}
    async def container(*args): return {'container_id': CONTAINER, 'init_pid': 123}
    async def execute(observed, argv, **kwargs):
        calls.append(argv)
        return {'stdout': '{}', 'stderr': '', 'exit_code': 0, **runner.unavailable_measurement()}
    owner._profile, owner._room_container, owner._execute = profile, container, execute
    result = asyncio.run(owner.room_action(intent))
    assert calls == [('python', '-I', '-S', '-c', runner.PRIVILEGE_ACTION_SCRIPT)]
    assert result['container'] == {'container_id': CONTAINER} and result['cgroup_identity'] is None
    absent = asyncio.run(owner.room_action(replace(intent, level='processes')))
    assert absent['result'] is None and absent['cgroup_identity']['status'] == 'unknown' and len(calls) == 1
    with pytest.raises(runner.RunnerError): asyncio.run(owner.room_action(replace(intent, level='memory')))


def test_room_wire_maximum_shape_fits_existing_global_frame():
    sample = [2**31-1, 2**31-1, 2**64-1, 2**31-1, 90000]
    result = {'stdout': 'a' * 8190, 'stderr': 'b' * 2046, 'exit_code': 0, **runner.unavailable_measurement()}
    body = dict(ok=True, op='room_action', result=result, container={'container_id': CONTAINER},
        cgroup_identity={'status': 'verified', 'version': runner.CGROUP_IDENTITY_VERSION,
            'container_id': CONTAINER, 'cgroup_layout': 'systemd', 'leaf': True,
            'init_in_cgroup': True, 'inode_cross_check': 'match', 'events_counter': 'pids.events',
            'events_scope': 'leaf_cgroup_hierarchical_equals_local'},
        pre=sample, during=[sample] * 400, post=sample, recheck={'ok': True}, tool=90.0, verification=90.0,
        installation_id='a' * 32, run_id='b' * 32, level='processes', stage='actor', context_sha256='c' * 64,
        intent_id='d' * 32, container_id=CONTAINER)
    assert len(json.dumps(result['stdout']).encode()) == 8192
    assert len(json.dumps(body, separators=(',', ':'), allow_nan=False).encode()) < 65536


def test_recovery_without_live_observer_requires_pinned_root_and_node_absence(directory):
    with open_store(directory, initialize=True) as store:
        intent = level(store, level='processes')
        store.ack(intent.intent_id, CONTAINER); store.starting(intent.intent_id)
        store.anchor_cgroup(intent.intent_id, anchor()); store.activate(intent.intent_id)
        intent = store.closing(intent.intent_id)
    owner = runtime.DockerInvoiceActor(**options())
    owner._room_root = lambda: (7, 9, anchor()['boot_id'])
    observed = []
    def missing(parts):
        observed.append(parts)
        raise FileNotFoundError()
    owner._room_reader = missing
    async def removed(observed):
        assert observed == intent
        return {'cleanup_confirmed': True, 'oom_killed': None, **runner.unavailable_measurement()}
    owner._close_actor = removed
    result = asyncio.run(owner.close(intent))
    assert result['cleanup_confirmed'] is True and result['cgroup_absent'] is True
    assert observed == [intent.cgroup_anchor.parts, intent.cgroup_anchor.parts]  # before and after remove


def test_process_action_samples_owner_observer_and_rechecks_same_identity(directory):
    with open_store(directory, initialize=True) as store:
        intent = level(store, level='processes')
        store.ack(intent.intent_id, CONTAINER); store.starting(intent.intent_id)
        store.anchor_cgroup(intent.intent_id, anchor()); intent = store.activate(intent.intent_id)
    owner = runtime.DockerInvoiceActor(**options())
    pinned = {'container_id': CONTAINER, 'init_pid': 123}
    calls = []
    class Observer:
        def recheck(self, container):
            assert container == pinned
            return {'ok': True}
        def sample(self):
            return {'ok': True, 'pids_max': 64, 'pids_current': 64, 'events_max': 10, 'peak': 64}
    observer = Observer()
    owner._room_observers[intent.intent_id] = (observer, {'status': 'verified'}, pinned)
    async def profile(*args): return {}
    async def container(*args): return pinned
    async def execute(observed, argv, **kwargs):
        calls.append(argv)
        await asyncio.sleep(0.06)
        return {'stdout': '{}', 'stderr': '', 'exit_code': 0, **runner.unavailable_measurement()}
    owner._profile, owner._room_container, owner._execute = profile, container, execute
    result = asyncio.run(owner.room_action(intent))
    assert calls == [('python', '-I', '-S', '-c', runner.PROCESS_ACTION_SCRIPT)]
    assert len(result['during']) >= 1 and result['pre'][:4] == [64, 64, 10, 64]
    assert result['recheck'] == {'ok': True}
    assert all(len(sample) == 5 for sample in result['during'])
    assert '123' not in json.dumps(result['container'])  # init PID stays owner-private


def test_oversize_anchor_is_rejected_without_corrupting_readable_diary(directory):
    with open_store(directory, initialize=True) as store:
        intent = level(store, level='processes')
        store.ack(intent.intent_id, CONTAINER); store.starting(intent.intent_id)
        value = anchor(parts=['a'] * 200 + ['docker-' + CONTAINER + '.scope'])
        assert len('/' + '/'.join(value['parts'])) <= 512
        assert len(json.dumps({'intent_id': intent.intent_id, 'anchor': value}, separators=(',', ':'))) > state.storage.MAX_PAYLOAD
        with pytest.raises(state.StateError, match='invalid_transition'):
            store.anchor_cgroup(intent.intent_id, value)
        assert store.pending().phase == 'START_PENDING' and store.pending().cgroup_anchor is None
        assert store.anchor_cgroup(intent.intent_id, anchor()).cgroup_anchor.inode == 8


@pytest.mark.parametrize('selected', ['processes', 'privileges'])
def test_room_result_discards_host_dispatch_diagnostics(directory, selected):
    with open_store(directory, initialize=True) as store:
        intent = level(store, level=selected)
        store.ack(intent.intent_id, CONTAINER); store.starting(intent.intent_id)
        if selected == 'processes': store.anchor_cgroup(intent.intent_id, anchor())
        intent = store.activate(intent.intent_id)
    owner = runtime.DockerInvoiceActor(**options())
    pinned = {'container_id': CONTAINER, 'init_pid': 123}
    class Observer:
        def recheck(self, value): return {'ok': True}
        def sample(self): return {'ok': True, 'pids_max': 64, 'pids_current': 2, 'events_max': 0, 'peak': None}
    owner._room_observers[intent.intent_id] = (Observer(), {'status': 'verified'}, pinned)
    async def profile(*args): return {}
    async def container(*args): return pinned
    async def execute(*args, **kwargs):
        return {'exit_code': 126, 'stdout': '/host/private/stdout', 'stderr': 'OCI runtime exec failed /proc/4242/ns/pid', **runner.unavailable_measurement()}
    owner._profile, owner._room_container, owner._execute = profile, container, execute
    result = asyncio.run(owner.room_action(intent))
    assert result['result']['stderr'] == result['result']['stdout'] == ''
    assert result['result']['exit_code'] == 126 and '/proc/4242' not in json.dumps(result)

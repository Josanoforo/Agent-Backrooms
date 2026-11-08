"""Sol M3.0: durable resource/intent and owner filesystem; no backend codec or API assumption."""
import asyncio
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile

import pytest

from services.agent import actor_state as state, invoice_actor_runtime as runtime, missions, runner
from test_actor_state import CONTAINER, RUN, begin, directory, open_store, options
from test_actor_level_adapters import finish, level, receipt as level_receipt, schema
from test_ola4_validity import inspect_output

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux owner registration and nofollow filesystem')
CONTEXT = 'a' * 64
B_PROFILE = 'b' * 64


@pytest.fixture
def resource_root():
    with tempfile.TemporaryDirectory(prefix='.m30-catalog-', dir=Path.home()) as path:
        os.chmod(path, 0o700)
        yield Path(path)


def prepare(store, parent, **changes):
    return runtime.open_catalog_resource(store, owner_uid=os.geteuid(), parent_directory=str(parent),
        catalog_profile_sha256=B_PROFILE, **({'prepare': True} | changes))


def cell(store, **changes):
    return store.begin_catalog(**(dict(controller_uid=options()['controller_uid'], run_id=RUN, variant='legitimate',
        catalog_profile='A', context_sha256=CONTEXT, catalog_id=missions.CATALOG_ID,
        catalog_sha256=missions.CATALOG_SHA256) | changes))


def catalog_receipt(store, intent, **changes):
    return store.receipt_catalog(**(dict(controller_uid=intent.controller_uid, run_id=intent.run_id,
        variant=intent.variant, catalog_profile=intent.catalog_profile, context_sha256=intent.context_sha256,
        catalog_id=intent.catalog_id, catalog_sha256=intent.catalog_sha256,
        intent_id=intent.intent_id, container_id=intent.container_id) | changes))


class EmptyRuntime:
    owner_uid = os.geteuid() if hasattr(os, 'geteuid') else 0
    async def installed_ids(self): return ()


def test_registered_resource_and_catalog_intents_preserve_m1_m2_after_reopen(directory, resource_root):
    with open_store(directory, initialize=True) as store:
        old = finish(store, begin(store))
        memory = finish(store, level(store), 'c' * 64)
        record, resource = prepare(store, resource_root)
        assert schema(directory) == state.CATALOG_SCHEMA and record.phase == 'CATALOG_READY'
        assert record.parent_directory not in repr(record) and record.source_path not in repr(resource)
        assert resource.check()['ok'] and record.file_identity[-2:] == (os.geteuid(), 0o444)
        assert Path(record.source_path).read_bytes() == missions.CATALOG_BYTES
        assert stat.S_IMODE(Path(record.directory).stat().st_mode) == 0o700
        with pytest.raises(FrozenInstanceError): record.phase = 'CATALOG_RELEASED'
        a = finish(store, cell(store), 'd' * 64)
        assert a.profile_sha256 == options()['profile_sha256'] and a.resource_id == record.resource_id
        assert resource.check()['ok']  # FINISH is the actor's, never a claim that its retained source is absent.
        with pytest.raises(state.StateError, match='already_started'):
            cell(store, catalog_profile='B')
        b = finish(store, cell(store, run_id='e' * 32, catalog_profile='B'), 'e' * 64)
        assert b.profile_sha256 == B_PROFILE
    with open_store(directory) as store:
        reopened, kept = prepare(store, resource_root, prepare=False)
        assert reopened == record and kept.check()['ok']
        assert catalog_receipt(store, a) == a and catalog_receipt(store, b) == b
        assert catalog_receipt(store, b, catalog_profile='A') is None
        assert catalog_receipt(store, b, context_sha256='0' * 64) is None
        assert level_receipt(store, memory) == memory
        assert store.receipt(controller_uid=old.controller_uid, run_id=old.run_id, variant=old.variant,
            intent_id=old.intent_id, container_id=old.container_id) == old
        assert asyncio.run(runtime.release_catalog_resource(store, EmptyRuntime())) is True
        assert not Path(record.source_path).exists() and not Path(record.directory).exists()
        assert resource_root.exists() and store.catalog_resource().phase == 'CATALOG_RELEASED'
        assert catalog_receipt(store, a) == a and catalog_receipt(store, b) == b
        assert runtime.open_catalog_resource(store, owner_uid=os.geteuid()) == (store.catalog_resource(), None)
        with pytest.raises(state.StateError, match='catalog_unavailable'): cell(store, run_id='f' * 32)
        with pytest.raises(runner.RunnerError, match='retired'): prepare(store, resource_root)
        assert finish(store, begin(store, run='f' * 32)).phase == 'FINISH'


def test_resource_preparation_refuses_while_any_actor_holds_the_plaza(directory, resource_root):
    with open_store(directory, initialize=True) as store:
        pending = begin(store)
        with pytest.raises(runner.RunnerError, match='preparation unconfirmed'): prepare(store, resource_root)
        assert store.catalog_resource() is None and schema(directory) == state.SCHEMA
        assert list(resource_root.iterdir()) == []
        finish(store, pending)
        prepare(store, resource_root)
        active = cell(store)
        with pytest.raises(runner.RunnerError, match='obligations remain'):
            asyncio.run(runtime.release_catalog_resource(store, EmptyRuntime()))
        assert store.catalog_resource().phase == 'CATALOG_READY'
        finish(store, active)


def test_missing_and_unacknowledged_resource_never_allow_a_cell_or_regeneration(directory, resource_root, monkeypatch):
    with open_store(directory, initialize=True) as store:
        with pytest.raises(state.StateError, match='catalog_unavailable'): cell(store)
        def cut(*a, **kw): raise state.StateError('state_unavailable')
        monkeypatch.setattr(store, 'ready_catalog_resource', cut)
        with pytest.raises(runner.RunnerError, match='preparation unconfirmed'): prepare(store, resource_root)
        record = store.catalog_resource()
        assert record.phase == 'CATALOG_PREPARE_PENDING' and Path(record.source_path).read_bytes() == missions.CATALOG_BYTES
    with open_store(directory) as store:
        before = Path(record.source_path).stat()
        with pytest.raises(runner.RunnerError, match='remains unconfirmed'): prepare(store, resource_root)
        with pytest.raises(state.StateError, match='catalog_unavailable'): cell(store)
        with pytest.raises(runner.RunnerError, match='preparation remains unconfirmed'):
            asyncio.run(runtime.release_catalog_resource(store, EmptyRuntime()))
        assert Path(record.source_path).stat() == before


@pytest.mark.parametrize('tamper', ['symlink', 'hardlink', 'mode', 'replacement', 'directory', 'parent'])
def test_registered_source_tamper_is_not_adopted_or_repaired(directory, resource_root, tamper):
    with open_store(directory, initialize=True) as store:
        record, resource = prepare(store, resource_root)
    path = Path(record.source_path)
    if tamper == 'symlink':
        path.unlink(); path.symlink_to(resource_root / 'unknown')
    elif tamper == 'hardlink': os.link(path, Path(record.directory) / 'extra-link')
    elif tamper == 'mode': path.chmod(0o644)
    elif tamper == 'replacement':
        path.unlink(); path.write_bytes(missions.CATALOG_BYTES); path.chmod(0o444)
    elif tamper == 'directory':
        Path(record.directory).rename(str(record.directory) + '-old')
        Path(record.directory).mkdir(mode=0o700); path.write_bytes(missions.CATALOG_BYTES); path.chmod(0o444)
    else:
        # Preserve the child and file identities while replacing their trusted parent: still rejected.
        parked = resource_root.with_name(resource_root.name + '-parked')
        resource_root.rename(parked); resource_root.mkdir(mode=0o700)
        (parked / Path(record.directory).name).rename(record.directory)
        parked.rmdir()
    with open_store(directory) as store:
        with pytest.raises(runner.RunnerError): prepare(store, resource_root, prepare=False)
        assert store.catalog_resource() == record


def test_release_suppression_is_not_confirmation_and_does_not_delete_a_neighbour(directory, resource_root):
    with open_store(directory, initialize=True) as store:
        record, resource = prepare(store, resource_root)
        neighbour = Path(record.directory) / 'unrecognized'
        neighbour.write_bytes(b'preserve')
        with pytest.raises(runner.RunnerError, match='release remains unconfirmed'):
            asyncio.run(runtime.release_catalog_resource(store, EmptyRuntime()))
        assert neighbour.read_bytes() == b'preserve' and store.catalog_resource().phase == 'CATALOG_RELEASE_PENDING'
        assert not Path(record.source_path).exists()
        with pytest.raises(runner.RunnerError, match='release remains unconfirmed'):
            asyncio.run(runtime.release_catalog_resource(store, EmptyRuntime()))
        neighbour.unlink(); Path(record.directory).rmdir()  # explicit fixture repair, not a product sweep
        assert asyncio.run(runtime.release_catalog_resource(store, EmptyRuntime())) is True


def test_resource_unknown_object_at_derived_path_is_never_adopted_or_removed(directory, resource_root):
    with open_store(directory, initialize=True) as store:
        unknown = resource_root / ('catalog-' + store.installation_id)
        unknown.mkdir(mode=0o700); (unknown / 'catalog.json').write_bytes(b'preserve unknown')
        with pytest.raises(runner.RunnerError, match='preparation unconfirmed'): prepare(store, resource_root)
        assert (unknown / 'catalog.json').read_bytes() == b'preserve unknown'
        assert store.catalog_resource().phase == 'CATALOG_PREPARE_PENDING'


def test_v4_schema_and_preparation_event_rollback_together(directory, resource_root):
    class Cut:
        def __init__(self, db): self.db = db
        def __enter__(self): return self.db.__enter__()
        def __exit__(self, *a): return self.db.__exit__(*a)
        def execute(self, sql, *a):
            if sql.startswith('INSERT INTO events'): raise sqlite3.OperationalError('cut after v4 upgrade')
            return self.db.execute(sql, *a)
    with open_store(directory, initialize=True) as store:
        db = store._db; store._db = Cut(db)
        with pytest.raises(runner.RunnerError): prepare(store, resource_root)
        store._db = db
        assert schema(directory) == state.SCHEMA and list(resource_root.iterdir()) == []
    with open_store(directory) as store:
        assert store.catalog_resource() is None
        prepare(store, resource_root)


def test_downgrade_cannot_reinterpret_a_retained_catalog_as_v3(directory, resource_root):
    with open_store(directory, initialize=True) as store: prepare(store, resource_root)
    with sqlite3.connect(directory / state.storage.DATABASE) as db:
        db.execute('UPDATE installation SET schema=?', (state.PERSISTENCE_SCHEMA,))
    with pytest.raises(state.StateError, match='state_corrupt'):
        with open_store(directory): pass


def test_version_without_its_first_resource_event_is_partial_state(directory):
    with open_store(directory, initialize=True): pass
    with sqlite3.connect(directory / state.storage.DATABASE) as db:
        db.execute('UPDATE installation SET schema=?', (state.CATALOG_SCHEMA,))
    with pytest.raises(state.StateError, match='state_corrupt'):
        with open_store(directory): pass


@pytest.fixture
def runtime_cell(directory, resource_root):
    image = options()['image_id']
    base_output = inspect_output(**{'.Image': image, '.Config.Image': image})
    profile_a = runner.parse_effective_profile(base_output)
    profile_b = runner.catalog_expected_profile(profile_a)
    digest_a, digest_b = runner.profile_digest(profile_a), runner.profile_digest(profile_b)
    with open_store(directory, initialize=True, profile_sha256=digest_a) as store:
        record, resource = runtime.open_catalog_resource(store, owner_uid=os.geteuid(), parent_directory=str(resource_root),
            catalog_profile_sha256=digest_b, prepare=True)
        intent = cell(store, catalog_profile='B')
        intent = store.ack(intent.intent_id, CONTAINER)
        intent = store.starting(intent.intent_id); intent = store.activate(intent.intent_id)
        holder = {'intent': intent, 'fault': None, 'calls': []}
        async def command(*args, **kwargs):
            holder['calls'].append((args, kwargs))
            observed, fault = holder['intent'], holder['fault']
            profile_b_selected = observed.catalog_profile == 'B'
            config_mounts = [{'Type': 'bind', 'Source': record.source_path, 'Target': missions.CATALOG_DESTINATION, 'ReadOnly': True}] if profile_b_selected else []
            effective = [{'Type': 'bind', 'Source': record.source_path, 'Destination': missions.CATALOG_DESTINATION,
                'RW': False, 'Propagation': 'rprivate'}] if profile_b_selected else []
            if fault == 'config-rw': config_mounts[0]['ReadOnly'] = False
            if fault == 'config-source': config_mounts[0]['Source'] = '/unrecognized'
            if fault == 'config-second': config_mounts *= 2
            if fault == 'rw': effective[0]['RW'] = True
            if fault == 'source': effective[0]['Source'] = '/unrecognized'
            if fault == 'destination': effective[0]['Destination'] = '/wrong'
            if fault == 'type': effective[0]['Type'] = 'volume'
            if fault == 'second': effective *= 2
            if fault == 'propagation': effective[0]['Propagation'] = 'shared'
            if args[0] == 'info': return 0, json.dumps([options()['docker_id'], options()['docker_root']]), ''
            if args[:2] == ('image', 'inspect'): return 0, image, ''
            if args[:2] == ('container', 'inspect'):
                template = args[args.index('--format') + 1]
                if template == runtime._FACTS_TEMPLATE:
                    facts = {key: None for key in runtime._FACTS}
                    facts.update(id=observed.container_id, name='/' + observed.name,
                        image=image if fault != 'image' else 'sha256:' + '0' * 64, labels=owner._labels(observed),
                        path='sh', argv=['-c', 'sleep 1000'], workdir='/work', health=['NONE'], status='running',
                        running=True, pid=123, oom=False, mounts=config_mounts, publish=False, auto_remove=False,
                        restart='no', ipc_mode='private', cgroupns='private', log_driver='none')
                    return 0, json.dumps([facts[key] for key in runtime._FACTS]), ''
                if template == runner.PROFILE_TEMPLATE:
                    changes = {'.Image': image, '.Config.Image': image}
                    if fault == 'user': changes['.Config.User'] = '0:0'
                    if fault == 'memory': changes['.HostConfig.Memory'] = 536870912
                    if fault == 'runtime': changes['.HostConfig.Runtime'] = 'runsc'
                    return 0, inspect_output(**changes) + ('bind' if profile_b_selected else ''), ''
                if template == runner.CATALOG_MOUNT_TEMPLATE:
                    return 0, 'invalid' if fault == 'incomplete' else json.dumps(effective), ''
            if args[:2] == ('container', 'exec'):
                if args[3:] == ('cat', '/sys/fs/cgroup/memory.peak'): return 0, '128', ''
                if args[3:] == ('python', '-I', '-S', '-c', runner.CATALOG_PROBE_SCRIPT):
                    probe = {'version': runner.CATALOG_PROBE_VERSION, 'state': 'present', 'read': 'ok',
                        'sha256': missions.CATALOG_SHA256, 'size': len(missions.CATALOG_BYTES),
                        'write_open': 'rejected', 'write_errno': 'EROFS'} if profile_b_selected else {
                        'version': runner.CATALOG_PROBE_VERSION, 'state': 'absent', 'read': None, 'sha256': None,
                        'size': None, 'write_open': None, 'write_errno': None}
                    return 0, json.dumps(probe), ''
                return 0, record.source_path + ' ' + record.directory, Path(record.directory).name
            raise AssertionError(args[:3])
        owner = runtime.DockerInvoiceActor(**(options() | {'profile_sha256': digest_a}), command=command)
        owner.attach_catalog(record, resource)
        yield store, owner, record, resource, intent, holder, profile_a, profile_b


def test_runtime_profile_b_is_exact_and_does_not_relax_the_ordinary_profile(runtime_cell):
    from services.agent import experiment
    store, owner, record, resource, b, holder, a_profile, b_profile = runtime_cell
    assert asyncio.run(owner.inspect_running(b))['profile'] == b_profile
    assert runner.hardened_violations(b_profile) and runner.catalog_violations(b_profile) == []
    assert owner._labels(b)['org.agent-escape-room.actor-profile'] == record.catalog_profile_sha256
    assert owner._labels(b)['org.agent-escape-room.actor-domain'] == 'catalog'
    store.closing(b.intent_id); store.finish(b.intent_id, container_id=b.container_id)
    a = cell(store, run_id='e' * 32, catalog_profile='A')
    a = store.ack(a.intent_id, 'f' * 64); a = store.starting(a.intent_id); a = store.activate(a.intent_id)
    holder['intent'] = a
    assert asyncio.run(owner.inspect_running(a))['profile'] == a_profile
    comparison = experiment.compare_catalog_profiles(a_profile, b_profile)
    assert comparison['status'] == 'comparable', comparison
    assert record.parent_directory not in json.dumps(owner.catalog_status())


@pytest.mark.parametrize('fault', ['rw', 'source', 'destination', 'type', 'second', 'propagation', 'incomplete',
    'config-rw', 'config-source', 'config-second', 'image', 'user', 'memory', 'runtime'])
def test_runtime_refuses_unapproved_mount_profile_before_model_dispatch(runtime_cell, fault):
    store, owner, record, resource, intent, holder, _, _ = runtime_cell
    holder['fault'] = fault
    with pytest.raises(runner.RunnerError): asyncio.run(owner.inspect_running(intent))
    assert not any(args[:2] == ('container', 'exec') for args, _ in holder['calls'])


def test_runtime_fixed_checks_are_independent_monotonic_and_output_redacted_in_owner(runtime_cell):
    _, owner, record, _, intent, holder, _, _ = runtime_cell
    first = asyncio.run(owner.catalog_check(intent)); second = asyncio.run(owner.catalog_check(intent))
    assert first['check_index'] == 1 and second['check_index'] == 2
    assert first['probe']['state'] == 'present' and first['probe']['write_open'] == 'rejected' and first['host_check']['ok']
    executed = [args[3:] for args, _ in holder['calls'] if args[:2] == ('container', 'exec')]
    assert executed.count(('python', '-I', '-S', '-c', runner.CATALOG_PROBE_SCRIPT)) == 2
    result = asyncio.run(owner.execute(intent, 'fixture command'))
    assert '[catalog source redacted]' in result['stdout'] and '[catalog source redacted]' in result['stderr']
    for secret in (record.source_path, record.directory, Path(record.directory).name): assert secret not in json.dumps(result)
    for op in ('artifact_capture', 'unknown'):
        with pytest.raises(runner.RunnerError): asyncio.run(owner.probe(intent, op))
    with pytest.raises(runner.RunnerError): asyncio.run(owner.probe_level(intent, 'cgroup_events'))
    with pytest.raises(runner.RunnerError): asyncio.run(owner.catalog_check(replace(intent, context_sha256='bad')))


def test_host_drift_is_not_a_missing_probe_and_disallows_further_agent_commands(runtime_cell):
    _, owner, record, _, intent, holder, _, _ = runtime_cell
    path = Path(record.source_path); path.chmod(0o600); path.write_bytes(b'changed'); path.chmod(0o444)
    assert owner.catalog_status()['ready'] is False
    observed = asyncio.run(owner.catalog_check(intent))
    assert observed['host_check']['ok'] is False and observed['host_check']['changed'] is True
    assert observed['probe']['ran'] is True  # a fixed observation is distinct from an agent command.
    count = len(holder['calls'])
    with pytest.raises(runner.RunnerError, match='resource unavailable'): asyncio.run(owner.execute(intent, 'true'))
    assert len(holder['calls']) == count


def test_check_bound_and_registration_cross_installation_never_dispatch(runtime_cell):
    _, owner, record, _, intent, holder, _, _ = runtime_cell
    owner._catalog_checks[intent.intent_id] = 64
    with pytest.raises(runner.RunnerError, match='bound exceeded'): asyncio.run(owner.catalog_check(intent))
    assert holder['calls'] == []
    with pytest.raises(runner.RunnerError): owner.attach_catalog(replace(record, installation_id='0' * 32))

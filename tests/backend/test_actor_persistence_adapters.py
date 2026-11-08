"""Sol's M2.3 adapter contract, independent of the future broker/codec extension."""
import asyncio
from dataclasses import asdict, FrozenInstanceError, replace
import hashlib
import json
import os
import sqlite3
import subprocess
import sys

import pytest

from services.agent import actor_state as state, invoice_actor_runtime as runtime_module, runner
from test_actor_state import CONTAINER, INSTALLATION, RUN, begin, directory, open_store, options
from test_actor_level_adapters import finish, level, receipt, schema

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux actor inventory and fixed probes')
CONTEXT = 'a' * 64
MARKER = '/work/marker-' + 'b' * 24


def phase(store, stage='actor', **changes):
    return level(store, level='persistence', stage=stage, **changes)


def test_two_phase_durable_predecessor_preserves_both_receipts_and_old_versions(directory):
    with open_store(directory, initialize=True) as store:
        old = finish(store, begin(store))
        memory = finish(store, level(store), 'c' * 64)
        assert schema(directory) == state.LEVEL_SCHEMA
        actor = finish(store, phase(store), 'd' * 64)
        assert schema(directory) == state.PERSISTENCE_SCHEMA
    with open_store(directory) as store:
        fresh = phase(store, 'fresh')
        assert fresh.predecessor == state.level_predecessor(INSTALLATION, actor)
        with pytest.raises(FrozenInstanceError):
            fresh.predecessor.intent_id = 'e' * 32
        with pytest.raises(state.StateError, match='invalid_transition'):
            store.ack(fresh.intent_id, actor.container_id)
        fresh = finish(store, fresh, 'e' * 64)
        with pytest.raises(state.StateError, match='already_started'):
            phase(store, 'fresh')
        with pytest.raises(state.StateError, match='already_started'):
            phase(store)
        finish(store, phase(store, run_id='f' * 32), 'f' * 64)
    with open_store(directory) as store:
        assert receipt(store, actor) == actor and receipt(store, fresh) == fresh
        assert receipt(store, memory) == memory
        assert store.receipt(controller_uid=old.controller_uid, run_id=old.run_id, variant=old.variant,
            intent_id=old.intent_id, container_id=old.container_id) == old
        assert receipt(store, fresh, stage='actor') is None
        assert receipt(store, fresh, context_sha256='0' * 64) is None


def test_fresh_first_unconfirmed_cross_context_and_cross_run_never_write(directory):
    with open_store(directory, initialize=True) as store:
        with pytest.raises(state.StateError, match='predecessor_unconfirmed'):
            phase(store, 'fresh')
        assert schema(directory) == state.SCHEMA
        actor = phase(store)
        with pytest.raises(state.StateError, match='actor_busy'):
            phase(store, 'fresh')
        store.ack(actor.intent_id, CONTAINER)
        store.closing(actor.intent_id)
        with pytest.raises(state.StateError, match='actor_busy'):
            phase(store, 'fresh')
        store.finish(actor.intent_id, container_id=CONTAINER)
        for changes, error in [({'run_id': 'c' * 32}, 'predecessor_unconfirmed'),
                               ({'context_sha256': 'c' * 64}, 'invalid_transition'),
                               ({'controller_uid': options()['controller_uid'] + 1}, 'invalid_transition')]:
            with pytest.raises(state.StateError, match=error):
                phase(store, 'fresh', **changes)
        assert store.pending() is None and phase(store, 'fresh').predecessor.container_id == CONTAINER


@pytest.mark.parametrize('field,value', [
    ('installation_id', '0' * 32), ('run_id', '0' * 32), ('level', 'memory'), ('stage', 'fresh'),
    ('context_sha256', '0' * 64), ('intent_id', '0' * 32), ('container_id', '0' * 64),
])
def test_predecessor_tamper_is_corruption_not_a_new_authority(directory, field, value):
    with open_store(directory, initialize=True) as store:
        finish(store, phase(store))
        phase(store, 'fresh')
    with sqlite3.connect(directory / state.storage.DATABASE) as db:
        sequence, raw = db.execute("SELECT sequence,payload FROM events WHERE kind='CREATE_PENDING' ORDER BY sequence DESC LIMIT 1").fetchone()
        payload = json.loads(raw)
        payload['predecessor'][field] = value
        db.execute('UPDATE events SET payload=? WHERE sequence=?', (json.dumps(payload), sequence))
    with pytest.raises(state.StateError, match='state_corrupt'):
        with open_store(directory):
            pass


def test_persistence_downgrade_and_interrupted_upgrade_fail_closed(directory):
    class Interrupted:
        def __init__(self, conn): self.conn = conn
        def __enter__(self): return self.conn.__enter__()
        def __exit__(self, *args): return self.conn.__exit__(*args)
        def execute(self, statement, *args):
            if statement.startswith('INSERT INTO events'):
                raise sqlite3.OperationalError('cut after upgrade')
            return self.conn.execute(statement, *args)
    with open_store(directory, initialize=True) as store:
        memory = finish(store, level(store))
        conn = store._db
        store._db = Interrupted(conn)
        with pytest.raises(state.StateError, match='state_unavailable'):
            phase(store)
        store._db = conn
        assert schema(directory) == state.LEVEL_SCHEMA
    with open_store(directory) as store:
        assert receipt(store, memory) == memory and store.pending() is None
        finish(store, phase(store), 'd' * 64)
    with sqlite3.connect(directory / state.storage.DATABASE) as db:
        db.execute('UPDATE installation SET schema=?', (state.LEVEL_SCHEMA,))
    with pytest.raises(state.StateError, match='state_corrupt'):
        with open_store(directory):
            pass


@pytest.mark.parametrize('blocked', ['id', 'intent', 'name', 'installation', None])
def test_runtime_rechecks_absence_before_fresh_create(directory, blocked):
    with open_store(directory, initialize=True) as store:
        actor = finish(store, phase(store))
        fresh = phase(store, 'fresh')
    calls = []
    async def command(*args, **kwargs):
        calls.append(args)
        if args[0] == 'info': return 0, json.dumps([options()['docker_id'], options()['docker_root']]), ''
        if args[:2] == ('container', 'ls'):
            query = args[-1]
            hit = {'id': query.startswith('id='), 'intent': 'actor-intent=' in query,
                   'name': query.startswith('name='), 'installation': 'actor-installation=' in query}.get(blocked, False)
            return 0, actor.container_id + '\n' if hit else '', ''
        if args[0] == 'create': return 0, 'e' * 64, ''
        raise AssertionError(args)
    runtime = runtime_module.DockerInvoiceActor(**options(), command=command)
    if blocked:
        with pytest.raises(runner.RunnerError, match='predecessor absence'):
            asyncio.run(runtime.create(fresh))
        assert not any(call[0] == 'create' for call in calls)
    else:
        assert asyncio.run(runtime.create(fresh)) == 'e' * 64
        assert len([c for c in calls if c[:2] == ('container', 'ls')]) == 4
    assert runtime._labels(fresh)['org.agent-escape-room.actor-predecessor-intent'] == actor.intent_id
    with pytest.raises(runner.RunnerError):
        runtime._labels(replace(fresh, predecessor=None))


@pytest.mark.parametrize('name,args', [
    ('file_state', {'path': '/etc/passwd'}), ('file_state', {'path': MARKER, 'script': 'bad'}),
    ('file_state', {'path': MARKER + '/..'}), ('copy_scan', {'sha256': CONTEXT, 'size': True, 'exclude': None}),
    ('copy_scan', {'sha256': CONTEXT, 'size': 1048577, 'exclude': None}),
    ('copy_scan', {'sha256': CONTEXT, 'size': 1, 'exclude': '/tmp/alias'}),
    ('copy_scan', {'sha256': CONTEXT.upper(), 'size': 1, 'exclude': None}), ('task_result', {}),
])
def test_probe_rejects_untyped_paths_and_extra_authority_before_exec(directory, name, args):
    with open_store(directory, initialize=True) as store:
        actor = phase(store)
    runtime = runtime_module.DockerInvoiceActor(**options())
    async def forbidden(*args, **kwargs): raise AssertionError('invalid probe dispatched')
    runtime._execute = forbidden
    with pytest.raises(runner.RunnerError, match='unavailable'):
        asyncio.run(runtime.probe_level(actor, name, **args))


def test_fixed_probe_dispatch_and_error_classification(directory):
    with open_store(directory, initialize=True) as store:
        actor = phase(store)
    runtime = runtime_module.DockerInvoiceActor(**options())
    calls = []
    async def execute(intent, args, **kwargs):
        calls.append((args, kwargs))
        return {'exit_code': 0, 'stdout': '{"status":"missing"}', 'stderr': ''}
    runtime._execute = execute
    assert asyncio.run(runtime.probe_level(actor, 'file_state', path=MARKER)) == {'status': 'missing'}
    malformed = asyncio.run(runtime.probe_level(actor, 'copy_scan', sha256=CONTEXT, size=48, exclude=None))
    assert malformed == runner.incomplete_copy_scan('malformed')
    assert all(args[:4] == ('python', '-I', '-S', '-c') and kwargs == {'timeout': 8} for args, kwargs in calls)
    assert calls[0][0][4:] == (runner.FILE_STATE_SCRIPT, MARKER)
    assert calls[1][0][4:] == (runner.COPY_SCAN_SCRIPT, CONTEXT, '48', '-')
    async def timeout(*args, **kwargs): raise runner.RunnerError('timed out')
    runtime._execute = timeout
    assert asyncio.run(runtime.probe_level(actor, 'file_state', path=MARKER)) == {'status': 'unavailable'}
    assert asyncio.run(runtime.probe_level(actor, 'copy_scan', sha256=CONTEXT, size=48, exclude=MARKER)) == runner.incomplete_copy_scan('probe_timeout')


@pytest.mark.parametrize('mode', ['regular', 'read', 'hardlink', 'missing', 'symlink', 'fifo', 'directory', 'oversize', 'parent-symlink', 'shadow'])
def test_real_fixed_file_probe_never_follows_or_blocks_nonregular_files(tmp_path, mode):
    path = tmp_path / 'marker'
    payload = b'bounded synthetic marker'
    if mode not in ('missing', 'symlink', 'fifo', 'directory', 'parent-symlink'):
        path.write_bytes(payload if mode != 'oversize' else b'x' * 1048577)
    if mode == 'symlink':
        target = tmp_path / 'target'; target.write_bytes(payload); path.symlink_to(target)
    if mode == 'fifo': os.mkfifo(path)
    if mode == 'directory': path.mkdir()
    if mode == 'hardlink': os.link(path, tmp_path / 'alias')
    if mode == 'parent-symlink':
        target = tmp_path / 'real'; target.mkdir(); (target / 'marker').write_bytes(payload)
        link = tmp_path / 'link'; link.symlink_to(target, target_is_directory=True); path = link / 'marker'
    if mode == 'shadow':
        (tmp_path / 'hashlib.py').write_text('raise RuntimeError("shadowed")')
        (tmp_path / 'sitecustomize.py').write_text('raise RuntimeError("shadowed")')
    def observe():
        result = subprocess.run([sys.executable, '-I', '-S', '-c', runner.FILE_STATE_SCRIPT, str(path)],
            cwd=tmp_path, capture_output=True, text=True, timeout=5)
        return runner.parse_file_state(result.returncode, result.stdout)
    before = observe()
    if mode in ('regular', 'read', 'hardlink', 'shadow'):
        assert before['status'] == 'present' and before['sha256'] == hashlib.sha256(payload).hexdigest()
        assert before['links'] == (2 if mode == 'hardlink' else 1)
        if mode == 'read':
            path.read_bytes(); assert observe() == before  # atime ignored
    else:
        assert before == {'status': 'missing' if mode == 'missing' else 'unavailable'}


@pytest.mark.parametrize('change', [{'inode': True}, {'size': -1}, {'size': 1048577}, {'mtime': True},
    {'ctime': -1}, {'links': 0}, {'sha256': 'x'}, {'extra': 'authority'}, {'status': 'missing'}])
def test_file_probe_parser_rejects_incomplete_or_unbounded_present(change):
    good = {'status': 'present', 'inode': 1, 'size': 1, 'mtime': 1, 'ctime': 1, 'links': 1, 'sha256': CONTEXT}
    assert runner.parse_file_state(0, json.dumps(good | change)) == {'status': 'unavailable'}

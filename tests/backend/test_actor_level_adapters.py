"""M2.0 durable identity and fixed runtime probes. No broker/codec implementation is assumed."""
import asyncio
from dataclasses import FrozenInstanceError, replace
import json
import sqlite3
import sys

import pytest

from services.agent import actor_state as state, invoice_actor_runtime as runtime_module, runner
from test_actor_state import (CONTAINER, IMAGE, INSTALLATION, PROFILE, RUN, begin, directory, open_store, options)

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux actor inventory')
CONTEXT = 'a' * 64


def level(store, **changes):
    return store.begin_level(**({'controller_uid': options()['controller_uid'], 'run_id': RUN,
        'level': 'memory', 'stage': 'actor', 'context_sha256': CONTEXT} | changes))


def finish(store, intent, cid=CONTAINER):
    intent = store.ack(intent.intent_id, cid)
    intent = store.starting(intent.intent_id)
    intent = store.activate(intent.intent_id)
    intent = store.closing(intent.intent_id)
    return store.finish(intent.intent_id, container_id=cid)


def schema(directory):
    with sqlite3.connect(directory / state.storage.DATABASE) as conn:
        return conn.execute('SELECT schema FROM installation').fetchone()[0]


def receipt(store, intent, **changes):
    return store.receipt_level(**({'controller_uid': intent.controller_uid, 'run_id': intent.run_id,
        'level': intent.level, 'stage': intent.stage, 'context_sha256': intent.context_sha256,
        'intent_id': intent.intent_id, 'container_id': intent.container_id} | changes))


def test_upgrade_preserves_m1_receipt_and_replay_domains_across_reopen(directory):
    with open_store(directory, initialize=True) as store:
        first = finish(store, begin(store))
        assert schema(directory) == state.SCHEMA
        second = finish(store, level(store), cid='b' * 64)
        assert schema(directory) == state.LEVEL_SCHEMA and not hasattr(second, 'variant')
        with pytest.raises(FrozenInstanceError):
            second.level = 'secret'
        with pytest.raises(state.StateError, match='already_started'):
            level(store)
        with pytest.raises(state.StateError, match='invalid_transition'):
            level(store, level='secret', context_sha256='c' * 64)
        assert store.pending() is None
    with open_store(directory) as store:
        assert receipt(store, second) == second
        assert receipt(store, second, context_sha256='d' * 64) is None
        assert store.receipt(controller_uid=first.controller_uid, run_id=first.run_id, variant=first.variant,
            intent_id=first.intent_id, container_id=first.container_id) == first
        third = finish(store, begin(store, variant='perturbed'), cid='e' * 64)
        assert receipt(store, second) == second  # later M1 activity does not erase M2 history
        assert store.pending() is None and third.variant == 'perturbed'


@pytest.mark.parametrize('change', [
    {'level': 'network'}, {'level': 'persistence', 'stage': 'unknown'}, {'stage': 'fresh'}, {'stage': None},
    {'controller_uid': True}, {'context_sha256': 'A' * 64}, {'context_sha256': None}, {'run_id': 'bad'},
])
def test_invalid_level_never_commits_version_or_intent(directory, change):
    with open_store(directory, initialize=True) as store:
        with pytest.raises(state.StateError):
            level(store, **change)
        assert schema(directory) == state.SCHEMA and store.pending() is None
        assert level(store).phase == 'CREATE_PENDING'


def test_unacknowledged_level_survives_restart_and_blocks_new_identity(directory):
    with open_store(directory, initialize=True) as store:
        intent = level(store)
    with open_store(directory) as store:
        assert store.pending() == intent and intent.container_id is None
        with pytest.raises(state.StateError, match='actor_busy'):
            level(store, run_id='c' * 32)
        with pytest.raises(state.StateError, match='invalid_transition'):
            store.finish(intent.intent_id, container_id=CONTAINER)
        assert receipt(store, replace(intent, container_id=CONTAINER)) is None


def test_cross_uid_and_workflow_receipts_cannot_confirm_a_level(directory):
    with open_store(directory, initialize=True) as store:
        intent = finish(store, level(store))
        with pytest.raises(state.StateError, match='identity_changed'):
            receipt(store, intent, controller_uid=intent.controller_uid + 1)
        assert store.receipt(controller_uid=intent.controller_uid, run_id=intent.run_id, variant='legitimate',
            intent_id=intent.intent_id, container_id=intent.container_id) is None
        assert receipt(store, intent) == intent


def test_downgraded_schema_cannot_reinterpret_level_history_as_m1(directory):
    with open_store(directory, initialize=True) as store:
        finish(store, level(store))
    with sqlite3.connect(directory / state.storage.DATABASE) as conn:
        conn.execute('UPDATE installation SET schema=?', (state.SCHEMA,))
    with pytest.raises(state.StateError, match='state_corrupt'):
        with open_store(directory):
            pass


def test_interrupted_schema_and_intention_transaction_rolls_back_and_closes_writer(directory):
    class Interrupted:
        def __init__(self, conn): self.conn = conn
        def __enter__(self): return self.conn.__enter__()
        def __exit__(self, *args): return self.conn.__exit__(*args)
        def execute(self, statement, *args):
            if statement.startswith('INSERT INTO events'):
                raise sqlite3.OperationalError('injected interruption after schema update')
            return self.conn.execute(statement, *args)

    with open_store(directory, initialize=True) as store:
        conn = store._db
        store._db = Interrupted(conn)
        with pytest.raises(state.StateError, match='state_unavailable'):
            level(store)
        assert schema(directory) == state.SCHEMA
        with pytest.raises(state.StateError, match='state_unavailable'):
            store.pending()
        store._db = conn
    with open_store(directory) as store:
        assert store.pending() is None and level(store).phase == 'CREATE_PENDING'


def test_unknown_schema_is_never_reinitialized(directory):
    with open_store(directory, initialize=True):
        pass
    with sqlite3.connect(directory / state.storage.DATABASE) as conn:
        conn.execute('UPDATE installation SET schema=?', ('actor-recovery/v99',))
    with pytest.raises(state.StateError, match='state_corrupt'):
        with open_store(directory):
            pass
    assert schema(directory) == 'actor-recovery/v99'


@pytest.mark.parametrize('text,exit_code,available', [
    ('low 0\noom 1\noom_kill 1\n', 0, True), ('oom_kill 0\n', 0, True),
    ('oom_kill -1\n', 0, False), ('oom_kill true\n', 0, False), ('oom_kill 1\noom_kill 2\n', 0, False),
    ('oom 0\n', 0, False), ('oom_kill 18446744073709551616\n', 0, False), ('oom_kill 0\n', 1, False),
])
def test_fixed_level_probe_parses_counters_without_inventing_zero(directory, text, exit_code, available):
    with open_store(directory, initialize=True) as store:
        intent = level(store)
    runtime = runtime_module.DockerInvoiceActor(**options())
    calls = []

    async def execute(observed, args):
        assert observed == intent
        calls.append(args)
        return {'stdout': text, 'stderr': '', 'exit_code': exit_code}

    runtime._execute = execute
    result = asyncio.run(runtime.probe_level(intent, 'cgroup_events'))
    assert result['status'] == ('available' if available else 'unavailable')
    assert (result['counters'] is not None) == available
    assert calls == [('cat', '--', '/sys/fs/cgroup/memory.events')]
    labels = runtime._labels(intent)
    assert labels['org.agent-escape-room.actor-context'] == CONTEXT
    assert labels['org.agent-escape-room.actor-domain'] == 'level' and 'org.agent-escape-room.actor-variant' not in labels
    for other, name, args in [(replace(intent, level='secret'), 'cgroup_events', {}),
                             (intent, 'task_result', {}), (intent, 'cgroup_events', {'path': '/host/file'})]:
        with pytest.raises(runner.RunnerError, match='unavailable'):
            asyncio.run(runtime.probe_level(other, name, **args))
    assert len(calls) == 1

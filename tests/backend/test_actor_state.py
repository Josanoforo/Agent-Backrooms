import json
import os
from pathlib import Path
import select
import signal
import sqlite3
import subprocess
import sys
import tempfile

import pytest

from services.agent import actor_state as state


pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux actor inventory')
RUN = '1' * 32
CONTAINER = '2' * 64
INSTALLATION = '3' * 32
IMAGE = 'sha256:' + '4' * 64
PROFILE = '5' * 64
DOCKER = 'e415cbb0-734f-4cd8-a30c-22c80d2b3ed3'


@pytest.fixture
def directory():
    with tempfile.TemporaryDirectory(prefix='.actor-inventory-test-', dir=Path.home()) as raw:
        yield Path(raw)


def options():
    uid = os.geteuid()
    return {'installation_id': INSTALLATION, 'owner_uid': uid, 'controller_uid': 65534 if uid != 65534 else 12345,
            'docker_id': DOCKER, 'docker_root': '/var/lib/docker', 'image_id': IMAGE, 'profile_sha256': PROFILE}


def open_store(directory, **changes):
    return state.open_actor_inventory(directory, **(options() | changes))


def begin(store, *, run=RUN, variant='legitimate'):
    return store.begin(controller_uid=options()['controller_uid'], run_id=run, variant=variant)


def history(directory):
    with sqlite3.connect(directory / state.storage.DATABASE) as db:
        return [kind for kind, in db.execute('SELECT kind FROM events ORDER BY sequence')]


def test_ack_precedes_start_and_finish_requires_the_recognized_id(directory):
    with open_store(directory, initialize=True) as store:
        assert store.installation_id == INSTALLATION
        intent = begin(store)
        assert intent.name == 'escape-actor-' + intent.intent_id
        assert history(directory) == ['CREATE_PENDING']
        assert intent.container_id is None and intent.profile_sha256 == PROFILE
        with pytest.raises(state.StateError, match='invalid_transition'):
            store.starting(intent.intent_id)
        with pytest.raises(state.StateError, match='actor_busy'):
            begin(store, variant='perturbed')
        with pytest.raises(state.StateError, match='invalid_transition'):
            store.ack('6' * 32, CONTAINER)
        assert store.ack(intent.intent_id, CONTAINER).phase == 'CREATE_ACK'
        with pytest.raises(state.StateError, match='invalid_transition'):
            store.ack(intent.intent_id, '7' * 64)
        assert store.starting(intent.intent_id).phase == 'START_PENDING'
        assert store.activate(intent.intent_id).phase == 'ACTIVE'
    with open_store(directory) as store:
        assert store.pending().container_id == CONTAINER
        closing = store.closing(intent.intent_id)
        assert closing.phase == 'CLOSE_PENDING' and store.closing(intent.intent_id) == closing
        with pytest.raises(state.StateError, match='invalid_transition'):
            store.finish(intent.intent_id, container_id='7' * 64)
        finished = store.finish(intent.intent_id, container_id=CONTAINER)
        assert finished.phase == 'FINISH' and store.finish(intent.intent_id, container_id=CONTAINER) == finished
        assert store.pending() is None
    assert history(directory) == ['CREATE_PENDING', 'CREATE_ACK', 'START_PENDING', 'ACTIVE', 'CLOSE_PENDING', 'FINISH']
    with open_store(directory) as store:
        assert store.finish(intent.intent_id, container_id=CONTAINER) == finished
        with pytest.raises(state.StateError, match='already_started'):
            begin(store)
        assert begin(store, variant='perturbed').variant == 'perturbed'


def test_receipt_retains_exact_finish_across_later_runs_and_restart(directory):
    with open_store(directory, initialize=True) as store:
        first = begin(store)
        query = {'controller_uid': options()['controller_uid'], 'run_id': RUN, 'variant': 'legitimate',
                 'intent_id': first.intent_id, 'container_id': CONTAINER}
        assert store.receipt(**query) is None
        store.ack(first.intent_id, CONTAINER)
        store.closing(first.intent_id)
        assert store.receipt(**query) is None
        finished = store.finish(first.intent_id, container_id=CONTAINER)
        second = begin(store, run='9' * 32)
        store.ack(second.intent_id, '8' * 64)
        store.closing(second.intent_id)
        store.finish(second.intent_id, container_id='8' * 64)
    with open_store(directory) as store:
        before = history(directory)
        assert store.receipt(**query) == finished
        assert store.receipt(**(query | {'run_id': '7' * 32})) is None
        assert store.receipt(**(query | {'container_id': '7' * 64})) is None
        assert store.receipt(**(query | {'variant': 'perturbed'})) is None
        with pytest.raises(state.StateError, match='identity_changed'):
            store.receipt(**(query | {'controller_uid': options()['controller_uid'] + 1}))
        assert history(directory) == before


@pytest.mark.parametrize('acked', [False, True])
def test_sigkill_preserves_intent_and_releases_the_process_lock(directory, acked):
    with open_store(directory, initialize=True):
        pass
    program = '''
import json, signal, sys
from services.agent.actor_state import open_actor_inventory
options = json.loads(sys.argv[2])
with open_actor_inventory(sys.argv[1], **options) as store:
    intent = store.begin(controller_uid=options['controller_uid'], run_id='1' * 32, variant='legitimate')
    if sys.argv[3] == 'True':
        store.ack(intent.intent_id, '2' * 64)
    print(intent.intent_id, flush=True)
    signal.pause()
'''
    child = subprocess.Popen([sys.executable, '-B', '-c', program, str(directory), json.dumps(options()), str(acked)],
                             stdout=subprocess.PIPE, text=True)
    try:
        assert select.select([child.stdout], [], [], 5)[0], 'child did not commit inventory'
        intent_id = child.stdout.readline().strip()
        assert len(intent_id) == 32
        with pytest.raises(state.StateError, match='state_locked'):
            with open_store(directory):
                pytest.fail('another process owned the lock')
    finally:
        if child.poll() is None:
            os.kill(child.pid, signal.SIGKILL)
        child.communicate(timeout=5)
    assert child.returncode == -signal.SIGKILL
    with open_store(directory) as store:
        intent = store.pending()
        assert intent.intent_id == intent_id and intent.run_id == RUN
        if acked:
            assert intent.phase == 'CREATE_ACK' and intent.container_id == CONTAINER
            store.closing(intent_id)
            store.finish(intent_id, container_id=CONTAINER)
        else:
            assert intent.phase == 'CREATE_PENDING' and intent.container_id is None
            with pytest.raises(state.StateError, match='invalid_transition'):
                store.closing(intent_id)
            with pytest.raises(state.StateError, match='actor_busy'):
                begin(store, run='8' * 32)


@pytest.mark.parametrize('changes', [
    {'installation_id': '8' * 32}, {'image_id': 'sha256:' + '8' * 64}, {'profile_sha256': '8' * 64},
    {'docker_id': 'another-daemon'}, {'docker_root': '/var/lib/another'},
])
def test_rejects_state_from_other_installation_or_profile(directory, changes):
    with open_store(directory, initialize=True) as store:
        intent = begin(store)
    with pytest.raises(state.StateError, match='identity_changed'):
        with open_store(directory, **changes):
            pytest.fail('foreign state accepted')
    with open_store(directory) as store:
        assert store.pending() == intent


def test_missing_or_truncated_state_is_never_treated_as_idle(directory):
    with pytest.raises(state.StateError, match='state_incomplete'):
        with open_store(directory):
            pytest.fail('empty state accepted')
    assert list(directory.iterdir()) == []
    with open_store(directory, initialize=True) as store:
        begin(store)
    with sqlite3.connect(directory / state.storage.DATABASE) as db:
        db.execute('DELETE FROM events WHERE sequence=1')
    with pytest.raises(state.StateError, match='state_corrupt'):
        with open_store(directory):
            pytest.fail('lost pending intent interpreted as idle')


def test_sync_failure_after_commit_preserves_the_unacknowledged_intent(directory, monkeypatch):
    def fail(_fd):
        raise OSError('simulated sync failure')

    with open_store(directory, initialize=True) as store:
        with monkeypatch.context() as patch:
            patch.setattr(state.os, 'fsync', fail)
            with pytest.raises(state.StateError, match='state_unavailable'):
                begin(store)
        with pytest.raises(state.StateError, match='state_unavailable'):
            store.pending()
    with open_store(directory) as store:
        assert store.pending().phase == 'CREATE_PENDING' and store.pending().container_id is None

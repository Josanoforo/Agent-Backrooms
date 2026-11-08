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

from services.agent import guard_state as state


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux durable guard state")
NAME = "escape-invoice-" + "a" * 32
RUN = "b" * 32
ARTIFACT = "c" * 64
CID = "d" * 64
DOCKER_ID = "e415cbb0-734f-4cd8-a30c-22c80d2b3ed3"


@pytest.fixture
def directory():
    # Use a private, trusted tree. /tmp is intentionally outside this contract.
    with tempfile.TemporaryDirectory(prefix=".guard-state-test-", dir=Path.home()) as raw:
        path = Path(raw)
        path.chmod(0o700)
        yield path


def options():
    uid = os.geteuid()
    return dict(guard_uid=uid, client_uid=65534 if uid != 65534 else 12345,
                docker_id=DOCKER_ID, docker_root="/var/lib/docker")


def open_store(directory, **changes):
    return state.open_state(directory, **(options() | changes))


def begin(store):
    store.begin(NAME, RUN, "perturbed", ARTIFACT)


def test_lifecycle_and_append_only_evidence(directory):
    with open_store(directory, initialize=True) as store:
        assert state.HEX32.fullmatch(store.installation_id)
        installation_id = store.installation_id
        assert store.pending() is None
        begin(store)
        expected = dict(name=NAME, run_id=RUN, variant="perturbed",
                        artifact_sha256=ARTIFACT, container_id=None)
        assert store.pending() == expected
        altered = store.pending()
        altered["container_id"] = CID
        assert store.pending() == expected
        store.ack(CID)
        assert store.pending() == expected | {"container_id": CID}
        store.finish()
        assert store.pending() is None
    with open_store(directory) as store:
        assert store.installation_id == installation_id
        assert store.pending() is None
    with sqlite3.connect(directory / state.DATABASE) as db:
        rows = db.execute("SELECT sequence,kind,payload FROM events ORDER BY sequence").fetchall()
    assert [(seq, kind) for seq, kind, _ in rows] == [(1, "PENDING"), (2, "ACK"), (3, "FINISH")]
    assert json.loads(rows[0][2]) == expected
    assert json.loads(rows[1][2]) == {"container_id": CID}
    assert json.loads(rows[2][2]) == {}
    assert b"artifact_b64" not in (directory / state.DATABASE).read_bytes()
    assert (directory / state.LOCK).stat().st_mode & 0o777 == 0o600
    assert (directory / state.DATABASE).stat().st_mode & 0o777 == 0o600


def test_no_implicit_initialization_or_overwrite(directory):
    with pytest.raises(state.StateError, match="^state_incomplete$"):
        with open_store(directory):
            pytest.fail("unexpected open")
    assert list(directory.iterdir()) == []
    with open_store(directory, initialize=True):
        pass
    original = (directory / state.DATABASE).read_bytes()
    with pytest.raises(state.StateError, match="^state_initialization_exists$"):
        with open_store(directory, initialize=True):
            pytest.fail("unexpected overwrite")
    assert (directory / state.DATABASE).read_bytes() == original


@pytest.mark.parametrize("missing", [state.LOCK, state.DATABASE])
def test_partial_installation_does_not_recreate(directory, missing):
    with open_store(directory, initialize=True):
        pass
    (directory / missing).unlink()
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    for initialize in (False, True):
        with pytest.raises(state.StateError):
            with open_store(directory, initialize=initialize):
                pytest.fail("partial installation accepted")
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before


def test_lock_is_shared_and_has_stable_inode(directory):
    with open_store(directory, initialize=True) as first:
        inode = (directory / state.LOCK).stat().st_ino
        with pytest.raises(state.StateError, match="^state_locked$"):
            with open_store(directory):
                pytest.fail("second writer admitted")
        assert first.pending() is None
    with open_store(directory):
        assert (directory / state.LOCK).stat().st_ino == inode


@pytest.mark.parametrize("acknowledged", [False, True])
def test_sigkill_releases_lock_but_preserves_intent(directory, acknowledged):
    with open_store(directory, initialize=True):
        pass
    program = """
import os, sys
from services.agent.guard_state import open_state
with open_state(sys.argv[1], guard_uid=os.geteuid(), client_uid=int(sys.argv[2]),
                docker_id=sys.argv[3], docker_root='/var/lib/docker') as store:
    store.begin(sys.argv[4], sys.argv[5], 'perturbed', sys.argv[6])
    if sys.argv[7] == 'yes':
        store.ack(sys.argv[8])
    print('durable', flush=True)
    sys.stdin.buffer.read(1)
"""
    child = subprocess.Popen(
        [sys.executable, "-B", "-S", "-c", program, str(directory),
         str(options()["client_uid"]), DOCKER_ID, NAME, RUN, ARTIFACT,
         "yes" if acknowledged else "no", CID],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        assert select.select([child.stdout], [], [], 5)[0]
        assert child.stdout.readline() == b"durable\n", child.stderr.read()
        with pytest.raises(state.StateError, match="^state_locked$"):
            with open_store(directory):
                pytest.fail("child lock ignored")
        child.kill()
        assert child.wait(timeout=5) == -signal.SIGKILL
        with open_store(directory) as store:
            assert store.pending()["container_id"] == (CID if acknowledged else None)
            if acknowledged:
                store.finish()
                assert store.pending() is None
            else:
                with pytest.raises(state.StateError, match="^state_transition_invalid$"):
                    store.finish()
                assert store.pending()["container_id"] is None
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


@pytest.mark.parametrize("change", [
    {"docker_id": "another-daemon"}, {"docker_root": "/another/docker-root"},
    {"client_uid": 9876},
])
def test_identity_mismatch_refuses_to_open(directory, change):
    with open_store(directory, initialize=True):
        pass
    with pytest.raises(state.StateError, match="^state_identity_mismatch$"):
        with open_store(directory, **change):
            pytest.fail("identity mismatch accepted")


@pytest.mark.parametrize(("name", "run", "variant", "artifact"), [
    ("foreign", RUN, "perturbed", ARTIFACT),
    (NAME, "not-a-run", "perturbed", ARTIFACT),
    (NAME, RUN, None, ARTIFACT),
    (NAME, RUN, "other", ARTIFACT),
    (NAME, RUN, "perturbed", "short"),
])
def test_bad_metadata_does_not_create_intent(directory, name, run, variant, artifact):
    with open_store(directory, initialize=True) as store:
        with pytest.raises(state.StateError, match="^state_record_invalid$"):
            store.begin(name, run, variant, artifact)
        assert store.pending() is None


def test_transitions_cannot_discard_ambiguous_or_replace_known_id(directory):
    with open_store(directory, initialize=True) as store:
        with pytest.raises(state.StateError, match="^state_transition_invalid$"):
            store.ack(CID)
        begin(store)
        with pytest.raises(state.StateError, match="^state_transition_invalid$"):
            begin(store)
        with pytest.raises(state.StateError, match="^state_transition_invalid$"):
            store.finish()
        with pytest.raises(state.StateError, match="^state_transition_invalid$"):
            store.ack("short-id")
        store.ack(CID)
        with pytest.raises(state.StateError, match="^state_transition_invalid$"):
            store.ack("e" * 64)
        assert store.pending()["container_id"] == CID


@pytest.mark.parametrize("sql", [
    "UPDATE installation SET schema='unknown'",
    "UPDATE installation SET installation_id='bad'",
    "UPDATE installation SET guard_uid=9876",
    "UPDATE events SET sequence=2",
    "UPDATE events SET kind='FINISH'",
    "UPDATE events SET payload='{}'",
    "UPDATE events SET payload='{\"x\":1,\"x\":2}'",
    "DELETE FROM events",
    "UPDATE installation SET event_count=999",
    "CREATE TABLE unexpected (x TEXT)",
])
def test_corrupt_schema_identity_or_history_refuses_open(directory, sql):
    with open_store(directory, initialize=True) as store:
        begin(store)
    with sqlite3.connect(directory / state.DATABASE) as db:
        db.execute(sql)
    with pytest.raises(state.StateError):
        with open_store(directory):
            pytest.fail("corrupt state accepted")


@pytest.mark.parametrize("entry", [state.LOCK, state.DATABASE])
@pytest.mark.parametrize("alias", ["hard", "symbolic"])
def test_links_are_rejected(directory, entry, alias):
    with open_store(directory, initialize=True):
        pass
    with tempfile.TemporaryDirectory(prefix=".guard-state-alias-", dir=directory.parent) as raw:
        target = Path(raw) / entry
        original = directory / entry
        if alias == "hard":
            os.link(original, target)
        else:
            original.rename(target)
            original.symlink_to(target)
        with pytest.raises(state.StateError, match="^state_file_invalid$"):
            with open_store(directory):
                pytest.fail("linked state opened")


@pytest.mark.parametrize("mode", [0o750, 0o770, 0o777])
def test_directory_mode_is_exact(directory, mode):
    directory.chmod(mode)
    with pytest.raises(state.StateError, match="^state_directory_invalid$"):
        with open_store(directory, initialize=True):
            pytest.fail("insecure directory accepted")


def test_symlink_directory_and_world_writable_ancestor_rejected(directory):
    child = directory / "child"
    child.mkdir(mode=0o700)
    alias = directory / "alias"
    alias.symlink_to(child)
    with pytest.raises(state.StateError, match="^state_directory_invalid$"):
        with open_store(alias, initialize=True):
            pytest.fail("alias accepted")
    directory.chmod(0o777)
    with pytest.raises(state.StateError, match="^state_directory_invalid$"):
        with open_store(child, initialize=True):
            pytest.fail("writable ancestor accepted")


def test_commit_reply_lost_preserves_intent_and_poisoned_handle(directory):
    class CommitLost:
        def __init__(self, db):
            self.db = db

        def execute(self, *args):
            return self.db.execute(*args)

        def commit(self):
            self.db.commit()
            raise sqlite3.OperationalError("simulated ambiguous commit with sensitive text")

        def rollback(self):
            return self.db.rollback()

    with open_store(directory, initialize=True) as store:
        store._db = CommitLost(store._db)
        with pytest.raises(state.StateError, match="^state_io_error$"):
            begin(store)
        with pytest.raises(state.StateError, match="^state_unavailable$"):
            store.pending()
    with open_store(directory) as recovered:
        assert recovered.pending()["container_id"] is None


def test_fsync_failure_does_not_report_success(directory, monkeypatch):
    with open_store(directory, initialize=True) as store:
        real_fsync = os.fsync

        def fail(_):
            raise OSError("private path must not escape")

        monkeypatch.setattr(os, "fsync", fail)
        with pytest.raises(state.StateError, match="^state_io_error$"):
            begin(store)
        monkeypatch.setattr(os, "fsync", real_fsync)
    with open_store(directory) as store:
        assert store.pending()["container_id"] is None

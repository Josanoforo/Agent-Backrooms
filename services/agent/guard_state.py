"""Private Linux state for a single invoice guard installation.

Provision an existing dedicated directory with mode 0700. Initialization is
explicit and refuses any existing entries. SQLite transactions append PENDING,
ACK and FINISH to the events table. FINISH requires an acknowledged container
ID, and its caller must first prove cleanup. Unknown creates remain pending
across restarts. This module neither contacts Docker nor resolves ambiguity.
"""

from contextlib import contextmanager
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import sys
import uuid

if sys.platform == "linux":
    import fcntl


SCHEMA = "guard-recovery/v1"
LOCK = "state.lock"
DATABASE = "state.sqlite3"
MAX_BYTES = 16 * 1024 * 1024
MAX_EVENTS = 20_000
MAX_PAYLOAD = 1024
HEX32 = re.compile(r"[a-f0-9]{32}")
HEX64 = re.compile(r"[a-f0-9]{64}")
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
METADATA_SQL = (
    "CREATE TABLE installation (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
    "schema TEXT NOT NULL, installation_id TEXT NOT NULL, guard_uid INTEGER NOT NULL, "
    "client_uid INTEGER NOT NULL, docker_id TEXT NOT NULL, docker_root TEXT NOT NULL, "
    "event_count INTEGER NOT NULL CHECK(event_count>=0))"
)
EVENTS_SQL = (
    "CREATE TABLE events (sequence INTEGER PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL)"
)


class StateError(Exception):
    """Stable local reason. No filesystem paths or underlying errors escape."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _identity(guard_uid, client_uid, docker_id, docker_root):
    if (
        type(guard_uid) is not int or type(client_uid) is not int
        or not 0 <= guard_uid < 2**32 - 1 or not 0 <= client_uid < 2**32 - 1
        or guard_uid == client_uid or guard_uid != os.geteuid()
        or not _matches(TOKEN, docker_id)
        or not isinstance(docker_root, str) or not 1 < len(docker_root) <= 4096
        or PurePosixPath(docker_root).anchor != "/" or str(PurePosixPath(docker_root)) != docker_root
        or ".." in PurePosixPath(docker_root).parts
        or any(ord(char) < 32 for char in docker_root)
    ):
        raise StateError("state_identity_invalid")
    return (guard_uid, client_uid, docker_id, docker_root)


def _directory(raw, uid):
    path = Path(raw)
    if (
        not path.is_absolute() or path.anchor != "/" or ".." in path.parts
        or path == Path("/")
    ):
        raise StateError("state_directory_invalid")
    for parent in reversed((path, *path.parents)):
        meta = parent.lstat()
        if (
            not stat.S_ISDIR(meta.st_mode) or meta.st_uid not in (0, uid)
            or meta.st_mode & 0o022
        ):
            raise StateError("state_directory_invalid")
    meta = path.lstat()
    if meta.st_uid != uid or stat.S_IMODE(meta.st_mode) != 0o700:
        raise StateError("state_directory_invalid")
    return path


def _file(meta, uid):
    if (
        not stat.S_ISREG(meta.st_mode) or meta.st_uid != uid
        or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_nlink != 1
        or meta.st_size > MAX_BYTES
    ):
        raise StateError("state_file_invalid")


def _check_files(path, uid):
    names = {item.name for item in path.iterdir()}
    if names - {LOCK, DATABASE, DATABASE + "-journal"}:
        raise StateError("state_file_invalid")
    if not {LOCK, DATABASE} <= names:
        raise StateError("state_incomplete")
    for name in names:
        _file((path / name).lstat(), uid)


def _json_payload(raw):
    if not isinstance(raw, str) or len(raw) > MAX_PAYLOAD:
        raise StateError("state_corrupt")
    try:
        value = json.loads(raw)
        # Canonical bytes also exclude duplicate keys and non-finite values.
        if json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) != raw:
            raise ValueError
        return value
    except (ValueError, RecursionError):
        raise StateError("state_corrupt") from None


def _pending_record(record):
    if (
        not isinstance(record, dict)
        or set(record) != {"name", "run_id", "variant", "artifact_sha256", "container_id"}
        or not isinstance(record["name"], str)
        or not record["name"].startswith("escape-invoice-")
        or not _matches(HEX32, record["name"][len("escape-invoice-"):])
        or not _matches(HEX32, record["run_id"])
        or record["variant"] not in ("legitimate", "perturbed")
        or not _matches(HEX64, record["artifact_sha256"])
        or record["container_id"] is not None
    ):
        raise StateError("state_record_invalid")


class GuardState:
    def __init__(self, connection, path, identity, directory_fd, database_fd):
        self._db = connection
        self._path = path
        self._identity = identity
        self._dir_fd = directory_fd
        self._database_fd = database_fd
        self._failed = False
        self._closed = False
        self.installation_id = None
        self._load()

    def _load(self):
        if self._closed or self._failed:
            raise StateError("state_unavailable")
        _check_files(self._path, self._identity[0])
        before = os.fstat(self._database_fd)
        current = (self._path / DATABASE).lstat()
        if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise StateError("state_file_invalid")
        schema = self._db.execute(
            "SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        if schema != [("events", EVENTS_SQL), ("installation", METADATA_SQL)]:
            raise StateError("state_corrupt")
        rows = self._db.execute("SELECT * FROM installation").fetchall()
        if (
            len(rows) != 1 or rows[0][:2] != (1, SCHEMA)
            or not _matches(HEX32, rows[0][2])
        ):
            raise StateError("state_corrupt")
        if rows[0][3:7] != self._identity:
            raise StateError("state_identity_mismatch")
        if self.installation_id is not None and self.installation_id != rows[0][2]:
            raise StateError("state_identity_mismatch")
        self.installation_id = rows[0][2]
        total = self._db.execute("SELECT count(*) FROM events").fetchone()[0]
        if (
            type(rows[0][7]) is not int or rows[0][7] != total
            or not 0 <= total <= MAX_EVENTS
        ):
            raise StateError("state_corrupt")
        pending = None
        seen_names = set()
        count = 0
        for sequence, kind, raw in self._db.execute(
            "SELECT sequence,kind,payload FROM events ORDER BY sequence"
        ):
            count += 1
            if type(sequence) is not int or sequence != count:
                raise StateError("state_corrupt")
            payload = _json_payload(raw)
            if kind == "PENDING" and pending is None:
                try:
                    _pending_record(payload)
                except StateError:
                    raise StateError("state_corrupt") from None
                if payload["name"] in seen_names:
                    raise StateError("state_corrupt")
                seen_names.add(payload["name"])
                pending = payload
            elif kind == "ACK" and pending is not None and pending["container_id"] is None:
                if (
                    not isinstance(payload, dict) or set(payload) != {"container_id"}
                    or not _matches(HEX64, payload["container_id"])
                ):
                    raise StateError("state_corrupt")
                pending["container_id"] = payload["container_id"]
            elif kind == "FINISH" and pending is not None and pending["container_id"] is not None:
                if payload != {}:
                    raise StateError("state_corrupt")
                pending = None
            else:
                raise StateError("state_corrupt")
        return pending, count, seen_names

    def pending(self):
        try:
            pending, _, _ = self._load()
            return None if pending is None else dict(pending)
        except (sqlite3.Error, OSError) as exc:
            self._failed = True
            raise StateError("state_io_error") from exc
        except StateError:
            self._failed = True
            raise

    def _append(self, kind, payload):
        try:
            self._db.execute("BEGIN IMMEDIATE")
            pending, count, seen_names = self._load()
            if count >= MAX_EVENTS or kind == "PENDING" and count > MAX_EVENTS - 3:
                raise StateError("state_capacity")
            if kind == "PENDING":
                _pending_record(payload)
                allowed = pending is None and payload["name"] not in seen_names
            elif kind == "ACK":
                allowed = (
                    pending is not None and pending["container_id"] is None
                    and _matches(HEX64, payload["container_id"])
                )
            else:
                allowed = pending is not None and pending["container_id"] is not None
            if not allowed:
                raise StateError("state_transition_invalid")
            raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
            self._db.execute("INSERT INTO events VALUES (?,?,?)", (count + 1, kind, raw))
            self._db.execute("UPDATE installation SET event_count=? WHERE singleton=1", (count + 1,))
            self._db.commit()
            os.fsync(self._database_fd)
            os.fsync(self._dir_fd)
        except StateError:
            self._db.rollback()
            raise
        except (sqlite3.Error, OSError) as exc:
            self._failed = True
            try:
                self._db.rollback()
            except sqlite3.Error:
                pass
            raise StateError("state_io_error") from exc

    def begin(self, name, run_id, variant, artifact_sha256):
        self._append("PENDING", {
            "name": name, "run_id": run_id, "variant": variant,
            "artifact_sha256": artifact_sha256, "container_id": None,
        })

    def ack(self, container_id):
        self._append("ACK", {"container_id": container_id})

    def finish(self):
        """The caller must prove absence before completing an acknowledged intent."""
        self._append("FINISH", {})


@contextmanager
def open_state(directory, *, guard_uid, client_uid, docker_id, docker_root, initialize=False):
    if sys.platform != "linux":
        raise StateError("state_unsupported_platform")
    if type(initialize) is not bool:
        raise StateError("state_identity_invalid")
    identity = _identity(guard_uid, client_uid, docker_id, docker_root)
    connection = None
    directory_fd = lock_fd = database_fd = None
    store = None
    try:
        try:
            path = _directory(directory, guard_uid)
            directory_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            entries = set(os.listdir(directory_fd))
            if initialize and entries:
                raise StateError("state_initialization_exists")
            if not initialize:
                _check_files(path, guard_uid)
            lock_fd = os.open(
                LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
                | (os.O_CREAT | os.O_EXCL if initialize else 0),
                0o600, dir_fd=directory_fd,
            )
            _file(os.fstat(lock_fd), guard_uid)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise StateError("state_locked") from None
            lock_meta = os.fstat(lock_fd)
            named_meta = (path / LOCK).lstat()
            if (lock_meta.st_dev, lock_meta.st_ino) != (named_meta.st_dev, named_meta.st_ino):
                raise StateError("state_file_invalid")
            os.fsync(lock_fd)
            os.fsync(directory_fd)
            database_fd = os.open(
                DATABASE, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
                | (os.O_CREAT | os.O_EXCL if initialize else 0),
                0o600, dir_fd=directory_fd,
            )
            _file(os.fstat(database_fd), guard_uid)
            _check_files(path, guard_uid)
            connection = sqlite3.connect((path / DATABASE).as_uri() + "?mode=rw", uri=True, timeout=0)
            if connection.execute("PRAGMA journal_mode=DELETE").fetchone() != ("delete",):
                raise StateError("state_storage_invalid")
            connection.execute("PRAGMA synchronous=EXTRA")
            if connection.execute("PRAGMA synchronous").fetchone() != (3,):
                raise StateError("state_storage_invalid")
            page_size = connection.execute("PRAGMA page_size").fetchone()[0]
            connection.execute(f"PRAGMA max_page_count={MAX_BYTES // page_size}")
            if initialize:
                with connection:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(METADATA_SQL)
                    connection.execute(EVENTS_SQL)
                    connection.execute(
                        "INSERT INTO installation VALUES (1,?,?,?,?,?,?,0)",
                        (SCHEMA, uuid.uuid4().hex, *identity),
                    )
                os.fsync(database_fd)
                os.fsync(directory_fd)
            if connection.execute("PRAGMA integrity_check(1)").fetchall() != [("ok",)]:
                raise StateError("state_corrupt")
            store = GuardState(connection, path, identity, directory_fd, database_fd)
        except StateError:
            raise
        except (sqlite3.Error, OSError, ValueError) as exc:
            raise StateError("state_io_error") from exc
        yield store
    finally:
        if store is not None:
            store._closed = True
        if connection is not None:
            connection.close()
        for descriptor in (database_fd, lock_fd, directory_fd):
            if descriptor is not None:
                os.close(descriptor)

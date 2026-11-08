"""Recovery of the SQLite run state: interrupted runs, terminal-write fallback, usage records,
coherent copies and guarded restoration.

Scope: the *state database* only (runs, receipts, events, quotas, usage). It does not recover a
VM, Docker images or containers. Standard library plus ``usage`` only (no web framework), so the
local CLI ``scripts/backup_state.py`` can import it. No network, no credentials.
"""
import contextlib
import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import usage

BACKUP_SCHEMA = 'escape-state-backup/v1'
RESTORED_BLOCK = 'restored_block'
CLEANUP_BLOCK = 'cleanup_block'
RECONCILIATION_LOG = 'reconciliation_log'
INTERRUPTED_ERROR = 'Service restarted during run'
TERMINAL_STATUSES = ('completed', 'failed', 'cancelled')
COUNTER_FIELDS = ('runs', 'calls', 'output_tokens_reserved')
BLOCK_REASONS = ((RESTORED_BLOCK, 'restored_state_unreconciled'), (CLEANUP_BLOCK, 'cleanup_unconfirmed'))
# Only these rooms can be reconciled through Docker inventory alone after interruption.
_DOCKER_CLEANUP_LEVELS = frozenset(('secret', 'network', 'memory', 'persistence', 'injection', 'workflow', 'privileges'))
_RUN_ID = re.compile(r'[0-9a-f]{32}\Z')


class RecoveryError(Exception):
    """A recovery precondition failed; nothing was changed."""


class AdmissionClosed(Exception):
    def __init__(self, reason, block_id=None):
        super().__init__(reason)
        self.reason, self.block_id = reason, block_id


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


@contextlib.contextmanager
def immediate(conn):
    """BEGIN IMMEDIATE ... COMMIT, or ROLLBACK on any error. Works for either isolation mode."""
    conn.execute('BEGIN IMMEDIATE')
    try:
        yield conn
    except BaseException:
        if conn.in_transaction: conn.rollback()
        raise
    else:
        conn.commit()


# ---------------------------------------------------------------- schema and operational state

def ensure_schema(conn):
    conn.execute('CREATE TABLE IF NOT EXISTS ops_state (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)')
    conn.execute('CREATE TABLE IF NOT EXISTS run_usage (run_id TEXT PRIMARY KEY, state TEXT NOT NULL, summary TEXT NOT NULL, updated_at TEXT NOT NULL)')
    # P3 sidecars. Neither is part of the run row, the report or its hash: provenance and the cancel request live beside them.
    conn.execute("CREATE TABLE IF NOT EXISTS run_meta (run_id TEXT PRIMARY KEY, origin TEXT NOT NULL CHECK(origin IN ('real','fixture','unknown')), created_at TEXT NOT NULL)")
    conn.execute('CREATE TABLE IF NOT EXISTS run_cancel (run_id TEXT PRIMARY KEY, requested_at TEXT NOT NULL)')


def record_meta(conn, run_id, origin, created_at):
    """Declared provenance and server admission time of a NEW run (inside the admission transaction). Never rewritten."""
    conn.execute('INSERT INTO run_meta(run_id,origin,created_at) VALUES(?,?,?)', (run_id, origin, created_at))


def cancel_marked(conn, run_id):
    """Whether a durable cancel request exists for the run (False when the table does not exist yet)."""
    try:
        return conn.execute('SELECT 1 FROM run_cancel WHERE run_id=?', (run_id,)).fetchone() is not None
    except sqlite3.OperationalError as exc:
        if _table_missing(exc): return False
        raise


def _table_missing(exc):
    return 'no such table' in str(exc)


def get_state(conn, key):
    try:
        row = conn.execute('SELECT value FROM ops_state WHERE key=?', (key,)).fetchone()
    except sqlite3.OperationalError as exc:
        if _table_missing(exc): return None
        raise
    if row is None: return None
    value = json.loads(row[0])
    if value is None and key in (CLEANUP_BLOCK, RESTORED_BLOCK):
        raise sqlite3.DataError('Operational block has no value')
    return value


def set_state(conn, key, value):
    conn.execute('INSERT OR REPLACE INTO ops_state(key,value,updated_at) VALUES(?,?,?)', (key, json.dumps(value, sort_keys=True), now_iso()))


def clear_state(conn, key):
    conn.execute('DELETE FROM ops_state WHERE key=?', (key,))


def admission_block(conn):
    """{'reason', 'block_id'} when new runs must not be admitted, else None. Restored state wins."""
    for key, reason in BLOCK_REASONS:
        value = get_state(conn, key)
        if value is not None:
            return {'reason': reason, 'block_id': value.get('block_id') if isinstance(value, dict) else None}
    return None


def open_readonly(path):
    return sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True, timeout=10)


def read_admission_block(db_path):
    """Read-only check used by /api/config; never writes and never creates the database."""
    if not Path(db_path).is_file(): return None
    try:
        with contextlib.closing(open_readonly(db_path)) as conn:
            return admission_block(conn)
    except (sqlite3.Error, json.JSONDecodeError):
        return {'reason': 'state_unavailable', 'block_id': None}


def read_state(db_path, key):
    if not Path(db_path).is_file(): return None
    with contextlib.closing(open_readonly(db_path)) as conn:
        return get_state(conn, key)


# ---------------------------------------------------------------- events and usage records

def insert_event(conn, run_id, kind, data):
    conn.execute('INSERT INTO events(run_id,kind,data) VALUES(?,?,?)', (run_id, kind, json.dumps(data)))


def unavailable_usage(run_id, reason):
    """Measurement lost (for example abrupt crash before any checkpoint): unknown, never zero."""
    return {'schema': usage.SCHEMA, 'run_id': run_id, 'source': 'provider_response_usage', 'attempts_total': None,
            'coverage': {'known_calls': None, 'unknown_calls': None, 'partial_calls': None, 'ratio': None, 'complete': False},
            'tokens': None, 'cost_usd': None, 'cost': None, 'rejected_before_network': None, 'attempts': [],
            'measurement': {'state': 'unavailable', 'collection_finished': False, 'reason': reason},
            'notes': ['Usage measurement is unavailable for this run; unknown is not zero.']}


def usage_record(summary, state, reason=None):
    """Stored copy of a collector summary plus an additive ``measurement`` block.

    Only ``final`` means the collector finished with the run. Any other state may be missing
    attempts, so totals become lower bounds and coverage is never reported complete.
    """
    record = json.loads(json.dumps(summary))
    measurement = {'state': state, 'collection_finished': state == 'final'}
    if reason: measurement['reason'] = reason
    record['measurement'] = measurement
    if state != 'final':
        if isinstance(record.get('coverage'), dict): record['coverage']['complete'] = False
        if isinstance(record.get('tokens'), dict): record['tokens']['lower_bound'] = True
        if isinstance(record.get('cost'), dict) and record['cost'].get('usd') is not None: record['cost']['lower_bound'] = True
    return record


def save_usage(conn, run_id, record, state, overwrite=False):
    """Checkpoints (overwrite=False) never replace a row that already left ``in_progress``."""
    values = (run_id, state, json.dumps(record, sort_keys=True), now_iso())
    if overwrite:
        conn.execute('INSERT OR REPLACE INTO run_usage(run_id,state,summary,updated_at) VALUES(?,?,?,?)', values)
    else:
        conn.execute("INSERT INTO run_usage(run_id,state,summary,updated_at) VALUES(?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET state=excluded.state, summary=excluded.summary, updated_at=excluded.updated_at WHERE run_usage.state='in_progress'", values)


def get_usage(conn, run_id):
    try:
        row = conn.execute('SELECT summary FROM run_usage WHERE run_id=?', (run_id,)).fetchone()
    except sqlite3.OperationalError as exc:
        if _table_missing(exc): return None
        raise
    return json.loads(row[0]) if row else None


# ---------------------------------------------------------------- terminal state

def _known_levels(levels):
    return isinstance(levels, list) and bool(levels) and all(
        isinstance(level, str) and (level == 'processes' or level in _DOCKER_CLEANUP_LEVELS) for level in levels)


def _decode_json(value):
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return None


def _docker_sweep_can_clear(conn, block):
    if not isinstance(block, dict) or not isinstance(block.get('block_id'), str) or not block['block_id']:
        return False
    levels = block.get('levels')
    if block.get('cause') != 'interrupted_run':
        return _known_levels(levels) and 'processes' not in levels

    if not isinstance(block.get('run_id'), str): return False
    run = conn.execute('SELECT levels,status,summary FROM runs WHERE id=?', (block['run_id'],)).fetchone()
    if run is None or run[1] not in ('failed', 'cancelled'): return False
    persisted_levels = _decode_json(run[0])
    if not _known_levels(persisted_levels): return False
    # Older interrupted-run blocks did not record their level. Use the durable run, and preserve any contradiction.
    if 'levels' in block and levels != persisted_levels: return False
    # The running transition commits before any level creates a sandbox.
    return 'processes' not in persisted_levels or _decode_json(run[2]) == interrupted_summary('queued')


def clear_swept_cleanup_block(conn, expected):
    """Clear only the block observed before the sweep, and only when Docker alone suffices."""
    with immediate(conn):
        block = get_state(conn, CLEANUP_BLOCK)
        if block != expected or not _docker_sweep_can_clear(conn, block):
            return False
        clear_state(conn, CLEANUP_BLOCK)
        return True


def write_terminal(conn, run_id, status, summary, usage_record_=None, block=None):
    """Terminal status, usage record, optional admission block and the terminal event in ONE transaction.

    Returns False without writing anything when the run is already terminal, so the transition
    (and its event) happens at most once however many times recovery repeats it.
    """
    if status not in TERMINAL_STATUSES: raise ValueError('Not a terminal status')
    with immediate(conn):
        cursor = conn.execute("UPDATE runs SET status=?,summary=? WHERE id=? AND status IN ('queued','running')", (status, json.dumps(summary), run_id))
        if cursor.rowcount != 1: return False
        if usage_record_ is not None:
            save_usage(conn, run_id, usage_record_, (usage_record_.get('measurement') or {}).get('state', 'final'), overwrite=True)
        if block is not None:
            previous = get_state(conn, CLEANUP_BLOCK)
            if previous is None or _docker_sweep_can_clear(conn, previous):
                set_state(conn, CLEANUP_BLOCK, block)
        insert_event(conn, run_id, 'run', {'id': run_id, 'status': status, 'summary': summary})
        return True


def interrupted_summary(previous_status):
    return {'error': INTERRUPTED_ERROR, 'interrupted': True, 'interrupted_from': previous_status, 'evidence_incomplete': True}


def _interrupted_usage(conn, run_id):
    stored = get_usage(conn, run_id)
    if stored is None:
        return unavailable_usage(run_id, 'process_restart_no_checkpoint')
    if (stored.get('measurement') or {}).get('state') == 'in_progress':
        return usage_record(stored, 'interrupted', 'process_restart')
    return None  # already final/interrupted/unavailable: keep what was stored


def spool_dir(db_path):
    return str(db_path) + '.terminal-spool'


def spool_terminal(db_path, run_id, payload):
    """Durable fallback when SQLite refuses the terminal write: an atomic JSON file beside the database."""
    directory = Path(spool_dir(db_path))
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / (run_id + '.json')
    temporary = directory / (run_id + '.tmp-' + uuid.uuid4().hex[:8])
    with open(temporary, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, target)


def load_spool(db_path):
    found = {}
    directory = Path(spool_dir(db_path))
    if not directory.is_dir(): return found
    for entry in directory.iterdir():
        if entry.suffix != '.json' or not _RUN_ID.match(entry.stem): continue
        try:
            payload = json.loads(entry.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        if isinstance(payload, dict) and payload.get('status') in TERMINAL_STATUSES and isinstance(payload.get('summary'), dict):
            found[entry.stem] = payload
    return found


def discard_spool(db_path, run_id):
    if _RUN_ID.match(run_id):
        with contextlib.suppress(OSError):
            (Path(spool_dir(db_path)) / (run_id + '.json')).unlink()


def recover_interrupted(conn, db_path=None):
    """Startup recovery. Idempotent: a run leaves queued/running exactly once.

    * A spooled terminal outcome (written when SQLite failed at the end of a run) is replayed as is.
    * Otherwise the run is failed with a persistent event and explicit incomplete-evidence marks.
      Receipts, quotas and partial usage stay as stored; nothing is executed or called again.
    Interrupted runs also close admission until sandbox cleanup is confirmed.
    """
    spooled = load_spool(db_path) if db_path else {}
    rows = conn.execute("SELECT id,status,levels FROM runs WHERE status IN ('queued','running') ORDER BY rowid").fetchall()
    recovered = []
    for row in rows:
        run_id, previous = row[0], row[1]
        payload = spooled.get(run_id)
        if payload is not None:
            written = write_terminal(conn, run_id, payload['status'], payload['summary'], payload.get('usage'), payload.get('block'))
            how, status = 'spool_replayed', payload['status']
        else:
            levels = _decode_json(row[2])
            block = {'reason': 'cleanup_unconfirmed', 'block_id': uuid.uuid4().hex, 'run_id': run_id,
                     'cause': 'interrupted_run', 'at': now_iso(),
                     'levels': levels if _known_levels(levels) else None}
            # A durable cancel request that never reached the task (crash between its commit and the signal) is honoured
            # here, without inference: the run ends 'cancelled' and keeps the interrupted/incomplete-evidence marks.
            requested = cancel_marked(conn, run_id)
            status = 'cancelled' if requested else 'failed'
            written = write_terminal(conn, run_id, status, interrupted_summary(previous), _interrupted_usage(conn, run_id), block)
            how = 'interrupted_cancel_requested' if requested else 'interrupted'
        if written: recovered.append({'id': run_id, 'status': status, 'how': how})
    if db_path:
        for run_id in spooled: discard_spool(db_path, run_id)
    return recovered


# ---------------------------------------------------------------- copy, restore, reconcile

def _local(path, label):
    text = os.fspath(path)
    if not isinstance(text, str) or not text or '\x00' in text or '://' in text or text.startswith(('\\\\', '//')):
        raise RecoveryError(label + ' must be a local filesystem path')
    return Path(text)


def _sidecars(path):
    return [Path(str(path) + suffix) for suffix in ('-wal', '-shm', '-journal')]


def _new_destination(path, label):
    target = _local(path, label).resolve()
    if not target.parent.is_dir(): raise RecoveryError(label + ' directory does not exist')
    if target.exists() or any(item.exists() for item in _sidecars(target)):
        raise RecoveryError(label + ' already exists; it is never overwritten')
    return target


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def _scalar(conn, sql):
    try:
        return conn.execute(sql).fetchone()[0]
    except sqlite3.OperationalError as exc:
        if _table_missing(exc): return None
        raise


def counters_of(conn):
    try:
        row = conn.execute('SELECT runs,calls,output_tokens_reserved FROM budget WHERE id=1').fetchone()
    except sqlite3.OperationalError as exc:
        raise RecoveryError('Database has no budget counters') from exc
    if row is None: raise RecoveryError('Database has no budget counters')
    return dict(zip(COUNTER_FIELDS, row))


def counters_of_database(path):
    source = _local(path, 'database')
    if not source.is_file(): raise RecoveryError('Database file not found')
    with contextlib.closing(open_readonly(source)) as conn:
        return counters_of(conn)


def _inspect(conn):
    if [tuple(r) for r in conn.execute('PRAGMA integrity_check').fetchall()] != [('ok',)]:
        raise RecoveryError('SQLite integrity check failed')
    counts = {'runs': _scalar(conn, 'SELECT COUNT(*) FROM runs'), 'run_config': _scalar(conn, 'SELECT COUNT(*) FROM run_config'),
              'run_usage': _scalar(conn, 'SELECT COUNT(*) FROM run_usage'), 'events': _scalar(conn, 'SELECT COUNT(*) FROM events'),
              'receipts': _scalar(conn, "SELECT COUNT(*) FROM events WHERE kind='receipt'")}
    return {'counters': counters_of(conn), 'counts': counts, 'last_event_seq': _scalar(conn, 'SELECT MAX(seq) FROM events')}


def _copy_with_backup_api(source, temporary):
    """SQLite Backup API from a read-only source connection: one consistent snapshot of every page."""
    reader = open_readonly(source)
    try:
        writer = sqlite3.connect(str(temporary))
        try:
            reader.backup(writer)
        finally:
            writer.close()
    finally:
        reader.close()


def _publish(temporary, target):
    """Make the finished file appear at target without ever replacing an existing file."""
    try:
        os.link(temporary, target)
    except FileExistsError as exc:
        raise RecoveryError('destination already exists; it is never overwritten') from exc
    except OSError:
        if target.exists(): raise RecoveryError('destination already exists; it is never overwritten')
        os.replace(temporary, target)
        return
    os.unlink(temporary)


def _discard(temporary):
    for item in [Path(temporary)] + _sidecars(temporary):
        with contextlib.suppress(OSError): item.unlink()


def _private(path):
    with contextlib.suppress(OSError): os.chmod(path, 0o600)


def _write_manifest(path, manifest):
    with open(path, 'x', encoding='utf-8') as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)


def load_manifest(path):
    try:
        manifest = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise RecoveryError('Backup manifest is missing or unreadable') from exc
    if not isinstance(manifest, dict) or manifest.get('schema') != BACKUP_SCHEMA:
        raise RecoveryError('Unsupported backup manifest')
    return manifest


def _manifest_path(backup, manifest_path):
    return _local(manifest_path, 'manifest') if manifest_path else Path(str(backup) + '.manifest.json')


def backup_database(source, destination, manifest_path=None, clock=now_iso):
    """Coherent private copy of the state database plus a manifest (hash, date, RPO, counters)."""
    origin = _local(source, 'source').resolve()
    if not origin.is_file(): raise RecoveryError('Source database not found')
    target = _new_destination(destination, 'destination')
    if target == origin: raise RecoveryError('destination must differ from the source')
    manifest_file = _manifest_path(target, manifest_path).resolve()
    if manifest_file.exists(): raise RecoveryError('manifest already exists; it is never overwritten')
    temporary = target.with_name(target.name + '.partial-' + uuid.uuid4().hex[:8])
    started, t0 = clock(), time.monotonic()
    try:
        _copy_with_backup_api(origin, temporary)
        # A WAL-mode source copies its WAL flag; store a single self-contained file instead.
        with contextlib.closing(sqlite3.connect(str(temporary))) as conn:
            conn.execute('PRAGMA journal_mode=DELETE').fetchone()
            info = _inspect(conn)
        _discard_sidecars_only(temporary)
        manifest = {'schema': BACKUP_SCHEMA, 'created_at': started, 'completed_at': clock(), 'backup_duration_ms': int((time.monotonic() - t0) * 1000),
                    'source_name': origin.name, 'file_name': target.name, 'sha256': _sha256_file(temporary), 'size_bytes': temporary.stat().st_size,
                    'sqlite_version': sqlite3.sqlite_version, 'integrity_check': 'ok', **info,
                    'rpo': {'recovery_point': started, 'meaning': 'Lower bound of the snapshot instant: data committed after it is not guaranteed to be in this copy.'},
                    'scope': 'sqlite_state_only', 'visibility': 'private_operational_copy_not_for_publication'}
        _publish(temporary, target)
        try:
            _write_manifest(manifest_file, manifest)
        except BaseException:
            with contextlib.suppress(OSError): target.unlink()
            raise
        _private(target)
        return manifest
    finally:
        _discard(temporary)


def _discard_sidecars_only(path):
    for item in _sidecars(path):
        with contextlib.suppress(OSError): item.unlink()


def verify_backup(backup, manifest_path=None, rpo_seconds=None, now=None):
    """Hash, integrity and counters against the manifest; raises RecoveryError on any mismatch."""
    source = _local(backup, 'backup').resolve()
    if not source.is_file(): raise RecoveryError('Backup file not found')
    manifest = load_manifest(_manifest_path(source, manifest_path))
    digest = _sha256_file(source)
    if digest != manifest.get('sha256') or source.stat().st_size != manifest.get('size_bytes'):
        raise RecoveryError('Backup hash does not match its manifest')
    with contextlib.closing(open_readonly(source)) as conn:
        info = _inspect(conn)
    for field in ('counters', 'counts', 'last_event_seq'):
        if info[field] != manifest.get(field): raise RecoveryError('Backup content does not match its manifest (' + field + ')')
    reference = now or datetime.now(timezone.utc)
    age = (reference - datetime.fromisoformat(manifest['created_at'])).total_seconds()
    return {'ok': True, 'sha256': digest, 'created_at': manifest['created_at'], 'age_seconds': age,
            'rpo_seconds_target': rpo_seconds, 'within_rpo': None if rpo_seconds is None else age <= rpo_seconds,
            'counters': info['counters'], 'counts': info['counts']}


def restore_database(backup, destination, manifest_path=None, clock=now_iso):
    """Restore into a NEW, different path and mark it blocked until explicit reconciliation.

    The marker is written before the file appears at its final name, so a restored database is
    never visible without the block. The backup file itself is not modified.
    """
    t0 = time.monotonic()
    source = _local(backup, 'backup').resolve()
    verified = verify_backup(source, manifest_path)
    manifest = load_manifest(_manifest_path(source, manifest_path))
    target = _new_destination(destination, 'destination')
    if target == source: raise RecoveryError('destination must differ from the backup')
    temporary = target.with_name(target.name + '.partial-' + uuid.uuid4().hex[:8])
    try:
        _copy_with_backup_api(source, temporary)
        restored_at = clock()
        with contextlib.closing(sqlite3.connect(str(temporary), isolation_level=None)) as conn:
            conn.execute('PRAGMA journal_mode=DELETE').fetchone()
            with immediate(conn):
                ensure_schema(conn)
                counters = counters_of(conn)
                if counters != manifest['counters']: raise RecoveryError('Restored counters differ from the manifest')
                previous = get_state(conn, RESTORED_BLOCK)
                block = {'block_id': uuid.uuid4().hex, 'reason': 'restored_state_unreconciled', 'restored_at': restored_at,
                         'backup_sha256': manifest['sha256'], 'backup_created_at': manifest['created_at'], 'counters_at_copy': counters,
                         'inherited_block_id': previous.get('block_id') if isinstance(previous, dict) else None,
                         'requires': 'backup_state.py reconcile with current counters >= counters_at_copy'}
                set_state(conn, RESTORED_BLOCK, block)
            _inspect(conn)
        _discard_sidecars_only(temporary)
        restored_sha = _sha256_file(temporary)
        _publish(temporary, target)
        _private(target)
    finally:
        _discard(temporary)
    created = datetime.fromisoformat(manifest['created_at'])
    return {'restored_to': str(target), 'block_id': block['block_id'], 'counters_at_copy': counters, 'backup_sha256': verified['sha256'],
            'restored_sha256': restored_sha, 'recovery_point': manifest['created_at'],
            'rpo_observed_seconds': (datetime.fromisoformat(restored_at) - created).total_seconds(),
            'rto_observed_ms': int((time.monotonic() - t0) * 1000), 'admission': 'blocked_until_reconciled'}


def _parse_counters(values):
    if not isinstance(values, dict) or set(values) != set(COUNTER_FIELDS):
        raise RecoveryError('Counters must provide exactly: ' + ', '.join(COUNTER_FIELDS))
    for field in COUNTER_FIELDS:
        if type(values[field]) is not int or values[field] < 0: raise RecoveryError(field + ' must be a non-negative integer')
    return {field: values[field] for field in COUNTER_FIELDS}


def reconcile_restored(db_path, block_id, counters, evidence, clock=now_iso):
    """Lift the restored-state block only with current counters at or above the copy's.

    Quotas never move backwards: every counter must be >= the copy's counters (and the database's
    own). The supplied counters become the stored ones and the decision is logged. This validates a
    monotonic bound; it cannot prove that the operator's figures are the live service's truth.
    """
    target = _local(db_path, 'database')
    if not target.is_file(): raise RecoveryError('Database file not found')
    supplied = _parse_counters(counters)
    if not isinstance(evidence, str) or not 3 <= len(evidence.strip()) <= 500 or not evidence.isprintable():
        raise RecoveryError('evidence must be a printable note (3-500 characters) saying where the counters come from')
    try:
        with contextlib.closing(sqlite3.connect(str(target), timeout=10, isolation_level=None)) as conn:
            with immediate(conn):
                marker = get_state(conn, RESTORED_BLOCK)
                if marker is None: raise RecoveryError('No restored-state block is present')
                if marker.get('block_id') != block_id: raise RecoveryError('block id does not match the current block')
                current, at_copy = counters_of(conn), marker['counters_at_copy']
                for field in COUNTER_FIELDS:
                    if supplied[field] < at_copy[field] or supplied[field] < current[field]:
                        raise RecoveryError(field + ' is lower than the restored copy; quotas cannot move backwards')
                conn.execute('UPDATE budget SET runs=?,calls=?,output_tokens_reserved=? WHERE id=1', tuple(supplied[f] for f in COUNTER_FIELDS))
                log = get_state(conn, RECONCILIATION_LOG) or []
                log.append({'block_id': block_id, 'at': clock(), 'counters_at_copy': at_copy, 'applied_counters': supplied, 'evidence': evidence.strip(),
                            'backup_sha256': marker.get('backup_sha256'), 'backup_created_at': marker.get('backup_created_at')})
                set_state(conn, RECONCILIATION_LOG, log[-20:])
                clear_state(conn, RESTORED_BLOCK)
    except sqlite3.Error as exc:
        raise RecoveryError('Database could not be updated') from exc
    return {'ok': True, 'block_id': block_id, 'applied_counters': supplied, 'counters_at_copy': at_copy}


def database_status(db_path):
    source = _local(db_path, 'database')
    if not source.is_file(): raise RecoveryError('Database file not found')
    with contextlib.closing(open_readonly(source)) as conn:
        return {'counters': counters_of(conn), 'restored_block': get_state(conn, RESTORED_BLOCK), 'cleanup_block': get_state(conn, CLEANUP_BLOCK),
                'reconciliations': get_state(conn, RECONCILIATION_LOG) or [], 'admission_block': admission_block(conn)}

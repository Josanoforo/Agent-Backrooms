"""Persistent conservative operational limits, independent of provider pricing."""
import contextlib
import os
import sqlite3
from pathlib import Path

class BudgetError(Exception): pass

# Default for agent calls. Tool-free explanations pass their own effective
# maximum explicitly; no global quota is increased by a larger per-call profile.
CALL_OUTPUT_TOKENS = 1024

def limits():
    try:
        values = tuple(int(os.getenv(name, default)) for name, default in (
            ('ESCAPE_MAX_RUNS', '10'), ('ESCAPE_MAX_CALLS', '40'), ('ESCAPE_MAX_OUTPUT_TOKENS', '40960')))
        if any(v < 0 for v in values): raise ValueError()
        return values
    except ValueError as exc:
        raise BudgetError('Invalid budget configuration') from exc

def initialize(conn):
    conn.execute('CREATE TABLE IF NOT EXISTS budget (id INTEGER PRIMARY KEY CHECK(id=1), runs INTEGER NOT NULL, calls INTEGER NOT NULL, output_tokens_reserved INTEGER NOT NULL)')
    conn.execute('INSERT OR IGNORE INTO budget VALUES (1,0,0,0)')

def read_counters(db):
    """Consumed counters without writing anything (read-only connection, never creates the file).

    A missing database or a database without the budget table has reserved nothing yet.
    """
    if not Path(db).is_file():
        return {'runs': 0, 'calls': 0, 'output_tokens_reserved': 0}
    try:
        with contextlib.closing(sqlite3.connect(Path(db).resolve().as_uri() + '?mode=ro', uri=True, timeout=10)) as conn:
            row = conn.execute('SELECT runs,calls,output_tokens_reserved FROM budget WHERE id=1').fetchone()
    except sqlite3.OperationalError as exc:
        if 'no such table' not in str(exc): raise BudgetError('Budget state unavailable') from exc
        row = None
    except sqlite3.Error as exc:
        raise BudgetError('Budget state unavailable') from exc
    runs, calls, tokens = row if row else (0, 0, 0)
    return {'runs': runs, 'calls': calls, 'output_tokens_reserved': tokens}

def snapshot(db):
    used = read_counters(db)
    mr, mc, mt = limits()
    return {'runs_remaining': max(0, mr-used['runs']), 'calls_remaining': max(0, mc-used['calls']), 'output_tokens_remaining': max(0, mt-used['output_tokens_reserved']), 'cost_usd': None}

def reserve_in(conn, kind, *, output_tokens=None):
    """Reserve inside a transaction owned by the caller (no BEGIN/COMMIT here).

    Admission uses this so the run reservation commits or rolls back together with the
    run row, its configuration and its first event.
    """
    initialize(conn)
    output_tokens = CALL_OUTPUT_TOKENS if output_tokens is None else output_tokens
    if type(output_tokens) is not int or not 1 <= output_tokens <= 16384:
        raise BudgetError('Invalid output reservation')
    runs, calls, tokens = conn.execute('SELECT runs,calls,output_tokens_reserved FROM budget WHERE id=1').fetchone()
    mr, mc, mt = limits()
    if kind == 'run':
        if runs >= mr or calls >= mc or tokens + output_tokens > mt: raise BudgetError('Operational budget exhausted')
        conn.execute('UPDATE budget SET runs=runs+1 WHERE id=1')
    elif kind == 'call':
        if calls >= mc or tokens + output_tokens > mt: raise BudgetError('Operational budget exhausted')
        conn.execute('UPDATE budget SET calls=calls+1, output_tokens_reserved=output_tokens_reserved+? WHERE id=1', (output_tokens,))
    else: raise ValueError('Unknown reservation')

def reserve(db, kind, *, output_tokens=None):
    try:
        with contextlib.closing(sqlite3.connect(db, timeout=10, isolation_level=None)) as conn:
            conn.execute('BEGIN IMMEDIATE')
            try:
                reserve_in(conn, kind, output_tokens=output_tokens)
                conn.execute('COMMIT')
            except BaseException:
                if conn.in_transaction: conn.execute('ROLLBACK')
                raise
    except sqlite3.Error as exc:
        # No reservation was made; callers must treat this as a rejection before the network.
        raise BudgetError('Budget state unavailable') from exc

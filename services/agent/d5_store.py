"""SQLite storage for D5 configurations and sealed suite admissions.

The caller owns the connection and transaction. Saving applies the current
controller policy. Reading verifies the versioned seal and stored identity, so
an archived configuration remains inspectable after a policy change. Reusing
it for execution requires validation against the current policy again.
"""

import re

from . import d5_configuration, d5_suite, missions


class StoreError(ValueError):
    """The persisted D5 document conflicts with its identity or format."""


def initialize(conn):
    conn.execute('''CREATE TABLE IF NOT EXISTS d5_configurations (
        configuration_id TEXT PRIMARY KEY NOT NULL,
        document TEXT NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS d5_suites (
        plan_id TEXT PRIMARY KEY NOT NULL,
        run_id TEXT UNIQUE NOT NULL,
        plan TEXT NOT NULL
    )''')


def save_configuration(conn, configuration, *, allowed_models, server_limits=None):
    """Insert a sealed configuration once, or return its identical prior value."""
    normalized = d5_configuration.validate_configuration(
        configuration, allowed_models=allowed_models, server_limits=server_limits,
    )
    configuration_id = normalized['configuration_id']
    document = missions.canonical(normalized)
    inserted = conn.execute('''INSERT INTO d5_configurations(configuration_id, document)
        VALUES (?, ?) ON CONFLICT(configuration_id) DO NOTHING''', (configuration_id, document))
    if inserted.rowcount == 0 and _stored_document(conn, configuration_id) != document:
        raise StoreError('stored configuration conflicts with its sealed identity')
    return normalized


def _stored_document(conn, configuration_id):
    row = conn.execute('SELECT document FROM d5_configurations WHERE configuration_id=?',
                       (configuration_id,)).fetchone()
    return None if row is None else row[0]


def get_configuration(conn, configuration_id):
    """Read a sealed historical configuration, or return None for an absent ID."""
    if type(configuration_id) is not str or not re.fullmatch(r'[0-9a-f]{64}', configuration_id):
        raise d5_configuration.ConfigurationError('configuration_id is invalid')
    document = _stored_document(conn, configuration_id)
    if document is None:
        return None
    try:
        envelope = missions.parse_strict(document)
        spec = envelope.get('specification') if type(envelope) is dict else None
        model = spec.get('model_id') if type(spec) is dict else None
        normalized = d5_configuration.validate_configuration(envelope, allowed_models=(model,))
    except (TypeError, ValueError, RecursionError):
        raise StoreError('stored configuration failed seal validation') from None
    if normalized['configuration_id'] != configuration_id or missions.canonical(normalized) != document:
        raise StoreError('stored configuration conflicts with its sealed identity')
    return normalized


def _require_candidate_run(plan, run_id):
    if type(run_id) is not str or not re.fullmatch(r'[0-9a-f]{32}', run_id):
        raise StoreError('suite run_id is invalid')
    if run_id == plan['specification']['baseline_run_id']:
        raise StoreError('suite run_id matches the baseline run')


def record_suite(conn, plan, run_id):
    """Bind the sealed plan to one candidate run in the caller's transaction."""
    verified = d5_suite.validate_plan(plan)
    _require_candidate_run(verified, run_id)
    plan_id = verified['plan_id']
    document = missions.canonical(verified)
    inserted = conn.execute('''INSERT INTO d5_suites(plan_id, run_id, plan)
        VALUES (?, ?, ?) ON CONFLICT DO NOTHING''', (plan_id, run_id, document))
    if inserted.rowcount == 0:
        stored = get_suite(conn, plan_id)
        if stored != {'plan': verified, 'run_id': run_id}:
            raise StoreError('suite plan or run already has a different binding')
    return {'plan': verified, 'run_id': run_id}


def get_suite(conn, plan_id):
    """Return the verified plan and its candidate run ID, or None if absent."""
    if type(plan_id) is not str or not re.fullmatch(r'[0-9a-f]{64}', plan_id):
        raise StoreError('suite plan_id is invalid')
    row = conn.execute('SELECT run_id, plan FROM d5_suites WHERE plan_id=?', (plan_id,)).fetchone()
    if row is None:
        return None
    run_id, document = row
    try:
        verified = d5_suite.validate_plan(missions.parse_strict(document))
    except (TypeError, ValueError, RecursionError):
        raise StoreError('stored suite plan failed seal validation') from None
    if verified['plan_id'] != plan_id or missions.canonical(verified) != document:
        raise StoreError('stored suite plan conflicts with its sealed identity')
    _require_candidate_run(verified, run_id)
    return {'plan': verified, 'run_id': run_id}

"""SQLite ledger for one private D4 campaign at a time."""
from decimal import Decimal, ROUND_CEILING, localcontext
import json
import os
import sqlite3

from . import budget, guards, recovery

PROVIDER_FRAMING_BYTES = 4096


class CampaignError(ValueError):
    pass


def initialize(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS d4_campaigns (
        id TEXT PRIMARY KEY, operator_key TEXT NOT NULL UNIQUE, digest TEXT NOT NULL,
        manifest TEXT NOT NULL, day_utc TEXT NOT NULL, reserved_microusd INTEGER NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS d4_runs (
        run_id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, position INTEGER NOT NULL,
        UNIQUE(campaign_id, position))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS d4_calls (
        run_id TEXT NOT NULL, variant TEXT NOT NULL, count INTEGER NOT NULL,
        PRIMARY KEY(run_id, variant))""")


def lookup(conn, campaign_id):
    row = conn.execute('SELECT manifest, day_utc, reserved_microusd FROM d4_campaigns WHERE id=?',
                       (campaign_id,)).fetchone()
    if row is None:
        return None
    manifest, day, reserved = row
    runs = conn.execute("""SELECT r.id, r.model, r.status FROM d4_runs d
        JOIN runs r ON r.id=d.run_id WHERE d.campaign_id=? ORDER BY d.position""", (campaign_id,))
    return {'manifest': json.loads(manifest), 'day_utc': day, 'reserved_microusd': reserved,
            'runs': [{'run_id': run_id, 'model_id': model, 'status': status}
                     for run_id, model, status in runs]}


def prior(conn, manifest):
    row = conn.execute('SELECT id, digest FROM d4_campaigns WHERE operator_key=?',
                       (manifest['idempotency_key'],)).fetchone()
    if row is not None:
        if row[1] != manifest['specification_sha256']:
            raise CampaignError('Campaign idempotency key has a different specification')
        return lookup(conn, row[0])
    return None


def cancel(conn, campaign_id):
    campaign = lookup(conn, campaign_id)
    if campaign is None:
        return None
    for run in campaign['runs']:
        run_id = run['run_id']
        requested = recovery.cancel_marked(conn, run_id)
        if run['status'] not in recovery.TERMINAL_STATUSES and not requested:
            now = recovery.now_iso()
            conn.execute('INSERT INTO run_cancel VALUES(?,?)', (run_id, now))
            recovery.insert_event(conn, run_id, 'cancel_requested', {
                'id': run_id, 'status': run['status'], 'cancel_requested': True, 'requested_at': now,
            })
            requested = True
        run['cancel_requested'] = requested
    return campaign


def dispatch_ledger(conn, run_id):
    counters = dict.fromkeys(('legitimate', 'perturbed'), 0)
    counters.update(conn.execute('SELECT variant,count FROM d4_calls WHERE run_id=?', (run_id,)))
    return {'schema': 'd4-dispatch-ledger/v1', 'reserved_slots': counters}


def reservation(specification):
    limits = specification['limits']
    with localcontext() as context:
        context.prec = 40
        costs = []
        for model in specification['models']:
            rate = specification['catalog']['models'][model]['rate']
            amount = ((limits['max_request_bytes'] + PROVIDER_FRAMING_BYTES) * Decimal(rate['input_per_million'])
                      + limits['max_output_tokens'] * Decimal(rate['output_per_million']))
            costs.append(int(amount.to_integral_value(rounding=ROUND_CEILING)))
    return sum(costs) * len(specification['variants']) * limits['calls_per_variant']


def require_day(day):
    if day != guards.day() or day != os.getenv('ESCAPE_D4_AUTHORIZED_DAY_UTC'):
        raise CampaignError('Campaign is outside its authorized UTC day')


def require_previous_evidence(conn, context):
    """Hold the queued model after an escape or loss of evidence on its predecessor."""
    rows = conn.execute("""SELECT prior.run_id, r.status, r.summary FROM d4_runs current
        JOIN d4_runs prior ON prior.campaign_id=current.campaign_id AND prior.position<current.position
        JOIN runs r ON r.id=prior.run_id WHERE current.run_id=?""", (context.run_id,))
    for run_id, status, raw_summary in rows:
        summary = json.loads(raw_summary).get('workflow', {})
        variants = [v for field in ('variants', 'completed_variants', 'observed_variants')
                    for v in summary.get(field, {}).values()]
        record = recovery.get_usage(conn, run_id) or {}
        attempts = record.get('attempts_total')
        ledger = dispatch_ledger(conn, run_id)['reserved_slots']
        if (status not in ('completed', 'failed') or not variants or summary.get('outcome') == 'escaped'
                or any(v.get('cleanup_confirmed') is not True or v.get('outcome') == 'escaped'
                       or v.get('sandbox_profile_sha256') != context.profile_sha256 for v in variants)
                or record.get('measurement', {}).get('collection_finished') is not True
                or type(attempts) is not int or attempts != sum(ledger.values())
                or (record.get('cost') or {}).get('unpriced_attempts') != 0):
            raise CampaignError('Campaign held after escape or incomplete prior containment, profile or cost evidence')


def admit(conn, manifest, configs, run_ids, day, origin):
    """Caller holds BEGIN IMMEDIATE. One commit reserves the whole campaign and both run rows."""
    require_day(day)
    if conn.execute('SELECT 1 FROM runs WHERE status IN (?,?) LIMIT 1', ('queued', 'running')).fetchone():
        raise CampaignError('Another run or campaign is active')
    if conn.execute('SELECT 1 FROM d4_campaigns WHERE id=?', (manifest['campaign_id'],)).fetchone():
        raise CampaignError('Campaign ID already exists')
    maximum = guards.limit()
    if maximum is None:
        raise CampaignError('Campaign requires a daily inference cap')
    specification = manifest['specification']
    amount = reservation(specification)
    guards.initialize(conn)
    current = conn.execute('SELECT reserved_microusd FROM daily_inference_budget WHERE day=?', (day,)).fetchone()
    if amount + (current[0] if current else 0) > maximum:
        raise CampaignError('Campaign daily inference reservation exceeds the remaining budget')
    limit_runs, limit_calls, limit_tokens = budget.limits()
    runs, calls, tokens = conn.execute('SELECT runs,calls,output_tokens_reserved FROM budget WHERE id=1').fetchone()
    declared = specification['limits']
    need_calls, need_tokens = declared['max_calls'], declared['max_calls'] * declared['max_output_tokens']
    if runs + 2 > limit_runs or calls + need_calls > limit_calls or tokens + need_tokens > limit_tokens:
        raise CampaignError('Campaign operational quota is insufficient')
    conn.execute("""INSERT INTO daily_inference_budget VALUES(?,?)
        ON CONFLICT(day) DO UPDATE SET reserved_microusd=reserved_microusd+excluded.reserved_microusd""", (day, amount))
    conn.execute('UPDATE budget SET runs=runs+2,calls=calls+?,output_tokens_reserved=output_tokens_reserved+? WHERE id=1',
                 (need_calls, need_tokens))
    cid = manifest['campaign_id']
    conn.execute('INSERT INTO d4_campaigns VALUES(?,?,?,?,?,?)',
                 (cid, manifest['idempotency_key'], manifest['specification_sha256'], json.dumps(manifest), day, amount))
    for index, (run_id, model, config) in enumerate(zip(run_ids, specification['models'], configs, strict=True)):
        conn.execute('INSERT INTO d4_runs VALUES(?,?,?)', (run_id, cid, index))
        conn.execute('INSERT INTO runs VALUES(?,?,?,?,?)', (run_id, 'queued', model, '["workflow"]', '{}'))
        conn.execute('INSERT INTO run_config VALUES(?,?)', (run_id, json.dumps(config)))
        recovery.record_meta(conn, run_id, origin, recovery.now_iso())
        recovery.insert_event(conn, run_id, 'run', {'id': run_id, 'status': 'queued'})
    require_day(day)
    return lookup(conn, cid)


def take_call(connect, context, variant, request_bytes):
    """Spend one prepaid slot before the HTTP transport. Uncertain sends retain it."""
    if type(request_bytes) is not int or not 0 < request_bytes <= context.max_request_bytes:
        raise CampaignError('Campaign request exceeds the reserved bound')
    try:
        with connect() as conn, recovery.immediate(conn):
            row = conn.execute("""SELECT c.id,c.digest,c.day_utc,r.model,r.status FROM d4_runs d
                JOIN d4_campaigns c ON c.id=d.campaign_id JOIN runs r ON r.id=d.run_id WHERE d.run_id=?""",
                (context.run_id,)).fetchone()
            if (row is None or (row[0], row[1], row[3], row[4]) !=
                    (context.campaign_id, context.specification_sha256, context.model_id, 'running')
                    or recovery.cancel_marked(conn, context.run_id) or recovery.admission_block(conn)):
                raise CampaignError('Campaign run is unavailable for inference')
            require_day(row[2])
            if variant not in ('legitimate', 'perturbed'):
                raise CampaignError('Campaign variant is unavailable')
            result = conn.execute("""INSERT INTO d4_calls VALUES(?,?,1)
                ON CONFLICT(run_id,variant) DO UPDATE SET count=count+1 WHERE count < ?""",
                (context.run_id, variant, context.calls_per_variant))
            if result.rowcount != 1:
                raise CampaignError('Campaign variant call allowance exhausted')
            require_day(row[2])
    except sqlite3.Error as exc:
        raise CampaignError('Campaign reservation state unavailable') from exc

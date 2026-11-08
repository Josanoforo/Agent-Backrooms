"""P3 operator helpers: run history, the cancel request record and comparison through the existing aggregator.

No web framework and no import of ``main`` (main imports this module). The only write is ``request_cancel``: the
request and its event are saved in ONE transaction. Nothing here calls a provider, reserves or refunds quota, or
touches a stored report: provenance (``run_meta``) and the cancel request (``run_cancel``) are sidecar rows, so the
report objects and their hashes stay exactly what they were.
"""
import collections
import copy
import importlib.util
import json
import os
import re
import sys
import time
from pathlib import Path

from . import recovery

ORIGINS = ('real', 'fixture', 'unknown')
TERMINAL = recovery.TERMINAL_STATUSES
DEFAULT_LIMIT, MAX_LIMIT = 20, 50
SQLITE_MAX_INT = 2 ** 63 - 1
_DIGITS = re.compile(r'[0-9]{1,3}')
_CURSOR = re.compile(r'[1-9][0-9]{0,18}')
_RUN_REF = re.compile(r'[A-Za-z0-9_-]{1,64}')  # an id, never a path, URL or document
AGGREGATOR_FILE = Path(__file__).resolve().parents[2] / 'scripts' / 'evaluation' / 'aggregate_reports.py'


class OperatorError(Exception):
    """A request the operator API refuses; ``status`` is the HTTP status, ``detail`` a short English message."""

    def __init__(self, status, detail):
        super().__init__(detail)
        self.status, self.detail = status, detail


def declared_origin():
    """Provenance declared by the SERVER environment (ESCAPE_EVIDENCE_ORIGIN). Not certification; a request cannot set it."""
    value = os.getenv('ESCAPE_EVIDENCE_ORIGIN', '').strip().lower()
    return value if value in ORIGINS else 'unknown'


# ---------------------------------------------------------------- history

def parse_limit(raw):
    if raw is None: return DEFAULT_LIMIT
    if not _DIGITS.fullmatch(raw) or not 1 <= int(raw) <= MAX_LIMIT:
        raise OperatorError(422, 'limit must be an integer from 1 to ' + str(MAX_LIMIT))
    return int(raw)


def parse_cursor(raw):
    """The cursor is the rowid of the last item of the previous page (decimal digits only)."""
    if raw is None: return None
    if not _CURSOR.fullmatch(raw) or int(raw) > SQLITE_MAX_INT: raise OperatorError(422, 'Invalid cursor')
    return int(raw)


def _levels_of(raw):
    try: value = json.loads(raw)
    except (TypeError, ValueError): return []
    return [x for x in value if isinstance(x, str)] if isinstance(value, list) else []


def list_runs(conn, limit, before=None):
    """Minimal projection, newest first by rowid. Bound parameters only; no prompts, receipts, summaries or tokens."""
    rows = conn.execute(
        'SELECT r.rowid AS pos, r.id, r.status, r.model, r.levels, m.origin, m.created_at, '
        'EXISTS(SELECT 1 FROM run_cancel c WHERE c.run_id = r.id) AS cancel_requested '
        'FROM runs r LEFT JOIN run_meta m ON m.run_id = r.id '
        'WHERE (? IS NULL OR r.rowid < ?) ORDER BY r.rowid DESC LIMIT ?', (before, before, limit + 1)).fetchall()
    items = [{'id': r['id'], 'status': r['status'], 'model': r['model'], 'levels': _levels_of(r['levels']),
              'created_at': r['created_at'], 'origin': r['origin'] if r['origin'] in ORIGINS else 'unknown',
              'cancel_requested': bool(r['cancel_requested'])} for r in rows[:limit]]
    return {'items': items, 'next_cursor': str(rows[limit - 1]['pos']) if len(rows) > limit else None}


def origins_of(conn, run_ids):
    found = {}
    for run_id in run_ids:
        row = conn.execute('SELECT origin FROM run_meta WHERE run_id=?', (run_id,)).fetchone()
        found[run_id] = row[0] if row and row[0] in ORIGINS else 'unknown'
    return found


# ---------------------------------------------------------------- cancellation

def request_cancel(conn, run_id, now=None):
    """Record a cancel request and its event atomically. Returns (payload, new) or None for an unknown run.

    Idempotent: a terminal run, or one already marked, is returned as stored with no write. The row status never
    changes here (no 'cancelling'); the task is told by the caller AFTER this commit. Quota is not touched.
    """
    with recovery.immediate(conn):
        row = conn.execute('SELECT status FROM runs WHERE id=?', (run_id,)).fetchone()
        if row is None: return None
        status = row[0]
        marked = recovery.cancel_marked(conn, run_id)
        if status in TERMINAL or marked:
            return {'id': run_id, 'status': status, 'cancel_requested': marked}, False
        now = now or recovery.now_iso()
        conn.execute('INSERT INTO run_cancel(run_id,requested_at) VALUES(?,?)', (run_id, now))
        recovery.insert_event(conn, run_id, 'cancel_requested', {'id': run_id, 'status': status, 'cancel_requested': True, 'requested_at': now})
        return {'id': run_id, 'status': status, 'cancel_requested': True}, True


class RunControl:
    """In-process coordination of one admitted run. Every method is synchronous: with a single event loop there is no
    await between a check and the phase change that follows it, which closes the races below.

    pending   admitted, the coroutine has not run its first instruction. ``Task.cancel()`` here could skip the coroutine's
              ``finally`` altogether (a task cancelled before it starts never runs its body), so the request is only
              remembered and the coroutine closes itself when it begins.
    executing levels may run: the one phase where ``Task.cancel()`` is delivered, and only once.
    closing   persistence of the terminal outcome and cleanup. Never interrupted: a repeated request cannot cut them short.
    """
    __slots__ = ('phase', 'cancel', 'signalled')

    def __init__(self):
        self.phase, self.cancel, self.signalled = 'pending', False, False

    def begin(self):
        """First instruction of the run coroutine. False: cancel was requested before it began (close without executing)."""
        if self.cancel:
            self.phase = 'closing'
            return False
        self.phase = 'executing'
        return True

    def closing(self):
        self.phase = 'closing'

    def signal(self, task):
        """Tell the run to stop: 'signalled' | 'deferred' | 'already' | 'late' (closing: left to finish)."""
        if self.signalled: return 'already'
        if self.phase == 'pending':
            self.cancel = self.signalled = True
            return 'deferred'
        if self.phase == 'executing':
            self.signalled = True
            if task is not None and not task.done(): task.cancel()
            return 'signalled'
        return 'late'


class Throttle:
    """Failed-authorization limiter for the operator endpoints (the run POST has its own rate limit)."""

    def __init__(self, maximum=20, window=60.0, capacity=10000, clock=time.monotonic):
        self.maximum, self.window, self.capacity, self.clock = maximum, window, capacity, clock
        self.hits = {}

    def blocked(self, key):
        queue = self.hits.get(key)
        if queue is None: return False
        now = self.clock()
        while queue and now - queue[0] >= self.window: queue.popleft()
        if not queue:
            del self.hits[key]
            return False
        return len(queue) >= self.maximum

    def record(self, key):
        now = self.clock()
        if key not in self.hits:
            if len(self.hits) >= self.capacity:
                for stale in [k for k, q in self.hits.items() if not q or now - q[-1] >= self.window]: del self.hits[stale]
            if len(self.hits) >= self.capacity: return  # bounded memory: stop tracking new clients rather than grow
            self.hits[key] = collections.deque(maxlen=self.maximum)
        self.hits[key].append(now)

    def clear(self):
        self.hits.clear()


# ---------------------------------------------------------------- comparison

def parse_compare_ids(left, right):
    for value in (left, right):
        if value is None or not _RUN_REF.fullmatch(value): raise OperatorError(422, 'left and right must be run ids')
    if left == right: raise OperatorError(422, 'left and right must be two different runs')
    return left, right


_aggregator = None


def aggregator():
    """The existing offline aggregator, loaded from its file once (read only; it is never run as a script)."""
    global _aggregator
    if _aggregator is None:
        spec = importlib.util.spec_from_file_location('escape_aggregate_reports', AGGREGATOR_FILE) if AGGREGATOR_FILE.is_file() else None
        if spec is None or spec.loader is None: raise OperatorError(503, 'Comparison is unavailable on this deployment')
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try: spec.loader.exec_module(module)
        except Exception as exc:
            sys.modules.pop(spec.name, None)
            raise OperatorError(503, 'Comparison is unavailable on this deployment') from exc
        _aggregator = module
    return _aggregator


SIDES = (('left', 'izquierda'), ('right', 'derecha'))


def _axis(variant, key):
    value = variant.get(key)
    return value.get('status') if isinstance(value, dict) and isinstance(value.get('status'), str) else None


def _variants(entry):
    """workflow: task and containment per variant, kept apart. Observed (cleanup not confirmed) variants stay labelled."""
    found = {}
    for field in ('variants', 'completed_variants', 'observed_variants'):
        group = entry.get(field) if isinstance(entry, dict) else None
        if not isinstance(group, dict): continue
        for name, variant in group.items():
            if isinstance(name, str) and isinstance(variant, dict) and name not in found:
                outcome = variant.get('outcome')
                found[name] = {'task': _axis(variant, 'task'), 'containment': _axis(variant, 'containment'), 'outcome': outcome if isinstance(outcome, str) else None, 'source': field}
    return found or None


def _tri(value):
    return {'true': True, 'false': False}.get(value)


def _detail(observation, entry):
    if observation is None: return None
    detail = {'verdict': observation['verdict'], 'tool_time_ms': observation['tool_time']['value_ms'], 'receipts': observation['tool_time']['receipts'],
              'memory_peak_bytes': observation['memory_peak']['value'], 'cleanup_confirmed': _tri(observation['cleanup_confirmed']),
              'oom_killed': _tri(observation['oom_killed']), 'receipt_outcomes': observation['receipt_outcomes']}
    variants = _variants(entry)
    if variants is not None: detail['variants'] = variants
    return detail


def _original_usage(doc, usage_entry):
    """The ``usage`` object exactly as the stored report carries it (cost, partial, attempts, rejected_before_network...).

    The aggregator's usage entry is a flattened digest (``cost_usd_estimated``, ``cost_partial``...) that the page's usage view
    does not read, so it would show a priced run as "cost not calculated". Same lookup as ``extract_usage`` (``/usage``, then
    ``/run/usage``); a report with no usage stays ``None`` (unknown, never 0). Copied, so the stored report is never aliased.
    """
    if usage_entry['status'] == 'absent': return None
    raw = doc.get('usage')
    if raw is None and isinstance(doc.get('run'), dict): raw = doc['run'].get('usage')
    return copy.deepcopy(raw)


def _analyze(agg, label, item):
    """The aggregator's reading of one stored report. Problems become reasons; nothing raises."""
    doc = item['report']
    try: run = agg.validate_report(doc)
    except agg.InputError as exc: return {'ok': False, 'blocking': ['El reporte de la corrida ' + label + ' no es válido (' + exc.code + ').']}
    display = 'run:' + run['id']
    hash_check = agg.check_report_hash(doc)
    profile_id, profile = agg.compute_profile(doc)
    effective = agg.effective_profile(doc)
    protocol = agg.protocol_info(doc)
    observations, anomalies = agg.extract_observations(run, display)
    usage_entry, usage_anomalies = agg.extract_usage(doc, display, run['id'], run['model'])
    blocking = []
    if hash_check['status'] != 'verified': blocking.append('No se pudo reproducir el hash del reporte de la corrida ' + label + ' (' + hash_check['status'] + ').')
    if profile is None: blocking.append('Perfil declarado ausente en la corrida ' + label + ': no es comparable.')
    if effective['status'] == 'unknown': blocking.append('Perfil efectivo del sandbox desconocido o incompleto en la corrida ' + label + ': no es comparable.')
    if protocol['status'] != 'recorded': blocking.append('Protocolo congelado ausente o inválido en la corrida ' + label + ': no es comparable.')
    recorded = protocol.get('protocol') or {}
    sources = recorded.get('sources')
    if isinstance(sources, dict) and not sources.get('sha256'):
        blocking.append('Identidad de fuentes desconocida en la corrida ' + label + ': no es comparable.')
    # The aggregate profile key can exist even when both reports omit the same evidence.
    # Keep the aggregator's semantics; additionally require coverage of each sandbox role
    # requested by this web comparison. Injection explicitly has no sandbox/tool test.
    summary = run.get('summary') or {}
    required = [level for level in run.get('levels', []) if level not in agg.SANDBOX_FREE_LEVELS]
    if required and effective['status'] != 'observed':
        blocking.append('Perfil efectivo no observado en la corrida ' + label + ': no es comparable.')
    for level in required:
        entry = summary.get(level) or {}
        fields = ('sandbox_profile', 'fresh_sandbox_profile') if level in ('workflow', 'persistence') else ('sandbox_profile',)
        for field in fields:
            value = entry.get(field) if isinstance(entry, dict) else None
            if not isinstance(value, dict) or value.get('available') is not True:
                blocking.append('Perfil efectivo incompleto en ' + label + ' / ' + level + ' / ' + field + '.')
            elif not value.get('image_id'):
                blocking.append('Identidad de imagen desconocida en ' + label + ' / ' + level + ' / ' + field + '.')
    flat = [{'pointer': a.get('pointer'), 'code': a.get('code')} for a in anomalies + usage_anomalies + effective['anomalies']]
    return {'ok': True, 'blocking': blocking, 'run': run, 'profile_id': profile_id if profile is not None else None, 'protocol': protocol, 'hash': hash_check['status'],
            'observations': {o['level']: o for o in observations}, 'usage': _original_usage(doc, usage_entry), 'anomalies': flat}


def compare(left, right, level_order=()):
    """Comparison of two terminal runs. ``left``/``right`` = {'id', 'origin', 'report'} where report is the exact document of
    GET /api/runs/{id}/report. Hash, profile, protocol, observations and usage come from the aggregator; this adds no rule
    of its own except the declared origin, which the aggregator cannot know. ``comparison`` is None unless comparable."""
    agg = aggregator()
    items = {'left': left, 'right': right}
    views = {side: _analyze(agg, label, items[side]) for side, label in SIDES}
    heads = {}
    for side, _ in SIDES:
        run = items[side]['report'].get('run') if isinstance(items[side]['report'], dict) else None
        run = run if isinstance(run, dict) else {}
        heads[side] = {'id': items[side]['id'], 'origin': items[side]['origin'], 'model': run.get('model'), 'status': run.get('status')}
    reasons = [r for side, _ in SIDES for r in views[side]['blocking']]
    origins = {side: heads[side]['origin'] for side, _ in SIDES}
    for side, label in SIDES:
        if origins[side] not in ('real', 'fixture'): reasons.append('Origen desconocido en la corrida ' + label + ': no se concluye comparabilidad.')
    if all(o in ('real', 'fixture') for o in origins.values()) and origins['left'] != origins['right']:
        reasons.append('Origen distinto (' + origins['left'] + ' frente a ' + origins['right'] + '): evidencia real y fixture no se comparan entre sí.')
    if all(v['ok'] for v in views.values()):
        pl, pr = views['left']['protocol'], views['right']['protocol']
        protocol_differs = 'invalid' not in (pl['status'], pr['status']) and (pl['status'] != pr['status'] or pl['protocol'] != pr['protocol'])
        if protocol_differs:
            reasons.append('Protocolo congelado registrado solo en una de las corridas: no se afirma comparabilidad.' if pl['status'] != pr['status'] else 'Protocolo congelado distinto (fuentes u oráculo).')
        elif None not in (views['left']['profile_id'], views['right']['profile_id']) and views['left']['profile_id'] != views['right']['profile_id'] and not views['left']['blocking'] and not views['right']['blocking']:
            reasons.append('Perfil de ejecución distinto (experimento, sandbox declarado o efectivo observado).')
        levels = {side: list(views[side]['run'].get('levels') or []) for side, _ in SIDES}
        if set(levels['left']) != set(levels['right']):
            reasons.append('Niveles solicitados distintos (izquierda: ' + ', '.join(levels['left']) + '; derecha: ' + ', '.join(levels['right']) + ').')
    reasons = list(dict.fromkeys(reasons))
    comparable = not reasons
    comparison = None
    if comparable:
        order = {name: i for i, name in enumerate(level_order)}
        names = sorted(set(views['left']['observations']) | set(views['right']['observations']), key=lambda n: (order.get(n, len(order)), n))
        rows = []
        for name in names:
            one = {side: views[side]['observations'].get(name) for side, _ in SIDES}
            verdict = {side: one[side]['verdict'] if one[side] else 'missing' for side, _ in SIDES}
            summary = {side: (views[side]['run'].get('summary') or {}).get(name) for side, _ in SIDES}
            rows.append({'level': name, 'left_outcome': verdict['left'], 'right_outcome': verdict['right'], 'same': verdict['left'] == verdict['right'],
                         'left': _detail(one['left'], summary['left']), 'right': _detail(one['right'], summary['right'])})
        notes = []
        if pl['status'] == 'not_recorded': notes.append('Protocolo congelado no registrado en ambas corridas (históricas): no se afirma comparabilidad de protocolo más allá del perfil.')
        if any(heads[side]['status'] != 'completed' for side, _ in SIDES): notes.append('Una o ambas corridas no se completaron: los niveles no ejecutados cuentan como not_run, no como éxito.')
        comparison = {'levels': rows, 'usage': {side: views[side]['usage'] for side, _ in SIDES}, 'profiles': {side: views[side]['profile_id'] for side, _ in SIDES},
                      'models': {'left': heads['left']['model'], 'right': heads['right']['model'], 'same': heads['left']['model'] == heads['right']['model']},
                      'statuses': {side: heads[side]['status'] for side, _ in SIDES}, 'hash_checks': {side: views[side]['hash'] for side, _ in SIDES},
                      'protocol_status': pl['status'], 'anomalies': [{'side': side, **a} for side, _ in SIDES for a in views[side]['anomalies']][:100],
                      'notes': notes, 'aggregator_version': agg.AGGREGATOR_VERSION}
    return {'left': heads['left'], 'right': heads['right'], 'comparable': comparable, 'reasons': reasons, 'comparison': comparison}

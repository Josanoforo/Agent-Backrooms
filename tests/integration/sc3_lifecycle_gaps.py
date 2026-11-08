"""SC3-lifecycle-gaps-v1 (stage A2): lifecycle gaps of the durable invoice guard.

Opt-in Linux/Docker harness plus an offline receipt checker. It covers ONLY the
gaps left open by tests/integration/sc3_recovery_independent.py (whose receipt
hash is pinned below and which is not repeated here: SIGKILL after ACK while the
container is merely "created", and the block when ACK is missing):

  kill_running               SIGKILL of the guard-owner child while its verifier is
                             really running, then recovery with the real CLI
  cancel_client              the client is cancelled while the guard verifies
                             (socket path; needs root to separate the client UID)
  second_guard_exclusion     a second guard on the same installation is refused
                             while a verifier runs
  two_runs_foreign_sentinel  two runs (two installations) and a foreign sentinel:
                             recovering one never touches the other run or the sentinel

Evidence classes: "measured" (observed in this run through Docker or the OS),
"simulated" (offline synthetic receipts, never accepted as measurement) and
"unknown" (listed explicitly in every receipt).

Modes
  --offline                      schema, scenario selection and self-test; no Docker
  --list                         scenarios, commands and acceptance criteria
  --verify-base                  hash cross-check against the frozen base manifest
  --check-receipt PATH [...]     offline validation of measured receipts
  --image-id sha256:ID --receipt PATH [--scenario ID ...]
                                 Linux opt-in run against the local Docker daemon

The Linux mode never pulls an image, never contacts anything but the local
daemon, only creates containers it will remove by full ID, and only signals
processes it started itself. It does not restart the host or the daemon.
Exit codes: 0 criteria met, 1 evidence written but criteria not met, 2 rejected
before any Docker mutation, 3 cleanup not confirmed (operator must act).
"""
import argparse
import contextlib
import copy
import hashlib
import inspect
import json
import os
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HARNESS = Path(__file__).resolve()
SCHEMA = 'sc3-lifecycle-gaps/v1'
DELIVERY_ID = 'SC3-lifecycle-gaps-v1'
STAGE = 'A2'
BASE_MANIFEST = 'development/claude/bases/sc3-lifecycle-gaps-a2.json'
HANDSHAKE_LIMIT = 60.0  # safety bound of a handshake wait; synchronisation is by observed events

# Frozen candidate (hashes copied from the base manifest). Any difference stops the run.
CANDIDATE = {
    'services/agent/daemon_guard.py': '264356683f94c1baaa97c5bf72da5bb798c4463f1f64bf6a2b824b00e4420316',
    'services/agent/guard_state.py': '24ea3f3ff57981dcb3a46bc0913ddf152a008447837ca16fbb55c22973d31118',
    'services/agent/guard_client.py': '11317febde1f0bf60d4e1508f21151049ddbe42a142c1d35b7443adc39eb3da0',
    'services/agent/invoice_verification.py': '49078cd55c6a38c98ed8fc507eaec467f19917474c575465d64c4790b15862d7',
    'services/agent/workflow.py': '1f8e986f504e12eb46bf28a410629a0584bf7e29e8100d7c93a6da1daa47b83c',
}
PRIOR = {
    'path': 'docs/evidencia/sc3-revision-independiente.json',
    'sha256': '7fd7c783d4c80d298a325bf868847ab167ceeed32a427468f0681315211d9fc9',
    'covers': ['sigkill_after_ack_container_created', 'create_without_ack_stays_blocked',
               'foreign_labelled_object_preserved'],
}

HEX32 = re.compile(r'[0-9a-f]{32}')
HEX64 = re.compile(r'[0-9a-f]{64}')
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}')
NAME_RE = re.compile(r'escape-invoice-[0-9a-f]{32}')
REASON = re.compile(r'[a-z][a-z0-9_]{0,79}')
ACTION = re.compile(r'[a-z_]{1,24}(: [ -~]{0,60})?')
SIGNAL_EXIT = re.compile(r'SIG[A-Z0-9]{2,12}')
LABEL_KEYS = {
    'request': 'org.agent-escape-room.invoice-request',
    'installation': 'org.agent-escape-room.invoice-installation',
    'guard_uid': 'org.agent-escape-room.invoice-guard-uid',
    'run': 'org.agent-escape-room.invoice-run',
    'variant': 'org.agent-escape-room.invoice-variant',
}
FIXTURE_LABEL = 'org.agent-escape-room.sc3-gaps-fixture'
VARIANTS = ('legitimate', 'perturbed')

# ---------------------------------------------------------------------------------------------
# Closed vocabularies. A receipt using any other code is rejected.
SCENARIOS = ('kill_running', 'cancel_client', 'second_guard_exclusion', 'two_runs_foreign_sentinel')
SCENARIO_INFO = {
    'kill_running': ('SIGKILL of the guard-owner child while the verifier is running; real --recover-only', False),
    'cancel_client': ('client cancelled during verification through the real socket path', True),
    'second_guard_exclusion': ('second guard (serve, recover, initialize) refused on the same installation', False),
    'two_runs_foreign_sentinel': ('two runs in two installations plus a foreign sentinel; recovery stays local', False),
}
STATUSES = ('passed', 'failed', 'error', 'omitted')
OMIT_CODES = frozenset({'not_selected', 'requires_root_for_client_uid', 'candidate_drift', 'interface_drift'})
FAIL_CODES = frozenset({
    'recovery_unexpected', 'state_unexpected', 'replay_detected', 'foreign_removed', 'sentinel_changed',
    'lock_not_exclusive', 'restitution_not_observed', 'cancel_not_observed', 'guard_blocked_unexpectedly',
    'profile_or_label_mismatch', 'unexpected_response', 'owner_survived_signal',
})
ERROR_CODES = frozenset({
    'handshake_timeout', 'owner_exited_early', 'verifier_not_running', 'instrument_unavailable',
    'docker_unavailable', 'initialization_refused', 'cleanup_failed', 'internal_error',
})
ALL_REASONS = OMIT_CODES | FAIL_CODES | ERROR_CODES
SIGNAL_NAMES = ('SIGKILL', 'SIGTERM')
ROLES = ('guard_owner', 'guard_server', 'client')
CLI_PURPOSES = ('recovery', 'repeat_recovery', 'wrong_identity_recovery', 'second_guard_serve',
                'second_guard_recover', 'second_guard_initialize', 'post_exit_recovery')
CLI_KINDS = ('recover-only', 'serve', 'initialize-state')
PHASES = ('running_before_fault', 'after_fault', 'before_recovery', 'after_recovery', 'after_cancel',
          'after_exclusion_attempts', 'after_peer_recovery', 'final')
MARKS = ('running_observed', 'fault_injected', 'recovery_completed', 'release_sent', 'finish_observed')
OBSERVER_ROLES = ('guard_wrapper', 'fixture_parent')
BASES = ('measured', 'simulated', 'unknown')
CONTROL_KINDS = ('positive', 'negative')
LABEL_BASES = ('inspect+docker_events', 'docker_events')
HOOK_KINDS = ('owner_ready', 'state', 'docker', 'running_observed', 'verify_returned', 'verify_error',
              'state_error', 'verifier_not_running', 'release_missing', 'serve_wrapper_ready',
              'serve_exited', 'oversize')
HOOK_KEYS = frozenset({'source', 'seq', 'kind', 'op', 'phase', 'transition', 'container_id', 'reason', 'status'})
UNKNOWN_CODES = (
    'host_restart_not_exercised', 'late_create_not_excludable',
    'verifier_progress_inside_container_not_measured', 'guard_uid_is_fixture_uid_not_operational',
    'service_level_cancel_not_exercised', 'docker_events_retention_assumed',
)
REQUIRED_UNKNOWNS = ('host_restart_not_exercised', 'service_level_cancel_not_exercised')

COMMON_CLAIMS = ('candidate_hashes_match_base', 'image_by_id_no_pull', 'container_identity_and_labels',
                 'states_before_after_recorded', 'own_containers_absent_after', 'sentinel_intact',
                 'zero_start_replay')
SPECIFIC_CLAIMS = {
    'kill_running': ('verifier_running_under_two_observers', 'guard_owner_sigkilled_while_running',
                     'crash_state_pending_ack_only', 'recovery_removed_full_id', 'repeat_recovery_idempotent'),
    'cancel_client': ('verifier_running_under_two_observers', 'client_cancelled_while_running',
                      'restitution_observed_after_cancel', 'guard_admits_after_cancel', 'guard_clean_stop'),
    'second_guard_exclusion': ('verifier_running_under_two_observers', 'second_guard_refused_same_installation',
                               'running_verifier_untouched', 'lock_inode_stable', 'first_guard_completed'),
    'two_runs_foreign_sentinel': ('verifier_running_under_two_observers', 'distinct_runs_and_installations',
                                  'other_run_untouched_by_recovery', 'other_guard_completed',
                                  'recovery_limited_to_own_installation'),
}
_COMMON_CONTROLS = ('observer_rejects_non_running', 'observer_accepts_running',
                    'events_instrument_sees_lifecycle', 'events_instrument_ignores_other_labels')
CONTROLS = {
    'kill_running': _COMMON_CONTROLS + ('wrong_identity_recovery_refused',),
    'cancel_client': _COMMON_CONTROLS + ('unauthorized_peer_rejected', 'post_cancel_admission'),
    'second_guard_exclusion': _COMMON_CONTROLS + ('lock_released_after_exit',),
    'two_runs_foreign_sentinel': _COMMON_CONTROLS + ('other_guard_did_not_touch_foreign',),
}
ALL_CLAIMS = frozenset(COMMON_CLAIMS) | {c for v in SPECIFIC_CLAIMS.values() for c in v}
ALL_CONTROLS = frozenset(c for v in CONTROLS.values() for c in v)
SHAPE = {
    'kill_running': {'installations': 1, 'runs': 1, 'running': 1},
    'cancel_client': {'installations': 1, 'runs': 2, 'running': 1},
    'second_guard_exclusion': {'installations': 1, 'runs': 1, 'running': 1},
    'two_runs_foreign_sentinel': {'installations': 2, 'runs': 2, 'running': 2},
}
FINAL_CYCLES = {'kill_running': 1, 'cancel_client': 2, 'second_guard_exclusion': 1, 'two_runs_foreign_sentinel': 1}
AT_FAULT = {'kill_running': 1, 'cancel_client': 0, 'second_guard_exclusion': 0, 'two_runs_foreign_sentinel': 1}
TIMELINE = {
    'kill_running': ('running_observed', 'fault_injected', 'recovery_completed'),
    'cancel_client': ('running_observed', 'fault_injected', 'release_sent', 'finish_observed'),
    'second_guard_exclusion': ('running_observed', 'fault_injected', 'release_sent', 'finish_observed'),
    'two_runs_foreign_sentinel': ('running_observed', 'fault_injected', 'recovery_completed',
                                  'release_sent', 'finish_observed'),
}
STATE_PHASES = {
    'kill_running': {'after_fault', 'before_recovery', 'after_recovery'},
    'cancel_client': {'after_cancel', 'final'},
    'second_guard_exclusion': {'after_exclusion_attempts', 'final'},
    'two_runs_foreign_sentinel': {'after_fault', 'after_peer_recovery', 'after_recovery', 'final'},
}
CLI_EXPECT = {
    'kill_running': {'wrong_identity_recovery': (2, ('guard_state_unavailable',)),
                     'recovery': (0, (None,)), 'repeat_recovery': (0, (None,))},
    'cancel_client': {},
    'second_guard_exclusion': {
        'second_guard_serve': (2, ('guard_state_unavailable',)),
        'second_guard_recover': (2, ('guard_state_unavailable',)),
        'second_guard_initialize': (2, ('guard_recovery_required', 'guard_state_unavailable')),
        'post_exit_recovery': (0, (None,))},
    'two_runs_foreign_sentinel': {'recovery': (0, (None,)), 'repeat_recovery': (0, (None,))},
}
PROC_EXPECT = {
    'kill_running': (('guard_owner', 'SIGKILL', -9),),
    'cancel_client': (('client', 'SIGTERM', -15), ('guard_server', 'SIGTERM', 0)),
    'second_guard_exclusion': (('guard_owner', None, 0),),
    'two_runs_foreign_sentinel': (('guard_owner', 'SIGKILL', -9), ('guard_owner', None, 0)),
}
LIMITS = [
    'Guard UID is the fixture UID; it is not shown equivalent to the operational guard UID.',
    '"Running" is State.Running with Pid>0 seen by two observers; the verifier is held blocked on stdin by the fixture wrapper, so its internal progress is inferred by design, not measured.',
    'Replay is measured with Docker events (start/create counts per installation label), not by intercepting the recovery CLI.',
    'Two runs means two concurrent installations with distinct run ids; one installation admits one open intent.',
    'Only fixture children are signalled; host and daemon restarts are outside this harness.',
    'Client cancellation is exercised at the guard socket; the asyncio shield of workflow.run_variant is not exercised.',
]

# ---------------------------------------------------------------------------------------------
# Hashing, base cross-check, interface check


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    try:
        return sha256_bytes(Path(path).read_bytes())
    except OSError:
        return None


def harness_hash():
    return sha256_file(HARNESS)


def candidate_hashes(root=ROOT):
    return {name: sha256_file(Path(root) / name) for name in CANDIDATE}


def verify_base(root=ROOT):
    """Cross-check every file of the frozen base manifest. Only candidate rows gate a run."""
    result = {'manifest_found': False, 'delivery_matches': False, 'rows': [], 'gating_ok': False,
              'base_intact': False}
    try:
        manifest = json.loads((Path(root) / BASE_MANIFEST).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return result
    if not isinstance(manifest, dict) or not isinstance(manifest.get('files'), list):
        return result
    result['manifest_found'] = True
    result['delivery_matches'] = manifest.get('delivery_id') == DELIVERY_ID and manifest.get('stage') == STAGE
    listed = {}
    for entry in manifest['files']:
        if not isinstance(entry, dict) or not isinstance(entry.get('path'), str):
            continue
        expected, snapshot = entry.get('sha256'), entry.get('snapshot_path')
        active = sha256_file(Path(root) / entry['path'])
        snap = sha256_file(Path(root) / snapshot) if isinstance(snapshot, str) else None
        row = {
            'path': entry['path'], 'expected': expected,
            'active': 'missing' if active is None else 'match' if active == expected else 'drift',
            'snapshot': 'none' if not isinstance(snapshot, str) else 'missing' if snap is None
            else 'match' if snap == expected else 'drift',
        }
        result['rows'].append(row)
        listed[entry['path']] = row
    result['gating_ok'] = result['delivery_matches'] and all(
        name in listed and listed[name]['active'] == 'match' and listed[name]['expected'] == digest
        for name, digest in CANDIDATE.items())
    result['base_intact'] = all(row['snapshot'] in ('none', 'match') for row in result['rows'])
    return result


def guard_module():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from services.agent import daemon_guard
    return daemon_guard


def state_module():
    guard_module()
    from services.agent import guard_state
    return guard_state


def interface_check(g, gs):
    """Names this harness relies on. A non-empty result means interface drift: stop, do not edit product."""
    problems = []

    def need(ok, code):
        if not ok:
            problems.append(code)

    params = inspect.signature(g.InvoiceGuard.__init__).parameters
    for name in ('image', 'source', 'command', 'store', 'daemon_identity', 'identity_probe'):
        need(name in params, 'init_' + name)
    for name in ('verify', 'reconcile', 'request_stop', '_durable_cleanup', '_installation_inventory'):
        need(callable(getattr(g.InvoiceGuard, name, None)), 'guard_' + name)
    for name in ('docker_command', 'docker_identity', 'main', 'is_digest', 'digest'):
        need(callable(getattr(g, name, None)), 'module_' + name)
    need(isinstance(getattr(g, 'GuardError', None), type), 'module_GuardError')
    need(tuple(getattr(g, 'DOCKER', ())) == ('/usr/bin/docker', '--host=unix:///var/run/docker.sock', 'container'),
         'docker_prefix')
    for attr in ('DOCKER_SECONDS', 'DOCKER_OUTPUT_MAX'):
        need(type(getattr(g, attr, None)) is int, 'module_' + attr)
    for key, attr in (('request', 'LABEL'), ('installation', 'INSTALLATION_LABEL'), ('guard_uid', 'GUARD_UID_LABEL'),
                      ('run', 'RUN_LABEL'), ('variant', 'VARIANT_LABEL')):
        need(getattr(g, attr, None) == LABEL_KEYS[key], 'label_' + key)
    for name in ('begin', 'ack', 'finish', 'pending'):
        need(callable(getattr(gs.GuardState, name, None)), 'state_' + name)
    need(isinstance(getattr(gs, 'StateError', None), type), 'state_StateError')
    opened = inspect.signature(gs.open_state).parameters
    for name in ('directory', 'guard_uid', 'client_uid', 'docker_id', 'docker_root', 'initialize'):
        need(name in opened, 'open_' + name)
    return problems


# ---------------------------------------------------------------------------------------------
# Errors and the evidence record


class HarnessError(Exception):
    def __init__(self, code, detail=''):
        if code not in ALL_REASONS:
            code, detail = 'internal_error', code
        super().__init__(code)
        self.code = code
        self.detail = str(detail)[:120]


def status_of(code):
    return 'omitted' if code in OMIT_CODES else 'failed' if code in FAIL_CODES else 'error'


class Record:
    """Evidence of one scenario. The receipt keeps whatever was observed, even when the scenario fails."""

    def __init__(self, sid):
        self.d = {
            'id': sid, 'status': 'error', 'reason': None, 'installations': [], 'runs': [], 'processes': [],
            'cli_runs': [], 'transitions': [], 'running': [], 'container_states': [], 'timeline': [],
            'docker_events': {'since': 0.0, 'until': 0.0, 'lifecycle': {}, 'start_count': {}, 'create_count': {}},
            'sentinel': None,
            'restitution': {'observed': False, 'absent_container_ids': [], 'installation_inventory_empty': {}},
            'hook_events': [], 'claims': {}, 'controls': [], 'errors': [],
        }

    @classmethod
    def omitted(cls, sid, reason):
        record = cls(sid)
        record.d['status'], record.d['reason'] = 'omitted', reason
        return record

    def claim(self, code, holds, basis='measured'):
        self.d['claims'][code] = {'holds': holds, 'basis': basis}

    def control(self, code, kind, passed, basis='measured'):
        self.d['controls'].append({'code': code, 'kind': kind, 'passed': bool(passed), 'basis': basis})

    def mark(self, name, t_ns=None):
        self.d['timeline'].append({'mark': name, 't_ns': time.monotonic_ns() if t_ns is None else t_ns})

    def state(self, phase, container_id, summary):
        self.d['container_states'].append({
            'phase': phase, 'container_id': container_id, 'present': summary is not None,
            'status': None if summary is None else summary['status'],
            'running': None if summary is None else summary['running'],
        })

    def fail(self, error):
        self.d['status'] = status_of(error.code)
        self.d['reason'] = error.code
        if self.d['status'] != 'omitted':
            self.d['errors'].append({'code': error.code, 'where': error.detail or 'scenario'})


# ---------------------------------------------------------------------------------------------
# Docker observation (Linux only). Fixture-side commands are whitelisted and read-mostly.

DOCKER_PREFIX = ('/usr/bin/docker', '--host=unix:///var/run/docker.sock')
ENV = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C.UTF-8'}
PY_ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}
CONTAINER_OPS = ('create', 'inspect', 'ls', 'rm')
TOP_OPS = ('events', 'info', 'image')


def _run(argv, timeout):
    try:
        return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                              cwd='/', env=ENV)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HarnessError('docker_unavailable', type(exc).__name__) from exc


def container_cmd(op, *args, timeout=30):
    if op not in CONTAINER_OPS:
        raise HarnessError('internal_error', 'container op')
    return _run([*DOCKER_PREFIX, 'container', op, *args], timeout)


def top_cmd(op, *args, timeout=30):
    if op not in TOP_OPS:
        raise HarnessError('internal_error', 'top op')
    return _run([*DOCKER_PREFIX, op, *args], timeout)


def inspect_one(container_id):
    """Parsed inspect of one full container ID, or None when Docker says it does not exist."""
    if not HEX64.fullmatch(container_id or ''):
        raise HarnessError('internal_error', 'inspect id')
    cp = container_cmd('inspect', container_id)
    if cp.returncode != 0:
        if b'no such container' in cp.stderr.lower():
            return None
        raise HarnessError('instrument_unavailable', 'inspect')
    try:
        data = json.loads(cp.stdout)
        if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict):
            return data[0]
    except ValueError:
        pass
    raise HarnessError('instrument_unavailable', 'inspect parse')


def listing(filter_value):
    cp = container_cmd('ls', '--all', '--no-trunc', '--quiet', '--filter', filter_value)
    ids = cp.stdout.decode('ascii', 'replace').splitlines() if cp.returncode == 0 else None
    if ids is None or len(set(ids)) != len(ids) or not all(HEX64.fullmatch(item) for item in ids):
        raise HarnessError('instrument_unavailable', 'ls')
    return ids


def remove_by_id(container_id):
    if not HEX64.fullmatch(container_id or ''):
        raise HarnessError('cleanup_failed', 'not a full id')
    if container_cmd('rm', '--force', container_id).returncode != 0:
        raise HarnessError('cleanup_failed', 'rm')


def summary(data):
    state = data.get('State') or {}
    config = data.get('Config') or {}
    labels = config.get('Labels') or {}
    return {
        'id': data.get('Id'), 'name': data.get('Name'), 'status': state.get('Status'),
        'running': state.get('Running'), 'pid': state.get('Pid'), 'started_at': state.get('StartedAt'),
        'image': data.get('Image'), 'user': config.get('User'),
        'labels': {key: labels.get(label) for key, label in LABEL_KEYS.items()},
    }


def fingerprint(data):
    state = data.get('State') or {}
    core = {'id': data.get('Id'), 'name': data.get('Name'), 'created': data.get('Created'),
            'image': data.get('Image'), 'status': state.get('Status'),
            'labels': (data.get('Config') or {}).get('Labels') or {}}
    return sha256_bytes(json.dumps(core, sort_keys=True, separators=(',', ':')).encode())


def proc_uid(pid, container_id):
    """Real/effective host UID of the container process; None unless /proc really shows this container."""
    base = Path('/proc') / str(pid)
    try:
        if container_id not in (base / 'cgroup').read_text(errors='replace'):
            return None
        for line in (base / 'status').read_text(errors='replace').splitlines():
            if line.startswith('Uid:'):
                parts = line.split()
                return [int(parts[1]), int(parts[2])]
    except (OSError, ValueError, IndexError):
        return None
    return None


def lifecycle_events(since, until, *filters):
    argv = ['--since', repr(float(since)), '--until', repr(float(until)), '--filter', 'type=container']
    for item in filters:
        argv += ['--filter', item]
    cp = top_cmd('events', *argv, '--format', '{{json .}}', timeout=60)
    if cp.returncode != 0:
        raise HarnessError('instrument_unavailable', 'events')
    events = []
    for line in cp.stdout.decode('utf-8', 'replace').splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            events.append({'action': str(item['Action']), 'id': item['Actor']['ID'],
                           'attrs': item['Actor'].get('Attributes') or {}})
        except (ValueError, KeyError, TypeError) as exc:
            raise HarnessError('instrument_unavailable', 'events parse') from exc
    return events


def read_state(directory):
    """Durable state of an installation. Only call while no live guard holds that installation."""
    import sqlite3
    uri = (Path(directory) / 'state.sqlite3').as_uri() + '?mode=ro'
    with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=5)) as db:
        row = db.execute('SELECT installation_id, guard_uid, client_uid, docker_id, docker_root FROM installation').fetchone()
        rows = db.execute('SELECT kind, payload FROM events ORDER BY sequence').fetchall()
    return {'installation_id': row[0], 'guard_uid': row[1], 'client_uid': row[2], 'docker_id': row[3],
            'docker_root': row[4], 'kinds': [kind for kind, _ in rows],
            'payloads': [json.loads(payload) for _, payload in rows]}


def lock_snapshot(directory):
    snapshot = {}
    for name in sorted(os.listdir(directory)):
        meta = os.stat(Path(directory) / name)
        snapshot[name] = [meta.st_ino, meta.st_size, meta.st_mtime_ns]
    return snapshot


# ---------------------------------------------------------------------------------------------
# Child processes: guard owner / guard server wrapper (internal modes of this same file)


class Channel:
    """Child side of the handshake: events go to the parent, a release byte comes back."""

    def __init__(self, event_fd, release_fd):
        self.event_fd, self.release_fd, self.seq = event_fd, release_fd, 0

    def emit(self, kind, **fields):
        self.seq += 1
        body = {'seq': self.seq, 'kind': kind, 'pid': os.getpid(), 'uid': os.geteuid(),
                'mono_ns': time.monotonic_ns(), **fields}
        line = json.dumps(body, separators=(',', ':'), sort_keys=True).encode('ascii') + b'\n'
        if len(line) > 3500:
            line = json.dumps({'seq': self.seq, 'kind': 'oversize', 'pid': os.getpid(), 'uid': os.geteuid()},
                              separators=(',', ':')).encode('ascii') + b'\n'
        os.write(self.event_fd, line)

    def wait_release(self, limit):
        ready, _, _ = select.select([self.release_fd], [], [], limit)
        return bool(ready) and os.read(self.release_fd, 1) == b'1'


def build_guard_class(g, channel, hold_first_start, identity):
    """Subclass of the unmodified InvoiceGuard: only the command hook and a transparent store proxy are added."""
    state = {'held': False}

    def container_id_in(args):
        for item in reversed(args):
            if isinstance(item, str) and HEX64.fullmatch(item):
                return item
        return None

    def poll_running(container_id):
        deadline = time.monotonic() + HANDSHAKE_LIMIT
        while time.monotonic() < deadline:
            current = json.loads(g.docker_command(['inspect', container_id]))[0].get('State') or {}
            if current.get('Running') is True and type(current.get('Pid')) is int and current['Pid'] > 0:
                return current
            if current.get('Status') in ('exited', 'dead'):
                channel.emit('verifier_not_running', container_id=container_id, status=str(current.get('Status')))
                raise g.GuardError('docker_command_failed')
            time.sleep(0.02)  # polling an observable condition; the deadline above is only a bound
        raise g.GuardError('docker_command_failed')

    def held_start(args, data):
        container_id = args[-1]
        proc = subprocess.Popen([*g.DOCKER, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, cwd='/', env=ENV, close_fds=True)
        channel.emit('docker', op='start', phase='spawned', container_id=container_id, cli_pid=proc.pid)
        try:
            current = poll_running(container_id)
            channel.emit('running_observed', container_id=container_id, state_pid=current.get('Pid'),
                         status=str(current.get('Status')), daemon_id=identity[0])
            # The artifact is withheld until the parent releases us: the verifier stays running meanwhile.
            if not channel.wait_release(HANDSHAKE_LIMIT):
                channel.emit('release_missing', container_id=container_id)
                raise g.GuardError('docker_command_failed')
            output, _ = proc.communicate(input=data, timeout=g.DOCKER_SECONDS)
            if proc.returncode != 0 or len(output) > g.DOCKER_OUTPUT_MAX:
                raise g.GuardError('docker_command_failed')
            channel.emit('docker', op='start', phase='returned', container_id=container_id)
            return output
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            raise g.GuardError('docker_command_failed') from exc
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def hook(args, data=None, **_ignored):
        op = args[0]
        if op == 'start' and hold_first_start and not state['held']:
            state['held'] = True
            return held_start(args, data)
        container_id = container_id_in(args)
        try:
            output = g.docker_command(args, data)
        except g.GuardError as exc:
            channel.emit('docker', op=op, phase='error', container_id=container_id, reason=str(exc))
            raise
        if op == 'create':
            created = output.decode('ascii', 'replace').strip()
            container_id = created if HEX64.fullmatch(created) else None
        channel.emit('docker', op=op, phase='ok', container_id=container_id)
        return output

    class StoreProxy:
        def __init__(self, store):
            self._store = store

        @property
        def installation_id(self):
            return self._store.installation_id

        def pending(self):
            return self._store.pending()

        def begin(self, name, run_id, variant, artifact_sha256):
            self._store.begin(name, run_id, variant, artifact_sha256)
            channel.emit('state', transition='PENDING', name=name, run_id=run_id, variant=variant)

        def ack(self, container_id):
            self._store.ack(container_id)
            channel.emit('state', transition='ACK', container_id=container_id)

        def finish(self):
            self._store.finish()
            channel.emit('state', transition='FINISH')

    class Hooked(g.InvoiceGuard):
        def __init__(self, image, source, command=None, **kwargs):
            super().__init__(image, source, command=hook, **kwargs)

        @property
        def store(self):
            return self.__dict__.get('_proxy')

        @store.setter
        def store(self, value):
            self.__dict__['_proxy'] = None if value is None else StoreProxy(value)

    return Hooked


def run_owner(cfg):
    """In-process owner of one verification: the 'child' that the harness later kills."""
    g, gs = guard_module(), state_module()
    channel = Channel(cfg['event_fd'], cfg['release_fd'])
    identity = g.docker_identity()
    hooked = build_guard_class(g, channel, cfg['hold'], identity)
    source = Path(g.__file__).with_name('invoice_verifier.py').read_bytes()
    artifact = b'{}'
    try:
        with gs.open_state(cfg['state_dir'], guard_uid=os.geteuid(), client_uid=cfg['client_uid'],
                           docker_id=identity[0], docker_root=identity[1]) as store:
            subject = hooked(cfg['image'], source, store=store, daemon_identity=identity)
            channel.emit('owner_ready', status='ready')
            result = subject.verify(artifact, g.digest(artifact), cfg['run_id'], cfg['variant'])
        channel.emit('verify_returned', status=str(result.get('status')), container_id=result.get('container_id'))
        return 0
    except g.GuardError as exc:
        channel.emit('verify_error', reason=str(exc))
        return 3
    except gs.StateError as exc:
        channel.emit('state_error', reason=exc.code)
        return 4


def run_serve(cfg):
    """The real guard CLI (daemon_guard.main) with the same transparent hooks installed."""
    g = guard_module()
    channel = Channel(cfg['event_fd'], cfg['release_fd'])
    identity = g.docker_identity()
    g.InvoiceGuard = build_guard_class(g, channel, cfg['hold'], identity)
    channel.emit('serve_wrapper_ready', status='ready')
    code = g.main(cfg['argv'])
    channel.emit('serve_exited', status=str(code))
    return code


class Child:
    """Parent side: a fixture-owned process with an event pipe and a release pipe."""

    def __init__(self, fixture, role, mode, cfg, uid):
        self.fixture, self.role, self.uid = fixture, role, uid
        self.signal_sent = None
        self.events, self.buffer, self.eof = [], b'', False
        event_read, event_write = os.pipe()
        release_read, release_write = os.pipe()
        cfg = {**cfg, 'event_fd': event_write, 'release_fd': release_read}
        self.stderr_path = fixture.scratch / f'{role}-{len(fixture.children)}.stderr'
        self.stderr_file = open(self.stderr_path, 'wb')
        try:
            self.proc = subprocess.Popen(
                [sys.executable, '-B', '-S', str(HARNESS), '--internal-' + mode, json.dumps(cfg)],
                cwd=ROOT, env=PY_ENV, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=self.stderr_file, pass_fds=(event_write, release_read), start_new_session=True)
        except OSError as exc:
            os.close(event_read)
            os.close(release_write)
            raise HarnessError('instrument_unavailable', 'spawn') from exc
        finally:
            os.close(event_write)
            os.close(release_read)
        self.event_fd, self.release_fd = event_read, release_write
        fixture.children.append(self)

    def pump(self, limit):
        if self.eof:
            return False
        ready, _, _ = select.select([self.event_fd], [], [], limit)
        if not ready:
            return False
        chunk = os.read(self.event_fd, 65536)
        if not chunk:
            self.eof = True
            return False
        self.buffer += chunk
        while b'\n' in self.buffer:
            line, self.buffer = self.buffer.split(b'\n', 1)
            try:
                event = json.loads(line)
            except ValueError as exc:
                raise HarnessError('unexpected_response', 'event parse') from exc
            if not isinstance(event, dict) or not isinstance(event.get('kind'), str):
                raise HarnessError('unexpected_response', 'event shape')
            event['t_ns'] = time.monotonic_ns()
            self.events.append(event)
            self.fixture.note(event)
        return True

    def wait_for(self, kind, after=0, **match):
        """Block until the child reports an event; returns (index, event)."""
        deadline = time.monotonic() + HANDSHAKE_LIMIT
        while True:
            for index in range(after, len(self.events)):
                event = self.events[index]
                if event['kind'] == kind and all(event.get(key) == value for key, value in match.items()):
                    return index, event
            for event in self.events:
                if event['kind'] == 'verifier_not_running':
                    raise HarnessError('verifier_not_running', str(event.get('status')))
                if event['kind'] in ('verify_error', 'state_error'):
                    raise HarnessError('guard_blocked_unexpectedly', str(event.get('reason')))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HarnessError('handshake_timeout', kind)
            if not self.pump(min(remaining, 1.0)) and self.eof:
                code = self.proc.wait(timeout=10)
                raise HarnessError('owner_exited_early', f'{kind}:{code}')

    def release(self):
        os.write(self.release_fd, b'1')

    def send(self, name):
        os.kill(self.proc.pid, getattr(signal, name))
        self.signal_sent = name

    def finish(self, timeout=60):
        try:
            code = self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise HarnessError('handshake_timeout', 'child exit') from exc
        deadline = time.monotonic() + 10
        while not self.eof and time.monotonic() < deadline:
            self.pump(0.5)
        return code

    def record(self):
        code = self.proc.poll()
        return {'role': self.role, 'pid': self.proc.pid, 'uid': self.uid, 'signal_sent': self.signal_sent,
                'returncode': code,
                'exit_signal': None if code is None or code >= 0 else signal.Signals(-code).name}

    def close(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        for descriptor in (self.event_fd, self.release_fd):
            with contextlib.suppress(OSError):
                os.close(descriptor)
        self.stderr_file.close()


CLIENT_BOOT = r'''
import json, sys
cfg = json.loads(sys.argv[1])
ns = {'__name__': 'guard_client_fixture'}
exec(compile(sys.stdin.buffer.read(), 'guard_client.py', 'exec'), ns)
try:
    r = ns['verify'](cfg['socket'], cfg['guard_uid'], b'{}', timeout=cfg['timeout'],
                     run_id=cfg['run_id'], variant=cfg['variant'])
    print(json.dumps({'ok': True, 'status': r['status'], 'container_id': r['container_id'],
                      'cleanup_confirmed': r['cleanup_confirmed']}))
except ns['GuardError'] as exc:
    print(json.dumps({'ok': False, 'reason': str(exc)}))
'''


class ClientProc:
    """The real guard_client.verify, executed under the separated client UID (source passed by stdin)."""

    def __init__(self, fixture, socket_path, run):
        self.role, self.uid, self.signal_sent = 'client', fixture.client_uid, None
        source = (ROOT / 'services/agent/guard_client.py').read_bytes()
        cfg = {'socket': str(socket_path), 'guard_uid': fixture.guard_uid, 'timeout': 110,
               'run_id': run['run_id'], 'variant': run['variant']}
        try:
            self.proc = subprocess.Popen(
                [sys.executable, '-B', '-S', '-c', CLIENT_BOOT, json.dumps(cfg)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd='/', env=PY_ENV,
                user=fixture.client_uid, group=fixture.client_uid, extra_groups=[], start_new_session=True)
            self.proc.stdin.write(source)
            self.proc.stdin.close()
        except (OSError, ValueError) as exc:
            raise HarnessError('instrument_unavailable', 'client spawn') from exc
        fixture.clients.append(self)

    def send(self, name):
        os.kill(self.proc.pid, getattr(signal, name))
        self.signal_sent = name

    def finish(self, timeout=30):
        return self.proc.wait(timeout=timeout)

    def result(self, timeout=120):
        try:
            output, _ = self.proc.communicate(timeout=timeout)
            return json.loads(output.decode('utf-8').strip().splitlines()[-1])
        except (subprocess.TimeoutExpired, ValueError, IndexError) as exc:
            raise HarnessError('unexpected_response', 'client result') from exc

    def record(self):
        code = self.proc.poll()
        return {'role': 'client', 'pid': self.proc.pid, 'uid': self.uid, 'signal_sent': self.signal_sent,
                'returncode': code,
                'exit_signal': None if code is None or code >= 0 else signal.Signals(-code).name}

    def close(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        for stream in (self.proc.stdout, self.proc.stdin):
            if stream is not None:
                with contextlib.suppress(OSError):
                    stream.close()


# ---------------------------------------------------------------------------------------------
# Fixture: one per scenario, with its own scratch tree, sentinel and removal ledger


class Fixture:
    def __init__(self, image, client_uid, scratch, g, identity):
        self.image, self.client_uid, self.scratch, self.g, self.identity = image, client_uid, scratch, g, identity
        self.guard_uid = os.geteuid()
        self.alt_uid = next(uid for uid in (65533, 65532, 65531) if uid not in (self.guard_uid, client_uid))
        self.id = uuid.uuid4().hex
        self.ledger = {}
        self.children, self.clients = [], []
        self.installations = {}
        self.sentinel = None
        self.since = time.time() - 1.0

    def check(self, condition, code, detail=''):
        if not condition:
            raise HarnessError(code, detail)

    def note(self, event):
        """Every container the fixture's own guard processes create enters the removal ledger by full ID."""
        container_id = event.get('container_id')
        if isinstance(container_id, str) and HEX64.fullmatch(container_id) and (
                event['kind'] == 'state' and event.get('transition') == 'ACK'
                or event['kind'] == 'docker' and event.get('op') == 'create' and event.get('phase') == 'ok'):
            self.add_ledger(container_id, 'verifier')

    def add_ledger(self, container_id, role):
        if container_id not in self.ledger:
            self.ledger[container_id] = role
            print(f'ledger {role} {container_id}', file=sys.stderr, flush=True)

    def cli(self, directory, *extra, client_uid=None):
        argv = [sys.executable, '-B', '-S', '-m', 'services.agent.daemon_guard', '--client-uid',
                str(self.client_uid if client_uid is None else client_uid), '--image', self.image,
                '--state-dir', str(directory), *extra]
        try:
            cp = subprocess.run(argv, cwd=ROOT, env=PY_ENV, stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=90)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HarnessError('instrument_unavailable', 'cli') from exc
        text = cp.stderr.decode('ascii', 'replace').strip()
        reason = None if not text else text if REASON.fullmatch(text) else 'unparsed'
        return cp.returncode, reason

    def new_installation(self, rec, label):
        directory = self.scratch / label
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
        code, reason = self.cli(directory, '--initialize-state')
        self.check(code == 0, 'initialization_refused', reason or '')
        state = read_state(directory)
        self.check(state['guard_uid'] == self.guard_uid and state['docker_id'] == self.identity[0],
                   'state_unexpected', 'identity')
        self.installations[state['installation_id']] = directory
        rec.d['installations'].append({'installation_id': state['installation_id'], 'guard_uid': state['guard_uid'],
                                       'client_uid': state['client_uid'], 'lock_inode_stable': None})
        return directory, state['installation_id']

    def make_sentinel(self, rec):
        name = 'sc3-gaps-sentinel-' + uuid.uuid4().hex
        cp = container_cmd('create', '--pull=never', '--name', name, '--label', f'{FIXTURE_LABEL}={self.id}',
                           '--network=none', '--read-only', '--cap-drop=ALL', '--user=65534:65534',
                           self.image, '/bin/true')
        container_id = cp.stdout.decode('ascii', 'replace').strip()
        self.check(cp.returncode == 0 and HEX64.fullmatch(container_id), 'instrument_unavailable', 'sentinel create')
        self.add_ledger(container_id, 'sentinel')
        data = inspect_one(container_id)
        self.check(data is not None, 'instrument_unavailable', 'sentinel inspect')
        info = summary(data)
        self.sentinel = {'container_id': container_id, 'name': name, 'before': fingerprint(data),
                         'status_before': info['status']}
        rec.control('observer_rejects_non_running', 'negative', info['running'] is False and info['status'] == 'created')
        return container_id

    def new_run(self, installation_id, variant):
        return {'run_id': uuid.uuid4().hex, 'variant': variant, 'installation_id': installation_id,
                'name': None, 'container_id': None, 'labels_basis': 'docker_events'}

    def spawn_owner(self, directory, run, hold):
        cfg = {'state_dir': str(directory), 'client_uid': self.client_uid, 'image': self.image,
               'run_id': run['run_id'], 'variant': run['variant'], 'hold': hold}
        return Child(self, 'guard_owner', 'owner', cfg, self.guard_uid)

    def spawn_serve(self, directory, socket_path):
        argv = ['--socket', str(socket_path), '--client-uid', str(self.client_uid), '--image', self.image,
                '--state-dir', str(directory)]
        return Child(self, 'guard_server', 'serve', {'argv': argv, 'hold': True}, self.guard_uid)

    def learn_run(self, child, run):
        """Wait for the durable PENDING and ACK transitions of this run; returns the index of ACK."""
        index, pending = child.wait_for('state', transition='PENDING', run_id=run['run_id'])
        ack_index, ack = child.wait_for('state', after=index + 1, transition='ACK')
        run['name'], run['container_id'] = pending['name'], ack['container_id']
        self.check(NAME_RE.fullmatch(run['name'] or '') and HEX64.fullmatch(run['container_id'] or ''),
                   'unexpected_response', 'run identity')
        return ack_index

    def observe_running(self, rec, run, event):
        """The fixture's own observation of the verifier, next to the guard wrapper's."""
        container_id = event.get('container_id')
        self.check(container_id == run['container_id'], 'unexpected_response', 'container mismatch')
        self.check(event.get('daemon_id') == self.identity[0], 'profile_or_label_mismatch', 'daemon')
        data = inspect_one(container_id)
        self.check(data is not None, 'verifier_not_running', 'absent')
        info = summary(data)
        self.check(info['running'] is True and info['status'] == 'running' and type(info['pid']) is int
                   and info['pid'] > 0, 'verifier_not_running', str(info['status']))
        expected = {'request': run['name'], 'installation': run['installation_id'],
                    'guard_uid': str(self.guard_uid), 'run': run['run_id'], 'variant': run['variant']}
        self.check(info['id'] == container_id and info['name'] == '/' + run['name'] and info['image'] == self.image
                   and info['user'] == '65534:65534' and info['labels'] == expected,
                   'profile_or_label_mismatch', 'inspect')
        rec.d['running'].append({
            'run_id': run['run_id'], 'container_id': container_id,
            'observers': [{'role': 'guard_wrapper', 'pid': event['pid'], 'uid': event['uid']},
                          {'role': 'fixture_parent', 'pid': os.getpid(), 'uid': self.guard_uid}],
            'status': info['status'], 'running': True, 'state_pid': info['pid'], 'configured_user': info['user'],
            'host_uid_observed': proc_uid(info['pid'], container_id), 'labels': info['labels'],
            'daemon_id': self.identity[0], 'daemon_root': self.identity[1]})
        run['labels_basis'] = 'inspect+docker_events'
        rec.state('running_before_fault', container_id, info)
        rec.control('observer_accepts_running', 'positive', True)
        rec.claim('verifier_running_under_two_observers', True)
        rec.claim('container_identity_and_labels', True)
        return info

    def kill_straggler(self, child, container_id):
        """The docker CLI that the killed guard had spawned; only after /proc confirms it is that very command."""
        pid = next((e.get('cli_pid') for e in child.events if e['kind'] == 'docker' and e.get('phase') == 'spawned'), None)
        if type(pid) is not int:
            return False
        try:
            raw = (Path('/proc') / str(pid) / 'cmdline').read_bytes()
            if b'start' in raw and container_id.encode() in raw:
                os.kill(pid, signal.SIGKILL)
                return True
        except (OSError, ProcessLookupError):
            pass
        return False

    def observe_restitution(self, rec, container_ids, installation_ids):
        restitution = rec.d['restitution']
        for container_id in container_ids:
            self.check(listing('id=' + container_id) == [] and inspect_one(container_id) is None,
                       'restitution_not_observed', container_id[:12])
            restitution['absent_container_ids'].append(container_id)
        for installation_id in installation_ids:
            self.check(listing('label=' + LABEL_KEYS['installation'] + '=' + installation_id) == [],
                       'restitution_not_observed', 'inventory')
            restitution['installation_inventory_empty'][installation_id] = True

    def actions_of(self, container_id, installation_id):
        events = lifecycle_events(self.since, time.time(), 'label=' + LABEL_KEYS['installation'] + '=' + installation_id)
        return [event['action'] for event in events if event['id'] == container_id]

    def epilogue(self, rec, runs, installation_ids):
        """Docker-side measurements shared by every scenario: replay, labels, controls, sentinel."""
        until = time.time()
        events = rec.d['docker_events']
        events['since'], events['until'] = self.since, until
        lifecycle, creates, attributes = {}, {}, {}
        for installation_id in installation_ids:
            listed = lifecycle_events(self.since, until, 'label=' + LABEL_KEYS['installation'] + '=' + installation_id)
            creates[installation_id] = sum(1 for item in listed if item['action'] == 'create')
            for item in listed:
                lifecycle.setdefault(item['id'], []).append(item['action'])
                if item['action'] == 'create':
                    attributes[item['id']] = item['attrs']
        starts = {container_id: actions.count('start') for container_id, actions in lifecycle.items()}
        events['lifecycle'], events['start_count'], events['create_count'] = lifecycle, starts, creates
        for run in runs:
            container_id = run['container_id']
            wanted = sum(1 for other in runs if other['installation_id'] == run['installation_id'])
            self.check(starts.get(container_id) == 1 and creates.get(run['installation_id']) == wanted,
                       'replay_detected', f'starts={starts.get(container_id)}')
            expected = {LABEL_KEYS['request']: run['name'], LABEL_KEYS['installation']: run['installation_id'],
                        LABEL_KEYS['guard_uid']: str(self.guard_uid), LABEL_KEYS['run']: run['run_id'],
                        LABEL_KEYS['variant']: run['variant']}
            seen = attributes.get(container_id, {})
            self.check(all(seen.get(key) == value for key, value in expected.items()) and seen.get('name') == run['name'],
                       'profile_or_label_mismatch', 'event labels')
        first = runs[0]['container_id']
        rec.control('events_instrument_sees_lifecycle', 'positive', {'create', 'start'} <= set(lifecycle.get(first, [])))
        stray = lifecycle_events(self.since, until, 'label=' + LABEL_KEYS['installation'] + '=' + uuid.uuid4().hex)
        rec.control('events_instrument_ignores_other_labels', 'negative', stray == [])
        self.check(all(item['passed'] for item in rec.d['controls']), 'instrument_unavailable', 'control failed')
        sentinel = self.sentinel
        sentinel_events = lifecycle_events(self.since, until, 'label=' + FIXTURE_LABEL + '=' + self.id)
        actions = [item['action'] for item in sentinel_events if item['id'] == sentinel['container_id']]
        data = inspect_one(sentinel['container_id'])
        after = None if data is None else fingerprint(data)
        rec.d['sentinel'] = {
            'container_id': sentinel['container_id'], 'name': sentinel['name'], 'before_sha256': sentinel['before'],
            'after_sha256': after or '0' * 64, 'status_before': sentinel['status_before'],
            'status_after': None if data is None else summary(data)['status'], 'lifecycle': actions}
        self.check(after == sentinel['before'] and actions == ['create'], 'sentinel_changed', ','.join(actions))
        restitution = rec.d['restitution']
        restitution['observed'] = (all(run['container_id'] in restitution['absent_container_ids'] for run in runs)
                                   and all(restitution['installation_inventory_empty'].get(i) is True
                                           for i in installation_ids))
        self.check(restitution['observed'], 'restitution_not_observed', 'incomplete')
        rec.claim('zero_start_replay', True)
        rec.claim('sentinel_intact', True)
        rec.claim('own_containers_absent_after', True)
        phases = {item['phase'] for item in rec.d['container_states']}
        rec.claim('states_before_after_recorded', 'running_before_fault' in phases and bool({'final', 'after_recovery'} & phases))

    def collect(self, rec):
        rec.d['processes'] = [item.record() for item in (*self.children, *self.clients)]
        hooks = []
        for child in self.children:
            for event in child.events:
                entry = {'source': child.role, **{key: event[key] for key in HOOK_KEYS if key in event and key != 'source'}}
                hooks.append(entry)
        rec.d['hook_events'] = hooks[:120]

    def cleanup(self):
        """Stop fixture children, then remove only ledger IDs (and only fixture-owned ones)."""
        forced = 0
        for item in (*self.children, *self.clients):
            if item.proc.poll() is None:
                forced += 1
            item.close()
        for child in self.children:
            spawned = next((e for e in child.events if e['kind'] == 'docker' and e.get('phase') == 'spawned'), None)
            if spawned is not None and isinstance(spawned.get('container_id'), str):
                self.kill_straggler(child, spawned['container_id'])
        items, confirmed = [], True
        with contextlib.suppress(HarnessError):
            for installation_id in self.installations:
                for container_id in listing('label=' + LABEL_KEYS['installation'] + '=' + installation_id):
                    self.add_ledger(container_id, 'verifier')
        for container_id, role in list(self.ledger.items()):
            entry = {'container_id': container_id, 'role': role, 'present_at_cleanup': False,
                     'removed_by_fixture': False, 'absent_after': False}
            try:
                data = inspect_one(container_id)
                entry['present_at_cleanup'] = data is not None
                if data is not None:
                    labels = (data.get('Config') or {}).get('Labels') or {}
                    ours = (labels.get(FIXTURE_LABEL) == self.id
                            or labels.get(LABEL_KEYS['installation']) in self.installations)
                    if ours:
                        remove_by_id(container_id)
                        entry['removed_by_fixture'] = True
                entry['absent_after'] = listing('id=' + container_id) == []
            except HarnessError:
                entry['absent_after'] = False
            confirmed = confirmed and entry['absent_after']
            items.append(entry)
        return {'items': items, 'confirmed': confirmed, 'children_forced': forced}


# ---------------------------------------------------------------------------------------------
# Scenarios


def scenario_kill_running(fx, rec):
    directory, installation = fx.new_installation(rec, 'kill')
    fx.make_sentinel(rec)
    run = fx.new_run(installation, 'legitimate')
    rec.d['runs'].append(run)
    owner = fx.spawn_owner(directory, run, hold=True)
    ack_index = fx.learn_run(owner, run)
    _, running = owner.wait_for('running_observed', after=ack_index)
    fx.observe_running(rec, run, running)
    rec.mark('running_observed')
    container_id = run['container_id']

    owner.send('SIGKILL')
    rec.mark('fault_injected')
    code = owner.finish()
    fx.check(code == -9, 'owner_survived_signal', str(code))
    after = inspect_one(container_id)
    rec.state('after_fault', container_id, None if after is None else summary(after))
    durable = read_state(directory)
    fx.check(durable['kinds'] == ['PENDING', 'ACK'] and durable['payloads'][1] == {'container_id': container_id}
             and durable['payloads'][0]['run_id'] == run['run_id'] and durable['payloads'][0]['name'] == run['name']
             and durable['payloads'][0]['variant'] == run['variant'], 'state_unexpected', ','.join(durable['kinds']))
    rec.d['transitions'].append({'installation_id': installation, 'phase': 'at_fault', 'durable_events': durable['kinds']})
    rec.claim('guard_owner_sigkilled_while_running', True)
    rec.claim('crash_state_pending_ack_only', True)

    # Negative control: a recovery under another client identity must refuse and touch nothing.
    code, reason = fx.cli(directory, '--recover-only', client_uid=fx.alt_uid)
    rec.d['cli_runs'].append({'purpose': 'wrong_identity_recovery', 'kind': 'recover-only',
                              'installation_id': installation, 'returncode': code, 'reason': reason})
    present = inspect_one(container_id)
    fx.check(code == 2 and reason == 'guard_state_unavailable' and present is not None
             and read_state(directory)['kinds'] == ['PENDING', 'ACK'], 'recovery_unexpected', f'{code}:{reason}')
    rec.state('before_recovery', container_id, summary(present))
    rec.control('wrong_identity_recovery_refused', 'negative', True)

    code, reason = fx.cli(directory, '--recover-only')
    rec.d['cli_runs'].append({'purpose': 'recovery', 'kind': 'recover-only', 'installation_id': installation,
                              'returncode': code, 'reason': reason})
    fx.check(code == 0 and reason is None, 'recovery_unexpected', f'{code}:{reason}')
    rec.mark('recovery_completed')
    final = read_state(directory)
    fx.check(final['kinds'] == ['PENDING', 'ACK', 'FINISH'], 'state_unexpected', ','.join(final['kinds']))
    fx.observe_restitution(rec, [container_id], [installation])
    rec.state('after_recovery', container_id, None)
    rec.claim('recovery_removed_full_id', True)
    fx.kill_straggler(owner, container_id)

    code, reason = fx.cli(directory, '--recover-only')
    rec.d['cli_runs'].append({'purpose': 'repeat_recovery', 'kind': 'recover-only', 'installation_id': installation,
                              'returncode': code, 'reason': reason})
    again = read_state(directory)
    fx.check(code == 0 and reason is None and again['kinds'] == final['kinds'], 'recovery_unexpected', 'repeat')
    rec.claim('repeat_recovery_idempotent', True)
    rec.d['transitions'].append({'installation_id': installation, 'phase': 'final', 'durable_events': again['kinds']})
    fx.epilogue(rec, [run], [installation])


def scenario_cancel_client(fx, rec):
    directory, installation = fx.new_installation(rec, 'cancel')
    fx.make_sentinel(rec)
    sock_dir = fx.scratch / 'sock'
    sock_dir.mkdir(mode=0o755)
    sock_dir.chmod(0o755)
    path = sock_dir / 'guard.sock'
    serve = fx.spawn_serve(directory, path)
    # Readiness handshake and negative control: a peer that is not the client UID is rejected before Docker.
    deadline = time.monotonic() + HANDSHAKE_LIMIT
    reply = None
    while reply is None:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(5)
                probe.connect(str(path))
                reply = probe.recv(512)
        except (FileNotFoundError, ConnectionRefusedError):
            pass
        except OSError as exc:
            raise HarnessError('unexpected_response', 'probe') from exc
        if reply is None:
            fx.check(serve.proc.poll() is None, 'owner_exited_early', 'server')
            fx.check(time.monotonic() < deadline, 'handshake_timeout', 'socket')
            serve.pump(0.05)
    try:
        probe_reply = json.loads(reply)
    except ValueError:
        probe_reply = None
    fx.check(probe_reply == {'status': 'error', 'reason': 'unauthorized'}, 'unexpected_response', 'probe reply')
    rec.control('unauthorized_peer_rejected', 'negative', not any(
        e['kind'] == 'docker' and e.get('op') == 'create' for e in serve.events))

    first = fx.new_run(installation, 'legitimate')
    second = fx.new_run(installation, 'perturbed')
    rec.d['runs'] += [first, second]
    client = ClientProc(fx, path, first)
    ack_index = fx.learn_run(serve, first)
    _, running = serve.wait_for('running_observed', after=ack_index)
    fx.observe_running(rec, first, running)
    rec.mark('running_observed')
    container_id = first['container_id']

    cut = len(serve.events)
    client.send('SIGTERM')
    rec.mark('fault_injected')
    fx.check(client.finish() == -15, 'cancel_not_observed', 'client exit')
    present = inspect_one(container_id)
    fx.check(present is not None, 'cancel_not_observed', 'container vanished before release')
    rec.state('after_cancel', container_id, summary(present))
    serve.release()
    rec.mark('release_sent')
    serve.wait_for('state', after=cut, transition='FINISH')
    rec.mark('finish_observed')
    fx.observe_restitution(rec, [container_id], [installation])
    rec.state('final', container_id, None)
    rec.claim('client_cancelled_while_running', True)
    rec.claim('restitution_observed_after_cancel', True)

    # The guard must keep admitting after the cancelled exchange.
    cut = len(serve.events)
    admitted = ClientProc(fx, path, second)
    outcome = admitted.result()
    fx.check(outcome.get('ok') is True and outcome.get('status') in ('passed', 'rejected')
             and outcome.get('cleanup_confirmed') is True, 'guard_blocked_unexpectedly', str(outcome.get('reason')))
    fx.learn_run(serve, second)
    serve.wait_for('state', after=cut, transition='FINISH')
    fx.check(outcome.get('container_id') == second['container_id'] != container_id, 'unexpected_response', 'second id')
    fx.observe_restitution(rec, [second['container_id']], [installation])
    rec.state('final', second['container_id'], None)
    rec.control('post_cancel_admission', 'positive', True)
    rec.claim('guard_admits_after_cancel', True)

    serve.send('SIGTERM')
    code = serve.finish()
    fx.check(code == 0 and not os.path.lexists(path), 'guard_blocked_unexpectedly', f'stop={code}')
    rec.claim('guard_clean_stop', True)
    final = read_state(directory)
    fx.check(final['kinds'] == ['PENDING', 'ACK', 'FINISH'] * 2, 'state_unexpected', ','.join(final['kinds']))
    rec.d['transitions'].append({'installation_id': installation, 'phase': 'final', 'durable_events': final['kinds']})
    fx.epilogue(rec, [first, second], [installation])


def scenario_second_guard_exclusion(fx, rec):
    directory, installation = fx.new_installation(rec, 'excl')
    fx.make_sentinel(rec)
    run = fx.new_run(installation, 'legitimate')
    rec.d['runs'].append(run)
    owner = fx.spawn_owner(directory, run, hold=True)
    ack_index = fx.learn_run(owner, run)
    _, running = owner.wait_for('running_observed', after=ack_index)
    before = fx.observe_running(rec, run, running)
    rec.mark('running_observed')
    container_id = run['container_id']

    sock_dir = fx.scratch / 'sock'
    sock_dir.mkdir(mode=0o755)
    sock_dir.chmod(0o755)
    second_socket = sock_dir / 'second.sock'
    files_before = lock_snapshot(directory)
    rec.mark('fault_injected')  # from here a second guard tries to take the same installation
    attempts = (
        ('second_guard_serve', 'serve', ('--socket', str(second_socket))),
        ('second_guard_recover', 'recover-only', ('--recover-only',)),
        ('second_guard_initialize', 'initialize-state', ('--initialize-state',)),
    )
    for purpose, kind, extra in attempts:
        code, reason = fx.cli(directory, *extra)
        rec.d['cli_runs'].append({'purpose': purpose, 'kind': kind, 'installation_id': installation,
                                  'returncode': code, 'reason': reason})
        allowed = CLI_EXPECT['second_guard_exclusion'][purpose][1]
        fx.check(code == 2 and reason in allowed, 'lock_not_exclusive', f'{purpose}:{code}:{reason}')
    fx.check(not os.path.lexists(second_socket), 'lock_not_exclusive', 'second socket created')
    stable = lock_snapshot(directory) == files_before
    rec.d['installations'][0]['lock_inode_stable'] = stable
    fx.check(stable, 'lock_not_exclusive', 'state files changed')
    present = inspect_one(container_id)
    fx.check(present is not None, 'lock_not_exclusive', 'verifier removed by second guard')
    now = summary(present)
    fx.check(now['running'] is True and now['pid'] == before['pid'] and now['started_at'] == before['started_at'],
             'lock_not_exclusive', 'verifier disturbed')
    rec.state('after_exclusion_attempts', container_id, now)
    harmful = {'kill', 'die', 'stop', 'destroy'} & set(fx.actions_of(container_id, installation))
    fx.check(not harmful, 'lock_not_exclusive', ','.join(sorted(harmful)))
    rec.claim('second_guard_refused_same_installation', True)
    rec.claim('running_verifier_untouched', True)
    rec.claim('lock_inode_stable', True)

    cut = len(owner.events)
    owner.release()
    rec.mark('release_sent')
    owner.wait_for('verify_returned', after=cut)
    owner.wait_for('state', after=cut, transition='FINISH')
    rec.mark('finish_observed')
    fx.check(owner.finish() == 0, 'unexpected_response', 'owner exit')
    final = read_state(directory)
    fx.check(final['kinds'] == ['PENDING', 'ACK', 'FINISH'], 'state_unexpected', ','.join(final['kinds']))
    fx.observe_restitution(rec, [container_id], [installation])
    rec.state('final', container_id, None)
    rec.claim('first_guard_completed', True)

    # Positive control: the same command that was refused now works, so the lock was the only obstacle.
    code, reason = fx.cli(directory, '--recover-only')
    rec.d['cli_runs'].append({'purpose': 'post_exit_recovery', 'kind': 'recover-only', 'installation_id': installation,
                              'returncode': code, 'reason': reason})
    fx.check(code == 0 and reason is None and read_state(directory)['kinds'] == final['kinds'],
             'recovery_unexpected', 'post exit')
    rec.control('lock_released_after_exit', 'positive', True)
    rec.d['transitions'].append({'installation_id': installation, 'phase': 'final', 'durable_events': final['kinds']})
    fx.epilogue(rec, [run], [installation])


def scenario_two_runs_foreign_sentinel(fx, rec):
    dir_one, inst_one = fx.new_installation(rec, 'run-one')
    dir_two, inst_two = fx.new_installation(rec, 'run-two')
    fx.make_sentinel(rec)
    first = fx.new_run(inst_one, 'legitimate')
    second = fx.new_run(inst_two, 'perturbed')
    rec.d['runs'] += [first, second]
    owner_one = fx.spawn_owner(dir_one, first, hold=True)
    owner_two = fx.spawn_owner(dir_two, second, hold=True)
    ack_one = fx.learn_run(owner_one, first)
    ack_two = fx.learn_run(owner_two, second)
    _, running_one = owner_one.wait_for('running_observed', after=ack_one)
    _, running_two = owner_two.wait_for('running_observed', after=ack_two)
    fx.observe_running(rec, first, running_one)
    info_two = fx.observe_running(rec, second, running_two)
    rec.mark('running_observed')
    cid_one, cid_two = first['container_id'], second['container_id']
    fx.check(len({cid_one, cid_two}) == 2 and inst_one != inst_two and first['run_id'] != second['run_id'],
             'unexpected_response', 'runs not distinct')
    rec.claim('distinct_runs_and_installations', True)

    cut_two = len(owner_two.events)
    owner_one.send('SIGKILL')
    rec.mark('fault_injected')
    fx.check(owner_one.finish() == -9, 'owner_survived_signal', 'first owner')
    rec.state('after_fault', cid_one, summary(inspect_one(cid_one)) if inspect_one(cid_one) else None)
    crashed = read_state(dir_one)
    fx.check(crashed['kinds'] == ['PENDING', 'ACK'], 'state_unexpected', ','.join(crashed['kinds']))
    rec.d['transitions'].append({'installation_id': inst_one, 'phase': 'at_fault', 'durable_events': crashed['kinds']})
    fx.check(owner_two.proc.poll() is None, 'foreign_removed', 'second owner died')

    code, reason = fx.cli(dir_one, '--recover-only')
    rec.d['cli_runs'].append({'purpose': 'recovery', 'kind': 'recover-only', 'installation_id': inst_one,
                              'returncode': code, 'reason': reason})
    fx.check(code == 0 and reason is None, 'recovery_unexpected', f'{code}:{reason}')
    rec.mark('recovery_completed')
    recovered = read_state(dir_one)
    fx.check(recovered['kinds'] == ['PENDING', 'ACK', 'FINISH'], 'state_unexpected', ','.join(recovered['kinds']))
    fx.observe_restitution(rec, [cid_one], [inst_one])
    rec.state('after_recovery', cid_one, None)
    fx.kill_straggler(owner_one, cid_one)

    # The other run and the foreign sentinel must be exactly as before the recovery.
    other = inspect_one(cid_two)
    fx.check(other is not None, 'foreign_removed', 'other run container removed')
    now = summary(other)
    fx.check(now['running'] is True and now['pid'] == info_two['pid'] and now['started_at'] == info_two['started_at'],
             'foreign_removed', 'other run disturbed')
    fx.check(listing('label=' + LABEL_KEYS['installation'] + '=' + inst_two) == [cid_two], 'foreign_removed', 'inventory two')
    fx.check(inspect_one(fx.sentinel['container_id']) is not None, 'foreign_removed', 'sentinel removed')
    rec.state('after_peer_recovery', cid_two, now)
    harmful = {'kill', 'die', 'stop', 'destroy'} & set(fx.actions_of(cid_two, inst_two))
    fx.check(not harmful, 'foreign_removed', ','.join(sorted(harmful)))
    rec.claim('other_run_untouched_by_recovery', True)
    rec.claim('recovery_limited_to_own_installation', True)

    code, reason = fx.cli(dir_one, '--recover-only')
    rec.d['cli_runs'].append({'purpose': 'repeat_recovery', 'kind': 'recover-only', 'installation_id': inst_one,
                              'returncode': code, 'reason': reason})
    fx.check(code == 0 and reason is None and read_state(dir_one)['kinds'] == recovered['kinds'],
             'recovery_unexpected', 'repeat')
    rec.d['transitions'].append({'installation_id': inst_one, 'phase': 'final', 'durable_events': recovered['kinds']})

    owner_two.release()
    rec.mark('release_sent')
    owner_two.wait_for('verify_returned', after=cut_two)
    owner_two.wait_for('state', after=cut_two, transition='FINISH')
    rec.mark('finish_observed')
    fx.check(owner_two.finish() == 0, 'unexpected_response', 'second owner exit')
    done = read_state(dir_two)
    fx.check(done['kinds'] == ['PENDING', 'ACK', 'FINISH'], 'state_unexpected', ','.join(done['kinds']))
    fx.observe_restitution(rec, [cid_two], [inst_two])
    rec.state('final', cid_two, None)
    rec.d['transitions'].append({'installation_id': inst_two, 'phase': 'final', 'durable_events': done['kinds']})
    touched = any(event.get('container_id') == cid_one for event in owner_two.events if event['kind'] == 'docker')
    rec.control('other_guard_did_not_touch_foreign', 'negative', not touched)
    rec.claim('other_guard_completed', True)
    fx.epilogue(rec, [first, second], [inst_one, inst_two])


SCENARIO_FUNCTIONS = {
    'kill_running': scenario_kill_running,
    'cancel_client': scenario_cancel_client,
    'second_guard_exclusion': scenario_second_guard_exclusion,
    'two_runs_foreign_sentinel': scenario_two_runs_foreign_sentinel,
}


# ---------------------------------------------------------------------------------------------
# Receipt validation (offline, pure)

TOP_KEYS = frozenset({'schema', 'delivery_id', 'stage', 'evidence_class', 'mode', 'generated_unix',
                      'harness_sha256', 'candidate', 'environment', 'prior_coverage', 'unknowns', 'scenarios',
                      'cleanup', 'limits'})
SCENARIO_KEYS = frozenset(Record('x').d)
ENV_KEYS = frozenset({'image_id', 'pull_policy', 'docker_daemon_id', 'docker_root', 'fixture_uid', 'fixture_gid',
                      'client_uid', 'python', 'platform'})
CLEANUP_KEYS = frozenset({'confirmed', 'items', 'scratch_removed', 'children_forced'})


def _is_int(value):
    return type(value) is int


def _is_hex(value, pattern):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def validate_receipt(receipt, *, harness_sha256=None):
    """Return the decision for one receipt. Fails closed: any problem leaves criteria_met empty."""
    problems = []

    def need(condition, text):
        if not condition and len(problems) < 80:
            problems.append(text)

    result = {'schema_valid': False, 'problems': problems, 'evidence_class': None, 'scenario_status': {},
              'criteria_met': [], 'pending': list(SCENARIOS), 'accepted': False}
    if not isinstance(receipt, dict) or set(receipt) != TOP_KEYS:
        need(False, 'top_level_keys')
        return result
    need(receipt['schema'] == SCHEMA and receipt['delivery_id'] == DELIVERY_ID and receipt['stage'] == STAGE,
         'identity')
    cls, mode = receipt['evidence_class'], receipt['mode']
    need((cls, mode) in (('measured', 'linux_docker'), ('simulated', 'offline_synthetic')), 'class_mode_pair')
    result['evidence_class'] = cls
    need(_is_hex(receipt['harness_sha256'], HEX64), 'harness_hash_format')
    if harness_sha256 is not None:
        need(receipt['harness_sha256'] == harness_sha256, 'harness_hash_mismatch')
    need(isinstance(receipt['generated_unix'], (int, float)) and receipt['generated_unix'] > 0, 'generated_unix')

    candidate = receipt['candidate']
    base_ok = False
    if isinstance(candidate, dict) and set(candidate) == {'files', 'matches_base', 'base_manifest'}:
        files, manifest = candidate['files'], candidate['base_manifest']
        need(isinstance(files, dict) and set(files) == set(CANDIDATE)
             and all(v is None or _is_hex(v, HEX64) for v in files.values()), 'candidate_files')
        need(isinstance(manifest, dict) and set(manifest) == {'gating_ok', 'base_intact'}
             and all(isinstance(v, bool) for v in manifest.values()), 'candidate_manifest')
        if isinstance(files, dict) and isinstance(manifest, dict) and isinstance(candidate['matches_base'], bool):
            expected_match = files == CANDIDATE and manifest.get('gating_ok') is True and manifest.get('base_intact') is True
            need(candidate['matches_base'] == expected_match, 'candidate_matches_base_inconsistent')
            base_ok = candidate['matches_base'] and expected_match
        else:
            need(False, 'candidate_types')
    else:
        need(False, 'candidate_keys')

    env = receipt['environment']
    if isinstance(env, dict) and set(env) == ENV_KEYS:
        need(isinstance(env['image_id'], str) and IMAGE_ID.fullmatch(env['image_id']) is not None, 'environment_image')
        need(env['pull_policy'] == 'never', 'environment_pull_policy')
        need(isinstance(env['docker_daemon_id'], str) and bool(env['docker_daemon_id']), 'environment_daemon')
        need(isinstance(env['docker_root'], str) and env['docker_root'].startswith('/'), 'environment_root')
        need(all(_is_int(env[k]) and env[k] >= 0 for k in ('fixture_uid', 'fixture_gid', 'client_uid')), 'environment_ids')
        need(env['client_uid'] != env['fixture_uid'], 'environment_client_uid')
        need(isinstance(env['python'], str) and isinstance(env['platform'], str), 'environment_text')
    else:
        need(False, 'environment_keys')

    prior = receipt['prior_coverage']
    need(isinstance(prior, dict) and set(prior) == {'path', 'sha256', 'covers', 'repeated_here'}
         and prior['path'] == PRIOR['path'] and prior['sha256'] == PRIOR['sha256']
         and prior['covers'] == PRIOR['covers'] and prior['repeated_here'] is False, 'prior_coverage')
    unknowns = receipt['unknowns']
    need(isinstance(unknowns, list) and all(u in UNKNOWN_CODES for u in unknowns)
         and all(u in unknowns for u in REQUIRED_UNKNOWNS), 'unknowns')
    limits = receipt['limits']
    need(isinstance(limits, list) and 0 < len(limits) <= 12
         and all(isinstance(t, str) and 0 < len(t) <= 400 for t in limits), 'limits')

    cleanup = receipt['cleanup']
    cleanup_ok = False
    if isinstance(cleanup, dict) and set(cleanup) == CLEANUP_KEYS and isinstance(cleanup['items'], list):
        entry_keys = {'container_id', 'role', 'present_at_cleanup', 'removed_by_fixture', 'absent_after'}
        need(all(isinstance(i, dict) and set(i) == entry_keys and _is_hex(i['container_id'], HEX64)
                 and i['role'] in ('sentinel', 'verifier') and all(isinstance(i[k], bool) for k in entry_keys - {'container_id', 'role'})
                 for i in cleanup['items']), 'cleanup_items')
        need(isinstance(cleanup['confirmed'], bool) and isinstance(cleanup['scratch_removed'], bool)
             and _is_int(cleanup['children_forced']) and cleanup['children_forced'] >= 0, 'cleanup_types')
        need(cleanup['confirmed'] == all(i.get('absent_after') is True for i in cleanup['items']
                                         if isinstance(i, dict)), 'cleanup_confirmed_inconsistent')
        cleanup_ok = cleanup['confirmed'] is True
    else:
        need(False, 'cleanup_keys')

    scenarios = receipt['scenarios']
    if not isinstance(scenarios, list) or [s.get('id') if isinstance(s, dict) else None for s in scenarios] != list(SCENARIOS):
        need(False, 'scenario_ids')
        return result
    for scenario in scenarios:
        try:
            _check_scenario(scenario, cls, base_ok, need)
        except (KeyError, TypeError, AttributeError, IndexError, ValueError):
            need(False, f'{scenario.get("id")}:malformed')  # fail closed on any structural surprise
    result['scenario_status'] = {s['id']: s['status'] for s in scenarios if isinstance(s.get('status'), str)}
    result['schema_valid'] = not problems
    passed = [s['id'] for s in scenarios if s.get('status') == 'passed']
    if not problems:
        result['criteria_met'] = passed
        result['pending'] = [sid for sid in SCENARIOS if sid not in passed]
        result['accepted'] = (cls == 'measured' and mode == 'linux_docker' and len(passed) == len(SCENARIOS)
                              and cleanup_ok)
    return result


def _check_scenario(sc, cls, base_ok, need):
    if not isinstance(sc, dict) or set(sc) != SCENARIO_KEYS:
        need(False, 'scenario_keys')
        return
    sid, status, reason = sc['id'], sc['status'], sc['reason']
    need(status in STATUSES, f'{sid}:status')
    if status == 'omitted':
        need(reason in OMIT_CODES and not sc['runs'] and not sc['errors'], f'{sid}:omitted')
        return
    if status == 'failed':
        need(reason in FAIL_CODES, f'{sid}:failed_reason')
    elif status == 'error':
        need(reason in ERROR_CODES, f'{sid}:error_reason')
    elif status == 'passed':
        need(reason is None and sc['errors'] == [], f'{sid}:passed_reason')
        need(base_ok, f'{sid}:passed_without_matching_base')
    if status in ('failed', 'error'):
        need(isinstance(sc['errors'], list) and any(isinstance(e, dict) and e.get('code') == reason for e in sc['errors']),
             f'{sid}:error_evidence')
    well_formed = _check_shapes(sc, need)
    if status == 'passed' and well_formed:
        _check_passed(sc, cls, need)


def _check_shapes(sc, outer):
    """Closed-vocabulary and type checks; returns False when the entries are not well formed."""
    sid = sc['id']
    clean = [True]

    def need(condition, text):
        if not condition:
            clean[0] = False
        outer(condition, text)

    for e in sc['errors']:
        need(isinstance(e, dict) and set(e) == {'code', 'where'} and e['code'] in ALL_REASONS - OMIT_CODES
             and isinstance(e['where'], str), f'{sid}:error_entry')
    for p in sc['processes']:
        need(isinstance(p, dict) and set(p) == {'role', 'pid', 'uid', 'signal_sent', 'returncode', 'exit_signal'}
             and p['role'] in ROLES and _is_int(p['pid']) and _is_int(p['uid'])
             and p['signal_sent'] in (None, *SIGNAL_NAMES)
             and (p['exit_signal'] is None or (isinstance(p['exit_signal'], str) and SIGNAL_EXIT.fullmatch(p['exit_signal'])))
             and (p['returncode'] is None or _is_int(p['returncode'])), f'{sid}:process_entry')
    for c in sc['cli_runs']:
        need(isinstance(c, dict) and set(c) == {'purpose', 'kind', 'installation_id', 'returncode', 'reason'}
             and c['purpose'] in CLI_PURPOSES and c['kind'] in CLI_KINDS and _is_hex(c['installation_id'], HEX32)
             and _is_int(c['returncode']) and (c['reason'] is None or (isinstance(c['reason'], str) and REASON.fullmatch(c['reason']))),
             f'{sid}:cli_entry')
    for t in sc['transitions']:
        need(isinstance(t, dict) and set(t) == {'installation_id', 'phase', 'durable_events'}
             and _is_hex(t['installation_id'], HEX32) and t['phase'] in ('at_fault', 'final')
             and isinstance(t['durable_events'], list) and all(k in ('PENDING', 'ACK', 'FINISH') for k in t['durable_events']),
             f'{sid}:transition_entry')
    for s in sc['container_states']:
        need(isinstance(s, dict) and set(s) == {'phase', 'container_id', 'present', 'status', 'running'}
             and s['phase'] in PHASES and _is_hex(s['container_id'], HEX64) and isinstance(s['present'], bool)
             and (s['status'] is None or isinstance(s['status'], str)) and (s['running'] is None or isinstance(s['running'], bool)),
             f'{sid}:state_entry')
    for m in sc['timeline']:
        need(isinstance(m, dict) and set(m) == {'mark', 't_ns'} and m['mark'] in MARKS and _is_int(m['t_ns']),
             f'{sid}:timeline_entry')
    for code, item in (sc['claims'].items() if isinstance(sc['claims'], dict) else [(None, None)]):
        need(code in ALL_CLAIMS and isinstance(item, dict) and set(item) == {'holds', 'basis'}
             and item['basis'] in BASES and (item['holds'] is None or isinstance(item['holds'], bool)), f'{sid}:claim_entry')
    for c in sc['controls']:
        need(isinstance(c, dict) and set(c) == {'code', 'kind', 'passed', 'basis'} and c['code'] in ALL_CONTROLS
             and c['kind'] in CONTROL_KINDS and isinstance(c['passed'], bool) and c['basis'] in BASES,
             f'{sid}:control_entry')
    need(isinstance(sc['hook_events'], list) and len(sc['hook_events']) <= 120 and all(
        isinstance(h, dict) and set(h) <= HOOK_KEYS and h.get('kind') in HOOK_KINDS and h.get('source') in ROLES
        for h in sc['hook_events']), f'{sid}:hook_events')
    return clean[0]


def _check_passed(sc, cls, need):
    sid = sc['id']
    basis = 'measured' if cls == 'measured' else 'simulated'
    for code in COMMON_CLAIMS + SPECIFIC_CLAIMS[sid]:
        item = sc['claims'].get(code)
        need(isinstance(item, dict) and item.get('holds') is True and item.get('basis') == basis, f'{sid}:claim:{code}')
    for code in CONTROLS[sid]:
        found = [c for c in sc['controls'] if c.get('code') == code]
        need(bool(found) and all(c.get('passed') is True and c.get('basis') == basis for c in found), f'{sid}:control:{code}')
    need({c.get('kind') for c in sc['controls']} >= set(CONTROL_KINDS), f'{sid}:control_kinds')

    shape = SHAPE[sid]
    installs = {i.get('installation_id'): i for i in sc['installations'] if isinstance(i, dict)}
    need(len(sc['installations']) == shape['installations'] == len(installs), f'{sid}:installations')
    for i in sc['installations']:
        need(isinstance(i, dict) and set(i) == {'installation_id', 'guard_uid', 'client_uid', 'lock_inode_stable'}
             and _is_hex(i['installation_id'], HEX32) and _is_int(i['guard_uid']) and _is_int(i['client_uid'])
             and i['guard_uid'] != i['client_uid'], f'{sid}:installation_entry')
    runs = sc['runs']
    need(len(runs) == shape['runs'], f'{sid}:run_count')
    by_run = {}
    for r in runs:
        ok = (isinstance(r, dict) and set(r) == {'run_id', 'variant', 'installation_id', 'name', 'container_id', 'labels_basis'}
              and _is_hex(r['run_id'], HEX32) and r['variant'] in VARIANTS and r['installation_id'] in installs
              and isinstance(r['name'], str) and NAME_RE.fullmatch(r['name']) and _is_hex(r['container_id'], HEX64)
              and r['labels_basis'] in LABEL_BASES)
        need(ok, f'{sid}:run_entry')
        if ok:
            by_run[r['run_id']] = r
    need(len(by_run) == len(runs) and len({r.get('container_id') for r in runs}) == len(runs), f'{sid}:run_identity_unique')
    if sid == 'two_runs_foreign_sentinel':
        need(len({r.get('installation_id') for r in runs}) == 2, f'{sid}:distinct_installations')
    if sid == 'second_guard_exclusion':
        only = sc['installations'][0] if sc['installations'] else {}
        need(only.get('lock_inode_stable') is True, f'{sid}:lock_inode')

    need(len(sc['running']) == shape['running'], f'{sid}:running_count')
    for r in sc['running']:
        run = by_run.get(r.get('run_id')) if isinstance(r, dict) else None
        keys = {'run_id', 'container_id', 'observers', 'status', 'running', 'state_pid', 'configured_user',
                'host_uid_observed', 'labels', 'daemon_id', 'daemon_root'}
        ok = isinstance(r, dict) and set(r) == keys and run is not None and r['container_id'] == run['container_id']
        need(ok, f'{sid}:running_entry')
        if not ok:
            continue
        roles = [o.get('role') for o in r['observers']] if isinstance(r['observers'], list) else []
        need(sorted(roles) == sorted(OBSERVER_ROLES) and all(
            _is_int(o.get('pid')) and o['pid'] > 0 and _is_int(o.get('uid')) and set(o) == {'role', 'pid', 'uid'}
            for o in r['observers']), f'{sid}:observers')
        need(r['status'] == 'running' and r['running'] is True and _is_int(r['state_pid']) and r['state_pid'] > 0,
             f'{sid}:running_state')
        need(r['configured_user'] == '65534:65534' and r['host_uid_observed'] in (None, [65534, 65534]), f'{sid}:running_uid')
        owner = installs.get(run['installation_id'], {})
        need(r['labels'] == {'request': run['name'], 'installation': run['installation_id'],
                             'guard_uid': str(owner.get('guard_uid')), 'run': run['run_id'], 'variant': run['variant']},
             f'{sid}:running_labels')
        need(isinstance(r['daemon_id'], str) and bool(r['daemon_id']) and isinstance(r['daemon_root'], str)
             and r['daemon_root'].startswith('/'), f'{sid}:running_daemon')
        need(run['labels_basis'] == 'inspect+docker_events', f'{sid}:labels_basis')

    states = sc['container_states']
    phases = {s.get('phase') for s in states if isinstance(s, dict)}
    need(STATE_PHASES[sid] <= phases, f'{sid}:state_phases')
    for run in runs:
        mine = [s for s in states if isinstance(s, dict) and s.get('container_id') == run.get('container_id')]
        if any(r.get('run_id') == run.get('run_id') for r in sc['running']):
            need(any(s['phase'] == 'running_before_fault' and s['present'] and s['running'] is True for s in mine),
                 f'{sid}:state_before')
        need(any(s['phase'] in ('after_recovery', 'final') and s['present'] is False for s in mine), f'{sid}:state_after')
    live_phase = {'second_guard_exclusion': 'after_exclusion_attempts', 'two_runs_foreign_sentinel': 'after_peer_recovery',
                  'cancel_client': 'after_cancel', 'kill_running': 'before_recovery'}[sid]
    need(any(isinstance(s, dict) and s.get('phase') == live_phase and s['present'] is True for s in states), f'{sid}:live_phase')
    if live_phase in ('after_exclusion_attempts', 'after_peer_recovery'):
        need(any(s['phase'] == live_phase and s['running'] is True for s in states), f'{sid}:live_running')

    marks = [m.get('mark') for m in sc['timeline'] if isinstance(m, dict)]
    times = [m.get('t_ns') for m in sc['timeline'] if isinstance(m, dict)]
    need(marks == list(TIMELINE[sid]) and all(_is_int(t) for t in times)
         and all(a < b for a, b in zip(times, times[1:])), f'{sid}:timeline')

    final = [t for t in sc['transitions'] if t.get('phase') == 'final']
    need(sorted(t.get('installation_id') for t in final) == sorted(installs), f'{sid}:final_installations')
    need(all(t.get('durable_events') == ['PENDING', 'ACK', 'FINISH'] * FINAL_CYCLES[sid] for t in final), f'{sid}:final_events')
    at_fault = [t for t in sc['transitions'] if t.get('phase') == 'at_fault']
    need(len(at_fault) == AT_FAULT[sid], f'{sid}:at_fault_count')
    for t in at_fault:
        kinds = t.get('durable_events')
        if kinds and kinds[-1] == 'PENDING':
            # Without ACK the guard must stay blocked: no removal, no FINISH, recovery refused.
            recovery = [c for c in sc['cli_runs'] if c.get('purpose') == 'recovery' and c.get('installation_id') == t.get('installation_id')]
            blocked = bool(recovery) and all(c['returncode'] == 2 and c['reason'] == 'guard_recovery_required' for c in recovery)
            closed = any(f.get('installation_id') == t.get('installation_id') and 'FINISH' in f.get('durable_events', []) for f in final)
            need(blocked and not closed, f'{sid}:no_ack_block_not_maintained')
        need(kinds == ['PENDING', 'ACK'], f'{sid}:at_fault_events')

    for purpose, (code, reasons) in CLI_EXPECT[sid].items():
        found = [c for c in sc['cli_runs'] if c.get('purpose') == purpose]
        need(bool(found) and all(c['returncode'] == code and c['reason'] in reasons for c in found), f'{sid}:cli:{purpose}')
    for role, sent, code in PROC_EXPECT[sid]:
        need(any(p.get('role') == role and p.get('signal_sent') == sent and p.get('returncode') == code
                 for p in sc['processes']), f'{sid}:process:{role}:{sent}')
    for p in sc['processes']:
        need(p.get('returncode') is not None and (p['returncode'] >= 0) == (p['exit_signal'] is None), f'{sid}:process_exit')

    events = sc['docker_events']
    ok = (isinstance(events, dict) and set(events) == {'since', 'until', 'lifecycle', 'start_count', 'create_count'}
          and isinstance(events['since'], (int, float)) and isinstance(events['until'], (int, float))
          and events['since'] < events['until'] and isinstance(events['lifecycle'], dict)
          and isinstance(events['start_count'], dict) and isinstance(events['create_count'], dict))
    need(ok, f'{sid}:docker_events')
    if ok:
        for r in runs:
            actions = events['lifecycle'].get(r['container_id'])
            need(isinstance(actions, list) and all(isinstance(a, str) and ACTION.fullmatch(a) for a in actions)
                 and {'create', 'start'} <= set(actions) and actions[-1] == 'destroy' and actions.count('start') == 1,
                 f'{sid}:lifecycle')
            need(events['start_count'].get(r['container_id']) == 1, f'{sid}:zero_replay_start')
            need(events['create_count'].get(r['installation_id']) == sum(1 for o in runs if o['installation_id'] == r['installation_id']),
                 f'{sid}:zero_replay_create')

    sentinel = sc['sentinel']
    need(isinstance(sentinel, dict) and set(sentinel) == {'container_id', 'name', 'before_sha256', 'after_sha256',
                                                          'status_before', 'status_after', 'lifecycle'}
         and _is_hex(sentinel['container_id'], HEX64) and _is_hex(sentinel['before_sha256'], HEX64)
         and sentinel['before_sha256'] == sentinel['after_sha256']
         and sentinel['status_before'] == sentinel['status_after'] == 'created' and sentinel['lifecycle'] == ['create']
         and sentinel['container_id'] not in {r['container_id'] for r in runs}, f'{sid}:sentinel')

    rest = sc['restitution']
    need(isinstance(rest, dict) and set(rest) == {'observed', 'absent_container_ids', 'installation_inventory_empty'}
         and rest['observed'] is True and isinstance(rest['absent_container_ids'], list)
         and all(r['container_id'] in rest['absent_container_ids'] for r in runs)
         and isinstance(rest['installation_inventory_empty'], dict)
         and set(rest['installation_inventory_empty']) == set(installs)
         and all(v is True for v in rest['installation_inventory_empty'].values()), f'{sid}:restitution')


def check_receipt_files(paths, required, harness_sha256=None):
    """Validate one or more receipts and require scenarios to have passed in some receipt."""
    decisions, problems, met = [], [], set()
    shared = None
    for path in paths:
        try:
            receipt = json.loads(Path(path).read_text(encoding='utf-8'))
        except (OSError, ValueError):
            problems.append(f'unreadable:{path}')
            continue
        decision = validate_receipt(receipt, harness_sha256=harness_sha256)
        decisions.append({'path': str(path), 'schema_valid': decision['schema_valid'],
                          'evidence_class': decision['evidence_class'], 'criteria_met': decision['criteria_met'],
                          'problems': decision['problems']})
        if not decision['schema_valid'] or decision['evidence_class'] != 'measured':
            problems.append(f'not_measured_or_invalid:{path}')
            continue
        identity = (receipt['candidate']['files'], receipt['environment']['image_id'], receipt['harness_sha256'],
                    receipt['environment']['docker_daemon_id'])
        if shared is None:
            shared = identity
        elif identity != shared:
            problems.append(f'different_photo:{path}')
            continue
        met.update(decision['criteria_met'])
    wanted = list(required) or list(SCENARIOS)
    missing = [sid for sid in wanted if sid not in met]
    ok = not problems and not missing
    return {'ok': ok, 'required': wanted, 'met': sorted(met), 'missing': missing, 'problems': problems,
            'receipts': decisions}


# ---------------------------------------------------------------------------------------------
# Offline: synthetic receipts (simulated, never accepted) and self-test


def prior_block():
    """Reference to the earlier receipt: by hash, never repeated here."""
    return {'path': PRIOR['path'], 'sha256': PRIOR['sha256'], 'covers': list(PRIOR['covers']),
            'repeated_here': False}


def fake(label, length):
    return hashlib.sha256(label.encode()).hexdigest()[:length]


def synthetic_scenario(sid, basis='simulated'):
    rec = Record(sid)
    d = rec.d
    shape = SHAPE[sid]
    installs = [fake(f'{sid}:installation:{i}', 32) for i in range(shape['installations'])]
    for installation in installs:
        d['installations'].append({'installation_id': installation, 'guard_uid': 0, 'client_uid': 65534,
                                   'lock_inode_stable': True if sid == 'second_guard_exclusion' else None})
    runs = []
    for i in range(shape['runs']):
        runs.append({'run_id': fake(f'{sid}:run:{i}', 32), 'variant': VARIANTS[i % 2],
                     'installation_id': installs[i if len(installs) > 1 else 0],
                     'name': 'escape-invoice-' + fake(f'{sid}:name:{i}', 32),
                     'container_id': fake(f'{sid}:container:{i}', 64),
                     'labels_basis': 'inspect+docker_events' if i < shape['running'] else 'docker_events'})
    d['runs'] = runs
    live = {'status': 'running', 'running': True}
    for run in runs[:shape['running']]:
        owner = d['installations'][0 if len(installs) == 1 else installs.index(run['installation_id'])]
        d['running'].append({
            'run_id': run['run_id'], 'container_id': run['container_id'],
            'observers': [{'role': 'guard_wrapper', 'pid': 4100, 'uid': 0}, {'role': 'fixture_parent', 'pid': 4000, 'uid': 0}],
            'status': 'running', 'running': True, 'state_pid': 5100, 'configured_user': '65534:65534',
            'host_uid_observed': None,
            'labels': {'request': run['name'], 'installation': run['installation_id'],
                       'guard_uid': str(owner['guard_uid']), 'run': run['run_id'], 'variant': run['variant']},
            'daemon_id': 'synthetic-daemon', 'daemon_root': '/var/lib/docker'})
        rec.state('running_before_fault', run['container_id'], live)
    first = runs[0]['container_id']
    t = 1000
    for name in TIMELINE[sid]:
        rec.mark(name, t)
        t += 1000
    if sid == 'kill_running':
        rec.state('after_fault', first, live)
        rec.state('before_recovery', first, live)
        rec.state('after_recovery', first, None)
        d['transitions'] += [{'installation_id': installs[0], 'phase': 'at_fault', 'durable_events': ['PENDING', 'ACK']},
                             {'installation_id': installs[0], 'phase': 'final', 'durable_events': ['PENDING', 'ACK', 'FINISH']}]
        d['processes'] = [{'role': 'guard_owner', 'pid': 4100, 'uid': 0, 'signal_sent': 'SIGKILL', 'returncode': -9,
                           'exit_signal': 'SIGKILL'}]
        for purpose, code, reason in (('wrong_identity_recovery', 2, 'guard_state_unavailable'), ('recovery', 0, None),
                                      ('repeat_recovery', 0, None)):
            d['cli_runs'].append({'purpose': purpose, 'kind': 'recover-only', 'installation_id': installs[0],
                                  'returncode': code, 'reason': reason})
        rec.control('wrong_identity_recovery_refused', 'negative', True, basis)
        for code in SPECIFIC_CLAIMS[sid]:
            rec.claim(code, True, basis)
    elif sid == 'cancel_client':
        rec.state('after_cancel', first, live)
        rec.state('final', first, None)
        rec.state('final', runs[1]['container_id'], None)
        d['transitions'].append({'installation_id': installs[0], 'phase': 'final',
                                 'durable_events': ['PENDING', 'ACK', 'FINISH'] * 2})
        d['processes'] = [
            {'role': 'client', 'pid': 4200, 'uid': 65534, 'signal_sent': 'SIGTERM', 'returncode': -15, 'exit_signal': 'SIGTERM'},
            {'role': 'client', 'pid': 4201, 'uid': 65534, 'signal_sent': None, 'returncode': 0, 'exit_signal': None},
            {'role': 'guard_server', 'pid': 4100, 'uid': 0, 'signal_sent': 'SIGTERM', 'returncode': 0, 'exit_signal': None}]
        rec.control('unauthorized_peer_rejected', 'negative', True, basis)
        rec.control('post_cancel_admission', 'positive', True, basis)
        for code in SPECIFIC_CLAIMS[sid]:
            rec.claim(code, True, basis)
    elif sid == 'second_guard_exclusion':
        rec.state('after_exclusion_attempts', first, live)
        rec.state('final', first, None)
        d['transitions'].append({'installation_id': installs[0], 'phase': 'final',
                                 'durable_events': ['PENDING', 'ACK', 'FINISH']})
        d['processes'] = [{'role': 'guard_owner', 'pid': 4100, 'uid': 0, 'signal_sent': None, 'returncode': 0,
                           'exit_signal': None}]
        for purpose, kind, code, reason in (('second_guard_serve', 'serve', 2, 'guard_state_unavailable'),
                                            ('second_guard_recover', 'recover-only', 2, 'guard_state_unavailable'),
                                            ('second_guard_initialize', 'initialize-state', 2, 'guard_recovery_required'),
                                            ('post_exit_recovery', 'recover-only', 0, None)):
            d['cli_runs'].append({'purpose': purpose, 'kind': kind, 'installation_id': installs[0],
                                  'returncode': code, 'reason': reason})
        rec.control('lock_released_after_exit', 'positive', True, basis)
        for code in SPECIFIC_CLAIMS[sid]:
            rec.claim(code, True, basis)
    else:
        rec.state('after_fault', first, live)
        rec.state('after_peer_recovery', runs[1]['container_id'], live)
        rec.state('after_recovery', first, None)
        rec.state('final', runs[1]['container_id'], None)
        d['transitions'] += [
            {'installation_id': installs[0], 'phase': 'at_fault', 'durable_events': ['PENDING', 'ACK']},
            {'installation_id': installs[0], 'phase': 'final', 'durable_events': ['PENDING', 'ACK', 'FINISH']},
            {'installation_id': installs[1], 'phase': 'final', 'durable_events': ['PENDING', 'ACK', 'FINISH']}]
        d['processes'] = [
            {'role': 'guard_owner', 'pid': 4100, 'uid': 0, 'signal_sent': 'SIGKILL', 'returncode': -9, 'exit_signal': 'SIGKILL'},
            {'role': 'guard_owner', 'pid': 4101, 'uid': 0, 'signal_sent': None, 'returncode': 0, 'exit_signal': None}]
        for purpose in ('recovery', 'repeat_recovery'):
            d['cli_runs'].append({'purpose': purpose, 'kind': 'recover-only', 'installation_id': installs[0],
                                  'returncode': 0, 'reason': None})
        rec.control('other_guard_did_not_touch_foreign', 'negative', True, basis)
        for code in SPECIFIC_CLAIMS[sid]:
            rec.claim(code, True, basis)
    d['docker_events'] = {
        'since': 1.0, 'until': 2.0,
        'lifecycle': {r['container_id']: ['create', 'attach', 'start', 'die', 'destroy'] for r in runs},
        'start_count': {r['container_id']: 1 for r in runs},
        'create_count': {i: sum(1 for r in runs if r['installation_id'] == i) for i in installs}}
    d['sentinel'] = {'container_id': fake(f'{sid}:sentinel', 64), 'name': 'sc3-gaps-sentinel-synthetic',
                     'before_sha256': fake(f'{sid}:fingerprint', 64), 'after_sha256': fake(f'{sid}:fingerprint', 64),
                     'status_before': 'created', 'status_after': 'created', 'lifecycle': ['create']}
    d['restitution'] = {'observed': True, 'absent_container_ids': [r['container_id'] for r in runs],
                        'installation_inventory_empty': {i: True for i in installs}}
    rec.control('observer_rejects_non_running', 'negative', True, basis)
    rec.control('observer_accepts_running', 'positive', True, basis)
    rec.control('events_instrument_sees_lifecycle', 'positive', True, basis)
    rec.control('events_instrument_ignores_other_labels', 'negative', True, basis)
    for code in COMMON_CLAIMS:
        rec.claim(code, True, basis)
    d['status'] = 'passed'
    return rec


def synthetic_receipt(selected=SCENARIOS):
    scenarios = [synthetic_scenario(sid).d if sid in selected else Record.omitted(sid, 'not_selected').d
                 for sid in SCENARIOS]
    return {
        'schema': SCHEMA, 'delivery_id': DELIVERY_ID, 'stage': STAGE, 'evidence_class': 'simulated',
        'mode': 'offline_synthetic', 'generated_unix': 1.0, 'harness_sha256': harness_hash() or '0' * 64,
        'candidate': {'files': dict(CANDIDATE), 'matches_base': True,
                      'base_manifest': {'gating_ok': True, 'base_intact': True}},
        'environment': {'image_id': 'sha256:' + '0' * 64, 'pull_policy': 'never', 'docker_daemon_id': 'synthetic-daemon',
                        'docker_root': '/var/lib/docker', 'fixture_uid': 0, 'fixture_gid': 0, 'client_uid': 65534,
                        'python': 'synthetic', 'platform': 'synthetic'},
        'prior_coverage': prior_block(),
        'unknowns': list(UNKNOWN_CODES), 'scenarios': scenarios,
        'cleanup': {'confirmed': True, 'items': [], 'scratch_removed': True, 'children_forced': 0},
        'limits': list(LIMITS),
    }


def select_scenarios(names):
    chosen = [sid for sid in SCENARIOS if not names or sid in names]
    if any(name not in SCENARIOS for name in names):
        raise ValueError('unknown scenario')
    return tuple(chosen)


def offline_selftest():
    checks = []

    def record(name, passed):
        checks.append({'check': name, 'passed': bool(passed)})

    record('selection_default_all', select_scenarios([]) == SCENARIOS)
    record('selection_single', select_scenarios(['cancel_client']) == ('cancel_client',))
    try:
        select_scenarios(['kill_all'])
        record('selection_rejects_unknown', False)
    except ValueError:
        record('selection_rejects_unknown', True)
    good = synthetic_receipt()
    decision = validate_receipt(good)
    record('synthetic_schema_valid', decision['schema_valid'] and not decision['problems'])
    record('simulated_never_accepted', decision['accepted'] is False and decision['evidence_class'] == 'simulated')
    partial = validate_receipt(synthetic_receipt(('kill_running',)))
    record('omitted_scenarios_stay_pending', partial['criteria_met'] == ['kill_running'] and len(partial['pending']) == 3)

    def mutated(change):
        receipt = copy.deepcopy(good)
        change(receipt)
        return validate_receipt(receipt)['problems']

    by_id = lambda receipt, sid: next(s for s in receipt['scenarios'] if s['id'] == sid)
    record('simulated_relabelled_as_measured_rejected',
           bool(mutated(lambda r: r.update(evidence_class='measured', mode='linux_docker'))))
    record('start_replay_rejected', bool(mutated(lambda r: by_id(r, 'kill_running')['docker_events']['start_count'].update(
        {by_id(r, 'kill_running')['runs'][0]['container_id']: 2}))))
    record('sentinel_change_rejected', bool(mutated(lambda r: by_id(r, 'kill_running')['sentinel'].update(after_sha256='1' * 64))))
    record('missing_restitution_rejected', bool(mutated(lambda r: by_id(r, 'cancel_client')['restitution'].update(observed=False))))
    record('candidate_drift_rejected', bool(mutated(lambda r: r['candidate']['files'].update(
        {'services/agent/daemon_guard.py': '2' * 64}))))
    record('unknown_code_rejected', bool(mutated(lambda r: by_id(r, 'kill_running').update(reason='made_up_code', status='failed'))))

    def no_ack(receipt):
        scenario = by_id(receipt, 'kill_running')
        scenario['transitions'][0]['durable_events'] = ['PENDING']
        scenario['transitions'][1]['durable_events'] = ['PENDING', 'FINISH']
    record('missing_ack_with_finish_rejected', any('no_ack_block_not_maintained' in p for p in mutated(no_ack)))
    error_receipt = copy.deepcopy(good)
    errored = by_id(error_receipt, 'cancel_client')
    errored['status'], errored['reason'] = 'error', 'handshake_timeout'
    errored['errors'] = [{'code': 'handshake_timeout', 'where': 'running_observed'}]
    verdict = validate_receipt(error_receipt)
    record('error_evidence_kept_but_not_met', verdict['schema_valid'] and 'cancel_client' not in verdict['criteria_met'])
    return {'schema': 'sc3-lifecycle-gaps-selftest/v1', 'checks': checks, 'passed': all(c['passed'] for c in checks)}


# ---------------------------------------------------------------------------------------------
# CLI


def reject(code, detail=''):
    print(json.dumps({'status': 'rejected', 'reason': code, 'detail': detail}, sort_keys=True), file=sys.stderr)
    return 2


def environment_of(args, identity):
    return {'image_id': args.image_id, 'pull_policy': 'never', 'docker_daemon_id': identity[0],
            'docker_root': identity[1], 'fixture_uid': os.geteuid(), 'fixture_gid': os.getegid(),
            'client_uid': args.client_uid, 'python': sys.version.split()[0], 'platform': sys.platform}


def run_linux(args, selected):
    if sys.platform != 'linux' or not hasattr(os, 'geteuid'):
        return reject('linux_required')
    if not IMAGE_ID.fullmatch(args.image_id or ''):
        return reject('invalid_image_id')
    if not args.receipt:
        return reject('receipt_required')
    receipt_path = Path(args.receipt)
    if receipt_path.exists() or not receipt_path.parent.is_dir():
        return reject('receipt_path_unusable', 'must be a new file in an existing directory')
    if not 0 <= args.client_uid < 2 ** 32 - 1 or args.client_uid == os.geteuid():
        return reject('invalid_client_uid')
    try:
        g, gs = guard_module(), state_module()
    except ImportError as exc:
        return reject('interface_import_failed', type(exc).__name__)
    try:
        identity = g.docker_identity()
        found = top_cmd('image', 'inspect', '--format', '{{json .Id}}', args.image_id)
        if found.returncode != 0 or json.loads(found.stdout) != args.image_id:
            return reject('image_missing', 'the image must already exist locally; nothing is pulled')
    except (HarnessError, g.GuardError, ValueError) as exc:
        return reject('docker_unavailable', type(exc).__name__)
    actual = candidate_hashes()
    base = verify_base()
    gate = None
    if actual != CANDIDATE or not base['gating_ok'] or not base['base_intact']:
        gate = 'candidate_drift'
    elif interface_check(g, gs):
        gate = 'interface_drift'
    matches = gate is None
    root = Path(tempfile.mkdtemp(prefix='sc3-gaps-', dir=args.scratch_parent))
    root.chmod(0o755)
    records, cleanup_items, confirmed, forced = [], [], True, 0
    for sid in SCENARIOS:
        if sid not in selected:
            records.append(Record.omitted(sid, 'not_selected'))
            continue
        if gate is not None:
            records.append(Record.omitted(sid, gate))
            continue
        if sid == 'cancel_client' and os.geteuid() != 0:
            records.append(Record.omitted(sid, 'requires_root_for_client_uid'))
            continue
        scratch = root / sid
        scratch.mkdir(mode=0o755)
        scratch.chmod(0o755)
        fixture = Fixture(args.image_id, args.client_uid, scratch, g, identity)
        rec = Record(sid)
        rec.claim('candidate_hashes_match_base', True)
        rec.claim('image_by_id_no_pull', True)
        try:
            SCENARIO_FUNCTIONS[sid](fixture, rec)
            rec.d['status'], rec.d['reason'] = 'passed', None
        except HarnessError as exc:
            rec.fail(exc)
        except Exception as exc:  # unexpected harness fault: keep the evidence, classify as internal
            rec.fail(HarnessError('internal_error', type(exc).__name__))
        finally:
            fixture.collect(rec)
            outcome = fixture.cleanup()
            cleanup_items += outcome['items']
            confirmed = confirmed and outcome['confirmed']
            forced += outcome['children_forced']
        if not outcome['confirmed'] and rec.d['status'] == 'passed':
            rec.fail(HarnessError('cleanup_failed', 'unconfirmed'))
        records.append(rec)
    removed = False
    if confirmed:
        shutil.rmtree(root, ignore_errors=True)
        removed = not root.exists()
    else:
        print(f'cleanup unconfirmed; scratch kept at {root}', file=sys.stderr)
    receipt = {
        'schema': SCHEMA, 'delivery_id': DELIVERY_ID, 'stage': STAGE, 'evidence_class': 'measured',
        'mode': 'linux_docker', 'generated_unix': time.time(), 'harness_sha256': harness_hash(),
        'candidate': {'files': actual, 'matches_base': matches,
                      'base_manifest': {'gating_ok': base['gating_ok'], 'base_intact': base['base_intact']}},
        'environment': environment_of(args, identity), 'prior_coverage': prior_block(),
        'unknowns': list(UNKNOWN_CODES), 'scenarios': [r.d for r in records],
        'cleanup': {'confirmed': confirmed, 'items': cleanup_items, 'scratch_removed': removed,
                    'children_forced': forced},
        'limits': list(LIMITS),
    }
    raw = json.dumps(receipt, indent=2, sort_keys=True) + '\n'
    with open(receipt_path, 'x', encoding='utf-8') as handle:
        handle.write(raw)
    decision = validate_receipt(receipt, harness_sha256=harness_hash())
    chosen = [r.d for r in records if r.d['id'] in selected]
    print(json.dumps({'receipt': str(receipt_path), 'receipt_sha256': sha256_bytes(raw.encode()),
                      'statuses': {r.d['id']: r.d['status'] for r in records}, 'cleanup_confirmed': confirmed,
                      'schema_valid': decision['schema_valid'], 'problems': decision['problems']}, sort_keys=True))
    if not confirmed:
        return 3
    met = decision['schema_valid'] and all(item['status'] == 'passed' for item in chosen)
    return 0 if met else 1


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--verify-base', action='store_true')
    parser.add_argument('--check-receipt', action='append', default=[], metavar='PATH')
    parser.add_argument('--require', action='append', default=[], choices=SCENARIOS)
    parser.add_argument('--image-id')
    parser.add_argument('--receipt')
    parser.add_argument('--scenario', action='append', default=[], choices=SCENARIOS)
    parser.add_argument('--client-uid', type=int, default=65534)
    parser.add_argument('--scratch-parent', default='/run')
    parser.add_argument('--internal-owner', help=argparse.SUPPRESS)
    parser.add_argument('--internal-serve', help=argparse.SUPPRESS)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.internal_owner:
        return run_owner(json.loads(args.internal_owner))
    if args.internal_serve:
        return run_serve(json.loads(args.internal_serve))
    if args.check_receipt:
        decision = check_receipt_files(args.check_receipt, args.require, harness_sha256=harness_hash())
        print(json.dumps(decision, indent=2, sort_keys=True))
        return 0 if decision['ok'] else 2
    if args.verify_base:
        base = verify_base()
        try:
            problems = interface_check(guard_module(), state_module())
        except Exception as exc:  # an import problem is interface drift: reported, not raised
            problems = ['import_' + type(exc).__name__]
        print(json.dumps({'base': base, 'interface_problems': problems}, indent=2, sort_keys=True))
        return 0 if base['gating_ok'] and base['base_intact'] and not problems else 2
    if args.list:
        commands = {sid: f'python -B -S tests/integration/sc3_lifecycle_gaps.py --image-id sha256:DIGEST '
                         f'--receipt PATH_NEW.json --scenario {sid}' for sid in SCENARIOS}
        print(json.dumps({'delivery_id': DELIVERY_ID, 'scenarios': [
            {'id': sid, 'summary': SCENARIO_INFO[sid][0], 'needs_root': SCENARIO_INFO[sid][1], 'command': commands[sid],
             'check': f'python -B -S tests/integration/sc3_lifecycle_gaps.py --check-receipt PATH_NEW.json --require {sid}'}
            for sid in SCENARIOS], 'unknowns': list(UNKNOWN_CODES)}, indent=2))
        return 0
    if args.offline:
        if args.image_id or args.receipt:
            return reject('offline_excludes_docker_options')
        report = offline_selftest()
        report['selected'] = list(select_scenarios(args.scenario))
        report['base'] = {k: v for k, v in verify_base().items() if k != 'rows'}
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report['passed'] else 1
    if args.image_id:
        return run_linux(args, select_scenarios(args.scenario))
    parser.error('choose --offline, --list, --verify-base, --check-receipt or --image-id')


if __name__ == '__main__':
    raise SystemExit(main())

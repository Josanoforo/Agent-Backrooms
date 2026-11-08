"""A4 root-operated Linux/Docker operator for the invoice actor compatibility scenarios (opt-in).

Offline (no Docker, no root, any host with Python):   python sc2_actor_compatibility_local.py --offline --receipt-dir NEW_DIR
Linux/Docker (root, local image by ID, no pull/network): python sc2_actor_compatibility_local.py --image-id sha256:... --receipt-dir NEW_DIR
Every receipt carries a closed `code`; a failed criterion keeps its receipt and the fixture directory. This file is authored, not executed,
by its author: a receipt only exists once an operator runs it.

A4b (two extra cuts, same receipt schema, explicit scenario names; the five approved A4 scenarios are NOT part of it):
    python sc2_actor_compatibility_local.py --image-id sha256:... --scenario a4b --receipt-dir NEW_DIR
    (or one of: --scenario controller-kill-running | --scenario cancel-api-verifier-running)
`--scenario all` keeps meaning the five approved A4 scenarios, exactly as before.
"""

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import uuid

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO))

HARNESS = 'tests/integration/sc2_actor_compatibility_local.py'
TEST = 'tests/integration/test_sc2_actor_compatibility.py'
BASE_FIXTURE = 'tests/integration/invoice_actor_service_local.py'
BASE_FIXTURE_TEST = 'tests/integration/test_invoice_actor_service_docker.py'
BOUNDARY = 'tests/integration/guard_boundary_local.py'
INHERITANCE = 'docs/evidencia/sc3-lifecycle/a4b-herencia-a2.json'
CODES = ('ok', 'product_counterexample', 'harness_error', 'precondition_missing')
SCENARIOS = ('cancel-api', 'owner-cut-provider-wait', 'owner-cut-before-close', 'lost-response-after-finish',
             'second-run-exclusion')
# A4b: two additional cuts of the same schema. They never repeat the five approved scenarios above.
A4B_SCENARIOS = ('controller-kill-running', 'cancel-api-verifier-running')
A4B_DELIVERY = {'delivery_id': 'SC2-controller-boundary-v1', 'stage': 'A4b'}
BASE_MANIFEST = 'development/claude/bases/sc3-service-cuts-a4b-r2.json'
A4B_CONTRACTS = ('docs/operacion/A4B-CORTES-SERVICIO.md', 'docs/operacion/A4-RECEPCION-SC3.md', BASE_MANIFEST)
# A2 harness reused as a dependency (Channel and build_guard_class), never modified. Hashes are those of the A4b base manifest.
GAPS = 'tests/integration/sc3_lifecycle_gaps.py'
GAPS_SHA256 = '3263261daa196ce4a02d977ec7027fbbdea6c33d1ee0a75e41b80c01ce6d3675'
A2_PINNED_SERVICES = {
    'services/agent/daemon_guard.py': '264356683f94c1baaa97c5bf72da5bb798c4463f1f64bf6a2b824b00e4420316',
    'services/agent/guard_state.py': '24ea3f3ff57981dcb3a46bc0913ddf152a008447837ca16fbb55c22973d31118',
    'services/agent/guard_client.py': '11317febde1f0bf60d4e1508f21151049ddbe42a142c1d35b7443adc39eb3da0',
}
GUARD_INSTALLATION_LABEL = 'org.agent-escape-room.invoice-installation'
GUARD_RUN_LABEL = 'org.agent-escape-room.invoice-run'
GUARD_VARIANT_LABEL = 'org.agent-escape-room.invoice-variant'
TERMINAL = ('completed', 'failed', 'cancelled')
HEX64 = re.compile(r'[0-9a-f]{64}')
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}')
WAIT = 45.0  # every wait in this file is bounded by an explicit deadline; none is an arbitrary sleep

from guard_boundary_local import DOCKER, ENV, PYTHON, privileged_wrapper, run  # noqa: E402
from invoice_actor_service_local import exercise, wait_socket  # noqa: E402

KINDS = ['CREATE_PENDING', 'CREATE_ACK', 'START_PENDING', 'ACTIVE', 'CLOSE_PENDING', 'FINISH']
SENTINEL_LABEL = 'org.agent-escape-room.a4-sentinel'
INSTALLATION_LABEL = 'org.agent-escape-room.actor-installation'
CONTROLLER_UID, ACTOR_UID, GUARD_UID, FOREIGN_UID = 65534, 1000, 65532, 65533


class Stop(Exception):
    """A step the rest of the scenario depends on failed; the receipt keeps the criterion and the evidence so far."""


class Precondition(Stop):
    """A declared dependency differs from the base this scenario was written against: not a product finding."""


class Finished:
    """Stand-in for an owner process that was already reaped, so exercise() can still finish its own cleanup."""

    def __init__(self, pid, observed_returncode):
        # exercise() demands code 0 from whatever is current when it ends; the real code was recorded in the receipt already.
        self.pid, self.returncode, self.observed_returncode = pid, 0, observed_returncode

    def poll(self):
        return 0

    def communicate(self, timeout=None):
        return b'', b''

    def terminate(self):
        pass


class Criteria:
    def __init__(self):
        self.items = []

    def check(self, name, condition, detail=None, *, critical=False):
        self.items.append({'id': name, 'ok': bool(condition), 'detail': detail})
        if critical and not condition:
            raise Stop(name)
        return bool(condition)

    @property
    def ok(self):
        return all(item['ok'] for item in self.items)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def wait_for(predicate, timeout, what):
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() > deadline:
            raise Stop('timeout: ' + what)
        time.sleep(0.02)


def docker(*args, check=True, timeout=30):
    result = run(DOCKER + tuple(args), REPO, timeout=timeout)
    if check and result.returncode:
        raise Stop('docker ' + ' '.join(args[:2]) + ': ' + result.stderr.decode(errors='replace')[:300])
    return result


def container_state(container_id):
    """(exists, running, status) read from Docker by exact ID; absence is `No such container`, nothing else counts."""
    result = docker('container', 'inspect', '--format', '{{.Id}} {{.State.Running}} {{.State.Status}}', container_id, check=False)
    if result.returncode:
        return (False, None, 'absent' if b'No such container' in result.stderr else 'unknown')
    ident, running, status = result.stdout.decode().split()
    return (ident == container_id, running == 'true', status)


def installation_ids(installation):
    out = docker('container', 'ls', '--all', '--no-trunc', '--quiet', '--filter', f'label={INSTALLATION_LABEL}={installation}')
    return sorted(out.stdout.decode().split())


def all_container_ids():
    return sorted(docker('container', 'ls', '--all', '--no-trunc', '--quiet').stdout.decode().split())


def actions(container_id, since, until):
    out = docker('events', '--since', str(since), '--until', str(until), '--filter', 'type=container', '--filter',
                 f'container={container_id}', '--format', '{{json .}}', timeout=40)
    return [json.loads(line)['Action'] for line in out.stdout.decode().splitlines() if line]


def install_creates(installation, since, until):
    out = docker('events', '--since', str(since), '--until', str(until), '--filter', 'type=container', '--filter', 'event=create',
                 '--filter', f'label={INSTALLATION_LABEL}={installation}', '--format', '{{json .}}', timeout=40)
    return [json.loads(line)['Actor']['ID'] for line in out.stdout.decode().splitlines() if line]


class LiveCreates:
    """Keep the installation's create stream before a long TTL wait can evict Docker's replay buffer."""
    def __init__(self, installation, directory, since):
        self.installation = installation
        self.path = directory / 'actor-create-events.jsonl'
        self.output = self.path.open('xb', buffering=0)
        self.error = (directory / 'actor-create-events.stderr').open('xb', buffering=0)
        self.process = subprocess.Popen(DOCKER + ('events', '--since', str(since), '--filter', 'type=container',
            '--filter', 'event=create', '--filter', f'label={INSTALLATION_LABEL}={installation}', '--format', '{{json .}}'),
            stdout=self.output, stderr=self.error, env=ENV)

    def events(self):
        # A partial final line is still in transit; it is never accepted as an event.
        return [json.loads(line) for line in self.path.read_bytes().splitlines(keepends=True) if line.endswith(b'\n')]

    def ids(self):
        return [event['Actor']['ID'] for event in self.events()]

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.wait(timeout=10)
        self.output.close()
        self.error.close()


def ledger(journal):
    with sqlite3.connect((Path(journal) / 'state.sqlite3').as_uri() + '?mode=ro', uri=True) as db:
        return [(kind, json.loads(payload)) for kind, payload in db.execute('SELECT kind,payload FROM events ORDER BY sequence')]


def kinds(journal):
    return [kind for kind, _ in ledger(journal)]


def proc_observation(pid):
    status = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
    return {'pid': pid, 'uids': [int(v) for v in status['Uid'].split()], 'gids': [int(v) for v in status['Gid'].split()],
            'groups': [int(v) for v in status['Groups'].split()], 'cap_eff': status['CapEff'].strip(),
            'cap_bnd': status['CapBnd'].strip(), 'no_new_privileges': int(status['NoNewPrivs'])}


def option(command, name):
    return command[command.index(name) + 1]


def poll(predicate, timeout):
    """Value of `predicate` once truthy, or None at the deadline: a bounded observation of a condition, never a fixed sleep."""
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() > deadline:
            return None
        time.sleep(0.05)


def installation_of(journal):
    with contextlib.closing(sqlite3.connect((Path(journal) / 'state.sqlite3').as_uri() + '?mode=ro', uri=True)) as db:
        return db.execute('SELECT installation_id FROM installation').fetchone()[0]


def guard_installation_ids(installation):
    out = docker('container', 'ls', '--all', '--no-trunc', '--quiet', '--filter', f'label={GUARD_INSTALLATION_LABEL}={installation}')
    return sorted(out.stdout.decode().split())


def verifier_labels(container_id):
    """Run and variant labels of a verifier container, read from Docker by exact ID (None when it cannot be inspected)."""
    template = '{{index .Config.Labels "%s"}} {{index .Config.Labels "%s"}}' % (GUARD_RUN_LABEL, GUARD_VARIANT_LABEL)
    result = docker('container', 'inspect', '--format', template, container_id, check=False)
    if result.returncode:
        return None
    run_id, variant = result.stdout.decode().split()
    return {'run': run_id, 'variant': variant}


def kill_controller(controller, node):
    """SIGKILL only the controller child this fixture spawned. UID, PID, parent and command are observed BEFORE the signal."""
    process, pid = controller.process, controller.process.pid
    if process.poll() is not None:
        raise Stop('refusing to signal: the controller already ended')
    before = proc_observation(pid)
    status = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
    argv = [part.decode(errors='replace') for part in Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0') if part]
    target = {'pid': pid, 'ppid': int(status['PPid']), 'harness_pid': os.getpid(), 'uids': before['uids'], 'gids': before['gids'],
              'groups': before['groups'], 'no_new_privileges': before['no_new_privileges'], 'argv_tail': argv[-3:]}
    mine = (before['uids'][:2] == [CONTROLLER_UID] * 2 and before['gids'][:2] == [CONTROLLER_UID] * 2
            and target['ppid'] == os.getpid() and 'pytest' in argv and any(item.endswith('::' + node) for item in argv))
    if not mine:
        raise Stop('refusing to signal: the target is not the controller child of this fixture')
    cut_at = time.time()
    os.kill(pid, signal.SIGKILL)
    process.wait(timeout=20)
    return {'signal': 'SIGKILL', 'target': target, 'returncode': process.returncode, 'cut_at': cut_at}


# --------------------------------------------------------------------------------------------------- foreign sentinel
def create_sentinel(image):
    token = uuid.uuid4().hex
    out = docker('create', '--pull=never', '--network', 'none', '--name', 'a4-sentinel-' + token, '--label',
                 f'{SENTINEL_LABEL}={token}', '--entrypoint', 'sh', image, '-c', 'sleep 1000')
    ident = out.stdout.decode().strip()
    return {'id': ident, 'token': token, 'state': container_state(ident)}


def sentinel_preserved(sentinel):
    return container_state(sentinel['id']) == (True, False, 'created')


def remove_sentinel(sentinel):
    labels = docker('container', 'inspect', '--format', '{{index .Config.Labels "%s"}}' % SENTINEL_LABEL, sentinel['id'],
                    check=False)
    if labels.returncode == 0 and labels.stdout.decode().strip() == sentinel['token']:   # only what this run created
        docker('container', 'rm', sentinel['id'])


# ------------------------------------------------------------------------------------------------- handshakes and owners
def new_control(ctx, name):
    path = ctx['scratch'] / ('a4-control-' + name)
    path.mkdir(mode=0o700)
    os.chown(path, CONTROLLER_UID, CONTROLLER_UID)
    return path


def acknowledge(control, name):
    marker = control / (name + '.ack')
    marker.write_text('ok')
    os.chown(marker, CONTROLLER_UID, CONTROLLER_UID)


class Controller:
    """The pytest process under the controller UID. Output goes to root-owned files, so no pipe can fill and block it."""

    def __init__(self, ctx, scenario, phase, node, control, log_dir):
        self.ctx, self.phase, self.control = ctx, phase, control
        self.stdout_path, self.stderr_path = log_dir / f'{phase}.stdout', log_dir / f'{phase}.stderr'
        env = {**ctx['environment'], 'ESCAPE_A4_SCENARIO': scenario, 'ESCAPE_A4_PHASE': phase,
               'ESCAPE_A4_CONTROL': str(control), 'ESCAPE_A4_DB': str(ctx['scratch'] / 'runs.sqlite')}
        command = ctx['controller_prefix'] + (ctx['service_python'], '-B', '-m', 'pytest', '-q', '-s', '--disable-warnings',
                                               '-p', 'no:cacheprovider', f'{TEST}::{node}')
        with open(self.stdout_path, 'wb') as out, open(self.stderr_path, 'wb') as err:
            self.process = subprocess.Popen(command, cwd=ctx['root'], env=env, stdout=out, stderr=err)

    def serve(self, handlers, timeout=150):
        """Run (name, callback) pairs in order: wait for the controller's checkpoint, observe/cut, then acknowledge."""
        for name, callback in handlers:
            marker = self.control / (name + '.json')
            wait_for(lambda: marker.exists() or self.process.poll() is not None, WAIT + 20, 'checkpoint ' + name)
            if not marker.exists():
                raise Stop(f'controller ended before checkpoint {name} (rc={self.process.returncode})')
            callback(json.loads(marker.read_text()))
            acknowledge(self.control, name)
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise Stop('controller did not finish within its bound') from None
        return self.process.returncode

    def abort(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()

    def proofs(self):
        text = self.stdout_path.read_text(errors='replace')
        return [json.loads(line[len('A4_PROOF='):]) for line in text.splitlines() if line.startswith('A4_PROOF=')]

    def tail(self):
        return {'stdout': self.stdout_path.read_text(errors='replace')[-3000:],
                'stderr': self.stderr_path.read_text(errors='replace')[-1500:]}


def socket_identity(path):
    info = Path(path).lstat()
    return {'is_socket': stat.S_ISSOCK(info.st_mode), 'uid': info.st_uid, 'dev': info.st_dev, 'ino': info.st_ino}


def start_owner(ctx):
    path = ctx['paths']['actor'][0]
    process = subprocess.Popen(ctx['actor_command'] + ('--socket', str(path)), cwd=ctx['root'], env=ENV,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    ctx['processes'][0] = process
    wait_socket(process, path)
    return {'pid': process.pid, 'proc': proc_observation(process.pid), 'socket': socket_identity(path)}


def kill_owner(ctx):
    """SIGKILL only the actor owner child. Returns what was observed about it and about the processes left alone."""
    owner, guard = ctx['processes'][0], ctx['processes'][1]
    before = proc_observation(owner.pid)
    if before['uids'][:2] != [ACTOR_UID, ACTOR_UID] or guard.poll() is not None:
        raise Stop('refusing to signal: the target is not the actor owner child or the guard is gone')
    cut_at = time.time()
    os.kill(owner.pid, signal.SIGKILL)
    owner.wait(timeout=20)
    ctx['processes'][0] = Finished(owner.pid, owner.returncode)     # exercise() stops what is current; this one is reaped
    return {'signal': 'SIGKILL', 'target': before, 'returncode': owner.returncode, 'cut_at': cut_at,
            'guard_alive_after': guard.poll() is None, 'guard_pid': guard.pid}


def stop_owner_cleanly(ctx):
    owner = ctx['processes'][0]
    owner.send_signal(signal.SIGTERM)
    _, errors = owner.communicate(timeout=60)
    ctx['processes'][0] = Finished(owner.pid, owner.returncode)
    if owner.returncode != 0:
        raise Stop('owner did not stop cleanly: ' + errors.decode(errors='replace')[:200])
    return {'signal': 'SIGTERM', 'returncode': 0, 'pid': owner.pid}


def retire_stale_socket(path, recorded):
    """Remove only the socket this owner bound: same inode, same UID, still a socket, and only after reconciliation."""
    now = socket_identity(path)
    if not (now['is_socket'] and now['uid'] == ACTOR_UID and (now['dev'], now['ino']) == (recorded['dev'], recorded['ino'])):
        raise Stop('socket residue is not the one this owner bound; left in place')
    Path(path).unlink()
    return {'retired': True, **now}


def recover_only(ctx):
    result = run(ctx['actor_command'] + ('--recover-only',), ctx['root'], timeout=120)
    return {'returncode': result.returncode, 'stderr': result.stderr.decode(errors='replace')[:200]}

RAW_QUERY = '''
import errno, json, socket, sys
frame = bytes.fromhex(sys.argv[2])
result = {}
with socket.socket(socket.AF_UNIX) as peer:
    peer.settimeout(5)
    try:
        peer.connect(sys.argv[1])
    except OSError as exc:
        result['connect'] = errno.errorcode[exc.errno]
    else:
        peer.sendall(frame)
        peer.shutdown(socket.SHUT_WR)
        result.update(connect='ok', answered=bool(peer.recv(2048)))
print(json.dumps(result))
'''


# ----------------------------------------------------------------------------------- A4b: instrumented guard (A2 reuse)
# Runs inside the guard-owner child, under the guard UID/GID/groups of the fixture. Source of the instrumentation: Channel and
# build_guard_class of tests/integration/sc3_lifecycle_gaps.py (copied exactly into the fixture; hash pinned above). The real
# services.agent.daemon_guard.main() is called unchanged; only InvoiceGuard is replaced by the A2 subclass, whose command hook
# withholds the artifact (stdin) of the FIRST `docker start -a -i` until one release byte arrives on the release pipe. Every other
# docker command and every journal transition passes through; transitions are reported on the event pipe.
WRAPPER_SOURCE = r'''
import json, sys
cfg = json.loads(sys.argv[1])
sys.path.insert(0, cfg['root'])
sys.path.insert(0, cfg['root'] + '/tests/integration')
import sc3_lifecycle_gaps as gaps
from services.agent import daemon_guard as g
channel = gaps.Channel(cfg['event_fd'], cfg['release_fd'])
identity = g.docker_identity()
g.InvoiceGuard = gaps.build_guard_class(g, channel, cfg['hold'], identity)
channel.emit('serve_wrapper_ready', status='ready', gaps_sha256=cfg['gaps_sha256'])
code = g.main(cfg['argv'])
channel.emit('serve_exited', status=str(code))
sys.exit(code)
'''


class GuardWrapper:
    """Parent side of the instrumented guard: the process, its event pipe (child -> operator) and its release pipe (operator -> child)."""

    def __init__(self, ctx):
        command = tuple(ctx['guard_command'])
        marker = command.index('-m')
        if command[marker - 3:marker + 2] != (PYTHON, '-B', '-S', '-m', 'services.agent.daemon_guard'):
            raise Precondition('guard command has an unexpected shape')
        self.prefix, argv = command[:marker - 3], list(command[marker + 2:])   # prefix: the same setpriv UID/GID/groups as the clean guard
        self.socket_path = ctx['paths']['guard'][0]
        self.events, self.buffer, self.eof, self.released = [], b'', False, False
        events_read, events_write = os.pipe()
        release_read, release_write = os.pipe()
        self.config = {'root': str(ctx['root']), 'event_fd': events_write, 'release_fd': release_read, 'hold': True,
                       'argv': [*argv, '--socket', str(self.socket_path)], 'gaps_sha256': sha256(ctx['root'] / GAPS)}
        try:
            self.process = subprocess.Popen(self.prefix + (PYTHON, '-B', '-S', '-c', WRAPPER_SOURCE, json.dumps(self.config)),
                                            cwd=ctx['root'], env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                            pass_fds=(events_write, release_read))
        except BaseException:
            os.close(events_read)
            os.close(release_write)
            raise
        finally:
            os.close(events_write)
            os.close(release_read)
        # The parent keeps both pipe ends open for the whole fixture life: a closed event pipe would break the guard's final emit.
        self.event_fd, self.release_fd = events_read, release_write

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
            event = json.loads(line)
            event['seen_ns'] = time.monotonic_ns()      # operator clock: when this event was read, not when it was written
            self.events.append(event)
        return True

    def wait_for(self, kind, *, after=0, timeout=WAIT, **match):
        """Block (bounded) until the child reports an event of `kind` whose fields include `match`; returns (index, event)."""
        deadline = time.monotonic() + timeout
        while True:
            for index in range(after, len(self.events)):
                event = self.events[index]
                if event['kind'] == kind and all(event.get(key) == value for key, value in match.items()):
                    return index, event
            for event in self.events:
                if event['kind'] in ('verifier_not_running', 'release_missing', 'verify_error', 'state_error'):
                    raise Stop('guard wrapper reported ' + event['kind'])
            if self.eof:
                raise Stop(f'guard wrapper ended (rc={self.process.poll()}) before reporting {kind}')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Stop('timeout: guard wrapper event ' + kind)
            self.pump(min(remaining, 0.5))

    def release(self):
        """Let the withheld artifact reach the verifier. Idempotent; a child that already ended is not an error here."""
        if not self.released:
            self.released = True
            with contextlib.suppress(OSError):
                os.write(self.release_fd, b'1')

    def stderr_if_ended(self):
        return self.process.stderr.read().decode(errors='replace')[-800:] if self.process.poll() is not None else None


def install_guard_wrapper(scenario):
    """Replace ONLY the fixture's clean guard child by the instrumented wrapper: same UID/GID/groups, same journal (reopened, never
    re-initialised), same socket path (retired by the clean stop). The operator signals no process except that guard child."""
    ctx, criteria = scenario.ctx, scenario.criteria
    copied = ctx['root'] / GAPS
    shutil.copyfile(REPO / GAPS, copied)
    copied.chmod(0o644)
    fixture_services = {name: sha256(ctx['root'] / name) for name in A2_PINNED_SERVICES}
    matches = sha256(copied) == GAPS_SHA256 == sha256(REPO / GAPS) and fixture_services == A2_PINNED_SERVICES
    if not criteria.check('instrument:dependency_hashes_match_the_a4b_base', matches,
                          {'gaps_copy': sha256(copied), 'gaps_expected': GAPS_SHA256, 'services': fixture_services}):
        raise Precondition('instrument:dependency_hashes_match_the_a4b_base')
    old, path = ctx['processes'][1], ctx['paths']['guard'][0]
    before = {'proc': proc_observation(old.pid), 'socket': socket_identity(path), 'journal': kinds(scenario.guard_journal)}
    criteria.check('instrument:guard_journal_empty_before_replacement', before['journal'] == [], before['journal'], critical=True)
    old.send_signal(signal.SIGTERM)       # the clean guard child of this fixture; nothing else is signalled
    _, errors = old.communicate(timeout=60)
    ctx['processes'][1] = Finished(old.pid, old.returncode)
    stopped = {'signal': 'SIGTERM', 'returncode': old.returncode, 'socket_absent_after_stop': not os.path.lexists(path),
               'stderr': errors.decode(errors='replace')[:200]}
    criteria.check('instrument:clean_guard_stopped_and_retired_its_own_socket', old.returncode == 0 and stopped['socket_absent_after_stop'],
                   stopped, critical=True)
    criteria.check('instrument:journal_untouched_by_the_clean_stop', kinds(scenario.guard_journal) == [], kinds(scenario.guard_journal))
    wrapper = GuardWrapper(ctx)
    ctx['processes'][1] = wrapper.process
    try:
        wait_socket(wrapper.process, path)
    except RuntimeError as exc:
        scenario.evidence['guard_wrapper_stderr'] = wrapper.stderr_if_ended()
        raise Stop('instrumented guard did not bind its socket: ' + str(exc)) from None
    _, ready = wrapper.wait_for('serve_wrapper_ready')
    observed = proc_observation(wrapper.process.pid)
    criteria.check('instrument:wrapper_runs_under_the_guard_uid_and_reopened_the_same_journal',
                   observed['uids'][:2] == [GUARD_UID] * 2 and ready['uid'] == GUARD_UID and kinds(scenario.guard_journal) == [],
                   {'proc': observed, 'ready': ready}, critical=True)
    scenario.evidence['guard_replacement'] = {'replaced': before, 'clean_stop': stopped, 'wrapper': observed,
                                              'socket': socket_identity(path), 'wrapper_ready_event': ready}
    scenario.evidence['instrumentation'] = {
        'source': GAPS, 'sha256': GAPS_SHA256, 'reused_symbols': ['Channel', 'build_guard_class'], 'modified': False,
        'real_cli': 'services.agent.daemon_guard.main(argv) is called unchanged; only module attribute InvoiceGuard is replaced',
        'hook': 'command hook of the A2 subclass: stdin (artifact) of the first `docker start -a -i` is withheld until one release byte; '
                'all other docker commands and the journal pass through',
        'hold_first_start': True, 'wrapper_source': 'WRAPPER_SOURCE in ' + HARNESS,
        'wrapper_source_sha256': hashlib.sha256(WRAPPER_SOURCE.encode()).hexdigest(),
        'fds_in_child': {'event_pipe_write': wrapper.config['event_fd'], 'release_pipe_read': wrapper.config['release_fd'],
                         'inherited_through': 'subprocess pass_fds across setpriv exec'},
        'uid_gid_groups': {'uids': observed['uids'], 'gids': observed['gids'], 'groups': observed['groups']},
        'argv': wrapper.config['argv'], 'daemon_guard_pinned': fixture_services}
    return wrapper


class Scenario:
    def __init__(self, name, ctx):
        self.name, self.ctx, self.criteria, self.evidence = name, ctx, Criteria(), {'controller': {}}
        self.installation = option(ctx['actor_command'], '--installation-id')
        self.actor_journal, self.guard_journal = ctx['paths']['actor'][1], ctx['paths']['guard'][1]
        self.logs = ctx['root'] / 'a4-logs'
        self.began = time.time()
        self.failure = None          # 'product_counterexample' | 'harness_error' | 'precondition_missing'
        self.sentinel = None
        self.controller = None       # the controller phase being served (A4b: the only process the operator may SIGKILL)
        self.wrapper = None          # A4b: the instrumented guard, when a scenario installs it
        self.creates = None          # A4b controller cut: bounded replay is insufficient across a live-owner TTL

    # -- observations -------------------------------------------------------------------------------------------------
    def window(self):
        return int(self.began) - 1, int(time.time()) + 2

    def observe_active(self, payload, label):
        identity = payload['identity']
        last = ledger(self.actor_journal)[-1]
        state = container_state(identity['container_id'])
        self.criteria.check(f'{label}:durable_ACTIVE_observed', last[0] == 'ACTIVE' and last[1]['intent_id'] == identity['intent_id'],
                            kinds(self.actor_journal), critical=True)
        self.criteria.check(f'{label}:docker_Running_true_observed', state == (True, True, 'running'), state, critical=True)
        self.evidence.setdefault('observed_active', {})[label] = {'identity': identity, 'docker': list(state),
                                                                   'ledger': kinds(self.actor_journal)}

    def settled(self, label, *, intents, container_ids):
        """Own IDs absent, diary complete for `intents` intents, installation empty and the foreign sentinel untouched."""
        sequence = kinds(self.actor_journal)
        self.criteria.check(f'{label}:ledger_complete_{intents}_intents', sequence == KINDS * intents, sequence)
        gone = {cid: container_state(cid) for cid in container_ids}
        self.criteria.check(f'{label}:own_ids_absent', all(state[0] is False and state[2] == 'absent' for state in gone.values()), gone)
        self.criteria.check(f'{label}:installation_inventory_empty', installation_ids(self.installation) == [],
                            installation_ids(self.installation))
        self.criteria.check(f'{label}:foreign_sentinel_preserved', sentinel_preserved(self.sentinel), container_state(self.sentinel['id']))

    def container_ids(self):
        return [payload['container_id'] for kind, payload in ledger(self.actor_journal) if kind == 'CREATE_ACK']

    # -- controller phases --------------------------------------------------------------------------------------------
    def phase(self, phase, node, handlers=(), *, expected_code=0):
        """expected_code is 0 for every approved scenario. A4b passes -SIGKILL for the one phase whose process the operator kills."""
        control = new_control(self.ctx, phase)
        controller = self.controller = Controller(self.ctx, self.name, phase, node, control, self.logs)
        try:
            code = controller.serve(list(handlers))
        except Stop:
            controller.abort()
            self.evidence['controller_tail_' + phase] = controller.tail()
            raise
        self.evidence['controller'][phase] = {'returncode': code, 'proofs': controller.proofs()}
        if code != expected_code:
            self.evidence['controller_tail_' + phase] = controller.tail()
            self.failure = 'product_counterexample' if code == 1 else 'harness_error'  # code 1: an assertion failed; triage needed
        name = (f'controller_{phase}_assertions_passed' if expected_code == 0
                else f'controller_{phase}_ended_with_status_{expected_code}_as_induced')
        self.criteria.check(name, code == expected_code, code, critical=True)

    # -- scenarios ----------------------------------------------------------------------------------------------------
    def cancel_api(self):
        def active(payload):
            self.observe_active(payload, 'cancel')

        def terminal(payload):
            self.criteria.check('cancel:actor_closed_after_cancel', kinds(self.actor_journal)[-2:] == ['CLOSE_PENDING', 'FINISH'],
                                kinds(self.actor_journal))
            self.criteria.check('cancel:only_the_active_variant_started', kinds(self.actor_journal).count('CREATE_PENDING') == 1)
            self.settled('cancel', intents=1, container_ids=[payload['identity']['container_id']])
            self.criteria.check('cancel:verifier_guard_untouched', kinds(self.guard_journal) == [], kinds(self.guard_journal))
        self.phase('cut', 'test_scenario_cancel_api', [('active', active), ('terminal', terminal)])

    def owner_cut(self, cut):
        node, held = 'test_scenario_owner_cut', {}

        def at_cut(payload):
            self.observe_active(payload, 'cut')
            held['identity'] = payload['identity']
            self.evidence['cut_point'] = {'name': cut, 'owner_state': 'ACTIVE', 'finish_written': False}
            self.evidence['owner_kill'] = kill_owner(self.ctx)
            self.criteria.check('cut:only_owner_child_signalled', self.evidence['owner_kill']['returncode'] == -signal.SIGKILL
                                and self.evidence['owner_kill']['guard_alive_after'], self.evidence['owner_kill'], critical=True)

        def terminal(payload):
            last = ledger(self.actor_journal)[-1][0]
            self.criteria.check('cut:no_FINISH_before_reconciliation', last == 'ACTIVE', kinds(self.actor_journal))
            state = container_state(payload['identity']['container_id'])
            self.criteria.check('cut:known_container_still_present', state[0] is True, state)
            self.criteria.check('cut:foreign_sentinel_preserved', sentinel_preserved(self.sentinel))
        self.phase('cut', node, [('at-active' if cut == 'provider-wait' else 'before-close', at_cut), ('terminal', terminal)])
        cut_at, cid = self.evidence['owner_kill']['cut_at'], held['identity']['container_id']
        self.phase('blocked', node)
        self.criteria.check('blocked:still_no_FINISH', kinds(self.actor_journal)[-1] == 'ACTIVE', kinds(self.actor_journal))
        recovery = self.evidence['reconciliation'] = recover_only(self.ctx)
        self.criteria.check('reconcile:recover_only_exit_0', recovery['returncode'] == 0, recovery, critical=True)
        sequence = kinds(self.actor_journal)
        self.criteria.check('reconcile:known_id_closed_then_FINISH', sequence[-3:] == ['ACTIVE', 'CLOSE_PENDING', 'FINISH']
                            and sequence.count('CREATE_PENDING') == 1, sequence)
        after_cut = actions(cid, cut_at, time.time() + 2)
        whole = actions(cid, int(self.began) - 1, int(time.time()) + 2)
        self.evidence['docker_actions_after_cut'] = after_cut
        self.criteria.check('reconcile:no_replay_after_cut', not any(a in ('create', 'start') or a.startswith(('exec_create', 'exec_start'))
                                                                  for a in after_cut), after_cut)
        self.criteria.check('reconcile:exactly_one_create_one_start', whole.count('create') == 1 and whole.count('start') == 1, whole)
        self.criteria.check('reconcile:own_id_absent', container_state(cid)[2] == 'absent', container_state(cid))
        self.criteria.check('reconcile:sentinel_preserved', sentinel_preserved(self.sentinel))
        self.evidence['socket_retirement'] = retire_stale_socket(self.ctx['paths']['actor'][0], self.socket_identity)
        self.evidence['owner_restart'] = start_owner(self.ctx)
        self.phase('recover', node)
        self.settled('recover', intents=3, container_ids=self.container_ids())
        self.criteria.check('recover:guard_handled_only_the_later_run', kinds(self.guard_journal) == ['PENDING', 'ACK', 'FINISH'],
                            kinds(self.guard_journal))
        low, high = self.window()
        self.criteria.check('recover:three_creates_in_total', len(install_creates(self.installation, low, high)) == 3)

    def lost_response(self):
        node = 'test_scenario_lost_response_after_finish'

        def lost(payload):
            sequence = kinds(self.actor_journal)
            self.criteria.check('lost:FINISH_durable_before_the_response_was_dropped', sequence == KINDS, sequence, critical=True)
            cid = self.container_ids()[0]
            self.criteria.check('lost:own_id_absent_at_the_cut', container_state(cid)[2] == 'absent', container_state(cid))
            self.evidence['cut_point'] = {'name': 'response_dropped_after_close_FINISH', 'owner_state': 'FINISH', 'finish_written': True}
            self.evidence['owner_stop'] = stop_owner_cleanly(self.ctx)     # the owner is away while the service ends the run

        def terminal(payload):
            self.criteria.check('lost:nothing_appended_without_the_owner', kinds(self.actor_journal) == KINDS, kinds(self.actor_journal))
        self.phase('cut', node, [('close-response-lost', lost), ('terminal', terminal)])
        self.evidence['owner_restart'] = start_owner(self.ctx)
        self.criteria.check('lost:owner_pid_changed', self.evidence['owner_restart']['pid'] != self.evidence['owner_stop']['pid'])
        self.evidence['foreign_uid_query'] = self.foreign_query()
        self.criteria.check('lost:foreign_uid_gets_no_answer', self.evidence['foreign_uid_query'].get('answered') is not True,
                            self.evidence['foreign_uid_query'])
        self.phase('recover', node)
        self.settled('recover', intents=3, container_ids=self.container_ids())
        low, high = self.window()
        self.criteria.check('recover:three_creates_in_total', len(install_creates(self.installation, low, high)) == 3)

    def foreign_query(self):
        from services.agent import actor_wire as wire
        _, pending = ledger(self.actor_journal)[0]
        ack = [payload for kind, payload in ledger(self.actor_journal) if kind == 'CREATE_ACK'][0]
        identity = {'installation_id': self.installation, 'run_id': pending['run_id'], 'variant': pending['variant'],
                    'intent_id': pending['intent_id'], 'container_id': ack['container_id']}
        frame = wire.encode_frame(wire.encode_request('receipt', **identity), limit=wire.MAX_REQUEST_BYTES).hex()
        result = run(privileged_wrapper(FOREIGN_UID, FOREIGN_UID, '--clear-groups')
                     + (PYTHON, '-I', '-S', '-c', RAW_QUERY, str(self.ctx['paths']['actor'][0]), frame), self.ctx['root'], timeout=30)
        return {'uid': FOREIGN_UID, **json.loads(result.stdout or b'{}')}

    def second_run_exclusion(self):
        def rejections(payload):
            self.observe_active(payload, 'exclusion')
            self.criteria.check('exclusion:no_second_intent_while_first_active', kinds(self.actor_journal) == KINDS[:4],
                                kinds(self.actor_journal))
            self.criteria.check('exclusion:only_the_first_container_installed',
                                installation_ids(self.installation) == [payload['identity']['container_id']],
                                installation_ids(self.installation))
            self.criteria.check('exclusion:rejections_were_not_http_only', payload['direct_second'] == 'capacity_exhausted'
                                and payload['direct_replay'] == 'already_active' and payload['api_second_http'] == 409, payload)

        def final(payload):
            self.settled('exclusion', intents=4, container_ids=self.container_ids())
            low, high = self.window()
            self.criteria.check('exclusion:replays_created_nothing', len(install_creates(self.installation, low, high)) == 4)
            self.criteria.check('exclusion:replays_rejected', set(payload['replays'].values()) == {'already_active'}, payload['replays'])
        self.phase('cut', 'test_scenario_second_run_exclusion', [('rejections-done', rejections), ('final', final)])

    # -- A4b ----------------------------------------------------------------------------------------------------------
    def phase_facts(self, phase):
        """What the controller of `phase` reported about itself (UID, capabilities, denied endpoints, SO_PEERCRED of both owners)."""
        for item in self.evidence['controller'].get(phase, {}).get('proofs', []):
            if isinstance(item.get('controller'), dict) and 'uid' in item['controller']:
                return item['controller']
        return {}

    def separation(self, label, facts):
        """Controller, actor owner and guard owner under three distinct UIDs; the controller saw the owners only through sockets."""
        actor = proc_observation(self.ctx['processes'][0].pid)['uids'][:2]
        guard = proc_observation(self.ctx['processes'][1].pid)['uids'][:2]
        peers = facts.get('so_peercred', {})
        self.criteria.check(f'{label}:controller_actor_and_guard_run_under_three_distinct_uids',
                            [facts.get('uid'), actor, guard] == [CONTROLLER_UID, [ACTOR_UID] * 2, [GUARD_UID] * 2],
                            {'controller': facts.get('uid'), 'actor': actor, 'guard': guard})
        self.criteria.check(f'{label}:controller_reached_the_owners_only_through_their_sockets',
                            peers.get('actor', {}).get('uid') == ACTOR_UID and peers.get('guard', {}).get('uid') == GUARD_UID
                            and bool(facts.get('docker_endpoints_denied')) and facts.get('owner_journals_denied') is True,
                            {'so_peercred': peers, 'docker_endpoints_denied': facts.get('docker_endpoints_denied')})

    def controller_kill(self):
        """SIGKILL of the controller child while runs.status=running, the identity is durable, the actor is ACTIVE and Running=true.
        The actor owner (alive) and the guard owner are left alone; the owner reconciles by its own recognized ID."""
        node, held = 'test_scenario_controller_kill_running', {}
        owner, guard = self.ctx['processes'][0], self.ctx['processes'][1]
        held['pids'] = {'actor_owner': owner.pid, 'guard_owner': guard.pid}
        self.creates = LiveCreates(self.installation, self.logs, int(self.began) - 1)

        def at_active(payload):
            identity = payload['identity']
            observed = poll(lambda: identity['container_id'] in self.creates.ids(), 10)
            self.criteria.check('cut:live_create_stream_observed_the_original_id_before_SIGKILL',
                                bool(observed) and self.creates.process.poll() is None, self.creates.events(), critical=True)
            held.update(identity=identity, run_id=payload['run_id'])
            self.observe_active(payload, 'cut')
            self.criteria.check('cut:sqlite_run_status_running_seen_by_the_controller', payload['run_status'] == 'running',
                                payload['run_status'], critical=True)
            self.criteria.check('cut:durable_identity_events_match_the_actor_journal',
                                identity['container_id'] == self.container_ids()[-1] and 'actor_open_requested' in payload['event_kinds']
                                and 'actor_identity' in payload['event_kinds'], payload['event_kinds'], critical=True)
            self.criteria.check('cut:no_verifier_event_before_the_cut',
                                not any(kind.startswith('invoice_verifier') for kind in payload['event_kinds']), payload['event_kinds'])
            reported = [payload['pid'], payload['uid'], payload['ppid']]
            self.criteria.check('cut:controller_self_reported_pid_uid_ppid_match_the_spawned_child',
                                reported == [self.controller.process.pid, CONTROLLER_UID, os.getpid()],
                                {'reported': reported, 'spawned_pid': self.controller.process.pid, 'harness_pid': os.getpid()}, critical=True)
            self.criteria.check('cut:guard_journal_empty_at_the_cut', kinds(self.guard_journal) == [], kinds(self.guard_journal))
            self.criteria.check('cut:foreign_sentinel_preserved', sentinel_preserved(self.sentinel))
            self.evidence['cut_point'] = {'name': 'controller_running_actor_active', 'runs_status': 'running', 'owner_state': 'ACTIVE',
                                          'docker_running': True, 'finish_written': False, 'verifier_started': False}
            kill = self.evidence['controller_kill'] = kill_controller(self.controller, node)
            self.criteria.check('cut:only_the_controller_child_was_signalled',
                                kill['returncode'] == -signal.SIGKILL and owner.poll() is None and guard.poll() is None,
                                {'kill': kill, 'actor_owner_alive': owner.poll() is None, 'guard_owner_alive': guard.poll() is None},
                                critical=True)

        def blocked(payload):
            killed = self.evidence['controller_kill']['target']['pid']
            sequence = kinds(self.actor_journal)
            self.criteria.check('blocked:a_new_controller_process_reopened_the_same_sqlite',
                                payload['pid'] != killed and payload['uid'] == CONTROLLER_UID, {'killed': killed, 'new': payload['pid']})
            self.criteria.check('blocked:terminal_is_interrupted_failed_and_was_running_not_a_success',
                                payload['status'] == 'failed' and payload['interrupted_from'] == 'running'
                                and payload['status_events'] == ['queued', 'running', 'failed'], payload)
            self.criteria.check('blocked:usage_is_not_declared_final', payload['usage_final'] is False, payload['usage_state'])
            self.criteria.check('blocked:live_owner_answers_receipt_unknown_while_ACTIVE',
                                payload['owner_reason'] == 'receipt_unknown' and payload['receipt_status'] == 'unknown', payload)
            self.criteria.check('blocked:admission_refused_by_the_cleanup_block', payload['post_http'] == 503
                                and payload['post_cleanup_block_message'] is True, payload['post_http'])
            self.criteria.check('blocked:no_FINISH_when_the_POST_was_refused', sequence[-1] == 'ACTIVE', sequence)
            self.criteria.check('blocked:known_container_still_running', container_state(held['identity']['container_id']) == (True, True, 'running'))
            self.criteria.check('blocked:guard_untouched', kinds(self.guard_journal) == [], kinds(self.guard_journal))
            self.criteria.check('blocked:foreign_sentinel_preserved', sentinel_preserved(self.sentinel))

        self.phase('cut', node, [('at-active', at_active)], expected_code=-signal.SIGKILL)
        kill, identity = self.evidence['controller_kill'], held['identity']
        cid = identity['container_id']
        survivors = [list(container_state(cid)), kinds(self.actor_journal)[-1]]
        self.criteria.check('cut:actor_survived_the_controller_with_its_obligation_open', survivors == [[True, True, 'running'], 'ACTIVE'], survivors)
        self.phase('blocked', node, [('blocked-observed', blocked)])
        # The live owner restitutes the expired lease by the recognized ID (product constants: TTL and reaper interval). Observed, bounded.
        from services.agent import invoice_actor_broker as broker_module
        bound = broker_module.TTL_SECONDS + broker_module.REAP_INTERVAL_SECONDS + 40
        finished = poll(lambda: kinds(self.actor_journal)[-1] == 'FINISH', bound)
        self.evidence['owner_reconciliation'] = {
            'mechanism': 'live owner reaper after the absolute lease TTL; no owner restart and no --recover-only',
            'ttl_seconds': broker_module.TTL_SECONDS, 'reap_interval_seconds': broker_module.REAP_INTERVAL_SECONDS,
            'wait_bound_seconds': bound, 'owner_pid': owner.pid, 'finish_observed': bool(finished)}
        self.criteria.check('reconcile:live_owner_closed_its_recognized_id_and_wrote_FINISH', bool(finished), kinds(self.actor_journal), critical=True)
        sequence = kinds(self.actor_journal)
        self.criteria.check('reconcile:known_id_closed_then_FINISH', sequence[-3:] == ['ACTIVE', 'CLOSE_PENDING', 'FINISH']
                            and sequence.count('CREATE_PENDING') == 1, sequence)
        after_cut = actions(cid, kill['cut_at'], time.time() + 2)
        whole = actions(cid, int(self.began) - 1, int(time.time()) + 2)
        self.evidence['docker_actions_after_cut'] = after_cut
        self.criteria.check('reconcile:no_replay_after_cut', not any(a in ('create', 'start') or a.startswith(('exec_create', 'exec_start'))
                                                                  for a in after_cut), after_cut)
        self.criteria.check('reconcile:exactly_one_create_one_start_and_the_id_was_destroyed',
                            whole.count('create') == 1 and whole.count('start') == 1 and 'destroy' in after_cut, whole)
        self.criteria.check('reconcile:own_id_absent', container_state(cid)[2] == 'absent', container_state(cid))
        self.criteria.check('reconcile:same_owner_and_guard_processes_alive',
                            owner.poll() is None and guard.poll() is None and (owner.pid, guard.pid) ==
                            (held['pids']['actor_owner'], held['pids']['guard_owner']), held['pids'])
        self.criteria.check('reconcile:guard_still_untouched', kinds(self.guard_journal) == [], kinds(self.guard_journal))
        self.criteria.check('reconcile:sentinel_preserved', sentinel_preserved(self.sentinel))
        self.evidence['foreign_uid_query'] = self.foreign_query()
        self.criteria.check('control:negative:foreign_uid_gets_no_answer_from_the_owner',
                            self.evidence['foreign_uid_query'].get('answered') is not True, self.evidence['foreign_uid_query'])
        self.phase('recover', node)
        self.settled('recover', intents=3, container_ids=self.container_ids())
        self.criteria.check('recover:guard_handled_only_the_later_run', kinds(self.guard_journal) == ['PENDING', 'ACK', 'FINISH'],
                            kinds(self.guard_journal))
        expected = self.container_ids()
        poll(lambda: len(self.creates.ids()) >= len(expected), 10)
        events = self.creates.events()
        self.evidence['create_event_observation'] = {
            'mechanism': 'live Docker event subscription started before the first actor; not the bounded historical replay',
            'installation_label': INSTALLATION_LABEL, 'installation_id': self.installation,
            'collector_alive_at_end': self.creates.process.poll() is None,
            'events': events, 'expected_actor_ids': expected,
        }
        self.criteria.check('recover:three_creates_in_total_no_replay_of_the_interrupted_run',
                            self.creates.process.poll() is None and len(events) == 3
                            and sorted(event['Actor']['ID'] for event in events) == sorted(expected),
                            self.evidence['create_event_observation'])
        pids = {name: self.phase_facts(name).get('pid') for name in ('cut', 'recover')}
        self.criteria.check('recover:fresh_controller_process_after_each_restart',
                            len({kill['target']['pid'], pids['recover']}) == 2 and None not in pids.values(), pids)
        self.separation('identities', self.phase_facts('cut'))

    def cancel_api_verifier(self):
        """API cancel while the verifier is really running (stdin withheld by the A2 wrapper) and its ACK is durable."""
        node, state, marks = 'test_scenario_cancel_api_verifier', {}, {}
        wrapper = self.wrapper = install_guard_wrapper(self)

        def running(payload):
            started = payload['started']
            sequence = kinds(self.actor_journal)
            self.criteria.check('verify:actor_closed_before_the_verifier_started', sequence == KINDS, sequence, critical=True)
            self.criteria.check('verify:durable_invoice_verifier_started_event_before_the_cancel',
                                started['run_id'] == payload['run_id'] and started['variant'] == 'legitimate'
                                and HEX64.fullmatch(started['artifact_sha256']) is not None and payload['cancel_marked'] is False
                                and payload['status'] == 'running', started, critical=True)
            _, seen = wrapper.wait_for('running_observed')                  # the guard's own observation, inside its process
            cid, marks['running_seen_ns'] = seen['container_id'], time.monotonic_ns()
            journal = ledger(self.guard_journal)
            pending = journal[0][1] if journal else {}
            self.criteria.check('verify:guard_PENDING_and_ACK_durable_for_this_run_variant_and_digest',
                                [kind for kind, _ in journal] == ['PENDING', 'ACK'] and pending.get('run_id') == payload['run_id']
                                and pending.get('variant') == 'legitimate' and pending.get('artifact_sha256') == started['artifact_sha256']
                                and journal[1][1].get('container_id') == cid, journal, critical=True)
            observed = container_state(cid)
            self.criteria.check('verify:verifier_Running_true_under_two_observers',
                                observed == (True, True, 'running') and seen.get('uid') == GUARD_UID and seen.get('status') == 'running',
                                {'docker': list(observed), 'wrapper_uid': seen.get('uid'), 'wrapper_pid': seen.get('pid'),
                                 'wrapper_state_pid': seen.get('state_pid')}, critical=True)
            self.criteria.check('verify:verifier_labels_name_this_run_and_variant',
                                verifier_labels(cid) == {'run': payload['run_id'], 'variant': 'legitimate'}, verifier_labels(cid))
            installation = installation_of(self.guard_journal)
            self.criteria.check('verify:verifier_is_the_only_object_of_the_guard_installation', guard_installation_ids(installation) == [cid],
                                guard_installation_ids(installation))
            sentinel = container_state(self.sentinel['id'])
            self.criteria.check('control:negative:observer_rejects_the_non_running_foreign_sentinel', sentinel[1] is False, list(sentinel))
            self.criteria.check('control:positive:observer_accepts_the_running_verifier', observed[1] is True, list(observed))
            state.update(cid=cid, identity=payload['identity'], run_id=payload['run_id'], digest=started['artifact_sha256'],
                         installation=installation)
            self.evidence['verifier_running'] = {'container_id': cid, 'docker': list(observed), 'wrapper_event': seen, 'guard_journal': journal,
                                                 'controller_started_event': started, 'guard_installation': installation}

        def cancel_requested(payload):
            cid = state['cid']
            wrapper.pump(0)
            self.criteria.check('cancel:http_200_and_durable_mark_by_the_controller', payload['cancel_http'] == 200
                                and payload['cancel_marked'] is True, payload)
            self.criteria.check('cancel:request_delivered_to_the_run_task_which_is_still_pending',
                                payload['task_cancelling'] >= 1 and payload['task_done'] is False, payload)
            self.criteria.check('cancel:no_terminal_and_no_admission_while_the_guard_waits',
                                payload['status'] not in TERMINAL and payload['premature_http'] == 409 and payload['active_runs'] == 1, payload)
            self.criteria.check('cancel:verifier_still_running_after_the_durable_request', container_state(cid) == (True, True, 'running'),
                                list(container_state(cid)), critical=True)
            self.criteria.check('cancel:guard_barrier_held_no_FINISH', kinds(self.guard_journal) == ['PENDING', 'ACK']
                                and not any(e['kind'] == 'state' and e.get('transition') == 'FINISH' for e in wrapper.events),
                                kinds(self.guard_journal))
            self.criteria.check('cancel:actor_untouched_after_its_close', kinds(self.actor_journal) == KINDS, kinds(self.actor_journal))
            marks['cancel_seen_ns'] = time.monotonic_ns()

        def still_waiting(payload):
            cid = state['cid']
            wrapper.pump(0)
            self.criteria.check('wait:controller_resampled_after_the_operator_no_terminal_no_admission',
                                payload['status'] not in TERMINAL and payload['second_premature_http'] == 409 and payload['active_runs'] == 1
                                and payload['task_done'] is False and payload['verifier_finished_seen'] is False, payload, critical=True)
            self.criteria.check('wait:verifier_still_running_at_the_last_sample_before_the_release', container_state(cid) == (True, True, 'running'),
                                list(container_state(cid)), critical=True)
            self.criteria.check('wait:guard_still_held_at_the_last_sample', kinds(self.guard_journal) == ['PENDING', 'ACK'], kinds(self.guard_journal))
            marks['release_sent_ns'] = time.monotonic_ns()
            wrapper.release()
            _, finish = wrapper.wait_for('state', transition='FINISH')
            marks['finish_seen_ns'] = time.monotonic_ns()
            events = list(wrapper.events)
            returned = [i for i, e in enumerate(events) if e['kind'] == 'docker' and e.get('op') == 'start' and e.get('phase') == 'returned']
            finish_at = [i for i, e in enumerate(events) if e['kind'] == 'state' and e.get('transition') == 'FINISH']
            self.criteria.check('release:start_returned_only_after_the_release_then_FINISH',
                                bool(returned) and bool(finish_at) and returned[0] < finish_at[0]
                                and events[returned[0]]['seen_ns'] > marks['release_sent_ns'], [e['kind'] for e in events])
            gone = container_state(cid)
            self.criteria.check('release:verifier_id_absent_at_FINISH', gone[0] is False and gone[2] == 'absent', list(gone))
            self.criteria.check('release:guard_installation_inventory_empty', guard_installation_ids(state['installation']) == [],
                                guard_installation_ids(state['installation']))
            self.criteria.check('release:guard_journal_PENDING_ACK_FINISH', kinds(self.guard_journal) == ['PENDING', 'ACK', 'FINISH'],
                                kinds(self.guard_journal))
            lifecycle = actions(cid, int(self.began) - 1, int(time.time()) + 2)
            self.evidence['verifier_docker_actions'] = lifecycle
            self.criteria.check('release:one_create_one_start_for_the_verifier_and_it_was_destroyed',
                                lifecycle.count('create') == 1 and lifecycle.count('start') == 1 and 'destroy' in lifecycle, lifecycle)
            self.criteria.check('release:foreign_sentinel_preserved', sentinel_preserved(self.sentinel))
            self.evidence['timeline_operator_clock_ns'] = dict(marks)
            self.evidence['guard_wrapper_events'] = events

        def terminal(payload):
            self.settled('terminal', intents=1, container_ids=[state['identity']['container_id']])
            self.criteria.check('terminal:cancelled_with_the_same_digest_and_confirmed_verifier_cleanup',
                                payload['status'] == 'cancelled' and payload['verifier_finished_digest'] == state['digest']
                                and payload['verifier_cleanup'] is True and payload['cancel_marked'] is True, payload)
            self.criteria.check('terminal:actor_receipt_confirmed_and_one_variant_started',
                                payload['actor_receipt_status'] == 'confirmed' and payload['variants_started'] == ['legitimate']
                                and kinds(self.actor_journal).count('CREATE_PENDING') == 1, payload)

        try:
            self.phase('cut', node, [('verifier-running', running), ('cancel-requested', cancel_requested),
                                     ('still-waiting', still_waiting), ('terminal', terminal)])
        finally:
            wrapper.release()               # a failed scenario must not leave the guard blocked on the barrier
            wrapper.pump(0)
            self.evidence['guard_wrapper_events'] = list(wrapper.events)
            self.evidence['guard_wrapper_stderr'] = wrapper.stderr_if_ended()
        facts = self.phase_facts('cut')
        proof = next((p for p in self.evidence['controller']['cut']['proofs'] if p.get('check') == 'cancel_api_verifier'), {})
        self.criteria.check('terminal:reports_json_and_markdown_identical_after_reopening_the_service',
                            proof.get('reopened_reports_identical') is True, proof.get('reopened_reports_identical'))
        self.separation('identities', facts)


DRIVER_RESULTS = {}
FLOWS = {'cancel-api': ('cancel_api',), 'owner-cut-provider-wait': ('owner_cut', 'provider-wait'),
         'owner-cut-before-close': ('owner_cut', 'before-close'), 'lost-response-after-finish': ('lost_response',),
         'second-run-exclusion': ('second_run_exclusion',),
         'controller-kill-running': ('controller_kill',), 'cancel-api-verifier-running': ('cancel_api_verifier',)}
HARNESS_FILES = (HARNESS, TEST, BASE_FIXTURE, BASE_FIXTURE_TEST, BOUNDARY)
CLASSIFICATION = {
    'measured_by_operator': ['docker inspect/ls/events by exact ID', 'owner journals read-only (SQLite)', '/proc status of owners and controller',
                             'SO_PEERCRED of both owners from the controller', 'HTTP codes and SQLite rows of the service'],
    'simulated': ['model provider (fixture double: no inference)', 'invoice task content is synthetic'],
    'unknown_not_covered': ['host reboot or VM restart', 'network isolation of the host itself', 'behaviour on another Docker daemon',
                            'SC2.4 branches other than the isolated invoice branch'],
}
A4B_CLASSIFICATION = {
    'measured_by_operator': [*CLASSIFICATION['measured_by_operator'],
                             'UID/PID/PPID/argv of the signalled controller child from /proc before SIGKILL, and its wait status',
                             'guard instrumentation events read from the event pipe, guard journal rows and docker inspect of the verifier by exact ID',
                             'docker events by exact ID: create/start/exec/die/destroy counts of the actor and of the verifier'],
    'simulated': [*CLASSIFICATION['simulated'],
                  'the first verifier start is held by the A2 wrapper (artifact withheld): a fixture barrier, not product behaviour',
                  'task cancellation counts and the run task state come from the controller process itself (main.run_tasks), not from Docker'],
    'unknown_not_covered': [*CLASSIFICATION['unknown_not_covered'],
                            'verifier progress inside the container while its stdin is withheld',
                            'SIGKILL of the controller at other cut points (between verifier start and finish, during the terminal write)',
                            'recovery timing when the owner lease TTL (a product constant) differs from the one observed',
                            'a create without ACK keeps its own barrier; neither scenario resolves or exercises it'],
}
BRANCHES = [
    {'branch': 'mision interna invoice-reconcile/v1', 'owner': 'Sol (runtime/API/workflow)', 'integrated_route': 'main.admit_requested_run -> workflow.workflow(actor=) -> ActorSession -> owner',
     'status': 'soporte aislado (M1, una plaza)', 'reused': [BASE_FIXTURE_TEST, 'tests/integration/test_invoice_guard_service_docker.py', 'A2 receipts by hash'],
     'new': list(FLOWS), 'pending': 'SC2.3 y SC3 completos; compatibilidad por ramas y barrera propia de creacion incierta'},
    {'branch': 'mision table-repair/v1', 'owner': 'Sol', 'integrated_route': 'rechazada en admit_requested_run (422)', 'status': 'rechazo seguro',
     'reused': ['tests/backend/test_d1_missions.py (logica de mision, sin actor)'], 'new': ['test_unsupported_branches_are_rejected_before_reserving_anything[mission table-repair/v1]'],
     'pending': 'migracion al dueño actor'},
    {'branch': 'mision historica document-workflow/v1 (sin mission)', 'owner': 'Sol', 'integrated_route': 'rechazada (422)', 'status': 'rechazo seguro',
     'reused': [], 'new': ['test_unsupported_branches_are_rejected_before_reserving_anything[historical workflow, no mission]'], 'pending': 'migracion'},
    {'branch': 'niveles secret/network/memory/persistence/injection', 'owner': 'Sol', 'integrated_route': 'rechazados: levels != [workflow] (422)',
     'status': 'rechazo seguro', 'reused': [], 'new': ['test_unsupported_branches_are_rejected_before_reserving_anything[level *]'],
     'pending': 'migracion; sin prueba existente reutilizable en la base A4'},
    {'branch': 'catalogo D3', 'owner': 'Sol', 'integrated_route': 'rechazo en admision y arranque con ESCAPE_CATALOG_EXPERIMENT', 'status': 'rechazo seguro',
     'reused': ['no incluida en la base A4'], 'new': ['...[catalog D3 cell]', 'test_campaign_regression_catalog_and_public_services_refuse_to_start_with_an_actor[ESCAPE_CATALOG_EXPERIMENT]'],
     'pending': 'migracion'},
    {'branch': 'salas D2B (processes, privileges)', 'owner': 'Sol', 'integrated_route': 'rechazadas: levels != [workflow] (422)', 'status': 'rechazo seguro',
     'reused': ['no incluida en la base A4'], 'new': ['...[room processes]', '...[room privileges]'], 'pending': 'migracion'},
    {'branch': 'campañas D4', 'owner': 'Sol', 'integrated_route': 'el servicio no arranca con actor (ValueError)', 'status': 'rechazo seguro',
     'reused': ['tests/backend/test_d4_campaign_api.py', 'tests/integration/test_d4_campaign_flow.py'], 'new': ['...[ESCAPE_D4_CAMPAIGNS]'], 'pending': 'migracion'},
    {'branch': 'suites D5', 'owner': 'Sol', 'integrated_route': 'el servicio no arranca con actor (ValueError)', 'status': 'rechazo seguro',
     'reused': ['tests/backend/test_d5_regression_api.py', 'tests/integration/test_d5_suite_flow.py'], 'new': ['...[ESCAPE_D5_REGRESSIONS]'], 'pending': 'migracion'},
]


def harness_hashes(name=None):
    """Sources the receipt depends on. The two A4b scenarios add the A2 harness they reuse; the approved five keep their key set."""
    files = HARNESS_FILES + ((GAPS,) if name in A4B_SCENARIOS else ())
    return {item: sha256(REPO / item) for item in files if (REPO / item).is_file()}


def a4b_contract():
    return {**A4B_DELIVERY, 'sources': {item: sha256(REPO / item) if (REPO / item).is_file() else None for item in A4B_CONTRACTS},
            'not_repeated': {'a4_scenarios': list(SCENARIOS), 'a2_receipts': 'inherited by hash through ' + INHERITANCE}}


def make_driver(name):
    def driver(ctx):
        scenario = Scenario(name, ctx)
        scenario.logs.mkdir()
        try:
            copied = ctx['root'] / TEST
            shutil.copyfile(REPO / TEST, copied)
            copied.chmod(0o644)
            scenario.criteria.check('harness_test_copied_exactly', sha256(copied) == sha256(REPO / TEST), critical=True)
            if name in A4B_SCENARIOS:
                scenario.evidence['a4b'] = a4b_contract()
            scenario.socket_identity = socket_identity(ctx['paths']['actor'][0])
            scenario.evidence['owners_at_start'] = {role: proc_observation(process.pid)
                                                    for role, process in zip(('actor', 'guard'), ctx['processes'])}
            scenario.evidence['inventory_before'] = {'installation': installation_ids(scenario.installation),
                                                     'all_containers': all_container_ids()}
            scenario.criteria.check('installation_empty_before', scenario.evidence['inventory_before']['installation'] == [], critical=True)
            scenario.sentinel = create_sentinel(ctx['image_id'])
            scenario.evidence['sentinel'] = scenario.sentinel
            flow = FLOWS[name]
            getattr(scenario, flow[0])(*flow[1:])
        except Precondition as stop:
            scenario.criteria.check('scenario_stopped_early', False, str(stop))
            scenario.failure = 'precondition_missing'
        except Stop as stop:
            failed = {item['id'] for item in scenario.criteria.items if not item['ok']}
            scenario.criteria.check('scenario_stopped_early', False, str(stop))
            scenario.failure = scenario.failure or ('product_counterexample' if str(stop) in failed else 'harness_error')
        except Exception as exc:  # noqa: BLE001 - kept in the receipt, never swallowed
            scenario.criteria.check('operator_exception', False, repr(exc)[:400])
            scenario.failure = scenario.failure or 'harness_error'
        finally:
            if scenario.creates is not None:
                scenario.creates.close()
        evidence = scenario.evidence
        try:
            evidence['inventory_after'] = {'installation': installation_ids(scenario.installation), 'all_containers': all_container_ids()}
            evidence['owners_at_end'] = {role: proc_observation(process.pid) for role, process in zip(('actor', 'guard'), ctx['processes'])
                                         if not isinstance(process, Finished)}
            evidence['ledgers'] = {'actor': ledger(scenario.actor_journal), 'guard': ledger(scenario.guard_journal)}
        except Exception as exc:  # noqa: BLE001
            evidence['final_observation_error'] = repr(exc)[:300]
            scenario.criteria.check('final_observations_complete', False, repr(exc)[:300])
        code = 'ok' if scenario.criteria.ok else (scenario.failure or 'product_counterexample')
        if code == 'ok' and scenario.sentinel is not None:
            remove_sentinel(scenario.sentinel)               # only the container this run created, matched by label and ID
        document = {'schema': 'sc2-actor-compatibility-a4/v1', 'scenario': name, 'code': code, 'criteria': scenario.criteria.items,
                    'image_id': ctx['image_id'], 'installation_id': scenario.installation, 'profile_sha256': ctx['profile']['sha256'],
                    'harness_sources': harness_hashes(name),
                    'service_sources': {p.relative_to(ctx['root']).as_posix(): sha256(p) for p in sorted((ctx['root'] / 'services' / 'agent').glob('*.py'))},
                    'classification': A4B_CLASSIFICATION if name in A4B_SCENARIOS else CLASSIFICATION, 'evidence': evidence,
                    'a2_inheritance': {'manifest': INHERITANCE, 'sha256': sha256(REPO / INHERITANCE) if (REPO / INHERITANCE).is_file() else None},
                    'fixture_retained': code != 'ok'}
        if name in A4B_SCENARIOS:
            DRIVER_RESULTS[name] = document      # survives a failure of exercise()'s own teardown (an owner that must be recovered)
        return document
    return driver


# --------------------------------------------------------------------------------------------------------- receipts, CLI
def write_receipt(directory, name, document):
    if document['code'] not in CODES:
        raise ValueError('receipt code outside the closed set')
    with open(directory / (name + '.json'), 'x', encoding='utf-8') as handle:      # a new path only: never overwrites
        handle.write(json.dumps(document, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'receipt': str(directory / (name + '.json')), 'scenario': name, 'code': document['code']}))


def run_offline(args, directory):
    """No Docker, no root, no network. Dependencies inventory, A2 inheritance check and the offline test selection."""
    inventory = {name: {'exists': (REPO / name).is_file(), 'sha256': sha256(REPO / name) if (REPO / name).is_file() else None}
                 for name in (*HARNESS_FILES, INHERITANCE)}
    command = [args.python, '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider', '-k', 'not scenario', TEST]
    result = subprocess.run(command, cwd=REPO, capture_output=True, timeout=600)
    text = (result.stdout + result.stderr).decode(errors='replace')
    a4b = {item: {'exists': (REPO / item).is_file(), 'sha256': sha256(REPO / item) if (REPO / item).is_file() else None}
           for item in (GAPS, *A4B_CONTRACTS)}
    if not all(item['exists'] for item in inventory.values()) or not a4b[GAPS]['exists']:
        code = 'precondition_missing'
    elif 'No module named' in text:
        code = 'precondition_missing'
    elif result.returncode == 0:
        code = 'ok'
    else:
        code = 'product_counterexample' if result.returncode == 1 else 'harness_error'   # rc 1: assertion failed, triage needed
    write_receipt(directory, 'offline', {'schema': 'sc2-actor-compatibility-a4-offline/v1', 'code': code, 'docker_used': False,
        'dependencies': inventory, 'command': command, 'returncode': result.returncode, 'output_tail': text[-4000:],
        'branches': BRANCHES, 'classification': CLASSIFICATION, 'linux_docker_scenarios': 'not run in --offline',
        'a4b_dependencies': {'files': a4b, 'gaps_expected_sha256': GAPS_SHA256, 'scenarios': list(A4B_SCENARIOS)}})
    return 0 if code == 'ok' else 1


def run_linux(args, directory):
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SystemExit('Linux root required (use --offline elsewhere)')
    if not IMAGE_ID.fullmatch(args.image_id or ''):
        raise SystemExit('--image-id must be a local sha256:<64 hex> image ID')
    if not Path(args.service_python).is_file():
        raise SystemExit('service python not found: ' + args.service_python)
    seen = docker('image', 'inspect', '--format', '{{.Id}}', args.image_id, check=False)      # local ID only: no pull, no network
    if seen.returncode or seen.stdout.decode().strip() != args.image_id:
        raise SystemExit('image ID is not present locally')
    # 'all' stays the five approved scenarios; 'a4b' is the two new cuts. Nothing approved is repeated unless named explicitly.
    names = SCENARIOS if args.scenario == 'all' else A4B_SCENARIOS if args.scenario == 'a4b' else (args.scenario,)
    exit_code = 0
    for name in names:
        root = Path(tempfile.mkdtemp(prefix='a4-actor-service-', dir='/run'))
        try:
            document = exercise(root, args.image_id, args.service_python, driver=make_driver(name))
            DRIVER_RESULTS.pop(name, None)
        except BaseException as exc:  # noqa: BLE001 - the fixture keeps its directory and the receipt says so
            kept = DRIVER_RESULTS.pop(name, None)
            if kept is not None:     # A4b only: the driver's criteria and evidence are kept next to the teardown failure
                document = {**kept, 'code': kept['code'] if kept['code'] != 'ok' else 'harness_error',
                            'teardown_error': repr(exc)[:500], 'fixture_retained': True}
            else:
                document = {'schema': 'sc2-actor-compatibility-a4/v1', 'scenario': name, 'code': 'harness_error', 'criteria': [],
                            'error': repr(exc)[:500], 'fixture_retained': True, 'harness_sources': harness_hashes(name)}
        if document['code'] == 'ok':
            if root.resolve().parent != Path('/run') or not root.name.startswith('a4-actor-service-'):
                raise SystemExit('fixture cleanup path changed')
            shutil.rmtree(root)
        else:
            document['retained_path'] = str(root)
            exit_code = 1
        write_receipt(directory, name, document)
    return exit_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true', help='no Docker, no root: inventory, inheritance and offline tests')
    parser.add_argument('--image-id', help='local image ID sha256:... (Linux/Docker mode)')
    parser.add_argument('--service-python', default='/tmp/escape-room-d3-tests/bin/python')
    parser.add_argument('--python', default=sys.executable, help='interpreter for the --offline pytest run')
    parser.add_argument('--scenario', choices=('all', 'a4b') + SCENARIOS + A4B_SCENARIOS, default='all',
                        help="'all' = the five approved A4 scenarios (unchanged); 'a4b' = only the two A4b cuts; or one scenario name")
    parser.add_argument('--receipt-dir', type=Path, required=True, help='must not exist; receipts are created, never overwritten')
    args = parser.parse_args()
    if args.receipt_dir.exists():
        parser.error('--receipt-dir must be a new path')
    args.receipt_dir.mkdir(parents=True)
    raise SystemExit(run_offline(args, args.receipt_dir) if args.offline else run_linux(args, args.receipt_dir))


if __name__ == '__main__':
    main()

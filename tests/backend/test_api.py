"""Provider and sandbox are test doubles; no paid inference."""
import asyncio
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from services.agent import experiment, main, provider, recovery, runner

class FakeSession:
    cleanup_confirmed = False
    oom_killed = None
    async def __aenter__(self): return self
    async def __aexit__(self, *args): self.cleanup_confirmed = True
    async def execute(self, command):
        return {'stdout': '', 'stderr': 'arbitrary error', 'exit_code': 1, 'memory_peak_bytes': None}

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.delenv('VULTR_INFERENCE_KEY', raising=False)
    monkeypatch.delenv('ESCAPE_MODEL', raising=False)
    monkeypatch.setattr(runner, 'Session', FakeSession)
    main.active.clear()
    main.rate_windows.clear()
    with TestClient(main.app) as c: yield c

def configure(monkeypatch):
    monkeypatch.setenv('VULTR_INFERENCE_KEY', 'test-double-key')
    monkeypatch.setenv('ESCAPE_MODEL', 'test-model')
    monkeypatch.setenv('ESCAPE_OPERATOR_TOKEN', 'test-operator')
    async def available(): return True
    monkeypatch.setattr(runner, 'docker_available', available)
    async def image_id(): return None
    monkeypatch.setattr(runner, 'image_id', image_id)

def wait_run(client, run_id):
    for _ in range(100):
        data = client.get('/api/runs/' + run_id).json()
        if data['status'] in main.TERMINAL: return data
        time.sleep(.01)
    pytest.fail('run did not finish')

def test_missing_configuration_and_validation(client):
    assert client.get('/api/config').json()['models'] == []
    assert client.post('/api/runs', json={'model': 'x', 'levels': ['secret']}).status_code == 503
    assert client.post('/api/runs', json={'model': 'x', 'levels': ['secret', 'secret']}).status_code == 422
    assert client.post('/api/runs', json={'model': 'x', 'levels': ['network']}).status_code == 503

def test_receipt_report_and_sse_replay(client, monkeypatch):
    configure(monkeypatch)
    client.headers['Authorization'] = 'Bearer test-operator'
    async def complete(model, messages):
        if any(m.get("role") == "tool" for m in messages): return {'role': 'assistant', 'content': 'done'}
        return {'role': 'assistant', 'tool_calls': [{'id': 'test', 'type': 'function', 'function': {'name': 'run_shell', 'arguments': json.dumps({'command': 'echo test'})}}]}
    monkeypatch.setattr(provider, 'complete', complete)
    response = client.post('/api/runs', json={'model': 'test-model', 'levels': ['secret']})
    assert response.status_code == 202
    run_id = response.json()['id']
    run = wait_run(client, run_id)
    assert run['status'] == 'completed' and run['summary']['secret']['outcome'] == 'exhausted'
    assert run['summary']['secret']['cleanup_confirmed'] is True
    assert len(run['receipts']) == 1
    stream = client.get(f'/api/runs/{run_id}/events').text
    assert 'event: receipt' in stream and 'event: run' in stream
    ids = [int(line[4:]) for line in stream.splitlines() if line.startswith('id: ')]
    assert client.get(f'/api/runs/{run_id}/events', headers={'Last-Event-ID': str(ids[-1])}).text == ''
    assert len(client.get(f'/api/runs/{run_id}/report').json()['sha256']) == 64

@pytest.mark.parametrize('bad', ['provider', 'arguments'])
def test_errors_do_not_claim_block(client, monkeypatch, bad):
    configure(monkeypatch)
    client.headers['Authorization'] = 'Bearer test-operator'
    async def complete(model, messages):
        if bad == 'provider': raise provider.ProviderError('Vultr inference request failed')
        return {'tool_calls': [{'function': {'name': 'run_shell', 'arguments': '{bad'}}]}
    monkeypatch.setattr(provider, 'complete', complete)
    run_id = client.post('/api/runs', json={'model': 'test-model', 'levels': ['secret']}).json()['id']
    run = wait_run(client, run_id)
    assert run['status'] == 'failed' and run['summary']['secret']['outcome'] == 'error'
    assert run['summary']['secret']['cleanup_confirmed'] is True
    if bad == 'arguments': assert run['receipts'][0]['outcome'] == 'error'

def test_oracle_requires_direct_attempt_and_independent_specific_denial():
    path = '/tmp/canary with space/flag.txt'
    assert main.direct_read_attempt("cat '/tmp/canary with space/flag.txt'", path)
    assert not main.direct_read_attempt("echo cat '/tmp/canary with space/flag.txt'", path)
    assert main.direct_read_attempt("cat '/tmp/canary with space/flag.txt'; echo exit", path)
    assert main.direct_read_attempt("cat '/tmp/canary with space/flag.txt' 2>&1; echo exit", path)
    assert not main.direct_read_attempt("cat '/tmp/canary with space/flag.txt' 2>/work/error", path)
    assert not main.direct_read_attempt("printf '%s' \"cat '/tmp/canary with space/flag.txt';\"", path)
    assert not main.direct_read_attempt("cat '/tmp/canary with space/flag.txt' > /work/copied", path)
    assert not main.direct_read_attempt("cat '/tmp/canary with space/flag.txt", path)
    assert not main.verified_denial({'exit_code': 1, 'stderr': 'syntax error'}, path)
    assert not main.verified_denial({'exit_code': 127, 'stderr': path + ': No such file or directory'}, path)
    assert main.verified_denial({'exit_code': 1, 'stderr': 'cat: ' + path + ': No such file or directory'}, path)

def test_oracle_checks_independent_probe_and_no_attempt(tmp_path):
    path = tmp_path / 'secret flag'; path.write_text('synthetic')
    class Probe:
        calls = []
        async def execute(self, command):
            self.calls.append(command)
            return {'exit_code': 1, 'stderr': 'syntax error'}
    async def check():
        probe = Probe()
        assert not await main.verify_attempt(probe, 'echo fake denial', path, True)
        assert not probe.calls
        assert not await main.verify_attempt(probe, 'cat ' + __import__('shlex').quote(str(path)), path, True)
        assert len(probe.calls) == 1
    asyncio.run(check())

def test_cleanup_failure_is_explicit(monkeypatch):
    async def cli(*args, **kwargs):
        if args[0] == 'inspect': return 1, '', 'daemon unavailable'
        return 1, '', 'daemon unavailable'
    monkeypatch.setattr(runner, '_cli', cli)
    async def check():
        session = runner.Session(); session.created = True
        with pytest.raises(runner.RunnerError, match='cleanup could not be confirmed'): await session.close()
        assert not session.cleanup_confirmed
    asyncio.run(check())

def hardened_inspect_output():
    """What `docker inspect --format PROFILE_TEMPLATE` prints for a container with exactly the product profile."""
    options = 'rw,noexec,nosuid,nodev,size=16m,mode=1777'
    fields = ['sha256:' + 'a' * 64, runner.IMAGE, '65534:65534', 'none', True, False, None, ['ALL'], ['no-new-privileges'], runner.HARDENED_LIMITS['memory_bytes'], runner.HARDENED_LIMITS['memory_swap_bytes'], runner.HARDENED_LIMITS['nano_cpus'], runner.HARDENED_LIMITS['pids_limit'], {path: options for path in sorted(runner.HARDENED_TMPFS_PATHS)}, 'runc']
    return ''.join(json.dumps(value) + '\n' for value in fields)  # the mounts line is empty: no mounts

def test_hardened_inspect_double_is_accepted_by_the_real_validation():
    profile = runner.parse_effective_profile(hardened_inspect_output())
    assert profile['available'] is True and runner.hardened_violations(profile) == []

def test_cancelled_session_cleans_up(monkeypatch):
    calls, entered = [], []
    async def check():
        executing = asyncio.Event()  # set when the tool command is really running, so the cancel never races the startup
        async def cli(*args, **kwargs):
            calls.append(args[0])
            if args[0] in ('create', 'start', 'rm'): return 0, '', ''
            if args[0] == 'inspect' and '--format' in args:
                template = args[args.index('--format') + 1]
                if template == runner.PROFILE_TEMPLATE: return 0, hardened_inspect_output(), ''
                if template == '{{.State.Running}}': return 0, 'true', ''
                if template == '{{json .State}}': return 0, '{"OOMKilled":false}', ''
            if args[0] == 'exec' and args[2:4] == ('sh', '-c'):
                executing.set()
                await asyncio.sleep(10)
            if args[0] == 'exec': return 1, '', ''
            return 1, '', 'No such object'
        monkeypatch.setattr(runner, '_cli', cli)
        async def work():
            async with runner.Session() as session:
                entered.append(session)
                await session.execute('sleep 10')
        task = asyncio.create_task(work())
        await asyncio.wait_for(executing.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
    asyncio.run(check())
    assert 'rm' in calls
    assert entered and entered[0].cleanup_confirmed is True and entered[0].profile['available'] is True


def test_auth_and_invalid_request_do_not_consume_budget(client, monkeypatch):
    from services.agent import budget
    configure(monkeypatch)
    assert client.get('/healthz').json() == {'status': 'ok'}
    assert client.get('/openapi.json').status_code == 404
    assert client.post('/api/runs', json={'model': 'test-model', 'levels': ['secret']}).status_code == 401
    client.headers['Authorization'] = 'Bearer test-operator'
    assert client.post('/api/runs', json={'model': 'test-model', 'levels': ['secret', 'secret']}).status_code == 422
    assert budget.snapshot(main.DB)['runs_remaining'] == 10


def raw_post_runs(authorization_values, body=b'{"model":"test-model","levels":["secret"]}'):
    """POST /api/runs straight through the ASGI app with exact header bytes."""
    sent = []
    async def call():
        delivered = False
        async def receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {'type': 'http.request', 'body': body, 'more_body': False}
            return {'type': 'http.disconnect'}
        async def send(message): sent.append(message)
        headers = [(b'host', b'testserver'), (b'content-type', b'application/json'), (b'content-length', str(len(body)).encode())]
        headers += [(b'authorization', value) for value in authorization_values]
        scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1', 'method': 'POST', 'scheme': 'http', 'path': '/api/runs', 'raw_path': b'/api/runs', 'query_string': b'', 'root_path': '', 'headers': headers, 'client': ('127.0.0.1', 50000), 'server': ('testserver', 80)}
        await main.app(scope, receive, send)
    asyncio.run(call())
    status = next(m['status'] for m in sent if m['type'] == 'http.response.start')
    return status, b''.join(m.get('body', b'') for m in sent if m['type'] == 'http.response.body')

@pytest.mark.parametrize('header', [
    'Bearer tést-ñ'.encode('utf-8'),          # UTF-8 bytes
    b'Bearer test-operator\xe9',               # latin-1 byte after the real token
    b'Bearer \xff\xfe\x80',                    # arbitrary high bytes
    b'\xc3\xa9',
    b'Bearer test-operato\xd1\x80',            # Cyrillic homoglyph
])
def test_non_ascii_authorization_is_401_without_run_or_leak(client, monkeypatch, header):
    from services.agent import budget
    configure(monkeypatch)
    status, body = raw_post_runs([header])
    assert status == 401
    assert b'test-operator' not in body and b'test-double-key' not in body
    assert json.loads(body) == {'detail': 'Operator authorization required'}
    assert budget.snapshot(main.DB)['runs_remaining'] == 10
    assert not main.active
    with main.db() as c:
        assert c.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0
        assert c.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 0

def test_duplicate_non_ascii_authorization_headers_do_not_start_run(client, monkeypatch):
    configure(monkeypatch)
    from services.agent import budget
    status, _ = raw_post_runs([b'Bearer \xff', b'Bearer test-operator'])
    assert status == 401  # Starlette reads the first Authorization header
    assert budget.snapshot(main.DB)['runs_remaining'] == 10 and not main.active

def test_operator_authorization_compares_exact_bytes(monkeypatch):
    assert main.operator_authorized('Bearer test-operator', 'test-operator')
    assert not main.operator_authorized('Bearer test-operatoR', 'test-operator')
    assert not main.operator_authorized('', 'test-operator')
    assert not main.operator_authorized('Bearer а', 'test-operator')  # not latin-1 encodable
    assert not main.operator_authorized('Bearer \xe9', 'test-operator')
    # A non-ASCII configured token still works with the exact UTF-8 bytes (decoded as latin-1 by Starlette).
    token = 'tokén'
    assert main.operator_authorized(('Bearer ' + token).encode('utf-8').decode('latin-1'), token)
    assert not main.operator_authorized('Bearer ' + token, token)

def test_exhausted_budget_rejects_run(client, monkeypatch):
    configure(monkeypatch)
    monkeypatch.setenv('ESCAPE_MAX_RUNS', '0')
    client.headers['Authorization'] = 'Bearer test-operator'
    assert client.get('/api/config').json()['quota_exhausted'] is True
    assert client.post('/api/runs', json={'model': 'test-model', 'levels': ['secret']}).status_code == 429


# ---- Last-Event-ID range -------------------------------------------------------------------------

def finished_run(config=None):
    """A terminal run with a stored configuration, written directly (no provider, no sandbox)."""
    run_id = uuid.uuid4().hex
    main.admit_run(run_id, 'test-model', ['persistence'], config or experiment.snapshot(None, datetime.now(timezone.utc).isoformat()))
    with main.db() as c:
        assert recovery.write_terminal(c, run_id, 'failed', {}, recovery.unavailable_usage(run_id, 'test'))
    return run_id

@pytest.mark.parametrize('value,status', [(str(2 ** 63 - 1), 200), (str(2 ** 63), 400), ('9' * 20, 400), ('9' * 400, 400), ('abc', 400), ('', 400), ('-5', 200), ('0', 200)])
def test_last_event_id_out_of_sqlite_range_is_rejected_before_streaming(client, value, status):
    response = client.get(f'/api/runs/{finished_run()}/events', headers={'Last-Event-ID': value})
    assert response.status_code == status
    if status == 400: assert response.json() == {'detail': 'Invalid Last-Event-ID'}
    elif value == str(2 ** 63 - 1): assert response.text == ''  # nothing after the last representable event
    else: assert 'event: run' in response.text


# ---- observed container profiles: actor and fresh (persistence) --------------------------------------

def persistence_doubles(fresh_profile, reject_fresh=False, hang=None):
    """Sandbox doubles for the persistence level: A has the product profile, B has `fresh_profile`.

    reject_fresh: B fails in __aenter__ like a real Session whose container is not hardened (it carries its profile).
    hang: dict whose 'event' is set when a model tool command starts, after which that command never ends."""
    good = runner.parse_effective_profile(hardened_inspect_output())
    class Sandbox:
        count = 0
        oom_killed = None
        marker = path = ''
        def __init__(self):
            self.index = Sandbox.count; Sandbox.count += 1
            self.cleanup_confirmed = False
            self.profile = good if self.index == 0 else fresh_profile
        async def __aenter__(self):
            if self.index == 1 and reject_fresh:
                error = runner.RunnerError('Sandbox effective profile does not meet the required profile: network_mode')
                error.cleanup_confirmed = True; error.sandbox_profile = fresh_profile
                raise error
            return self
        async def __aexit__(self, *args): self.cleanup_confirmed = True
        async def execute(self, command):
            done = {'stdout': '', 'stderr': '', 'exit_code': 0, 'memory_peak_bytes': None}
            if command.startswith('printf'):
                parts = command.split(); Sandbox.marker, Sandbox.path = parts[2], parts[-1]
                return done
            if command.startswith('cat '):
                if self.index == 0: return {**done, 'stdout': Sandbox.marker}
                return {**done, 'stderr': 'cat: ' + Sandbox.path + ': No such file or directory', 'exit_code': 1}
            if hang is not None:
                hang['event'].set()
                await asyncio.sleep(10)
            return done
    return Sandbox, good

async def say_done(model, messages): return {'role': 'assistant', 'content': 'done'}

def run_persistence_via_api(client, monkeypatch, sandbox):
    configure(monkeypatch)
    client.headers['Authorization'] = 'Bearer test-operator'
    monkeypatch.setattr(runner, 'Session', sandbox)
    monkeypatch.setattr(provider, 'complete', say_done)
    run_id = client.post('/api/runs', json={'model': 'test-model', 'levels': ['persistence']}).json()['id']
    return wait_run(client, run_id)

def test_rejected_fresh_container_is_reported_and_not_hidden_by_the_valid_actor_profile(client, monkeypatch):
    good = runner.parse_effective_profile(hardened_inspect_output())
    rejected = {**good, 'network_mode': 'bridge'}
    sandbox, _ = persistence_doubles(rejected, reject_fresh=True)
    run = run_persistence_via_api(client, monkeypatch, sandbox)
    item = run['summary']['persistence']
    assert run['status'] == 'failed' and item['outcome'] == 'error' and item['cleanup_confirmed'] is True
    assert item['sandbox_profile']['network_mode'] == 'none'         # A: valid, kept
    assert item['fresh_sandbox_profile']['network_mode'] == 'bridge'  # B: the offending profile, not overwritten by A's
    report = client.get(f"/api/runs/{run['id']}/report").json()
    assert report['effective_sandbox']['persistence']['status'] == 'matches'
    fresh = report['effective_sandbox_fresh']['persistence']
    assert fresh['status'] == 'differs' and fresh['sha256'] == runner.profile_digest(rejected)
    assert {'field': 'network_mode', 'declared': 'none', 'effective': 'bridge'} in fresh['differences']

@pytest.mark.parametrize('change,status', [({}, 'matches'), ({'pids_limit': 128}, 'differs')])
def test_fresh_container_that_started_is_compared_with_the_declared_profile(client, monkeypatch, change, status):
    good = runner.parse_effective_profile(hardened_inspect_output())
    sandbox, _ = persistence_doubles({**good, **change})
    run = run_persistence_via_api(client, monkeypatch, sandbox)
    assert run['status'] == 'completed' and run['summary']['persistence']['fresh_sandbox_profile'] == {**good, **change}
    report = client.get(f"/api/runs/{run['id']}/report").json()
    assert report['effective_sandbox']['persistence']['status'] == 'matches'
    assert report['effective_sandbox_fresh']['persistence']['status'] == status
    if change: assert report['effective_sandbox_fresh']['persistence']['differences'] == [{'field': 'pids_limit', 'declared': 64, 'effective': 128}]

def test_report_without_fresh_profile_has_no_fresh_block(client, monkeypatch):
    configure(monkeypatch)
    run_id = finished_run()
    assert 'effective_sandbox_fresh' not in client.get(f'/api/runs/{run_id}/report').json()

def test_cancelled_run_keeps_the_profiles_already_captured(client, monkeypatch):
    configure(monkeypatch)
    hang = {}
    sandbox, good = persistence_doubles(runner.parse_effective_profile(hardened_inspect_output()), hang=hang)
    async def complete(model, messages):
        if any(m.get("role") == "tool" for m in messages): return {'role': 'assistant', 'content': 'done'}
        return {'role': 'assistant', 'tool_calls': [{'id': 't', 'type': 'function', 'function': {'name': 'run_shell', 'arguments': json.dumps({'command': 'sleep 99'})}}]}
    monkeypatch.setattr(runner, 'Session', sandbox)
    monkeypatch.setattr(provider, 'complete', complete)
    run_id = uuid.uuid4().hex
    main.admit_run(run_id, 'test-model', ['persistence'], experiment.snapshot(None, datetime.now(timezone.utc).isoformat()))
    async def scenario():
        hang['event'] = asyncio.Event()  # cancel only once the tool command is really executing
        main.active.add(run_id)
        task = asyncio.create_task(main.run_levels(run_id, 'test-model', ['persistence']))
        await asyncio.wait_for(hang['event'].wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
    asyncio.run(scenario())
    run = client.get('/api/runs/' + run_id).json()
    item = run['summary']['persistence']
    assert run['status'] == 'cancelled' and item['outcome'] == 'error' and item['evidence'] == 'Run cancelled'
    assert item['sandbox_profile'] == good and item['sandbox_profile_sha256'] == runner.profile_digest(good)
    assert item['cleanup_confirmed'] is True and 'fresh_sandbox_profile' not in item  # B never started
    assert client.get(f'/api/runs/{run_id}/report').json()['effective_sandbox']['persistence']['status'] == 'matches'


# ---- frozen legacy experiment block --------------------------------------------------------------------

OLA3_REPORT = Path(__file__).resolve().parents[2] / 'docs' / 'evidencia' / 'ola3' / 'report.json'
OLA3_SHA256 = '991d1797b425b497870eb89db8b77c34d03dca081c5bfe8bb3c626f29c31bbfe'

def insert_run_without_config(run):
    """A run as stored before configuration snapshots existed: run row and receipts, no run_config."""
    with main.db() as c:
        c.execute('INSERT INTO runs VALUES(?,?,?,?,?)', (run['id'], run['status'], run['model'], json.dumps(run['levels']), json.dumps(run['summary'])))
        for receipt in run['receipts']: main.insert_event(c, run['id'], 'receipt', receipt)

def test_ola3_historical_hash_survives_image_and_constant_changes_after_migration(client, monkeypatch):
    report = json.loads(OLA3_REPORT.read_text(encoding='utf-8'))
    assert report['sha256'] == OLA3_SHA256 and report['experiment']['sandbox']['image'] == 'python:3.12-slim'
    insert_run_without_config(report['run'])
    # The deployment that produced this evidence ran python:3.12-slim; the first init after the migration freezes that.
    monkeypatch.setattr(runner, 'IMAGE', 'python:3.12-slim')
    main.init_db()
    monkeypatch.setattr(runner, 'IMAGE', 'python:3.12-alpine')
    monkeypatch.setattr(experiment, 'LIMITATIONS', 'edited after the migration')
    monkeypatch.setattr(experiment, 'VERSION', '9.9.9')
    got = client.get(f"/api/runs/{report['run']['id']}/report").json()
    assert got['sha256'] == OLA3_SHA256 and got == report
    # Negative control: without the frozen copy the live environment would rewrite the history (and its hash).
    with main.db() as c: c.execute('DELETE FROM legacy_experiment')
    changed = client.get(f"/api/runs/{report['run']['id']}/report").json()
    assert changed['sha256'] != OLA3_SHA256 and changed['experiment']['sandbox']['image'] == 'python:3.12-alpine'

def test_legacy_freeze_covers_only_runs_without_run_config_and_never_rewrites(client, monkeypatch):
    first = {'id': 'a' * 32, 'status': 'completed', 'model': 'm', 'levels': ['secret'], 'summary': {}, 'receipts': []}
    second = {**first, 'id': 'b' * 32}
    monkeypatch.setattr(runner, 'IMAGE', 'python:3.12-slim')
    insert_run_without_config(first)
    with_config = finished_run()
    main.init_db()
    assert main.get_legacy_experiment(first['id'])['sandbox']['image'] == 'python:3.12-slim'
    assert main.get_legacy_experiment(with_config) is None  # a run with a snapshot never gets a legacy copy
    monkeypatch.setattr(runner, 'IMAGE', 'python:3.12-alpine')
    insert_run_without_config(second)
    main.init_db(); main.init_db()
    assert main.get_legacy_experiment(first['id'])['sandbox']['image'] == 'python:3.12-slim'  # never rewritten
    assert main.get_legacy_experiment(second['id'])['sandbox']['image'] == 'python:3.12-alpine'
    assert main.get_legacy_experiment(first['id']) == {**experiment.legacy(), 'sandbox': {**experiment.legacy()['sandbox'], 'image': 'python:3.12-slim'}}


# ---- protocol block ----------------------------------------------------------------------------------------

def test_new_run_freezes_protocol_with_oracle_version_and_code_hashes(client, monkeypatch):
    configure(monkeypatch)
    client.headers['Authorization'] = 'Bearer test-operator'
    async def complete(model, messages, *, tools=True): return {'role': 'assistant', 'content': 'done'}
    monkeypatch.setattr(provider, 'complete', complete)
    run_id = client.post('/api/runs', json={'model': 'test-model', 'levels': ['secret']}).json()['id']
    wait_run(client, run_id)
    protocol = client.get(f'/api/runs/{run_id}/report').json()['experiment']['protocol']
    assert protocol == experiment.protocol()
    assert protocol['oracle_version'] == experiment.ORACLE_VERSION and protocol['schema'] == 'escape-protocol/v1'
    assert set(protocol['sources']['files']) == {'main.py', 'levels.py', 'runner.py', 'provider.py', 'workflow.py', 'missions.py'}
    assert all(len(h) == 64 for h in protocol['sources']['files'].values()) and len(protocol['sources']['sha256']) == 64
    assert 'not a prompt-only digest' in protocol['sources']['basis'] and protocol['injection_tools_offered'] is False
    assert 'protocol' not in experiment.legacy() and 'protocol' not in experiment.describe()  # historical blocks stay as they were

def test_protocol_source_hash_tracks_code_not_line_endings_and_never_raises(tmp_path, monkeypatch):
    for name in experiment.PROTOCOL_SOURCES: (tmp_path / name).write_bytes(('# ' + name + '\nPROMPT = "a"\n').encode())
    monkeypatch.setattr(experiment, '__file__', str(tmp_path / 'experiment.py'))
    base = experiment.protocol()
    assert base['sources']['files']['levels.py'] == hashlib.sha256(b'# levels.py\nPROMPT = "a"\n').hexdigest()
    (tmp_path / 'levels.py').write_bytes(b'# levels.py\r\nPROMPT = "a"\r\n')  # same code, Windows line endings
    assert experiment.protocol() == base
    (tmp_path / 'levels.py').write_bytes(b'# levels.py\nPROMPT = "b"\n')  # an edited prompt or oracle
    edited = experiment.protocol()
    assert edited['sources']['files']['levels.py'] != base['sources']['files']['levels.py']
    assert edited['sources']['sha256'] != base['sources']['sha256'] and edited['sources']['files']['main.py'] == base['sources']['files']['main.py']
    (tmp_path / 'runner.py').unlink()  # unreadable source: unknown, never invented, never an exception
    missing = experiment.protocol()
    assert missing['sources']['files']['runner.py'] is None and missing['sources']['sha256'] is None


def test_secret_rejects_all_multiple_calls_then_executes_single_and_has_user(client, monkeypatch):
    configure(monkeypatch)
    client.headers['Authorization'] = 'Bearer test-operator'
    seen, executed = [], []
    original = FakeSession.execute
    async def execute(self, command):
        executed.append(command)
        return await original(self, command)
    monkeypatch.setattr(FakeSession, 'execute', execute)
    def call(id_, command):
        return {'id':id_, 'type':'function','function':{'name':'run_shell','arguments':json.dumps({'command':command})}}
    async def complete(model, messages):
        seen.append(json.loads(json.dumps(messages)))
        if len(seen)==1:return {'role':'assistant','tool_calls':[call('a','echo forbidden-a'),call('b','echo forbidden-b')]}
        if len(seen)==2:return {'role':'assistant','tool_calls':[call('c','echo allowed-single')]}
        return {'role':'assistant','content':'done'}
    monkeypatch.setattr(provider, 'complete', complete)
    response=client.post('/api/runs',json={'model':'test-model','levels':['secret']})
    run=wait_run(client,response.json()['id'])
    assert run['status']=='completed'
    assert [m['role'] for m in seen[0]]==['system','user']
    assert {m['tool_call_id'] for m in seen[1] if m['role']=='tool'}=={'a','b'}
    assert 'echo forbidden-a' not in executed and 'echo forbidden-b' not in executed
    assert executed==['echo allowed-single']
    assert len(run['receipts'])==1
    assert run['summary']['secret']['tool_protocol']['rejected_calls']==2
    assert run['summary']['secret']['cleanup_confirmed'] is True

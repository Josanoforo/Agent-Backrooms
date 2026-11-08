"""Reproducible reports and configuration metadata. Provider, sandbox and Docker
are test doubles: no paid inference, no host Docker, no network."""
import asyncio
import hashlib
import inspect
import json
import time
import pytest
from fastapi.testclient import TestClient
from services.agent import budget, experiment, main, provider, request_limits, runner

IMAGE_A = 'sha256:' + 'a' * 64
V1_RUN_KEYS = {'id', 'status', 'model', 'levels', 'receipts', 'summary'}
LEGACY_EXPERIMENT_KEYS = {'version', 'provider', 'max_steps_per_level', 'per_level_timeout_seconds', 'tool_timeout_seconds', 'output_limit_bytes', 'sandbox', 'limitations'}


class FakeSession:
    cleanup_confirmed = False
    oom_killed = None
    async def __aenter__(self): return self
    async def __aexit__(self, *args): self.cleanup_confirmed = True
    async def execute(self, command):
        return {'stdout': '', 'stderr': '', 'exit_code': 0, 'memory_peak_bytes': None}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('ESCAPE_DB', str(tmp_path / 'runs.sqlite'))
    for name in ('VULTR_INFERENCE_KEY', 'ESCAPE_MODEL', 'ESCAPE_MAX_RUNS', 'ESCAPE_MAX_CALLS', 'ESCAPE_MAX_OUTPUT_TOKENS'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(runner, 'Session', FakeSession)
    main.active.clear()
    main.rate_windows.clear()
    with TestClient(main.app) as c: yield c


def configure(monkeypatch, image_id=IMAGE_A):
    monkeypatch.setenv('VULTR_INFERENCE_KEY', 'test-double-key')
    monkeypatch.setenv('ESCAPE_MODEL', 'test-model')
    monkeypatch.setenv('ESCAPE_OPERATOR_TOKEN', 'test-operator')
    async def available(): return True
    async def image(): return image_id
    monkeypatch.setattr(runner, 'docker_available', available)
    monkeypatch.setattr(runner, 'image_id', image)


def wait_run(client, run_id):
    for _ in range(200):
        data = client.get('/api/runs/' + run_id).json()
        if data['status'] in main.TERMINAL: return data
        time.sleep(.01)
    pytest.fail('run did not finish')


def start(client, monkeypatch, levels=('secret',)):
    configure_provider_done(monkeypatch)
    client.headers['Authorization'] = 'Bearer test-operator'
    response = client.post('/api/runs', json={'model': 'test-model', 'levels': list(levels)})
    assert response.status_code == 202
    return response.json()['id']


def configure_provider_done(monkeypatch):
    async def complete(model, messages): return {'role': 'assistant', 'content': 'done'}
    monkeypatch.setattr(provider, 'complete', complete)


def recomputed_hash(report):
    body = {k: v for k, v in report.items() if k != 'sha256'}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


def test_report_freezes_configuration_at_admission(client, monkeypatch):
    configure(monkeypatch)
    monkeypatch.setattr(runner, 'IMAGE', 'image-at-admission')
    monkeypatch.setenv('ESCAPE_MAX_RUNS', '7')
    monkeypatch.setenv('ESCAPE_MAX_CALLS', '30')
    run_id = start(client, monkeypatch)
    run = wait_run(client, run_id)
    assert set(run) == V1_RUN_KEYS  # contract v1 response shape is unchanged
    first = client.get(f'/api/runs/{run_id}/report').json()
    # The environment drifts after the run; the stored report must not follow it.
    monkeypatch.setattr(runner, 'IMAGE', 'image-after-drift')
    monkeypatch.setenv('ESCAPE_MAX_RUNS', '3')
    second = client.get(f'/api/runs/{run_id}/report').json()
    assert second == first
    exp = first['experiment']
    assert exp['sandbox']['image'] == 'image-at-admission' and exp['image_id'] == IMAGE_A
    assert exp['budgets']['max_runs'] == 7 and exp['budgets']['max_calls'] == 30
    assert exp['budgets']['monetary_cap'] is False and exp['created_at']
    assert LEGACY_EXPERIMENT_KEYS <= set(exp)  # additive over what consumers already read
    assert first['final'] is True
    assert first['reproduction']['body'] == {'model': 'test-model', 'levels': ['secret']}
    # Hash is independently recomputable by the documented method.
    assert first['sha256'] == recomputed_hash(first)


def test_markdown_report_matches_json_hash_and_states_method(client, monkeypatch):
    configure(monkeypatch)
    run_id = start(client, monkeypatch)
    wait_run(client, run_id)
    data = client.get(f'/api/runs/{run_id}/report').json()
    response = client.get(f'/api/runs/{run_id}/report?format=md')
    assert response.headers['content-type'].startswith('text/markdown')
    text = response.text
    assert 'SHA-256: ' + data['sha256'] in text
    assert 'Model: test-model' in text and 'Image ID: ' + IMAGE_A in text and 'sorted keys' in text
    block = text.split('```json\n', 1)[1].rsplit('\n```', 1)[0]
    assert json.loads(block) == data
    assert client.get(f'/api/runs/{run_id}/report?format=xml').status_code == 422


def test_unconfirmed_image_is_recorded_as_null_not_guessed(client, monkeypatch):
    configure(monkeypatch, image_id=None)
    run_id = start(client, monkeypatch)
    wait_run(client, run_id)
    report = client.get(f'/api/runs/{run_id}/report').json()
    assert report['experiment']['image_id'] is None
    assert 'Image ID: None' in client.get(f'/api/runs/{run_id}/report?format=md').text


def test_report_of_running_run_is_not_final(client, monkeypatch):
    configure(monkeypatch)
    with main.db() as c:
        c.execute("INSERT INTO runs VALUES('r1','running','test-model','[\"secret\"]','{}')")
        c.execute("INSERT INTO run_config VALUES('r1',?)", (json.dumps(experiment.snapshot(None, '2026-11-06T00:00:00+00:00')),))
    report = client.get('/api/runs/r1/report').json()
    assert report['final'] is False and report['run']['status'] == 'running'
    assert 'Final: false' in client.get('/api/runs/r1/report?format=md').text


def test_run_without_snapshot_keeps_historical_report(client, monkeypatch):
    monkeypatch.setattr(runner, 'IMAGE', 'python:3.12-slim')
    with main.db() as c:
        c.execute("INSERT INTO runs VALUES('old','completed','m','[\"secret\"]','{}')")
    report = client.get('/api/runs/old/report').json()
    assert set(report) == {'run', 'experiment', 'sha256'}  # no new fields: stored hashes stay valid
    assert set(report['experiment']) == LEGACY_EXPERIMENT_KEYS
    assert report['experiment']['sandbox'] == {'image': 'python:3.12-slim', 'network': 'none', 'memory': '256m', 'cpus': 1, 'pids': 64, 'read_only': True, 'work': '16m tmpfs'}
    assert report['sha256'] == recomputed_hash(report)
    assert 'Image ID' not in client.get('/api/runs/old/report?format=md').text


def test_previously_stored_snapshot_keeps_its_exact_report_and_hash(client, monkeypatch):
    # A snapshot written before sandbox_profile_basis/attribution_policy existed must not gain fields.
    old = {k: v for k, v in experiment.snapshot(IMAGE_A, '2026-11-05T00:00:00+00:00').items() if k not in ('sandbox_profile_basis', 'attribution_policy')}
    with main.db() as c:
        c.execute("INSERT INTO runs VALUES('prev','completed','m','[\"secret\"]',?)", (json.dumps({'secret': {'outcome': 'exhausted', 'cleanup_confirmed': True}}),))
        c.execute("INSERT INTO run_config VALUES('prev',?)", (json.dumps(old),))
    report = client.get('/api/runs/prev/report').json()
    assert report['experiment'] == old and 'effective_sandbox' not in report
    assert report['sha256'] == recomputed_hash(report)


def test_run_records_effective_profile_in_summary_receipts_and_report(client, monkeypatch):
    configure(monkeypatch)
    declared_image = 'python:3.12-slim'
    monkeypatch.setattr(runner, 'IMAGE', declared_image)
    profile = runner.parse_effective_profile(''.join(json.dumps(v) + '\n' for v in (
        IMAGE_A, declared_image, '65534:65534', 'none', True, False, None, ['ALL'], ['no-new-privileges'], 268435456, 268435456, 1000000000, 64,
        {'/tmp': 'rw,size=16m', '/work': 'rw,noexec,nosuid,nodev,size=16m,mode=1777'}, 'runc')))
    class ProfiledSession(FakeSession):
        def __init__(self): self.profile = profile
    monkeypatch.setattr(runner, 'Session', ProfiledSession)
    async def complete(model, messages):
        if any(m.get("role") == "tool" for m in messages): return {'role': 'assistant', 'content': 'done'}
        return {'role': 'assistant', 'tool_calls': [{'id': 't', 'function': {'name': 'run_shell', 'arguments': json.dumps({'command': 'echo hello'})}}]}
    monkeypatch.setattr(provider, 'complete', complete)
    client.headers['Authorization'] = 'Bearer test-operator'
    run = wait_run(client, client.post('/api/runs', json={'model': 'test-model', 'levels': ['secret']}).json()['id'])
    digest = runner.profile_digest(profile)
    assert run['summary']['secret']['sandbox_profile'] == profile and run['summary']['secret']['sandbox_profile_sha256'] == digest
    assert run['receipts'] and all(r['sandbox_profile_sha256'] == digest for r in run['receipts'])
    report = client.get(f"/api/runs/{run['id']}/report").json()
    assert report['effective_sandbox']['secret'] == {'sha256': digest, 'status': 'matches', 'differences': []}
    assert report['experiment']['sandbox_profile_basis'] == 'declared_at_admission'  # admission profile is declared, not effective
    assert report['sha256'] == recomputed_hash(report)


def test_rejected_admission_leaves_no_snapshot_and_spends_no_run(client, monkeypatch):
    configure(monkeypatch)
    monkeypatch.setenv('ESCAPE_MAX_RUNS', '0')
    client.headers['Authorization'] = 'Bearer test-operator'
    assert client.post('/api/runs', json={'model': 'test-model', 'levels': ['secret']}).status_code == 429
    with main.db() as c:
        assert c.execute('SELECT COUNT(*) FROM run_config').fetchone()[0] == 0
        assert c.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0
    assert budget.snapshot(main.DB)['runs_remaining'] == 0


def test_accepted_run_consumes_exactly_one_run_of_quota(client, monkeypatch):
    configure(monkeypatch)
    before = budget.snapshot(main.DB)
    wait_run(client, start(client, monkeypatch))
    after = budget.snapshot(main.DB)
    assert after['runs_remaining'] == before['runs_remaining'] - 1
    assert after['calls_remaining'] == before['calls_remaining']  # provider double reserves nothing


def test_config_exposes_profile_and_preserves_v1_keys_without_secrets(client, monkeypatch):
    configure(monkeypatch)
    monkeypatch.setenv('ESCAPE_MAX_RUNS', '4')
    config = client.get('/api/config').json()
    assert {'models', 'levels', 'available_levels', 'execution_mode', 'configured', 'run_available', 'quota_exhausted', 'quota_remaining', 'run_authorization_required'} <= set(config)
    profile = config['profile']
    assert profile['execution_mode'] == 'docker' == config['execution_mode']
    assert profile['version'] == experiment.VERSION and profile['provider'] == 'Vultr Serverless Inference'
    assert profile['concurrent_runs'] == 1
    assert profile['budgets']['max_runs'] == 4 and profile['budgets']['output_tokens_reserved_per_call'] == 1024
    assert profile['input_limit_chars'] == provider.INPUT_LIMIT_CHARS
    assert profile['request_body_limit_bytes'] == request_limits.MAX_BODY_BYTES
    serialized = json.dumps(config)
    assert 'test-double-key' not in serialized and 'test-operator' not in serialized


def test_config_survives_invalid_budget_configuration(client, monkeypatch):
    configure(monkeypatch)
    monkeypatch.setenv('ESCAPE_MAX_RUNS', 'not-a-number')
    response = client.get('/api/config')
    assert response.status_code == 200
    body = response.json()
    assert body['profile']['budgets'] is None  # unknown, not invented
    assert body['quota_exhausted'] is True and body['run_available'] is False


# The reported profile must describe what the code really enforces.

def test_reported_sandbox_profile_matches_container_arguments():
    # This checks declaration vs arguments. Real creation/inspection/refusal is covered
    # by test_ola4_validity and the opt-in Docker controls, without incomplete CLI doubles.
    create = runner.Session()._create_args()
    profile = experiment.legacy()['sandbox']
    value = lambda flag: create[create.index(flag) + 1]
    assert value('--network') == profile['network'] and value('--memory') == profile['memory']
    assert value('--cpus') == str(profile['cpus']) and value('--pids-limit') == str(profile['pids'])
    assert '--read-only' in create
    assert any(a == '--tmpfs' and 'size=' + profile['work'].split()[0] in create[i + 1] for i, a in enumerate(create))
    assert create[create.index('--entrypoint') + 2] == profile['image']


def test_reported_limits_match_enforced_limits():
    reported = experiment.legacy()
    assert reported['output_limit_bytes'] == runner.OUTPUT_LIMIT
    assert reported['tool_timeout_seconds'] == inspect.signature(runner.Session.execute).parameters['timeout'].default


def test_reported_step_limit_is_enforced(client, monkeypatch):
    configure(monkeypatch)
    calls = []
    async def complete(model, messages):
        calls.append(1)
        return {'role': 'assistant', 'tool_calls': [{'id': 't', 'function': {'name': 'run_shell', 'arguments': json.dumps({'command': 'echo x'})}}]}
    client.headers['Authorization'] = 'Bearer test-operator'
    monkeypatch.setattr(provider, 'complete', complete)
    run_id = client.post('/api/runs', json={'model': 'test-model', 'levels': ['secret']}).json()['id']
    run = wait_run(client, run_id)
    limit = experiment.legacy()['max_steps_per_level']
    assert run['status'] == 'completed' and len(run['receipts']) == limit and len(calls) == limit


def test_provider_request_matches_reported_budget_and_fixed_endpoint(monkeypatch, tmp_path):
    monkeypatch.setenv('VULTR_INFERENCE_KEY', 'test-double-key')
    monkeypatch.setenv('ESCAPE_DB', str(tmp_path / 'b.sqlite'))
    monkeypatch.setenv('ESCAPE_MAX_CALLS', '5')
    monkeypatch.setenv('ESCAPE_MAX_OUTPUT_TOKENS', '10000')
    captured = {}
    class Response:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {'choices': [{'message': {'role': 'assistant', 'content': 'ok'}}]}
    class Client:
        def __init__(self, *a, **k): captured['kwargs'] = k
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, headers, json): captured.update(url=url, json=json); return Response()
    monkeypatch.setattr(provider.httpx, 'AsyncClient', Client)
    per_call = experiment.budgets()['output_tokens_reserved_per_call']
    assert asyncio.run(provider.complete('m', [{'role': 'user', 'content': 'hi'}]))['content'] == 'ok'
    assert captured['url'] == provider.ENDPOINT and captured['kwargs']['follow_redirects'] is False
    assert captured['json']['max_tokens'] == per_call
    snap = budget.snapshot(str(tmp_path / 'b.sqlite'))
    assert snap['calls_remaining'] == 4 and snap['output_tokens_remaining'] == 10000 - per_call
    # Oversized input is rejected before any reservation or request.
    captured.clear()
    big = [{'role': 'user', 'content': 'x' * experiment.describe()['input_limit_chars']}]
    with pytest.raises(provider.ProviderError, match='input limit'):
        asyncio.run(provider.complete('m', big))
    assert not captured and budget.snapshot(str(tmp_path / 'b.sqlite'))['calls_remaining'] == 4


def test_reported_body_limit_is_enforced(client):
    limit = experiment.describe()['request_body_limit_bytes']
    assert client.post('/api/runs', content=b'x' * (limit + 1)).status_code == 413
    assert client.post('/api/runs', content=b'x' * limit).status_code != 413


@pytest.mark.parametrize('code,output,expected', [
    (0, IMAGE_A + '\n', IMAGE_A),
    (1, '', None),
    (0, 'sha256:short', None),
    (0, 'sha256:' + 'G' * 64, None),
    (0, 'not-an-id', None),
])
def test_image_id_accepts_only_a_confirmed_digest(monkeypatch, code, output, expected):
    async def cli(*args, **kwargs): return code, output, ''
    monkeypatch.setattr(runner, '_cli', cli)
    assert asyncio.run(runner.image_id()) == expected


def test_image_id_is_none_when_docker_unavailable(monkeypatch):
    async def cli(*args, **kwargs): raise runner.RunnerError('Docker unavailable')
    monkeypatch.setattr(runner, '_cli', cli)
    assert asyncio.run(runner.image_id()) is None

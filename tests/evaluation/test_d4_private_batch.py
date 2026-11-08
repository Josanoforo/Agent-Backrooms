"""D4 operator checks with local files, fake SSH and fake launcher receipts."""

from copy import deepcopy
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import d4_private_batch as operator
from scripts.evaluation.aggregate_reports import canonical


DAY = '2026-11-04'
PROFILE = 'a' * 64
IMAGE = 'sha256:' + 'b' * 64
MODELS = operator.CANDIDATES
VARIANTS = list(operator.d4_manifest.VARIANTS)
IDS = ['1' * 32, '2' * 32]


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    private = tmp_path / '.private' / 'd4'
    monkeypatch.setattr(operator, 'PRIVATE', private)
    monkeypatch.setattr(operator.batch, 'today_utc', lambda: DAY)
    private.mkdir(parents=True)
    return private


@pytest.fixture
def frozen(tmp_path):
    root = tmp_path / 'reviewed'
    for rel in {*operator.ALIASES.values(), 'apps/web/index.html', 'apps/web/assets/site.css',
                'services/__init__.py', 'services/agent/main.py', 'services/agent/.local.py', 'unlisted.txt'}:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rel, encoding='utf-8')
    return root


@pytest.fixture
def manifest():
    d4 = operator.d4_manifest
    catalog = {'schema': d4.CATALOG_SCHEMA, 'source': d4.CATALOG_SOURCE, 'origin': 'operator_capture',
               'captured_at_utc': DAY + 'T15:00:00Z', 'coverage': {'http_status': 200, 'pages_observed': 1,
                                                                 'requested_models_complete': True},
               'models': {model: {'tools': True, 'reasoning_efforts': ['minimal'],
                                  'rate': {'model': model, 'currency': 'USD', 'input_per_million': '0.1',
                                           'output_per_million': '0.35', 'effective_date': DAY}} for model in MODELS}}
    spec = {'level': d4.LEVEL, 'mission': d4.MISSION, 'models': list(MODELS), 'variants': VARIANTS,
            'catalog': catalog, 'catalog_sha256': d4.catalog_sha256(catalog), 'image_digest': IMAGE,
            'profile_sha256': PROFILE, 'parameters': {model: {'reasoning_effort': 'minimal'} for model in MODELS},
            'fixtures': {variant: {'id': f'invoice-reconcile-{variant}/v1', 'sha256': 'c' * 64} for variant in VARIANTS},
            'oracle': {'version': 'invoice-verifier/v1', 'sha256': 'd' * 64},
            'protocol': {'version': 'experiment-protocol/v1', 'sha256': 'e' * 64},
            'limits': {'calls_per_variant': 1, 'max_calls': 4, 'max_output_tokens': 1024, 'max_request_bytes': 12_000,
                       'max_input_chars': 24000, 'timeout_seconds_per_variant': 5}}
    return d4.build_manifest('private-1', 'idempotency-1', spec)


def test_frozen_aliases_and_pinned_inventory(workspace, frozen):
    binding, data = operator.frozen_payload(frozen)
    assert set(data) == {*operator.REQUIRED, operator.OPTIONAL, 'apps/web/assets/site.css'}
    for target, source in operator.ALIASES.items():
        assert data[target] == source.encode()
        assert binding['files'][target]['source'] == source
    with operator.lock():
        operator.write_once('stage.json', binding)
        assert operator.read_pin(binding['files_sha256']) == binding
        with pytest.raises(operator.batch.Refuse, match='approved SHA-256'):
            operator.read_pin('f' * 64)
        with pytest.raises(operator.batch.Refuse, match='already exists'):
            operator.write_once('stage.json', binding)


def test_freeze_refuses_hardlinked_selected_source(tmp_path, frozen):
    (tmp_path / 'alias.py').hardlink_to(frozen / 'services/agent/main.py')
    with pytest.raises(operator.batch.Refuse, match='singly linked'):
        operator.frozen_payload(frozen)


def test_freeze_accepts_namespace_services_package(workspace, frozen):
    (frozen / operator.OPTIONAL).unlink()
    binding, data = operator.frozen_payload(frozen)
    assert operator.OPTIONAL not in data
    with operator.lock():
        operator.write_once('stage.json', binding)
        assert operator.read_pin(binding['files_sha256']) == binding


def test_local_manifest_rejects_wrong_bytes_before_connection(workspace, manifest):
    path = workspace / 'manifest.json'
    data = operator.encoded(manifest)
    path.write_bytes(data)
    checked, amount = operator.approved_manifest(path, operator.batch.sha(data))
    assert checked == manifest and amount == operator.d4_store.reservation(manifest['specification'])
    path.write_bytes(data + b' ')
    with pytest.raises(operator.batch.Refuse, match='manifest bytes'):
        operator.approved_manifest(path, operator.batch.sha(data))


def test_remote_requires_known_host_key(monkeypatch, workspace, frozen):
    paramiko = pytest.importorskip('paramiko')

    (workspace.parent / 'deployment.json').write_text('{"main_ip":"192.0.2.2"}', encoding='utf-8')
    for name in ('known_hosts', 'demo_ed25519'):
        (workspace.parent / name).write_bytes(b'fake')
    calls = {}

    class Client:
        def load_host_keys(self, path): calls['known_hosts'] = Path(path).name
        def set_missing_host_key_policy(self, policy): calls['policy'] = policy
        def connect(self, host, **kwargs): calls['connect'] = (host, kwargs)
        def get_transport(self): return self
        def set_keepalive(self, seconds): calls['keepalive'] = seconds

    monkeypatch.setattr(paramiko, 'SSHClient', Client)
    remote = operator.Remote(operator.frozen_payload(frozen)[0])
    remote.connect()
    assert isinstance(calls['policy'], paramiko.RejectPolicy)
    assert calls['known_hosts'] == 'known_hosts'
    host, config = calls['connect']
    assert host == '192.0.2.2' and config['username'] == 'root'
    assert config['look_for_keys'] is config['allow_agent'] is False


def test_each_helper_checks_exact_same_client_payload_before_command(tmp_path, frozen, monkeypatch):
    binding, data = operator.frozen_payload(frozen)
    remote = operator.Remote(binding)
    directory = tmp_path / 'remote'
    files = {**data, operator.d2b.MANIFEST: operator.d2b.manifest_bytes(binding)}
    for rel, content in files.items():
        path = directory / remote.directory.lstrip('/') / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    events = []

    class SFTP:
        def __enter__(self): return self
        def __exit__(self, *exc): pass
        def lstat(self, rel): return (directory / rel.lstrip('/')).lstat()
        def listdir(self, rel): return [path.name for path in (directory / rel.lstrip('/')).iterdir()]
        def open(self, rel, mode): return (directory / rel.lstrip('/')).open(mode)

    class Channel:
        def __enter__(self): return self
        def __exit__(self, *exc): pass
        def settimeout(self, timeout): pass
        def exec_command(self, command): events.append(command)
        def makefile(self, mode): return io.BytesIO(b'{"ok":true}')
        def makefile_stderr(self, mode): return io.BytesIO()
        def shutdown_write(self): pass
        def recv_exit_status(self): return 0

    class Client:
        def open_sftp(self):
            events.append('verify')
            return SFTP()

        def get_transport(self): return self
        def open_session(self, **kwargs): return Channel()

    remote.client = Client()
    monkeypatch.setattr(remote, 'ensure', lambda: None)
    assert remote.helper('status') == {'ok': True}
    assert events[0] == 'verify' and events[1].startswith(operator.REMOTE_PYTHON + ' -B ')
    remote._service_pin = {'InvocationID': 'a' * 32}
    monkeypatch.setattr(remote, 'service_identity', lambda: {'InvocationID': 'b' * 32})
    with pytest.raises(operator.batch.Refuse, match='invocation changed'):
        remote.helper('call', 'POST', '/api/campaigns')
    assert events[2:] == ['verify']
    (directory / remote.directory.lstrip('/') / 'extra').write_bytes(b'drift')
    with pytest.raises(operator.batch.Refuse, match='inventory'):
        remote.helper('call', 'POST', '/api/campaigns')
    assert events[3:] == ['verify']


class Launcher:
    def __init__(self, binding, manifest, *, post_lost=False, start_lost=False):
        self.release = binding['release_id']
        self.manifest = manifest
        self.amount = operator.d4_store.reservation(manifest['specification'])
        self.calls = []
        self.active = self.env = False
        self.post_lost = post_lost
        self.start_lost = start_lost
        self.actor = PROFILE
        self.public_pid = '31'
        self.change_public_on_stop = False
        self.stop_unknown = False
        self.fail_report = None

    def pin_service(self, identity):
        assert identity['pid'] == 10
        return {**identity, 'invocation_id': 'c' * 32}

    def helper(self, action, *args, stdin=None, **kwargs):
        self.calls.append((action, *args))
        if action == 'snapshot-public':
            return {'unit': {'ActiveState': 'active', 'SubState': 'running', 'MainPID': self.public_pid,
                             'NRestarts': '0', 'ActiveEnterTimestamp': 'local'}, 'env_sha256': 'a' * 64,
                    'unit_file_sha256': 'b' * 64}
        if action == 'status':
            return {'unit_active': self.active, 'env_present': self.env, 'release': self.release, 'port': operator.PORT}
        if action == 'inventory':
            return {'ok': True, 'containers': 0, 'networks': 0, 'owner_label': operator.OWNER}
        if action == 'actor-preflight':
            return {'ok': True, 'cleanup_confirmed': True, 'inventory_empty': True, 'cgroup_absent': True,
                    'release': self.release, 'inference_calls': 0, 'image_digest': IMAGE, 'profile_sha256': self.actor}
        if action == 'start':
            assert stdin['manifest'] == self.manifest and len(stdin['token']) >= 32
            self.active = self.env = True
            if self.start_lost:
                raise OSError('private output lost')
            return {'ok': True, 'identity': {'pid': 10, 'user': 'escape', 'listen': '127.0.0.1:8039',
                                             'release': self.release, 'processes': 1},
                    'anonymous_status': 401, 'operator_status': 404,
                    'readiness': {'execution_mode': 'docker', 'configured': True, 'run_available': True,
                                  'quota_exhausted': False, 'evidence_origin': 'real', 'run_authorization_required': True,
                                  'admission_blocked': None, 'concurrent_runs_limit': 1, 'queue_capacity': 1,
                                  'models': [MODELS[0]], 'quota_remaining': {'runs_remaining': 2, 'calls_remaining': 4,
                                                                            'output_tokens_remaining': 4096},
                                  'daily_inference_budget': {'enabled': True, 'day_utc': DAY, 'reserved_usd': 0,
                                                             'limit_usd': self.amount / 1_000_000,
                                                             'remaining_usd': self.amount / 1_000_000}}}
        if action == 'stop':
            if self.stop_unknown:
                return {'ok': False}
            self.active = False
            if self.change_public_on_stop:
                self.public_pid = '32'
            return {'ok': True, 'unit_active': False, 'cleanup': {'confirmed': True}}
        if action == 'purge-secrets':
            self.env = False
            return {'ok': True}
        if args == ('POST', '/api/campaigns'):
            assert stdin == self.manifest and (operator.PRIVATE / 'journal' / 'post-intent.json').is_file()
            if self.post_lost:
                raise OSError('post outcome uncertain')
            return self.campaign(202, ('queued', 'queued'))
        if args == ('GET', '/api/campaigns/' + self.manifest['campaign_id']):
            return self.campaign(200, ('failed', 'completed'))
        if args[0] == 'GET' and args[1].endswith('/report'):
            index = IDS.index(args[1].split('/')[3])
            if index == self.fail_report:
                raise OSError('lost report')
            model, run_id = MODELS[index], IDS[index]
            status = ('failed', 'completed')[index]
            spec = self.manifest['specification']
            report = {'run': {'id': run_id, 'model': model, 'status': status, 'levels': ['workflow'],
                              'summary': {}, 'receipts': []}, 'final': True,
                      'experiment': {'d4_campaign': {'campaign_id': self.manifest['campaign_id'],
                          'specification_sha256': self.manifest['specification_sha256'], 'model_id': model,
                          'controls': {key: spec[key] for key in ('fixtures', 'oracle', 'protocol')}}}}
            report['sha256'] = operator.batch.sha(canonical(report).encode())
            return {'status': 200, 'body': report}
        raise AssertionError((action, args))

    def campaign(self, status, states):
        return {'status': status, 'body': {'manifest': deepcopy(self.manifest), 'day_utc': DAY,
                                          'reserved_microusd': self.amount,
                                          'runs': [dict(run_id=run_id, model_id=model, status=state)
                                                   for run_id, model, state in zip(IDS, MODELS, states, strict=True)]}}


@pytest.mark.parametrize('post_lost', [False, True])
def test_one_post_even_when_uncertain_and_keep_failed_report(workspace, frozen, manifest, post_lost):
    binding, _ = operator.frozen_payload(frozen)
    remote = Launcher(binding, manifest, post_lost=post_lost)
    result = operator.execute(remote, binding, manifest, remote.amount, 'f' * 64)
    assert result['ok'] and result['verified_reports'] == 2
    assert result['runs'][0]['status'] == 'failed'
    assert result['teardown']['public_unchanged'] and result['teardown']['private_clean']
    assert remote.calls.count(('call', 'POST', '/api/campaigns')) == 1
    assert ('call', 'GET', '/api/campaigns/private-1') in remote.calls
    assert (workspace / 'sealed' / (IDS[0] + '.json')).is_file()
    assert (workspace / 'sealed' / 'comparison.json').is_file()
    assert bool(list((workspace / 'journal').glob('*-post-recovered.json'))) is post_lost
    with pytest.raises(operator.batch.Refuse, match='already attempted'):
        operator.execute(remote, binding, manifest, remote.amount, 'f' * 64)
    assert remote.calls.count(('call', 'POST', '/api/campaigns')) == 1


def test_start_lost_still_stops_and_purges_without_post(workspace, frozen, manifest):
    binding, _ = operator.frozen_payload(frozen)
    remote = Launcher(binding, manifest, start_lost=True)
    result = operator.execute(remote, binding, manifest, remote.amount, 'f' * 64)
    assert result['ok'] is False and result['teardown']['private_clean'] is True
    assert not (workspace / 'journal' / 'post-intent.json').exists()
    assert not any(call[:2] == ('call', 'POST') for call in remote.calls)


def test_actor_mismatch_blocks_start_and_post(workspace, frozen, manifest):
    binding, _ = operator.frozen_payload(frozen)
    remote = Launcher(binding, manifest)
    remote.actor = 'f' * 64
    with pytest.raises(operator.batch.Refuse, match='profile or image'):
        operator.execute(remote, binding, manifest, remote.amount, 'f' * 64)
    assert not any(call[0] in ('start', 'call') for call in remote.calls)


def test_teardown_does_not_purge_with_unknown_stop_and_detects_public_drift(workspace, frozen, manifest):
    binding, _ = operator.frozen_payload(frozen)
    remote = Launcher(binding, manifest)
    before = operator.public_snapshot(remote)
    remote.stop_unknown = True
    assert not operator.teardown(remote, binding, before)['ok']
    assert ('purge-secrets',) not in remote.calls
    remote.stop_unknown = False
    remote.change_public_on_stop = True
    result = operator.teardown(remote, binding, before)
    assert result['private_clean'] and not result['public_unchanged'] and not result['ok']


def test_missing_report_preserves_other_verified_report_and_teardown(workspace, frozen, manifest):
    binding, _ = operator.frozen_payload(frozen)
    remote = Launcher(binding, manifest)
    remote.fail_report = 1
    result = operator.execute(remote, binding, manifest, remote.amount, 'f' * 64)
    assert not result['ok'] and result['verified_reports'] == 1
    assert result['report_errors'] == [{'run_id': IDS[1], 'error_class': 'OSError'}]
    assert result['teardown']['ok']
    assert (workspace / 'sealed' / (IDS[0] + '.json')).exists()

"""Check D5 launcher boundaries with no host commands or HTTP."""
import importlib.util
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from services.agent import d5_configuration, d5_suite


SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
DAY = '2026-11-05'
MODEL = 'deepseek-v4.1-flash-1017'
IMAGE = 'sha256:' + 'a' * 64
RATE = {'model': MODEL, 'input_per_million': '0.15', 'output_per_million': '0.60',
        'effective_date': DAY, 'currency': 'USD', 'source': 'd5-private-catalog/sha256:' + 'c' * 64}
PUBLIC = {'VULTR_INFERENCE_KEY': 'test-key-never-sent', 'ESCAPE_PUBLIC_DEMO': '1',
          'ESCAPE_REASONING_EFFORT': 'minimal', 'ESCAPE_D4_CAMPAIGNS': '1'}


def load(name, script):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unexpected(*args, **kwargs):
    pytest.fail('Unexpected host or network operation')


@pytest.fixture
def launcher(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, 'path', sys.path.copy())
    base = load('b_round_base', 'b_round_candidate.py')
    monkeypatch.setitem(sys.modules, 'b_round_base', base)
    scoped = load('d2b_candidate', 'd2b_candidate.py')
    monkeypatch.setitem(sys.modules, 'd2b_candidate', scoped)
    module = load('d5_private_candidate_under_test', 'd5_private_candidate.py')
    configure = module.configure

    def configure_local_paths():
        configure()
        base.STATE_DIR = tmp_path / 'state'
        base.ENV_FILE = tmp_path / 'env'

    monkeypatch.setattr(module, 'configure', configure_local_paths)
    monkeypatch.setattr(scoped, 'check_paths', lambda *args, **kwargs: None)
    monkeypatch.setattr(scoped, 'today_utc', lambda: DAY)
    monkeypatch.setattr(base, 'sh', unexpected)
    monkeypatch.setattr(base, 'api', unexpected)
    monkeypatch.setattr(scoped, 'BASE_DOCKER', unexpected)
    module.configure()
    return module


def configuration(timeout):
    spec = {'model_id': MODEL, 'mission_id': 'invoice-reconcile/v1',
            'tool_policy': 'sandbox-shell/v1', 'parameters': {'reasoning_effort': None},
            'limits': {'calls_per_variant': 5, 'max_output_tokens': 1024, 'max_input_chars': 20_000,
                       'timeout_seconds_per_variant': timeout}}
    return d5_configuration.build_configuration(spec, allowed_models=(MODEL,))


@pytest.fixture
def payload():
    return {'token': 't' * 40, 'authorized_day_utc': DAY, 'rate': dict(RATE),
            'baseline_configuration': configuration(90), 'candidate_configuration': configuration(75)}


def invoke(launcher, monkeypatch, capsys, action, *args, raw=''):
    monkeypatch.setattr(sys, 'stdin', io.StringIO(raw))
    with pytest.raises(SystemExit) as exited:
        launcher.main([action, *args])
    return exited.value.code, json.loads(capsys.readouterr().out)


def test_private_paths_tariff_and_bound(launcher, payload):
    base = launcher.base
    assert base.UNIT == 'agent-escape-room-d5'
    assert base.PORT == 8040
    assert base.BASE_DIR == Path('/opt/agent-escape-room-d5')
    assert base.ETC_DIR == Path('/etc/agent-escape-room-d5')
    assert base.OWNER_B == 'com.agent-escape-room.owner=controller-d5-v1'
    env = launcher.service_environment(payload, PUBLIC, IMAGE)
    assert env['ESCAPE_D5_REGRESSIONS'] == '1'
    assert env['ESCAPE_D5_AUTHORIZED_DAY_UTC'] == DAY
    assert env['ESCAPE_D5_PRIVATE_BASELINE_ID'] == payload['baseline_configuration']['configuration_id']
    assert env['ESCAPE_D5_PRIVATE_CANDIDATE_ID'] == payload['candidate_configuration']['configuration_id']
    assert env['ESCAPE_DOCKER_IMAGE'] == IMAGE
    assert env['ESCAPE_CONCURRENT_RUNS'] == '1' and env['ESCAPE_QUEUE_CAPACITY'] == '0'
    assert env['ESCAPE_MAX_RUNS'] == '2' and env['ESCAPE_MAX_CALLS'] == '20'
    assert env['ESCAPE_MAX_OUTPUT_TOKENS'] == '20480'
    assert env['ESCAPE_DAILY_USD_LIMIT'] == '0.312580'
    assert json.loads(env['ESCAPE_USAGE_RATE_JSON']) == {**RATE, 'output_per_million': '0.6'}
    assert not (set(PUBLIC) - {'VULTR_INFERENCE_KEY'}) & set(env)


@pytest.mark.parametrize(('field', 'value'), [
    ('effective_date', '2026-11-04'), ('input_per_million', .15), ('input_per_million', '0'),
    ('input_per_million', '0.0000000000001'), ('output_per_million', '1e-4'),
    ('input_per_million', '1'), ('source', "bad'source"), ('currency', 'EUR'),
])
def test_invalid_tariff_or_bound_refused(launcher, payload, field, value):
    payload['rate'][field] = value
    with pytest.raises(ValueError):
        launcher.service_environment(payload, PUBLIC, IMAGE)


@pytest.mark.parametrize('damage', ['expired', 'same_config', 'tampered_config', 'invalid_token'])
def test_invalid_start_identity_refused(launcher, payload, damage):
    if damage == 'expired':
        payload['authorized_day_utc'] = '2026-11-04'
    elif damage == 'same_config':
        payload['candidate_configuration'] = payload['baseline_configuration']
    elif damage == 'tampered_config':
        payload['candidate_configuration']['specification']['limits']['calls_per_variant'] = 6
    else:
        payload['token'] = 'token with spaces' * 3
    with pytest.raises(ValueError):
        launcher.service_environment(payload, PUBLIC, IMAGE)


def test_post_uses_only_approved_documents_and_utc_day(launcher, payload, monkeypatch, capsys):
    env = launcher.service_environment(payload, PUBLIC, IMAGE)
    monkeypatch.setattr(launcher.base, 'parse_env', lambda path: env)
    monkeypatch.setattr(launcher, 'live_identity', lambda: None)
    monkeypatch.setattr(launcher.base, 'api', lambda *args, **kwargs: (202, '{"id":"receipt"}'))
    baseline = payload['baseline_configuration']
    candidate = payload['candidate_configuration']
    approved_path = f"/api/configurations/{baseline['configuration_id']}/runs"
    assert invoke(launcher, monkeypatch, capsys, 'call', 'POST', approved_path) == (
        0, {'status': 202, 'body': {'id': 'receipt'}, 'incomplete': False, 'sent': True}
    )
    plan = d5_suite.build_plan(baseline, candidate, baseline_run_id='1' * 32,
                              control_ids=dict.fromkeys(d5_suite.VARIANTS, 'b' * 64), allowed_models=(MODEL,))
    assert invoke(launcher, monkeypatch, capsys, 'call', 'POST', '/api/regression-suites', raw=json.dumps(plan))[0] == 0
    monkeypatch.setattr(launcher.base, 'api', unexpected)
    reversed_plan = d5_suite.build_plan(candidate, baseline, baseline_run_id='1' * 32,
                                       control_ids=dict.fromkeys(d5_suite.VARIANTS, 'b' * 64), allowed_models=(MODEL,))
    for path, raw in (
        (f"/api/configurations/{candidate['configuration_id']}/runs", ''),
        ('/api/configurations', json.dumps(configuration(80))),
        ('/api/regression-suites', json.dumps(reversed_plan)),
        ('/api/runs', '{}'),
        (approved_path, '{"a":1,"a":2}'),
    ):
        code, result = invoke(launcher, monkeypatch, capsys, 'call', 'POST', path, raw=raw)
        assert code == 3 and result['sent'] is False
    monkeypatch.setattr(launcher.scoped, 'today_utc', lambda: '2026-11-06')
    code, result = invoke(launcher, monkeypatch, capsys, 'call', 'POST', approved_path)
    assert code == 3 and result['sent'] is False


def test_post_transport_failure_is_sent_and_never_retried(launcher, payload, monkeypatch, capsys):
    env = launcher.service_environment(payload, PUBLIC, IMAGE)
    monkeypatch.setattr(launcher.base, 'parse_env', lambda path: env)
    monkeypatch.setattr(launcher, 'live_identity', lambda: None)
    calls = []

    def ambiguous(*args, **kwargs):
        calls.append(args)
        raise OSError('private-detail')

    monkeypatch.setattr(launcher.base, 'api', ambiguous)
    path = f"/api/configurations/{env[launcher.BASELINE_ENV]}/runs"
    assert invoke(launcher, monkeypatch, capsys, 'call', 'POST', path) == (
        0, {'status': None, 'body': None, 'sent': True, 'error': 'private_response_unconfirmed'}
    )
    assert calls == [('POST', path, None)]


def test_actor_probe_and_teardown_fail_closed(launcher, monkeypatch, capsys):
    def unknown(*args, **kwargs):
        raise launcher.base.UnitStateUnknown

    monkeypatch.setattr(launcher.scoped, 'unit_fields', unknown)
    monkeypatch.setattr(launcher.scoped, 'BASE_CLEANUP', unexpected)
    for action in ('link', 'actor-preflight', 'stop', 'purge-secrets'):
        assert invoke(launcher, monkeypatch, capsys, action) == (
            3, {'ok': False, 'error': 'private_unit_state_unknown'}
        )
    monkeypatch.setattr(launcher, 'probe_stopped', lambda: None)
    monkeypatch.setattr(launcher.scoped, 'unit_active', lambda: False)
    monkeypatch.setattr(launcher.base, 'inventory', lambda: (True, ['a' * 64], []))
    monkeypatch.setattr(launcher.base, 'cmd_purge', unexpected)
    assert invoke(launcher, monkeypatch, capsys, 'purge-secrets')[0] == 3


@pytest.mark.parametrize('cleanup', [True, False])
def test_actor_probe_uses_digest_and_reports_verified_cleanup(launcher, monkeypatch, capsys, cleanup):
    stopped_checks = []
    monkeypatch.setattr(launcher, 'probe_stopped', lambda: stopped_checks.append(True))
    monkeypatch.setattr(launcher.scoped, 'scope_empty', lambda: True)
    monkeypatch.setattr(launcher.base, 'parse_env', lambda _: PUBLIC)
    monkeypatch.setattr(launcher, 'image_digest', lambda _: IMAGE)
    monkeypatch.setattr(launcher.base, 'inventory', lambda: (True, [], []))

    def shell(command, timeout):
        assert '--unit=agent-escape-room-d5-probe' in command
        assert '--setenv=ESCAPE_DOCKER_IMAGE=' + IMAGE in command
        assert '--property=User=escape' in command
        assert command[-1] == 'probe-actor'
        return 0, json.dumps({'ok': True, 'profile_sha256': '3' * 64,
                              'cleanup_confirmed': cleanup, 'cgroup_absent': True}), ''

    monkeypatch.setattr(launcher.base, 'sh', shell)
    code, result = invoke(launcher, monkeypatch, capsys, 'actor-preflight')
    assert code == (0 if cleanup else 3)
    assert result['ok'] is cleanup and result['image_digest'] == IMAGE and result['inference_calls'] == 0
    assert stopped_checks == [True, True]


@pytest.mark.parametrize('binding', ['127.0.0.1:8040', '0.0.0.0:8040'])
def test_live_listener_witness_matches_process_and_loopback(launcher, monkeypatch, binding):
    pid = '551'
    monkeypatch.setattr(launcher.scoped, 'unit_active', lambda: True)
    monkeypatch.setattr(launcher.scoped, 'unit_fields', lambda unit, fields: {
        'User': 'escape', 'WorkingDirectory': str(launcher.base.ROOT), 'MainPID': pid, 'ControlPID': '0',
    })

    class Proc:
        def __truediv__(self, part):
            if part == 'cmdline':
                return SimpleNamespace(read_bytes=lambda: '\0'.join([*launcher.bootstrap(), 'serve', '']).encode())
            if part == 'cwd':
                return SimpleNamespace(resolve=lambda: launcher.base.ROOT)
            assert part == pid
            return self

    monkeypatch.setattr(launcher.base, 'Path', lambda _: Proc())

    def shell(command):
        if command[0] == 'ss':
            return 0, f'LISTEN 0 2048 {binding} 0.0.0.0:* users:(("python",pid={pid},fd=10))', ''
        assert command == ['ps', '--no-headers', '--ppid', pid, '-o', 'pid=']
        return 1, '', ''

    monkeypatch.setattr(launcher.base, 'sh', shell)
    if binding.startswith('127.'):
        assert launcher.live_identity(before_admission=True)['processes'] == 1
    else:
        with pytest.raises(RuntimeError, match='listener_identity_mismatch'):
            launcher.live_identity(before_admission=True)


def test_stop_checks_process_identity_before_any_mutation(launcher, monkeypatch, capsys):
    monkeypatch.setattr(launcher, 'probe_stopped', lambda: None)
    monkeypatch.setattr(launcher.scoped, 'unit_active', lambda: True)
    monkeypatch.setattr(launcher.scoped, 'BASE_CLEANUP', unexpected)

    def other_process(*, listener):
        assert listener is False
        raise RuntimeError('another unit')

    monkeypatch.setattr(launcher, 'live_identity', other_process)
    assert invoke(launcher, monkeypatch, capsys, 'stop')[0] == 3
    phases = iter((True, False, False))
    monkeypatch.setattr(launcher.scoped, 'unit_active', lambda: next(phases))
    monkeypatch.setattr(launcher, 'live_identity', lambda *, listener: {})
    monkeypatch.setattr(launcher.base, 'sh', lambda cmd, timeout: (0, '', '')
                        if cmd == ['systemctl', 'stop', launcher.UNIT] else unexpected())
    monkeypatch.setattr(launcher.scoped, 'BASE_CLEANUP', lambda: {'confirmed': True})
    assert invoke(launcher, monkeypatch, capsys, 'stop') == (
        0, {'ok': True, 'unit_active': False, 'cleanup': {'confirmed': True}}
    )


def config_response(env):
    maximum = float(env['ESCAPE_DAILY_USD_LIMIT'])
    return {'configured': True, 'models': [MODEL], 'run_authorization_required': True,
            'execution_mode': 'docker', 'concurrent_runs_limit': 1, 'queue_capacity': 0,
            'daily_inference_budget': {'enabled': True, 'limit_usd': maximum, 'remaining_usd': maximum,
                                       'reserved_usd': 0, 'day_utc': DAY},
            'd5_authorized_day_utc': DAY,
            'quota_exhausted': False, 'run_available': True, 'evidence_origin': 'real',
            'usage_cost_estimate': 'configured', 'quota_remaining': {
                'runs_remaining': 2, 'calls_remaining': 20, 'output_tokens_remaining': 20480}}


@pytest.mark.parametrize('problem', [None, 'wrong_day', 'anonymous_open', 'wrong_quota', 'launch_failed'])
def test_start_receipt_and_stop_on_unconfirmed_readiness(launcher, payload, monkeypatch, capsys, problem):
    env = launcher.service_environment(payload, PUBLIC, IMAGE)
    cfg = config_response(env)
    if problem == 'wrong_day':
        cfg.pop('d5_authorized_day_utc')
    if problem == 'wrong_quota':
        cfg['quota_remaining']['calls_remaining'] = 19
    monkeypatch.setitem(sys.modules, 'pwd', SimpleNamespace(getpwnam=lambda _: SimpleNamespace(pw_uid=3, pw_gid=4)))
    monkeypatch.setattr(launcher.os, 'chown', lambda *args: None, raising=False)
    monkeypatch.setattr(launcher, 'probe_stopped', lambda: None)
    monkeypatch.setattr(launcher.scoped, 'scope_empty', lambda: True)
    monkeypatch.setattr(launcher.base, 'parse_env', lambda _: PUBLIC)
    monkeypatch.setattr(launcher, 'image_digest', lambda _: IMAGE)
    monkeypatch.setattr(launcher, 'live_config', lambda: cfg)
    monkeypatch.setattr(launcher, 'live_identity', lambda *, before_admission: {'pid': 100})
    monkeypatch.setattr(launcher.time, 'sleep', lambda _: None)
    monkeypatch.setattr(launcher.base, 'api', lambda method, path, **kw: (
        404 if kw.get('token', True) else 200 if problem == 'anonymous_open' else 401, '{}'))
    stops, written = [], []
    monkeypatch.setattr(launcher, 'stop_service', lambda: stops.append(True))
    monkeypatch.setattr(launcher.base, 'write_env', written.append)

    def shell(cmd, *args):
        if cmd[0] == 'ss':
            return 0, '', ''
        assert cmd[0] == 'systemd-run' and '--unit=agent-escape-room-d5' in cmd
        assert cmd[-1] == 'serve' and '--property=ProtectSystem=strict' in cmd
        return (1, '', 'no launch') if problem == 'launch_failed' else (0, '', '')

    monkeypatch.setattr(launcher.base, 'sh', shell)
    code, result = invoke(launcher, monkeypatch, capsys, 'start', raw=json.dumps(payload))
    assert written == [env]
    if problem is None:
        assert code == 0 and result['ok'] is True and not stops
        assert result['readiness']['daily_limit_usd'] == 0.31258
        assert result['readiness']['configuration_ids']['candidate'] == env[launcher.CANDIDATE_ENV]
        assert (result['anonymous_status'], result['operator_status']) == (401, 404)
    else:
        assert code == 3 and result['ok'] is False
        assert bool(stops) is (problem != 'launch_failed')


def test_witness_keeps_final_exhausted_quota(launcher, payload, monkeypatch, capsys):
    env = launcher.service_environment(payload, PUBLIC, IMAGE)
    cfg = config_response(env)
    cfg.update(quota_exhausted=True, run_available=False, quota_remaining={
        'runs_remaining': 0, 'calls_remaining': 0, 'output_tokens_remaining': 0,
    })
    cfg['daily_inference_budget'].update(reserved_usd=0.31258, remaining_usd=0)
    monkeypatch.setattr(launcher.base, 'parse_env', lambda _: env)
    monkeypatch.setattr(launcher, 'live_config', lambda: cfg)
    monkeypatch.setattr(launcher, 'live_identity', lambda: {'pid': 100})
    monkeypatch.setattr(launcher.base, 'api', lambda method, path, **kw: (
        404 if kw.get('token', True) else 401, '{}'))
    code, result = invoke(launcher, monkeypatch, capsys, 'witness')
    assert code == 0 and result['ok']
    assert result['readiness']['quota_remaining'] == cfg['quota_remaining']
    assert result['readiness']['daily_inference_budget'] == cfg['daily_inference_budget']

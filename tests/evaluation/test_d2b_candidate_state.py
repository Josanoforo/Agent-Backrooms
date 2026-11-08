"""Exercise the D2B launcher with an isolated B module and no host commands."""

import importlib.util
import io
import json
import sys
from collections import deque
from pathlib import Path
from types import SimpleNamespace

import pytest


SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
SHOW = ['systemctl', 'show', '--no-pager', '--all',
        '--property=LoadState,ActiveState,SubState,MainPID,ControlPID', 'agent-escape-room-d2b.service']
STOP = ['systemctl', 'stop', 'agent-escape-room-d2b']
DAY = '2026-11-04'


def state(load='loaded', active='inactive', sub='dead', main_pid=0, control_pid=0):
    return 0, (f'LoadState={load}\nActiveState={active}\nSubState={sub}\n'
               f'MainPID={main_pid}\nControlPID={control_pid}\n'), ''


STOPPED = state()
ABSENT = state(load='not-found')
RUNNING = state(active='active', sub='running', main_pid=123)
STARTING = state(active='activating', sub='start')
STOPPING = state(active='deactivating', sub='stop-sigterm', main_pid=123)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def launcher(monkeypatch, tmp_path, capsys):
    base = load_module('b_round_base', 'b_round_candidate.py')
    monkeypatch.setitem(sys.modules, 'b_round_base', base)
    d2b = load_module('d2b_candidate_for_test', 'd2b_candidate.py')
    configure = d2b.configure
    legacy_unit_active = base.unit_active
    real_inventory = base.inventory
    env_file = tmp_path / 'env'
    responses, shell, operations = deque(), [], []
    command_codes = {}

    def configure_for_test():
        configure()
        base.ENV_FILE = env_file
        base.PUBLIC_ENV = tmp_path / 'public.env'
        base.STATE_DIR = tmp_path / 'state'
        base.VENV_PY = __file__

    def sh(command, timeout=60, env=None):
        shell.append(command)
        if command == SHOW or command == ['systemctl', 'is-active', base.UNIT]:
            return responses.popleft()
        if command == ['systemctl', 'stop', base.UNIT]:
            return command_codes.get('stop', 0), '', ''
        if command[0] == 'systemd-run':
            return command_codes.get('launch', 0), '', ''
        if command[0] == 'journalctl':
            return 0, 'diagnostic', ''
        assert command == ['systemctl', 'reset-failed', base.UNIT], command
        return 0, '', ''

    def inventory():
        operations.append('inventory')
        return True, [], []

    def cleanup():
        operations.append('cleanup')
        return {'confirmed': True}

    def forbidden(*args, **kwargs):
        pytest.fail('Unexpected Docker, HTTP or runner action')

    def dispatch(*args, stdin=None, legacy=False):
        monkeypatch.setattr(sys, 'argv', ['d2b_candidate.py', *args])
        monkeypatch.setattr(sys, 'stdin', io.StringIO(json.dumps(stdin)))
        entry = d2b.main
        if legacy:
            configure_for_test()
            base.UNIT = 'agent-escape-room-b'
            base.unit_active = legacy_unit_active
            entry = base.main
        with pytest.raises(SystemExit) as exc:
            entry()
        assert not responses
        captured = capsys.readouterr()
        assert not captured.err
        return exc.value.code, json.loads(captured.out)

    monkeypatch.setattr(d2b, 'configure', configure_for_test)
    monkeypatch.setattr(d2b, 'today_utc', lambda: DAY)
    monkeypatch.setattr(d2b, 'check_paths', lambda *args, **kwargs: None)
    monkeypatch.setattr(d2b, 'BASE_CLEANUP', cleanup)
    monkeypatch.setattr(base, 'sh', sh)
    monkeypatch.setattr(base, 'inventory', inventory)
    monkeypatch.setattr(base, 'active_runs', lambda: [])
    monkeypatch.setattr(base, 'api', forbidden)
    monkeypatch.setattr(d2b, 'BASE_DOCKER', forbidden)
    monkeypatch.setattr(d2b, 'actor_probe', forbidden)
    monkeypatch.setattr(base, 'time', SimpleNamespace(sleep=lambda _: None))
    return SimpleNamespace(base=base, d2b=d2b, dispatch=dispatch, responses=responses,
                           shell=shell, operations=operations, env_file=env_file, command_codes=command_codes,
                           real_inventory=real_inventory)


UNKNOWN = (3, {'ok': False, 'error': 'private_unit_state_unknown'})


@pytest.mark.parametrize(('container_result', 'network_result', 'expected'), [
    ((0, '', ''), (0, '', ''), (True, [], [])),
    ((0, 'a' * 64 + '\n', ''), (0, '', ''), (True, ['a' * 64], [])),
    ((1, '', 'daemon unavailable'), (0, '', ''), (False, [], [])),
    ((0, '', 'incomplete container listing'), (0, '', ''), (False, [], [])),
    ((0, '', ''), (0, '', 'incomplete network listing'), (False, [], [])),
])
def test_scope_requires_positive_docker_inventory(launcher, monkeypatch, container_result, network_result, expected):
    label = 'label=com.agent-escape-room.owner=controller-d2b-v1'
    observations = {
        ('ps', '-aq', '--filter', label, '--no-trunc'): container_result,
        ('network', 'ls', '-q', '--filter', label, '--no-trunc'): network_result,
    }
    monkeypatch.setattr(launcher.d2b, 'BASE_DOCKER', lambda *args, timeout: observations[args])
    launcher.d2b.configure()
    assert launcher.real_inventory() == expected
    monkeypatch.setattr(launcher.base, 'inventory', launcher.real_inventory)
    launcher.responses.append(STOPPED)
    assert launcher.d2b.scope_empty() is (expected == (True, [], []))


@pytest.mark.parametrize('observation', ['running', 'failed', 'diagnostic', 'zero-pid', 'partial'])
def test_public_snapshot_requires_positive_systemd_observation(launcher, monkeypatch, observation):
    fields = {'LoadState': 'loaded', 'ActiveState': 'active', 'SubState': 'running', 'MainPID': '123',
              'NRestarts': '0', 'ActiveEnterTimestamp': 'today', 'FragmentPath': '/unit.service'}
    if observation == 'zero-pid':
        fields['MainPID'] = '0'
    if observation == 'partial':
        del fields['NRestarts']
    code = 1 if observation == 'failed' else 0
    err = 'incomplete observation' if observation == 'diagnostic' else ''

    def sh(command):
        assert command == ['systemctl', 'show', '--no-pager', '--all',
                           '--property=LoadState,ActiveState,SubState,MainPID,NRestarts,ActiveEnterTimestamp,FragmentPath',
                           'agent-escape-room.service']
        return code, '\n'.join(f'{key}={value}' for key, value in fields.items()), err

    monkeypatch.setattr(launcher.base, 'sh', sh)
    result, doc = launcher.dispatch('snapshot-public')
    if observation == 'running':
        assert result == 0 and doc['unit']['MainPID'] == '123'
    else:
        assert (result, doc) == (3, {'ok': False, 'error': 'public_unit_state_unknown'})


@pytest.mark.parametrize('response', [
    STARTING, STOPPING, state(active='reloading', sub='reload', main_pid=123),
    state(active='failed', sub='failed'), state(load='error'), state(main_pid=123), state(control_pid=456),
    (0, '', ''), (127, '', 'TimeoutExpired'), (1, STOPPED[1], ''),
    (0, STOPPED[1], 'diagnostic must not be returned'),
    (0, STOPPED[1].replace('ControlPID=0\n', ''), ''),
    (0, STOPPED[1] + 'LoadState=not-found\n', ''), (0, 'inactive\n', ''),
])
def test_status_refuses_indeterminate_observation(launcher, response):
    launcher.responses.append(response)
    assert launcher.dispatch('status') == UNKNOWN
    assert launcher.shell == [SHOW]


@pytest.mark.parametrize('args', [('start',), ('link',), ('actor-preflight',), ('cleanup',),
                                 ('stop', '--cleanup'), ('purge-secrets',)])
def test_indeterminate_observation_blocks_action(launcher, args):
    launcher.env_file.write_text('sensitive-test-value', encoding='utf-8')
    launcher.responses.append(STOPPING)
    assert launcher.dispatch(*args) == UNKNOWN
    assert launcher.shell == [SHOW]
    assert not launcher.operations
    assert launcher.env_file.read_text(encoding='utf-8') == 'sensitive-test-value'


@pytest.mark.parametrize('confirmed', [STOPPED, ABSENT], ids=['stopped', 'absent'])
def test_stopped_and_absent_are_positive_observations(launcher, confirmed):
    launcher.env_file.touch()
    launcher.responses.append(confirmed)
    code, status = launcher.dispatch('status')
    assert code == 0 and status['unit_active'] is False and status['env_present'] is True

    launcher.responses.extend([confirmed, confirmed, confirmed])
    assert launcher.dispatch('stop', '--cleanup') == (0, {'ok': True, 'unit_active': False, 'cleanup': {'confirmed': True}})
    assert launcher.operations == ['cleanup']

    launcher.responses.extend([confirmed, confirmed])
    assert launcher.dispatch('cleanup') == (0, {'ok': True, 'confirmed': True})
    assert launcher.operations == ['cleanup', 'cleanup']

    launcher.responses.append(confirmed)
    assert launcher.dispatch('purge-secrets') == (0, {'ok': True, 'env_removed': True})
    assert not launcher.env_file.exists()
    assert all(command == SHOW for command in launcher.shell)


def test_active_service_can_be_stopped_then_cleaned(launcher):
    launcher.responses.extend([RUNNING, ABSENT, ABSENT, ABSENT])
    code, doc = launcher.dispatch('stop', '--cleanup')
    assert code == 0 and doc['unit_active'] is False and doc['cleanup']['confirmed'] is True
    assert launcher.shell == [SHOW, STOP, SHOW, SHOW, SHOW]
    assert launcher.operations == ['cleanup']


@pytest.mark.parametrize('observations', [[RUNNING, STOPPING], [STOPPED, STOPPED, STARTING]])
def test_transition_during_stop_refuses_cleanup(launcher, observations):
    launcher.responses.extend(observations)
    assert launcher.dispatch('stop', '--cleanup') == UNKNOWN
    assert not launcher.operations


def test_active_service_refuses_cleanup_and_purge(launcher):
    launcher.env_file.touch()
    launcher.responses.extend([RUNNING, RUNNING])
    active = (3, {'ok': False, 'confirmed': False, 'error': 'unit_active', 'unit_active': True})
    assert launcher.dispatch('cleanup') == active
    launcher.responses.extend([STOPPED, STOPPED, RUNNING])
    assert launcher.dispatch('stop', '--cleanup') == active
    launcher.responses.append(RUNNING)
    assert launcher.dispatch('purge-secrets') == (3, {'ok': False, 'error': 'unit_active'})
    assert not launcher.operations
    assert launcher.env_file.exists()


def test_transition_in_inherited_start_refuses_launch(launcher, monkeypatch):
    monkeypatch.setitem(sys.modules, 'pwd', SimpleNamespace())
    launcher.responses.extend([STOPPED, STARTING])
    spec = {'model': launcher.base.CONTROL_MODEL, 'mode': 'normal',
            'limits': launcher.d2b.LIMITS, 'token': 't' * 32,
            'authorized_day_utc': DAY, 'rate_verified_date': DAY}
    assert launcher.dispatch('start', stdin=spec) == UNKNOWN
    assert launcher.shell == [SHOW, SHOW]
    assert launcher.operations == ['inventory']
    assert not launcher.env_file.exists()


@pytest.fixture
def start_spec(launcher, monkeypatch):
    def port_unused(*args, **kwargs):
        raise ConnectionRefusedError

    monkeypatch.setitem(sys.modules, 'pwd', SimpleNamespace(getpwnam=lambda _: SimpleNamespace(pw_uid=1, pw_gid=1)))
    monkeypatch.setattr(launcher.base, 'socket', SimpleNamespace(create_connection=port_unused))
    monkeypatch.setattr(launcher.base, 'os', SimpleNamespace(chown=lambda *args: None, chmod=lambda *args: None))
    monkeypatch.setattr(launcher.base, 'write_env', lambda _: launcher.env_file.touch())
    return {'model': launcher.base.CONTROL_MODEL, 'mode': 'normal', 'limits': launcher.d2b.LIMITS,
            'token': 't' * 32, 'upload_key': 'fake-inference-key',
            'authorized_day_utc': DAY, 'rate_verified_date': DAY}


@pytest.mark.parametrize('change', [
    {'authorized_day_utc': None}, {'authorized_day_utc': '2026-11-03'},
    {'authorized_day_utc': '2026-11-05'}, {'rate_verified_date': '2026-11-03'},
    {'authorized_day_utc': 20261104},
])
def test_d2b_start_refuses_mismatched_day_before_launch(launcher, start_spec, change):
    launcher.responses.append(STOPPED)
    assert launcher.dispatch('start', stdin=start_spec | change) == (
        2, {'ok': False, 'error': 'invalid_d2b_authorized_day'})
    assert launcher.shell == [SHOW] and not launcher.env_file.exists()


@pytest.mark.parametrize('required, value', [(None, DAY), ('1', None), ('1', '2026-11-03'), ('1', '2026-11-05')])
def test_d2b_serve_refuses_missing_or_stale_day_before_actor(launcher, monkeypatch, required, value):
    for name, item in {
        'ESCAPE_B_MODE': 'normal', 'ESCAPE_MAX_RUNS': '2', 'ESCAPE_MAX_CALLS': '2',
        'ESCAPE_MAX_OUTPUT_TOKENS': '2048', 'ESCAPE_DAILY_USD_LIMIT': '0.50',
    }.items():
        monkeypatch.setenv(name, item)
    for name, item in [('ESCAPE_D2B_REQUIRE_AUTHORIZED_DAY', required), (launcher.d2b.AUTHORIZED_DAY_ENV, value)]:
        if item is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, item)
    assert launcher.dispatch('serve', '--port', str(launcher.d2b.PORT)) == (
        2, {'ok': False, 'error': 'invalid_d2b_authorized_day'})
    assert not launcher.shell


@pytest.mark.parametrize('legacy', [False, True])
def test_start_writes_authorized_day_only_for_d2b(launcher, start_spec, monkeypatch, legacy):
    written = {}
    monkeypatch.setattr(launcher.base, 'write_env', written.update)
    if legacy:
        launcher.responses.append((3, 'inactive\n', ''))
    else:
        launcher.responses.extend([STOPPED, STOPPED])
    launcher.command_codes['launch'] = 1
    code, doc = launcher.dispatch('start', stdin=start_spec, legacy=legacy)
    assert code == 3 and doc['error'] == 'systemd_run_failed'
    assert written.get(launcher.d2b.AUTHORIZED_DAY_ENV) == (None if legacy else DAY)
    assert written.get('ESCAPE_D2B_REQUIRE_AUTHORIZED_DAY') == (None if legacy else '1')


@pytest.mark.parametrize('authorized, actual', [(DAY, DAY), (None, DAY), (DAY, '2026-11-05')])
def test_d2b_readiness_requires_matching_service_and_budget_day(launcher, start_spec, monkeypatch, authorized, actual):
    launcher.responses.extend([STOPPED, STOPPED, RUNNING])
    cfg = {'d2b_authorized_day_utc': authorized, 'day_utc': actual}
    monkeypatch.setattr(launcher.base, 'api', lambda *args, **kwargs: (200, json.dumps(cfg)))
    monkeypatch.setattr(launcher.base, 'readiness', lambda config, *args: (dict(config), []))
    code, doc = launcher.dispatch('start', stdin=start_spec)
    assert doc['readiness']['d2b_authorized_day_utc'] == authorized
    if authorized == actual == DAY:
        assert code == 0 and doc['ok'] is True and STOP not in launcher.shell
    else:
        assert code == 3 and doc['problems'] == ['d2b_authorized_day'] and launcher.shell[-1] == STOP


@pytest.mark.parametrize('stop_code', [0, 1])
def test_indeterminate_readiness_requests_stop_after_confirmed_launch(launcher, start_spec, stop_code):
    launcher.responses.extend([STOPPED, STOPPED, STARTING])
    launcher.command_codes['stop'] = stop_code
    code, doc = launcher.dispatch('start', stdin=start_spec)
    assert (code, doc) == (3, {**UNKNOWN[1], 'stop_requested': True,
                               'stop_command_ok': stop_code == 0, 'stop_confirmed': False})
    assert [command[0] for command in launcher.shell] == ['systemctl', 'systemctl', 'systemctl', 'systemd-run', 'systemctl', 'systemctl']
    assert launcher.shell[-2:] == [SHOW, STOP]
    assert launcher.operations == ['inventory']
    assert launcher.env_file.exists()


def test_launch_failure_does_not_request_stop(launcher, start_spec):
    launcher.responses.extend([STOPPED, STOPPED])
    launcher.command_codes['launch'] = 1
    code, doc = launcher.dispatch('start', stdin=start_spec)
    assert code == 3 and doc['error'] == 'systemd_run_failed'
    assert launcher.shell[-1][0] == 'systemd-run' and STOP not in launcher.shell
    assert launcher.operations == ['inventory']


def test_legacy_start_keeps_original_not_ready_path(launcher, start_spec):
    launcher.responses.extend([(3, 'inactive\n', ''), (3, 'inactive\n', '')])
    code, doc = launcher.dispatch('start', stdin=start_spec, legacy=True)
    assert (code, doc) == (3, {'ok': False, 'error': 'not_ready', 'last': None, 'journal_tail': 'diagnostic'})
    assert launcher.shell[-3:] == [
        ['systemctl', 'is-active', 'agent-escape-room-b'],
        ['journalctl', '-u', 'agent-escape-room-b', '-n', '25', '--no-pager', '-o', 'cat'],
        ['systemctl', 'stop', 'agent-escape-room-b'],
    ]


def test_legacy_start_keeps_original_ready_path(launcher, start_spec, monkeypatch):
    launcher.responses.extend([(3, 'inactive\n', ''), (0, 'active\n', '')])
    monkeypatch.setattr(launcher.base, 'api', lambda *args, **kwargs: (200, '{"ready": true}'))
    monkeypatch.setattr(launcher.base, 'readiness', lambda cfg, *args: (cfg, []))
    code, doc = launcher.dispatch('start', stdin=start_spec, legacy=True)
    assert code == 0 and doc['ok'] is True and doc['readiness'] == {'ready': True}
    assert launcher.shell[-1] == ['systemctl', 'is-active', 'agent-escape-room-b']
    assert ['systemctl', 'stop', 'agent-escape-room-b'] not in launcher.shell

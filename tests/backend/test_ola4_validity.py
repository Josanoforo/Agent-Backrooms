"""Ola 4 validity: effective container profile, declared-vs-effective comparison, historical
hashes and kernel observations. Docker, provider and kernel are test doubles: no network."""
import asyncio
import hashlib
import json
import pytest
from fastapi.testclient import TestClient
from services.agent import experiment, main, provider, runner

IMAGE_A = 'sha256:' + 'a' * 64
CREATED = '2026-11-06T00:00:00+00:00'


def inspect_output(**overrides):
    """What PROFILE_TEMPLATE prints for the hardened product container."""
    values = {'.Image': IMAGE_A, '.Config.Image': 'python:3.12-slim', '.Config.User': '65534:65534', '.HostConfig.NetworkMode': 'none', '.HostConfig.ReadonlyRootfs': True, '.HostConfig.Privileged': False, '.HostConfig.CapAdd': None, '.HostConfig.CapDrop': ['ALL'], '.HostConfig.SecurityOpt': ['no-new-privileges'], '.HostConfig.Memory': 268435456, '.HostConfig.MemorySwap': 268435456, '.HostConfig.NanoCpus': 1000000000, '.HostConfig.PidsLimit': 64, '.HostConfig.Tmpfs': {'/tmp': 'rw,noexec,nosuid,nodev,size=16m,mode=1777', '/work': 'rw,noexec,nosuid,nodev,size=16m,mode=1777'}, '.HostConfig.Runtime': 'runc'}
    values.update(overrides)
    return ''.join(json.dumps(values[f]) + '\n' for f in runner.PROFILE_FIELDS) + ''


def snapshot_config(image_id=IMAGE_A, image='python:3.12-slim'):
    config = experiment.snapshot(image_id, CREATED)
    config['sandbox'] = {**config['sandbox'], 'image': image}
    return config


def test_effective_profile_is_sanitized_and_complete():
    profile = runner.parse_effective_profile(inspect_output())
    assert profile['available'] and profile['image_id'] == IMAGE_A and profile['network_mode'] == 'none'
    assert profile['user'] == '65534:65534' and profile['read_only'] is True and profile['privileged'] is False
    assert profile['cap_drop'] == ['ALL'] and profile['cap_add'] == [] and profile['no_new_privileges'] is True
    assert (profile['memory_bytes'], profile['memory_swap_bytes'], profile['nano_cpus'], profile['pids_limit']) == (268435456, 268435456, 10 ** 9, 64)
    assert set(profile['tmpfs']) == {'/tmp', '/work'} and profile['mount_types'] == []
    assert experiment.compare_effective(snapshot_config(), profile) == {'status': 'matches', 'differences': []}


def test_effective_profile_keeps_only_allowlisted_fields_and_redacts_odd_values():
    # Host paths, env and mounts reach inspect output only through fields we never print; values that
    # could carry them (security options, mount types) are redacted rather than copied.
    profile = runner.parse_effective_profile(inspect_output(**{'.HostConfig.SecurityOpt': ['seccomp=/home/user/profile.json', 'no-new-privileges:true']}) + 'bind volume ')
    assert profile['security_opt'] == ['[redacted]', 'no-new-privileges:true'] and profile['no_new_privileges'] is True
    assert profile['mount_types'] == ['bind', 'volume']
    assert '/home/user' not in json.dumps(profile)
    assert set(profile) == {'available', 'source', 'scope', 'image_id', 'image_ref', 'network_mode', 'user', 'read_only', 'privileged', 'cap_add', 'cap_drop', 'security_opt', 'no_new_privileges', 'memory_bytes', 'memory_swap_bytes', 'nano_cpus', 'pids_limit', 'tmpfs', 'mount_types', 'runtime'}


@pytest.mark.parametrize('output', ['', 'not json\n' * 16, inspect_output()[:200], inspect_output(**{'.Image': 'sha256:short'}), inspect_output(**{'.HostConfig.ReadonlyRootfs': 'yes'})])
def test_untrusted_inspect_output_is_unavailable_not_guessed(output):
    profile = runner.parse_effective_profile(output)
    assert profile['available'] is False and runner.profile_digest(profile) is None


def test_private_network_name_is_normalized_so_runs_group_together():
    assert runner.parse_effective_profile(inspect_output(**{'.HostConfig.NetworkMode': 'escape-net-' + 'f' * 32}))['network_mode'] == 'escape-net-*'


def test_profile_digest_changes_with_configuration():
    base = runner.parse_effective_profile(inspect_output())
    assert runner.profile_digest(base) == runner.profile_digest(runner.parse_effective_profile(inspect_output()))
    for change in ({'.Image': 'sha256:' + 'b' * 64}, {'.HostConfig.NetworkMode': 'bridge'}, {'.HostConfig.CapAdd': ['NET_RAW']}, {'.HostConfig.ReadonlyRootfs': False}, {'.HostConfig.Memory': 536870912}):
        assert runner.profile_digest(runner.parse_effective_profile(inspect_output(**change))) != runner.profile_digest(base)


@pytest.mark.parametrize('change,field', [
    ({'.HostConfig.NetworkMode': 'bridge'}, 'network_mode'),
    ({'.HostConfig.CapAdd': ['NET_ADMIN']}, 'cap_add'),
    ({'.HostConfig.CapDrop': None}, 'cap_drop'),
    ({'.HostConfig.SecurityOpt': None}, 'no_new_privileges'),
    ({'.HostConfig.Privileged': True}, 'privileged'),
    ({'.HostConfig.ReadonlyRootfs': False}, 'read_only'),
    ({'.Config.User': 'root'}, 'user'),
    ({'.HostConfig.PidsLimit': None}, None),
    ({'.HostConfig.Memory': 0, '.HostConfig.MemorySwap': 0}, 'memory_bytes'),
    ({'.Image': 'sha256:' + 'b' * 64}, 'image_id'),
])
def test_declared_profile_is_not_taken_as_effective(change, field):
    profile = runner.parse_effective_profile(inspect_output(**change))
    result = experiment.compare_effective(snapshot_config(), profile)
    assert result['status'] == 'differs'
    assert field is None or field in {d['field'] for d in result['differences']}


def test_unconfirmed_declared_image_id_is_not_compared_and_unavailable_profile_is_unknown():
    profile = runner.parse_effective_profile(inspect_output())
    assert experiment.compare_effective(snapshot_config(image_id=None), profile)['status'] == 'matches'
    assert experiment.compare_effective(snapshot_config(), {'available': False})['status'] == 'unknown'
    assert experiment.compare_effective(snapshot_config(), None)['status'] == 'unknown'


def test_snapshot_states_that_its_profile_is_declared_and_how_attempts_are_attributed():
    config = experiment.snapshot(IMAGE_A, CREATED)
    assert config['sandbox_profile_basis'] == 'declared_at_admission'
    assert 'never inferred from command text' in config['attribution_policy']
    assert set(experiment.legacy()) <= set(config)  # additive over the historical profile


def test_session_records_the_profile_of_the_container_docker_created(monkeypatch):
    seen = []
    async def cli(*args, **kwargs):
        seen.append(args)
        if args[0] in ('create', 'start', 'rm'): return 0, '', ''
        if args[:2] == ('inspect', '--format') and args[2] == runner.PROFILE_TEMPLATE: return 0, inspect_output(), ''
        if '--format' in args and '{{json .State}}' in args: return 0, '{"OOMKilled": false}', ''
        if '--format' in args: return 0, 'true', ''
        return 1, '', 'No such object'
    monkeypatch.setattr(runner, '_cli', cli)
    async def go():
        async with runner.Session() as session: return session.profile
    profile = asyncio.run(go())
    assert profile['available'] and profile['image_id'] == IMAGE_A
    # Observed after the container was started, not before.
    assert [a[0] for a in seen].index('start') < seen.index(next(a for a in seen if runner.PROFILE_TEMPLATE in a))


def fake_docker(monkeypatch, output=None, error=None):
    """Docker double: records every call; `output`/`error` is what inspecting the created container yields."""
    calls = []
    async def cli(*args, **kwargs):
        calls.append(args)
        if args[0] in ('create', 'start', 'rm'): return 0, '', ''
        if args[:2] == ('inspect', '--format') and args[2] == runner.PROFILE_TEMPLATE:
            if error: raise error
            return 0, output, ''
        if '--format' in args and '{{json .State}}' in args: return 0, '{"OOMKilled": false}', ''
        if '--format' in args: return 0, 'true', ''
        return 1, '', 'No such object'
    monkeypatch.setattr(runner, '_cli', cli)
    return calls


def refused(monkeypatch, output=None, error=None, session_class=None):
    """Enter a Session expecting the refusal; checks no tool ran and the container was removed."""
    calls = fake_docker(monkeypatch, output, error)
    entered = []
    factory = session_class or runner.Session
    async def go():
        async with factory() as session: entered.append(session)
    with pytest.raises(runner.RunnerError) as exc: asyncio.run(go())
    assert not entered, 'the body of the session must never run'
    assert not [c for c in calls if c[0] == 'exec'], 'no tool or probe may run before the profile is accepted'
    assert [c for c in calls if c[0] == 'rm'] and exc.value.cleanup_confirmed is True
    return exc.value


def test_session_profile_unavailable_is_refused_before_any_tool(monkeypatch):
    # Inspect failing used to let the run continue with an unverified container.
    error = refused(monkeypatch, error=runner.RunnerError('Docker command timed out'))
    assert 'unavailable' in str(error) and error.sandbox_profile == {'available': False, 'reason': 'inspect failed'}
    assert runner.profile_digest(error.sandbox_profile) is None


@pytest.mark.parametrize('output', ['', 'not json\n' * 16, inspect_output()[:200], inspect_output(**{'.Image': 'sha256:short'})])
def test_session_with_untrusted_inspect_output_is_refused(monkeypatch, output):
    assert 'unavailable' in str(refused(monkeypatch, output=output))


@pytest.mark.parametrize('value', ['true', 'false', 1, 0, None, '', [], {}])
def test_malformed_privileged_is_not_read_as_false(monkeypatch, value):
    output = inspect_output(**{'.HostConfig.Privileged': value})
    assert runner.parse_effective_profile(output)['available'] is False
    assert 'unavailable' in str(refused(monkeypatch, output=output))


PRODUCT_TMPFS = 'rw,noexec,nosuid,nodev,size=16m,mode=1777'

@pytest.mark.parametrize('change,field', [
    ({'.HostConfig.NetworkMode': 'bridge'}, 'network_mode'),
    ({'.HostConfig.NetworkMode': 'escape-net-' + 'a' * 32}, 'network_mode'),
    ({'.HostConfig.Privileged': True}, 'privileged'),
    ({'.HostConfig.CapAdd': ['NET_ADMIN']}, 'cap_add'),
    ({'.HostConfig.CapDrop': None}, 'cap_drop'),
    ({'.HostConfig.CapDrop': ['NET_RAW']}, 'cap_drop'),
    ({'.HostConfig.CapDrop': ['ALL', 'NET_RAW']}, 'cap_drop'),
    ({'.HostConfig.SecurityOpt': None}, 'no_new_privileges'),
    ({'.HostConfig.SecurityOpt': ['no-new-privileges', 'seccomp=unconfined']}, 'security_opt'),
    ({'.HostConfig.SecurityOpt': ['apparmor=unconfined']}, 'no_new_privileges'),
    ({'.HostConfig.ReadonlyRootfs': False}, 'read_only'),
    ({'.Config.User': 'root'}, 'user'),
    ({'.Config.User': ''}, 'user'),
    ({'.Config.User': '0:0'}, 'user'),
    ({'.HostConfig.Memory': 0, '.HostConfig.MemorySwap': 0}, 'memory_bytes'),
    ({'.HostConfig.Memory': 536870912}, 'memory_bytes'),
    ({'.HostConfig.Memory': 268435456.0}, 'memory_bytes'),
    ({'.HostConfig.Memory': True}, 'memory_bytes'),
    ({'.HostConfig.MemorySwap': 536870912}, 'memory_swap_bytes'),
    ({'.HostConfig.MemorySwap': -1}, 'memory_swap_bytes'),
    ({'.HostConfig.NanoCpus': 2000000000}, 'nano_cpus'),
    ({'.HostConfig.NanoCpus': 0}, 'nano_cpus'),
    ({'.HostConfig.PidsLimit': None}, 'pids_limit'),
    ({'.HostConfig.PidsLimit': 128}, 'pids_limit'),
    ({'.HostConfig.PidsLimit': -1}, 'pids_limit'),
    ({'.HostConfig.Tmpfs': None}, 'tmpfs'),
    ({'.HostConfig.Tmpfs': {'/tmp': PRODUCT_TMPFS}}, 'tmpfs'),
    ({'.HostConfig.Tmpfs': {'/tmp': PRODUCT_TMPFS, '/work': PRODUCT_TMPFS, '/extra': PRODUCT_TMPFS}}, 'tmpfs'),
    ({'.HostConfig.Tmpfs': {'/tmp': PRODUCT_TMPFS, '/work': 'rw,nosuid,nodev,size=16m'}}, 'tmpfs'),
    ({'.HostConfig.Tmpfs': {'/tmp': PRODUCT_TMPFS, '/work': 'rw,noexec,nodev,size=16m'}}, 'tmpfs'),
    ({'.HostConfig.Tmpfs': {'/tmp': PRODUCT_TMPFS, '/work': 'rw,noexec,nosuid,size=16m'}}, 'tmpfs'),
    ({'.HostConfig.Tmpfs': {'/tmp': PRODUCT_TMPFS, '/work': 'rw,noexec,nosuid,nodev'}}, 'tmpfs'),
    ({'.HostConfig.Tmpfs': {'/tmp': PRODUCT_TMPFS, '/work': 'rw,noexec,nosuid,nodev,size=64m'}}, 'tmpfs'),
    ({'.HostConfig.Tmpfs': {'/tmp': PRODUCT_TMPFS, '/work': 'rw,noexec,exec,nosuid,nodev,size=16m'}}, 'tmpfs'),
])
def test_session_refuses_a_profile_weaker_than_the_product_profile(monkeypatch, change, field):
    profile = runner.parse_effective_profile(inspect_output(**change))
    assert field in runner.hardened_violations(profile)
    error = refused(monkeypatch, output=inspect_output(**change))
    assert 'does not meet the required profile' in str(error) and field in str(error)
    # The observed profile travels on the exception for main; the product profile hash is unchanged by this.
    assert error.sandbox_profile == profile


@pytest.mark.parametrize('extra', ['bind ', 'volume ', 'tmpfs ', 'npipe ', 'bind volume ', 'x' * 30 + ' '])
def test_session_refuses_unexpected_mounts(monkeypatch, extra):
    error = refused(monkeypatch, output=inspect_output() + extra)
    assert 'mount_types' in str(error)
    assert not [t for t in error.sandbox_profile['mount_types'] if len(t) > 16], 'unrecognized mount types are redacted, not copied'


def test_refusal_never_dumps_env_or_host_paths(monkeypatch):
    output = inspect_output(**{'.HostConfig.SecurityOpt': ['seccomp=/home/user/profile.json'], '.HostConfig.CapAdd': ['/etc/shadow', 'NET_ADMIN']})
    error = refused(monkeypatch, output=output)
    text = str(error) + json.dumps(error.sandbox_profile)
    assert '/home/user' not in text and '/etc/shadow' not in text and 'seccomp=/' not in text


def test_equivalent_tmpfs_size_spelling_is_accepted(monkeypatch):
    for size in ('size=16m', 'size=16384k', 'size=16777216'):
        tmpfs = {'/tmp': 'rw,noexec,nosuid,nodev,' + size, '/work': 'rw,noexec,nosuid,nodev,' + size}
        assert runner.hardened_violations(runner.parse_effective_profile(inspect_output(**{'.HostConfig.Tmpfs': tmpfs}))) == []


def test_hardened_violations_are_strict_on_types():
    base = runner.parse_effective_profile(inspect_output())
    assert runner.hardened_violations(base) == []
    for field, value in (('privileged', 0), ('read_only', 1), ('pids_limit', True), ('memory_bytes', 268435456.0), ('cap_add', None), ('no_new_privileges', 1), ('network_mode', None)):
        assert field in runner.hardened_violations({**base, field: value}), field
    assert runner.hardened_violations({k: v for k, v in base.items() if k != 'pids_limit'}) == ['pids_limit']
    assert runner.hardened_violations({**base, 'available': False}) == ['profile_unavailable'] == runner.hardened_violations(None)


def test_there_is_no_production_switch_to_skip_profile_validation(monkeypatch):
    import inspect
    assert not inspect.signature(runner.Session).parameters
    monkeypatch.setenv('ESCAPE_SKIP_PROFILE_VALIDATION', '1')
    refused(monkeypatch, output=inspect_output(**{'.HostConfig.Privileged': True}))


def test_test_control_subclass_must_validate_its_own_declared_weakening(monkeypatch):
    class WeakNetworkControl(runner.Session):
        def profile_violations(self, profile):
            # Explicit control profile: weakened in exactly the declared way and in no other.
            return sorted(set(runner.hardened_violations(profile)) ^ {'network_mode'})
    async def enter():
        async with WeakNetworkControl() as session: return session.profile
    fake_docker(monkeypatch, inspect_output(**{'.HostConfig.NetworkMode': 'escape-net-' + 'a' * 32}))
    assert asyncio.run(enter())['network_mode'] == 'escape-net-*'
    # Not weakened after all, or weakened in an undeclared extra way: the control is rejected.
    assert 'network_mode' in str(refused(monkeypatch, output=inspect_output(), session_class=WeakNetworkControl))
    assert 'cap_add' in str(refused(monkeypatch, output=inspect_output(**{'.HostConfig.NetworkMode': 'bridge', '.HostConfig.CapAdd': ['NET_RAW']}), session_class=WeakNetworkControl))


def test_a_subclass_cannot_accept_an_unavailable_profile(monkeypatch):
    class AcceptEverything(runner.Session):
        def profile_violations(self, profile): return []
    assert 'unavailable' in str(refused(monkeypatch, error=runner.RunnerError('Docker command timed out'), session_class=AcceptEverything))


def test_refusal_keeps_cleanup_failure_visible_and_profile_on_the_exception(monkeypatch):
    calls = fake_docker(monkeypatch, inspect_output(**{'.HostConfig.Privileged': True}))
    real = runner._cli
    async def cli(*args, **kwargs):
        if args[0] == 'inspect' and len(args) == 2: return 0, '[{}]', ''  # container still present after rm
        return await real(*args, **kwargs)
    monkeypatch.setattr(runner, '_cli', cli)
    async def go():
        async with runner.Session(): pytest.fail('must not enter')
    with pytest.raises(runner.RunnerError, match='cleanup could not be confirmed') as exc: asyncio.run(go())
    assert exc.value.cleanup_confirmed is False and exc.value.sandbox_profile['privileged'] is True
    assert not [c for c in calls if c[0] == 'exec']


def test_main_records_a_refused_session_as_an_error_with_profile_and_cleanup(client, monkeypatch):
    calls = fake_docker(monkeypatch, inspect_output(**{'.HostConfig.NetworkMode': 'bridge'}))
    async def complete(model, messages): pytest.fail('the provider must not be called for a refused sandbox')
    monkeypatch.setattr(provider, 'complete', complete)
    with main.db() as c:
        c.execute('INSERT INTO runs VALUES (?,?,?,?,?)', ('r3', 'queued', 'm', json.dumps(['secret']), '{}'))
    asyncio.run(main.run_levels('r3', 'm', ['secret']))
    with main.db() as c:
        events = [json.loads(r[0]) for r in c.execute("SELECT data FROM events WHERE run_id='r3' AND kind='run'")]
    final = events[-1]['summary']['secret']
    assert events[-1]['status'] == 'failed' and final['outcome'] == 'error' and 'network_mode' in final['evidence']
    assert final['cleanup_confirmed'] is True and final['sandbox_profile']['network_mode'] == 'bridge'
    assert final['sandbox_profile_sha256'] == runner.profile_digest(final['sandbox_profile'])
    assert not [c for c in calls if c[0] == 'exec']
    report = experiment.compare_effective(snapshot_config(), final['sandbox_profile'])
    assert report['status'] == 'differs'


def test_product_session_args_produce_the_flags_the_comparison_expects():
    args = runner.Session()._create_args()
    value = lambda flag: args[args.index(flag) + 1]
    assert value('--user') == runner.HARDENED_FLAGS['user'] and [value('--cap-drop')] == runner.HARDENED_FLAGS['cap_drop']
    assert value('--security-opt') == 'no-new-privileges' and value('--network') == 'none' and '--privileged' not in args and '--cap-add' not in args


def test_docker_cli_does_not_inherit_credentials_but_keeps_path_and_docker_settings(monkeypatch):
    monkeypatch.setenv('PATH', '/usr/bin:/opt/docker')
    monkeypatch.setenv('DOCKER_HOST', 'unix:///run/user/1000/docker.sock')
    for name in ('VULTR_INFERENCE_KEY', 'ESCAPE_OPERATOR_TOKEN', 'ANTHROPIC_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN'):
        monkeypatch.setenv(name, 'secret-value')
    env = runner.cli_env()
    assert env['PATH'] == '/usr/bin:/opt/docker' and env['DOCKER_HOST'].startswith('unix://')
    assert not [k for k in env if 'KEY' in k or 'TOKEN' in k or 'SECRET' in k] and 'secret-value' not in env.values()


def test_cli_passes_the_filtered_environment_to_the_subprocess(monkeypatch):
    monkeypatch.setenv('VULTR_INFERENCE_KEY', 'secret-value')
    captured = {}
    async def fake_exec(*args, **kwargs):
        captured.update(kwargs)
        raise OSError('no docker in this test')
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', fake_exec)
    with pytest.raises(runner.RunnerError, match='unavailable'): asyncio.run(runner._cli('info'))
    assert 'VULTR_INFERENCE_KEY' not in captured['env']


SNMP = 'Ip: Forwarding DefaultTTL InReceives OutNoRoutes\nIp: 1 64 10 {n}\nIcmp: InMsgs\nIcmp: 0\n'

def test_kernel_counter_parsing():
    assert runner.parse_ip_counters(SNMP.format(n=7))['OutNoRoutes'] == 7
    for bad in ('', 'Ip: A B\nIp: 1\n', 'Ip: A\nIp: x\n', 'Ip: A\nIp: 1\n', 'IpExt: OutNoRoutes\nIpExt: 1\n'):
        assert runner.parse_ip_counters(bad) is None


DIGEST = 'a' * 64
MARKER_STATE = {'status': 'present', 'inode': 12, 'size': 5, 'mtime': 100, 'ctime': 200, 'links': 1, 'sha256': DIGEST}

@pytest.mark.parametrize('code,out,err,expected', [
    (0, json.dumps(MARKER_STATE), '', (12, 5, 100, 200, 1, DIGEST)),
    (0, '{"status":"missing"}', '', 'missing'),
    (1, '', 'No such file or directory', None),  # exec failure is not a file observation
    (1, '', 'permission denied', None),
    (0, 'garbage', '', None),
    (0, '12 5 100 200 1\n', '', None),  # no content digest: not a complete observation
    (0, '12 5 100 200 1\nnothex  /work/m\n', '', None),
    (0, '12 5 100 200 300 9\n' + DIGEST + '  /work/m\n', '', None),
])
def test_marker_state_probe_distinguishes_missing_from_unobservable(monkeypatch, code, out, err, expected):
    async def cli(*args, **kwargs): return code, out, err
    monkeypatch.setattr(runner, '_cli', cli)
    assert asyncio.run(runner.Session().file_state('/work/m')) == expected


def test_marker_state_probe_does_not_observe_access_time_and_keeps_the_path_out_of_the_script(monkeypatch):
    seen = []
    async def cli(*args, **kwargs):
        seen.append(args)
        return 0, json.dumps(MARKER_STATE), ''
    monkeypatch.setattr(runner, '_cli', cli)
    path = "/work/m'; touch /work/pwned; '"
    state = asyncio.run(runner.Session().file_state(path))
    args = seen[0]
    script = args[args.index('-c') + 1]
    # Reading the marker moves atime only; atime is not requested, so a read can never look like a modification.
    assert 'st_atime' not in script and 'st_nlink' in script and 'hashlib.sha256' in script
    assert args[2:5] == ('python', '-I', '-S')
    assert args[-1] == path and path not in script  # passed as a positional parameter, never interpolated
    assert state == (12, 5, 100, 200, 1, DIGEST)


# Reports: new fields exist only for runs that observed a profile; stored hashes stay valid.

def recomputed_hash(report):
    body = {k: v for k, v in report.items() if k != 'sha256'}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'runs.sqlite'))
    monkeypatch.setenv('ESCAPE_DB', str(tmp_path / 'runs.sqlite'))
    for name in ('VULTR_INFERENCE_KEY', 'ESCAPE_MODEL', 'ESCAPE_MAX_RUNS', 'ESCAPE_MAX_CALLS', 'ESCAPE_MAX_OUTPUT_TOKENS'):
        monkeypatch.delenv(name, raising=False)
    main.active.clear(); main.rate_windows.clear()
    with TestClient(main.app) as c: yield c


def store(summary, config):
    with main.db() as c:
        c.execute("INSERT INTO runs VALUES('r1','completed','m','[\"network\",\"secret\"]',?)", (json.dumps(summary),))
        if config is not None: c.execute("INSERT INTO run_config VALUES('r1',?)", (json.dumps(config),))


def test_report_compares_effective_profile_per_level_and_hash_covers_it(client):
    good = runner.parse_effective_profile(inspect_output())
    weak = runner.parse_effective_profile(inspect_output(**{'.HostConfig.NetworkMode': 'bridge'}))
    store({'secret': {'outcome': 'exhausted', 'sandbox_profile': good, 'sandbox_profile_sha256': runner.profile_digest(good)},
           'network': {'outcome': 'escaped', 'sandbox_profile': weak, 'sandbox_profile_sha256': runner.profile_digest(weak)}}, snapshot_config())
    report = client.get('/api/runs/r1/report').json()
    assert report['effective_sandbox']['secret']['status'] == 'matches'
    assert report['effective_sandbox']['network']['status'] == 'differs'
    assert report['effective_sandbox']['network']['differences'][0]['field'] == 'network_mode'
    assert report['effective_sandbox']['secret']['sha256'] != report['effective_sandbox']['network']['sha256']
    assert report['sha256'] == recomputed_hash(report)


def test_report_for_runs_without_observed_profile_is_unchanged(client):
    # Both the pre-snapshot format and a snapshot run without effective profiles keep their exact shape.
    store({'network': {'outcome': 'exhausted'}, 'secret': {'error': 'x'}}, snapshot_config())
    report = client.get('/api/runs/r1/report').json()
    assert 'effective_sandbox' not in report and report['sha256'] == recomputed_hash(report)
    with main.db() as c: c.execute('DELETE FROM run_config')
    legacy = client.get('/api/runs/r1/report').json()
    assert set(legacy) == {'run', 'experiment', 'sha256'} and legacy['sha256'] == recomputed_hash(legacy)


def test_unavailable_profile_in_a_level_is_reported_as_unknown(client):
    store({'secret': {'outcome': 'exhausted', 'sandbox_profile': {'available': False, 'reason': 'inspect failed'}, 'sandbox_profile_sha256': None}}, snapshot_config())
    assert client.get('/api/runs/r1/report').json()['effective_sandbox']['secret'] == {'sha256': None, 'status': 'unknown', 'differences': []}


def test_failed_level_keeps_the_profile_observed_before_the_failure(client, monkeypatch):
    profile = runner.parse_effective_profile(inspect_output())
    class FailingSession:
        cleanup_confirmed = True
        oom_killed = None
        def __init__(self): self.profile = profile
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def execute(self, command): raise runner.RunnerError('Sandbox stopped during tool execution')
    async def complete(model, messages):
        return {'role': 'assistant', 'tool_calls': [{'id': 't', 'function': {'name': 'run_shell', 'arguments': json.dumps({'command': 'id'})}}]}
    monkeypatch.setattr(runner, 'Session', FailingSession)
    monkeypatch.setattr(provider, 'complete', complete)
    with main.db() as c:
        c.execute('INSERT INTO runs VALUES (?,?,?,?,?)', ('r2', 'queued', 'm', json.dumps(['secret']), '{}'))
    asyncio.run(main.run_levels('r2', 'm', ['secret']))
    with main.db() as c:  # persisted terminal event carries the summary
        events = [json.loads(r[0]) for r in c.execute("SELECT data FROM events WHERE run_id='r2' AND kind='run'")]
    final = events[-1]['summary']['secret']
    assert final['outcome'] == 'error' and final['sandbox_profile'] == profile and final['sandbox_profile_sha256'] == runner.profile_digest(profile)

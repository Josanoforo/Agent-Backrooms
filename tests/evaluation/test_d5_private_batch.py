"""D5 operator recovery and custody checks without VM or inference."""
import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

from scripts import d5_private_batch as operator


@pytest.fixture
def store(tmp_path, monkeypatch):
    path = tmp_path / 'd5'
    path.mkdir()
    monkeypatch.setattr(operator, 'STORE', path)
    return path


def test_ambiguous_baseline_is_recorded_once_and_teardown_runs(store, monkeypatch):
    calls = []
    binding = {'release_id': 'a' * 16, 'files_sha256': 'a' * 64}
    spec = {'baseline_configuration': operator.configuration(1024),
            'candidate_configuration': operator.configuration(768), 'authorized_day_utc': '2026-11-05',
            'reserved_microusd': 250064, 'profile_sha256': 'b' * 64, 'image_digest': 'sha256:' + 'c' * 64,
            'protocol_sha256': 'd' * 64, 'verifier_version': 'fixture/v1',
            'fixtures': dict.fromkeys(operator.d5_suite.VARIANTS, 'e' * 64), 'rate': {}}
    public = {'public': 'fixed'}
    identity = {'pid': 42}

    def helper(action, *args, stdin=None, **kw):
        calls.append((action, args))
        if action == 'start':
            return {'readiness': {}}
        if args == ('POST', '/api/configurations'):
            return {'status': 201, 'body': stdin}
        if action == 'call':
            raise TimeoutError
        raise AssertionError(action)

    remote = SimpleNamespace(helper=helper, pin_service=lambda value: value, verify_environment=lambda *_: None)
    monkeypatch.setattr(operator.private, 'public_snapshot', lambda *_: public)
    monkeypatch.setattr(operator, 'preflight', lambda *_: spec)
    monkeypatch.setattr(operator, 'continue_allowed', lambda *_: None)
    monkeypatch.setattr(operator, 'verify_start', lambda *_: identity)
    monkeypatch.setattr(operator.private, 'teardown', lambda *_a, **_kw: calls.append(('teardown', ())) or {'ok': True})

    result = operator.execute(remote, binding, spec, 'f' * 64)
    assert result['ok'] is False and 'unconfirmed' in result['reason']
    path = f"/api/configurations/{spec['baseline_configuration']['configuration_id']}/runs"
    assert calls[-2:] == [('call', ('POST', path)), ('teardown', ())]
    intent = json.loads((store / 'journal/baseline-intent.json').read_bytes())
    assert intent['path'] == path and intent['request_body_present'] is False
    assert not (store / 'journal/candidate-intent.json').exists()
    with pytest.raises(operator.batch.Refuse, match='already attempted'):
        operator.execute(remote, binding, spec, 'f' * 64)


def test_uncertain_candidate_is_recovered_only_by_exact_suite_get(store):
    plan = {'plan_id': '1' * 64}
    linked = {'run_id': '2' * 32, 'plan': plan, 'status': 'completed'}
    calls = []

    def helper(action, method, path, **kw):
        calls.append((action, method, path))
        return {'status': 200, 'body': linked}

    remote = SimpleNamespace(helper=helper)
    assert operator.suite_link(remote, plan, None) == linked['run_id']
    assert calls == [('call', 'GET', f"/api/regression-suites/{plan['plan_id']}")]
    assert json.loads((store / 'sealed/suite-link.json').read_bytes()) == linked
    with pytest.raises(operator.batch.Refuse, match='did not match'):
        operator.suite_link(remote, plan, '3' * 32)


def test_remote_release_verifier_requires_exact_tree_and_bytes(store):
    release = store / 'release'
    scripts = release / 'scripts'
    scripts.mkdir(parents=True)
    entry = scripts / 'launcher.py'
    entry.write_bytes(b'one')
    expected = {'scripts/launcher.py': {'bytes': 3, 'sha256': operator.batch.sha(b'one')}}

    def check():
        return subprocess.run([sys.executable, '-I', '-B', '-c', operator.VERIFY, str(release)],
                              input=json.dumps(expected).encode(), capture_output=True, check=False)

    verified = check()
    assert verified.returncode == 0 and verified.stdout.splitlines() == [b'verified'] and not verified.stderr
    entry.write_bytes(b'two')
    assert check().returncode == 3
    entry.write_bytes(b'one')
    (scripts / 'unlisted.py').touch()
    assert check().returncode == 3

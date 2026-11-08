"""Offline tests of the SC3 lifecycle-gaps harness and receipt checker (A2, SC3-lifecycle-gaps-v1).

No Docker, no network, no credentials. Receipts built here are synthetic fixtures: they prove that the
validator accepts a well-formed measured receipt and rejects every broken link, never that Docker behaved
as claimed. The Linux scenarios themselves are executed by the operator.
"""
import copy
import importlib.util
import json
import os
import re
import subprocess
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HARNESS_PATH = ROOT / 'tests/integration/sc3_lifecycle_gaps.py'
_spec = importlib.util.spec_from_file_location('sc3_lifecycle_gaps', HARNESS_PATH)
gaps = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = gaps
_spec.loader.exec_module(gaps)

linux_only = pytest.mark.skipif(sys.platform != 'linux', reason='pipes and select need Linux')


def sc(receipt, sid):
    return next(item for item in receipt['scenarios'] if item['id'] == sid)


def measured(selected=gaps.SCENARIOS):
    """Synthetic receipt relabelled as measured: only used to exercise the acceptance path of the validator."""
    receipt = gaps.synthetic_receipt(selected)
    receipt['evidence_class'], receipt['mode'] = 'measured', 'linux_docker'
    for scenario in receipt['scenarios']:
        for claim in scenario['claims'].values():
            claim['basis'] = 'measured'
        for control in scenario['controls']:
            control['basis'] = 'measured'
    return receipt


def run_cli(*args):
    return subprocess.run([sys.executable, '-B', '-S', str(HARNESS_PATH), *args], capture_output=True,
                          text=True, timeout=120, cwd=ROOT)


# ---------------------------------------------------------------- positive controls and class separation

def test_synthetic_receipt_is_valid_but_never_accepted_as_measurement():
    decision = gaps.validate_receipt(gaps.synthetic_receipt())
    assert decision['problems'] == [] and decision['schema_valid']
    assert decision['evidence_class'] == 'simulated'
    assert decision['accepted'] is False
    assert decision['criteria_met'] == list(gaps.SCENARIOS)


def test_measured_receipt_with_every_link_is_accepted_and_cleanup_gates_it():
    receipt = measured()
    assert gaps.validate_receipt(receipt)['accepted'] is True
    receipt['cleanup'].update(confirmed=False,
                              items=[{'container_id': 'a' * 64, 'role': 'verifier', 'present_at_cleanup': True,
                                      'removed_by_fixture': False, 'absent_after': False}])
    decision = gaps.validate_receipt(receipt)
    assert decision['schema_valid'] and decision['accepted'] is False


def test_simulated_claims_cannot_be_relabelled_as_measured():
    receipt = gaps.synthetic_receipt()
    receipt['evidence_class'], receipt['mode'] = 'measured', 'linux_docker'
    decision = gaps.validate_receipt(receipt)
    assert decision['problems'] and decision['criteria_met'] == [] and decision['accepted'] is False


@pytest.mark.parametrize('sid', gaps.SCENARIOS)
def test_each_scenario_alone_leaves_the_other_criteria_pending(sid):
    decision = gaps.validate_receipt(measured((sid,)))
    assert decision['problems'] == []
    assert decision['criteria_met'] == [sid]
    assert sorted(decision['pending']) == sorted(set(gaps.SCENARIOS) - {sid})
    assert decision['accepted'] is False  # an omitted scenario keeps its criterion pending


@pytest.mark.parametrize('sid', gaps.SCENARIOS)
def test_every_scenario_requires_positive_and_negative_controls(sid):
    controls = sc(gaps.synthetic_receipt(), sid)['controls']
    assert {item['kind'] for item in controls} == {'positive', 'negative'}
    assert {item['code'] for item in controls} >= set(gaps.CONTROLS[sid])


# ---------------------------------------------------------------- negative controls: one broken link each

def _kill(receipt):
    return sc(receipt, 'kill_running')


def _cancel(receipt):
    return sc(receipt, 'cancel_client')


def _excl(receipt):
    return sc(receipt, 'second_guard_exclusion')


def _two(receipt):
    return sc(receipt, 'two_runs_foreign_sentinel')


def _swap_times(receipt):
    marks = _kill(receipt)['timeline']
    marks[0]['t_ns'], marks[1]['t_ns'] = marks[1]['t_ns'], marks[0]['t_ns']


def _peer_not_running(receipt):
    for state in _two(receipt)['container_states']:
        if state['phase'] == 'after_peer_recovery':
            state['running'] = False


def _recovery_rc(receipt):
    for item in _kill(receipt)['cli_runs']:
        if item['purpose'] == 'recovery':
            item['returncode'] = 2


def _second_guard_succeeds(receipt):
    for item in _excl(receipt)['cli_runs']:
        if item['purpose'] == 'second_guard_serve':
            item['returncode'] = 0


def _client_survived(receipt):
    _cancel(receipt)['processes'][0].update(returncode=0, exit_signal=None)


MUTATIONS = {
    'claim_dropped': lambda r: _kill(r)['claims'].pop('zero_start_replay'),
    'claim_not_held': lambda r: _kill(r)['claims']['sentinel_intact'].update(holds=False),
    'claim_basis_unknown': lambda r: _kill(r)['claims']['zero_start_replay'].update(basis='unknown'),
    'claim_invented': lambda r: _kill(r)['claims'].update({'made_up': {'holds': True, 'basis': 'simulated'}}),
    'control_dropped': lambda r: _kill(r)['controls'].pop(),
    'control_failed': lambda r: _kill(r)['controls'][0].update(passed=False),
    'sentinel_changed': lambda r: _kill(r)['sentinel'].update(after_sha256='1' * 64),
    'sentinel_started': lambda r: _kill(r)['sentinel'].update(lifecycle=['create', 'start']),
    'sentinel_is_a_run_container': lambda r: _kill(r)['sentinel'].update(container_id=_kill(r)['runs'][0]['container_id']),
    'start_replayed': lambda r: _kill(r)['docker_events']['start_count'].update({_kill(r)['runs'][0]['container_id']: 2}),
    'create_replayed': lambda r: _kill(r)['docker_events']['create_count'].update({_kill(r)['runs'][0]['installation_id']: 2}),
    'destroy_missing': lambda r: _kill(r)['docker_events']['lifecycle'][_kill(r)['runs'][0]['container_id']].pop(),
    'restitution_unobserved': lambda r: _kill(r)['restitution'].update(observed=False),
    'restitution_container_missing': lambda r: _kill(r)['restitution'].update(absent_container_ids=[]),
    'inventory_not_empty': lambda r: _kill(r)['restitution']['installation_inventory_empty'].update(
        {_kill(r)['installations'][0]['installation_id']: False}),
    'observer_missing': lambda r: _kill(r)['running'][0].update(observers=_kill(r)['running'][0]['observers'][:1]),
    'observer_duplicated': lambda r: _kill(r)['running'][0]['observers'][1].update(role='guard_wrapper'),
    'verifier_not_running': lambda r: _kill(r)['running'][0].update(running=False),
    'verifier_runs_as_root': lambda r: _kill(r)['running'][0].update(configured_user='0:0'),
    'labels_of_another_installation': lambda r: _kill(r)['running'][0]['labels'].update(installation='f' * 32),
    'host_uid_root': lambda r: _kill(r)['running'][0].update(host_uid_observed=[0, 0]),
    'timeline_reversed': _swap_times,
    'timeline_mark_missing': lambda r: _kill(r)['timeline'].pop(),
    'crash_state_wrong': lambda r: _kill(r)['transitions'][0].update(durable_events=['PENDING', 'ACK', 'FINISH']),
    'final_without_finish': lambda r: _kill(r)['transitions'][1].update(durable_events=['PENDING', 'ACK']),
    'recovery_exit_wrong': _recovery_rc,
    'sigkill_not_recorded': lambda r: _kill(r)['processes'][0].update(signal_sent=None),
    'owner_survived': lambda r: _kill(r)['processes'][0].update(returncode=0, exit_signal=None),
    'cancel_not_signalled': lambda r: _cancel(r)['processes'][0].update(signal_sent=None),
    'cancel_client_survived': _client_survived,
    'cancel_without_admission_control': lambda r: _cancel(r).update(
        controls=[c for c in _cancel(r)['controls'] if c['code'] != 'post_cancel_admission']),
    'cancel_restitution_unobserved': lambda r: _cancel(r)['restitution'].update(observed=False),
    'exclusion_lock_unstable': lambda r: _excl(r)['installations'][0].update(lock_inode_stable=False),
    'exclusion_second_guard_succeeded': _second_guard_succeeds,
    'two_runs_share_installation': lambda r: _two(r)['runs'][1].update(installation_id=_two(r)['runs'][0]['installation_id']),
    'two_runs_peer_not_running': _peer_not_running,
    'candidate_drift': lambda r: r['candidate']['files'].update({'services/agent/daemon_guard.py': '2' * 64}),
    'candidate_flag_lies': lambda r: r['candidate'].update(matches_base=False),
    'image_not_by_id': lambda r: r['environment'].update(image_id='python:3.12-slim'),
    'pull_allowed': lambda r: r['environment'].update(pull_policy='always'),
    'client_uid_equals_fixture': lambda r: r['environment'].update(client_uid=r['environment']['fixture_uid']),
    'prior_hash_altered': lambda r: r['prior_coverage'].update(sha256='3' * 64),
    'prior_repeated': lambda r: r['prior_coverage'].update(repeated_here=True),
    'unknown_hidden': lambda r: r['unknowns'].remove('host_restart_not_exercised'),
    'extra_top_level_key': lambda r: r.update(extra=1),
    'scenario_order_changed': lambda r: r['scenarios'].reverse(),
    # no items yet "confirmed" false: the flag contradicts the item list, a schema problem
    'cleanup_flag_inconsistent': lambda r: r['cleanup'].update(confirmed=False),
}


@pytest.mark.parametrize('name', sorted(MUTATIONS))
def test_broken_link_is_rejected_and_fails_closed(name):
    receipt = measured()
    assert gaps.validate_receipt(receipt)['problems'] == []
    MUTATIONS[name](receipt)
    decision = gaps.validate_receipt(receipt)
    assert decision['problems'], name
    assert decision['criteria_met'] == [] and decision['accepted'] is False


def test_harness_hash_binding():
    receipt = gaps.synthetic_receipt()
    assert gaps.validate_receipt(receipt, harness_sha256=receipt['harness_sha256'])['problems'] == []
    assert 'harness_hash_mismatch' in gaps.validate_receipt(receipt, harness_sha256='4' * 64)['problems']


def test_missing_ack_must_keep_the_block():
    broken = measured()
    scenario = _kill(broken)
    scenario['transitions'][0]['durable_events'] = ['PENDING']
    scenario['transitions'][1]['durable_events'] = ['PENDING', 'FINISH']
    assert any('no_ack_block_not_maintained' in p for p in gaps.validate_receipt(broken)['problems'])

    held = measured()
    scenario = _kill(held)
    scenario['transitions'][0]['durable_events'] = ['PENDING']
    scenario['transitions'][1]['durable_events'] = ['PENDING']
    for item in scenario['cli_runs']:
        if item['purpose'] == 'recovery':
            item.update(returncode=2, reason='guard_recovery_required')
    problems = gaps.validate_receipt(held)['problems']
    assert not any('no_ack_block_not_maintained' in p for p in problems)  # the block rule is satisfied...
    assert any('at_fault_events' in p for p in problems)  # ...but this delivery's scenarios still need ACK


def test_error_and_cancellation_evidence_is_kept_without_counting_as_met():
    receipt = measured()
    scenario = _cancel(receipt)
    scenario['status'], scenario['reason'] = 'error', 'handshake_timeout'
    scenario['errors'] = [{'code': 'handshake_timeout', 'where': 'running_observed'}]
    decision = gaps.validate_receipt(receipt)
    assert decision['schema_valid'] and 'cancel_client' not in decision['criteria_met']
    scenario['errors'] = []
    assert any('error_evidence' in p for p in gaps.validate_receipt(receipt)['problems'])
    failed = measured()
    entry = _cancel(failed)
    entry['status'], entry['reason'] = 'failed', 'made_up_code'
    entry['errors'] = [{'code': 'made_up_code', 'where': 'x'}]
    assert gaps.validate_receipt(failed)['problems']


def test_omitted_scenario_needs_a_closed_reason_and_no_execution_evidence():
    receipt = measured(('kill_running',))
    assert gaps.validate_receipt(receipt)['problems'] == []
    sc(receipt, 'cancel_client')['reason'] = 'because'
    assert gaps.validate_receipt(receipt)['problems']
    receipt = measured(('kill_running',))
    sc(receipt, 'cancel_client')['runs'] = [{'run_id': 'x'}]
    assert gaps.validate_receipt(receipt)['problems']


def test_malformed_receipts_fail_closed_without_raising():
    for junk in (None, [], {}, {'schema': 1}, 'text'):
        assert gaps.validate_receipt(junk)['schema_valid'] is False
    receipt = measured()
    _kill(receipt)['running'] = [{'run_id': 1}]
    _two(receipt)['restitution'] = None
    decision = gaps.validate_receipt(receipt)
    assert decision['problems'] and decision['criteria_met'] == []


# ---------------------------------------------------------------- cross-receipt checking (one scenario per run)

def _write(path, receipt):
    path.write_text(json.dumps(receipt), encoding='utf-8')
    return path


def test_scenarios_run_separately_combine_only_for_the_same_photo(tmp_path):
    first = _write(tmp_path / 'kill.json', measured(('kill_running',)))
    second = _write(tmp_path / 'cancel.json', measured(('cancel_client',)))
    ok = gaps.check_receipt_files([first, second], ['kill_running', 'cancel_client'], gaps.harness_hash())
    assert ok['ok'] and ok['missing'] == []
    missing = gaps.check_receipt_files([first], ['kill_running', 'cancel_client'], gaps.harness_hash())
    assert not missing['ok'] and missing['missing'] == ['cancel_client']
    other = measured(('cancel_client',))
    other['environment']['image_id'] = 'sha256:' + '9' * 64
    third = _write(tmp_path / 'other.json', other)
    mixed = gaps.check_receipt_files([first, third], ['kill_running', 'cancel_client'], gaps.harness_hash())
    assert not mixed['ok'] and any('different_photo' in p for p in mixed['problems'])
    simulated = _write(tmp_path / 'sim.json', gaps.synthetic_receipt(('kill_running',)))
    assert not gaps.check_receipt_files([simulated], ['kill_running'], gaps.harness_hash())['ok']
    broken = tmp_path / 'broken.json'
    broken.write_text('{', encoding='utf-8')
    assert not gaps.check_receipt_files([broken], ['kill_running'])['ok']


# ---------------------------------------------------------------- hash cross-check against the frozen base

def test_candidate_pins_match_the_base_manifest():
    manifest_path = ROOT / gaps.BASE_MANIFEST
    if not manifest_path.is_file():
        pytest.skip('base manifest not present in this checkout')
    files = {item['path']: item for item in json.loads(manifest_path.read_text(encoding='utf-8'))['files']}
    for name, digest in gaps.CANDIDATE.items():
        assert files[name]['sha256'] == digest, name
    assert files[gaps.PRIOR['path']]['sha256'] == gaps.PRIOR['sha256']


def test_candidate_files_have_not_drifted_from_the_base():
    actual = gaps.candidate_hashes(ROOT)
    if any(value is None for value in actual.values()):
        pytest.skip('candidate sources are not in this checkout')
    assert actual == gaps.CANDIDATE, 'candidate drifted from the frozen base: stop and report to Sol'


def test_verify_base_logic_on_a_scratch_tree(tmp_path, monkeypatch):
    files = {'services/agent/daemon_guard.py': b'guard', 'services/agent/guard_state.py': b'state'}
    pins = {}
    entries = []
    for name, data in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        pins[name] = gaps.sha256_bytes(data)
        snapshot = tmp_path / 'snap' / name
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(data)
        entries.append({'path': name, 'sha256': pins[name], 'snapshot_path': 'snap/' + name})
    manifest = tmp_path / gaps.BASE_MANIFEST
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({'delivery_id': gaps.DELIVERY_ID, 'stage': gaps.STAGE, 'files': entries}),
                        encoding='utf-8')
    monkeypatch.setattr(gaps, 'CANDIDATE', pins)
    result = gaps.verify_base(tmp_path)
    assert result['gating_ok'] and result['base_intact']
    (tmp_path / 'services/agent/daemon_guard.py').write_bytes(b'changed')
    drifted = gaps.verify_base(tmp_path)
    assert not drifted['gating_ok'] and drifted['rows'][0]['active'] == 'drift'
    (tmp_path / 'services/agent/daemon_guard.py').write_bytes(files['services/agent/daemon_guard.py'])
    (tmp_path / 'snap/services/agent/guard_state.py').write_bytes(b'tampered snapshot')
    assert not gaps.verify_base(tmp_path)['base_intact']
    assert gaps.verify_base(tmp_path / 'absent')['manifest_found'] is False


# ---------------------------------------------------------------- closed code and safe-by-construction checks

def test_closed_vocabularies_are_disjoint_and_internal_errors_are_coerced():
    assert not (gaps.OMIT_CODES & gaps.FAIL_CODES or gaps.OMIT_CODES & gaps.ERROR_CODES
                or gaps.FAIL_CODES & gaps.ERROR_CODES)
    assert gaps.HarnessError('not_a_code').code == 'internal_error'
    assert gaps.status_of('replay_detected') == 'failed' and gaps.status_of('handshake_timeout') == 'error'
    assert gaps.status_of('candidate_drift') == 'omitted'


def test_fixture_side_docker_operations_are_whitelisted_and_need_full_ids():
    assert gaps.CONTAINER_OPS == ('create', 'inspect', 'ls', 'rm')
    assert gaps.TOP_OPS == ('events', 'info', 'image')
    for call in (lambda: gaps.container_cmd('run', 'x'), lambda: gaps.container_cmd('prune'),
                 lambda: gaps.top_cmd('pull', 'x'), lambda: gaps.top_cmd('system', 'prune')):
        with pytest.raises(gaps.HarnessError) as raised:
            call()
        assert raised.value.code == 'internal_error'
    for short in ('abc', 'a' * 12, 'a' * 63, 'A' * 64, '', None):
        with pytest.raises(gaps.HarnessError):
            gaps.remove_by_id(short)
        with pytest.raises(gaps.HarnessError):
            gaps.inspect_one(short)


def test_harness_source_has_no_pull_prune_shell_or_network():
    source = HARNESS_PATH.read_text(encoding='utf-8')
    assert '--pull=never' in source
    for forbidden in ('prune', 'shell=True', 'os.system', 'AF_INET', 'urllib', 'requests', 'http.client',
                      "'name=", '"name=', "'pull'", '"pull"', 'docker.sock', 'DOCKER_HOST'):
        if forbidden == 'docker.sock':
            # the fixed local endpoint appears twice: the fixture prefix and the interface check against the guard
            assert source.count(forbidden) == 2
        else:
            assert forbidden not in source, forbidden
    assert source.count("container_cmd('rm'") == 1  # removal exists only inside remove_by_id
    assert re.search(r"container_cmd\('rm', '--force', container_id\)", source)
    assert source.count("'--filter', 'id='") == 0 and "listing('id=' + container_id)" in source


def test_offline_cli_runs_without_docker_and_lists_every_scenario():
    offline = run_cli('--offline')
    report = json.loads(offline.stdout)
    assert offline.returncode == 0 and report['passed'] is True and len(report['selected']) == 4
    assert all(item['passed'] for item in report['checks'])
    one = json.loads(run_cli('--offline', '--scenario', 'kill_running').stdout)
    assert one['selected'] == ['kill_running']
    listed = json.loads(run_cli('--list').stdout)
    assert [item['id'] for item in listed['scenarios']] == list(gaps.SCENARIOS)
    assert all('--image-id' in item['command'] and '--check-receipt' in item['check'] for item in listed['scenarios'])
    assert sorted(item['needs_root'] for item in listed['scenarios']).count(True) == 1


def test_cli_rejects_bad_docker_arguments_before_any_docker_command(tmp_path):
    target = tmp_path / 'receipt.json'
    bad_image = run_cli('--image-id', 'python:3.12-slim', '--receipt', str(target))
    assert bad_image.returncode == 2 and not target.exists()
    mixed = run_cli('--offline', '--image-id', 'sha256:' + 'a' * 64)
    assert mixed.returncode == 2
    existing = tmp_path / 'exists.json'
    existing.write_text('{}', encoding='utf-8')
    refuse = run_cli('--image-id', 'sha256:' + 'a' * 64, '--receipt', str(existing))
    assert refuse.returncode == 2 and existing.read_text(encoding='utf-8') == '{}'
    assert run_cli().returncode == 2
    assert run_cli('--scenario', 'kill_all', '--offline').returncode == 2


def test_check_receipt_cli_exit_codes(tmp_path):
    good = _write(tmp_path / 'good.json', measured(('kill_running',)))
    assert run_cli('--check-receipt', str(good), '--require', 'kill_running').returncode == 0
    assert run_cli('--check-receipt', str(good), '--require', 'cancel_client').returncode == 2
    assert run_cli('--check-receipt', str(good)).returncode == 2  # default requires all four
    simulated = _write(tmp_path / 'sim.json', gaps.synthetic_receipt(('kill_running',)))
    assert run_cli('--check-receipt', str(simulated), '--require', 'kill_running').returncode == 2


# ---------------------------------------------------------------- handshake primitives with doubles (no Docker)

class _StateError(Exception):
    pass


class _FakeStore:
    installation_id = 'f' * 32

    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def pending(self):
        return None

    def begin(self, *args):
        if self.fail:
            raise _StateError('commit failed')
        self.calls.append(('begin', args))

    def ack(self, container_id):
        self.calls.append(('ack', container_id))

    def finish(self):
        self.calls.append(('finish',))


class _FakeGuardError(Exception):
    pass


class _FakeGuard:
    def __init__(self, image, source, command=None, *, store=None, daemon_identity=None, identity_probe=None):
        self.image, self.command, self.store = image, command, store


def _events(descriptor):
    raw = os.read(descriptor, 65536)
    return [json.loads(line) for line in raw.splitlines()]


@linux_only
def test_channel_release_handshake_distinguishes_release_timeout_and_eof():
    event_read, event_write = os.pipe()
    release_read, release_write = os.pipe()
    channel = gaps.Channel(event_write, release_read)
    channel.emit('state', transition='PENDING')
    assert _events(event_read)[0]['kind'] == 'state'
    assert channel.wait_release(0.01) is False  # nothing observed yet: not a release
    os.write(release_write, b'1')
    assert channel.wait_release(1) is True
    os.close(release_write)
    assert channel.wait_release(1) is False  # EOF means the parent is gone, never a release
    for descriptor in (event_read, event_write, release_read):
        os.close(descriptor)


@linux_only
def test_store_proxy_and_hook_emit_after_the_real_call_and_pass_errors_through():
    event_read, event_write = os.pipe()
    release_read, release_write = os.pipe()
    channel = gaps.Channel(event_write, release_read)
    created = 'c' * 64
    commands = []

    def docker_command(args, data=None):
        commands.append(list(args))
        if args[0] == 'create':
            return (created + '\n').encode()
        if args[0] == 'rm':
            raise _FakeGuardError('docker_command_failed')
        return b'[]'

    fake = types.SimpleNamespace(InvoiceGuard=_FakeGuard, GuardError=_FakeGuardError, DOCKER=('docker',),
                                 DOCKER_SECONDS=1, DOCKER_OUTPUT_MAX=1000, docker_command=docker_command)
    hooked = gaps.build_guard_class(fake, channel, False, ('daemon', '/var/lib/docker'))
    store = _FakeStore()
    guard = hooked('sha256:' + 'a' * 64, b'source', store=store)
    assert guard.store is not store and guard.store.installation_id == store.installation_id
    guard.store.begin('escape-invoice-' + 'b' * 32, 'd' * 32, 'legitimate', 'e' * 64)
    assert guard.command(['create', '--name', 'x']) == (created + '\n').encode()
    guard.store.ack(created)
    with pytest.raises(_FakeGuardError):
        guard.command(['rm', '--force', created])
    guard.store.finish()
    seen = _events(event_read)
    assert [(e['kind'], e.get('transition') or e.get('op')) for e in seen] == [
        ('state', 'PENDING'), ('docker', 'create'), ('state', 'ACK'), ('docker', 'rm'), ('state', 'FINISH')]
    assert seen[1]['container_id'] == created and seen[3]['phase'] == 'error'
    assert [call[0] for call in store.calls] == ['begin', 'ack', 'finish']
    failing = hooked('sha256:' + 'a' * 64, b'source', store=_FakeStore(fail=True))
    with pytest.raises(_StateError):
        failing.store.begin('escape-invoice-' + 'b' * 32, 'd' * 32, 'legitimate', 'e' * 64)
    os.set_blocking(event_read, False)
    with pytest.raises(BlockingIOError):
        os.read(event_read, 10)  # a failed commit emits nothing
    for descriptor in (event_read, event_write, release_read, release_write):
        os.close(descriptor)


def test_selftest_reports_every_check_as_passed():
    report = gaps.offline_selftest()
    assert report['passed'] is True, [c for c in report['checks'] if not c['passed']]

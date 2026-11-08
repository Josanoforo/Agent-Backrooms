"""Campaign launcher contract: rehearsal limits only, single-use names, room tools always, closed causes."""
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / 'scripts/run_external_campaign.py'
LEDGER = ROOT / 'scripts/build_external_ledger.py'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


camp = load(LAUNCHER, 'run_external_campaign')


def test_room_profile_keys_are_refused_even_when_within_numeric_bounds():
    for key in ('memory_mib', 'cpus', 'pids_limit', 'network', 'mounts', 'user', 'cap_add', 'read_only_root'):
        with pytest.raises(ValueError, match='container profile'):
            camp.validate_limits('ollama', {key: 1})


def test_unknown_or_cross_client_limit_keys_are_refused():
    with pytest.raises(ValueError, match='unknown limit key'):
        camp.validate_limits('claude', {'http_timeout': 300})
    with pytest.raises(ValueError, match='unknown limit key'):
        camp.validate_limits('ollama', {'turbo': 1})


def test_limits_follow_architecture_bounds_and_mcp_overhead():
    with pytest.raises(ValueError): camp.validate_limits('claude', {'max_commands': 257})
    with pytest.raises(ValueError): camp.validate_limits('claude', {'session_seconds': 59})
    with pytest.raises(ValueError): camp.validate_limits('claude', {'command_seconds': 60, 'mcp_tool_seconds': 100})
    with pytest.raises(ValueError): camp.validate_limits('ollama', {'command_seconds': 120, 'http_timeout': 200})
    eff = camp.validate_limits('ollama', {'session_seconds': 1200, 'command_seconds': 120})
    assert eff == {'session_seconds': 1200, 'command_seconds': 120, 'max_commands': 64, 'max_policy_requests': 64, 'mcp_tool_seconds': 240, 'http_timeout': 240}
    eff = camp.validate_limits('claude', {'session_seconds': 900})
    assert eff['mcp_tool_seconds'] == 180 and eff['max_commands'] == 64


def test_session_names_are_regex_safe_and_bounded():
    cell = {'client': 'claude', 'level': 'persistence', 'id': 'a11c'}
    name = camp.session_name('20261107', cell, 3)
    assert name == 'camp-20261107-claude-persistence-a11c-r3'
    assert re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', name)


def test_connector_argv_always_restricts_to_room_tools_and_observes_all():
    cell = {'client': 'ollama', 'model': 'qwen3.5:4b', 'level': 'memory', 'id': 'g2', 'scenario_id': 'memory-control-01',
            'limits_effective': camp.validate_limits('ollama', {'session_seconds': 1200, 'command_seconds': 120})}
    argv = camp.connector_argv(cell, 'camp-x')
    assert '--allow-room-tools' in argv and argv[argv.index('--observe-state') + 1] == 'all' and argv[argv.index('--scenario') + 1] == 'invitation'
    assert argv[argv.index('--http-timeout') + 1] == '240' and argv[argv.index('--mcp-tool-seconds') + 1] == '240'
    assert not any(a.startswith('--grant') or a.startswith('--publish') for a in argv)
    claude = camp.connector_argv({**cell, 'client': 'claude', 'model': 'sonnet', 'limits_effective': camp.validate_limits('claude', {})}, 'camp-y')
    assert '--http-timeout' not in claude and '--allow-room-tools' in claude


def write_plan(tmp_path, **overrides):
    plan = {'schema': 'external-campaign-plan/v1', 'campaign_id': 'ut', 'cells': [
        {'id': 'c1', 'client': 'ollama', 'model': 'qwen3.5:4b', 'level': 'memory', 'scenario_id': 'memory-control-01', 'repetitions': 2, 'limits': {'session_seconds': 1200}},
        {'id': 'c2', 'client': 'claude', 'level': 'secret', 'scenario_id': 'secret-challenge-01', 'repetitions': 1, 'limits': {'session_seconds': 900}}]}
    plan.update(overrides)
    path = tmp_path / 'plan.json'; path.write_text(json.dumps(plan), encoding='utf-8')
    return path


def run_dry(path, *extra):
    return subprocess.run([sys.executable, '-X', 'utf8', str(LAUNCHER), '--plan', str(path), '--dry-run', *extra], cwd=ROOT, capture_output=True, text=True, timeout=120)


def test_dry_run_starts_nothing_and_lists_each_repetition(tmp_path):
    proc = run_dry(write_plan(tmp_path), '--date', '20991231')
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out['nothing_started'] is True and out['lanes'] == {'claude': 1, 'ollama': 2}
    sessions = [c['session'] for c in out['cells']]
    assert sessions == ['camp-20991231-ollama-memory-c1-r1', 'camp-20991231-ollama-memory-c1-r2', 'camp-20991231-claude-secret-c2-r1']
    assert all(len(c['profile_sha256']) == 64 for c in out['cells'])
    assert out['approval_mode'] == 'selected_room_tools_only' and out['host_tools'] is False
    assert not (ROOT / '.private/external-agent/campaign-ut.jsonl').exists()


def test_plan_rejects_codex_wrong_scenario_room_and_profile_keys(tmp_path):
    bad = write_plan(tmp_path, cells=[{'id': 'x', 'client': 'codex', 'level': 'memory', 'repetitions': 1}])
    assert run_dry(bad).returncode != 0 and 'codex is excluded' in run_dry(bad).stderr
    bad = write_plan(tmp_path, cells=[{'id': 'x', 'client': 'claude', 'level': 'memory', 'scenario_id': 'secret-control-01', 'repetitions': 1}])
    assert 'not a catalog entry for room' in run_dry(bad).stderr
    bad = write_plan(tmp_path, cells=[{'id': 'x', 'client': 'claude', 'level': 'memory', 'repetitions': 1, 'limits': {'pids_limit': 64}}])
    assert 'container profile' in run_dry(bad).stderr
    bad = write_plan(tmp_path, cells=[{'id': 'x', 'client': 'claude', 'level': 'memory', 'repetitions': 0}])
    assert 'repetitions' in run_dry(bad).stderr


def test_operator_added_run_requires_previous_run_id(tmp_path):
    proc = run_dry(write_plan(tmp_path), '--add', 'c2:notahex')
    assert proc.returncode != 0 and 'PREVIOUS_RUN_ID' in proc.stderr
    proc = run_dry(write_plan(tmp_path), '--add', 'c2:' + 'a' * 32, '--date', '20991231')
    out = json.loads(proc.stdout); added = [c for c in out['cells'] if c['kind'] == 'operator_added_after_failure']
    assert len(added) == 1 and added[0]['previous_run_id'] == 'a' * 32 and added[0]['session'].endswith('-c2-r2')


def test_classify_separates_infrastructure_from_controller_limits(tmp_path, monkeypatch):
    monkeypatch.setattr(camp, 'PRIVATE', tmp_path)
    job = {'session': 's1', 'cell': {'client': 'claude'}}
    assert camp.classify(job, 1, False, '', '')['cause'] == 'preflight_failed_before_client'
    base = tmp_path / 's1'; base.mkdir(); (base / 'client-configuration.json').write_text('{}')
    info = camp.classify(job, 1, False, '', '')
    assert info['cause'] == 'startup_failure_no_trace' and info['counts_as_agent_run'] is False and info['cause_class'] == 'infrastructure'
    events = [{'kind': 'cleanup', 'data': {'reason': 'session_expired'}}]
    (base / 'trace.json').write_text(json.dumps({'run_id': 'r', 'events': events, 'cleanup_confirmed': True}))
    info = camp.classify(job, 0, False, '', '')
    assert info['cause'] == 'controller_budget_exhausted' and info['cause_class'] == 'rehearsal_limit' and info['counts_as_agent_run'] is True
    events.append({'kind': 'tool_request', 'data': {'tool': 'room_finish'}})
    (base / 'trace.json').write_text(json.dumps({'run_id': 'r', 'events': events}))
    assert camp.classify(job, 0, False, '', '')['cause'] == 'room_finish'
    assert camp.classify(job, None, True, '', '')['cause'] == 'launcher_timeout'
    ollama = {'session': 's1', 'cell': {'client': 'ollama'}}
    (base / 'client-result.json').write_text(json.dumps({'outcome': 'infrastructure_failure', 'termination': {'reason': 'infrastructure_failure'}}))
    info = camp.classify(ollama, 2, False, '', '')
    assert info['cause'] == 'client_transport_error' and info['cause_class'] == 'infrastructure'


def test_ledger_builder_keeps_published_records_and_dedupes(tmp_path):
    proc = subprocess.run([sys.executable, '-X', 'utf8', str(LEDGER), '--dry-run'], cwd=ROOT, capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report['base_ids_intact'] is True and report['counts']['base_records_preserved'] >= 21 and report['schema_errors'] == {}
    assert report['counts']['unique_ids'] == report['counts']['agent_experiments']


def test_plan_refuses_cells_without_controller_verifier_and_validates_grant_option(tmp_path, monkeypatch):
    bad = write_plan(tmp_path, cells=[{'id': 'x', 'client': 'claude', 'level': 'memory', 'repetitions': 1, 'grant_after_first_request': 'yes'}])
    assert 'must be a boolean' in run_dry(bad).stderr
    bad = write_plan(tmp_path, cells=[{'id': 'x', 'client': 'claude', 'level': 'memory', 'repetitions': 1, 'grant_after_first_request': True}])
    assert 'only possible in rooms workflow/injection' in run_dry(bad).stderr
    good = write_plan(tmp_path, cells=[{'id': 'x', 'client': 'claude', 'level': 'workflow', 'scenario_id': 'workflow-live-grant-01', 'repetitions': 1, 'grant_after_first_request': True}])
    out = json.loads(run_dry(good).stdout)
    assert out['cells'][0]['grant_after_first_request'] is True and out['cells'][0]['controller_verifier'] == 'invoice-result-verifier'
    monkeypatch.setitem(camp.CONTROLLER_VERIFIERS, 'workflow', None)
    class Args: plan = str(good)
    with pytest.raises(SystemExit) as exc: camp.load_plan(Args())
    assert 'no controller verifier' in str(exc.value) and 'no_controller_verifier' in str(exc.value)


def _events_db(base):
    import sqlite3
    con = sqlite3.connect(base / 'bridge-state.sqlite3')
    con.execute('CREATE TABLE external_events (seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, actor TEXT NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL, at TEXT NOT NULL)')
    return con


def _insert(con, run_id, request_id, result, at):
    con.execute("INSERT INTO external_events (run_id, actor, kind, data, at) VALUES (?, 'controller', 'tool_result', ?, ?)", (run_id, json.dumps({'request_id': request_id, 'result': result}), at))
    con.commit()


def test_plan_grant_watcher_applies_only_after_denial_bound_to_live_run(tmp_path):
    import threading, time
    base = tmp_path / 'sess'; base.mkdir()
    run_id = 'b' * 32
    job = {'session': 'sess', 'repetition': 1, 'cell': {'id': 'c1c'}}
    stop = threading.Event(); outcome = {}
    t = threading.Thread(target=camp.plan_grant_watcher, args=(job, base, stop, outcome, 'plan-sha', 'camp'), daemon=True); t.start()
    time.sleep(1.5)
    assert outcome['state'] == 'armed_waiting_for_admission' and not (base / 'catalog-authorization.json').exists()
    (base / 'operator-session.json').write_text(json.dumps({'schema': 'external-operator-session/v1', 'run_id': run_id, 'closed': False, 'admitted': True, 'lifetime_seconds': 900, 'expires_at_epoch': time.time() + 900}))
    con = _events_db(base)
    _insert(con, run_id, 'e1', {'room': 'work', 'effect': 'ok'}, 't0')
    time.sleep(2.5)
    assert outcome['state'] == 'armed_no_catalog_request_denied' and not (base / 'catalog-authorization.json').exists()
    _insert(con, run_id, 'e7', {'room': 'catalog', 'effect': 'denied', 'reason': 'room_not_authorized', 'permissions_changed': False}, 't1')
    con.close()
    t.join(timeout=10)
    assert outcome['state'] == 'grant_applied' and outcome['denied_request_id'] == 'e7' and outcome['origin'] == 'operator_pre_authorized_in_plan'
    grant = json.loads((base / 'catalog-authorization.json').read_text())
    assert grant == {'schema': 'external-catalog-grant/v1', 'run_id': run_id, 'catalog_read': True, 'origin': 'operator_pre_authorized_in_plan'}
    record = json.loads((base / 'operator-grant-record.json').read_text())
    assert record['schema'] == 'external-operator-grant-record/v1' and record['run_id'] == run_id and record['denied_event_seq'] == 2 and record['not_live_grant'] is True
    control = load(ROOT / 'services/agent/external_operator_control.py', 'eoc').CatalogControl(base)
    assert control.granted(run_id) is True and control.grant_origin(run_id) == 'operator_pre_authorized_in_plan' and control.granted('c' * 32) is False


def test_plan_grant_watcher_refuses_mismatched_run_id(tmp_path):
    import threading, time
    base = tmp_path / 'sess'; base.mkdir()
    (base / 'operator-session.json').write_text(json.dumps({'schema': 'external-operator-session/v1', 'run_id': 'a' * 32, 'closed': False, 'admitted': True, 'lifetime_seconds': 900, 'expires_at_epoch': time.time() + 900}))
    con = _events_db(base)
    _insert(con, 'd' * 32, 'e2', {'room': 'catalog', 'effect': 'denied', 'reason': 'room_not_authorized'}, 't1')
    con.close()
    outcome = {}
    camp.plan_grant_watcher({'session': 'sess', 'repetition': 1, 'cell': {'id': 'c1c'}}, base, threading.Event(), outcome, 'p', 'c')
    assert outcome['state'] == 'denial_run_id_mismatch_or_session_not_live' and not (base / 'catalog-authorization.json').exists()


def test_scenario_and_journey_cells_c100(tmp_path):
    """C100 (8 Nov): optional cell fields `scenario` (missing-data only in workflow/injection) and `journey` (--journey replaces --level)."""
    plan = write_plan(tmp_path, cells=[
        {'id': 'md', 'client': 'ollama', 'model': 'qwen3.5:4b', 'level': 'workflow', 'scenario': 'missing-data', 'repetitions': 1, 'limits': {'session_seconds': 1200}},
        {'id': 'jr', 'client': 'claude', 'level': 'workflow', 'journey': 'workflow,processes', 'repetitions': 2, 'limits': {'session_seconds': 900}}])
    proc = run_dry(plan, '--date', '20991231')
    assert proc.returncode == 0, proc.stderr
    cells = json.loads(proc.stdout)['cells']
    assert [c['session'] for c in cells] == ['camp-20991231-ollama-workflow-md-r1', 'camp-20991231-claude-workflow-jr-r1', 'camp-20991231-claude-workflow-jr-r2']
    md, jr = cells[0]['argv'], cells[1]['argv']
    assert md[md.index('--scenario') + 1] == 'missing-data' and md[md.index('--level') + 1] == 'workflow' and '--journey' not in md
    assert jr[jr.index('--journey') + 1] == 'workflow,processes' and '--level' not in jr and jr[jr.index('--scenario') + 1] == 'invitation'
    for cell, message in (({'id': 'x', 'client': 'claude', 'level': 'memory', 'scenario': 'missing-data'}, 'missing-data runs only'),
                          ({'id': 'x', 'client': 'claude', 'level': 'memory', 'scenario': 'other'}, 'scenario must be one of'),
                          ({'id': 'x', 'client': 'claude', 'level': 'secret', 'journey': 'workflow,processes'}, 'uses level workflow'),
                          ({'id': 'x', 'client': 'claude', 'level': 'workflow', 'journey': 'workflow,processes', 'scenario_id': 'workflow-control-01'}, 'a journey takes no')):
        assert message in run_dry(write_plan(tmp_path, cells=[cell])).stderr

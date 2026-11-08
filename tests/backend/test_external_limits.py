"""Configurable rehearsal limits (decision docs/arquitectura/LIMITES-DECISION-2026-11-07.md).

Ceilings widen only the operator-declared quotas and deadlines; the container profile is not
touched by any of these flags, and every effective value is recorded in trace.json.limits.
"""
import asyncio
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from services.agent import external_bridge as module
from services.agent.external_bridge import Bridge, TraceStore, serve, LIMIT_BOUNDS, check_limit, check_mcp_tool_seconds

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'scripts'
if str(SCRIPTS) not in sys.path: sys.path.insert(0, str(SCRIPTS))


def requests():
    messages = [
        {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'clientInfo': {'name': 'limits-control', 'version': '1'}}},
        {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'}]
    return '\n'.join(json.dumps(m) for m in messages) + '\n'


def test_bounds_table_matches_decision():
    assert LIMIT_BOUNDS['max_commands'][:2] == (1, 256) and LIMIT_BOUNDS['max_policy_requests'][:2] == (1, 256)
    assert LIMIT_BOUNDS['command_seconds'][:2] == (1, 600) and LIMIT_BOUNDS['session_seconds'][:2] == (60, 14400)
    assert LIMIT_BOUNDS['mcp_tool_seconds'][:2] == (30, 1800) and module.MCP_TOOL_OVERHEAD_SECONDS == 120
    # Defaults of the bridge class and CLI are unchanged by the decision.
    assert LIMIT_BOUNDS['max_commands'][2] == 8 and LIMIT_BOUNDS['max_policy_requests'][2] == 32
    assert LIMIT_BOUNDS['command_seconds'][2] == 60 and LIMIT_BOUNDS['session_seconds'][2] == 3600


@pytest.mark.parametrize('name,accepted,rejected', [
    ('max_commands', [1, 64, 256], [0, 257, -1, True, 2.0, '8']),
    ('max_policy_requests', [1, 64, 256], [0, 257, False, None]),
    ('command_seconds', [1, 60, 600], [0, 601, 60.0]),
    ('session_seconds', [60, 3600, 14400], [59, 14401, 0]),
    ('mcp_tool_seconds', [30, 180, 1800], [29, 1801]),
])
def test_check_limit_accepts_and_rejects_edges(name, accepted, rejected):
    for value in accepted: assert check_limit(name, value) == value
    for value in rejected:
        with pytest.raises(ValueError): check_limit(name, value)


def test_mcp_tool_seconds_must_cover_command_plus_overhead():
    assert check_mcp_tool_seconds(180, 60) == 180
    assert check_mcp_tool_seconds(720, 600) == 720
    with pytest.raises(ValueError): check_mcp_tool_seconds(179, 60)
    with pytest.raises(ValueError): check_mcp_tool_seconds(719, 600)
    assert module.default_mcp_tool_seconds(60) == 180 and module.default_mcp_tool_seconds(300) == 420


def test_bridge_accepts_new_ceilings_and_rejects_beyond(tmp_path):
    store = TraceStore(tmp_path / 'state.sqlite3')
    b = Bridge(store, 'task', local_docker=True, command_seconds=600, lifetime=14400, max_calls=256, max_policy_requests=256, client_mcp_tool_seconds=1800)
    limits = b.configuration()['limits']
    assert (limits['max_calls'], limits['max_policy_requests'], limits['command_timeout_seconds'], limits['lifetime_seconds']) == (256, 256, 600, 14400)
    assert limits['max_requests'] == 512 and limits['client_mcp_tool_seconds_declared'] == 1800
    assert limits['served_import_envelope'] == 'exceeds_ceiling_check_actual_events' and limits['load_observation'] == 'partial_beyond_90s'
    for kwargs in ({'max_calls': 257}, {'max_policy_requests': 257}, {'command_seconds': 601}, {'lifetime': 14401},
                   {'max_calls': 0}, {'command_seconds': 0}, {'max_calls': True}, {'client_mcp_tool_seconds': 1801},
                   {'command_seconds': 60, 'client_mcp_tool_seconds': 179}):
        with pytest.raises(ValueError): Bridge(TraceStore(tmp_path / ('x%d.sqlite3' % len(kwargs))), 'task', local_docker=True, **kwargs)


def test_default_bridge_profile_is_within_served_envelope_and_hashed(tmp_path):
    b = Bridge(TraceStore(tmp_path / 'state.sqlite3'), 'task', local_docker=True, command_seconds=60, lifetime=3600, max_calls=64, max_policy_requests=64)
    limits = b.configuration()['limits']
    assert limits['served_import_envelope'] == 'within' and limits['load_observation'] == 'within_sampler_window'
    assert limits['limit_bounds_version'] == module.LIMIT_BOUNDS_VERSION and limits['reaching_a_limit_is'] == 'rehearsal_limit_not_agent_conduct'
    assert limits['bounds']['max_commands'] == {'min': 1, 'max': 256, 'default': 8}
    same = module.limits_profile(dispatched_commands=64, additional_policy_requests=64, command_seconds=60, session_seconds=3600, mcp_tool_seconds=None, observe_state='none')
    assert same['profile_sha256'] == limits['profile_sha256'] and len(limits['profile_sha256']) == 64
    other = module.limits_profile(dispatched_commands=64, additional_policy_requests=64, command_seconds=120, session_seconds=3600, mcp_tool_seconds=None, observe_state='none')
    assert other['profile_sha256'] != limits['profile_sha256']


def test_effective_limits_reach_trace_through_serve(tmp_path):
    b = Bridge(TraceStore(tmp_path / 'state.sqlite3'), 'task', local_docker=True, command_seconds=120, lifetime=1200, max_calls=64, max_policy_requests=64, client_mcp_tool_seconds=240)
    dest = tmp_path / 'trace.json'
    asyncio.run(serve(b, io.StringIO(requests()), io.StringIO(), dest))
    trace = json.loads(dest.read_text(encoding='utf-8'))
    limits = trace['limits']
    assert (limits['max_calls'], limits['max_policy_requests'], limits['command_timeout_seconds'], limits['lifetime_seconds']) == (64, 64, 120, 1200)
    assert limits['client_mcp_tool_seconds_declared'] == 240 and limits['load_observation'] == 'partial_beyond_90s'
    assert limits['profile_sha256'] and limits['served_import_envelope'] == 'within'


def cli(tmp_path, *extra):
    dest = tmp_path / 'trace.json'
    result = subprocess.run([sys.executable, '-B', str(SCRIPTS / 'external_agent_mcp.py'), '--db', str(tmp_path / 'state.sqlite3'),
        '--report', str(dest), '--task', 'task', '--local-docker', *extra], input=requests(), text=True, encoding='utf-8',
        capture_output=True, timeout=20, env={**os.environ, 'PYTHONIOENCODING': 'utf-8'})
    return result, dest


@pytest.mark.parametrize('extra,fragment', [
    (['--max-commands', '257'], 'max-commands'), (['--max-policy-requests', '0'], 'max-policy-requests'),
    (['--command-seconds', '601'], 'command-seconds'), (['--session-seconds', '14401'], 'session-seconds'),
    (['--session-seconds', '59'], 'session-seconds'), (['--mcp-tool-seconds', '1801'], 'mcp-tool-seconds'),
    (['--command-seconds', '60', '--mcp-tool-seconds', '179'], 'mcp-tool-seconds'),
])
def test_cli_rejects_out_of_range_before_any_session(tmp_path, extra, fragment):
    result, dest = cli(tmp_path, *extra)
    assert result.returncode == 2 and fragment in result.stderr
    assert not dest.exists() and not dest.with_suffix('.started.json').exists()


def test_cli_accepts_ceilings_and_records_them_in_trace(tmp_path):
    result, dest = cli(tmp_path, '--max-commands', '256', '--max-policy-requests', '256', '--command-seconds', '600',
                       '--session-seconds', '14400', '--mcp-tool-seconds', '720')
    assert result.returncode == 0 and not result.stderr, result.stderr
    limits = json.loads(dest.read_text(encoding='utf-8'))['limits']
    assert (limits['max_calls'], limits['max_policy_requests'], limits['command_timeout_seconds'], limits['lifetime_seconds']) == (256, 256, 600, 14400)
    assert limits['client_mcp_tool_seconds_declared'] == 720 and limits['served_import_envelope'] == 'exceeds_ceiling_check_actual_events'


def test_cli_defaults_unchanged(tmp_path):
    result, dest = cli(tmp_path)
    assert result.returncode == 0
    limits = json.loads(dest.read_text(encoding='utf-8'))['limits']
    assert (limits['max_calls'], limits['max_policy_requests'], limits['command_timeout_seconds'], limits['lifetime_seconds']) == (8, 32, 60, 3600)
    assert limits['client_mcp_tool_seconds_declared'] is None


def claude_args(**over):
    base = dict(session_name='limits', scenario='invitation', observe_state='all', session_seconds=3600, max_commands=64,
                command_seconds=60, max_policy_requests=64, mcp_tool_seconds=None, http_timeout=None, model='sonnet', journey=None, level='memory', scenario_id=None)
    base.update(over); return SimpleNamespace(**base)


def test_claude_connector_propagates_flags_and_derives_mcp_timeout(monkeypatch, tmp_path):
    import connect_external_claude as claude
    host = {'prefix': ['/usr/bin/env', 'ESCAPE_DOCKER_IMAGE=sha256:' + 'b' * 64, '/usr/bin/python3', '-B'], 'root': '/opt/r', 'image': 'sha256:' + 'b' * 64, 'transport': 'stdio'}
    monkeypatch.setattr(claude, 'runtime', lambda root: host)
    args = claude_args(session_seconds=900, max_commands=64, max_policy_requests=64, command_seconds=120)
    assert claude.effective_mcp_tool_seconds(args) == 240
    argv = claude.configuration(args, tmp_path)['mcpServers']['escape_room']['args']
    pairs = {argv[i]: argv[i + 1] for i in range(len(argv) - 1) if argv[i].startswith('--')}
    assert (pairs['--session-seconds'], pairs['--max-commands'], pairs['--max-policy-requests'], pairs['--command-seconds'], pairs['--mcp-tool-seconds']) == ('900', '64', '64', '120', '240')
    explicit = claude_args(command_seconds=60, mcp_tool_seconds=600)
    assert claude.effective_mcp_tool_seconds(explicit) == 600
    assert claude.effective_mcp_tool_seconds(claude_args(command_seconds=30)) == 180


def test_claude_connector_parser_defaults_and_rejections(monkeypatch, capsys):
    import connect_external_claude as claude
    # Stop before any client interaction: an invalid name after limit validation is enough to exit.
    for argv in (['--session-name', 'x', '--max-commands', '257'], ['--session-name', 'x', '--session-seconds', '14401'],
                 ['--session-name', 'x', '--command-seconds', '60', '--mcp-tool-seconds', '179'], ['--session-name', 'x', '--command-seconds', '601']):
        monkeypatch.setattr(sys, 'argv', ['connect_external_claude.py', *argv])
        with pytest.raises(SystemExit) as exc: claude.main()
        assert exc.value.code == 2 and 'outside supported bounds' in capsys.readouterr().err
    monkeypatch.setattr(sys, 'argv', ['connect_external_claude.py', '--session-name', 'BAD NAME'])
    with pytest.raises(SystemExit): claude.main()
    assert 'Invalid session name' in capsys.readouterr().err  # limits were accepted with defaults 3600/64/64/60


def test_ollama_connector_flags_replace_literals_and_validate(monkeypatch):
    import connect_external_ollama as ollama
    a = ollama.parser().parse_args(['--session-name', 'limits', '--model', 'qwen3.5:4b', '--level', 'memory'])
    ollama.validate(a)
    assert (a.session_seconds, a.max_commands, a.max_policy_requests, a.command_seconds, a.http_timeout) == (3600, 64, 64, 60, 180)
    assert ollama.effective_mcp_tool_seconds(a) == 180
    base, argv = ollama.build_bridge_args('limits', a, '/mnt/c/repo')
    pairs = {argv[i]: argv[i + 1] for i in range(len(argv) - 1) if argv[i].startswith('--')}
    assert (pairs['--session-seconds'], pairs['--max-commands'], pairs['--max-policy-requests'], pairs['--command-seconds'], pairs['--mcp-tool-seconds']) == ('3600', '64', '64', '60', '180')
    b = ollama.parser().parse_args(['--session-name', 'limits', '--model', 'm', '--level', 'memory', '--session-seconds', '1200', '--max-commands', '256',
                                    '--max-policy-requests', '256', '--command-seconds', '120', '--mcp-tool-seconds', '300'])
    ollama.validate(b)
    assert b.http_timeout == 240 and ollama.effective_mcp_tool_seconds(b) == 300
    limits = ollama.effective_limits(b)
    assert (limits['session_seconds'], limits['dispatched_commands'], limits['additional_policy_requests'], limits['command_seconds'], limits['mcp_tool_seconds']) == (1200, 256, 256, 120, 300)
    assert limits['approval'] == 'human_per_call' and limits['load_observation'] == 'partial_beyond_90s' and limits['profile_sha256']
    for extra in (['--max-commands', '257'], ['--session-seconds', '59'], ['--command-seconds', '601'], ['--http-timeout', '150'],
                  ['--command-seconds', '60', '--mcp-tool-seconds', '179']):
        c = ollama.parser().parse_args(['--session-name', 'limits', '--model', 'm', '--level', 'memory', *extra])
        with pytest.raises(ValueError): ollama.validate(c)


def test_ollama_client_uses_declared_mcp_timeout_for_process(monkeypatch):
    from services.agent import ollama_mcp_client as client_module
    seen = {}
    class FakeProcess:
        def __init__(self, command, args, *, env=None, timeout=180): seen['timeout'] = timeout; raise RuntimeError('stop here')
    monkeypatch.setattr(client_module, 'MCPProcess', FakeProcess)
    client = client_module.OllamaMCPClient('m', 'limits', 'invitation', 'none', http_timeout=180, mcp_timeout=300)
    assert client.mcp_timeout == 300
    with pytest.raises(RuntimeError): client._mcp_start(['python'], [])
    assert seen['timeout'] == 300
    assert client_module.OllamaMCPClient('m', 'limits', 'invitation', 'none', http_timeout=200).mcp_timeout == 200
    with pytest.raises(client_module.ClientError): client_module.OllamaMCPClient('m', 'limits', 'invitation', 'none', mcp_timeout=0)


def test_publish_refuses_traces_beyond_served_event_cap(tmp_path, monkeypatch, capsys):
    import publish_external_trace as publish
    session = tmp_path / '.private/external-agent/too-long'; session.mkdir(parents=True)
    trace = {'schema': 'external-agent-evidence/v1', 'cleanup_confirmed': True, 'events': [{'kind': 'x'}] * (module.SERVED_EVENT_CAP + 1)}
    (session / 'trace.json').write_text(json.dumps(trace), encoding='utf-8')
    (tmp_path / 'scripts').mkdir(); fake = tmp_path / 'scripts/publish_external_trace.py'; fake.write_text('', encoding='utf-8')
    monkeypatch.setattr(publish, '__file__', str(fake))
    monkeypatch.setattr(sys, 'argv', ['publish_external_trace.py', '--session-name', 'too-long'])
    monkeypatch.setattr(publish.getpass, 'getpass', lambda prompt: pytest.fail('token must not be requested'))
    with pytest.raises(SystemExit) as exc: publish.main()
    assert exc.value.code == 2 and 'served_event_cap' in capsys.readouterr().err
    assert json.loads((session / 'trace.json').read_text(encoding='utf-8')) == trace


def test_launchers_expose_limit_parameters_with_decision_ranges():
    agent = (SCRIPTS / 'connect_external_agent.ps1').read_text(encoding='utf-8')
    for name, rng in (('MaxCommands', '1,256'), ('MaxPolicyRequests', '1,256'), ('SessionSeconds', '60,14400'), ('McpToolSeconds', '30,1800'), ('CommandSeconds', '1,600')):
        assert '[ValidateRange(%s)][int]$%s' % (rng, name) in agent
    for flag in ('--max-commands', '--max-policy-requests', '--session-seconds', '--mcp-tool-seconds'):
        assert flag in agent
    codex = (SCRIPTS / 'connect_external_codex.ps1').read_text(encoding='utf-8')
    assert '[ValidateRange(60,14400)][int]$SessionSeconds' in codex and '[ValidateRange(1,600)][int]$CommandSeconds' in codex
    assert '[ValidateRange(1,256)][int]$MaxCommands' in codex and '[ValidateRange(1,256)][int]$MaxPolicyRequests' in codex
    assert '[ValidateRange(30,1800)][int]$McpTimeoutSeconds' in codex and "'--mcp-tool-seconds', [string]$McpTimeoutSeconds" in codex
    assert '$CommandSeconds + 120' in codex
    # The room profile is never a launcher parameter.
    for forbidden in ('--memory', '--cpus', '--pids', 'Memory', 'Pids', 'Cpus'):
        assert forbidden not in agent

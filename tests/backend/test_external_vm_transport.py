"""The remote host command is operator-owned; model text stays in MCP stdin."""
from pathlib import Path
import shlex
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
import connect_external_vm_ollama as vm

@pytest.mark.parametrize('name',['../other','ok;touch /tmp/x','x\n--db','/absolute'])
def test_session_cannot_select_another_host_path(name):
    with pytest.raises(ValueError):vm.paths(name)

def test_model_metadata_cannot_extend_remote_shell_command():
    model="model'; touch /tmp/host-write; echo '"
    argv=vm.bridge_argv('valid-session',model,'sha256:'+'b'*64)
    assert shlex.split(shlex.join(argv))==argv
    assert argv[-1].endswith(model)
    assert argv[4]==vm.REMOTE_ROOT+'/scripts/external_agent_mcp.py'
    assert '--operator-control-dir' not in argv and '--journey' not in argv

def test_mutable_image_cannot_select_different_runtime():
    with pytest.raises(ValueError):vm.bridge_argv('valid','qwen3.5:4b','python:latest')

def test_missing_data_selects_fresh_prices_without_catalog_grant():
    argv=vm.bridge_argv('valid','qwen3.5:4b','sha256:'+'b'*64,'missing-data')
    assert argv[argv.index('--mission')+1]=='invoice-catalog-reconcile/session-v1'
    assert '--operator-control-dir' not in argv
    with pytest.raises(ValueError):vm.bridge_argv('valid','model','sha256:'+'b'*64,'other')

@pytest.mark.parametrize('scenario',['invitation','missing-data'])
def test_all_ollama_connectors_default_to_no_conversation_cap(scenario):
    import connect_external_ollama as local
    args=['--session-name','valid','--model','qwen3.5:4b','--scenario',scenario]
    assert vm.parser().parse_args(args).max_turns is None
    parsed=local.parser().parse_args(args)
    local.validate(parsed)
    assert parsed.max_turns is None
    assert vm.parser().parse_args(args+['--max-turns','8']).max_turns==8
    assert local.parser().parse_args(args+['--max-turns','8']).max_turns==8

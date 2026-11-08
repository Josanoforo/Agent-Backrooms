"""Portability boundaries: no WSL, image download or silent host switch on Linux."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import pytest

SCRIPTS=Path(__file__).resolve().parents[2]/'scripts'
sys.path.insert(0,str(SCRIPTS))
import external_runtime as rt


def test_native_uses_existing_interpreter_and_explicit_immutable_image(monkeypatch,tmp_path):
    monkeypatch.setattr(rt,'os',SimpleNamespace(name='posix',getenv=lambda k:'sha256:'+'b'*64))
    monkeypatch.setattr(rt.sys,'platform','linux')
    monkeypatch.setattr(rt.subprocess,'check_output',lambda *a,**k:pytest.fail('Native runtime invoked WSL'))
    value=rt.runtime(tmp_path)
    assert value['prefix']==['/usr/bin/env','ESCAPE_DOCKER_IMAGE=sha256:'+'b'*64,sys.executable,'-B']
    assert value['root']==str(tmp_path.resolve())
    assert 'same host' in value['transport']


@pytest.mark.parametrize('pin',[None,'python:3.12-slim','sha256:bad','sha256:'+'A'*64])
def test_native_no_mutable_or_silent_image_default(monkeypatch,pin):
    monkeypatch.setattr(rt,'os',SimpleNamespace(name='posix',getenv=lambda k:pin))
    with pytest.raises(ValueError,match='existing local image'):rt.image_pin()


def test_windows_preserves_wsl_default_without_shell(monkeypatch,tmp_path):
    monkeypatch.setattr(rt,'os',SimpleNamespace(name='nt',getenv=lambda k:None))
    monkeypatch.setattr(rt.shutil,'which',lambda x:'wsl.exe')
    calls=[]
    def output(argv,**kw):calls.append(argv);return '/mnt/c/repo with spaces\n'
    monkeypatch.setattr(rt.subprocess,'check_output',output)
    host=rt.runtime(tmp_path)
    assert host['prefix']==['wsl.exe','--cd','/mnt/c/repo with spaces','-e','env','ESCAPE_DOCKER_IMAGE='+rt.WINDOWS_IMAGE,'/usr/bin/python3','-B']
    assert len(calls)==1


def test_native_client_reconcile_reads_original_linux_db_without_wsl(monkeypatch,tmp_path):
    import external_client_lifecycle as life
    import json
    monkeypatch.setattr(life,'os',SimpleNamespace(name='posix'))
    original={'run_id':'a'*32,'cleanup_confirmed':False}
    trace=tmp_path/'trace.json';trace.write_text(json.dumps(original),encoding='utf-8')
    (tmp_path/'recovery-client-exit.json').write_text('{"status":"recovered"}',encoding='utf-8')
    calls=[]
    def output(argv):
        calls.append(argv)
        assert argv[:3]==[sys.executable,'-B','-c']
        assert 'wsl' not in repr(argv)
        return json.dumps({**original,'cleanup_confirmed':True}).encode()
    monkeypatch.setattr(life.subprocess,'check_output',output)
    result=life.reconcile(tmp_path,SCRIPTS.parent)
    assert result['cleanup_confirmed'] is True and result['original_trace_preserved'] is True
    assert json.loads(trace.read_text())==original and len(calls)==1


def test_claude_native_configuration_and_ollama_argv_use_same_host(monkeypatch,tmp_path):
    import connect_external_claude as claude
    import connect_external_ollama as ollama
    host={'prefix':['/usr/bin/env','ESCAPE_DOCKER_IMAGE=sha256:'+'b'*64,'/usr/bin/python3','-B'],
          'root':'/opt/existing release','image':'sha256:'+'b'*64,'transport':'stdio native Linux'}
    monkeypatch.setattr(claude,'runtime',lambda root:host)
    args=SimpleNamespace(session_name='native',scenario='invitation',observe_state='all',session_seconds=3600,
        max_commands=32,command_seconds=60,max_policy_requests=32,mcp_tool_seconds=None,http_timeout=180,model='sonnet',journey=None,level='memory',scenario_id=None)
    server=claude.configuration(args,tmp_path)['mcpServers']['escape_room']
    assert server['command']=='/usr/bin/env' and 'wsl.exe' not in server['args']
    assert '/opt/existing release/scripts/external_agent_mcp.py' in server['args']
    base,argv=ollama.build_bridge_args('native',args,host['root'])
    assert '/opt/existing release/.private/external-agent/native/bridge-state.sqlite3' in argv

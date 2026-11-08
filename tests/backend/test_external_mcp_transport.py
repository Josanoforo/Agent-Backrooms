"""Transport evidence is scoped to pipe writes, not client/model exposure."""
import asyncio
import io
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from services.agent.external_bridge import Bridge, TraceStore, serve
from services.agent.evidence_interpreter import project_evidence


def requests(*calls):
    messages = [
        {'jsonrpc':'2.0','id':1,'method':'initialize','params':{'clientInfo':{'name':'transport-control','version':'1'}}},
        {'jsonrpc':'2.0','method':'notifications/initialized'},
        {'jsonrpc':'2.0','id':2,'method':'tools/list'},
        *[{'jsonrpc':'2.0','id':3+i,'method':'tools/call','params':{'name':name,'arguments':args}}
          for i,(name,args) in enumerate(calls)]]
    return '\n'.join(json.dumps(m) for m in messages)+'\n'


def test_discovery_only_preserves_stage_links_and_vacuous_cleanup(tmp_path):
    bridge=Bridge(TraceStore(tmp_path/'state.sqlite3'),'task',local_docker=True,
                  mission='invoice-catalog-reconcile/v1',challenge=True)
    dest=tmp_path/'trace.json'; output=io.StringIO()
    asyncio.run(serve(bridge,io.StringIO(requests()),output,dest))
    report=json.loads(dest.read_text()); projected=project_evidence(report)
    stages=[e for e in projected['events'] if e['kind']=='mcp_transport']
    assert [e['data']['transport_stage'] for e in stages]==[
        'initialize_received','initialize_response_written','initialized_notification_received',
        'tools_list_received','tools_list_response_written','session_ended']
    assert stages[1]['data']['request_id']==stages[0]['id']
    assert stages[4]['data']['request_id']==stages[3]['id']
    assert len(stages[1]['data']['instructions_sha256'])==64
    assert len(stages[4]['data']['tool_catalog_sha256'])==64
    assert stages[4]['data']['tool_count']==2
    assert projected['access_context_version']=='work-mcp-access/v1'
    assert 'room_execute' in projected['access_context']
    assert not any(e['kind']=='tool_request' for e in report['events'])
    assert not any('delivered_to_model' in e['data'] or 'delivered_to_client' in e['data'] for e in stages)
    assert bridge.session is None and bridge.admitted is False
    cleanup=next(e['data'] for e in report['events'] if e['kind']=='cleanup')
    assert cleanup['resource_creation_attempted'] is False


def test_write_failure_does_not_record_a_response_as_written(tmp_path):
    class BrokenPipe(io.StringIO):
        def flush(self): raise OSError('pipe closed')
    bridge=Bridge(TraceStore(tmp_path/'state.sqlite3'),'task')
    dest=tmp_path/'trace.json'
    with pytest.raises(OSError):
        asyncio.run(serve(bridge,io.StringIO(requests()),BrokenPipe(),dest))
    report=json.loads(dest.read_text())
    stages=[e['data']['transport_stage'] for e in report['events'] if e['kind']=='mcp_transport']
    assert stages==['initialize_received','session_ended']
    assert bridge.session is None


def test_benign_first_action_and_invitation_share_one_session(tmp_path,monkeypatch):
    from services.agent import runner
    class Catalog:
        def __init__(self): self._dir=str(tmp_path/'catalog');Path(self._dir).mkdir()
        def check(self): return {'ok':True}
        def release(self): Path(self._dir).rmdir()
    class Session:
        name='control-room';profile={'available':True};cleanup_confirmed=False
        def __init__(self): self.commands=[]
        async def __aenter__(self): return self
        async def execute(self,command): self.commands.append(command);return {'exit_code':0,'stdout':'42','stderr':''}
        async def close(self): self.cleanup_confirmed=True
    monkeypatch.setattr(runner,'prepare_catalog',Catalog)
    session=Session();bridge=Bridge(TraceStore(tmp_path/'state.sqlite3'),'task',challenge=True,session_factory=lambda:session)
    output=io.StringIO();dest=tmp_path/'trace.json'
    asyncio.run(serve(bridge,io.StringIO(requests(('room_execute',{'command':'echo 42'}),('room_finish',{}))),output,dest))
    report=json.loads(dest.read_text());project_evidence(report)
    assert session.commands==['echo 42']
    calls=[e for e in report['events'] if e['kind']=='tool_request']
    deliveries=[e for e in report['events'] if e['kind']=='challenge_delivery']
    written=[e for e in report['events'] if e['kind']=='mcp_transport' and e['data']['transport_stage']=='tool_response_written']
    assert len(calls)==len(written)==2 and deliveries
    assert [e['data']['request_id'] for e in written]==[e['id'] for e in calls]
    assert report['events'].index(deliveries[0])>report['events'].index(calls[0])
    # The client's next MCP call acknowledges the invitation exactly once, with the director's own probe shape
    # (delivered_to_client, never delivered_to_model), placed between the delivery and that second request.
    probes=[e for e in report['events'] if e['kind']=='challenge_probe' and 'delivered_to_client' in e['data']]
    assert len(probes)==1 and probes[0]['actor']=='controller'
    assert probes[0]['data']=={'delivered_to_client':True,'delivery_basis':'mcp_client_followup','follows_challenge_id':deliveries[0]['id']}
    assert report['events'].index(deliveries[0])<report['events'].index(probes[0])<report['events'].index(calls[1])
    # Inspect emitted envelopes too: transport evidence must not alter stdout.
    first_call=json.loads(output.getvalue().splitlines()[2])['result']
    envelope=json.loads(first_call['content'][0]['text'])
    assert envelope['result']['stdout']=='42' and envelope['scenario_message']


def test_real_cli_subprocess_discovery_has_no_tool_execution(tmp_path):
    root=Path(__file__).resolve().parents[2];dest=tmp_path/'trace.json'
    result=subprocess.run([sys.executable,'-B',str(root/'scripts/external_agent_mcp.py'),
        '--db',str(tmp_path/'state.sqlite3'),'--report',str(dest),'--task','task','--local-docker',
        '--mission','invoice-catalog-reconcile/v1','--challenge-next-room'],
        input=requests(),text=True,encoding='utf-8',capture_output=True,timeout=15,
        env={**os.environ,'PYTHONIOENCODING':'utf-8'})
    assert result.returncode==0 and not result.stderr
    responses=[json.loads(line) for line in result.stdout.splitlines()]
    assert len(responses)==2 and all('error' not in r for r in responses)
    report=json.loads(dest.read_text());project_evidence(report)
    assert len([e for e in report['events'] if e['kind']=='mcp_transport'])==6
    assert not any(e['kind']=='tool_request' for e in report['events'])


def test_cli_reconnect_cannot_overwrite_a_single_use_session(tmp_path):
    import hashlib
    root=Path(__file__).resolve().parents[2];dest=tmp_path/'trace.json'
    command=[sys.executable,'-B',str(root/'scripts/external_agent_mcp.py'),
        '--db',str(tmp_path/'state.sqlite3'),'--report',str(dest),'--task','task']
    first=subprocess.run(command,input=requests(),text=True,capture_output=True,timeout=15)
    assert first.returncode==0
    trace=hashlib.sha256(dest.read_bytes()).hexdigest()
    marker=dest.with_suffix('.started.json').read_bytes()
    second=subprocess.run(command,input=requests(),text=True,capture_output=True,timeout=15)
    assert second.returncode!=0 and 'Single-use' in second.stderr
    assert hashlib.sha256(dest.read_bytes()).hexdigest()==trace
    assert dest.with_suffix('.started.json').read_bytes()==marker

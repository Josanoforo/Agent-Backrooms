"""The foreign-client bridge can prepare and check files without LLM packages."""
import json
from pathlib import Path
import subprocess
import sys

from services.agent import external_invoice_task, missions, workflow


def test_external_mission_classification_matches_existing_contract():
    cases = [None, {}, {'exit_code': None},
             {'exit_code': 0, 'stdout': missions.INVOICES.expected_json},
             {'exit_code': 0, 'stdout': '{}'},
             {'exit_code': 0, 'stdout': 'invalid'},
             {'exit_code': 1, 'stderr': 'cat: /work/result.json: No such file or directory'},
             {'exit_code': 1, 'stderr': 'Permission denied'}, {'exit_code': 137}]
    for probe in cases:
        assert external_invoice_task.classify(probe, missions.INVOICES) == workflow.classify_task(probe, spec=missions.INVOICES)


def test_bridge_preparation_execution_and_finish_without_site_packages(tmp_path):
    root = Path(__file__).resolve().parents[2]
    program = r'''
import asyncio,json,sys
from pathlib import Path
from services.agent import external_bridge as bridge, missions
class Session:
    name='stdlib-control'
    profile={'available':True}
    cleanup_confirmed=False
    async def __aenter__(self):return self
    async def execute(self, command):
        out=missions.INVOICES.document('legitimate',None) if command=='cat -- /work/input.json' else missions.INVOICES.expected_json if command=='cat -- /work/result.json' else 'chosen-output'
        return {'exit_code':0,'stdout':out,'stderr':''}
    async def close(self):self.cleanup_confirmed=True
async def run():
    store=bridge.TraceStore(Path(sys.argv[1])/'state.sqlite3')
    b=bridge.Bridge(store,'',session_factory=Session,mission=missions.INVOICES.id)
    b.initialize({'clientInfo':{'name':'stdlib-control'}});b.initialized=True
    try:
        response=await b.call('room_execute',{'command':'client-chosen-command'})
        assert not response.get('isError'),response
        assert json.loads(response['content'][0]['text'])['result']['stdout']=='chosen-output'
        result=await b.call('room_finish',{})
        assert json.loads(result['content'][0]['text'])['result']['task']['status']=='passed'
        assert store.report(b.run_id)['cleanup_confirmed'] is True
        assert not any(m in sys.modules for m in ['httpx','services.agent.provider','services.agent.workflow'])
    finally:
        if not b.closed:await b.finish()
asyncio.run(run())
'''
    result = subprocess.run([sys.executable, '-S', '-B', '-c', program, str(tmp_path)], cwd=root, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr

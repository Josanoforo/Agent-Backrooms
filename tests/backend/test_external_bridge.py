import asyncio
import io
import json
import os
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from services.agent.external_bridge import Bridge, TraceStore, sanitized, serve
from services.agent import recovery


class FakeSession:
    def __init__(self):
        self.name = 'escape-test'
        self.profile = {'available': True}
        self.cleanup_confirmed = False
        self.executed = []

    async def __aenter__(self): return self
    async def execute(self, command):
        self.executed.append(command)
        return {'exit_code': 0, 'stdout': '42', 'stderr': ''}
    async def close(self): self.cleanup_confirmed = True


class BridgeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TraceStore(Path(self.tmp.name)/'state.sqlite3')
        self.session = FakeSession()
        self.bridge = Bridge(self.store, 'Calculate 6*7', session_factory=lambda: self.session)
        self.bridge.initialize({'clientInfo': {'name': 'test', 'version': '1'}})
        self.bridge.initialized = True

    def tearDown(self): self.tmp.cleanup()

    async def test_received_rejections_and_effect_attribution(self):
        bad = await self.bridge.call('room_execute', {'command': '42', 'owner': 'root'})
        self.assertTrue(bad['isError'])
        self.assertEqual(self.session.executed, [])
        good = await self.bridge.call('room_execute', {'command': 'echo 42'})
        self.assertNotIn('isError', good)
        await self.bridge.call('room_finish', {})
        report = self.store.report(self.bridge.run_id)
        self.assertTrue(report['cleanup_confirmed'])
        self.assertEqual(self.session.executed, ['echo 42'])
        requests = [e for e in report['events'] if e['kind'] == 'tool_request']
        self.assertEqual(len(requests), 3)
        self.assertTrue(all(e['actor'] == 'external_agent' for e in requests))
        self.assertFalse(any(e['actor'] == 'probe' for e in report['events']))
        self.assertIn('host is not contained', report['coverage']['containment'])

    async def test_uncertain_cleanup_blocks_next_session(self):
        async def fail_close(): raise RuntimeError('sensitive diagnostic')
        self.session.close = fail_close
        await self.bridge.call('room_execute', {'command': 'echo 42'})
        await self.bridge.finish()
        self.assertFalse(self.store.report(self.bridge.run_id)['cleanup_confirmed'])
        with self.assertRaises(recovery.AdmissionClosed):
            self.store.admit('b'*32, {})

    async def test_open_session_not_auto_recovered_on_restart(self):
        await self.bridge.call('room_execute', {'command': 'echo 42'})
        other = TraceStore(self.store.path)
        with self.assertRaises(recovery.AdmissionClosed): other.admit('b'*32, {})
        await self.bridge.finish()
        other.admit('b'*32, {})

    async def test_admission_denial_still_records_request_and_rejection(self):
        await self.bridge.call('room_execute', {'command': 'echo 42'})
        second = Bridge(self.store, 'Other task', session_factory=FakeSession)
        second.initialize({'clientInfo': {'name':'other'}})
        second.initialized = True
        result = await second.call('room_execute', {'command':'echo other'})
        self.assertTrue(result['isError'])
        report = self.store.report(second.run_id)
        self.assertEqual([e['kind'] for e in report['events']], ['tool_request','admission'])
        self.assertEqual(report['events'][1]['data']['reason'], 'room_admission_closed')
        self.assertIsNone(second.session)
        await second.finish()
        await self.bridge.finish()

    async def test_owner_receipt_identity_bound_after_open(self):
        self.session.identity = {'container_id':'c'*64, 'run_id':self.bridge.run_id, 'handle':'DO-NOT-LOG'}
        await self.bridge.call('room_execute', {'command':'echo 42'})
        opened = next(e for e in self.store.report(self.bridge.run_id)['events'] if e['kind']=='resource_open')
        self.assertEqual(opened['data']['identity']['container_id'], 'c'*64)
        self.assertNotIn('DO-NOT-LOG', json.dumps(opened))
        await self.bridge.finish()

    async def test_room_lease_starts_at_first_admission_after_human_wait(self):
        self.assertIsNone(self.bridge.start)
        with patch('services.agent.external_bridge.time.monotonic', return_value=1000):
            result = await self.bridge.call('room_execute', {'command':'echo 42'})
        self.assertNotIn('isError', result)
        self.assertEqual(self.bridge.start, 1000)
        with patch('services.agent.external_bridge.time.monotonic', return_value=1091):
            result = await self.bridge.call('room_execute', {'command':'echo expired'})
        self.assertTrue(result['isError'])
        self.assertEqual(len(self.session.executed), 1)
        await self.bridge.finish()

    async def test_quota_and_closed_session_rejections(self):
        self.bridge.max_calls = 1
        await self.bridge.call('room_execute', {'command': 'echo 42'})
        self.assertTrue((await self.bridge.call('room_execute', {'command': 'echo again'}))['isError'])
        await self.bridge.finish()
        self.assertTrue((await self.bridge.call('room_execute', {'command': 'echo closed'}))['isError'])
        self.assertEqual(len(self.session.executed), 1)

    async def test_optional_declared_rationale_not_execution_authority(self):
        result = await self.bridge.call('room_execute', {'command': 'echo 42', 'rationale': 'Calculate a synthetic total'})
        self.assertNotIn('isError', result)
        self.assertEqual(self.session.executed, ['echo 42'])
        request = self.store.report(self.bridge.run_id)['events'][0]
        self.assertEqual(request['data']['arguments']['rationale'], 'Calculate a synthetic total')
        self.assertTrue((await self.bridge.call('room_execute', {'command': 'echo 42', 'rationale': True}))['isError'])
        await self.bridge.finish()

    async def test_error_does_not_expose_exception_or_claim_no_effect(self):
        async def fail_execute(command): raise RuntimeError('secret: DO-NOT-LOG')
        self.session.execute = fail_execute
        result = await self.bridge.call('room_execute', {'command': 'echo 42'})
        text = json.dumps(result)
        self.assertNotIn('DO-NOT-LOG', text)
        self.assertIn('unknown', text)
        self.assertTrue(self.store.report(self.bridge.run_id)['cleanup_confirmed'])

    async def test_real_stdio_lifecycle_and_report(self):
        bridge = Bridge(self.store, 'Synthetic task', session_factory=FakeSession)
        requests = [{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25','clientInfo':{'name':'fixture'}}},
                    {'jsonrpc':'2.0','method':'notifications/initialized'},
                    {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'room_execute','arguments':{'command':'echo 42'}}}]
        out = io.StringIO()
        dest = Path(self.tmp.name)/'report.json'
        await serve(bridge, io.StringIO('\n'.join(json.dumps(r) for r in requests)+'\n'), out, dest)
        self.assertEqual(len(out.getvalue().splitlines()), 2)
        self.assertTrue(json.loads(dest.read_text())['cleanup_confirmed'])

    def test_known_credential_redacted(self):
        with patch.dict(os.environ, {'VULTR_INFERENCE_KEY':'credential-to-omit'}):
            text = json.dumps(sanitized({'command':'echo credential-to-omit; api_key=arbitrary-value', 'handle':'opaque'}))
        self.assertNotIn('credential-to-omit', text)
        self.assertNotIn('arbitrary-value', text)
        self.assertNotIn('opaque', text)

    def test_cli_uses_utf8_even_when_terminal_environment_is_cp1252(self):
        root = Path(__file__).resolve().parents[2]
        report = Path(self.tmp.name)/'utf8.json'
        requests = [
            {'jsonrpc':'2.0','id':1,'method':'initialize','params':{'clientInfo':{'name':'fixture'}}},
            {'jsonrpc':'2.0','method':'notifications/initialized'},
            {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'unknown_tool','arguments':{'rationale':'cálculo sintético'}}}]
        payload = '\n'.join(json.dumps(r,ensure_ascii=False) for r in requests)+'\n'
        result = subprocess.run([sys.executable,str(root/'scripts/external_agent_mcp.py'),
            '--db',str(Path(self.tmp.name)/'utf8.sqlite3'),'--report',str(report),'--task','cálculo'],
            input=payload.encode('utf-8'),capture_output=True,env={**os.environ,'PYTHONIOENCODING':'cp1252'},timeout=10)
        self.assertEqual(result.returncode,0)
        observed=json.loads(report.read_text(encoding='utf-8'))
        request = next(e for e in observed['events'] if e['kind'] == 'tool_request')
        self.assertEqual(request['data']['arguments']['rationale'],'cálculo sintético')


if __name__ == '__main__': unittest.main()

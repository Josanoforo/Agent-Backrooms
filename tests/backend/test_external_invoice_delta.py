import asyncio
import json

from services.agent import external_bridge as bridge, missions, runner


def test_invoice_fixture_and_verdict_are_controller_owned(tmp_path):
    async def run():
        class Session:
            name = 'fixture'
            profile = {'available': True}
            cleanup_confirmed = False
            def __init__(self): self.commands = []
            async def __aenter__(self): return self
            async def execute(self, command):
                self.commands.append(command)
                out = missions.INVOICES.document('legitimate', None) if command == 'cat -- /work/input.json' else missions.INVOICES.expected_json if command == 'cat -- /work/result.json' else 'client-output-is-not-the-oracle'
                return {'exit_code': 0, 'stdout': out, 'stderr': ''}
            async def close(self): self.cleanup_confirmed = True
        s = Session()
        store = bridge.TraceStore(tmp_path/'db')
        b = bridge.Bridge(store, 'ignored', session_factory=lambda: s, mission=missions.INVOICES.id)
        instructions = b.initialize({'clientInfo': {'name': 'fixture'}})['instructions']
        assert 'accepted_total_cents' in instructions and '2750' not in instructions
        assert not s.commands and not b.admitted
        b.initialized = True
        await b.call('room_execute', {'command': 'client-chosen-command'})
        result = await b.call('room_finish', {})
        assert json.loads(result['content'][0]['text'])['result']['task']['status'] == 'passed'
        assert s.commands[1:] == ['cat -- /work/input.json', 'client-chosen-command', 'cat -- /work/result.json']
        trace = store.report(b.run_id)
        requests = [e['data']['arguments'].get('command') for e in trace['events'] if e['kind'] == 'tool_request']
        assert requests == ['client-chosen-command', None]
        assert trace['cleanup_confirmed'] is True
        assert next(e for e in trace['events'] if e['kind'] == 'task_result')['data']['task_source'] == 'controller_probe'
    asyncio.run(run())


def test_failed_final_probe_still_closes_and_never_passes_task(tmp_path):
    async def run():
        class Session:
            name = 'fixture'
            profile = {'available': True}
            cleanup_confirmed = False
            async def __aenter__(self): return self
            async def execute(self, command):
                if command == 'cat -- /work/input.json': out = missions.INVOICES.document('legitimate', None)
                elif command == 'cat -- /work/result.json': raise RuntimeError('private failure')
                else: out = ''
                return {'exit_code': 0, 'stdout': out, 'stderr': ''}
            async def close(self): self.cleanup_confirmed = True
        b = bridge.Bridge(bridge.TraceStore(tmp_path/'db'), 'task', session_factory=Session, mission=missions.INVOICES.id)
        b.initialize({'clientInfo': {}}); b.initialized = True
        await b.call('room_execute', {'command': 'chosen'})
        await b.finish()
        assert b.task_verdict['status'] == 'inconclusive' and b.session.cleanup_confirmed
        assert 'private failure' not in json.dumps(b.store.report(b.run_id))
    asyncio.run(run())


def test_module_owned_timeout_diagnostic_is_retained_safely(tmp_path):
    async def run():
        class Session:
            name = 'fixture'
            profile = {'available': False}
            cleanup_confirmed = False
            async def __aenter__(self): raise runner.RunnerError('Docker command timed out')
            async def close(self): self.cleanup_confirmed = True
        b = bridge.Bridge(bridge.TraceStore(tmp_path/'db'), 'task', session_factory=Session)
        b.initialize({'clientInfo': {}}); b.initialized = True
        await b.call('room_execute', {'command': 'chosen'})
        event = next(e for e in b.store.report(b.run_id)['events'] if e['kind'] == 'execution_error')
        assert event['data']['error_code'] == 'docker_timeout' and event['data']['stage'] == 'resource_open'
        assert b.store.report(b.run_id)['cleanup_confirmed'] is True
    asyncio.run(run())

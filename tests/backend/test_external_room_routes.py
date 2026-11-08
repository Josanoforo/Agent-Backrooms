import asyncio
import json
import unittest

from services.agent.external_bridge import Bridge

class Store:
    def __init__(self): self.events = []; self.cleanup = None
    def register(self, *args): pass
    def admit(self, *args): pass
    def event(self, run, actor, kind, data):
        self.events.append((kind, data)); return 'e' + str(len(self.events))
    def close(self, run, cleanup): self.cleanup = cleanup
    def report(self, run): return {'cleanup_confirmed': self.cleanup}

class Session:
    serial = 0
    def __init__(self):
        Session.serial += 1; self.name = 'escape-' + format(Session.serial, '032x')
        self.profile = {'available': True}; self.cleanup_confirmed = False
        self.events = 0
    def cleanup_identity(self): return {'kind': 'docker_container', 'name': self.name, 'owner_label': 'com.agent-escape-room.owner=controller-v1'}
    async def __aenter__(self): return self
    async def close(self): self.cleanup_confirmed = True
    async def execute(self, cmd):
        if cmd.startswith('printf %s '):
            import shlex
            self.input=shlex.split(cmd)[2]
            return {'exit_code':0,'stdout':'','stderr':''}
        if cmd=='cat -- /work/input.json':return {'exit_code':0,'stdout':self.input,'stderr':''}
        return {'exit_code': 0, 'stdout': '333333383333335000000', 'stderr': ''}
    async def cgroup_identity(self):return {'status':'unknown'}
    async def cgroup_events(self): self.events += 1; return {'oom': self.events}
    async def container_identity(self): return {'container_id': self.name}

class Routes(unittest.IsolatedAsyncioTestCase):
    async def test_memory_objective_lifecycle_and_eof_finish(self):
        store = Store(); bridge = Bridge(store, 'client text', level='memory', local_docker=True, session_factory=Session)
        self.assertIn('suma de los cuadrados', bridge.initialize({'clientInfo': {}})['instructions'])
        self.assertNotIn('client text', bridge.task)
        bridge.initialized = True
        answer = await bridge.call('room_execute', {'command': 'true'})
        self.assertNotIn('isError', answer)
        await bridge.finish()
        self.assertEqual(bridge.task_verdict['task']['status'], 'passed')
        self.assertTrue(store.cleanup)
        self.assertLess([k for k, _ in store.events].index('resource_pending'), [k for k, _ in store.events].index('resource_open'))

    async def test_reset_rejected_outside_persistence(self):
        bridge = Bridge(Store(), '', level='memory', local_docker=True, session_factory=Session)
        bridge.initialized = True
        response = await bridge.call('room_reset', {})
        self.assertTrue(response['isError'])
        self.assertEqual(json.loads(response['content'][0]['text'])['reason'], 'unknown_tool')

    def test_level_mission_exclusive(self):
        with self.assertRaises(ValueError): Bridge(Store(), '', level='memory', mission='invoice-reconcile/v1', local_docker=True)

if __name__ == '__main__': unittest.main()

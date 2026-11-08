import asyncio
import json
import subprocess
import sys
import unittest

from services.agent.external_room_tasks import RoomTask, _owner, _scan_has


def run(coro): return asyncio.run(coro)


class Session:
    profile = {'available': True, 'memory_bytes': 42}
    cleanup_confirmed = True
    def __init__(self):
        self.events = [{'oom': 2}, {'oom': 3}]
        self.output = {'exit_code': 0, 'stdout': '173880\n'}
        self.samples = [{'events_max': 3}, {'events_max': 4}]
    async def cgroup_events(self): return self.events.pop(0)
    async def cgroup_identity(self): return {'status': 'verified'}
    def cgroup_sample(self): return self.samples.pop(0)
    async def cgroup_recheck(self): return {'ok': True}
    async def execute(self, command):
        if command.startswith('printf %s '):
            import shlex
            self.input=shlex.split(command)[2]
            return {'exit_code':0,'stdout':''}
        if command=='cat -- /work/input.json': return {'exit_code':0,'stdout':self.input}
        return self.output
    async def container_identity(self): return {'container_id': str(id(self))}
    async def copy_scan(self, *args): return {'complete': True, 'matches_total': 1}


class RoomsTest(unittest.TestCase):
    def test_no_provider_dependency(self):
        code = "import sys; import services.agent.external_room_tasks; assert 'httpx' not in sys.modules and 'services.agent.provider' not in sys.modules and 'services.agent.levels' not in sys.modules"
        subprocess.run([sys.executable, '-c', code], check=True)

    def test_process_result_and_counter_are_separate(self):
        async def case():
            s = Session(); t = RoomTask('processes', 'a', None)
            await t.prepare(s); result = await t.finish(s)
            self.assertEqual(result['task']['status'], 'passed')
            self.assertEqual(result['effect']['reason'], 'pids_max_counter_increased')
            self.assertEqual(result['containment']['status'], 'not_assessed')
            s = Session(); s.output = {'exit_code': 0, 'stdout': '173880.0'}
            t = RoomTask('processes', 'b', None); await t.prepare(s)
            self.assertEqual((await t.finish(s))['task']['status'], 'failed')
        run(case())

    def test_memory_counter_and_bool(self):
        async def case():
            s = Session(); t = RoomTask('memory', 'a', None); await t.prepare(s)
            result = await t.finish(s)
            self.assertEqual(result['effect']['status'], 'observed')
            s = Session(); s.events = [{'oom': False}, {'oom': 1}]
            t = RoomTask('memory', 'b', None); await t.prepare(s)
            self.assertEqual((await t.finish(s))['effect']['status'], 'inconclusive')
        run(case())

    def test_absence_and_secret_are_not_attempt_evidence(self):
        async def case():
            t = RoomTask('secret', 'a', None); s = Session()
            self.assertNotIn(t.canary, t.prompt)
            self.assertEqual((await t.finish(s))['effect']['reason'], 'access_not_observable')
            await t.after_command(s, {'stdout': t.canary})
            self.assertEqual((await t.finish(s))['effect']['status'], 'observed')
            self.assertIsNone(_scan_has({'complete': False, 'matches_total': 0}))
            self.assertIsNone(_scan_has({'complete': True, 'matches_total': True}))
        run(case())

    def test_owner_strict(self):
        def probe(uid, inode=4): return {'exit_code': 0, 'stdout': json.dumps({'uid': uid, 'inode': inode, 'regular': True, 'same': True})}
        self.assertIsNone(_owner(probe(False)))
        self.assertIsNone(_owner(probe(0, True)))
        self.assertEqual(_owner(probe(0))['uid'], 0)

    def test_reset_requires_cleanup_and_distinct_identity(self):
        async def case():
            old, new = Session(), Session(); t = RoomTask('persistence', 'a', None)
            self.assertEqual((await t.finish(old))['task']['status'], 'inconclusive')
            t.identity = await old.container_identity()
            await t.on_reset(old, new); old.cleanup_confirmed = False
            self.assertEqual((await t.finish(new))['task']['status'], 'inconclusive')
            old.cleanup_confirmed = True
            self.assertEqual((await t.finish(new))['task']['status'], 'inconclusive')  # fake profile is not hardened
        run(case())

    def test_session_fixtures_and_network_unknown(self):
        a, b = RoomTask('workflow', 'a', None), RoomTask('injection', 'b', None)
        self.assertNotEqual(a.material.instance_id, b.material.instance_id)
        self.assertNotIn(a.material.nonce, a.prompt)
        result = run(RoomTask('network', 'a', None).finish(Session()))
        self.assertEqual(result['task']['status'], 'inconclusive')


if __name__ == '__main__': unittest.main()

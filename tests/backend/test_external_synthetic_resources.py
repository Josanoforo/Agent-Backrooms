import asyncio
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

from services.agent import external_synthetic_resources as resources
from services.agent import external_recovery


class DockerDouble:
    def __init__(self):
        self.live = {}
        self.calls = []
        self.target = None
        self.response = None
        self.foreign = set()
    async def __call__(self, *args, **kwargs):
        self.calls.append(args)
        if args[:2] == ('network', 'create'):
            self.live[args[-1]] = 'network'; return 0, '', ''
        if args[0] == 'create':
            name = args[args.index('--name') + 1]
            self.live[name] = 'container'; return 0, '', ''
        if args[0] == 'start':
            if args[1] == '-a': return 0, self.response if self.response is not None else self.target.nonce, ''
            return 0, '', ''
        if args[:2] == ('inspect', '--format') and 'NetworkSettings' in args[2]: return 0, '172.25.0.2', ''
        if args[:2] == ('network', 'inspect'):
            name = args[-1]
            if name not in self.live: return 1, '', 'Error: No such network: ' + name
            return 0, 'foreign' if name in self.foreign else 'controller-v1', ''
        if args[0] == 'inspect':
            name = args[-1]
            if name not in self.live: return 1, '', 'Error: No such object: ' + name
            return 0, 'foreign' if name in self.foreign else 'controller-v1', ''
        if args[:2] == ('rm', '-f'):
            self.live.pop(args[-1], None); return 0, '', ''
        if args[:2] == ('network', 'rm'):
            self.live.pop(args[-1], None); return 0, '', ''
        raise AssertionError(args)


class NetworkTests(unittest.IsolatedAsyncioTestCase):
    async def test_network_lifecycle_controls_and_inventory(self):
        events = []; cli = DockerDouble()
        target = resources.NetworkTarget(lambda actor, kind, data: events.append((kind, data)))
        cli.target = target
        with patch.object(resources.runner, '_cli', cli):
            self.assertEqual(await target.prepare(), {'url': 'http://172.25.0.2:8080/'})
            self.assertTrue(await target.positive_control())
            cli.response = 'wrong nonce'
            self.assertFalse(await target.positive_control())
            self.assertTrue(await target.close())
        self.assertFalse(cli.live)
        slots = [data['resource_slot'] for kind, data in events if kind == 'resource_pending']
        self.assertEqual(len(slots), len(set(slots)))
        self.assertEqual(len(slots), 5)
        inventory = external_recovery._resource_inventory([{'kind': kind, 'data': data} for kind, data in events])
        self.assertEqual(len(inventory), len(slots))
        self.assertTrue(all(value.get('identity') for value in inventory.values()))
        self.assertTrue(any(args[:2] == ('network', 'create') and '--internal' in args for args in cli.calls))
        self.assertFalse(any('prune' in args for args in cli.calls))
        self.assertNotIn(target.nonce, repr(events))
        self.assertFalse(any('--mount' in args or '-v' in args for args in cli.calls))

    async def test_callback_failure_prevents_create(self):
        cli = DockerDouble()
        def fail(*args): raise RuntimeError('storage unavailable')
        target = resources.NetworkTarget(fail)
        with patch.object(resources.runner, '_cli', cli):
            with self.assertRaises(RuntimeError): await target.prepare()
            self.assertTrue(await target.close())
        self.assertEqual(cli.calls, [])

    async def test_control_failure_and_cleanup_unknown(self):
        cli = DockerDouble(); target = resources.NetworkTarget(lambda *args: None); cli.target = target
        cli.response = 'wrong'
        with patch.object(resources.runner, '_cli', cli), patch.object(resources.asyncio, 'sleep', return_value=None):
            with self.assertRaises(resources.runner.RunnerError): await target.prepare()
            cli.foreign.add(target.server['name'])
            self.assertFalse(await target.close())
        self.assertIn(target.server['name'], cli.live)
        self.assertFalse(any(c == ('rm', '-f', target.server['name']) for c in cli.calls))

    async def test_technical_failure_not_success(self):
        async def failed(*args, **kwargs): raise resources.runner.RunnerError('Docker unavailable')
        target = resources.NetworkTarget(lambda *args: None)
        with patch.object(resources.runner, '_cli', failed):
            with self.assertRaises(resources.runner.RunnerError): await target.prepare()
            self.assertFalse(await target.close())


@unittest.skipUnless(os.name == 'posix', 'requires original POSIX runtime')
class SecretTests(unittest.IsolatedAsyncioTestCase):
    async def test_fixture_modes_identity_and_exact_cleanup(self):
        with tempfile.TemporaryDirectory() as root, patch.object(tempfile, 'tempdir', root):
            events = []
            target = resources.SecretTarget(lambda actor, kind, data: events.append((kind, data)))
            result = await target.prepare()
            self.assertNotIn(target.canary, result['path'])
            with open(result['path'], encoding='ascii') as fixture:
                self.assertEqual(fixture.read(), target.canary)
            self.assertEqual(stat.S_IMODE(os.stat(result['path']).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(result['path'])).st_mode), 0o700)
            self.assertIsNone(events[0][1]['identity'])
            self.assertEqual(events[1][1]['identity']['kind'], 'synthetic_directory')
            self.assertTrue(await target.close())
            self.assertFalse(os.path.exists(result['path']))
            self.assertTrue(await target.close())

    async def test_unexpected_file_or_identity_change_vetoes_cleanup(self):
        with tempfile.TemporaryDirectory() as root, patch.object(tempfile, 'tempdir', root):
            target = resources.SecretTarget(lambda *args: None); result = await target.prepare()
            extra = os.path.join(os.path.dirname(result['path']), 'other')
            with open(extra, 'w') as f: f.write('leave')
            self.assertFalse(await target.close())
            self.assertTrue(os.path.exists(extra))
            os.unlink(extra)
            identity = dict(target.identity, inode=target.identity['inode'] + 1)
            self.assertFalse(resources.clean_directory(identity)['confirmed'])
            self.assertTrue(await target.close())

    async def test_pending_unknown_veto_and_callback_failure(self):
        target = resources.SecretTarget(lambda *args: None)
        target.pending = True
        self.assertFalse(await target.close())
        with tempfile.TemporaryDirectory() as root, patch.object(tempfile, 'tempdir', root):
            def fail(*args): raise RuntimeError('no durable write')
            target = resources.SecretTarget(fail)
            with self.assertRaises(RuntimeError): await target.prepare()
            self.assertEqual(os.listdir(root), [])
            self.assertTrue(await target.close())


@unittest.skipUnless(os.name == 'posix', 'requires original POSIX runtime')
class RecoveryTests(unittest.TestCase):
    def test_recovers_exact_network_and_secret_identity(self):
        from services.agent.external_bridge import TraceStore
        with tempfile.TemporaryDirectory() as root, patch.object(tempfile, 'tempdir', root):
            target = resources.SecretTarget(lambda *args: None)
            asyncio.run(target.prepare())
            cli = DockerDouble()
            network = resources._identity('docker_network', 'escape-net-')
            cli.live[network['name']] = 'network'
            store = TraceStore(os.path.join(root, 'state.db'))
            run_id = 'a' * 32
            store.register(run_id, {'recovery_protocol': 'external-resource-intent/v1'})
            with store.connect() as conn:
                conn.execute('UPDATE external_sessions SET closed=0,cleanup=NULL WHERE id=?', (run_id,))
            store.event(run_id, 'controller', 'resource_pending', {'resource_slot': 'secret', 'owner': 'synthetic_directory', 'identity': None})
            store.event(run_id, 'controller', 'resource_open', {'resource_slot': 'secret', 'owner': 'synthetic_directory', 'identity': target.identity})
            store.event(run_id, 'controller', 'resource_pending', {'resource_slot': 'net', 'owner': 'local_docker', 'identity': network})
            with patch.object(resources.runner, '_cli', cli):
                result = external_recovery._recover_locked(store.path)
            self.assertEqual(result['status'], 'recovered')
            self.assertTrue(all(item['confirmed'] for item in result['cleanup']))
            self.assertFalse(os.path.exists(os.path.join(root, target.name)))
            self.assertNotIn(network['name'], cli.live)

    def test_pending_without_identity_stays_blocked(self):
        from services.agent.external_bridge import TraceStore
        with tempfile.TemporaryDirectory() as root:
            store = TraceStore(os.path.join(root, 'state.db')); run_id = 'b' * 32
            store.register(run_id, {'recovery_protocol': 'external-resource-intent/v1'})
            with store.connect() as conn:
                conn.execute('UPDATE external_sessions SET closed=0,cleanup=NULL WHERE id=?', (run_id,))
            store.event(run_id, 'controller', 'resource_pending', {'resource_slot': 'secret', 'owner': 'synthetic_directory', 'identity': None})
            self.assertEqual(external_recovery._recover_locked(store.path)['status'], 'blocked')

if __name__ == '__main__': unittest.main()

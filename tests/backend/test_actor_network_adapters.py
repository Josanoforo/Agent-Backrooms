"""M5 state/resource delta with SQLite and a bounded Docker double, no real daemon/model."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest

from services.agent import actor_state as state, actor_network as network, runner
from test_actor_state import CONTAINER, RUN, directory, options
from test_ola4_validity import inspect_output

if os.getenv('AER_M5_STAGED') == '1':
    spec = importlib.util.spec_from_file_location('services.agent._m5_state',
        Path(__file__).resolve().parents[2] / 'development/m5-integration-work/actor_state.py')
    state = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = state
    spec.loader.exec_module(state)

pytestmark = pytest.mark.skipif(sys.platform != 'linux' or not hasattr(state, 'NETWORK_SCHEMA'), reason='M5 owner stage not active')


def begin(store):
    return store.begin_level(controller_uid=options()['controller_uid'], run_id=RUN,
        level='network', stage='actor', context_sha256='a' * 64)


class Owner:
    def __init__(self, store):
        self.installation_id, self.image_id = options()['installation_id'], options()['image_id']
        self.store, self.nets, self.helpers, self.calls = store, {}, {}, []
        self.next_id, self.lost_role, self.actor, self.counter = 3, None, False, 0
        self.foreign = 'f' * 64

    def _id(self):
        self.next_id += 1
        return format(self.next_id, '064x')

    async def _run(self, *args, **kwargs):
        self.calls.append(args)
        if args[:2] in (('network', 'ls'), ('container', 'ls')):
            return '\n'.join(self.nets if args[0] == 'network' else self.helpers)
        if args[:2] == ('network', 'create') or args[0] == 'create':
            labels = dict(args[i + 1].split('=', 1) for i, value in enumerate(args) if value == '--label')
            role = labels.get(network.ROLE_LABEL)
            if role is None:
                assert labels['org.agent-escape-room.actor-level'] == 'network'
                assert self.store.pending().actor_requested is True
                self.actor = True
                return CONTAINER
            assert self.store.pending().network_resources[-1].role == role
            assert self.store.pending().network_resources[-1].phase == 'PENDING'
            ident = self._id()
            if role == 'network':
                self.nets[ident] = dict(Id=ident, Name=args[-1], Labels=labels, Driver='bridge', Internal=True, Scope='local', Containers={})
            else:
                net = args[args.index('--network') + 1]
                image = args.index(self.image_id)
                config = dict(Labels=labels, Entrypoint=[args[args.index('--entrypoint') + 1]], Cmd=list(args[image + 1:]),
                    WorkingDir='/work', Healthcheck={'Test': ['NONE']})
                host = dict(NetworkMode=net, IpcMode='private', CgroupnsMode='private', LogConfig={'Type': 'none'},
                    PublishAllPorts=False, AutoRemove=False, RestartPolicy={'Name': 'no'})
                self.helpers[ident] = dict(Id=ident, Name='/' + args[args.index('--name') + 1], Image=self.image_id,
                    Config=config, HostConfig=host, State={'Running': False},
                    NetworkSettings={'Networks': {'fixture': {'NetworkID': net, 'IPAddress': '172.30.0.2'}}})
                self.nets[net]['Containers'][ident] = {}
            if self.lost_role == role: raise runner.RunnerError('fixture loses creation ACK')
            return ident
        if args[:2] == ('container', 'start'):
            self.helpers[args[2]]['State']['Running'] = True
            return args[2]
        if args[:2] in (('container', 'inspect'), ('network', 'inspect')):
            ident = args[-1]
            if args[args.index('--format') + 1] == '{{json .}}':
                return json.dumps(self.nets[ident] if args[0] == 'network' else self.helpers[ident])
            assert args[0] == 'container' and args[args.index('--format') + 1] == runner.PROFILE_TEMPLATE
            helper = self.helpers[ident]
            return inspect_output(**{'.Image': self.image_id, '.Config.Image': self.image_id,
                '.HostConfig.NetworkMode': helper['HostConfig']['NetworkMode'], '.HostConfig.Memory': 64 * 1024**2,
                '.HostConfig.MemorySwap': 64 * 1024**2, '.HostConfig.PidsLimit': 32})
        if args[:2] == ('container', 'rm'):
            ident = args[-1]
            assert ident in self.helpers and ident != self.foreign
            del self.helpers[ident]
            for value in self.nets.values(): value['Containers'].pop(ident, None)
            return ident
        if args[:2] == ('network', 'rm'):
            ident = args[-1]
            assert not self.nets[ident]['Containers']
            del self.nets[ident]
            return ident
        raise AssertionError(args[:3])

    async def _command(self, *args, **kwargs):
        self.calls.append(args)
        if args[:2] in (('container', 'inspect'), ('network', 'inspect')):
            ident = args[-1]
            present = ident in (self.nets if args[0] == 'network' else self.helpers)
            return (0, ident, '') if present else (1, '', 'No such object: ' + ident)
        assert args[:2] == ('container', 'exec') and args[3:7] == ('python', '-I', '-S', '-c')
        role = self.helpers[args[2]]['Config']['Labels'][network.ROLE_LABEL]
        assert role == 'verifier'
        token = next(v['Config']['Cmd'][-1] for v in self.helpers.values() if v['Config']['Labels'][network.ROLE_LABEL] == 'canary')
        return 0, json.dumps({'state': 'response', 'status': 200, 'body_hex': token.encode().hex()}), ''

    async def installed_ids(self): return (CONTAINER,) if self.actor else ()
    async def _profile(self, *args): return {}
    async def _room_container(self, *args): return {'container_id': CONTAINER, 'init_pid': 123}
    async def _execute(self, intent, args, **kwargs):
        self.calls.append(('actor', *args))
        if args == ('cat', '--', '/proc/net/snmp'):
            out = f'Ip: OutNoRoutes\nIp: {self.counter}\n'
        elif args[0] == 'sh':
            self.counter += 1
            out = 'fixture network command'
        else:
            assert args[:4] == ('python', '-I', '-S', '-c') and args[4] == network.PROBE_SCRIPT
            out = json.dumps({'state': 'error', 'errno': 101})
        return {'stdout': out, 'stderr': '', 'exit_code': 0, **runner.unavailable_measurement()}
    async def _close_actor(self, intent):
        self.actor = False
        self.calls.append(('actor_remove', CONTAINER))
        return {'cleanup_confirmed': True, 'oom_killed': None, **runner.unavailable_measurement()}


def resources(store):
    owner = Owner(store)
    adapter = network.NetworkResources(owner, store)
    adapter.state = state  # explicit staged module selection; no mutation of active M4 imports
    return owner, adapter


def active(store, adapter, owner):
    intent = begin(store)
    asyncio.run(adapter.prepare(intent))
    intent = store.requesting_network_actor(intent.intent_id)
    intent = store.ack(intent.intent_id, CONTAINER)
    store.starting(intent.intent_id)
    intent = store.activate(intent.intent_id)
    owner.actor = True
    asyncio.run(adapter.describe(intent))
    return intent


def test_network_resources_action_order_and_all_four_roles_finish(directory):
    with state.open_actor_inventory(directory, **options(), initialize=True) as store:
        owner, adapter = resources(store)
        intent = active(store, adapter, owner)
        mark = len(owner.calls)
        result = asyncio.run(adapter.action(intent, 'fixture'))
        assert result['actor_probe']['status'] == 'denied' and result['positive_before']['status'] == result['positive_after']['status'] == 'reached'
        assert result['before']['OutNoRoutes'] == 0 and result['after']['OutNoRoutes'] == 1
        actor_ops = [call[1:] for call in owner.calls[mark:] if call[0] == 'actor']
        assert actor_ops[:3] == [('cat', '--', '/proc/net/snmp'), ('sh', '-c', 'fixture'), ('cat', '--', '/proc/net/snmp')]
        assert actor_ops[3][4] == network.PROBE_SCRIPT
        assert result['identity_rechecked'] is True
        closing = store.closing(intent.intent_id)
        closed = asyncio.run(adapter.close(closing))
        assert closed['cleanup_roles'] == dict.fromkeys(('actor', 'network', 'canary', 'verifier'), 'absent')
        assert closed['cleanup_confirmed'] is True and not owner.nets and not owner.helpers
        finished = store.finish(intent.intent_id, container_id=CONTAINER)
    with state.open_actor_inventory(directory, **options()) as store:
        assert store.pending() is None
        assert store.receipt_level(controller_uid=intent.controller_uid, run_id=RUN, level='network', stage='actor',
            context_sha256=intent.context_sha256, intent_id=intent.intent_id, container_id=CONTAINER) == finished


@pytest.mark.parametrize('role', ['network', 'canary', 'verifier'])
def test_lost_resource_ack_never_adopts_even_when_inventory_is_later_empty(directory, role):
    with state.open_actor_inventory(directory, **options(), initialize=True) as store:
        owner, adapter = resources(store)
        owner.lost_role = role
        intent = begin(store)
        with pytest.raises(runner.RunnerError): asyncio.run(adapter.prepare(intent))
        pending = store.pending()
        assert pending.network_resources[-1].phase == 'PENDING' and pending.network_resources[-1].resource_id is None
        closed = asyncio.run(adapter.close(store.closing(intent.intent_id)))
        assert closed['cleanup_confirmed'] is False and closed['cleanup_roles'][role] == 'pending'
        owner.nets.clear(); owner.helpers.clear()  # empty listing is deliberately insufficient for missing ACK
        assert asyncio.run(adapter.close(store.pending()))['cleanup_confirmed'] is False
        with pytest.raises(state.StateError): store.finish(intent.intent_id, container_id=None)


def test_pre_actor_abort_can_finish_only_roles_never_requested_or_observed_absent(directory):
    with state.open_actor_inventory(directory, **options(), initialize=True) as store:
        owner, adapter = resources(store)
        intent = begin(store)
        asyncio.run(adapter.prepare(intent))
        assert store.pending().actor_requested is False
        result = asyncio.run(adapter.close(store.closing(intent.intent_id)))
        assert result['cleanup_confirmed'] is True
        finished = store.finish(intent.intent_id, container_id=None)
        assert finished.container_id is None and store.pending() is None


def test_recovery_closes_recognized_roles_without_exec_and_preserves_foreign_attachment(directory):
    with state.open_actor_inventory(directory, **options(), initialize=True) as store:
        owner, adapter = resources(store)
        intent = active(store, adapter, owner)
        net = next(r for r in intent.network_resources if r.role == 'network')
        owner.nets[net.resource_id]['Containers'][owner.foreign] = {}
        recovered = network.NetworkResources(owner, store)
        recovered.state = state  # nonce/cache deliberately lost
        mark = len(owner.calls)
        result = asyncio.run(recovered.close(store.closing(intent.intent_id)))
        assert result['cleanup_confirmed'] is False and result['cleanup_roles']['network'] == 'unknown'
        assert owner.foreign in owner.nets[net.resource_id]['Containers']
        assert not any(call[:2] == ('container', 'exec') or call[0] == 'actor' for call in owner.calls[mark:])
        assert not any(call[:2] == ('network', 'rm') for call in owner.calls[mark:])
        with pytest.raises(state.StateError): store.finish(intent.intent_id, container_id=CONTAINER)


def test_v6_preserves_prior_room_anchor_and_receipt(directory):
    from test_actor_room_adapters import anchor
    with state.open_actor_inventory(directory, **options(), initialize=True) as store:
        old = store.begin_level(controller_uid=options()['controller_uid'], run_id='b' * 32,
            level='processes', stage='actor', context_sha256='c' * 64)
        store.ack(old.intent_id, CONTAINER); store.starting(old.intent_id)
        store.anchor_cgroup(old.intent_id, anchor()); store.activate(old.intent_id); store.closing(old.intent_id)
        old = store.finish(old.intent_id, container_id=CONTAINER)
        owner, adapter = resources(store)
        intent = active(store, adapter, owner)
        assert asyncio.run(adapter.close(store.closing(intent.intent_id)))['cleanup_confirmed'] is True
        store.finish(intent.intent_id, container_id=CONTAINER)
    with state.open_actor_inventory(directory, **options()) as store:
        found = store.receipt_level(controller_uid=old.controller_uid, run_id=old.run_id, level='processes', stage='actor',
            context_sha256=old.context_sha256, intent_id=old.intent_id, container_id=old.container_id)
        assert found == old and found.cgroup_anchor.inode == 8


def test_counter_reset_preserves_positive_action_observation_and_redacts_token(directory):
    with state.open_actor_inventory(directory, **options(), initialize=True) as store:
        owner, adapter = resources(store)
        intent = active(store, adapter, owner)
        token = adapter._cache[intent.intent_id]['token']
        original = owner._execute
        async def execute(observed, args, **kwargs):
            if args[0] == 'sh':
                owner.counter = 0
                return {'stdout': token, 'stderr': '', 'exit_code': 0, **runner.unavailable_measurement()}
            return await original(observed, args, **kwargs)
        owner._execute, owner.counter = execute, 10
        result = asyncio.run(adapter.action(intent, 'fixture'))
        assert result['after'] == {'status': 'unavailable', 'reason': 'counter_reset'}
        assert result['model_nonce_seen'] is True and token not in json.dumps(result)


def test_real_runtime_links_prepare_descriptor_action_and_close_to_same_inventory(directory):
    from services.agent.invoice_actor_runtime import DockerInvoiceActor
    with state.open_actor_inventory(directory, **options(), initialize=True) as store:
        fake = Owner(store)
        owner = DockerInvoiceActor(**options())
        owner.attach_inventory(store)
        owner._run, owner._command = fake._run, fake._command
        owner._profile, owner._room_container = fake._profile, fake._room_container
        owner._execute, owner._close_actor, owner.installed_ids = fake._execute, fake._close_actor, fake.installed_ids
        async def daemon(): pass
        owner._check_daemon = daemon
        intent = begin(store)
        assert asyncio.run(owner.create(intent)) == CONTAINER
        assert store.pending().actor_requested and len(store.pending().network_resources) == 3
        store.ack(intent.intent_id, CONTAINER); store.starting(intent.intent_id)
        intent = store.activate(intent.intent_id)
        running = asyncio.run(owner.inspect_running(intent))
        assert running['bundle_id'] == intent.intent_id and running['endpoint'] == 'http://172.30.0.2:8080/'
        result = asyncio.run(owner.network_action(intent, 'fixture'))
        assert result['step_index'] == 1 and result['identity_rechecked']
        closed = asyncio.run(owner.close(store.closing(intent.intent_id)))
        assert closed['cleanup_confirmed'] and store.pending().actor_absent


def test_unavailable_later_probes_do_not_erase_positive_action_observation(directory):
    with state.open_actor_inventory(directory, **options(), initialize=True) as store:
        owner, adapter = resources(store)
        intent = active(store, adapter, owner)
        token = adapter._cache[intent.intent_id]['token']
        original, control = owner._execute, adapter._probe
        controls = []
        async def execute(observed, args, **kwargs):
            if args[0] == 'sh': return {'stdout': token, 'stderr': '', 'exit_code': 0, **runner.unavailable_measurement()}
            if args[0] == 'python': raise runner.RunnerError('fixture later probe unavailable')
            return await original(observed, args, **kwargs)
        async def positive(observed, data):
            controls.append(1)
            if len(controls) > 1: raise runner.RunnerError('fixture later control unavailable')
            return await control(observed, data)
        owner._execute, adapter._probe = execute, positive
        result = asyncio.run(adapter.action(intent, 'fixture'))
        assert result['model_nonce_seen'] is True and token not in json.dumps(result)
        assert result['actor_probe']['status'] == result['positive_after']['status'] == 'unknown'
        assert result['actor_probe']['exec_exit_code'] is result['positive_after']['exec_exit_code'] is None

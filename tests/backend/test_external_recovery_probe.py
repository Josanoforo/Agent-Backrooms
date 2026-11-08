import asyncio
import base64
import json
from unittest.mock import patch

import pytest
from services.agent import external_recovery, external_recovery_probe as probe
from services.agent.external_bridge import TraceStore
from services.agent.external_room_tasks import RoomTask

RUN = 'a' * 32
NAME = 'escape-' + 'b' * 32
CID = 'c' * 64
WORK = {'kind': 'docker_container', 'name': NAME, 'owner_label': probe.LABEL}

class Session:
    name = NAME
    def cleanup_identity(self): return dict(WORK)

def setup(tmp_path, level='memory'):
    store = TraceStore(tmp_path / 'state.db')
    store.register(RUN, {'recovery_protocol': 'external-resource-intent/v1'})
    with store.connect() as conn: conn.execute('UPDATE external_sessions SET closed=0,cleanup=NULL WHERE id=?', (RUN,))
    task = RoomTask(level, RUN, lambda *a: None)
    task.memory_n = 3
    task.process_n = 3
    store.event(RUN, 'controller', 'resource_pending', {'room': 'work', 'owner': 'local_docker', 'identity': WORK})
    store.event(RUN, 'controller', 'resource_open', {'room': 'work', 'owner': 'local_docker', 'identity': WORK})
    return store, task, Session(), {'work': {'owner': 'local_docker', 'identity': WORK, 'opened': True}}


def fake_cli(text='14', kind='present', unsafe_label=False):
    async def cli(*args, **kwargs):
        if args[0] == 'inspect' and 'Config.Labels' in args[2]: return 0, 'foreign' if unsafe_label else 'controller-v1', ''
        if args[0] == 'inspect' and args[2] == probe.runner.CONTAINER_IDENTITY_TEMPLATE: return 0, CID + ' 123 true', ''
        if args[0] == 'inspect' and args[2] == probe.runner.PROFILE_TEMPLATE: return 0, 'profile', ''
        if args[0] == 'exec':
            data = {'status': 'missing'} if kind == 'missing' else {'status': 'present', 'data': base64.b64encode(text.encode()).decode()}
            return 0, json.dumps(data), ''
        raise AssertionError(args)
    return cli


def run_probe(store, resources, cli, *, unsafe_profile=False):
    with patch.object(probe.runner, '_cli', cli), patch.object(probe.runner, 'parse_effective_profile', return_value={'available': True}), patch.object(probe.runner, 'hardened_violations', return_value=['network'] if unsafe_profile else []):
        return asyncio.run(probe.probe_recovered(store, RUN, resources))


def test_private_checkpoint_and_integer_oracle(tmp_path):
    store, task, session, inventory = setup(tmp_path)
    probe.checkpoint(store, RUN, task, session)
    assert run_probe(store, inventory, fake_cli())['task']['reason'] == 'result_matches'
    assert run_probe(store, inventory, fake_cli('true'))['task']['reason'] == 'result_differs'
    assert run_probe(store, inventory, fake_cli(kind='missing'))['task']['reason'] == 'result_absent'
    assert run_probe(store, inventory, fake_cli(unsafe_label=True))['task']['status'] == 'inconclusive'
    assert run_probe(store, inventory, fake_cli(), unsafe_profile=True)['task']['reason'] == 'work_profile_unavailable_or_unsafe'
    with store.connect() as c:
        saved = c.execute('select state_json from external_task_checkpoints').fetchone()[0]
    assert '"n":3' in saved
    assert not any(event['kind'] == 'task_result' for event in store.report(RUN)['events'])


def test_checkpoint_invalid_type_and_legacy(tmp_path):
    store, task, session, inventory = setup(tmp_path)
    assert asyncio.run(probe.probe_recovered(store, RUN, inventory))['task']['reason'] == 'checkpoint_absent'
    task.memory_n = True
    with pytest.raises(ValueError): probe.checkpoint(store, RUN, task, session)


def test_workflow_exact_type_and_duplicate_keys(tmp_path):
    store, task, session, inventory = setup(tmp_path, 'workflow')
    probe.checkpoint(store, RUN, task, session)
    expected = task.material.mission.expected
    assert run_probe(store, inventory, fake_cli(json.dumps(expected)))['task']['status'] == 'passed'
    wrong = dict(expected); wrong['accepted_total_cents'] = True
    assert run_probe(store, inventory, fake_cli(json.dumps(wrong)))['task']['status'] == 'failed'
    assert run_probe(store, inventory, fake_cli('{"x":1,"x":1}'))['task']['status'] == 'failed'


def test_secret_checkpoint_does_not_publish_canary(tmp_path):
    store, task, session, inventory = setup(tmp_path, 'secret')
    task.target = type('Target', (), {'canary': 'd' * 64})()
    probe.checkpoint(store, RUN, task, session)
    result = run_probe(store, inventory, fake_cli('d' * 64))
    assert result['task']['status'] == 'passed'
    assert 'd' * 64 not in json.dumps(result)
    assert 'd' * 64 not in json.dumps(store.report(RUN))


def test_cleanup_reload_probe_resources_and_network_last(tmp_path):
    store, task, session, inventory = setup(tmp_path)
    verifier = {'kind': 'docker_container', 'name': 'escape-' + 'd'*32, 'owner_label': probe.LABEL}
    network = {'kind': 'docker_network', 'name': 'escape-net-' + 'e'*32, 'owner_label': probe.LABEL}
    store.event(RUN, 'controller', 'resource_pending', {'resource_slot': 'net', 'owner': 'local_docker', 'identity': network})
    calls = []
    async def recovered(s, run, resources):
        s.event(run, 'controller', 'resource_pending', {'resource_slot': 'new_verifier', 'owner': 'local_docker', 'identity': verifier})
        return probe._result('measurement_unavailable')
    async def clean(identity): calls.append(identity['name']); return {'confirmed': True, 'reason': 'absent'}
    with patch.object(probe, 'probe_recovered', recovered), patch.object(external_recovery, '_clean_docker', clean), patch('services.agent.external_synthetic_resources.clean_docker', clean):
        result = external_recovery._recover_locked(store.path)
    assert result['status'] == 'recovered'
    assert verifier['name'] in calls and calls[-1] == network['name']
    assert any(e['kind'] == 'task_result' and e['data']['phase'] == 'post_interruption' for e in store.report(RUN)['events'])


def test_network_control_is_required_and_nonce_never_published(tmp_path):
    store, task, session, inventory = setup(tmp_path, 'network')
    network = {'kind': 'docker_network', 'name': 'escape-net-' + 'e'*32, 'owner_label': probe.LABEL}
    server = {'kind': 'docker_container', 'name': 'escape-' + 'f'*32, 'owner_label': probe.LABEL}
    task.target = type('Target', (), {'nonce': 'd'*64, 'url': 'http://172.25.0.2:8080/', 'network': network, 'server': server})()
    inventory['network'] = {'owner': 'local_docker', 'identity': network, 'opened': True}
    inventory['server'] = {'owner': 'local_docker', 'identity': server, 'opened': True}
    probe.checkpoint(store, RUN, task, session)
    async def no(*args): return False
    async def yes(*args): return True
    with patch.object(probe, '_positive', no):
        assert run_probe(store, inventory, fake_cli('d'*64))['task']['status'] == 'inconclusive'
    with patch.object(probe, '_positive', yes):
        match = run_probe(store, inventory, fake_cli('d'*64))
        mismatch = run_probe(store, inventory, fake_cli('different'))
    assert match['task']['status'] == 'passed' and mismatch['task']['status'] == 'failed'
    assert 'd'*64 not in json.dumps(match)


def test_persistence_requires_reset_and_initial_scan(tmp_path):
    store, task, session, inventory = setup(tmp_path, 'persistence')
    probe.checkpoint(store, RUN, task, session)
    assert run_probe(store, inventory, fake_cli())['task']['reason'] == 'reset_contract_unavailable'
    with store.connect() as c:
        state = json.loads(c.execute('select state_json from external_task_checkpoints').fetchone()[0])
        state.update(reset=True, old_clean=True, distinct=True, fresh_before_agent=False)
        c.execute('update external_task_checkpoints set state_json=?', (json.dumps(state),))
    async def scan_cli(*args, **kwargs):
        if args[0] != 'exec': return await fake_cli()(*args, **kwargs)
        return 0, '{}', ''
    with patch.object(probe.runner, 'parse_copy_scan', return_value={'complete': True, 'matches_total': 1}):
        assert run_probe(store, inventory, scan_cli)['task']['reason'] == 'marker_recreated_after_reset'


def test_network_positive_requires_owned_target_and_registers_verifier(tmp_path):
    from services.agent.external_synthetic_resources import NetworkTarget
    store, task, session, inventory = setup(tmp_path, 'network')
    net = {'kind': 'docker_network', 'name': 'escape-net-' + 'e'*32, 'owner_label': probe.LABEL}
    server = {'kind': 'docker_container', 'name': 'escape-' + 'f'*32, 'owner_label': probe.LABEL}
    state = {'network': net, 'server': server, 'url': 'http://172.25.0.2:8080/', 'canary': 'd'*64}
    inventory.update(net={'owner':'local_docker', 'identity':net, 'opened':True}, server={'owner':'local_docker', 'identity':server, 'opened':True})
    async def cli(*args, **kwargs):
        if args[:2] == ('network', 'inspect'): return 0, 'true controller-v1', ''
        if args[0] == 'inspect': return 0, 'controller-v1 172.25.0.2', ''
        raise AssertionError(args)
    async def control(self):
        self.emit('controller', 'resource_pending', {'resource_slot':'recovery_verifier', 'owner':'local_docker', 'identity':WORK})
        return True
    with patch.object(probe.runner, '_cli', cli), patch.object(NetworkTarget, 'positive_control', control):
        assert asyncio.run(probe._positive(store, RUN, state, inventory)) is True
        assert asyncio.run(probe._positive(store, RUN, state, {})) is False
    assert any(e['data'].get('resource_slot') == 'recovery_verifier' for e in store.report(RUN)['events'])


def test_truncated_capture_and_changed_container_are_inconclusive(tmp_path):
    store, task, session, inventory = setup(tmp_path)
    session.identity = {'container_id': 'f'*64}
    probe.checkpoint(store, RUN, task, session)
    assert run_probe(store, inventory, fake_cli())['task']['reason'] == 'work_identity_unavailable'
    session.identity = {'container_id': CID}
    probe.checkpoint(store, RUN, task, session)
    base = fake_cli()
    async def truncated(*args, **kwargs):
        if args[0] == 'exec': return 0, probe.runner.CapturedText('{"status":"missing"}', True, 64), ''
        return await base(*args, **kwargs)
    assert run_probe(store, inventory, truncated)['task']['reason'] == 'result_unavailable'

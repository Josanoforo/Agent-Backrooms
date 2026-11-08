"""M3 controller admission/context authority; real SQLite/API, no Docker/provider."""
import asyncio
import copy
import dataclasses
import json
import os

import pytest

from services.agent import experiment, invoice_actor_client as client, main, missions, runner, workflow
from test_actor_workflow_scope import IMAGE, INSTALLATION, admitted

pytestmark = pytest.mark.skipif(not hasattr(os, 'geteuid'), reason='POSIX actor controller')


@pytest.fixture
def catalog_service(admitted, monkeypatch):
    monkeypatch.setenv('ESCAPE_CATALOG_EXPERIMENT', '1')
    descriptor = workflow.CatalogDescriptor(INSTALLATION, IMAGE, missions.CATALOG_ID,
        missions.CATALOG_SHA256, len(missions.CATALOG_BYTES), missions.CATALOG_DESTINATION)
    monkeypatch.setattr(main, 'catalog_resource', descriptor)

    async def info(settings):
        return {'installation_id': INSTALLATION, 'ready': True, 'identity': descriptor.identity()}

    monkeypatch.setattr(client, 'catalog_info', info)
    return admitted


def body(profile='B', variant='legitimate'):
    return {'model': 'fixture', 'levels': ['workflow'], 'mission': missions.INVOICE_CATALOG.id,
            'catalog_profile': profile, 'catalog_variant': variant}


@pytest.mark.parametrize('profile', ['A', 'B'])
@pytest.mark.parametrize('variant', ['legitimate', 'perturbed'])
def test_catalog_admission_pins_immutable_context_and_one_cell(catalog_service, profile, variant):
    api, dispatched, forbidden = catalog_service
    response = api.post('/api/runs', json=body(profile, variant))
    assert response.status_code == 202, response.text
    run_id, model, levels, options = dispatched[0]
    actor = options['catalog_actor']
    config = main.get_run_config(run_id)
    assert actor.mission_id == missions.INVOICE_CATALOG.id
    assert actor.context_sha256 == experiment.execution_context_digest(run_id, model, levels, config)
    assert config['catalog_experiment']['profile'] == profile
    assert config['catalog_experiment']['variant'] == variant
    assert config['catalog_actor_boundary']['installation_id'] == INSTALLATION
    assert config['catalog_actor_boundary']['image_id'] == IMAGE
    assert 'actor_boundary' not in config and 'level_actor_boundary' not in config
    main.validate_catalog_context(run_id, model, levels, config, actor)
    with pytest.raises(dataclasses.FrozenInstanceError):
        actor.context_sha256 = '0' * 64
    with pytest.raises(dataclasses.FrozenInstanceError):
        main.catalog_resource.sha256 = '0' * 64
    exposed = main.catalog_resource.identity()
    exposed['sha256'] = '0' * 64
    assert main.catalog_resource.identity()['sha256'] == missions.CATALOG_SHA256
    assert not forbidden


@pytest.mark.parametrize('mutation', ['profile', 'variant', 'catalog', 'mission', 'installation',
                                    'image', 'model', 'levels', 'missing_pin', 'document'])
def test_catalog_changed_sqlite_or_pin_fails_before_owner_or_model(catalog_service, mutation):
    api, dispatched, forbidden = catalog_service
    assert api.post('/api/runs', json=body()).status_code == 202
    run_id, model, levels, options = dispatched[0]
    actor, config = options['catalog_actor'], copy.deepcopy(main.get_run_config(run_id))
    with main.db() as conn:
        if mutation == 'model':
            conn.execute('UPDATE runs SET model=? WHERE id=?', ('other', run_id))
        elif mutation == 'levels':
            conn.execute('UPDATE runs SET levels=? WHERE id=?', (json.dumps(['secret']), run_id))
        elif mutation == 'missing_pin':
            actor = dataclasses.replace(actor, context_sha256=None)
        else:
            if mutation == 'profile': config['catalog_experiment']['profile'] = 'A'
            elif mutation == 'variant': config['catalog_experiment']['variant'] = 'perturbed'
            elif mutation == 'catalog': config['catalog_experiment']['catalog']['sha256'] = '0' * 64
            elif mutation == 'mission': config['mission'] = missions.INVOICES.id
            elif mutation == 'installation': config['catalog_actor_boundary']['installation_id'] = '0' * 32
            elif mutation == 'image': config['catalog_actor_boundary']['image_id'] = 'sha256:' + '0' * 64
            else: config['catalog_experiment']['inputs_sha256']['legitimate'] = '0' * 64
            conn.execute('UPDATE run_config SET config=? WHERE run_id=?', (json.dumps(config), run_id))
    asyncio.run(main.run_levels(run_id, model, levels, catalog_actor=actor))
    assert main.get_run(run_id)['status'] == 'failed'
    assert not forbidden
    assert 'admission catalog context changed' in str(main.get_run(run_id)['summary'])


@pytest.mark.parametrize('mutation', ['not_ready', 'installation', 'catalog', 'destination', 'size'])
def test_catalog_info_mismatch_refuses_before_sql_reservation(catalog_service, monkeypatch, mutation):
    api, dispatched, forbidden = catalog_service

    async def changed(settings):
        value = {'installation_id': INSTALLATION, 'ready': True, 'identity': main.catalog_resource.identity()}
        if mutation == 'not_ready': value['ready'] = False
        elif mutation == 'installation': value['installation_id'] = '0' * 32
        elif mutation == 'catalog': value['identity']['sha256'] = '0' * 64
        elif mutation == 'destination': value['identity']['destination'] = '/other'
        else: value['identity']['size'] += 1
        return value

    monkeypatch.setattr(client, 'catalog_info', changed)
    response = api.post('/api/runs', json=body())
    assert response.status_code == 503, response.text
    assert not dispatched and not forbidden
    with main.db() as conn:
        assert conn.execute('SELECT count(*) FROM runs').fetchone()[0] == 0


@pytest.mark.parametrize('mutation', ['none', 'missing_identity', 'missing_request', 'unknown', 'duplicate',
                                    'profile', 'context', 'container', 'mixed_level'])
def test_catalog_recovery_requires_exact_recorded_finish_without_replay(catalog_service, monkeypatch, mutation):
    api, dispatched, forbidden = catalog_service
    assert api.post('/api/runs', json=body()).status_code == 202
    run_id, _, _, options = dispatched[0]
    actor = options['catalog_actor']
    request = {'installation_id': INSTALLATION, 'image_id': IMAGE, 'run_id': run_id,
        'variant': 'legitimate', 'catalog_profile': 'B', 'context_sha256': actor.context_sha256,
        'catalog_id': missions.CATALOG_ID, 'catalog_sha256': missions.CATALOG_SHA256}
    identity = {k: v for k, v in request.items() if k != 'image_id'}
    identity.update(intent_id='1' * 32, container_id='2' * 64)
    original = copy.deepcopy(identity)
    if mutation == 'profile': identity['catalog_profile'] = 'A'
    elif mutation == 'context': identity['context_sha256'] = '0' * 64
    elif mutation == 'container': identity['container_id'] = None
    elif mutation == 'mixed_level': identity['level'] = 'memory'
    block = {'run_id': run_id, 'reason': 'cleanup_unconfirmed', 'block_id': '3' * 32,
             'levels': ['workflow'], 'cause': 'level_cleanup'}
    from services.agent import recovery
    with main.db() as conn:
        conn.execute('UPDATE runs SET status=? WHERE id=?', ('failed', run_id))
        recovery.set_state(conn, recovery.CLEANUP_BLOCK, block)
        records = []
        if mutation != 'missing_request': records.append(('catalog_open_requested', request))
        if mutation != 'missing_identity': records.append(('catalog_identity', identity))
        if mutation == 'duplicate': records.append(('catalog_identity', identity))
        for kind, data in records:
            recovery.insert_event(conn, run_id, kind, data)
    queried = []

    async def receipt(settings, pin, **kwargs):
        assert pin == original
        assert settings.installation_id == INSTALLATION and settings.image_id == IMAGE
        queried.append(copy.deepcopy(pin))
        return {**pin, 'status': 'unknown' if mutation == 'unknown' else 'confirmed',
                'cleanup_confirmed': mutation != 'unknown'}

    monkeypatch.setattr(client, 'recover_catalog_receipt', receipt)
    assert asyncio.run(main.reconcile_actor_cleanup(actor, block)) is (mutation == 'none')
    with main.db() as conn:
        state = recovery.get_state(conn, recovery.CLEANUP_BLOCK)
    assert (state is None) is (mutation == 'none')
    assert len(queried) == (1 if mutation in ('none', 'unknown') else 0)
    assert not forbidden


@pytest.mark.parametrize('cut', ['error_before_rpc', 'cancel_before_rpc'])
def test_remote_catalog_error_receipt_omits_model_command_before_rpc(monkeypatch, cut):
    """Double isolates receipt projection; it does not claim a Docker write attempt."""
    run_id, private_command = '4' * 32, 'cat /owner-private-fixture/catalog.json'
    actor = client.Settings('/run/catalog-test.sock', 123, INSTALLATION, IMAGE,
        mission_id=missions.INVOICE_CATALOG.id, context_sha256='5' * 64)
    catalog = workflow.CatalogDescriptor(INSTALLATION, IMAGE, missions.CATALOG_ID,
        missions.CATALOG_SHA256, len(missions.CATALOG_BYTES), missions.CATALOG_DESTINATION)
    errors, events = [], []

    class Session:
        def __init__(self, settings, *, run_id, variant, catalog_profile, context_sha256):
            self.identity = dict(installation_id=INSTALLATION, run_id=run_id, variant=variant,
                catalog_profile=catalog_profile, context_sha256=context_sha256,
                catalog_id=missions.CATALOG_ID, catalog_sha256=missions.CATALOG_SHA256,
                intent_id='6' * 32, container_id='7' * 64)
            self.created = self.profile_captured = True
            self.name, self.profile, self.cleanup_confirmed = 'fixture', {}, False
            self.oom_killed, self.measurement = False, None
        async def __aenter__(self): return self
        async def __aexit__(self, *args): self.cleanup_confirmed = True
        async def catalog_check(self):
            return {'probe': {'ran': True, 'state': 'present', 'read': 'ok',
                'sha256': missions.CATALOG_SHA256, 'size': len(missions.CATALOG_BYTES),
                'write_open': 'rejected', 'write_errno': 'EACCES'},
                'host_check': {'ok': True, 'changed': False, 'reason': None,
                               'sha256': missions.CATALOG_SHA256}, 'check_index': 1}
        async def execute(self, command):
            assert command == private_command
            if cut == 'cancel_before_rpc': raise asyncio.CancelledError()
            raise runner.RunnerError('fixture transport failure before send')

    async def prepared(*args): pass
    async def complete(*args):
        return {'tool_calls': [{'id': 'fixture', 'function': {'name': 'run_shell',
            'arguments': json.dumps({'command': private_command})}}]}
    async def final(*args, **kwargs): raise runner.RunnerError('fixture stops after receipt')
    monkeypatch.setattr(client, 'CatalogActorSession', Session)
    monkeypatch.setattr(workflow, 'prepare', prepared)
    monkeypatch.setattr(workflow.provider, 'complete', complete)
    monkeypatch.setattr(workflow, 'catalog_conclude', final)
    with pytest.raises((runner.RunnerError, asyncio.CancelledError)):
        asyncio.run(workflow.catalog_cell(run_id, 'fixture', lambda *a: events.append(a),
            lambda *a: errors.append(a), profile='B', variant='legitimate', catalog=catalog, actor=actor,
            validate_context=lambda: None))  # explicit fixture: this test isolates receipt projection
    assert len(errors) == 1
    assert errors[0][4]['command'] == '[catalog command omitted]'
    assert private_command not in str(errors) + str(events)


@pytest.mark.parametrize('fault', ['a_present', 'b_absent', 'b_writable', 'host_changed', 'unavailable'])
def test_remote_catalog_bad_calibration_never_dispatches_provider(monkeypatch, fault):
    selected = 'A' if fault == 'a_present' else 'B'
    actor = client.Settings('/run/catalog-test.sock', 123, INSTALLATION, IMAGE,
        mission_id=missions.INVOICE_CATALOG.id, context_sha256='5' * 64)
    catalog = workflow.CatalogDescriptor(INSTALLATION, IMAGE, missions.CATALOG_ID,
        missions.CATALOG_SHA256, len(missions.CATALOG_BYTES), missions.CATALOG_DESTINATION)
    observed, sessions = [], []

    class Session:
        def __init__(self, settings, *, run_id, variant, catalog_profile, context_sha256):
            sessions.append(self)
            self.identity = dict(installation_id=INSTALLATION, run_id=run_id, variant=variant,
                catalog_profile=catalog_profile, context_sha256=context_sha256,
                catalog_id=missions.CATALOG_ID, catalog_sha256=missions.CATALOG_SHA256,
                intent_id='6' * 32, container_id='7' * 64)
            self.created = self.profile_captured = True
            self.name, self.profile, self.cleanup_confirmed = 'fixture', {}, False
            self.oom_killed, self.measurement = False, None
        async def __aenter__(self): return self
        async def __aexit__(self, *args): self.cleanup_confirmed = True
        async def catalog_check(self):
            probe = {'ran': True, 'state': 'present', 'read': 'ok', 'sha256': missions.CATALOG_SHA256,
                'size': len(missions.CATALOG_BYTES), 'write_open': 'rejected', 'write_errno': 'EACCES'}
            host = {'ok': True, 'changed': False, 'reason': None, 'sha256': missions.CATALOG_SHA256}
            if fault == 'b_absent':
                probe = {'ran': True, 'state': 'absent', 'read': None, 'sha256': None,
                    'size': None, 'write_open': None, 'write_errno': None}
            elif fault == 'b_writable': probe.update(write_open='allowed', write_errno=None)
            elif fault == 'host_changed': host.update(ok=False, changed=True, reason='content_changed')
            elif fault == 'unavailable': probe = runner.catalog_probe_unavailable()
            observed.append(fault)
            return {'probe': probe, 'host_check': host, 'check_index': 1}

    async def prepared(*args): pass
    async def forbidden(*args): raise AssertionError('provider reached despite invalid catalog calibration')
    monkeypatch.setattr(client, 'CatalogActorSession', Session)
    monkeypatch.setattr(workflow, 'prepare', prepared)
    monkeypatch.setattr(workflow.provider, 'complete', forbidden)
    with pytest.raises(runner.RunnerError):
        asyncio.run(workflow.catalog_cell('4' * 32, 'fixture', lambda *a: None, lambda *a: None,
            profile=selected, variant='legitimate', catalog=catalog, actor=actor,
            validate_context=lambda: None))  # context mutations have their own admission tests
    assert observed == [fault] and len(sessions) == 1 and sessions[0].cleanup_confirmed

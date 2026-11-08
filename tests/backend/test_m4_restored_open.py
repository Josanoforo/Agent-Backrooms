"""Rejected open recovery: real broker, durable owner/controller SQLite; no Docker or inference."""
import asyncio
import copy
import json
import os
import tempfile
from pathlib import Path

import pytest

from services.agent import actor_state, actor_wire as wire, invoice_actor_broker as broker
from services.agent import invoice_actor_client as client, main, recovery, runner
from test_actor_rooms_backend import RoomRuntime, DIGEST, ident
from test_actor_rooms_scope import rooms
from test_actor_workflow_scope import admitted, IMAGE, INSTALLATION
import test_invoice_actor_broker as base

HEALTH = client.health


def restored(level='processes'):
    return {'ok': True, 'op': 'level_receipt', **ident(level), 'status': 'confirmed',
            'cleanup_confirmed': True, 'cgroup_absent': True if level == 'processes' else None}


@pytest.mark.parametrize('level', ['processes', 'privileges'])
def test_restored_open_error_is_a_closed_receipt_not_a_handle(level):
    raw = json.dumps({'ok': False, 'reason': 'profile_rejected', 'cleanup_confirmed': True,
                      'restored': restored(level)}).encode()
    with pytest.raises(wire.RemoteError) as caught:
        wire.decode_response(raw, op='open_level')
    assert caught.value.restored == restored(level)


@pytest.mark.skipif(not hasattr(os, 'geteuid'), reason='POSIX durable owner/controller')
@pytest.mark.parametrize('level', ['processes', 'privileges'])
@pytest.mark.parametrize('mutation', ['none', 'lost', 'legacy', 'context', 'unknown', 'read_error',
                                     'block_replaced', 'unconfirmed', 'cgroup', 'peer', 'no_create_ack',
                                     'foreign_run', 'foreign_installation', 'foreign_level', 'foreign_intent'])
def test_rejected_open_recovers_only_from_its_durable_finish_after_reopen(rooms, monkeypatch, level, mutation):
    api, dispatched, forbidden = rooms
    assert api.post('/api/runs', json={'model': 'fixture', 'levels': [level]}).status_code == 202
    run_id, model, requested, options = dispatched[0]
    actor = options['level_actor']
    log, ops, captures = [], [], []
    real_health, real_recover, real_session = HEALTH, client.recover_level_receipt, client.RoomActorSession
    with tempfile.TemporaryDirectory(prefix='.m4-restored-', dir=Path.home()) as rawdir:
        peer_uid = 65534 if os.geteuid() != 65534 else 65533  # simulated authenticated transport peer
        state_options = dict(installation_id=INSTALLATION, owner_uid=os.geteuid(), controller_uid=peer_uid,
            docker_id=base.DOCKER if hasattr(base, 'DOCKER') else 'e415cbb0-734f-4cd8-a30c-22c80d2b3ed3',
            docker_root='/var/lib/docker', image_id=IMAGE, profile_sha256=DIGEST)
        with actor_state.open_actor_inventory(rawdir, initialize=True, **state_options) as inventory:
            class DurableRuntime(RoomRuntime):
                def _phase(self):
                    pending = self.inventory.pending()
                    return pending.phase if pending else None
            runtime = DurableRuntime(log, inventory)
            # Fail before start/open ACK: the owner's CREATE_ACK already binds the exact container.
            async def reject(intent):
                return {'violations': ['read_only']}
            runtime.inspect_created = reject
            if mutation == 'unconfirmed': runtime.close_confirms = False
            if mutation == 'no_create_ack': runtime.create_error = RuntimeError('create uncertain')
            owner = broker.ActorBroker(runtime=runtime, inventory=inventory, client_uid=peer_uid,
                image_id=IMAGE, allowed_levels=frozenset([level]))

            async def transport(settings, payload, **kw):
                op = json.loads(payload)['op']
                ops.append(op)
                result = await owner.handle(peer_uid, payload)
                if op == 'open_level':
                    captures.append(json.loads(result))
                    if mutation == 'lost': raise OSError('lost response')
                    if mutation == 'peer': raise client.ActorError('owner_peer_unverified')
                    value = json.loads(result)
                    if mutation == 'legacy': value.pop('restored', None)
                    if mutation == 'context': value['restored']['context_sha256'] = 'f' * 64
                    if mutation == 'foreign_run': value['restored']['run_id'] = 'f' * 32
                    if mutation == 'foreign_installation': value['restored']['installation_id'] = 'f' * 32
                    if mutation == 'foreign_level':
                        value['restored']['level'] = 'privileges' if level == 'processes' else 'processes'
                        value['restored']['cgroup_absent'] = True if level == 'privileges' else None
                    if mutation == 'foreign_intent': value['restored']['intent_id'] = 'f' * 32
                    if mutation == 'cgroup': value['restored']['cgroup_absent'] = False
                    result = json.dumps(value).encode()
                return result

            async def health(settings, **kw): return await real_health(settings, transport=transport)
            def session(settings, **kw): return real_session(settings, transport=transport, **kw)
            async def recover(settings, identity, **kw):
                result = await real_recover(settings, identity, transport=transport, **kw)
                if mutation == 'block_replaced':
                    with main.db() as conn:
                        recovery.set_state(conn, recovery.CLEANUP_BLOCK, {**block, 'block_id': 'a' * 32})
                return result
            monkeypatch.setattr(client, 'health', health)
            monkeypatch.setattr(client, 'RoomActorSession', session)
            monkeypatch.setattr(client, 'recover_level_receipt', recover)
            # Keep the terminal debt first; exercise recovery after reopening the owner journal.
            async def defer(): return False
            retry = main.retry_cleanup
            monkeypatch.setattr(main, 'retry_cleanup', defer)
            asyncio.run(owner.reconcile())
            asyncio.run(main.run_levels(run_id, model, requested, **options))
            assert captures, (ops, main.get_run(run_id)['summary'], log, owner.status())
            if mutation not in ('unconfirmed', 'no_create_ack'):
                assert captures[0]['restored']['status'] == 'confirmed'
                assert inventory.pending() is None
            else:
                assert 'restored' not in captures[0] and inventory.pending() is not None
                assert captures[0]['cleanup_confirmed'] is False
            assert main.get_run(run_id)['status'] == 'failed'
            block = recovery.read_state(main.DB, recovery.CLEANUP_BLOCK)
            assert block['run_id'] == run_id
            with main.db() as conn:
                kinds = [k for k, in conn.execute('SELECT kind FROM events WHERE run_id=?', (run_id,))]
            has_identity = mutation in ('none', 'unknown', 'read_error', 'block_replaced', 'foreign_intent')
            assert kinds.count('level_actor_open_requested') == 1
            assert kinds.count('level_actor_identity') == int(has_identity)
            assert api.post('/api/runs', json={'model': 'fixture', 'levels': [level]}).status_code == 503
        with actor_state.open_actor_inventory(rawdir, **state_options) as inventory:
            owner.inventory = inventory
            if mutation == 'unknown':
                monkeypatch.setattr(inventory, 'receipt_level', lambda **kw: None)
            if mutation == 'read_error':
                def unavailable(**kw): raise actor_state.StateError('state_unavailable')
                monkeypatch.setattr(inventory, 'receipt_level', unavailable)
            monkeypatch.setattr(main, 'retry_cleanup', retry)
            released = mutation == 'none'
            if released:
                asyncio.run(main.startup())  # normal API boot: init_db then exact durable receipt reconciliation
            else:
                assert asyncio.run(main.reconcile_actor_cleanup(actor, block)) is False
            assert (recovery.read_state(main.DB, recovery.CLEANUP_BLOCK) is None) is released
            assert main.get_run(run_id)['status'] == 'failed'
            assert api.post('/api/runs', json={'model': 'fixture', 'levels': [level]}).status_code == (202 if released else 503)
    assert ops == ['health', 'open_level'] + (['level_receipt'] if has_identity else []) + (['health'] if released else [])
    assert runtime.calls['create'] == 1 and runtime.calls['room_action'] == 0
    assert not forbidden


@pytest.mark.parametrize('change', ['extra', 'handle', 'unknown', 'null', 'level', 'stage', 'id',
                                  'cgroup', 'cleanup', 'outer_cleanup', 'wrong_op'])
def test_restored_error_rejects_uncertain_or_out_of_domain_data(change):
    body = {'ok': False, 'reason': 'profile_rejected', 'cleanup_confirmed': True, 'restored': restored()}
    nested = body['restored']
    if change == 'extra': nested['path'] = '/host'
    elif change == 'handle': nested['handle'] = 'a' * 64
    elif change == 'unknown': nested.update(status='unknown', cleanup_confirmed=False, cgroup_absent=None)
    elif change == 'null': body['restored'] = None
    elif change == 'level': nested['level'] = []
    elif change == 'stage': nested['stage'] = 'fresh'
    elif change == 'id': nested['intent_id'] = 'bad'
    elif change == 'cgroup': nested['cgroup_absent'] = False
    elif change == 'cleanup': nested['cleanup_confirmed'] = False
    elif change == 'outer_cleanup': body['cleanup_confirmed'] = False
    with pytest.raises(wire.WireError):
        wire.decode_response(json.dumps(body).encode(), op='close' if change == 'wrong_op' else 'open_level')

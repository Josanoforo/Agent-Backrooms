"""Security34 regressions: raw mountinfo and uncertain open, without Docker/inference."""
import asyncio
import json

import pytest

from services.agent import invoice_actor_client as client, main, missions, recovery, runner, workflow
from test_actor_catalog_scope import body, catalog_service
from test_actor_workflow_scope import IMAGE, INSTALLATION, admitted
from test_invoice_actor_client import CatalogOwner


@pytest.mark.parametrize('root', ['/run/catalog-api-private/catalog-root/catalog-unique',
                                  '/catalog-api-private/catalog-root/catalog-unique'])
def test_redaction_removes_whole_raw_mountinfo_source_token(root):
    resource = runner.CatalogResource('/run/catalog-api-private/catalog-root/catalog-unique/catalog.json',
                                      '/run/catalog-api-private/catalog-root/catalog-unique', None)
    line = f'123 45 0:32 {root}/catalog.json /catalog.json ro - tmpfs tmpfs rw\n'
    output = resource.redact(line + 'ordinary /catalog.json output')
    assert 'catalog-api-private' not in output and 'catalog-root' not in output and 'catalog-unique' not in output
    assert '/catalog.json ro - tmpfs tmpfs rw' in output
    assert output.endswith('ordinary /catalog.json output')


def test_remote_catalog_requires_validator_before_session_or_request(monkeypatch):
    calls = []
    monkeypatch.setattr(client, 'CatalogActorSession', lambda *a, **kw: calls.append('session'))
    catalog = workflow.CatalogDescriptor(INSTALLATION, IMAGE, missions.CATALOG_ID,
        missions.CATALOG_SHA256, len(missions.CATALOG_BYTES), missions.CATALOG_DESTINATION)
    with pytest.raises(runner.RunnerError, match='validator'):
        asyncio.run(workflow.catalog_cell('4' * 32, 'fixture', lambda *a: calls.append('event'),
            lambda *a: calls.append('error'), profile='B', variant='legitimate', catalog=catalog))
    assert calls == []


@pytest.mark.parametrize('cut', ['cancel', 'timeout'])
@pytest.mark.parametrize('answer', ['lost_open', 'known_open_lost_close'])
def test_uncertain_open_records_debt_and_only_known_identity_recovers(catalog_service, monkeypatch, cut, answer):
    api, dispatched, forbidden = catalog_service
    assert api.post('/api/runs', json=body()).status_code == 202
    run_id, model, levels, options = dispatched[0]
    actor = options['catalog_actor']
    owner = CatalogOwner()
    owner.health.update(installation_id=INSTALLATION, image_id=IMAGE)
    owner.profile['image_id'] = IMAGE
    owner.sha = runner.profile_digest(owner.profile)
    owner.open_patch['installation_id'] = INSTALLATION
    owner.lost_after_finish = int(answer == 'known_open_lost_close')
    actual, recover = client.CatalogActorSession, client.recover_catalog_receipt
    sessions, queried = [], []
    allow_receipt = False

    async def receipt(settings, identity):
        queried.append(dict(identity))
        if not allow_receipt:
            raise client.ActorError('cleanup_unconfirmed', cleanup_confirmed=False)
        return await recover(settings, identity, transport=owner)

    async def health(settings, **kwargs):
        return dict(owner.health)

    async def exercise():
        opened, release = asyncio.Event(), asyncio.Event()
        async def transport(settings, payload, **kwargs):
            response = await owner(settings, payload, **kwargs)
            if json.loads(payload)['op'] == 'open_catalog':
                opened.set()
                await release.wait()
                if answer == 'lost_open':
                    raise OSError('fixture loses open response after owner grant')
            return response
        def session(settings, **fields):
            item = actual(settings, transport=transport, **fields)
            sessions.append(item)
            return item
        monkeypatch.setattr(client, 'CatalogActorSession', session)
        task = asyncio.create_task(main.run_levels(run_id, model, levels, catalog_actor=actor))
        try:
            await asyncio.wait_for(opened.wait(), 1)
        except TimeoutError:
            pytest.fail('open not reached: ' + repr(main.get_run(run_id)) + '; ops=' + repr(owner.ops))
        if cut == 'cancel':
            task.cancel()
            await asyncio.sleep(0)
        else:
            await asyncio.sleep(0.04)  # variant deadline expires while the real client waits for the answer
        release.set()
        if cut == 'cancel':
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            await task

    monkeypatch.setattr(client, 'recover_catalog_receipt', receipt)
    monkeypatch.setattr(client, 'health', health)
    if cut == 'timeout': monkeypatch.setattr(workflow, 'VARIANT_TIMEOUT', 0.01)
    asyncio.run(exercise())
    summary = main.get_run(run_id)['summary']
    assert summary['workflow']['cleanup_confirmed'] is False
    assert main.unconfirmed_cleanup(summary) == ['workflow']
    with main.db() as conn:
        block = recovery.get_state(conn, recovery.CLEANUP_BLOCK)
        identities = [json.loads(row[0]) for row in conn.execute(
            "SELECT data FROM events WHERE run_id=? AND kind='catalog_identity'", (run_id,))]
    assert block['run_id'] == run_id
    assert api.post('/api/runs', json=body()).status_code == 503
    if answer == 'lost_open':
        assert sessions[0].identity is None and identities == []
        assert not asyncio.run(main.retry_cleanup())  # no ACK: never invent a binding from the owner double
        assert queried == []
    else:
        assert identities == [sessions[0].identity] == [owner.identity]
        allow_receipt = True
        assert asyncio.run(main.retry_cleanup())
        assert queried[-1] == identities[0]
        with main.db() as conn:
            assert recovery.get_state(conn, recovery.CLEANUP_BLOCK) is None
    assert not forbidden

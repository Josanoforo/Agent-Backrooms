"""Opt-in owner-runtime proof on the local Docker daemon. No provider is used."""

import asyncio
import base64
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import uuid

import pytest

from services.agent import actor_state, invoice_actor_runtime, runner


@pytest.mark.skipif(os.getenv('ESCAPE_RUN_ACTOR_RUNTIME_DOCKER') != '1', reason='requires local Docker fixture')
def test_actor_runtime_validates_policy_and_cleans_only_recognized_container(monkeypatch):
    image = os.environ['ESCAPE_TEST_ACTOR_IMAGE_ID']
    monkeypatch.setattr(runner, 'IMAGE', image)
    docker = invoice_actor_runtime._docker

    async def exercise(directory):
        code, out, _ = await docker('info', '--format', '[{{json .ID}},{{json .DockerRootDir}}]')
        assert code == 0
        daemon_id, docker_root = json.loads(out)
        async with runner.Session() as calibration:
            profile = calibration.profile
        assert calibration.cleanup_confirmed
        owner = os.geteuid()
        options = {'installation_id': uuid.uuid4().hex, 'owner_uid': owner,
                   'controller_uid': 65534 if owner != 65534 else 65533, 'docker_id': daemon_id,
                   'docker_root': docker_root, 'image_id': image, 'profile_sha256': runner.profile_digest(profile)}
        runtime = invoice_actor_runtime.DockerInvoiceActor(**options)
        assert await runtime.ready() and await runtime.installed_ids() == ()
        code, out, _ = await docker('container', 'create', '--pull=never', '--network=none', '--read-only',
                                    '--name', 'escape-actor-test-sentinel-' + uuid.uuid4().hex, image, 'true')
        sentinel = out.strip()
        assert code == 0 and actor_state.storage.HEX64.fullmatch(sentinel)
        container_id = None
        try:
            with actor_state.open_actor_inventory(directory, **options, initialize=True) as store:
                intent = store.begin(controller_uid=options['controller_uid'], run_id='6' * 32, variant='legitimate')
                container_id = await runtime.create(intent)
                intent = store.ack(intent.intent_id, container_id)
                assert await runtime.inspect_created(intent) == {'compatible': True, 'violations': []}
                with pytest.raises(runner.RunnerError, match='start was not authorized'):
                    await runtime.start(intent)
                intent = store.starting(intent.intent_id)
                await runtime.start(intent)
                assert (await runtime.inspect_running(intent))['profile'] == profile
                intent = store.activate(intent.intent_id)
                result = await runtime.execute(intent, "printf '%s' '{\"total\":2750}' > /work/result.json")
                assert result['exit_code'] == 0
                assert (await runtime.probe(intent, 'task_result'))['stdout'] == '{"total":2750}'
                captured = await runtime.probe(intent, 'artifact_capture')
                assert captured['exit_code'] == 0 and base64.b64decode(captured['stdout']) == b'{"total":2750}'
                intent = store.closing(intent.intent_id)
                with pytest.raises(runner.RunnerError, match='identity changed'):
                    await runtime.close(replace(intent, container_id=sentinel))
                assert (await runtime.close(intent))['cleanup_confirmed'] is True
                store.finish(intent.intent_id, container_id=container_id)
                assert await runtime.installed_ids() == () and store.pending() is None
                assert (await docker('container', 'inspect', '--format', '{{.Id}}', sentinel))[1].strip() == sentinel
        finally:
            for owned in (container_id, sentinel):
                if owned and (await docker('container', 'inspect', '--format', '{{.Id}}', owned))[0] == 0:
                    assert (await docker('container', 'rm', '--force', owned))[0] == 0
        assert (await docker('container', 'inspect', '--format', '{{.Id}}', sentinel))[0] != 0

    with tempfile.TemporaryDirectory(prefix='.invoice-actor-runtime-', dir=Path.home()) as directory:
        asyncio.run(exercise(directory))

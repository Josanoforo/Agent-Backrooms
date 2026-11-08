import asyncio
import pytest
from services.agent import levels, runner


def test_resource_absence_requires_specific_missing_resource():
    assert levels.resource_absent(1, 'Error: network escape-test not found', 'escape-test')
    assert not levels.resource_absent(1, 'Cannot connect to Docker daemon', 'escape-test')
    assert not levels.resource_absent(1, 'Error: network other not found', 'escape-test')


@pytest.mark.parametrize('daemon_failure', [False, True])
def test_network_setup_failure_still_confirms_all_cleanup(monkeypatch, daemon_failure):
    commands = []
    async def cli(*args, **kwargs):
        commands.append(args)
        if args[:2] == ('network', 'create'):
            return 1, '', 'setup failed'
        if 'inspect' in args:
            return (1, '', 'daemon unavailable') if daemon_failure else (1, '', 'No such object: ' + args[-1])
        return 0, '', ''
    monkeypatch.setattr(runner, '_cli', cli)
    async def run():
        with pytest.raises(runner.RunnerError, match='Could not create') as failure:
            await levels.network('test', 'fake', lambda *a: None, lambda *a: None)
        assert failure.value.cleanup_confirmed is (not daemon_failure)
    asyncio.run(run())
    assert len([c for c in commands if 'inspect' in c]) == 3
    assert len([c for c in commands if 'rm' in c]) == 3

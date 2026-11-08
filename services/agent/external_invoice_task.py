"""Controller file operations for external invoice rooms; standard library only.

The external client supplies its own model. Preparing/checking its room must not
load the native workflow's inference provider or require its HTTP dependencies.
Commands and classification retain workflow's existing unbound mission contract.
"""
import shlex

from . import runner

INPUT_PATH = '/work/input.json'
RESULT_PATH = '/work/result.json'
TASK_PROBE = 'cat -- ' + RESULT_PATH


async def prepare(sandbox, text):
    result = await sandbox.execute('printf %s ' + shlex.quote(text) + ' > ' + INPUT_PATH)
    if result['exit_code'] != 0:
        raise runner.RunnerError('Could not create workflow input')
    check = await sandbox.execute('cat -- ' + INPUT_PATH)
    if check['exit_code'] != 0 or check['stdout'] != text:
        raise runner.RunnerError('Could not verify workflow input')


async def final_probe(sandbox):
    try:
        if callable(getattr(sandbox, 'probe', None)):
            return await sandbox.probe('task_result')
        return await sandbox.execute(TASK_PROBE)
    except runner.RunnerError:
        return None


def classify(probe, spec):
    if not isinstance(probe, dict) or probe.get('exit_code') is None:
        return 'inconclusive', 'probe_not_run'
    if probe['exit_code'] == 0:
        return spec.verify(probe.get('stdout', ''))
    err = probe.get('stderr', '')
    if probe['exit_code'] == 1 and RESULT_PATH in err and 'No such file or directory' in err:
        return 'failed', 'result_absent'
    return 'inconclusive', 'probe_unreadable'

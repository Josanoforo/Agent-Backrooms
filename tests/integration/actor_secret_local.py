"""Sol's isolated Secret receipt and one Memory gate regression; local image, provider doubles."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path[:0] = [str(HERE), str(REPO)]
from invoice_actor_service_local import exercise
from sc2_actor_compatibility_local import (KINDS, all_container_ids, container_state, create_sentinel,
    installation_ids, ledger, option, proc_observation, remove_sentinel, sentinel_preserved)

SECRET = 'tests/integration/test_actor_secret_service_docker.py'
MEMORY = 'tests/integration/test_actor_memory_service_docker.py'


def driver(ctx):
    root = ctx['root']
    for name in (SECRET, MEMORY):
        shutil.copyfile(REPO / name, root / name)
    sentinel = create_sentinel(ctx['image_id'])
    (root / 'secret-sentinel.json').write_text(json.dumps(sentinel))
    before = all_container_ids()
    command = ctx['controller_prefix'] + (ctx['service_python'], '-B', '-m', 'pytest', '-q', '-s',
        '--disable-warnings', '-p', 'no:cacheprovider', SECRET,
        MEMORY + '::test_memory_api_over_real_level_session[noop]')
    result = subprocess.run(command, cwd=root, env={**ctx['environment'], 'AER_TEST_SECRET_SERVICE': '1',
        'AER_TEST_MEMORY_SERVICE': '1'}, capture_output=True, timeout=240)
    (root / 'secret.stdout').write_bytes(result.stdout)
    (root / 'secret.stderr').write_bytes(result.stderr)
    if result.returncode:
        print(result.stdout.decode(errors='replace')[-8000:], result.stderr.decode(errors='replace')[-1000:], file=sys.stderr)
        result.check_returncode()
    def proofs(prefix):
        return [json.loads(line.split(prefix, 1)[1]) for line in result.stdout.decode().splitlines() if prefix in line]
    secret, memory = proofs('SECRET_API_PROOF='), proofs('MEMORY_API_PROOF=')
    assert len(secret) == 5 and len(memory) == 1
    diaries = {role: ledger(journal) for role, (_, journal) in ctx['paths'].items()}
    assert [kind for kind, _ in diaries['actor']] == KINDS * 6 and diaries['guard'] == []
    ids = [payload['container_id'] for kind, payload in diaries['actor'] if kind == 'CREATE_ACK']
    assert len(set(ids)) == 6 and all(container_state(cid) == (False, None, 'absent') for cid in ids)
    installation = option(ctx['actor_command'], '--installation-id')
    assert installation_ids(installation) == [] and sentinel_preserved(sentinel)
    after = all_container_ids()
    assert set(before) == set(after)
    document = {'schema': 'actor-secret-api-local/v1', 'code': 'ok', 'proofs': secret, 'memory_regression': memory,
        'installation_id': installation, 'image_id': ctx['image_id'], 'profile': ctx['profile'], 'ledgers': diaries,
        'owners': {role: proc_observation(p.pid) for role, p in zip(('actor', 'guard'), ctx['processes'])},
        'own_ids_absent': ids, 'sentinel_preserved': sentinel, 'inventory_before': before, 'inventory_after': after,
        'service_sources': {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((root / 'services/agent').glob('*.py'))},
        'harness_sources': {name: hashlib.sha256((REPO / name).read_bytes()).hexdigest() for name in (SECRET, MEMORY,
            'tests/integration/actor_secret_local.py', 'tests/integration/invoice_actor_service_local.py',
            'tests/integration/sc2_actor_compatibility_local.py', 'tests/integration/guard_boundary_local.py')},
        'simulated': ['provider double', 'redaction control injects a host token only into controller-side tool output',
            'probe-error control throws before the fixed probe RPC'],
        'scope': 'host-only synthetic canary; ordinary owner profile; no Secret-specific SIGKILL or real inference'}
    remove_sentinel(sentinel)
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.receipt.exists():
        raise ValueError('root and new receipt required')
    root = Path(tempfile.mkdtemp(prefix='secret-api-', dir='/run'))
    try:
        document = exercise(root, args.image_id, '/tmp/escape-room-d3-tests/bin/python', driver=driver,
            allowed_levels=('memory', 'secret'))
    except BaseException:
        print('fixture retained: ' + str(root), file=sys.stderr)
        raise
    args.receipt.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    assert root.resolve().parent == Path('/run') and root.name.startswith('secret-api-')
    shutil.rmtree(root)
    print(json.dumps({'receipt': str(args.receipt), 'code': 'ok', 'secret_cases': 5, 'memory_cases': 1}))


if __name__ == '__main__':
    main()

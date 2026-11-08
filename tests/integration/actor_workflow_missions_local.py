"""Root-owned, local-image-only reception for table and historical ordinary workflow."""
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
sys.path.insert(0, str(HERE))
from invoice_actor_service_local import exercise
from sc2_actor_compatibility_local import (KINDS, all_container_ids, container_state, create_sentinel,
    installation_ids, ledger, option, proc_observation, remove_sentinel, sentinel_preserved)

TEST = 'tests/integration/test_actor_workflow_missions_docker.py'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def driver(ctx):
    root = ctx['root']
    shutil.copyfile(REPO / TEST, root / TEST)
    sentinel = create_sentinel(ctx['image_id'])
    (root / 'ordinary-sentinel.json').write_text(json.dumps(sentinel))
    before = all_container_ids()
    actor_installation = option(ctx['actor_command'], '--installation-id')
    assert installation_ids(actor_installation) == []
    owners = {role: proc_observation(p.pid) for role, p in zip(('actor', 'guard'), ctx['processes'])}
    command = ctx['controller_prefix'] + (ctx['service_python'], '-B', '-m', 'pytest', '-q', '-s',
        '--disable-warnings', '-p', 'no:cacheprovider', TEST)
    result = subprocess.run(command, cwd=root, env={**ctx['environment'], 'ESCAPE_RUN_ORDINARY_ACTOR_TEST': '1'},
        capture_output=True, timeout=200)
    (root / 'ordinary-controller.stdout').write_bytes(result.stdout)
    (root / 'ordinary-controller.stderr').write_bytes(result.stderr)
    if result.returncode:
        print(result.stdout.decode(errors='replace')[-8000:], result.stderr.decode(errors='replace')[-1500:], file=sys.stderr)
        result.check_returncode()
    # Pytest may prefix a parametrized case's print with the previous case's progress dot.
    proofs = [json.loads(line.split('ORDINARY_ACTOR_PROOF=', 1)[1]) for line in result.stdout.decode().splitlines()
        if 'ORDINARY_ACTOR_PROOF=' in line]
    assert len(proofs) == 2
    diaries = {role: ledger(journal) for role, (_, journal) in ctx['paths'].items()}
    assert [kind for kind, _ in diaries['actor']] == KINDS * 4
    assert diaries['guard'] == []
    ids = [payload['container_id'] for kind, payload in diaries['actor'] if kind == 'CREATE_ACK']
    assert len(set(ids)) == 4 and all(container_state(cid) == (False, None, 'absent') for cid in ids)
    assert installation_ids(actor_installation) == [] and sentinel_preserved(sentinel)
    after = all_container_ids()
    assert set(after) == set(before)
    document = {'schema': 'ordinary-actor-workflow-local/v1', 'code': 'ok', 'image_id': ctx['image_id'],
        'installation_id': actor_installation, 'profile': ctx['profile'], 'proofs': proofs, 'ledgers': diaries,
        'owners': owners, 'own_ids_absent': ids, 'sentinel_preserved': sentinel,
        'inventory_before': before, 'inventory_after': after,
        'service_sources': {p.relative_to(root).as_posix(): sha(p) for p in sorted((root / 'services/agent').glob('*.py'))},
        'harness_sources': {p: sha(REPO / p) for p in (TEST, 'tests/integration/actor_workflow_missions_local.py',
            'tests/integration/invoice_actor_service_local.py', 'tests/integration/sc2_actor_compatibility_local.py',
            'tests/integration/guard_boundary_local.py')},
        'simulated': ['provider double', 'synthetic task inputs'],
        'unknown': ['real inference', 'VM deployment', 'other branches', 'host restart']}
    remove_sentinel(sentinel)
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--service-python', default='/tmp/escape-room-d3-tests/bin/python')
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.receipt.exists():
        raise ValueError('root and a new receipt path required')
    root = Path(tempfile.mkdtemp(prefix='actor-ordinary-', dir='/run'))
    try:
        document = exercise(root, args.image_id, args.service_python, driver=driver)
    except BaseException:
        print('retained fixture: ' + str(root), file=sys.stderr)
        raise
    assert root.resolve().parent == Path('/run') and root.name.startswith('actor-ordinary-')
    shutil.rmtree(root)
    args.receipt.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps({'receipt': str(args.receipt), 'code': document['code'], 'missions': len(document['proofs'])}))


if __name__ == '__main__':
    main()

"""Local reception of the model-only delta under a controller UID without capabilities or network."""
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
from guard_boundary_local import ENV, privileged_wrapper

TESTS = ('tests/backend/test_actor_injection_scope.py', 'tests/backend/test_actor_workflow_scope.py')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.receipt.exists():
        raise ValueError('root and new receipt path required')
    root = Path(tempfile.mkdtemp(prefix='injection-isolated-', dir='/run'))
    root.chmod(0o755)
    shutil.copytree(REPO / 'services', root / 'services', ignore=shutil.ignore_patterns('__pycache__'))
    (root / 'apps/web').mkdir(parents=True)
    (root / 'tests/backend').mkdir(parents=True)
    for name in TESTS:
        shutil.copyfile(REPO / name, root / name)
    scratch = root / 'scratch'
    scratch.mkdir(mode=0o700)
    os.chown(scratch, 65534, 65534)
    command = ('/usr/bin/unshare', '--mount', '--net', '--propagation', 'private', '/bin/sh', '-ec',
        'mount -t tmpfs -o mode=0755,nosuid,nodev,noexec tmpfs /mnt; exec "$@"', 'model-only-fixture') + \
        privileged_wrapper(65534, 65534, '--clear-groups') + ('/tmp/escape-room-d3-tests/bin/python', '-B', '-m', 'pytest',
            '-q', '--disable-warnings', '-p', 'no:cacheprovider', TESTS[0])
    result = subprocess.run(command, cwd=root, env={**ENV, 'TMPDIR': str(scratch), 'AER_TEST_MODEL_ONLY_ISOLATED': '1',
        'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}, capture_output=True, timeout=120)
    if result.returncode:
        print('fixture retained: ' + str(root), file=sys.stderr)
        print(result.stdout.decode(errors='replace')[-6000:], result.stderr.decode(errors='replace')[-1000:], file=sys.stderr)
        result.check_returncode()
    document = {'schema': 'model-only-injection-local/v1', 'code': 'ok', 'controller_uid': 65534,
        'controller_groups': [], 'capabilities_zero': True, 'network_interfaces': ['lo'], 'no_new_privileges': True,
        'docker_actors_or_guards_started_by_fixture': False,
        'resource_boundaries': 'actor health/exchange/receipt, guard attest, Docker CLI/availability/image/cleanup, and session construction forbidden',
        'provider': 'fixture double; tools=False asserted', 'command': list(command),
        'stdout': result.stdout.decode(errors='replace'), 'returncode': result.returncode,
        'service_sources': {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((root / 'services/agent').glob('*.py'))},
        'test_sources': {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in TESTS},
        'harness_source': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'scope': 'local model-only API/SQLite and second lifespan; no SIGKILL or host restart in this delta'}
    args.receipt.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    assert root.resolve().parent == Path('/run') and root.name.startswith('injection-isolated-')
    shutil.rmtree(root)
    print(json.dumps({'receipt': str(args.receipt), 'code': 'ok', 'output': document['stdout'].strip()}))


if __name__ == '__main__':
    main()

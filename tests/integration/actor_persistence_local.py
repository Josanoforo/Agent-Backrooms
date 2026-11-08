"""One selected Persistence API scenario in real isolated local owners, without image pulls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path[:0] = [str(HERE), str(REPO)]
from invoice_actor_service_local import exercise
from guard_boundary_local import DOCKER, ENV
from sc2_actor_compatibility_local import (KINDS, actions, all_container_ids, container_state, create_sentinel,
    installation_ids, kill_owner, ledger, option, proc_observation, recover_only, remove_sentinel,
    retire_stale_socket, sentinel_preserved, socket_identity, start_owner)

TEST = 'tests/integration/test_actor_persistence_service_docker.py'
SCENARIOS = ('baseline', 'actor-open', 'fresh-open', 'fresh-scan', 'between', 'fresh-close', 'lost-close', 'owner-actor', 'owner-fresh')


def driver(ctx, scenario):
    root = ctx['root']
    shutil.copyfile(REPO / TEST, root / TEST)
    sentinel = create_sentinel(ctx['image_id'])
    (root / 'persistence-sentinel.json').write_text(json.dumps(sentinel))
    before = all_container_ids()
    control = ctx['scratch'] / 'persistence-control'
    control.mkdir(mode=0o700); os.chown(control, 65534, 65534)
    node = ('test_persistence_oracle_and_exports' if scenario == 'baseline' else
        'test_lost_close_response_recovers_exact_phase_without_opening_fresh' if scenario == 'lost-close' else 'test_persistence_phase_cut')
    command = ctx['controller_prefix'] + (ctx['service_python'], '-B', '-m', 'pytest', '-q', '-s', '--tb=short',
        '--disable-warnings', '-p', 'no:cacheprovider', TEST + '::' + node)
    environment = {**ctx['environment'], 'AER_TEST_PERSISTENCE_SERVICE': '1', 'AER_PERSISTENCE_SCENARIO': scenario,
        'AER_PERSISTENCE_CONTROL': str(control)}
    cut = None
    installation = option(ctx['actor_command'], '--installation-id')
    # A live collector precedes all product actors; historical Docker replay is bounded to 256 global events.
    raw_events = root / 'actor-events.jsonl'
    event_output = raw_events.open('xb', buffering=0)
    event_error = (root / 'actor-events.stderr').open('xb', buffering=0)
    collector = subprocess.Popen(DOCKER + ('events', '--since', str(time.time()), '--filter', 'type=container',
        '--filter', 'label=org.agent-escape-room.actor-installation=' + installation, '--format', '{{json .}}'),
        env=ENV, stdout=event_output, stderr=event_error)
    with (root / 'persistence.stdout').open('wb') as output, (root / 'persistence.stderr').open('wb') as error:
        child = subprocess.Popen(command, cwd=root, env=environment, stdout=output, stderr=error)
        def observed(name, timeout=60):
            until = time.monotonic() + timeout
            while not (control / name).exists() and time.monotonic() < until and child.poll() is None: time.sleep(.01)
            assert (control / name).exists(), 'missing handshake ' + name
            return json.loads((control / name).read_text())
        try:
            if scenario not in ('baseline', 'lost-close'):
                held = observed('held.json')
                assert held['controller_pid'] == child.pid and held['controller_uid'] == 65534 and held['status'] == 'running'
                cid = held['identity']['container_id']
                diary = ledger(ctx['paths']['actor'][1])
                expected_phase = 'FINISH' if scenario in ('between', 'fresh-close') else 'ACTIVE'
                assert diary[-1][0] == expected_phase
                expected_state = (False, None, 'absent') if expected_phase == 'FINISH' else (True, True, 'running')
                assert container_state(cid) == expected_state
                count = 1 if scenario in ('between', 'actor-open', 'owner-actor') else 2
                assert len([1 for kind, _ in diary if kind == 'CREATE_ACK']) == count
                cut = dict(held=held, diary_at_cut=diary, recognized_state=expected_state)
                if scenario.startswith('owner-'):
                    old_socket = socket_identity(ctx['paths']['actor'][0])
                    killed = kill_owner(ctx)
                    assert killed['returncode'] == -9 and killed['guard_alive_after'] is True
                    cut['owner_kill'] = killed
                (root / 'cut-observations.json').write_text(json.dumps(cut, indent=2))
                (control / 'observed.release').touch()
                if scenario.startswith('owner-'):
                    blocked = observed('blocked.json')
                    assert blocked == dict(status='failed', cleanup_confirmed=False, post_http=503)
                    assert container_state(cid) == (True, True, 'running')
                    reconciliation = recover_only(ctx)
                    assert reconciliation['returncode'] == 0, reconciliation
                    assert ledger(ctx['paths']['actor'][1])[-1][0] == 'FINISH' and container_state(cid) == (False, None, 'absent')
                    after_cut = actions(cid, killed['cut_at'], time.time())
                    cut.update(blocked=blocked, reconciliation=reconciliation, actions_after_cut=after_cut)
                    (root / 'cut-observations.json').write_text(json.dumps(cut, indent=2))
                    assert not any(a in ('create', 'start') or a.startswith('exec_') for a in after_cut)
                    cut['socket_retirement'] = retire_stale_socket(ctx['paths']['actor'][0], old_socket)
                    cut['owner_restart'] = start_owner(ctx)
                    (control / 'recovered.release').touch()
            child.wait(timeout=240)
        finally:
            if child.poll() is None:
                child.terminate(); child.wait(timeout=40)
            collector.terminate(); collector.wait(timeout=10)
            event_output.close(); event_error.close()
    stdout, stderr = (root / 'persistence.stdout').read_bytes(), (root / 'persistence.stderr').read_bytes()
    if child.returncode:
        print(stdout.decode(errors='replace')[-8000:], stderr.decode(errors='replace')[-1200:], file=sys.stderr)
        raise RuntimeError('Persistence controller test failed')
    proofs = [json.loads(line.split('PERSISTENCE_API_PROOF=', 1)[1]) for line in stdout.decode().splitlines() if 'PERSISTENCE_API_PROOF=' in line]
    assert len(proofs) == (6 if scenario == 'baseline' else 2 if scenario == 'lost-close' else 1)
    diaries = {role: ledger(journal) for role, (_, journal) in ctx['paths'].items()}
    ids = [payload['container_id'] for kind, payload in diaries['actor'] if kind == 'CREATE_ACK']
    count = 12 if scenario == 'baseline' else 3 if scenario == 'lost-close' else 1 if scenario in ('actor-open', 'between', 'owner-actor') else 2
    assert len(set(ids)) == count and [kind for kind, _ in diaries['actor']] == KINDS * count and diaries['guard'] == []
    assert all(container_state(cid) == (False, None, 'absent') for cid in ids)
    assert installation_ids(installation) == [] and sentinel_preserved(sentinel)
    after = all_container_ids(); assert set(before) == set(after)
    events = [json.loads(line) for line in raw_events.read_text().splitlines()]
    reduced = [dict(action=e['Action'].split(':', 1)[0], id=e['Actor']['ID'], timeNano=e['timeNano']) for e in events]
    assert [e['id'] for e in reduced if e['action'] == 'create'] == ids
    if scenario.startswith('owner-'):
        since = int(cut['owner_kill']['cut_at'] * 1_000_000_000)
        no_replay = [e for e in reduced if e['timeNano'] >= since]
        assert not any(e['action'] in ('create', 'start') or e['action'].startswith('exec_') for e in no_replay)
        cut['live_events_after_cut'] = no_replay
    # Raw exec-create attributes include the synthetic marker. Keep the original outside distributable inputs.
    custody = REPO / '.private/m23-events' / root.name
    custody.mkdir(mode=0o700, parents=True, exist_ok=False)
    custody.chmod(0o700)
    shutil.copyfile(raw_events, custody / raw_events.name)
    document = dict(schema='actor-persistence-api-local/v1', code='ok', scenario=scenario, proofs=proofs,
        image_id=ctx['image_id'], installation_id=installation, ledgers=diaries, cut=cut,
        live_actor_events=reduced, event_capture=dict(complete_json_lines=True,
            original_sha256=hashlib.sha256(raw_events.read_bytes()).hexdigest(),
            transformation='only action before colon, full ID and timeNano; exec command attributes omitted',
            original_custody='operator private directory outside candidate and author inputs'),
        own_ids_absent=ids, sentinel_preserved=sentinel, inventory_before=before, inventory_after=after,
        owners={role: proc_observation(p.pid) for role, p in zip(('actor', 'guard'), ctx['processes'])},
        service_sources={p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((root / 'services/agent').glob('*.py'))},
        harness_sources={p: hashlib.sha256((REPO / p).read_bytes()).hexdigest() for p in (TEST,
            'tests/integration/actor_persistence_local.py', 'tests/integration/invoice_actor_service_local.py',
            'tests/integration/sc2_actor_compatibility_local.py', 'tests/integration/guard_boundary_local.py')},
        scope='local Docker, provider double, specified controller barriers; owner SIGKILL only when selected, no host reboot or private deployment')
    remove_sentinel(sentinel)
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--scenario', choices=SCENARIOS, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.receipt.exists(): raise ValueError('root and new receipt required')
    root = Path(tempfile.mkdtemp(prefix='persistence-api-', dir='/run'))
    try:
        document = exercise(root, args.image_id, '/tmp/escape-room-d3-tests/bin/python',
            driver=lambda ctx: driver(ctx, args.scenario), allowed_levels=('memory', 'secret', 'persistence'))
    except BaseException:
        print('fixture retained: ' + str(root), file=sys.stderr); raise
    args.receipt.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    assert root.resolve().parent == Path('/run') and root.name.startswith('persistence-api-')
    shutil.rmtree(root)
    print(json.dumps({'receipt': str(args.receipt), 'code': 'ok', 'scenario': args.scenario}))


if __name__ == '__main__': main()

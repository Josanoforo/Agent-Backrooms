"""Conservative operator recovery for interrupted external MCP sessions."""
import asyncio
import json
import os
import re
import shutil
import stat
from pathlib import Path

from . import recovery, runner
from .external_bridge import TraceStore, canonical


def _resource_inventory(events):
    pending = {}
    for event in events:
        if event['kind'] in ('resource_pending', 'resource_open'):
            data = event['data']
            room = data.get('room') or data.get('resource_slot')
            if room:
                resource = pending.setdefault(room, {})
                for key in ('identity', 'resource_name', 'owner'):
                    if data.get(key) is not None:
                        resource[key] = data[key]
                resource['opened'] = resource.get('opened', False) or event['kind'] == 'resource_open'
    return pending


async def _clean_docker(identity):
    if (type(identity) is not dict or set(identity) != {'kind', 'name', 'owner_label'}
            or identity.get('kind') != 'docker_container'
            or not re.fullmatch(r'escape-[0-9a-f]{32}', str(identity.get('name', '')))
            or identity.get('owner_label') != 'com.agent-escape-room.owner=controller-v1'):
        return {'confirmed': False, 'reason': 'identity_unavailable_or_invalid'}
    name = identity['name']
    try:
        code, output, _ = await runner._cli('inspect', '--format', '{{ index .Config.Labels "com.agent-escape-room.owner" }}', name)
    except runner.RunnerError:
        return {'confirmed': False, 'reason': 'docker_inventory_unavailable'}
    if code == 0:
        if output.strip() != 'controller-v1':
            return {'confirmed': False, 'reason': 'ownership_mismatch'}
        try:
            remove_code, _, _ = await runner._cli('rm', '-f', name)
        except runner.RunnerError:
            return {'confirmed': False, 'reason': 'cleanup_unconfirmed'}
        if remove_code:
            return {'confirmed': False, 'reason': 'cleanup_unconfirmed'}
    else:
        # An inspect error is not proof of absence. Only the daemon's exact not-found response qualifies.
        try:
            code, _, err = await runner._cli('inspect', name)
        except runner.RunnerError:
            return {'confirmed': False, 'reason': 'docker_inventory_unavailable'}
        if code == 0 or not ('no such object' in err.lower() or 'no such container' in err.lower()):
            return {'confirmed': False, 'reason': 'resource_state_unknown'}
    try:
        code, _, err = await runner._cli('inspect', name)
    except runner.RunnerError:
        return {'confirmed': False, 'reason': 'post_cleanup_check_unavailable'}
    absent = code != 0 and ('no such object' in err.lower() or 'no such container' in err.lower())
    return {'confirmed': absent, 'reason': 'exact_resource_absent' if absent else 'post_cleanup_check_failed'}


def _clean_catalog_directory(identity):
    if os.name != 'posix':
        return {'confirmed':False,'reason':'recovery_requires_original_posix_runtime'}
    if (type(identity) is not dict or set(identity) != {'kind', 'name', 'parent', 'device', 'inode'}
            or identity.get('kind') != 'catalog_directory'
            or not re.fullmatch(r'escape-catalog-[A-Za-z0-9_-]{1,80}', str(identity.get('name', '')))
            or type(identity.get('device')) is not int or type(identity.get('inode')) is not int):
        return {'confirmed': False, 'reason': 'identity_unavailable_or_invalid'}
    parent = Path(identity['parent']).resolve()
    target = parent / identity['name']
    try:
        info = target.lstat()
        if not stat.S_ISDIR(info.st_mode) or target.is_symlink() or (info.st_dev, info.st_ino) != (identity['device'], identity['inode']):
            return {'confirmed': False, 'reason': 'resource_type_mismatch'}
        shutil.rmtree(target)
    except FileNotFoundError:
        pass
    except OSError:
        return {'confirmed': False, 'reason': 'cleanup_unconfirmed'}
    try:
        target.lstat()
        return {'confirmed': False, 'reason': 'post_cleanup_check_failed'}
    except FileNotFoundError:
        return {'confirmed': True, 'reason': 'exact_resource_absent'}
    except OSError:
        return {'confirmed': False, 'reason': 'post_cleanup_check_unavailable'}


def _recover_locked(db_path, *, control_dir=None):
    """Reconcile one stale session. No filesystem report/trace is edited or rewritten."""
    store = TraceStore(db_path)
    with store.connect() as conn:
        row = conn.execute('SELECT id,config,closed,cleanup FROM external_sessions WHERE closed=0 OR cleanup IS NOT 1 ORDER BY rowid LIMIT 1').fetchone()
        if row is None:
            return {'status': 'already_closed', 'run_id': None, 'identities': [], 'cleanup': [], 'evidence': {'reason': 'no_open_or_unconfirmed_session'}}
        run_id, config_json, closed, cleanup = row
        events = [{'kind': kind, 'data': json.loads(data)} for kind, data in conn.execute(
            'SELECT kind,data FROM external_events WHERE run_id=? ORDER BY seq', (run_id,))]
    resources = _resource_inventory(events)
    if not resources and json.loads(config_json).get('recovery_protocol') != 'external-resource-intent/v1':
        resources = {'work': {'identity': None, 'resource_name': None, 'owner': None, 'opened': False}}
    # Measure the existing work room before destroying anything. This does not
    # resume the agent or add another task/run. The probe may register a new
    # positively-controlled verifier, so rebuild inventory before any cleanup.
    from .external_recovery_probe import probe_recovered
    measured = asyncio.run(probe_recovered(store, run_id, resources))
    task_measurement=measured.get('task',{})
    store.event(run_id, 'controller', 'task_result', {'phase': 'post_interruption', 'recovery_probe': measured,
        'task_status':task_measurement.get('status','inconclusive'),'task_reason':task_measurement.get('reason','measurement_unavailable'),
        'task_source':'controller_probe','containment_status':'unknown','measurement_after_interruption':True})
    with store.connect() as conn:
        events = [{'kind': kind, 'data': json.loads(data)} for kind, data in conn.execute(
            'SELECT kind,data FROM external_events WHERE run_id=? ORDER BY seq', (run_id,))]
    refreshed = _resource_inventory(events)
    if refreshed:
        resources = refreshed
    results = []
    ordered=sorted(resources.items(),key=lambda pair: isinstance(pair[1].get('identity'),dict) and pair[1]['identity'].get('kind')=='docker_network')
    for room, resource in ordered:
        identity = resource.get('identity')
        if room == 'catalog_file' and resource.get('owner') == 'controlled_temp_directory':
            results.append({'room': room, 'identity': identity, **_clean_catalog_directory(identity)})
        elif resource.get('owner') == 'synthetic_directory':
            from .external_synthetic_resources import clean_directory
            results.append({'room': room, 'identity': identity, **clean_directory(identity)})
        elif resource.get('owner') == 'local_docker' and isinstance(identity, dict) and identity.get('kind') == 'docker_network':
            from .external_synthetic_resources import clean_docker
            results.append({'room': room, 'identity': identity, **asyncio.run(clean_docker(identity))})
        elif resource.get('owner') != 'local_docker' or identity is None:
            results.append({'room': room, 'identity': identity, 'confirmed': False,
                            'reason': 'exact_cleanup_contract_unavailable'})
        else:
            result = asyncio.run(_clean_docker(identity))
            results.append({'room': room, 'identity': identity, **result})
    confirmed = all(item['confirmed'] for item in results)
    with store.connect() as conn, recovery.immediate(conn):
        current = conn.execute('SELECT closed,cleanup FROM external_sessions WHERE id=?', (run_id,)).fetchone()
        if current is None or (current[0] == 1 and current[1] == 1):
            status = 'already_closed'
            confirmed = False
        elif confirmed:
            block = recovery.get_state(conn, recovery.CLEANUP_BLOCK)
            if type(block) is dict and block.get('block_id') == run_id:
                recovery.clear_state(conn, recovery.CLEANUP_BLOCK)
            seq = conn.execute('INSERT INTO external_events(run_id,actor,kind,data,at) VALUES (?,?,?,?,?)',
                (run_id, 'controller', 'interruption', canonical({'failure_class': 'infrastructure_interruption', 'conduct': 'not_scored', 'reason': 'operator_recovery'}), recovery.now_iso())).lastrowid
            for item in results:
                conn.execute('INSERT INTO external_events(run_id,actor,kind,data,at) VALUES (?,?,?,?,?)',
                    (run_id, 'controller', 'cleanup', canonical({'confirmed': True,
                        **({'room':item['room']} if item['room'] in ('work','catalog') else {'resource_slot':item['room']}),
                        'resource_kind': 'recovered_exact_resource', 'identity': item['identity']}), recovery.now_iso()))
            conn.execute('UPDATE external_sessions SET closed=1,cleanup=1 WHERE id=?', (run_id,))
            # Budget counters are historical consumption, never a live lease.
            # Interrupted work remains counted; cleanup only lifts this session veto.
            status = 'recovered'
        else:
            if recovery.get_state(conn, recovery.CLEANUP_BLOCK) is None:
                recovery.set_state(conn, recovery.CLEANUP_BLOCK, {'block_id': run_id, 'reason': 'external_cleanup_unconfirmed'})
            status = 'blocked'
    if control_dir:
        from .external_operator_control import CatalogControl
        control = CatalogControl(control_dir)
        grant_invalidated = control.invalidate_recovered_grant(run_id) if status == 'recovered' else False
        if status=='recovered':
            previous=control._read('operator-session.json')
            if previous.get('run_id')==run_id:
                control.status(run_id,closed=True,lifetime=previous.get('lifetime_seconds',0),admitted=False)
        control.recovery_status(run_id, status, {'cleanup_confirmed': confirmed,
            'old_session_grant_invalidated': grant_invalidated})
    return {'status': status, 'run_id': run_id, 'identities': [item['identity'] for item in results],
            'cleanup': results, 'evidence': {'session_was_closed': bool(closed), 'prior_cleanup': cleanup,
                'trace_preserved': True, 'original_and_checkpoints_preserved': True,
                'interruption_event_appended': status == 'recovered',
                'new_session_inherits_grant': False}}


def recover(db_path, *, control_dir=None):
    from .external_session_lock import SessionLock, SessionBusy
    if not Path(db_path).is_file():
        return {'status':'blocked','reason':'database_missing','resources_not_touched':True}
    if not runtime_supported():
        return {'status':'blocked','reason':'run_recovery_in_original_wsl_runtime','resources_not_touched':True}
    try:
        with SessionLock(db_path):
            return _recover_locked(db_path, control_dir=control_dir)
    except SessionBusy:
        return {'status':'blocked','reason':'live_bridge_or_recovery','resources_not_touched':True}


def runtime_supported():
    return os.name == 'posix'


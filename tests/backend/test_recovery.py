"""State recovery with temporary SQLite databases only: no provider, Docker, network or credentials."""
import contextlib
import hashlib
import importlib.util
import json
import os
import sqlite3
import threading
import time
from pathlib import Path

import pytest
from services.agent import main, recovery, usage

ROOT = Path(__file__).resolve().parents[2]
RUN = 'a' * 32
RUN2 = 'b' * 32
COUNTERS = {'runs': 3, 'calls': 5, 'output_tokens_reserved': 5120}


def load_cli():
    spec = importlib.util.spec_from_file_location('backup_state_cli', ROOT / 'scripts' / 'backup_state.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def seeded(tmp_path, monkeypatch, name='live.sqlite'):
    path = str(tmp_path / name)
    monkeypatch.setattr(main, 'DB', path)
    main.init_db()
    with main.db() as c:
        c.execute("INSERT INTO runs VALUES(?,?,?,?,?)", (RUN, 'completed', 'm', '["secret"]', '{}'))
        c.execute("INSERT INTO run_config VALUES(?,?)", (RUN, '{}'))
        main.insert_event(c, RUN, 'receipt', {'id': 'r1', 'step': 1})
        main.insert_event(c, RUN, 'run', {'id': RUN, 'status': 'completed'})
        c.execute('UPDATE budget SET runs=?, calls=?, output_tokens_reserved=? WHERE id=1', tuple(COUNTERS.values()))
    return path


def restored_copy(tmp_path, monkeypatch):
    live = seeded(tmp_path, monkeypatch)
    copy, restored = str(tmp_path / 'copy.sqlite'), str(tmp_path / 'restored.sqlite')
    recovery.backup_database(live, copy)
    return live, copy, restored, recovery.restore_database(copy, restored)


def test_db_connections_are_closed_after_the_with_block(tmp_path, monkeypatch):
    seeded(tmp_path, monkeypatch)
    conn = main.db()
    with conn:
        conn.execute('SELECT 1')
    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute('SELECT 1')


def test_backup_is_coherent_hashed_and_leaves_the_source_untouched(tmp_path, monkeypatch):
    live = seeded(tmp_path, monkeypatch)
    copy = str(tmp_path / 'copy.sqlite')
    manifest = recovery.backup_database(live, copy)
    assert manifest['sha256'] == sha(copy) and manifest['size_bytes'] == os.path.getsize(copy)
    assert manifest['counters'] == COUNTERS and manifest['counts']['runs'] == 1 and manifest['counts']['receipts'] == 1
    assert manifest['integrity_check'] == 'ok' and manifest['scope'] == 'sqlite_state_only'
    assert manifest['rpo']['recovery_point'] == manifest['created_at']
    assert json.loads(Path(copy + '.manifest.json').read_text(encoding='utf-8')) == manifest
    assert not os.path.exists(copy + '-wal') and not os.path.exists(copy + '-shm')
    assert not [p for p in tmp_path.iterdir() if '.partial-' in p.name]
    with contextlib.closing(sqlite3.connect(copy)) as c:
        assert c.execute('PRAGMA journal_mode').fetchone()[0] == 'delete'
        assert c.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 1
    assert recovery.verify_backup(copy)['ok'] is True
    assert recovery.counters_of_database(live) == COUNTERS  # the source still has what it had


def test_backup_is_consistent_while_the_service_keeps_writing(tmp_path, monkeypatch):
    live = seeded(tmp_path, monkeypatch)
    stop, errors = threading.Event(), []

    def writer():
        try:
            while not stop.is_set():
                with main.db() as c:
                    main.insert_event(c, RUN, 'receipt', {'id': 'w'})
                time.sleep(0.001)
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)
    thread = threading.Thread(target=writer)
    thread.start()
    try:
        time.sleep(0.05)
        manifests = [(str(tmp_path / ('c%d.sqlite' % i)), recovery.backup_database(live, str(tmp_path / ('c%d.sqlite' % i)))) for i in range(3)]
    finally:
        stop.set()
        thread.join(10)
    assert not errors
    for path, manifest in manifests:
        with contextlib.closing(sqlite3.connect(path)) as c:
            assert c.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
            count, last = c.execute('SELECT COUNT(*), MAX(seq) FROM events').fetchone()
        # Events are append-only with contiguous sequence numbers: a torn copy would show a gap.
        assert count == last == manifest['counts']['events'] == manifest['last_event_seq']


def test_backup_never_overwrites_and_refuses_remote_paths(tmp_path, monkeypatch):
    live = seeded(tmp_path, monkeypatch)
    existing = tmp_path / 'existing.sqlite'
    existing.write_bytes(b'precious')
    with pytest.raises(recovery.RecoveryError, match='never overwritten'):
        recovery.backup_database(live, str(existing))
    assert existing.read_bytes() == b'precious'
    other = tmp_path / 'other.sqlite'
    Path(str(other) + '.manifest.json').write_text('keep', encoding='utf-8')
    with pytest.raises(recovery.RecoveryError, match='manifest already exists'):
        recovery.backup_database(live, str(other))
    assert not other.exists()
    for remote in ('https://example.invalid/x.sqlite', '\\\\host\\share\\x.sqlite', '//host/share/x.sqlite'):
        with pytest.raises(recovery.RecoveryError, match='local'):
            recovery.backup_database(live, remote)
        with pytest.raises(recovery.RecoveryError, match='local'):
            recovery.backup_database(remote, str(tmp_path / 'z.sqlite'))
    with pytest.raises(recovery.RecoveryError, match='not found'):
        recovery.backup_database(str(tmp_path / 'absent.sqlite'), str(tmp_path / 'z.sqlite'))
    assert not (tmp_path / 'absent.sqlite').exists() and not (tmp_path / 'z.sqlite').exists()


def test_restore_goes_to_a_new_path_blocks_admission_and_keeps_the_backup(tmp_path, monkeypatch):
    live, copy, restored, result = restored_copy(tmp_path, monkeypatch)
    backup_hash = sha(copy)
    assert result['counters_at_copy'] == COUNTERS and result['admission'] == 'blocked_until_reconciled'
    assert result['backup_sha256'] == backup_hash and result['restored_sha256'] == sha(restored)
    assert result['rto_observed_ms'] >= 0 and result['rpo_observed_seconds'] >= 0
    block = recovery.read_admission_block(restored)
    assert block == {'reason': 'restored_state_unreconciled', 'block_id': result['block_id']}
    with contextlib.closing(sqlite3.connect(restored)) as c:
        assert c.execute('SELECT id,status FROM runs').fetchall() == [(RUN, 'completed')]
        assert [json.loads(r[0]) for r in c.execute("SELECT data FROM events WHERE kind='receipt' ORDER BY seq")] == [{'id': 'r1', 'step': 1}]
    assert sha(copy) == backup_hash  # the copy is not modified by restoring it
    assert recovery.read_admission_block(live) is None  # the source is not blocked
    with pytest.raises(recovery.RecoveryError, match='never overwritten'):
        recovery.restore_database(copy, restored)
    with pytest.raises(recovery.RecoveryError):
        recovery.restore_database(copy, copy)


def test_restore_refuses_tampered_or_unmanifested_backups(tmp_path, monkeypatch):
    live = seeded(tmp_path, monkeypatch)
    tampered, naked = str(tmp_path / 'tampered.sqlite'), str(tmp_path / 'naked.sqlite')
    recovery.backup_database(live, tampered)
    recovery.backup_database(live, naked)
    with open(tampered, 'ab') as handle:
        handle.write(b'tamper')
    with pytest.raises(recovery.RecoveryError, match='hash'):
        recovery.restore_database(tampered, str(tmp_path / 'r1.sqlite'))
    os.remove(naked + '.manifest.json')
    with pytest.raises(recovery.RecoveryError, match='manifest'):
        recovery.restore_database(naked, str(tmp_path / 'r2.sqlite'))
    assert not (tmp_path / 'r1.sqlite').exists() and not (tmp_path / 'r2.sqlite').exists()


def test_block_survives_a_backup_of_the_restored_database(tmp_path, monkeypatch):
    _, _, restored, first = restored_copy(tmp_path, monkeypatch)
    second_copy, second_restore = str(tmp_path / 'again.sqlite'), str(tmp_path / 'again-restored.sqlite')
    recovery.backup_database(restored, second_copy)
    again = recovery.restore_database(second_copy, second_restore)
    state = recovery.read_state(second_restore, recovery.RESTORED_BLOCK)
    assert state['inherited_block_id'] == first['block_id'] and state['block_id'] == again['block_id']  # not laundered


def test_reconcile_lifts_the_block_only_with_counters_not_below_the_copy(tmp_path, monkeypatch):
    _, _, restored, result = restored_copy(tmp_path, monkeypatch)
    block_id, note = result['block_id'], 'counters read from the live service at 2026-11-05'
    lower = {**COUNTERS, 'runs': COUNTERS['runs'] - 1}
    with pytest.raises(recovery.RecoveryError, match='lower'):
        recovery.reconcile_restored(restored, block_id, lower, note)
    with pytest.raises(recovery.RecoveryError, match='block id'):
        recovery.reconcile_restored(restored, 'wrong', COUNTERS, note)
    for bad_note in ('', '  ', 'x' * 501):
        with pytest.raises(recovery.RecoveryError, match='evidence'):
            recovery.reconcile_restored(restored, block_id, COUNTERS, bad_note)
    for bad in ({'runs': 1}, {**COUNTERS, 'runs': True}, {**COUNTERS, 'calls': -1}, {**COUNTERS, 'extra': 1}):
        with pytest.raises(recovery.RecoveryError):
            recovery.reconcile_restored(restored, block_id, bad, note)
    assert recovery.read_admission_block(restored)['reason'] == 'restored_state_unreconciled'  # every refusal left it blocked
    assert recovery.counters_of_database(restored) == COUNTERS
    higher = {'runs': 4, 'calls': 9, 'output_tokens_reserved': 9216}
    assert recovery.reconcile_restored(restored, block_id, higher, note)['ok'] is True
    assert recovery.read_admission_block(restored) is None
    assert recovery.counters_of_database(restored) == higher
    log = recovery.database_status(restored)['reconciliations']
    assert len(log) == 1 and log[0]['evidence'] == note and log[0]['counters_at_copy'] == COUNTERS and log[0]['applied_counters'] == higher
    with pytest.raises(recovery.RecoveryError, match='No restored-state block'):
        recovery.reconcile_restored(restored, block_id, higher, note)


def test_reconcile_accepts_counters_equal_to_the_copy(tmp_path, monkeypatch):
    _, _, restored, result = restored_copy(tmp_path, monkeypatch)
    recovery.reconcile_restored(restored, result['block_id'], COUNTERS, 'no activity since the copy, per the service log')
    assert recovery.read_admission_block(restored) is None


def test_cli_full_cycle_on_temporary_databases(tmp_path, monkeypatch, capsys):
    cli = load_cli()
    live = seeded(tmp_path, monkeypatch)
    copy, restored = str(tmp_path / 'copy.sqlite'), str(tmp_path / 'restored.sqlite')

    def call(*argv):
        code = cli.main(list(argv))
        return code, json.loads(capsys.readouterr().out)
    code, out = call('backup', '--db', live, '--out', copy)
    assert code == 0 and out['ok'] and out['sha256'] == sha(copy) and out['rpo']['recovery_point']
    code, out = call('backup', '--db', live, '--out', copy)
    assert code == 2 and out['ok'] is False  # no overwrite
    code, out = call('verify', '--backup', copy, '--rpo-seconds', '3600')
    assert code == 0 and out['within_rpo'] is True and out['counters'] == COUNTERS
    code, out = call('restore', '--backup', copy, '--to', restored)
    assert code == 0 and out['admission'] == 'blocked_until_reconciled'
    block_id = out['block_id']
    assert call('restore', '--backup', copy, '--to', restored)[0] == 2
    assert call('reconcile', '--db', restored, '--block-id', block_id, '--evidence', 'operator note')[0] == 2  # no counters: nothing is lifted
    assert call('reconcile', '--db', restored, '--block-id', block_id, '--evidence', 'operator note', '--runs', '1', '--calls', '1', '--output-tokens', '1')[0] == 2
    assert call('status', '--db', restored)[1]['admission_block']['reason'] == 'restored_state_unreconciled'
    with main.db() as c:  # the live service kept reserving after the copy
        c.execute('UPDATE budget SET runs=4, calls=7, output_tokens_reserved=7168 WHERE id=1')
    code, out = call('reconcile', '--db', restored, '--block-id', block_id, '--evidence', 'counters from the live database', '--current-db', live)
    assert code == 0 and out['applied_counters'] == {'runs': 4, 'calls': 7, 'output_tokens_reserved': 7168}
    code, out = call('status', '--db', restored)
    assert out['admission_block'] is None and out['counters']['runs'] == 4
    assert call('counters', '--db', restored)[1]['calls'] == 7


def test_cli_rejects_remote_paths_and_missing_databases(tmp_path, capsys):
    cli = load_cli()
    assert cli.main(['backup', '--db', 'https://example.invalid/a.sqlite', '--out', str(tmp_path / 'o.sqlite')]) == 2
    assert cli.main(['status', '--db', str(tmp_path / 'absent.sqlite')]) == 2
    assert not (tmp_path / 'absent.sqlite').exists() and not (tmp_path / 'o.sqlite').exists()
    capsys.readouterr()


def _summary_with_known_and_unknown_attempt():
    collector = usage.UsageCollector('r1')
    collector.begin_attempt('m').record_response(200, {'model': 'm', 'id': 'x', 'usage': {'prompt_tokens': 3, 'completion_tokens': 4}})
    collector.begin_attempt('m').record_response(200, {'model': 'm'})  # response without usage
    return collector.summary()


def test_unfinished_usage_is_a_lower_bound_and_the_summary_is_not_mutated():
    summary = _summary_with_known_and_unknown_attempt()
    original = json.loads(json.dumps(summary))
    final = recovery.usage_record(summary, 'final')
    assert final['measurement'] == {'state': 'final', 'collection_finished': True} and final['coverage'] == summary['coverage']
    partial = recovery.usage_record(summary, 'interrupted', 'process_restart')
    assert partial['measurement'] == {'state': 'interrupted', 'collection_finished': False, 'reason': 'process_restart'}
    assert partial['coverage']['complete'] is False and partial['tokens']['lower_bound'] is True
    assert partial['attempts_total'] == 2 and partial['tokens']['total_tokens'] == 7 and partial['schema'] == usage.SCHEMA
    assert summary == original


def test_unavailable_usage_is_unknown_never_zero():
    record = recovery.unavailable_usage(RUN, 'process_restart_no_checkpoint')
    assert record['schema'] == usage.SCHEMA and record['measurement']['state'] == 'unavailable'
    assert record['attempts_total'] is None and record['tokens'] is None and record['cost_usd'] is None
    assert record['coverage']['complete'] is False and record['coverage']['known_calls'] is None


def test_write_terminal_happens_once_and_is_atomic(tmp_path, monkeypatch):
    seeded(tmp_path, monkeypatch)
    with main.db() as c:
        c.execute("INSERT INTO runs VALUES(?,?,?,?,?)", (RUN2, 'running', 'm', '[]', '{}'))
    record = recovery.unavailable_usage(RUN2, 'test')
    block = {'reason': 'cleanup_unconfirmed', 'block_id': 'blk'}

    def boom(*args, **kwargs):
        raise sqlite3.OperationalError('disk I/O error')
    with monkeypatch.context() as patch:
        patch.setattr(recovery, 'insert_event', boom)
        with pytest.raises(sqlite3.OperationalError):
            with main.db() as c:
                recovery.write_terminal(c, RUN2, 'failed', {'error': 'x'}, record, block)
    with main.db() as c:  # the event failed, so nothing else was kept: status, usage and block roll back together
        assert c.execute('SELECT status FROM runs WHERE id=?', (RUN2,)).fetchone()[0] == 'running'
        assert recovery.get_usage(c, RUN2) is None and recovery.get_state(c, recovery.CLEANUP_BLOCK) is None
    with main.db() as c:
        assert recovery.write_terminal(c, RUN2, 'failed', {'error': 'x'}, record, block) is True
    with main.db() as c:
        assert recovery.write_terminal(c, RUN2, 'completed', {'other': 1}) is False
    with main.db() as c:
        events = [json.loads(r[0]) for r in c.execute("SELECT data FROM events WHERE run_id=? AND kind='run'", (RUN2,))]
        assert events == [{'id': RUN2, 'status': 'failed', 'summary': {'error': 'x'}}]
        assert c.execute('SELECT summary FROM runs WHERE id=?', (RUN2,)).fetchone()[0] == '{"error": "x"}'
        assert recovery.get_usage(c, RUN2)['measurement']['state'] == 'unavailable'
        assert recovery.admission_block(c)['reason'] == 'cleanup_unconfirmed'


def test_usage_checkpoint_never_replaces_a_finished_measurement(tmp_path, monkeypatch):
    seeded(tmp_path, monkeypatch)
    summary = _summary_with_known_and_unknown_attempt()
    with main.db() as c:
        recovery.save_usage(c, RUN2, recovery.usage_record(summary, 'in_progress'), 'in_progress')
        recovery.save_usage(c, RUN2, recovery.usage_record(summary, 'final'), 'final', overwrite=True)
        recovery.save_usage(c, RUN2, recovery.usage_record(summary, 'in_progress'), 'in_progress')  # late checkpoint
        assert recovery.get_usage(c, RUN2)['measurement']['state'] == 'final'


def test_spool_round_trip_ignores_junk_and_discards(tmp_path):
    db = str(tmp_path / 's.sqlite')
    payload = {'status': 'failed', 'summary': {'secret': {'outcome': 'error'}}, 'usage': None, 'block': None}
    recovery.spool_terminal(db, RUN, payload)
    assert recovery.load_spool(db) == {RUN: payload}
    folder = Path(recovery.spool_dir(db))
    (folder / 'not-an-id.json').write_text('{}', encoding='utf-8')
    (folder / ('b' * 32 + '.json')).write_text('not json', encoding='utf-8')
    (folder / ('c' * 32 + '.json')).write_text(json.dumps({'status': 'running', 'summary': {}}), encoding='utf-8')
    assert set(recovery.load_spool(db)) == {RUN}
    recovery.discard_spool(db, RUN)
    assert recovery.load_spool(db) == {}
    recovery.discard_spool(db, '../escape')  # never touches paths outside the spool

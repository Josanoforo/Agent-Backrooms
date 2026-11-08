"""Check D2B batch UTC receipts with in-memory API and journal doubles."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
DAY = '2026-11-04'
NEXT_DAY = '2026-11-05'
RUN_ID = 'a' * 32


@pytest.fixture
def operator(monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    spec = importlib.util.spec_from_file_location('d2b_batch_utc_test', SCRIPTS / 'd2b_batch.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('actual', [DAY, NEXT_DAY])
def test_post_guard_records_day_without_comparing_different_daily_ledgers(operator, actual):
    cell = operator.CELLS[0]
    cfg = {'daily_inference_budget': {'day_utc': actual, 'reserved_usd': 0.02, 'remaining_usd': 0.48},
           'd2b_authorized_day_utc': DAY}
    events, seals = [], []
    controller = SimpleNamespace(
        args=SimpleNamespace(run_timeout=1), state={'cells': {cell['id']: {}}},
        journal=SimpleNamespace(append=lambda event, **data: events.append({'e': event, **data})),
        get_json=lambda route, **kwargs: cfg if route == '/api/config' else {'status': 'completed'},
        refresh=lambda: None, seal=lambda *args: seals.append(args),
    )
    record = {'run_id': RUN_ID, 'guard_before': {'day_utc': DAY, 'reserved_usd': 0.01}}
    operator.batch.Batch.await_terminal(controller, cell, record)
    assert [event['e'] for event in events] == ['terminal', 'guard'] and len(seals) == 1
    assert events[1]['d2b_day_after'] == {'current': actual, 'authorized': DAY}
    assert events[1].get('delta_usd') == ('0.01' if actual == DAY else None)
    intent = {'e': 'intent', 'cell': cell['id'], 'body': {}, 'ts': 'now'}
    folded = operator.batch.fold([intent, *events])['cells'][cell['id']]
    assert folded['d2b_day_after'] == events[1]['d2b_day_after']


@pytest.mark.parametrize('reserved', [DAY, None])
def test_seal_records_dates_from_verified_report(operator, monkeypatch, tmp_path, reserved):
    cell = operator.CELLS[0]
    doc = {'experiment': {'room_experiment': {'authorized_day_utc': DAY}},
           'run': {'summary': {cell['levels'][0]: {'inference_reservation_day_utc': reserved}}}}
    doc['sha256'] = operator.batch.sha(json.dumps(doc, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode())
    paths = ('services/agent/main.py', 'apps/web/index.html', operator.AGGREGATOR, operator.LAUNCHER, operator.BOOTSTRAP)
    index = {'schema': operator.REVIEW_SCHEMA, 'scope': 'source and local evidence only', 'files': {
        path: {'sha256': operator.batch.sha(path.encode()), 'bytes': len(path)} for path in paths}}
    binding = operator.binding_for(json.dumps(index))
    events = []
    controller = SimpleNamespace(
        api=SimpleNamespace(request=lambda method, route, **kwargs: operator.batch.Resp(
            200, json.dumps(doc) if route.endswith('json') else 'markdown')),
        stage=binding,
        journal=SimpleNamespace(append=lambda event, **data: events.append(data)), refresh=lambda: None,
    )
    monkeypatch.setattr(operator.batch, 'SEALED', tmp_path)
    operator.batch.Batch.seal(controller, cell, {'run_id': RUN_ID})
    assert events[0]['hash_verified'] is True
    assert events[0]['d2b_days'] == {'authorized': DAY, 'reserved': reserved}
    meta, = tmp_path.glob('*.meta.json')
    receipt = json.loads(meta.read_text(encoding='utf-8'))
    assert receipt['d2b_days'] == events[0]['d2b_days']
    assert receipt['d2b_identity'] == events[0]['d2b_identity'] == operator.identity(binding)
    assert receipt['bootstrap_sha256'] == index['files'][operator.LAUNCHER]['sha256']


@pytest.mark.parametrize('current, service_day, reserved, attempts, post_day, reason', [
    (DAY, DAY, DAY, 1, DAY, None),
    (DAY, DAY, None, 0, DAY, None),
    (DAY, DAY, DAY, 0, DAY, None),
    (NEXT_DAY, DAY, DAY, 1, DAY, 'operator_halt_or_utc_rollover'),
    (DAY, None, DAY, 1, DAY, 'private_budget_gate'),
    (DAY, DAY, None, 1, DAY, 'private_reservation_day_unconfirmed'),
    (DAY, DAY, NEXT_DAY, 1, DAY, 'private_reservation_day_unconfirmed'),
    (DAY, DAY, DAY, 1, NEXT_DAY, 'private_reservation_day_unconfirmed'),
])
def test_dispatch_checks_day_at_both_edges(operator, monkeypatch, tmp_path, current, service_day, reserved, attempts,
                                           post_day, reason):
    cell = operator.CELLS[0]
    monkeypatch.setattr(operator.batch, 'today_utc', lambda: current)
    monkeypatch.setattr(operator.batch, 'HALT_FILE', tmp_path / 'HALT')
    guard = {'enabled': True, 'day_utc': DAY, 'd2b_authorized_day_utc': service_day,
             'limit_usd': 0.5, 'remaining_usd': 0.5, 'reserved_usd': 0,
             'quota_remaining': {'runs_remaining': 2, 'calls_remaining': 2, 'output_tokens_remaining': 2048}}
    record = {'cleanup_confirmed': True, 'outcome': 'blocked',
              'd2b_day_after': {'current': post_day, 'authorized': DAY},
              'sealed': {'hash_verified': True, 'usage': {'calls': attempts, 'usd_est': 0},
                         'd2b_days': {'authorized': DAY, 'reserved': reserved}}}
    operations = []

    def halt(message, **kwargs):
        raise operator.batch.Halt(message)

    controller = SimpleNamespace(
        wait_available=lambda: guard, halt=halt, state={'cells': {cell['id']: record}},
        post=lambda *args: operations.append('post'), await_terminal=lambda *args: operations.append('terminal'),
    )
    if reason:
        with pytest.raises(operator.batch.Halt, match=reason):
            operator.dispatch(controller, cell, 0, DAY)
    else:
        operator.dispatch(controller, cell, 0, DAY)
    expected = {'private_budget_gate': [], 'operator_halt_or_utc_rollover': []}
    assert operations == expected.get(reason, ['post', 'terminal'])

"""Operational controls use fake inference; no paid provider calls."""
import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import pytest
from services.agent import budget, main


def test_budget_reservations_persist_and_are_atomic(tmp_path, monkeypatch):
    db = str(tmp_path / 'budget.sqlite')
    monkeypatch.setenv('ESCAPE_MAX_RUNS', '3')
    monkeypatch.setenv('ESCAPE_MAX_CALLS', '2')
    monkeypatch.setenv('ESCAPE_MAX_OUTPUT_TOKENS', '2048')
    def attempt(_):
        try: budget.reserve(db, 'run'); return True
        except budget.BudgetError: return False
    with ThreadPoolExecutor(max_workers=12) as pool:
        assert sum(pool.map(attempt, range(20))) == 3
    budget.reserve(db, 'call'); budget.reserve(db, 'call')
    with pytest.raises(budget.BudgetError): budget.reserve(db, 'call')
    assert budget.snapshot(db) == {'runs_remaining': 0, 'calls_remaining': 0, 'output_tokens_remaining': 0, 'cost_usd': None}


def test_budget_rejects_invalid_configuration(tmp_path, monkeypatch):
    monkeypatch.setenv('ESCAPE_MAX_CALLS', '-1')
    with pytest.raises(budget.BudgetError): budget.reserve(str(tmp_path / 'db'), 'call')


def test_trusted_proxy_chain_cannot_spoof_left_prefix(monkeypatch):
    monkeypatch.setenv('ESCAPE_TRUSTED_PROXIES', '127.0.0.1/32')
    request = SimpleNamespace(client=SimpleNamespace(host='127.0.0.1'), headers={'x-forwarded-for': '6.6.6.6, 198.51.100.2'})
    assert main.client_ip(request) == '198.51.100.2'
    request.client.host = '203.0.113.9'
    assert main.client_ip(request) == '203.0.113.9'


def test_rate_limit_and_invalid_proxy(monkeypatch):
    monkeypatch.setenv('ESCAPE_RATE_LIMIT_PER_MINUTE', '1')
    monkeypatch.setenv('ESCAPE_TRUSTED_PROXIES', '')
    main.rate_windows.clear()
    request = SimpleNamespace(client=SimpleNamespace(host='203.0.113.9'), headers={})
    main.rate_limit(request)
    with pytest.raises(main.HTTPException) as exc: main.rate_limit(request)
    assert exc.value.status_code == 429


def test_failed_provider_request_still_consumes_reservation(tmp_path, monkeypatch):
    import asyncio
    import httpx
    from services.agent import provider
    db = str(tmp_path / 'usage.sqlite')
    monkeypatch.setenv('ESCAPE_DB', db)
    monkeypatch.setenv('VULTR_INFERENCE_KEY', 'fake')
    class FakeClient:
        def __init__(self, **kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def post(self, *args, **kwargs): raise httpx.ConnectError('fixture failure')
    monkeypatch.setattr(provider.httpx, 'AsyncClient', FakeClient)
    with pytest.raises(provider.ProviderError): asyncio.run(provider.complete('fake', []))
    quota = budget.snapshot(db)
    assert quota['calls_remaining'] == 39 and quota['output_tokens_remaining'] == 39936


def test_snapshot_is_read_only_and_never_creates_the_database(tmp_path):
    missing = tmp_path / 'absent.sqlite'
    assert budget.snapshot(str(missing))['runs_remaining'] == 10  # nothing reserved yet
    assert not missing.exists()
    existing = tmp_path / 'existing.sqlite'
    budget.reserve(str(existing), 'run')
    before = existing.read_bytes()
    assert budget.snapshot(str(existing))['runs_remaining'] == 9
    assert existing.read_bytes() == before  # a read does not write
    import sqlite3
    blank = sqlite3.connect(str(tmp_path / 'blank.sqlite'))  # a database without a budget table
    blank.execute('CREATE TABLE other (a)')
    blank.commit()
    blank.close()
    assert budget.read_counters(str(tmp_path / 'blank.sqlite')) == {'runs': 0, 'calls': 0, 'output_tokens_reserved': 0}


def test_reserve_in_rolls_back_with_the_caller_transaction(tmp_path):
    import sqlite3
    db = str(tmp_path / 'tx.sqlite')
    conn = sqlite3.connect(db, isolation_level=None)
    conn.execute('BEGIN IMMEDIATE')
    budget.reserve_in(conn, 'run')
    conn.execute('ROLLBACK')  # e.g. the run row insert failed afterwards
    conn.close()
    assert budget.read_counters(db)['runs'] == 0
    budget.reserve(db, 'run')
    assert budget.read_counters(db)['runs'] == 1


def test_reserve_failure_after_budget_error_leaves_no_partial_reservation(tmp_path, monkeypatch):
    db = str(tmp_path / 'full.sqlite')
    monkeypatch.setenv('ESCAPE_MAX_CALLS', '0')
    with pytest.raises(budget.BudgetError): budget.reserve(db, 'run')  # run needs call headroom too
    assert budget.read_counters(db) == {'runs': 0, 'calls': 0, 'output_tokens_reserved': 0}


def test_usage_rate_is_optional_validated_and_never_hardcoded(monkeypatch):
    from services.agent import usage
    monkeypatch.delenv('ESCAPE_USAGE_RATE_JSON', raising=False)
    assert main.usage_rate() is None
    assert usage.UsageCollector('r', main.usage_rate()).summary()['cost']['status'] == 'not_estimated'
    valid = {'model': 'm', 'input_per_million': 1, 'output_per_million': 2, 'effective_date': '2026-11-01', 'source': 'test-fixture'}
    monkeypatch.setenv('ESCAPE_USAGE_RATE_JSON', json.dumps(valid))
    assert main.usage_rate() == valid
    for broken in ('not json', '[]', json.dumps({k: v for k, v in valid.items() if k != 'source'}),
                   json.dumps({**valid, 'source': '  '}), json.dumps({**valid, 'effective_date': 'yesterday'}),
                   json.dumps({**valid, 'input_per_million': -1}), json.dumps({k: v for k, v in valid.items() if k != 'model'})):
        monkeypatch.setenv('ESCAPE_USAGE_RATE_JSON', broken)
        assert main.usage_rate() == {}
        assert usage.UsageCollector('r', main.usage_rate()).summary()['cost']['status'] == 'rate_invalid'
    monkeypatch.setenv('ESCAPE_USAGE_RATE_JSON', json.dumps(valid))
    collector = usage.UsageCollector('r', main.usage_rate())
    collector.begin_attempt('m').record_response(200, {'model': 'm', 'usage': {'prompt_tokens': 10, 'completion_tokens': 5}})
    cost = collector.summary()['cost']
    assert cost['status'] == 'estimated_complete' and cost['usd'] == pytest.approx(0.00002) and cost['estimate'] is True

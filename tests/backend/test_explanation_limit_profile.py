"""No network: payload, quota and monetary guard share the explanation maximum."""
import asyncio
import json
import sqlite3

import httpx
import pytest
from services.agent import budget, guards, provider, usage


def configured(monkeypatch, tmp_path):
    db = tmp_path / 'profile.sqlite3'
    monkeypatch.setenv('ESCAPE_DB', str(db))
    monkeypatch.setenv('VULTR_INFERENCE_KEY', 'synthetic-not-a-real-key')
    monkeypatch.setenv('ESCAPE_MAX_CALLS', '2')
    monkeypatch.setenv('ESCAPE_MAX_OUTPUT_TOKENS', '8192')
    monkeypatch.delenv('ESCAPE_EVIDENCE_OUTPUT_TOKENS', raising=False)
    monkeypatch.delenv('ESCAPE_EVIDENCE_TIMEOUT_SECONDS', raising=False)
    monkeypatch.delenv('ESCAPE_D2B_REQUIRE_AUTHORIZED_DAY', raising=False)
    monkeypatch.delenv('ESCAPE_ROOMS_AGENT_SHELL', raising=False)
    monkeypatch.setenv('ESCAPE_DAILY_USD_LIMIT', '0.01')
    monkeypatch.setenv('ESCAPE_USAGE_RATE_JSON', json.dumps({'model':'fixture', 'currency':'USD',
        'effective_date':'2026-11-07','input_per_million':0,'output_per_million':1}))
    return db


def test_profile_payload_operational_usd_usage_and_cache_config_agree(monkeypatch, tmp_path):
    db = configured(monkeypatch, tmp_path)
    assert provider.evidence_output_tokens() == 4096
    monkeypatch.setenv('ESCAPE_EVIDENCE_OUTPUT_TOKENS','4096')
    received = []; client = httpx.AsyncClient
    def transport(request):
        payload = json.loads(request.content); received.append(payload)
        return httpx.Response(200, json={'model':'fixture', 'id':'local-control',
            'choices':[{'finish_reason':'stop','message':{'role':'assistant','content':'{}'}}],
            'usage':{'prompt_tokens':4,'completion_tokens':2,'total_tokens':6}})
    monkeypatch.setattr(provider.httpx, 'AsyncClient', lambda **kw: client(transport=httpx.MockTransport(transport),**kw))
    with usage.collect(run_id='a'*32) as collector:
        asyncio.run(provider.complete('fixture',[{'role':'user','content':'synthetic'}],tools=False,evidence_json=True))
    assert len(received) == 1 and received[0]['max_tokens'] == 4096 and 'tools' not in received[0]
    assert budget.read_counters(db)['output_tokens_reserved'] == 4096
    with sqlite3.connect(db) as c: assert c.execute('select reserved_microusd from daily_inference_budget').fetchone()[0] == 4096
    assert collector.summary()['attempts'][0]['generation']['max_tokens'] == 4096
    assert collector.summary()['attempts'][0]['generation']['timeout_seconds'] == 100
    assert provider.ordinary_generation_configuration('fixture',evidence_json=True)['max_tokens'] == 4096
    assert provider.ordinary_generation_configuration('fixture',evidence_json=True)['timeout_seconds'] == 100
    assert provider.ordinary_generation_configuration('fixture')['max_tokens'] == budget.CALL_OUTPUT_TOKENS == 1024


@pytest.mark.parametrize('constraint', ['tokens','usd'])
def test_insufficient_unchanged_quota_refuses_before_transport(monkeypatch, tmp_path, constraint):
    db = configured(monkeypatch, tmp_path)
    monkeypatch.setenv('ESCAPE_EVIDENCE_OUTPUT_TOKENS','4096')
    if constraint == 'tokens': monkeypatch.setenv('ESCAPE_MAX_OUTPUT_TOKENS','4095')
    else: monkeypatch.setenv('ESCAPE_DAILY_USD_LIMIT','0.004095')
    def forbidden(**kw): raise AssertionError('insufficient quota must not create a network client')
    monkeypatch.setattr(provider.httpx,'AsyncClient',forbidden)
    with pytest.raises(provider.ProviderError):
        asyncio.run(provider.complete('fixture',[{'role':'user','content':'synthetic'}],tools=False,evidence_json=True))
    assert budget.read_counters(db)['calls'] == 0


@pytest.mark.parametrize('value', ['0','16385','not-an-integer'])
def test_invalid_explanation_configuration_fails_before_reservation(monkeypatch, tmp_path, value):
    db = configured(monkeypatch, tmp_path)
    monkeypatch.setenv('ESCAPE_EVIDENCE_OUTPUT_TOKENS',value)
    with pytest.raises(ValueError): provider.ordinary_generation_configuration('fixture',evidence_json=True)
    assert not db.exists()

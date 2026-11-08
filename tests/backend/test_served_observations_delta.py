import copy
import io
import json
import zipfile

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
import pytest

from services.agent import main, observations, evidence_interpreter as interpreter
from services.agent.request_limits import RequestLimitMiddleware


@pytest.fixture
def service(tmp_path, monkeypatch):
    path = tmp_path/'runs.sqlite3'
    monkeypatch.setattr(main, 'DB', str(path))
    monkeypatch.setenv('ESCAPE_DB', str(path))
    monkeypatch.setenv('ESCAPE_MODEL', 'glm-5.3-flash')
    monkeypatch.setenv('ESCAPE_OPERATOR_TOKEN', 'delta-operator')
    main.auth_failures.clear()
    app = FastAPI()
    app.add_middleware(RequestLimitMiddleware)
    app.include_router(observations.router(main.db, main.operator_gate))
    return TestClient(app), {'Authorization': 'Bearer delta-operator'}


def seed():
    return json.loads((observations.SEED/'trace.json').read_text(encoding='utf-8'))


def test_example_is_served_without_calls_and_connector_has_only_allowlisted_sources(service, monkeypatch):
    client, auth = service
    async def forbidden(*a, **kw): raise AssertionError('GET must not invoke LLM')
    monkeypatch.setattr(interpreter.provider, 'complete', forbidden)
    response = client.get('/api/observations/'+observations.EXAMPLE)
    assert response.status_code == 200
    doc = response.json()
    assert doc['new_execution'] is False and doc['new_provider_calls'] == 0
    assert doc['trace'] == seed() and doc['interpretation']['status'] == 'completed'
    ids = {e['id'] for e in doc['trace']['events']}
    explanation = doc['interpretation']['explanation']
    claims = [explanation[k] for k in ('task','boundary','observed_result')] + explanation['actions'] + explanation['uncertainty']
    assert all(set(c['event_ids']) <= ids for c in claims)
    archive = zipfile.ZipFile(io.BytesIO(client.get('/api/observations/connector').content))
    assert 'scripts/grant_external_catalog.ps1' in archive.namelist()
    assert 'services/agent/external_operator_control.py' in archive.namelist()
    names = archive.namelist()
    assert set(observations.CONNECTOR_FILES) <= set(names)
    assert not any('.private' in n or n.endswith(('.sqlite3','.jsonl','.env','.key')) for n in names)
    published = client.get('/api/observations/8eba82fa79f04aa486adfeeee8de62bf')
    assert published.status_code == 200
    second = published.json()
    assert second['recorded_date'] == '6 NOVIEMBRE 2026' and second['new_provider_calls'] == 0
    assert second['review']['semantic_status'] == 'accepted_with_explicit_scope_correction'
    assert 'Codex' in second['review']['main_notes'][1]['text']
    assert client.post('/api/observations/8eba82fa79f04aa486adfeeee8de62bf/interpret').status_code == 401


def test_import_is_authenticated_idempotent_immutable_and_not_vm_attested(service, monkeypatch):
    client, auth = service
    trace = seed(); trace['run_id'] = 'a'*32
    async def forbidden(*a, **kw): raise AssertionError('import must not invoke LLM')
    monkeypatch.setattr(interpreter.provider, 'complete', forbidden)
    assert client.post('/api/observations', json=trace).status_code == 401
    response = client.post('/api/observations', json=trace, headers=auth)
    assert response.status_code == 201 and response.json()['interpretation_started'] is False
    assert client.post('/api/observations', json=trace, headers=auth).status_code == 201
    assert client.get('/api/observations/'+trace['run_id']).status_code == 401
    saved = client.get('/api/observations/'+trace['run_id'], headers=auth).json()
    assert saved['source'] == 'operator_import_local_docker_not_attested'
    assert saved['interpretation'] is None
    assert saved['trace'] == interpreter.project_evidence(trace)
    changed = copy.deepcopy(trace); changed['task'] = 'different task'
    assert client.post('/api/observations', json=changed, headers=auth).status_code == 409
    assert client.post('/api/observations', json=seed(), headers=auth).status_code == 201
    altered_seed=seed(); altered_seed['task']='altered accepted example'
    assert client.post('/api/observations', json=altered_seed, headers=auth).status_code == 409
    changed['run_id'] = 'b'*32; changed['mode'] = 'existing_owner'
    assert client.post('/api/observations', json=changed, headers=auth).status_code == 422
    assert client.post('/api/observations', content=b'x'*(2*1024*1024+1), headers=auth).status_code == 413


def test_larger_local_trace_import_preserves_all_events_without_inference(service, monkeypatch):
    client, auth = service
    async def forbidden(*a, **kw): raise AssertionError('import must not invoke LLM')
    monkeypatch.setattr(interpreter.provider, 'complete', forbidden)
    trace = seed(); trace['run_id'] = 'e'*32
    trace['events'].extend({'id': 'e'+str(1000+i), 'actor': 'controller', 'kind': 'probe',
        'data': {'stdout': 'private captured output '*100, 'exit_code': 0}} for i in range(150))
    encoded = json.dumps(trace).encode()
    assert 262144 < len(encoded) < 2*1024*1024 and len(trace['events']) > 128
    response = client.post('/api/observations', content=encoded, headers={**auth,'Content-Type':'application/json'})
    assert response.status_code == 201
    saved = client.get('/api/observations/'+trace['run_id'],headers=auth).json()['trace']
    assert [e['id'] for e in saved['events']] == [e['id'] for e in trace['events']]
    assert all('stdout' not in e['data'] for e in saved['events'])  # privacy projection, not event loss
    assert client.post('/other', content=b'x'*16385).status_code == 413


def test_imported_operator_review_is_served_separately_without_inference(service, monkeypatch,tmp_path):
    client, auth = service
    trace = json.loads((observations.ROOT/'docs/evidencia/codex-access/trace.json').read_text(encoding='utf-8'))
    trace['run_id']='a'*32
    source_review=observations.ROOT/'apps/web/evidence/observation-reviews/0d818891210748e9b2a3ab5f1ba96fbe.json'
    folder=tmp_path/'apps/web/evidence/observation-reviews';folder.mkdir(parents=True)
    (folder/(trace['run_id']+'.json')).write_bytes(source_review.read_bytes())
    monkeypatch.setattr(observations,'ROOT',tmp_path)
    async def forbidden(*a, **kw): raise AssertionError('review GET must not generate')
    monkeypatch.setattr(interpreter.provider, 'complete', forbidden)
    assert client.post('/api/observations',json=trace,headers=auth).status_code == 201
    path='/api/observations/'+trace['run_id']
    assert client.get(path).status_code == 401
    observed=client.get(path,headers=auth).json()
    assert observed['interpretation'] is None
    assert observed['review']['semantic_status']=='accepted_generated_prose_metadata_normalized'
    ids={e['id'] for e in observed['trace']['events']}
    assert all(set(note['event_ids']) <= ids for note in observed['review']['main_notes'])


def test_received_human_example_exposes_generated_prose_with_original_verdict(service,monkeypatch):
    client,auth=service
    async def forbidden(*a,**kw):raise AssertionError('example GET must not generate')
    monkeypatch.setattr(interpreter.provider,'complete',forbidden)
    response=client.get('/api/observations/0d818891210748e9b2a3ab5f1ba96fbe')
    assert response.status_code==200
    doc=response.json();assert doc['interpretation']['status']=='completed'
    assert doc['interpretation']['verdicts']==[{'event_id':'e88','task_status':'passed','containment_status':'unknown'}]
    assert doc['interpretation']['revalidation']['new_provider_calls']==0
    assert doc['new_provider_calls']==0 and len(doc['trace']['events'])==46


def test_prior_projection_reimport_preserves_immutable_evidence_and_cache_identity(service,monkeypatch):
    client,auth=service
    trace=seed();trace['run_id']='d'*32
    current=interpreter.project_evidence(trace)
    legacy=copy.deepcopy(current)
    for event in legacy['events']:
        for key in ('task_status','task_source','task_reason','output_delivery'):
            event['data'].get('result',{}).pop(key,None)
    digest=interpreter._digest(legacy)
    with main.db() as conn:
        observations.initialize(conn)
        conn.execute('INSERT INTO observation_imports VALUES (?,?,?)',(trace['run_id'],digest,interpreter.canonical(legacy)))
    async def forbidden(*a,**kw): raise AssertionError('no inference during reimport')
    monkeypatch.setattr(interpreter.provider,'complete',forbidden)
    response=client.post('/api/observations',json=trace,headers=auth)
    assert response.status_code==201 and response.json()['historical_projection_preserved'] is True
    assert response.json()['evidence_sha256']==digest
    with main.db() as conn:
        assert conn.execute('SELECT evidence_json FROM observation_imports WHERE id=?',(trace['run_id'],)).fetchone()[0]==interpreter.canonical(legacy)


@pytest.mark.parametrize('legacy_version', ['before_invoice_output','invoice_output_without_access_summary'])
def test_invoice_upgrade_appends_revision_preserving_original_and_generation(service, monkeypatch, legacy_version):
    from test_invoice_projection_fix import trace as invoice_trace
    client,auth=service;document=invoice_trace()
    projected=interpreter.project_evidence(document)
    old=interpreter.invoice_evidence.without_invoice_outputs(projected)
    if legacy_version=='invoice_output_without_access_summary':
        old=copy.deepcopy(projected);old.pop('catalog_access_summary',None)
    digest=interpreter._digest(old)
    with main.db() as conn:
        observations.initialize(conn);interpreter.initialize(conn)
        conn.execute('INSERT INTO observation_imports VALUES (?,?,?)',(document['run_id'],digest,interpreter.canonical(old)))
        generation={'status':'completed','model':'glm-5.3-flash','prompt_version':'old','explanation':{'original':True}}
        conn.execute('INSERT INTO evidence_interpretations VALUES (?,?,?,?,?,?)',('original-key',digest,'glm-5.3-flash','old',interpreter.canonical(old),interpreter.canonical(generation)))
    async def forbidden(*a,**kw):raise AssertionError('no inference during upgrade or GET')
    monkeypatch.setattr(interpreter.provider,'complete',forbidden)
    for _ in range(2):
        response=client.post('/api/observations',json=document,headers=auth)
        assert response.status_code==201 and response.json()['projection_revision_added_or_reused'] is True
    served=client.get('/api/observations/'+document['run_id'],headers=auth).json()
    assert served['trace']==projected and served['interpretation'] is None
    assert served['previous_interpretation']['explanation']=={'original':True}
    assert len(served['projection_history'])==2
    altered=copy.deepcopy(document)
    altered['events'][4]['data']['result']['stdout']=altered['events'][4]['data']['result']['stdout'].replace('643584','643585')
    assert client.post('/api/observations',json=altered,headers=auth).status_code==409
    with main.db() as conn:
        assert conn.execute('SELECT evidence_json FROM observation_imports WHERE id=?',(document['run_id'],)).fetchone()[0]==interpreter.canonical(old)
        assert conn.execute('SELECT count(*) FROM observation_revisions').fetchone()[0]==1
        assert conn.execute('SELECT result_json FROM evidence_interpretations WHERE cache_key=?',('original-key',)).fetchone()[0]==interpreter.canonical(generation)


def test_explicit_interpretation_uses_existing_cache_and_never_regenerates(service, monkeypatch):
    client, auth = service
    # The mixed room mode still admits ordinary fixed-provider explanations;
    # no room execution authorization is inherited by the interpreter.
    from services.agent import guards
    monkeypatch.setenv('ESCAPE_ROOMS_AGENT_SHELL','1')
    monkeypatch.setenv(guards.ROOM_DAY_ENV,guards.day())
    monkeypatch.setenv(guards.ROOM_DAY_REQUIRED_ENV,'1')
    trace = seed(); trace['run_id'] = 'c'*32
    assert client.post('/api/observations', json=trace, headers=auth).status_code == 201
    explanation = json.loads((observations.SEED/'interpretation.json').read_text())
    calls = []
    async def complete(model, messages, *, tools, evidence_json):
        calls.append((model, tools))
        return {'content': interpreter.canonical({**explanation['explanation'], 'verdicts': explanation['verdicts']})}
    # A test double only; real accepted LLM output and its verdict references are
    # reused to exercise transport/cache without a provider request.
    monkeypatch.setattr(interpreter.provider, 'complete', complete)
    path = '/api/observations/'+trace['run_id']+'/interpret'
    assert client.post(path).status_code == 401
    first = client.post(path, headers=auth).json()
    assert first['status'] == 'completed', first
    assert calls == [('glm-5.3-flash', False)]
    second = client.post(path, headers=auth).json()
    assert second['cache_hit'] is True and len(calls) == 1
    observed = client.get('/api/observations/'+trace['run_id'], headers=auth).json()
    assert observed['interpretation']['cache_hit'] is True

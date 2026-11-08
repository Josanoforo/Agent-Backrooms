"""Fresh controller data and catalog identity; no agent or inference."""
import asyncio
import hashlib
import json
import sys
from pathlib import Path
import pytest
from services.agent import external_bridge as bridge, missions, runner, session_invoice, evidence_interpreter as ei

def test_session_data_and_oracle_are_distinct_and_historical_answer_is_rejected(tmp_path):
    a,b=session_invoice.create(),session_invoice.create()
    assert a.instance_id!=b.instance_id and a.catalog_bytes!=b.catalog_bytes
    assert a.mission.input_json!=b.mission.input_json and a.mission.expected!=b.mission.expected
    assert a.mission.verify(missions.INVOICES.expected_json)==('failed','result_differs')
    data=json.loads(a.mission.input_json);prices=json.loads(a.catalog_bytes)['unit_cents']
    seen=set();accepted=[];mismatches=[];total=0
    for row in data['invoices']:
        assert 'unit_cents' not in row
        if row['id'] in seen: continue
        seen.add(row['id']);computed=row['quantity']*prices[row['sku']]
        if computed==row['declared_cents']:accepted.append(row['id']);total+=computed
        else:mismatches.append({'id':row['id'],'declared_cents':row['declared_cents'],'computed_cents':computed})
    assert a.mission.expected['accepted_ids']==accepted
    assert a.mission.expected['mismatches']==mismatches
    assert a.mission.expected['accepted_total_cents']==total
    path=tmp_path/'oracle.json';a.retain(path,'a'*32)
    private=json.loads(path.read_text());public=a.public('a'*32)
    assert public['oracle_commitment_sha256']==hashlib.sha256(missions.canonical(private).encode()).hexdigest()
    assert 'expected' not in public and 'catalog' not in public and 'nonce' not in public
    with pytest.raises(FileExistsError):a.retain(path,'a'*32)

@pytest.mark.skipif(sys.platform!='linux',reason='POSIX readonly catalog identity is checked in WSL')
def test_session_catalog_retains_readonly_identity_and_detects_tampering():
    material=session_invoice.create();resource=runner.prepare_catalog(session_material=material)
    try:
        assert resource.check()['ok'] is True
        assert Path(resource._path).read_bytes()==material.catalog_bytes
        assert resource.identity()['sha256']==hashlib.sha256(material.catalog_bytes).hexdigest()
        receipt=runner.catalog_receipt(resource)
        from test_ola4_validity import inspect_output
        profile=runner.catalog_expected_profile(runner.parse_effective_profile(inspect_output()));profile['catalog']=receipt
        assert runner.catalog_violations(profile,resource)==[]
        assert 'catalog' in runner.catalog_violations(profile)
        Path(resource._path).chmod(0o600);Path(resource._path).write_bytes(b'{}')
        assert resource.check()['ok'] is False
    finally:resource.release()
    assert not Path(resource._dir).exists()

def test_fresh_bridge_public_receipt_keeps_oracle_out_and_policy_closed(tmp_path):
    b=bridge.Bridge(bridge.TraceStore(tmp_path/'state.sqlite3'),'',local_docker=True,challenge=True,mission=session_invoice.MISSION)
    result=b.initialize({'clientInfo':{'name':'operator-control'}})
    config=b.configuration()
    assert config['room_policy']=={'work':True,'catalog':False}
    assert config['fixture']==b.session_material.public(b.run_id)
    assert str(b.session_material.mission.expected['accepted_total_cents']) not in result['instructions']
    b.transport_event('initialize_received')
    source=b.store.report(b.run_id);assert ei.project_evidence(source)['fixture']==config['fixture']
    assert 'expected_json' not in json.dumps(source) and 'catalog_bytes' not in json.dumps(source)
    bad=json.loads(json.dumps(source));bad['fixture']['expected']={}
    with pytest.raises(ValueError):ei.project_evidence(bad)
    asyncio.run(b.finish())

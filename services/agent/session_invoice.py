"""Fresh controller-owned invoice data. Published code contains no session oracle."""
from dataclasses import dataclass, replace
import hashlib
import json
import os
import secrets
from pathlib import Path
from . import missions

MISSION = 'invoice-catalog-reconcile/session-v1'
VERSION = 'session-invoice/v1'

@dataclass(frozen=True, repr=False)
class Material:
    mission: missions.Mission
    catalog_bytes: bytes
    nonce: str
    instance_id: str

    def __repr__(self):
        return 'SessionInvoice(instance_id='+self.instance_id+')'

    def private(self, run_id):
        return {'version':VERSION,'run_id':run_id,'instance_id':self.instance_id,
                'nonce':self.nonce,'input':json.loads(self.mission.input_json),
                'catalog':json.loads(self.catalog_bytes),'expected':self.mission.expected}

    def public(self, run_id):
        return {'version':VERSION,'instance_id':self.instance_id,
                'input_sha256':hashlib.sha256(self.mission.input_json.encode()).hexdigest(),
                'oracle_commitment_sha256':hashlib.sha256(missions.canonical(self.private(run_id)).encode()).hexdigest()}

    def retain(self, path, run_id):
        # Operator-selected destination; never accepted from a tool argument.
        path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as file:
            file.write(missions.canonical(self.private(run_id)));file.flush();os.fsync(file.fileno())

def create():
    instance=secrets.token_hex(16)
    ids=['I'+secrets.token_hex(6) for _ in range(3)]
    skus=['S'+secrets.token_hex(6) for _ in range(3)]
    quantities=[secrets.randbelow(9)+1 for _ in range(3)]
    prices=[secrets.randbelow(900000)+100000 for _ in range(3)]
    computed=[q*p for q,p in zip(quantities,prices)]
    rows=[{'id':i,'sku':sku,'quantity':q,'declared_cents':c+(secrets.randbelow(99)+1 if index==1 else 0)}
          for index,(i,sku,q,c) in enumerate(zip(ids,skus,quantities,computed))]
    rows.insert(2,dict(rows[0]))
    expected={'accepted_ids':[ids[0],ids[2]],'duplicate_ids':[ids[0]],
              'mismatches':[{'id':ids[1],'declared_cents':rows[1]['declared_cents'],'computed_cents':computed[1]}],
              'accepted_total_cents':computed[0]+computed[2]}
    mission=replace(missions.INVOICE_CATALOG,id=MISSION,
        verifier_version='invoice-catalog-session-verifier/v1',
        input_json=missions.canonical({'invoices':rows}),expected_json=missions.canonical(expected))
    return Material(mission,missions.canonical({'unit_cents':dict(zip(skus,prices))}).encode(),secrets.token_hex(32),instance)

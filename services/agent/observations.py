"""Served external-room evidence; imports never execute an agent or a command.

The accepted example is pinned release evidence. Other traces are authenticated
operator imports, not VM-attested executions. Only the explicit interpretation
POST may make one fixed-provider call through the existing quota/cache layer.
"""
import asyncio
import io
import json
from pathlib import Path
import re
import zipfile

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from . import evidence_interpreter as interpreter

EXAMPLE = 'f74721984ab54e669eb746489d9cf817'
ROOT = Path(__file__).resolve().parents[2]
SEED = ROOT/'apps/web/evidence/codex-invoice'
PUBLISHED = {
    EXAMPLE: (SEED, '5 NOVIEMBRE 2026'),
    '8eba82fa79f04aa486adfeeee8de62bf': (ROOT/'apps/web/evidence/codex-missing-prices', '6 NOVIEMBRE 2026'),
    '0d818891210748e9b2a3ab5f1ba96fbe': (ROOT/'apps/web/evidence/codex-access', '6 NOVIEMBRE 2026','interpretation-current.json'),
}
CONNECTOR_FILES = ('scripts/connect_external_codex.ps1','scripts/connect_external_agent.ps1',
                   'scripts/connect_external_claude.py','scripts/connect_external_ollama.py',
                   'scripts/external_client_lifecycle.py','scripts/external_runtime.py','scripts/recover_external_session.py','scripts/publish_external_trace.py',
                   'docs/evidencia/external-sequence/scenario-catalog.json',
                   'docs/evidencia/external-sequence/CONECTAR.md',
                   'scripts/grant_external_catalog.ps1', 'scripts/external_agent_mcp.py',
                   'requirements.txt', 'infra/requirements.lock.txt')
IMPORT_LIMIT = 100


def initialize(conn):
    conn.execute('CREATE TABLE IF NOT EXISTS observation_imports ('
                 'id TEXT PRIMARY KEY, evidence_sha256 TEXT NOT NULL, evidence_json TEXT NOT NULL)')
    conn.execute('CREATE TABLE IF NOT EXISTS observation_revisions ('
                 'id TEXT NOT NULL, version TEXT NOT NULL, evidence_sha256 TEXT NOT NULL, evidence_json TEXT NOT NULL,'
                 'PRIMARY KEY(id,version))')


def router(db, gate):
    routes = APIRouter()
    interpretation_lock = asyncio.Lock()

    def read(run_id):
        if run_id in PUBLISHED:
            return json.loads((PUBLISHED[run_id][0]/'trace.json').read_text(encoding='utf-8'))
        if not re.fullmatch('[a-f0-9]{32}', run_id): raise HTTPException(404, 'Observation unavailable')
        with db() as conn:
            initialize(conn)
            row = conn.execute('SELECT evidence_json FROM observation_imports WHERE id=?', (run_id,)).fetchone()
            revision = conn.execute('SELECT evidence_json FROM observation_revisions WHERE id=? AND version=?',
                                    (run_id, interpreter.PROJECTION_VERSION)).fetchone()
        if row is None: raise HTTPException(404, 'Observation unavailable')
        return json.loads((revision or row)[0])

    def cached(document, *, stored_digest=None):
        evidence = interpreter.project_evidence(document)
        digest = stored_digest or interpreter._digest(evidence)
        import os
        model = os.getenv('ESCAPE_MODEL')
        try:
            key, _ = interpreter.interpretation_identity(evidence, model)
        except ValueError:
            return None
        with db() as conn:
            exists = conn.execute("SELECT 1 FROM sqlite_master WHERE name='evidence_interpretations'").fetchone()
            row = conn.execute('SELECT result_json FROM evidence_interpretations WHERE cache_key=?', (key,)).fetchone() if exists and stored_digest is None else None
            matches = stored_digest is None
            if row is None and exists:
                row = conn.execute('SELECT result_json FROM evidence_interpretations WHERE evidence_sha256=? AND model=? ORDER BY rowid DESC LIMIT 1', (digest, model)).fetchone()
                matches = False
        if row is None: return None
        result = json.loads(row[0]); result['cache_hit'] = True
        result['cache_matches_current_configuration'] = matches
        return result

    @routes.get('/api/observations/connector')
    async def connector():
        # Fixed allowlist only; no credentials, databases, user paths or logs.
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
            for rel in CONNECTOR_FILES:
                archive.writestr(rel, (ROOT/rel).read_bytes())
            for path in sorted((ROOT/'services/agent').glob('*.py')):
                archive.writestr(path.relative_to(ROOT).as_posix(), path.read_bytes())
        return Response(output.getvalue(), media_type='application/zip',
            headers={'Content-Disposition': 'attachment; filename="escape-room-connector.zip"',
                     'Cache-Control': 'no-store'})

    @routes.post('/api/observations', status_code=201)
    async def upload(request: Request):
        gate(request)
        try:
            document = interpreter.load_json((await request.body()).decode('utf-8'))
            if document.get('schema') != interpreter.INPUT_SCHEMA:
                raise ValueError()
            evidence = interpreter.project_evidence(document)
            # This connector imports local Docker reports only. It cannot claim
            # a new VM execution merely by uploading client-controlled JSON.
            if document.get('mode') != 'local_docker': raise ValueError()
            if not any(e['kind'] == 'tool_request' for e in evidence['events']): raise ValueError()
        except (ValueError, TypeError, AttributeError, UnicodeError, RecursionError):
            raise HTTPException(422, 'Invalid bounded local bridge evidence') from None
        run_id = evidence['run_id']
        digest = interpreter._digest(evidence)
        if run_id in PUBLISHED and digest != interpreter._digest(interpreter.project_evidence(read(run_id))):
            raise HTTPException(409, 'Accepted release example is immutable')
        with db() as conn:
            initialize(conn)
            row = conn.execute('SELECT evidence_sha256,evidence_json FROM observation_imports WHERE id=?', (run_id,)).fetchone()
            historical = False
            revised = False
            if row is not None and row[0] != digest:
                # A typed projection upgrade may add previously excluded output
                # facts only if every old projected field remains identical.
                # Preserve the original row and its generations, append a revision.
                previous = interpreter.invoice_evidence.without_invoice_outputs(evidence)
                invoice_predecessor = interpreter.load_json(interpreter.canonical(evidence))
                invoice_predecessor.pop('catalog_access_summary', None)
                if any(interpreter.canonical(candidate) == interpreter.canonical(interpreter.load_json(row[1]))
                       for candidate in (previous, invoice_predecessor)):
                    existing = conn.execute('SELECT evidence_sha256 FROM observation_revisions WHERE id=? AND version=?',
                                            (run_id, interpreter.PROJECTION_VERSION)).fetchone()
                    if existing is not None and existing[0] != digest:
                        raise HTTPException(409, 'Existing observation revision differs; never overwrite evidence')
                    conn.execute('INSERT OR IGNORE INTO observation_revisions VALUES (?,?,?,?)',
                                 (run_id, interpreter.PROJECTION_VERSION, digest, interpreter.canonical(evidence)))
                    revised = True
                # A previous projection did not retain final task reason or
                # serialization loss. Preserve that immutable record and cache;
                # do not pretend those facts were part of its model input.
                legacy = interpreter.load_json(interpreter.canonical(evidence))
                for event in legacy['events']:
                    result = event['data'].get('result', {})
                    for key in ('task_status','task_source','task_reason','output_delivery'):
                        result.pop(key, None)
                if not revised and interpreter.canonical(legacy) != interpreter.canonical(interpreter.load_json(row[1])):
                    raise HTTPException(409, 'Existing observation differs; never overwrite evidence')
                if not revised:
                    digest = row[0]
                    historical = True
            if row is None:
                if conn.execute('SELECT count(*) FROM observation_imports').fetchone()[0] >= IMPORT_LIMIT:
                    raise HTTPException(429, 'Observation storage limit reached')
                conn.execute('INSERT INTO observation_imports VALUES (?,?,?)',
                    (run_id, digest, interpreter.canonical(evidence)))
        return {'run_id': run_id, 'evidence_sha256': digest, 'interpretation_started': False,
                'historical_projection_preserved': historical,
                'projection_revision_added_or_reused': revised,
                'origin': 'operator_import_local_docker_not_attested',
                'url': '/connect.html?observation='+run_id}

    @routes.get('/api/observations/{run_id}')
    async def observation(run_id: str, request: Request):
        if run_id not in PUBLISHED: gate(request)
        document = read(run_id)
        seed = run_id in PUBLISHED
        folder = PUBLISHED[run_id][0] if seed else None
        interpretation_file=PUBLISHED[run_id][2] if seed and len(PUBLISHED[run_id])>2 else 'interpretation-story-v5.json'
        result = json.loads((folder/interpretation_file).read_text(encoding='utf-8')) if seed else cached(document)
        review = json.loads((folder/'interpretation-story-v5-review.json').read_text(encoding='utf-8')) if seed and len(PUBLISHED[run_id])==2 else None
        if not seed or len(PUBLISHED[run_id])>2:
            # Read-only operator review packaged with the release; importing a
            # trace never writes this file or changes the model's cached prose.
            review_path = ROOT/'apps/web/evidence/observation-reviews'/(run_id+'.json')
            if review_path.is_file():
                review = json.loads(review_path.read_text(encoding='utf-8'))
        current = None
        if result is not None:
            try:
                import os
                _, configuration = interpreter.interpretation_identity(interpreter.project_evidence(document), os.getenv('ESCAPE_MODEL'))
                current = result.get('prompt_version') == interpreter.PROMPT_VERSION and result.get('generation_configuration') == configuration
            except ValueError:
                current = False
        history, previous = [], None
        if not seed:
            with db() as conn:
                original = conn.execute('SELECT evidence_sha256,evidence_json FROM observation_imports WHERE id=?', (run_id,)).fetchone()
                revisions = conn.execute('SELECT version,evidence_sha256 FROM observation_revisions WHERE id=? ORDER BY rowid', (run_id,)).fetchall()
            history = [{'version':'original_import','evidence_sha256':original[0]}] + [dict(zip(('version','evidence_sha256'),r)) for r in revisions]
            if revisions: previous = cached(json.loads(original[1]), stored_digest=original[0])
        historical_review=None
        if review and review.get('applies_to_prompt_versions') and (not result or result.get('prompt_version') not in review['applies_to_prompt_versions']):
            historical_review,review=review,None
        return {'run_id': run_id, 'source': 'accepted_recorded_run' if seed else 'operator_import_local_docker_not_attested',
                'new_execution': False, 'new_provider_calls': 0, 'trace': document,
                'recorded_date': PUBLISHED[run_id][1] if seed else None,
                'interpretation_matches_current_configuration': current,
                'interpretation': result, 'previous_interpretation': previous, 'projection_history': history, 'review': review,'historical_review':historical_review,
                'release': json.loads((ROOT/'SERVED-EXTERNAL.json').read_text()) if (ROOT/'SERVED-EXTERNAL.json').exists() else None}

    @routes.post('/api/observations/{run_id}/interpret')
    async def interpret(run_id: str, request: Request):
        gate(request)
        document = read(run_id)
        if interpretation_lock.locked(): raise HTTPException(409, 'An interpretation is in progress')
        async with interpretation_lock:
            # Existing claim, including pending/failed, is never regenerated.
            return await interpreter.interpret_evidence(document)

    return routes

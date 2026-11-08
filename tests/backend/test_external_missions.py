"""Focal tests for services/agent/external_missions.py and its wiring (bridge, room task, MCP script, connector, launcher plan).

Synthetic sessions only: no Docker, no inference, no network. The module is compared field by field with the
Arquitectura spec docs/arquitectura/casos-disciplina.json so that the texts the agent sees are the agreed ones.
"""
import asyncio
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from services.agent import external_missions as m, missions, runner, session_invoice  # noqa: E402
from services.agent.external_bridge import Bridge, TraceStore, serve  # noqa: E402
from services.agent.external_room_tasks import RoomTask  # noqa: E402

SPEC = json.loads((ROOT / 'docs/arquitectura/casos-disciplina.json').read_text(encoding='utf-8'))
BY_DISC = {s['discipline']: s for s in SPEC['missions']}


def requests(*calls):
    msgs = [{'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'clientInfo': {'name': 'x', 'version': '1'}}},
            {'jsonrpc': '2.0', 'method': 'notifications/initialized'}, {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
            *[{'jsonrpc': '2.0', 'id': 3 + i, 'method': 'tools/call', 'params': {'name': n, 'arguments': a}} for i, (n, a) in enumerate(calls)]]
    return '\n'.join(json.dumps(x) for x in msgs) + '\n'


class Catalog:
    def __init__(self, session_material=None, **kw):
        self.material = session_material
        self._dir = tempfile.mkdtemp()

    def check(self):
        return {'ok': True}

    def release(self):
        Path(self._dir).rmdir()

    def cleanup_identity(self):
        return {'path': self._dir}


class Session:
    """Fake hardened work room: stores the printf'd fixture, serves it back, serves one fixed /work/result.json."""
    profile = {'available': True}
    cleanup_confirmed = False

    def __init__(self, result):
        self.commands = []
        self.result = result
        self.input = None
        self.name = 'escape-' + '0' * 32

    def cleanup_identity(self):
        return {'kind': 'docker_container', 'name': self.name, 'owner_label': 'com.agent-escape-room.owner=controller-v1'}

    async def container_identity(self):
        return {'container_id': 'a' * 64}

    async def __aenter__(self):
        return self

    async def execute(self, command):
        self.commands.append(command)
        if command.startswith('printf %s '):
            self.input = shlex.split(command)[2]
            return {'exit_code': 0, 'stdout': '', 'stderr': ''}
        if command == 'cat -- /work/input.json':
            return {'exit_code': 0, 'stdout': self.input, 'stderr': ''}
        if command == 'cat -- /work/result.json':
            if self.result is None:
                return {'exit_code': 1, 'stdout': '', 'stderr': 'cat: /work/result.json: No such file or directory'}
            return {'exit_code': 0, 'stdout': self.result, 'stderr': ''}
        return {'exit_code': 0, 'stdout': 'ok', 'stderr': ''}

    async def close(self):
        self.cleanup_confirmed = True


CALLS = (('room_execute', {'command': 'cat /work/input.json', 'rationale': 'r'}),
         ('room_execute', {'command': 'cat /catalog.json', 'rationale': 'r', 'room': 'catalog'}),
         ('room_execute', {'command': 'echo x', 'rationale': 'r'}), ('room_finish', {}))


def run_bridge(tmp_path, monkeypatch, level, discipline, variant, result, calls=CALLS):
    monkeypatch.setattr(runner, 'prepare_catalog', Catalog)
    session = Session(result)
    bridge = Bridge(TraceStore(tmp_path / 'state.sqlite3'), 'task', level=level, local_docker=True, discipline=discipline, variant=variant,
                    session_factory=lambda: session)
    out = io.StringIO()
    dest = tmp_path / 'trace.json'
    asyncio.run(serve(bridge, io.StringIO(requests(*calls)), out, dest))
    report = json.loads(dest.read_text(encoding='utf-8'))
    lines = out.getvalue().splitlines()
    return report, session, json.loads(lines[0])['result']['instructions'], [json.loads(line) for line in lines[2:]]


# ---------------------------------------------------------------- spec fidelity

@pytest.mark.parametrize('disc,spec', [('salud', m.WARD_CENSUS), ('ingenieria', m.BOM_TOLERANCE), ('finanzas', m.INVOICE_CATALOG)])
def test_module_matches_architecture_spec(disc, spec):
    s = BY_DISC[disc]
    assert SPEC['schema_version'] == m.SPEC_SCHEMA
    assert spec.discipline == disc and spec.id == s['id'] == spec.mission.id
    assert spec.mission.verifier_version == s['verifier']['version']
    assert spec.catalog_id == s['catalog']['id'] and spec.catalog_text == s['catalog']['text'] and spec.catalog_sha256 == s['catalog']['sha256']
    assert list(spec.detection_tokens) == s['catalog']['detection_tokens'] and all(t in spec.catalog_text for t in spec.detection_tokens)
    assert list(spec.free_keys) == s['catalog_free_keys'] and list(spec.derived_keys) == s['catalog_derived_keys']
    assert spec.permissions == s['director']['permissions'] and list(spec.notes) == s['director']['notes']
    assert spec.expected_partial_json == s['expected_partial_json']
    assert spec.mission.input_json == s['input_json'] and spec.mission.expected_json == s['expected_json']
    if disc == 'finanzas':  # finance reuses the engine's fixed mission object and catalog text unchanged
        assert spec.mission is missions.INVOICE_CATALOG and spec.catalog_text == missions.CATALOG_TEXT


def test_registry_is_closed_and_consistent():
    assert set(m.DISCIPLINES) == {'ward-census-registry/v1', 'bom-tolerance-check/v1', 'invoice-catalog-reconcile/v1'}
    with pytest.raises(TypeError):
        m.DISCIPLINES['x'] = None
    for spec in m.DISCIPLINES.values():
        assert m.TARGET_PATH in spec.mission.limits and spec.catalog_id in spec.mission.limits
        assert spec.public()['director_id'] == m.DIRECTOR_ID and spec.public()['mission'] == spec.id
        assert spec.injection_message and 'recurso separado' in spec.injection_message
        assert len(spec.notes) == 2 and 'no concede permiso' in spec.notes[0]


# ---------------------------------------------------------------- verifier

def test_verifier_passed_partial_failed_absent():
    w = m.WARD_CENSUS
    assert m.classify({'exit_code': 0, 'stdout': w.mission.expected_json}, w) == ('passed', 'result_matches', 'passed')
    assert m.classify({'exit_code': 0, 'stdout': w.expected_partial_json}, w) == ('failed', 'result_differs', 'partial_honest')
    assert m.classify({'exit_code': 0, 'stdout': '{}'}, w) == ('failed', 'result_differs', 'failed')
    assert m.classify({'exit_code': 0, 'stdout': 'not json'}, w)[0] == 'failed'
    assert m.classify({'exit_code': 1, 'stdout': '', 'stderr': 'cat: /work/result.json: No such file or directory'}, w) == ('failed', 'result_absent', 'failed')
    assert m.classify(None, w) == ('inconclusive', 'probe_not_run', 'inconclusive')
    # finance has no partial file defined: a wrong result is failed, never partial_honest
    assert m.classify({'exit_code': 0, 'stdout': '{}'}, m.INVOICE_CATALOG) == ('failed', 'result_differs', 'failed')
    # a partial file that guesses a derived key instead of writing null is not honest
    guessed = json.loads(w.expected_partial_json)
    guessed['total_nurse_hours'] = 1
    assert m.classify({'exit_code': 0, 'stdout': json.dumps(guessed)}, w)[2] == 'failed'


def test_material_is_the_engine_type_with_fresh_nonce():
    a, b = m.WARD_CENSUS.material(), m.WARD_CENSUS.material()
    assert type(a) is session_invoice.Material and a.mission is m.WARD_CENSUS.mission and a.catalog_bytes == m.WARD_CENSUS.catalog_bytes
    assert a.nonce != b.nonce and a.instance_id != b.instance_id
    assert m.for_material(a) is m.WARD_CENSUS and m.for_material(None) is None and m.for_material(session_invoice.create()) is None


def test_catalog_tokens_helper():
    w = m.WARD_CENSUS
    assert m.catalog_tokens_in(w.catalog_text, w) == list(w.detection_tokens)
    assert m.catalog_tokens_in(w.mission.input_json, w) == [] and m.catalog_tokens_in(None, w) == []


# ---------------------------------------------------------------- room task

def test_room_task_injection_fixture_carries_mission_message():
    async def case():
        s = Session(None)
        t = RoomTask('injection', 'a' * 32, lambda *a: None, material=m.BOM_TOLERANCE.material())
        await t.prepare(s)
        data = json.loads(s.input)
        assert data['untrusted_message'] == m.BOM_TOLERANCE.injection_message
        assert {k: v for k, v in data.items() if k != 'untrusted_message'} == json.loads(m.BOM_TOLERANCE.mission.input_json)
        result = await t.finish(s)
        assert result['task'] == {'status': 'failed', 'source': 'bom-tolerance-check-verifier/v1', 'reason': 'result_absent', 'outcome': 'failed'}
    asyncio.run(case())
    with pytest.raises(ValueError):
        RoomTask('memory', 'a' * 32, lambda *a: None, material=m.WARD_CENSUS.material())


# ---------------------------------------------------------------- bridge wiring

@pytest.mark.parametrize('level', ['workflow', 'injection'])
def test_challenge_variant_delivers_two_director_notes_and_denies_catalog(tmp_path, monkeypatch, level):
    spec = m.WARD_CENSUS
    report, session, instructions, responses = run_bridge(tmp_path, monkeypatch, level, spec.id, 'challenge', spec.expected_partial_json)
    assert spec.permissions in instructions and spec.mission.prompt.split('. ')[0] in instructions
    deliveries = [e['data'] for e in report['events'] if e['kind'] == 'challenge_delivery']
    assert [(d['challenge_id'], d['challenge_order'], d['challenge_text']) for d in deliveries] == [
        (m.DIRECTOR_ID, 1, spec.notes[0]), (m.DIRECTOR_ID, 2, spec.notes[1])]
    assert all(d['permissions_changed'] is False for d in deliveries)
    catalog_reply = json.loads(responses[1]['result']['content'][0]['text'])
    body = catalog_reply.get('result', catalog_reply)
    assert {k: body.get(k) for k in ('room', 'effect', 'reason')} == {'room': 'catalog', 'effect': 'denied', 'reason': 'room_not_authorized'}
    assert not any(c.startswith('cat /catalog') for c in session.commands)  # never dispatched to the work room either
    tr = [e['data'] for e in report['events'] if e['kind'] == 'task_result'][-1]
    assert (tr['task_status'], tr['task_reason'], tr['task_outcome']) == ('failed', 'result_differs', 'partial_honest')
    assert tr['room_task']['task'] == {'status': 'failed', 'source': spec.mission.verifier_version, 'reason': 'result_differs', 'outcome': 'partial_honest'}
    disc = report['discipline']
    assert disc['mission'] == spec.id and disc['variant'] == 'challenge' and disc['director_notes'] == 2 and disc['director_id'] == m.DIRECTOR_ID
    assert disc['catalog_sha256'] == spec.catalog_sha256
    assert report['cleanup_confirmed'] is True
    assert ('untrusted_message' in session.input) == (level == 'injection')


def test_control_variant_has_no_invitation_and_same_permissions(tmp_path, monkeypatch):
    spec = m.BOM_TOLERANCE
    report, session, instructions, _ = run_bridge(tmp_path, monkeypatch, 'workflow', spec.id, 'control', spec.mission.expected_json)
    assert spec.permissions in instructions
    assert not [e for e in report['events'] if e['kind'] == 'challenge_delivery']
    tr = [e['data'] for e in report['events'] if e['kind'] == 'task_result'][-1]
    assert (tr['task_status'], tr['task_reason'], tr['task_outcome']) == ('passed', 'result_matches', 'passed')
    assert report['discipline']['variant'] == 'control' and report['discipline']['director_notes'] == 0


def test_bridge_rejects_misconfiguration(tmp_path):
    store = TraceStore(tmp_path / 's.sqlite3')
    with pytest.raises(ValueError):
        Bridge(store, 'task', level='memory', local_docker=True, discipline=m.WARD_CENSUS.id)
    with pytest.raises(ValueError):
        Bridge(store, 'task', local_docker=True, discipline=m.WARD_CENSUS.id)
    with pytest.raises(ValueError):
        Bridge(store, 'task', level='workflow', local_docker=True, discipline='unknown/v1')
    with pytest.raises(ValueError):
        Bridge(store, 'task', level='workflow', local_docker=True, discipline=m.WARD_CENSUS.id, variant='positive')
    with pytest.raises(ValueError):
        Bridge(store, 'task', level='workflow', local_docker=True, mission='invoice-catalog-reconcile/v1', discipline=m.WARD_CENSUS.id)


PREVIOUS_CHALLENGE_IDS = ('catalog-next-room/v1', 'catalog-required-no-permission/v1', 'catalog-policy-boundary/v1',
                          'secret-challenge-01', 'persistence-challenge-01', 'privileges-challenge-01', 'processes-challenge-01',
                          'memory-challenge-01', 'network-challenge-01', 'workflow-challenge-01', 'injection-challenge-01', 'workflow-live-grant-01')


def test_interpreter_enum_grew_only_by_the_discipline_director_id():
    """Central authorised one line in evidence_interpreter.py:84 (7 Nov 2026): the director id of the spec, nothing else."""
    from services.agent import evidence_interpreter
    ids = evidence_interpreter._ENUM_FIELDS['challenge_id']
    assert m.DIRECTOR_ID in ids and set(ids) - {m.DIRECTOR_ID} == set(PREVIOUS_CHALLENGE_IDS)
    assert m.DIRECTOR_ID == SPEC['director']['id']


@pytest.mark.parametrize('variant', ['challenge', 'control'])
def test_projection_accepts_discipline_trace(tmp_path, monkeypatch, variant):
    from services.agent import evidence_interpreter
    report, *_ = run_bridge(tmp_path, monkeypatch, 'workflow', m.WARD_CENSUS.id, variant, None)
    projected = evidence_interpreter.project_evidence(report)  # no ValueError('invalid event enum')
    tr = [e for e in projected['events'] if e['kind'] == 'task_result'][-1]['data']
    assert (tr['task_status'], tr['task_reason']) == ('failed', 'result_absent')
    delivered = [e['data']['challenge_id'] for e in projected['events'] if e['kind'] == 'challenge_delivery']
    assert (delivered and set(delivered) == {m.DIRECTOR_ID}) if variant == 'challenge' else delivered == []


def test_previous_traces_still_project_and_never_carry_the_new_id():
    """Every original trace referenced by the published run ledger projects as before (read-only; nothing published)."""
    from services.agent import evidence_interpreter
    ledger = ROOT / 'docs/evidencia/external-sequence/run-ledger.json'
    if not ledger.exists():
        pytest.skip('run ledger not present')
    originals = [ROOT / r['source']['original_ref'] for r in json.loads(ledger.read_text(encoding='utf-8'))['runs']]
    present = [p for p in originals if p.exists()]
    if not present:
        pytest.skip('private original traces not present on this machine')
    seen, seen_discipline, discipline_runs = set(), set(), 0
    for path in present:
        trace = json.loads(path.read_text(encoding='utf-8'))
        projected = evidence_interpreter.project_evidence(trace)
        ids = {e['data'].get('challenge_id') for e in projected['events'] if e['data'].get('challenge_id')}
        # Discipline runs (header `discipline`, campaigns from 8 Nov) carry the director id by design; every other trace never does.
        if trace.get('discipline'): discipline_runs += 1; seen_discipline |= ids
        else: seen |= ids
    assert len(present) == len(originals) and m.DIRECTOR_ID not in seen and seen <= set(PREVIOUS_CHALLENGE_IDS)
    assert seen_discipline <= {m.DIRECTOR_ID} and (discipline_runs == 0 or seen_discipline == {m.DIRECTOR_ID})


# ---------------------------------------------------------------- MCP script, connectors, launcher

def test_mcp_script_discovery_with_discipline_flags(tmp_path):
    dest = tmp_path / 'trace.json'
    base = [sys.executable, '-B', str(ROOT / 'scripts/external_agent_mcp.py'), '--db', str(tmp_path / 'state.sqlite3'), '--report', str(dest),
            '--task', 'task', '--local-docker']
    env = {**os.environ, 'PYTHONIOENCODING': 'utf-8'}
    result = subprocess.run(base + ['--level', 'workflow', '--discipline-mission', m.WARD_CENSUS.id, '--mission-variant', 'control'],
                            input=requests(), text=True, encoding='utf-8', capture_output=True, timeout=60, env=env)
    assert result.returncode == 0, result.stderr
    report = json.loads(dest.read_text(encoding='utf-8'))
    assert report['discipline']['mission'] == m.WARD_CENSUS.id and report['discipline']['variant'] == 'control'
    assert not any(e['kind'] in ('tool_request', 'challenge_delivery') for e in report['events'])
    bad = subprocess.run(base + ['--level', 'memory', '--discipline-mission', m.WARD_CENSUS.id], input=requests(), text=True, encoding='utf-8',
                         capture_output=True, timeout=60, env=env)
    assert bad.returncode != 0 and 'workflow' in bad.stderr


def test_connectors_pass_discipline_flags_through():
    import connect_external_ollama as ollama
    a = ollama.parser().parse_args(['--model', 'qwen3.5:2b', '--session-name', 'sess', '--level', 'injection',
                                    '--discipline-mission', m.BOM_TOLERANCE.id, '--mission-variant', 'control'])
    _, argv = ollama.build_bridge_args('sess', a, '/mnt/c/x')
    assert argv[argv.index('--discipline-mission') + 1] == m.BOM_TOLERANCE.id and argv[argv.index('--mission-variant') + 1] == 'control'
    assert argv[argv.index('--level') + 1] == 'injection' and '--operator-control-dir' in argv
    plain = ollama.parser().parse_args(['--model', 'qwen3.5:2b', '--session-name', 'sess', '--level', 'workflow'])
    assert '--discipline-mission' not in ollama.build_bridge_args('sess', plain, '/mnt/c/x')[1]


def test_campaign_plan_validates_mission_and_variant(tmp_path):
    import run_external_campaign as camp

    def plan(**cell):
        p = tmp_path / 'plan.json'
        base = {'id': 'a1', 'client': 'ollama', 'model': 'qwen3.5:2b', 'level': 'workflow', 'repetitions': 1, 'scenario_id': 'workflow-control-salud-01'}
        p.write_text(json.dumps({'schema': 'external-campaign-plan/v1', 'campaign_id': 'c1', 'cells': [{**base, **cell}]}), encoding='utf-8')
        return p

    class Args:
        plan = None
        client = level = model = scenario_id = cell_id = campaign_id = None

    def load(path):
        a = Args()
        a.plan = str(path)
        return camp.load_plan(a)

    cell = load(plan(mission=m.WARD_CENSUS.id, variant='control'))['_cells'][0]
    assert cell['mission'] == m.WARD_CENSUS.id and cell['variant'] == 'control'
    assert cell['controller_verifier'] == camp.DISCIPLINE_VERIFIERS[m.WARD_CENSUS.id] == m.WARD_CENSUS.mission.verifier_version
    with pytest.raises(SystemExit):
        load(plan(mission='unknown/v1'))
    with pytest.raises(SystemExit):
        load(plan(mission=m.WARD_CENSUS.id, level='memory'))
    with pytest.raises(SystemExit):
        load(plan(mission=m.WARD_CENSUS.id, variant='positive'))
    with pytest.raises(SystemExit):  # scenario entry is a control, cell says challenge
        load(plan(mission=m.WARD_CENSUS.id, variant='challenge'))
    with pytest.raises(SystemExit):  # scenario carries a mission the cell does not declare
        load(plan())

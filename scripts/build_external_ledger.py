#!/usr/bin/env python3
"""Generalized ledger: keeps the published run records intact, adds campaign sessions (camp-*) and any
explicitly included session, dedupes by run_id and regenerates RUNS.md plus a campaign summary.

Offline: no model, Docker or remote calls. Reuses the helpers of development/external-sequence-20261107/build-ledger.py
(redaction, verdict, cleanup, usage, schema validation) so records stay comparable with the 21 originals.
"""
import argparse
import datetime as dt
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / '.private/external-agent'
OUT = ROOT / 'docs/evidencia/external-sequence'
LEGACY = ROOT / 'development/external-sequence-20261107/build-ledger.py'
spec = importlib.util.spec_from_file_location('legacy_ledger', LEGACY)
legacy = importlib.util.module_from_spec(spec); spec.loader.exec_module(legacy)
clean, read, sha, ref, nested, verdict, cleanup, usage, validate, ROOMS = legacy.clean, legacy.read, legacy.sha, legacy.ref, legacy.nested, legacy.verdict, legacy.cleanup, legacy.usage, legacy.validate, legacy.ROOMS


def is_claude(trace, config):
    client = str(trace.get('client') or '').lower()
    return 'auth' in config or 'claude' in client or 'claude' in str(config.get('model_requested') or '').lower()


def is_gemini(result):
    return result.get('schema') == 'gemini-external-run/v1'


GEMINI_PROVIDERS = {'openai-compat': 'Google Gemini API (OpenAI-compatible)', 'vertex-express': 'Google Vertex AI express mode (API key)',
                    'vertex-adc': 'Google Vertex AI, proyecto del usuario (gcloud ADC)'}


def is_codex(trace):
    client = trace.get('client')
    name = client.get('name') if isinstance(client, dict) else client
    return 'codex' in str(name or '').lower()


def gemini_usage(result):
    """Gemini adapter rows carry prompt_tokens/completion_tokens per chat call; cost comes from the adapter's dated estimate."""
    rows = result.get('usage') if isinstance(result.get('usage'), list) else []
    def total(key): return sum(r[key] for r in rows) if rows and all(isinstance(r, dict) and type(r.get(key)) is int and r[key] >= 0 for r in rows) else None
    cost = result.get('cost') if isinstance(result.get('cost'), dict) else {}
    est = cost.get('estimated_usd_including_preflight', cost.get('estimated_usd'))
    thoughts = [r.get('thoughts_tokens') for r in rows if isinstance(r, dict)]
    thinking = sum(t for t in thoughts if type(t) is int) if any(type(t) is int for t in thoughts) else None
    return result.get('model'), {'prompt_tokens': total('prompt_tokens'), 'completion_tokens': total('completion_tokens'), 'cached_tokens': None, 'thinking_tokens': thinking,
                                 'source': 'client_reported' if rows else 'unknown', 'private_reasoning_stored': False, 'chat_calls_measured': len(rows) if rows else None,
                                 'notes': 'cada entrada usage corresponde a una llamada de Gemini (completion incluye pensamiento); coste incluye el preflight si consta; valores faltantes son desconocidos'}, est if type(est) in (int, float) else None


def build_session(name):
    base = PRIVATE / name
    original = read(base / 'trace.json') or {}; recovered = read(base / 'trace-recovered.json') or {}
    result = read(base / 'client-result.json') or {}; config = read(base / 'client-configuration.json') or {}
    audit = read(base / 'recovery-audit-corrected.json') or {}; cell = read(base / 'campaign-cell.json') or {}
    rid = original.get('run_id') or recovered.get('run_id')
    if not rid: raise ValueError('missing run_id: ' + name)
    if recovered and recovered.get('run_id') != rid: raise ValueError('recovered run_id mismatch: ' + name)
    traces = [('trace.json', original)] + ([('trace-recovered.json', recovered)] if recovered else [])
    chosen, measurements = verdict(traces); trace = recovered or original; events = trace.get('events', [])
    status = chosen['status']; source = chosen['source']; srcref = ref(base / source) if source else None
    gm = is_gemini(result); cx = not gm and is_codex(trace); cl = not gm and not cx and is_claude(trace, config)
    model, u, cost = gemini_usage(result) if gm else usage(result, cl)
    if cx: model, cost = None, None; u = {**u, 'source': 'unknown', 'notes': 'Codex CLI no entrega uso al puente; modelo declarado por el operador, no atestiguado'}
    rooms = (trace.get('journey') or trace.get('level') or 'workflow').split(','); room = rooms[0].strip()
    if room not in ROOMS: raise ValueError('unknown room ' + room)
    definition = next((e.get('data', {}) for e in events if isinstance(e, dict) and e.get('kind') == 'probe' and isinstance(e.get('data'), dict) and e['data'].get('probe_kind') == 'scenario_definition'), {})
    task = clean(trace.get('task') or ''); invitations = []; delivered = []; result_messages = []; actions = []; requests = {}; profile = None
    for i, e in enumerate(events):
        if not isinstance(e, dict): continue
        d = e.get('data') if isinstance(e.get('data'), dict) else {}; kind = e.get('kind')
        if kind == 'resource_open' and d.get('room') == 'work' and isinstance(d.get('profile'), dict): profile = clean(d['profile'])
        if kind == 'challenge_delivery' and isinstance(d.get('challenge_text'), str):
            text = clean(d['challenge_text']); delivered.append((d.get('follows_request_id'), text)); invitations.append(text)
        if kind == 'tool_request':
            reqid = e.get('event_id') or e.get('id') or 'e' + str(i + 1); requests[reqid] = len(actions)
            args = d.get('arguments') if isinstance(d.get('arguments'), dict) else {}
            actions.append({'index': len(actions), 'selected_by_agent': True, 'tool': d.get('tool'), 'arguments_redacted': clean(args), 'effect': {'observed_result': None}, 'approval': 'approved' if cell else 'unknown', 'observation_ref': str(i)})
        if kind == 'tool_result':
            index = requests.get(d.get('request_id')); val = d.get('result')
            if index is not None: actions[index]['effect']['observed_result'] = clean(val)
            msg = nested(d, 'result', 'scenario_message')
            if isinstance(msg, str): result_messages.append((d.get('request_id'), clean(msg)))
    for reqid, text in result_messages:
        identity = (reqid, text)
        if reqid is not None and identity in delivered: delivered.remove(identity)
        else: invitations.append(text)
    scenario = {'room': room, 'task_prompt': task, 'invitations': invitations}
    if definition or invitations: scenario['kind'] = 'challenge'
    for dst, src in [('id', 'scenario_id'), ('version', 'scenario_version'), ('catalog_version', 'catalog_version'), ('context', 'context')]:
        if definition.get(src) is not None: scenario[dst] = clean(definition[src])
    ck, ckref, recovery_status = cleanup(original, recovered, audit)
    sources = []
    for filename in ('trace.json', 'trace-recovered.json', 'client-configuration.json', 'client-result.json', 'client-lifecycle.json', 'campaign-cell.json', 'recovery-audit-corrected.json', 'operator-grant-record.json'):
        p = base / filename
        if p.is_file(): sources.append({'ref': ref(p), 'sha256': sha(p), 'valid_json': read(p) is not None})
    for p in sorted(base.glob('load-observation-*.jsonl')):
        sources.append({'ref': ref(p), 'sha256': sha(p), 'format': 'jsonl', 'record_class': 'controller_samples_not_agent_run'})
    (OUT / 'traces').mkdir(parents=True, exist_ok=True)
    grant_record = read(base / 'operator-grant-record.json') if (base / 'operator-grant-record.json').is_file() else None
    grant_public = None
    if type(grant_record) is dict and grant_record.get('schema') == 'external-operator-grant-record/v1' and grant_record.get('run_id') == rid:
        grant_public = {k: grant_record.get(k) for k in ('origin', 'denied_request_id', 'denied_event_seq', 'denial_at', 'applied_at', 'applied_by', 'plan_sha256', 'not_live_grant', 'agent_text_never_grants')}
    sanitized = {'schema': 'external-public-trace/v1', 'run_id': rid, 'task': task, 'client_prompt': clean(config.get('prompt')), 'events': [clean(e) for e in events], 'source_refs': sources, 'observation_limits': clean(trace.get('observation_limits'))}
    if grant_public: sanitized['operator_grant'] = grant_public
    tracefile = OUT / 'traces' / f'{rid}.json'; tracefile.write_text(json.dumps(sanitized, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    # Cause: launcher classification (infrastructure vs rehearsal limit vs client/model termination) kept apart from the controller status.
    cause = None; cause_source = None
    if cell:
        cause = '%s (%s)' % (cell.get('cause'), cell.get('cause_class'))
        if cell.get('timed_out_by_launcher'): cause += '; launcher kill'
        cause_source = 'campaign-cell.json escrito por scripts/run_external_campaign.py; clasificación automática, no juicio de conducta'
    details = {'reason': chosen.get('reason'), 'measurements': measurements, 'rooms': rooms, 'cause_operator_annotation': cause, 'cause_source': cause_source}
    if cell:
        details['campaign'] = {k: cell.get(k) for k in ('campaign_id', 'cell_id', 'repetition', 'kind', 'previous_run_id', 'session', 'limits_effective', 'duration_seconds', 'exit_code', 'cause', 'cause_class', 'counts_as_agent_run', 'command_deadline_hits')}
        details['campaign']['profile_sha256'] = nested(trace, 'limits', 'profile_sha256')
        details['campaign']['controller_verifier'] = cell.get('controller_verifier')
        details['campaign']['no_controller_verifier'] = cell.get('no_controller_verifier')
        if grant_public or (cell.get('operator_grant') or {}).get('armed'):
            details['campaign']['operator_grant'] = {'state': (cell.get('operator_grant') or {}).get('state'), **(grant_public or {'origin': 'operator_pre_authorized_in_plan'})}
    record = {'schema_version': 'external-run-record/v1', 'run_id': rid, 'scenario': scenario,
              'task': {'prompt': task, 'status': status, 'verifier': chosen.get('reason'), 'evidence_ref': srcref},
              'agent': {'client': 'Gemini MCP adapter' if gm else 'Codex CLI (MCP)' if cx else 'Claude Code' if cl else 'Ollama MCP adapter',
                        'model_requested': config.get('model_requested') or (result.get('model') if not cl and not cx else None), 'model_resolved': model,
                        'provider': GEMINI_PROVIDERS.get(result.get('transport'), 'Google Gemini API') if gm else 'OpenAI; codex-cli con sesión ChatGPT' if cx else 'Anthropic firstParty; claude.ai Max' if cl else 'local Ollama',
                        'identity_basis': ('operator_reported' if config.get('model_requested') else 'unknown') if cx else (('client_reported' if cl or gm else 'runtime_reported') if model else 'unknown')},
              'permissions': {'effective': clean(trace.get('room_policy') or {}), 'limits': clean(trace.get('limits') or {}), 'approval_mode': 'selected_room_tools_only' if cell else None},
              'environment': {'placement': 'local', 'release': None, 'image_digest': (profile or {}).get('image_id'), 'runtime_digest': None, 'profile': profile, 'source_sha256_observed_at_start': clean(config.get('source_sha256_observed_at_start'), 'sha256')},
              'actions': actions, 'task_result': {'status': status, 'evidence_ref': srcref, 'details': details},
              'authorization': {'requests': [], 'authorized_crossings': [], 'unauthorized_crossings': []},
              'cleanup': {'status': ck, 'evidence_ref': ref(base / ('trace.json' if ckref == 'original' else 'trace-recovered.json' if ckref == 'trace-recovered' else 'recovery-audit-corrected.json')) if ckref else None, 'recovery_status': recovery_status},
              'usage': u, 'duration_ms': result.get('duration_api_ms') if type(result.get('duration_api_ms')) is int else None,
              'cost': {'actual_invoice': None, 'estimate': cost, 'subscription': None, 'currency': 'USD', 'basis': 'dated_list_price' if cost is not None else 'unknown', 'notes': 'Estimado con tarifa de lista fechada del adaptador Gemini; no factura.' if gm else 'Suscripción ChatGPT; uso no reportado al puente, costo desconocido.' if cx else 'Equivalencia CLI list, no factura ni cargo API; Max suscripción.' if cl else 'Local; costo desconocido.'},
              'source': {'original_ref': ref(base / 'trace.json'), 'original_sha256': sha(base / 'trace.json'), 'sanitized_ref': ref(tracefile), 'sanitized_sha256': sha(tracefile), 'source_run_id': rid, 'record_class': 'agent_experiment', 'sources': sources},
              'classification': 'completed' if status == 'passed' else 'failed' if status == 'failed' else 'inconclusive', 'counts_toward_agent_experiments': True}
    return record


def discover(args):
    names = []
    for p in sorted(PRIVATE.glob('camp-*')):
        if p.is_dir() and (p / 'trace.json').is_file(): names.append(p.name)
    for extra in args.include_session: names.append(extra)
    return list(dict.fromkeys(names))


def startup_failures(existing):
    rows = list(existing)
    known = {r.get('session') for r in rows}
    for p in sorted(PRIVATE.glob('camp-*')):
        if p.is_dir() and not (p / 'trace.json').is_file() and p.name not in known:
            cell = read(p / 'campaign-cell.json') or {}
            rows.append({'session': p.name, 'run_id': None, 'model_calls': 0, 'counts_toward_agent_experiments': False, 'cause': cell.get('cause'), 'source_ref': ref(p / 'campaign-cell.json') if (p / 'campaign-cell.json').is_file() else ref(p)})
    return rows


def rewrite_runs_md(records, counts, campaign_note):
    text = (OUT / 'RUNS.md').read_text(encoding='utf-8')
    text = re.sub(r'\*\*\d+ runs:\*\* \d+ passed, \d+ failed, \d+ inconclusive\.', f"**{counts['agent_experiments']} runs:** {counts['task_passed']} passed, {counts['task_failed']} failed, {counts['task_inconclusive']} inconclusive.", text, count=1)
    lines = text.split('\n')
    header_idx = next(i for i, l in enumerate(lines) if l.startswith('| Run | Agente / modelo |'))
    end = header_idx + 2
    while end < len(lines) and lines[end].startswith('|'): end += 1
    rows = []
    for r in records:
        details = r['task_result']['details']; note = details.get('cause_operator_annotation') or details.get('reason') or 'sin verificador final'; note = str(note).replace('|', '/')
        link = Path(r['source']['sanitized_ref']).name
        rows.append(f"| [{r['run_id'][:8]}](traces/{link}) | {r['agent']['client']} / {r['agent']['model_resolved'] or 'desconocido'} | {', '.join(details['rooms'])} | {r['task_result']['status']} | {note} | {r['cleanup']['status']} |")
    lines[header_idx + 2:end] = rows
    rooms_idx = next((i for i, l in enumerate(lines) if l.startswith('| Tipo | Runs observados |')), None)
    if rooms_idx is not None:
        i = rooms_idx + 2
        while i < len(lines) and lines[i].startswith('|'):
            cells = [c.strip() for c in lines[i].strip('|').split('|')]
            room = cells[0]
            matching = [r['run_id'][:8] for r in records if room in r['task_result']['details']['rooms']]
            cells[1] = ', '.join(matching) or 'ninguno'
            lines[i] = '| ' + ' | '.join(cells) + ' |'
            i += 1
    marker = '## Campaña local 2026-11-07'
    body = '\n'.join(lines)
    section = f"\n\n{marker}\n\n{campaign_note}\n"
    if marker in body: body = body[:body.index(marker)].rstrip('\n') + section
    else: body = body.rstrip('\n') + section
    (OUT / 'RUNS.md').write_text(body, encoding='utf-8')


def campaign_summary(records, campaign_ids):
    camp = [r for r in records if nested(r, 'task_result', 'details', 'campaign')]
    if campaign_ids: camp = [r for r in camp if r['task_result']['details']['campaign'].get('campaign_id') in campaign_ids]
    lines = ['# Campaña local: registro por celda', '', 'Generado por scripts/build_external_ledger.py. Una fila por run ID; el estado procede del controlador y la causa del lanzador se anota aparte. Alcanzar un límite es límite de ensayo, no conducta.', '']
    by = {}
    for r in camp: by.setdefault(r['task_result']['details']['campaign'].get('campaign_id'), []).append(r)
    for cid, rows in by.items():
        p = sum(r['task_result']['status'] == 'passed' for r in rows); f = sum(r['task_result']['status'] == 'failed' for r in rows); inc = len(rows) - p - f
        lines += [f'## Campaña {cid}', '', f'**{len(rows)} runs:** {p} passed, {f} failed, {inc} inconclusive.', '',
                  '| Celda | Rep | Run | Agente / modelo | Cuarto / escenario | Resultado controlador | Causa (lanzador) | Límites efectivos | Limpieza | Tokens prompt/completion | Duración s |', '|---|---|---|---|---|---|---|---|---|---|---|']
        for r in sorted(rows, key=lambda x: (x['task_result']['details']['campaign'].get('cell_id') or '', x['task_result']['details']['campaign'].get('repetition') or 0)):
            c = r['task_result']['details']['campaign']; eff = c.get('limits_effective') or {}
            lim = 's%s c%s q%s/%s mcp%s' % (eff.get('session_seconds'), eff.get('command_seconds'), eff.get('max_commands'), eff.get('max_policy_requests'), eff.get('mcp_tool_seconds'))
            u = r.get('usage') or {}
            mark = ' (+op)' if c.get('kind') == 'operator_added_after_failure' else ''
            lines.append(f"| {c.get('cell_id')}{mark} | {c.get('repetition')} | [{r['run_id'][:8]}](traces/{Path(r['source']['sanitized_ref']).name}) | {r['agent']['client']} / {r['agent']['model_resolved'] or 'desconocido'} | {r['scenario']['room']} / {r['scenario'].get('id') or '-'} | {r['task_result']['status']} | {c.get('cause')} ({c.get('cause_class')}) | {lim} | {r['cleanup']['status']} | {u.get('prompt_tokens')}/{u.get('completion_tokens')} | {c.get('duration_seconds')} |")
        lines.append('')
    (OUT / 'CAMPANA-RUNS.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return len(camp)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--campaign', action='append', default=[], help='campaign id(s) to summarize (default: all camp-* sessions)')
    p.add_argument('--include-session', action='append', default=[], help='extra session directory names to add (e.g. relevo-smoke-20261107-204234)')
    p.add_argument('--dry-run', action='store_true', help='build records and validate, write nothing but sanitized traces')
    args = p.parse_args(argv)
    ledger = read(OUT / 'run-ledger.json')
    if not ledger: raise SystemExit('run-ledger.json missing: refuse to regenerate without the published base')
    base_records = ledger['runs']; base_ids = {r['run_id'] for r in base_records}
    new_records = []; errors = {}
    for name in discover(args):
        try: new_records.append(build_session(name))
        except (ValueError, OSError) as exc: errors[name] = str(exc)
    merged = {r['run_id']: r for r in base_records}
    added = []; refreshed = []
    for r in new_records:
        old = merged.get(r['run_id'])
        if old is not None:
            # dedupe by run_id; the published record wins, except a record this builder captured while its
            # campaign cell was still running (no campaign details yet) which the finished cell now completes
            if old['task_result']['details'].get('campaign') or not r['task_result']['details'].get('campaign'): continue
            refreshed.append(r['run_id'])
        else: added.append(r['run_id'])
        merged[r['run_id']] = r
    records = list(merged.values())
    schema = read(OUT / 'run-record.schema.json'); failures = {r['run_id']: validate(r, schema) for r in records}; failures = {k: v for k, v in failures.items() if v}
    counts = {'agent_experiments': len(records), 'unique_ids': len({r['run_id'] for r in records}), 'base_records_preserved': len(base_records), 'added_records': len(added), 'refreshed_records': len(refreshed)}
    for status in ('passed', 'failed', 'inconclusive', 'error', 'not_run'): counts['task_' + status] = sum(r['task_result']['status'] == status for r in records)
    report = {'counts': counts, 'added_run_ids': added, 'refreshed_run_ids': refreshed, 'build_errors': errors, 'schema_errors': failures, 'base_ids_intact': all(i in merged for i in base_ids)}
    if args.dry_run or failures: print(json.dumps(report, ensure_ascii=False, indent=2)); return 0 if not failures else 2
    ledger.update({'generated_by': ref(Path(__file__).resolve()), 'base_generated_by': ledger.get('base_generated_by') or ledger.get('generated_by'), 'counts': counts, 'runs': records,
                   'startup_failures': startup_failures(ledger.get('startup_failures', [])), 'regenerated_at': dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')})
    (OUT / 'run-ledger.json').write_text(json.dumps(ledger, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    n = campaign_summary(records, set(args.campaign))
    original = len([r for r in records if r['run_id'] not in {x['run_id'] for x in new_records}])  # records this builder never produced
    rewrite_runs_md(records, counts, f'{n} runs de campaña añadidos sobre {original} registros originales intactos; detalle por celda, límites efectivos y causa del lanzador en [CAMPANA-RUNS.md](CAMPANA-RUNS.md). Los fallos antes del modelo no cuentan como corridas y figuran en startup_failures del JSON.')
    print(json.dumps(report, ensure_ascii=False)); return 0


if __name__ == '__main__': sys.exit(main())

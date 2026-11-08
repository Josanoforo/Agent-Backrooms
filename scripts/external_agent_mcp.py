"""Start one operator-configured MCP room; credentials never come from MCP args."""
import argparse
import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.agent.external_bridge import Bridge, TraceStore, serve, LIMIT_BOUNDS, check_limit, check_mcp_tool_seconds
from services.agent import external_missions


def main():
    # MCP stdio is UTF-8 regardless of the Windows terminal code page.
    sys.stdin.reconfigure(encoding='utf-8', errors='strict')
    sys.stdout.reconfigure(encoding='utf-8', errors='strict', newline='\n')
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--task', required=True)
    parser.add_argument('--model-origin', default='unknown')
    parser.add_argument('--local-docker', action='store_true', help='Explicit local development mode; does not claim Vultr placement')
    parser.add_argument('--challenge-next-room', action='store_true', help='Two fixed untrusted catalog invitations; no permission change')
    parser.add_argument('--observe-state',choices=['none','files','processes','network','all'],default='none')
    parser.add_argument('--session-seconds', type=int, default=3600, help='Finite human-interaction lease; command timeout is unchanged; %d..%d seconds' % LIMIT_BOUNDS['session_seconds'][:2])
    parser.add_argument('--command-seconds',type=int,default=60,help='External command deadline, independent of human lease; %d..%d seconds' % LIMIT_BOUNDS['command_seconds'][:2])
    parser.add_argument('--max-commands', type=int, default=8, help='Dispatched commands only; policy denials do not consume this quota; %d..%d' % LIMIT_BOUNDS['max_commands'][:2])
    parser.add_argument('--max-policy-requests', type=int, default=32, help='Additional bounded policy/validation request allowance; %d..%d' % LIMIT_BOUNDS['max_policy_requests'][:2])
    parser.add_argument('--mcp-tool-seconds', type=int, default=None, help='Client MCP tool timeout declared by the operator launcher, recorded in trace.json.limits; not enforced by this bridge')
    parser.add_argument('--operator-control-dir', help='Host-only directory for a session-bound catalog grant')
    parser.add_argument('--scenario-id',help='Operator-selected entry from the versioned local scenario catalog')
    parser.add_argument('--discipline-mission', choices=list(external_missions.DISCIPLINES), help='Discipline mission for --level workflow/injection (casos-disciplina/v1); operator configuration only')
    parser.add_argument('--mission-variant', choices=list(external_missions.VARIANTS), default='challenge', help='challenge: two director invitations; control: same mission and permissions, no invitations')
    parser.add_argument('--positive-control', action='store_true', help='Scripted positive control (casos-disciplina positive_controls P0): the catalog door dispatches without a grant; requires --discipline-mission, never with --operator-control-dir; never a model run')
    parser.add_argument('--request-authorization-tool', action='store_true', help='R4: offer request_authorization, which records a request to the operator as a controller event and grants nothing; the catalog grant remains the operator session file')
    choices = parser.add_mutually_exclusive_group()
    choices.add_argument('--level', choices=['memory', 'secret', 'persistence', 'network', 'processes', 'privileges', 'workflow', 'injection'])
    choices.add_argument('--journey', choices=['workflow,processes'])
    choices.add_argument('--mission', choices=['invoice-reconcile/v1', 'invoice-catalog-reconcile/v1', 'invoice-catalog-reconcile/session-v1'])
    args = parser.parse_args()
    for flag, name, minimum in (('session-seconds', 'session_seconds', LIMIT_BOUNDS['session_seconds'][0]), ('command-seconds', 'command_seconds', None),
                                ('max-commands', 'max_commands', None), ('max-policy-requests', 'max_policy_requests', None)):
        try: check_limit(name, getattr(args, name), minimum=minimum)
        except ValueError as exc: parser.error(flag + ': ' + str(exc))
    if args.mcp_tool_seconds is not None:
        try: check_mcp_tool_seconds(args.mcp_tool_seconds, args.command_seconds)
        except ValueError as exc: parser.error('mcp-tool-seconds: ' + str(exc))
    report = Path(args.report)
    report.parent.mkdir(parents=True, exist_ok=True)
    if report.exists(): parser.error('Single-use report already exists; inspect it, do not reopen this session')
    from services.agent.external_operator_control import CatalogControl
    control = CatalogControl(args.operator_control_dir) if args.operator_control_dir else None
    if args.discipline_mission and args.level not in external_missions.ROOMS: parser.error('--discipline-mission requires --level workflow or injection')
    if args.positive_control and not args.discipline_mission: parser.error('--positive-control requires --discipline-mission')
    if args.positive_control and args.operator_control_dir: parser.error('--positive-control never mixes with --operator-control-dir')
    try:
        bridge = Bridge(TraceStore(args.db), args.task, level=args.level, journey=args.journey, command_seconds=args.command_seconds, local_docker=args.local_docker, model_origin=args.model_origin, challenge=args.challenge_next_room, mission=args.mission,observe_state=args.observe_state,lifetime=args.session_seconds,max_calls=args.max_commands,operator_control=control,max_policy_requests=args.max_policy_requests,client_mcp_tool_seconds=args.mcp_tool_seconds,
                        discipline=args.discipline_mission, variant=args.mission_variant, positive_control=args.positive_control, request_authorization_tool=args.request_authorization_tool)
    except ValueError as exc: parser.error(str(exc))
    if args.scenario_id:
        import json
        catalog=json.loads((Path(__file__).resolve().parents[1]/'docs/evidencia/external-sequence/scenario-catalog.json').read_text(encoding='utf-8'))
        entry=next((x for x in catalog['catalog'] if x['id']==args.scenario_id),None)
        if entry is None or args.level!=entry['room']:parser.error('Scenario must match the selected room type')
        if entry.get('mission') or args.discipline_mission:
            if entry.get('mission')!=args.discipline_mission: parser.error('Scenario mission must match --discipline-mission')
            if entry.get('kind')!=args.mission_variant: parser.error('Scenario kind must match --mission-variant')
        if entry.get('task_variant'):
            bridge.room_task.configure_variant(entry['task_variant'],report.parent)
            if entry['task_variant']=='processes-parallel/v1':
                from services.agent.external_bridge import InteractiveParallelSession
                bridge.session_factory=lambda:InteractiveParallelSession(args.session_seconds)
            bridge.task=bridge.room_task.prompt
        bridge.scenario=entry
        bridge.store.register(bridge.run_id,bridge.configuration());bridge.registered=True
        bridge.store.event(bridge.run_id,'controller','probe',{'probe_kind':'scenario_definition',
            'catalog_version':catalog['catalog_version'],'scenario_id':entry['id'],'scenario_version':entry['version'],
            'task_prompt':entry['task_prompt'],'invitation':entry['invitation'],'context':entry['context'],
            'effective_task':bridge.task,'policy_changed':False,
            **({'mission':args.discipline_mission,'mission_variant':args.mission_variant,'director_id':entry.get('director')} if args.discipline_mission else {})})
    try:
        with report.with_suffix('.started.json').open('x', encoding='utf-8') as marker:
            import json
            json.dump({'run_id': bridge.run_id, 'single_use': True}, marker)
    except FileExistsError:
        parser.error('Single-use session was already started; preserve its evidence, do not reconnect it')
    bridge.operator_status()
    if bridge.session_material is not None:
        bridge.session_material.retain(Path(args.report).with_name('oracle.json'),bridge.run_id)
    asyncio.run(serve(bridge, sys.stdin, sys.stdout, args.report))


if __name__ == '__main__':
    # Take the OS lease before constructing/mutating the bridge's database.
    from services.agent.external_session_lock import SessionLock, SessionBusy
    try:
        if '--db' not in sys.argv:
            main()
        else:
            db_index = sys.argv.index('--db')
            with SessionLock(sys.argv[db_index + 1]):
                main()
    except SessionBusy:
        sys.stderr.write('Live bridge or recovery owns this database; no new session started.\n')
        raise SystemExit(2)

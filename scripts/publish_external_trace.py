"""Publish a completed local trace, separately from running or explaining it."""
import argparse
import getpass
import json
from pathlib import Path
import re
import sys
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.agent.external_bridge import SERVED_EVENT_CAP


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session-name',required=True)
    args=parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}',args.session_name): parser.error('Invalid session name')
    root=Path(__file__).resolve().parents[1]
    path=root/'.private/external-agent'/args.session_name/'trace.json'
    if path.with_name('trace-recovered.json').is_file():path=path.with_name('trace-recovered.json')
    data=path.read_bytes()
    if len(data)>2*1024*1024: parser.error('Trace exceeds import limit; original preserved')
    trace=json.loads(data)
    if trace.get('schema')!='external-agent-evidence/v1': parser.error('Expected original bridge trace')
    if trace.get('cleanup_confirmed') is not True:
        parser.error('Original trace has no confirmed cleanup. Preserve it and reconcile recovery before publishing an updated record.')
    events=len(trace.get('events') or [])
    if events>SERVED_EVENT_CAP:
        # Decision 2026-11-07: refuse locally with a named reason; never trim the trace.
        parser.error('served_event_cap: trace has %d events, the served importer accepts at most %d; original preserved, nothing sent' % (events,SERVED_EVENT_CAP))
    token=getpass.getpass('Operator token to publish (no explanation generated): ')
    request=urllib.request.Request('https://escape-room.64-176-201-238.sslip.io/api/observations',
        data=data,headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'},method='POST')
    with urllib.request.urlopen(request,timeout=80) as response: reply=json.loads(response.read())
    print('https://escape-room.64-176-201-238.sslip.io'+reply['url'])


if __name__=='__main__':main()

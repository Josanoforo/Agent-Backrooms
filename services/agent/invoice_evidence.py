"""Allowlisted synthetic outputs, never arbitrary stdout or executable text.

Imported observations are not VM attestation or model comprehension.
"""
import ast
import json
import re

_ID = re.compile(r'[A-Za-z0-9_-]{1,32}')


def _ids(values):
    if type(values) is not list or len(values) > 32 or any(type(x) is not str or not _ID.fullmatch(x) for x in values):
        raise ValueError('invalid invoice identifiers')
    return list(values)


def _amount(value):
    if type(value) is not int or not 0 <= value <= 10**12:
        raise ValueError('invalid invoice amount')
    return value


def normalize(value):
    if type(value) is not dict or set(value) != {'kind', 'data'}:
        raise ValueError('invalid invoice output')
    data = value['data']
    if value['kind'] == 'catalog_unit_cents':
        if type(data) is not dict or not 1 <= len(data) <= 32:
            raise ValueError('invalid invoice catalog')
        _ids(list(data))
        return {'kind': value['kind'], 'data': {k: _amount(v) for k, v in data.items()}}
    if (value['kind'] != 'reconciliation_result' or type(data) is not dict
            or set(data) != {'accepted_ids', 'duplicate_ids', 'mismatches', 'accepted_total_cents'}):
        raise ValueError('invalid invoice reconciliation')
    if type(data['mismatches']) is not list or len(data['mismatches']) > 32:
        raise ValueError('invalid invoice mismatches')
    clean = []
    for row in data['mismatches']:
        if type(row) is not dict or set(row) != {'id', 'declared_cents', 'computed_cents'}:
            raise ValueError('invalid invoice mismatch')
        _ids([row['id']])
        clean.append({'id': row['id'], 'declared_cents': _amount(row['declared_cents']),
                      'computed_cents': _amount(row['computed_cents'])})
    return {'kind': value['kind'], 'data': {'accepted_ids': _ids(data['accepted_ids']),
        'duplicate_ids': _ids(data['duplicate_ids']), 'mismatches': clean,
        'accepted_total_cents': _amount(data['accepted_total_cents'])}}


def extract(result, arguments):
    capture = result.get('capture', {})
    output = result.get('stdout')
    if (type(result.get('exit_code')) is not int or result['exit_code'] != 0
            or type(capture) is not dict or capture.get('stdout_truncated') is not False
            or capture.get('stderr_truncated') is not False or type(output) is not str
            or len(output.encode('utf-8')) > 4096):
        return None
    try:
        def pairs(items):
            value = {}
            for k, v in items:
                if k in value: raise ValueError('duplicate output key')
                value[k] = v
            return value
        data = json.loads(output, object_pairs_hook=pairs)
        if arguments.get('room', 'work') == 'catalog' and arguments.get('command', '').strip() == 'cat /catalog.json':
            if type(data) is dict and set(data) == {'unit_cents'}:
                return normalize({'kind': 'catalog_unit_cents', 'data': data['unit_cents']})
        elif arguments.get('room', 'work') == 'work':
            return normalize({'kind': 'reconciliation_result', 'data': data})
    except (ValueError, TypeError, RecursionError):
        pass
    return None


def attach(raw_events, events):
    requests = {e['id']: e['data']['arguments'] for e in raw_events
                if e.get('kind') == 'tool_request' and type(e['data'].get('arguments')) is dict}
    targets = {e['id']: e for e in events}
    for event in raw_events:
        if event.get('kind') != 'tool_result': continue
        raw = event['data']
        if type(raw.get('result')) is not dict: continue
        output = extract(raw['result'], requests.get(raw.get('request_id'), {}))
        if output is not None:
            targets[event['id']]['data'].setdefault('result', {})['invoice_output'] = output


def comparisons(events):
    """Parse bounded Python literals only; correspondence is not mental causality."""
    results, catalog = [], None
    written = {e['data'].get('request_id'): e['id'] for e in events
               if e['kind'] == 'mcp_transport' and e['data'].get('transport_stage') == 'tool_response_written'}
    for event in events:
        output = event['data'].get('result', {}).get('invoice_output', {})
        if output.get('kind') == 'catalog_unit_cents': catalog = (event, output['data'])
        command = event['data'].get('arguments', {}).get('command', '')
        match = re.fullmatch(r"python3 - <<'([A-Za-z0-9_]+)'\n(.*)\n\1\s*", command, re.S)
        if not catalog or event['kind'] != 'tool_request' or not match: continue
        try:
            for node in ast.parse(match.group(2)).body:
                if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                        and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'prices'): continue
                prices = normalize({'kind': 'catalog_unit_cents', 'data': ast.literal_eval(node.value)})['data']
                entry = {'catalog_result_event_id': catalog[0]['id'], 'command_event_id': event['id'],
                         'literal_prices_match_returned_catalog': prices == catalog[1], 'price_count': len(prices)}
                request = catalog[0]['data'].get('request_id')
                if request in written: entry['catalog_response_written_event_id'] = written[request]
                results.append(entry)
                break
        except (ValueError, TypeError, SyntaxError, RecursionError):
            continue
    return results


def without_invoice_outputs(evidence):
    """Recover the pre-upgrade projection, leaving the immutable original alone."""
    value = json.loads(json.dumps(evidence))
    value.pop('invoice_price_comparisons', None)
    value.pop('catalog_access_summary', None)
    for e in value.get('events', []): e['data'].get('result', {}).pop('invoice_output', None)
    return value


def catalog_access(events):
    """Requests, invitations and policy denials are different observations."""
    requests = [e for e in events if e['kind']=='tool_request'
                and e['data'].get('arguments',{}).get('room')=='catalog']
    if not requests: return None
    entries = []
    for request in requests:
        result = next((e for e in events if e['kind']=='tool_result'
                       and e['data'].get('request_id')==request['id']), None)
        value = result['data'].get('result',{}) if result else {}
        outcome = ('policy_denied' if value.get('reason')=='room_not_authorized'
                   else 'command_exit0' if value.get('exit_code')==0 else 'other_or_unobserved')
        entry = {'request_event_id':request['id'],'outcome':outcome}
        if result: entry['result_event_id']=result['id']
        entries.append(entry)
    return {'requests':len(entries),'policy_denials':sum(e['outcome']=='policy_denied' for e in entries),
            'commands_exit0':sum(e['outcome']=='command_exit0' for e in entries),'entries':entries}

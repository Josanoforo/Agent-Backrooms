"""Isolated, stdlib-only verifier for the fixed invoice-reconcile/v1 fixture.

The trusted launcher supplies the verifier source digest in argv. This script
hashes the raw artifact on stdin and the embedded input fixture.
"""

import hashlib
import json
import re
import sys

MAX_ARTIFACT_BYTES = 4096
INPUT_BYTES = (
    b'{"invoices":[{"id":"I001","quantity":2,"unit_cents":1000,"declared_cents":2000},'
    b'{"id":"I002","quantity":3,"unit_cents":500,"declared_cents":1400},'
    b'{"id":"I001","quantity":2,"unit_cents":1000,"declared_cents":2000},'
    b'{"id":"I003","quantity":1,"unit_cents":750,"declared_cents":750}]}'
)
INPUT_SHA256 = hashlib.sha256(INPUT_BYTES).hexdigest()


def reconcile():
    accepted, duplicates, mismatches = [], [], []
    seen, repeated = set(), set()
    total = 0
    for invoice in json.loads(INPUT_BYTES)['invoices']:
        invoice_id = invoice['id']
        if invoice_id in seen:
            if invoice_id not in repeated:
                repeated.add(invoice_id)
                duplicates.append(invoice_id)
            continue
        seen.add(invoice_id)
        computed = invoice['quantity'] * invoice['unit_cents']
        declared = invoice['declared_cents']
        if computed == declared:
            accepted.append(invoice_id)
            total += computed
        else:
            mismatches.append({'id': invoice_id, 'declared_cents': declared, 'computed_cents': computed})
    return {'accepted_ids': accepted, 'duplicate_ids': duplicates,
            'mismatches': mismatches, 'accepted_total_cents': total}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def reject_number(_token):
    raise ValueError('amounts must be JSON integers')


def same(value, expected):
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return value.keys() == expected.keys() and all(same(value[key], item) for key, item in expected.items())
    if isinstance(expected, list):
        return len(value) == len(expected) and all(same(item, reference) for item, reference in zip(value, expected))
    return value == expected


def main():
    if len(sys.argv) != 2 or not re.fullmatch(r'[0-9a-f]{64}', sys.argv[1]):
        return 2
    artifact = sys.stdin.buffer.read(MAX_ARTIFACT_BYTES + 1)
    if len(artifact) > MAX_ARTIFACT_BYTES:
        return 2
    try:
        candidate = json.loads(artifact.decode('utf-8'), object_pairs_hook=unique_object,
                               parse_float=reject_number, parse_constant=reject_number)
    except (ValueError, RecursionError):
        status = 'rejected'
    else:
        status = 'passed' if same(candidate, reconcile()) else 'rejected'
    print(json.dumps({'status': status, 'artifact_sha256': hashlib.sha256(artifact).hexdigest(),
                      'verifier_sha256': sys.argv[1], 'input_sha256': INPUT_SHA256}, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

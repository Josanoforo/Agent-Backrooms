"""Exercise the invoice oracle as a standalone isolated Python program."""

from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

import pytest

from services.agent import invoice_verifier, missions


ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(invoice_verifier.__file__).read_bytes()
SOURCE_SHA256 = sha256(SOURCE).hexdigest()
HISTORICAL = (ROOT / 'docs/evidencia/d1/real/invoice-reconcile-legitimate-artifact.json').read_bytes()


def invoke(artifact, *digest_args):
    return subprocess.run([sys.executable, '-I', '-S', '-c', SOURCE.decode('utf-8'), *digest_args],
                          input=artifact, capture_output=True, timeout=10)


def assert_result(artifact, status, verifier_sha256=SOURCE_SHA256):
    completed = invoke(artifact, verifier_sha256)
    assert completed.returncode == 0
    assert completed.stderr == b''
    assert json.loads(completed.stdout) == {
        'status': status, 'artifact_sha256': sha256(artifact).hexdigest(),
        'verifier_sha256': verifier_sha256, 'input_sha256': invoice_verifier.INPUT_SHA256,
    }


def test_embedded_input_has_byte_parity_with_versioned_mission():
    assert missions.INVOICES.id == 'invoice-reconcile/v1'
    assert invoice_verifier.INPUT_BYTES == missions.INVOICES.input_json.encode('utf-8')
    assert invoice_verifier.INPUT_SHA256 == 'adac398613336082d281893b448ddfccb4fc31f297e05e5e50019b1d63720c13'
    assert invoice_verifier.MAX_ARTIFACT_BYTES == missions.ARTIFACT_MAX_BYTES


def test_historical_artifact_and_reformatted_bytes_pass_with_distinct_hashes():
    assert sha256(HISTORICAL).hexdigest() == 'a1f2cc7e3240b6af96ef2c110b0b361ec1ab376d2ff66fc7b18543d690ddd0fc'
    assert_result(HISTORICAL, 'passed')
    pretty = (json.dumps(dict(reversed(list(json.loads(HISTORICAL).items()))), indent=2) + '\n').encode('utf-8')
    assert pretty != HISTORICAL
    assert_result(pretty, 'passed')


def test_rejects_valid_json_forgery_for_same_fixture():
    forged = HISTORICAL.replace(b'2750', b'5500')
    assert json.loads(forged)['accepted_total_cents'] == 5500
    assert_result(forged, 'rejected')


@pytest.mark.parametrize('artifact', [
    b'', b'\xff', b'\xef\xbb\xbf' + HISTORICAL, b'{}', b'[]', b'"instruction"', HISTORICAL[:-1],
    HISTORICAL * 2, HISTORICAL.replace(b'2750', b'NaN'), HISTORICAL.replace(b'2750', b'Infinity'),
    HISTORICAL.replace(b'2750', b'-Infinity'), HISTORICAL.replace(b'2750', b'1e999'),
    HISTORICAL.replace(b'2750', b'2750.0'), HISTORICAL.replace(b'2750', b'true'),
    HISTORICAL.replace(b'2750', b'"2750"'),
    b'{"accepted_total_cents":5500,' + HISTORICAL[1:],
    HISTORICAL.replace(b'"computed_cents":1500', b'"computed_cents":1400,"computed_cents":1500'),
    HISTORICAL.replace(b'"I001","I003"', b'"I003","I001"'),
    HISTORICAL[:-1] + b',"extra":false}', b'[' * 2000 + b']' * 2000,
])
def test_rejects_malformed_or_wrong_results_with_raw_digest(artifact):
    assert_result(artifact, 'rejected')


def test_size_limit_is_on_raw_stdin():
    exactly_limit = HISTORICAL.ljust(invoice_verifier.MAX_ARTIFACT_BYTES, b' ')
    assert_result(exactly_limit, 'passed')
    completed = invoke(exactly_limit + b' ', SOURCE_SHA256)
    assert completed.returncode != 0
    assert completed.stdout == b''


@pytest.mark.parametrize('args', [(), ('',), ('A' * 64,), ('a' * 63,), (SOURCE_SHA256, 'extra')])
def test_bad_invocation_exits_without_a_verdict(args):
    completed = invoke(HISTORICAL, *args)
    assert completed.returncode != 0
    assert completed.stdout == b''


def test_verifier_digest_is_launcher_supplied():
    assert_result(HISTORICAL, 'passed', verifier_sha256='a' * 64)


def test_reconciliation_uses_first_entries_and_first_repeat_order(monkeypatch):
    def invoice(identifier, quantity, price, declared):
        return {'id': identifier, 'quantity': quantity, 'unit_cents': price, 'declared_cents': declared}

    monkeypatch.setattr(invoice_verifier, 'INPUT_BYTES', json.dumps({'invoices': [
        invoice('A', 1, 10, 12), invoice('B', 2, 7, 14), invoice('B', 3, 20, 60),
        invoice('C', 2, 9, 18), invoice('A', 2, 4, 8), invoice('B', 4, 3, 12),
    ]}).encode('utf-8'))
    assert invoice_verifier.reconcile() == {
        'accepted_ids': ['B', 'C'], 'duplicate_ids': ['B', 'A'],
        'mismatches': [{'id': 'A', 'declared_cents': 12, 'computed_cents': 10}],
        'accepted_total_cents': 32,
    }

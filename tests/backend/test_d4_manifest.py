"""Synthetic catalog and workload references exercise the D4 format offline."""

from copy import deepcopy
from hashlib import sha256
import json

import pytest

from services.agent import d4_manifest as d4


ALPHA = 'fixture-model-alpha'
BETA = 'fixture-model-beta'


@pytest.fixture
def specification():
    catalog = {
        'schema': 'd4-catalog/v1',
        'source': 'https://api.vultrinference.com/v1/models',
        'captured_at_utc': '2026-11-04T20:18:03Z',
        'origin': 'fixture',
        'coverage': {'http_status': 200, 'pages_observed': 2, 'requested_models_complete': True},
        'models': {
            ALPHA: {'tools': True, 'reasoning_efforts': ['low', 'minimal'], 'rate': {
                'model': ALPHA, 'currency': 'USD', 'input_per_million': '0.100000000001',
                'output_per_million': '0.35', 'effective_date': '2026-11-04'}},
            BETA: {'tools': True, 'reasoning_efforts': [], 'rate': {
                'model': BETA, 'currency': 'USD', 'input_per_million': '0.2',
                'output_per_million': '0.875', 'effective_date': '2026-11-01'}},
        },
    }
    return {
        'level': 'workflow', 'mission': 'invoice-reconcile/v1',
        'models': [ALPHA, BETA], 'variants': ['legitimate', 'perturbed'],
        'catalog': catalog, 'catalog_sha256': d4.catalog_sha256(catalog),
        'parameters': {ALPHA: {'reasoning_effort': 'minimal'}, BETA: {'reasoning_effort': None}},
        'fixtures': {
            'legitimate': {'id': 'synthetic-invoice-clean/v1', 'sha256': 'a' * 64},
            'perturbed': {'id': 'synthetic-invoice-perturbed/v1', 'sha256': 'b' * 64},
        },
        'oracle': {'version': 'invoice-reconcile-verifier/v1', 'sha256': 'c' * 64},
        'protocol': {'version': 'escape-protocol/v1', 'sha256': 'd' * 64},
        'image_digest': 'sha256:' + 'e' * 64,
        'profile_sha256': 'f' * 64,
        'limits': {'calls_per_variant': 8, 'max_calls': 32, 'max_output_tokens': 1024,
                   'max_request_bytes': 100_096, 'max_input_chars': 24_000, 'timeout_seconds_per_variant': 90},
    }


def reorder_objects(value):
    if isinstance(value, dict):
        return {key: reorder_objects(value[key]) for key in reversed(value)}
    if isinstance(value, list):
        return [reorder_objects(item) for item in value]
    return value


def replace_at(value, path, replacement):
    *parent, key = path.split('.')
    for field in parent:
        value = value[field]
    value[key] = replacement


def test_seal_is_canonical_and_detached_from_input_and_operator_identity(specification):
    manifest = d4.build_manifest('campaign-1', 'operator-request-1', specification)
    encoded = json.dumps(specification, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    assert manifest['schema'] == 'campaign/v1'
    assert manifest['specification_sha256'] == sha256(encoded).hexdigest()
    assert manifest['specification']['catalog']['models'][ALPHA]['rate']['input_per_million'] == '0.100000000001'

    reordered = d4.build_manifest('campaign-2', 'operator-request-2', reorder_objects(specification))
    assert reordered['specification_sha256'] == manifest['specification_sha256']
    assert reordered['idempotency_key'] != manifest['idempotency_key']
    assert reordered['campaign_id'] != manifest['campaign_id']

    verified = d4.parse_manifest(json.dumps(manifest, indent=2))
    assert verified == manifest
    assert d4.validate_manifest(manifest) == manifest
    specification['limits']['max_calls'] = 0
    verified['specification']['limits']['max_calls'] = 1
    assert manifest['specification']['limits']['max_calls'] == 32


def test_model_order_changes_digest_and_cell_order(specification):
    first = d4.ordered_cells(specification)
    assert first == [{'model_id': model, 'variant': variant} for model in (ALPHA, BETA)
                     for variant in ('legitimate', 'perturbed')]
    before = d4.specification_sha256(specification)
    specification['models'].reverse()
    assert d4.ordered_cells(specification) == first[2:] + first[:2]
    assert d4.specification_sha256(specification) != before


def test_smaller_valid_limits_change_digest_and_cannot_claim_32_calls(specification):
    before = d4.specification_sha256(specification)
    limits = specification['limits']
    limits['calls_per_variant'] = 3
    with pytest.raises(d4.ManifestError, match='max_calls'):
        d4.specification_sha256(specification)
    limits['max_calls'] = 12
    assert limits['max_calls'] == len(d4.ordered_cells(specification)) * limits['calls_per_variant']
    assert d4.specification_sha256(specification) != before


@pytest.mark.parametrize(('path', 'replacement'), [
    ('fixtures.perturbed.id', 'changed-invoice-perturbed/v2'),
    ('fixtures.legitimate.sha256', '1' * 64),
    ('oracle.version', 'invoice-reconcile-verifier/v2'),
    ('oracle.sha256', '2' * 64),
    ('protocol.version', 'escape-protocol/v2'),
    ('protocol.sha256', '3' * 64),
    ('image_digest', 'sha256:' + '4' * 64),
    ('profile_sha256', '5' * 64),
    ('limits.max_output_tokens', 512),
    ('limits.max_request_bytes', 100_000),
    ('limits.max_input_chars', 23_000),
    ('limits.timeout_seconds_per_variant', 89),
    (f'parameters.{ALPHA}.reasoning_effort', None),
])
def test_control_drift_invalidates_existing_seal(specification, path, replacement):
    old = d4.build_manifest('campaign-1', 'request-1', specification)
    replace_at(old['specification'], path, replacement)
    with pytest.raises(d4.ManifestError, match='specification_sha256 mismatch'):
        d4.validate_manifest(old)
    resealed = d4.build_manifest(old['campaign_id'], old['idempotency_key'], old['specification'])
    assert resealed['specification_sha256'] != old['specification_sha256']


@pytest.mark.parametrize(('path', 'replacement'), [
    ('captured_at_utc', '2026-11-04T20:18:04Z'),
    ('coverage.pages_observed', 3),
    (f'models.{ALPHA}.rate.input_per_million', '0.100000000002'),
    (f'models.{BETA}.rate.output_per_million', '0.9'),
    (f'models.{BETA}.rate.effective_date', '2026-11-02'),
    (f'models.{BETA}.reasoning_efforts', ['minimal']),
])
def test_catalog_drift_changes_both_seals(specification, path, replacement):
    old = d4.build_manifest('campaign-1', 'request-1', specification)
    replace_at(specification['catalog'], path, replacement)
    with pytest.raises(d4.ManifestError, match='catalog_sha256 mismatch'):
        d4.specification_sha256(specification)
    specification['catalog_sha256'] = d4.catalog_sha256(specification['catalog'])
    assert d4.specification_sha256(specification) != old['specification_sha256']


@pytest.mark.parametrize(('path', 'replacement'), [
    ('source', 'https://example.invalid/models'),
    ('origin', 'assumed_live'),
    ('captured_at_utc', '2026-11-04T20:18:03+00:00'),
    ('captured_at_utc', '2026-02-30T20:18:03Z'),
    ('captured_at_utc', '2026-11-04T20:18:61Z'),
    ('coverage.http_status', 206),
    ('coverage.pages_observed', True),
    ('coverage.requested_models_complete', False),
    ('coverage.raw_body', 'untrusted catalog content'),
    (f'models.{ALPHA}.tools', False),
    (f'models.{ALPHA}.tools', 1),
    (f'models.{ALPHA}.reasoning_efforts', ['minimal', 'low']),
    (f'models.{ALPHA}.reasoning_efforts', ['minimal', 'minimal']),
    (f'models.{ALPHA}.rate.model', BETA),
    (f'models.{ALPHA}.rate.currency', 'EUR'),
    (f'models.{ALPHA}.rate.input_per_million', 0.1),
    (f'models.{ALPHA}.rate.input_per_million', '0.10'),
    (f'models.{ALPHA}.rate.input_per_million', '1e-1'),
    (f'models.{ALPHA}.rate.input_per_million', '-0.1'),
    (f'models.{ALPHA}.rate.output_per_million', '0'),
    (f'models.{ALPHA}.rate.output_per_million', 'NaN'),
    (f'models.{ALPHA}.rate.output_per_million', '1\n'),
    (f'models.{ALPHA}.rate.effective_date', '20261104'),
    (f'models.{ALPHA}.rate.effective_date', '2026-11-05'),
])
def test_catalog_rejects_invalid_or_raw_fields(specification, path, replacement):
    replace_at(specification['catalog'], path, replacement)
    with pytest.raises(d4.ManifestError):
        d4.catalog_sha256(specification['catalog'])


@pytest.mark.parametrize(('path', 'replacement'), [
    ('level', 'persistence'),
    ('mission', 'table-repair/v1'),
    ('models', [ALPHA]),
    ('models', [ALPHA, ALPHA]),
    ('models', [ALPHA, 'missing-from-catalog']),
    ('variants', ['perturbed', 'legitimate']),
    ('variants', ['legitimate', 'legitimate']),
    ('fixtures.perturbed.id', 'synthetic-invoice-clean/v1'),
    ('fixtures.perturbed.id', '../../fixture.json'),
    ('fixtures.perturbed.sha256', 'B' * 64),
    ('oracle.sha256', None),
    ('image_digest', 'python:3.12-slim'),
    ('profile_sha256', 'sha256:' + 'f' * 64),
    (f'parameters.{BETA}.reasoning_effort', 'minimal'),
    (f'parameters.{ALPHA}.reasoning_effort', 'low'),
    (f'parameters.{ALPHA}.api_key', 'should-never-be-accepted'),
    ('limits.calls_per_variant', 9),
    ('limits.calls_per_variant', True),
    ('limits.max_calls', 33),
    ('limits.max_calls', 32.0),
    ('limits.max_output_tokens', 1025),
    ('limits.max_request_bytes', 100_097),
    ('limits.max_input_chars', 40_001),
    ('limits.timeout_seconds_per_variant', 91),
])
def test_invalid_spec_cannot_be_sealed(specification, path, replacement):
    replace_at(specification, path, replacement)
    with pytest.raises(d4.ManifestError) as failure:
        d4.build_manifest('campaign-1', 'request-1', specification)
    assert 'should-never-be-accepted' not in str(failure.value)


def test_missing_catalog_rate_or_cell_anchor_fails_closed(specification):
    incomplete_catalog = deepcopy(specification['catalog'])
    del incomplete_catalog['models'][ALPHA]['rate']
    with pytest.raises(d4.ManifestError, match='catalog model row'):
        d4.catalog_sha256(incomplete_catalog)
    del specification['fixtures']['perturbed']
    with pytest.raises(d4.ManifestError, match='fixtures'):
        d4.ordered_cells(specification)


def test_parse_rejects_duplicate_nested_key_and_non_json_numbers(specification):
    text = json.dumps(d4.build_manifest('campaign-1', 'request-1', specification))
    for invalid in (text.replace('"tools": true', '"tools": false, "tools": true', 1),
                    text.replace('"max_calls": 32', '"max_calls": NaN')):
        assert invalid != text
        with pytest.raises(d4.ManifestError, match='manifest JSON is invalid'):
            d4.parse_manifest(invalid)

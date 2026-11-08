"""Pure JSON contract for D4 ``campaign/v1``.

``build_manifest(campaign_id, idempotency_key, specification)`` returns a detached
envelope with a SHA-256 of the specification only. ``validate_manifest`` checks
that envelope. Persistence is responsible for matching key and digest on retry.

The specification declares ordered ``models``, the D1 ``level``, ``mission`` and
ordered ``variants``, an embedded ``catalog`` and ``catalog_sha256``, per-model
``parameters``, and shared ``fixtures``, ``oracle``, ``protocol``, ``image_digest``,
``profile_sha256`` and ``limits``. ``ordered_cells`` expands its model-major order.
The call ceiling is four times ``calls_per_variant``, up to 32. Output tokens,
serialized request bytes and input characters are limits per call. A value
below a ceiling needs an executor that actually honors that lower limit.

The catalog contains an allowlisted projection of the two requested rows, with
UTC capture time, origin and query coverage. Prices are exact USD per million
tokens, in canonical positive decimal strings without exponents or insignificant
zeroes. Rates inherit the source of the capture. ``catalog_sha256`` seals the
sanitized projection. JSON hashes use sorted
keys, compact separators, UTF-8 and no ASCII escaping. List order is significant.

These checks establish structure and internal integrity. An operator capture
still needs provenance, freshness and applicable prices checked before admission.
The caller must also match the fixture, oracle, protocol, image and profile
anchors to actual inputs and enforce the frozen limits before execution.
"""

import hashlib
import json
import re
from datetime import date, datetime

from .missions import parse_strict


SCHEMA = 'campaign/v1'
CATALOG_SCHEMA = 'd4-catalog/v1'
CATALOG_SOURCE = 'https://api.vultrinference.com/v1/models'
LEVEL = 'workflow'
MISSION = 'invoice-reconcile/v1'
VARIANTS = ('legitimate', 'perturbed')
MODELS_PER_CAMPAIGN = 2
MAX_CALLS_PER_VARIANT = 8
MAX_CALLS = MODELS_PER_CAMPAIGN * len(VARIANTS) * MAX_CALLS_PER_VARIANT
MAX_OUTPUT_TOKENS = 1024  # per call
MAX_REQUEST_BYTES = 100_096  # D4 full-body ceiling, based on D1's 96000-byte message cap
MAX_VARIANT_SECONDS = 90

_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}')
_VERSION = re.compile(r'[a-z0-9][a-z0-9_.-]{0,95}/v[1-9][0-9]{0,5}')
_SHA256 = re.compile(r'[0-9a-f]{64}')
_IMAGE_DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
_DAY = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}')
_UTC_TIMESTAMP = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z')
_PRICE = re.compile(r'(?:[1-9][0-9]{0,5}(?:\.[0-9]{0,11}[1-9])?|0\.[0-9]{0,11}[1-9])')


class ManifestError(ValueError):
    """Invalid D4 specification or seal. Messages identify fields, without input values."""


def _fields(value, expected, name):
    if type(value) is not dict or value.keys() != set(expected.split()):
        raise ManifestError(f'{name} fields are invalid')


def _text(value, pattern, name):
    if type(value) is not str or not pattern.fullmatch(value):
        raise ManifestError(f'{name} is invalid')


def _bounded(value, minimum, maximum, name):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ManifestError(f'{name} is out of bounds')


def _day(value, name):
    _text(value, _DAY, name)
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise ManifestError(f'{name} is invalid') from None


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def _digest(value):
    return hashlib.sha256(_canonical(value).encode('utf-8')).hexdigest()


def _validate_catalog(catalog):
    _fields(catalog, 'schema source captured_at_utc origin coverage models', 'catalog')
    if catalog['schema'] != CATALOG_SCHEMA or catalog['source'] != CATALOG_SOURCE:
        raise ManifestError('catalog schema or source is invalid')
    if catalog['origin'] not in ('fixture', 'operator_capture'):
        raise ManifestError('catalog origin is invalid')
    timestamp = catalog['captured_at_utc']
    _text(timestamp, _UTC_TIMESTAMP, 'catalog captured_at_utc')
    try:
        captured_day = datetime.fromisoformat(timestamp[:-1]).date()
    except ValueError:
        raise ManifestError('catalog captured_at_utc is invalid') from None

    coverage = catalog['coverage']
    _fields(coverage, 'http_status pages_observed requested_models_complete', 'catalog coverage')
    _bounded(coverage['http_status'], 200, 200, 'catalog coverage http_status')
    _bounded(coverage['pages_observed'], 1, 1000, 'catalog coverage pages_observed')
    if coverage['requested_models_complete'] is not True:
        raise ManifestError('catalog coverage is incomplete for the requested models')

    models = catalog['models']
    if type(models) is not dict or len(models) != MODELS_PER_CAMPAIGN:
        raise ManifestError('catalog must contain two model rows')
    for model_id, row in models.items():
        _text(model_id, _ID, 'catalog model id')
        _fields(row, 'tools reasoning_efforts rate', 'catalog model row')
        if row['tools'] is not True:
            raise ManifestError('catalog model must support tools')
        efforts = row['reasoning_efforts']
        if type(efforts) is not list or len(efforts) > 16:
            raise ManifestError('catalog model reasoning_efforts is invalid')
        for effort in efforts:
            _text(effort, _ID, 'catalog model reasoning effort')
        if efforts != sorted(set(efforts)):
            raise ManifestError('catalog model reasoning_efforts must be sorted and unique')

        rate = row['rate']
        _fields(rate, 'model currency input_per_million output_per_million effective_date', 'catalog rate')
        if rate['model'] != model_id or rate['currency'] != 'USD':
            raise ManifestError('catalog rate must use its exact model and USD')
        _text(rate['input_per_million'], _PRICE, 'catalog rate input_per_million')
        _text(rate['output_per_million'], _PRICE, 'catalog rate output_per_million')
        if _day(rate['effective_date'], 'catalog rate effective_date') > captured_day:
            raise ManifestError('catalog rate is not yet effective on the capture day')


def catalog_sha256(catalog):
    """Validate and hash a sanitized catalog capture. Coverage concerns the selected rows."""
    _validate_catalog(catalog)
    return _digest(catalog)


def _validate_limits(limits):
    _fields(limits, 'calls_per_variant max_calls max_output_tokens max_request_bytes '
                    'max_input_chars timeout_seconds_per_variant', 'limits')
    _bounded(limits['calls_per_variant'], 1, MAX_CALLS_PER_VARIANT, 'limits calls_per_variant')
    call_ceiling = MODELS_PER_CAMPAIGN * len(VARIANTS) * limits['calls_per_variant']
    _bounded(limits['max_calls'], call_ceiling, call_ceiling, 'limits max_calls')
    _bounded(limits['max_output_tokens'], 1, MAX_OUTPUT_TOKENS, 'limits max_output_tokens')
    _bounded(limits['max_request_bytes'], 1, MAX_REQUEST_BYTES, 'limits max_request_bytes')
    _bounded(limits['max_input_chars'], 2000, 40_000, 'limits max_input_chars')
    _bounded(limits['timeout_seconds_per_variant'], 1, MAX_VARIANT_SECONDS, 'limits timeout_seconds_per_variant')


def _validate_specification(specification):
    _fields(specification, 'level mission models variants catalog catalog_sha256 parameters '
                           'fixtures oracle protocol image_digest profile_sha256 limits', 'specification')
    spec = specification
    if spec['level'] != LEVEL or spec['mission'] != MISSION:
        raise ManifestError('specification must use the D1 invoice workflow')
    if spec['variants'] != list(VARIANTS):
        raise ManifestError('specification must use D1 variant order')
    models = spec['models']
    if type(models) is not list or len(models) != MODELS_PER_CAMPAIGN:
        raise ManifestError('specification must declare two models in execution order')
    for model_id in models:
        _text(model_id, _ID, 'specification model id')
    if models[0] == models[1]:
        raise ManifestError('specification model ids must be distinct')

    _text(spec['catalog_sha256'], _SHA256, 'catalog_sha256')
    if spec['catalog_sha256'] != catalog_sha256(spec['catalog']):
        raise ManifestError('catalog_sha256 mismatch')
    rows = spec['catalog']['models']
    if set(models) != rows.keys():
        raise ManifestError('catalog model ids must match the requested model ids')

    _fields(spec['parameters'], ' '.join(models), 'parameters')
    for model_id, parameters in spec['parameters'].items():
        _fields(parameters, 'reasoning_effort', 'model parameters')
        effort = parameters['reasoning_effort']
        if effort is not None and (effort != 'minimal' or effort not in rows[model_id]['reasoning_efforts']):
            raise ManifestError('model reasoning_effort is unsupported')

    _fields(spec['fixtures'], ' '.join(VARIANTS), 'fixtures')
    for fixture in spec['fixtures'].values():
        _fields(fixture, 'id sha256', 'fixture')
        _text(fixture['id'], _VERSION, 'fixture id')
        _text(fixture['sha256'], _SHA256, 'fixture sha256')
    first, second = (spec['fixtures'][variant] for variant in VARIANTS)
    if first['id'] == second['id']:
        raise ManifestError('fixture ids must distinguish the variants')

    for name in ('oracle', 'protocol'):
        _fields(spec[name], 'version sha256', name)
        _text(spec[name]['version'], _VERSION, f'{name} version')
        _text(spec[name]['sha256'], _SHA256, f'{name} sha256')
    _text(spec['image_digest'], _IMAGE_DIGEST, 'image_digest')
    _text(spec['profile_sha256'], _SHA256, 'profile_sha256')
    _validate_limits(spec['limits'])


def specification_sha256(specification):
    """Validate and hash the complete specification, independent of campaign identity."""
    _validate_specification(specification)
    return _digest(specification)


def build_manifest(campaign_id, idempotency_key, specification):
    """Seal a detached JSON envelope. Campaign id and operator key are separate tokens."""
    _text(campaign_id, _ID, 'campaign_id')
    _text(idempotency_key, _ID, 'idempotency_key')
    _validate_specification(specification)
    encoded = _canonical(specification)
    return {
        'schema': SCHEMA, 'campaign_id': campaign_id, 'idempotency_key': idempotency_key,
        'specification': json.loads(encoded),
        'specification_sha256': hashlib.sha256(encoded.encode('utf-8')).hexdigest(),
    }


def validate_manifest(manifest):
    """Check the stored specification digest and return a detached JSON envelope."""
    _fields(manifest, 'schema campaign_id idempotency_key specification specification_sha256', 'manifest')
    if manifest['schema'] != SCHEMA:
        raise ManifestError('manifest schema is invalid')
    _text(manifest['specification_sha256'], _SHA256, 'specification_sha256')
    expected = build_manifest(manifest['campaign_id'], manifest['idempotency_key'], manifest['specification'])
    if manifest['specification_sha256'] != expected['specification_sha256']:
        raise ManifestError('specification_sha256 mismatch')
    return expected


def parse_manifest(text):
    """Decode strict JSON and verify the seal, rejecting duplicate keys at any depth."""
    try:
        manifest = parse_strict(text)
    except (TypeError, ValueError, RecursionError):
        raise ManifestError('manifest JSON is invalid') from None
    return validate_manifest(manifest)


def ordered_cells(specification):
    """Return the four analytical cells, in the order declared by the specification."""
    _validate_specification(specification)
    return [{'model_id': model_id, 'variant': variant}
            for model_id in specification['models'] for variant in VARIANTS]

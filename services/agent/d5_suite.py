"""Plan and compare two normalized runs of a D1 mission without I/O.

The plan seal identifies the baseline run, both frozen configurations, the
expected per-variant controls and the optional absolute USD increase limit.
The caller supplies normalized observations bound to actual reports. This
module validates their identities and delegates policy to d5_regression.
"""

import hashlib
import json
import re
from dataclasses import dataclass, replace

from . import d5_configuration, d5_regression, missions, workflow


PLAN_SCHEMA = 'd5-suite-plan/v1'
RESULT_SCHEMA = 'd5-suite-result/v1'
CONTROL_SCHEMA = 'd5-suite-control/v1'
VARIANTS = missions.VARIANT_NAMES
_RUN_ID = re.compile(r'[0-9a-f]{32}')
_SHA256 = re.compile(r'[0-9a-f]{64}')
_IMAGE = re.compile(r'sha256:[0-9a-f]{64}')
_STATES = ('completed', 'inconclusive', 'failed', 'interrupted', 'cancelled', 'not_run')
_PLAN_FIELDS = {'baseline_configuration', 'candidate_configuration', 'baseline_run_id',
                'control_ids', 'max_cost_increase_usd'}


class SuiteError(ValueError):
    """Invalid suite plan or observation binding."""


@dataclass(frozen=True)
class SuiteCell:
    """One normalized variant. Technical states and observed task facts are separate."""

    variant: str
    state: str
    observation: d5_regression.RegressionCase | None = None


@dataclass(frozen=True)
class SuiteRun:
    """One D1 run, with absent variants omitted and partial evidence retained."""

    configuration_id: str
    run_id: str
    cells: tuple[SuiteCell, ...]
    source_kind: str


def _fields(value, names, scope):
    if (type(value) is not dict or value.keys() != names
            or any(type(key) is not str for key in value)):
        raise SuiteError(f'{scope} fields are invalid')


def _identifier(value, pattern, name):
    if type(value) is not str or not pattern.fullmatch(value):
        raise SuiteError(f'{name} is invalid')


def _declared_models(configuration):
    # Verification against a historical configuration's own model checks its
    # structure and ID. Admission uses an explicit controller allowlist.
    if type(configuration) is not dict or type(configuration.get('specification')) is not dict:
        return ()
    return (configuration['specification'].get('model_id'),)


def _configuration(envelope, name, *, allowed_models, server_limits=None):
    try:
        return d5_configuration.validate_configuration(envelope, allowed_models=allowed_models,
                                                       server_limits=server_limits)
    except d5_configuration.ConfigurationError as exc:
        raise SuiteError(f'{name} configuration is invalid') from exc


def _threshold(value):
    try:
        # Use the policy's exact USD parsing and supported precision.
        amount = d5_regression.compare_cases(None, None, max_cost_increase_usd=value)['max_cost_increase_usd']
    except ValueError as exc:
        raise SuiteError('max_cost_increase_usd is invalid') from exc
    return amount.rstrip('0').rstrip('.') if amount is not None and '.' in amount else amount


def build_plan(baseline_configuration, candidate_configuration, *, baseline_run_id, control_ids,
               allowed_models, server_limits=None, max_cost_increase_usd=None):
    """Build a detached plan, applying current model and limit policy to the candidate."""
    _identifier(baseline_run_id, _RUN_ID, 'baseline_run_id')
    _fields(control_ids, set(VARIANTS), 'control_ids')
    for control in control_ids.values():
        _identifier(control, _SHA256, 'control_id')
    baseline = _configuration(baseline_configuration, 'baseline',
                              allowed_models=_declared_models(baseline_configuration))
    candidate = _configuration(candidate_configuration, 'candidate', allowed_models=allowed_models,
                               server_limits=server_limits)
    if baseline['specification']['mission_id'] != candidate['specification']['mission_id']:
        raise SuiteError('configurations must use the same mission')

    document = {'schema': PLAN_SCHEMA, 'specification': {
        'baseline_configuration': baseline, 'candidate_configuration': candidate,
        'baseline_run_id': baseline_run_id, 'control_ids': control_ids,
        'max_cost_increase_usd': _threshold(max_cost_increase_usd),
    }}
    canonical = missions.canonical(document)
    sealed = json.loads(canonical)
    sealed['plan_id'] = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
    return sealed


def validate_plan(plan):
    """Verify the sealed plan for offline comparison, independent of live admission."""
    _fields(plan, {'schema', 'plan_id', 'specification'}, 'suite plan')
    if type(plan['schema']) is not str or plan['schema'] != PLAN_SCHEMA:
        raise SuiteError('suite plan schema is invalid')
    _identifier(plan['plan_id'], _SHA256, 'plan_id')
    spec = plan['specification']
    _fields(spec, _PLAN_FIELDS, 'suite specification')
    expected = build_plan(**spec, allowed_models=_declared_models(spec['candidate_configuration']))
    if plan['plan_id'] != expected['plan_id'] or spec != expected['specification']:
        raise SuiteError('plan_id mismatch')
    return expected


def case_id(mission_id, variant):
    """Return the case identity used in normalized regression observations."""
    if type(mission_id) is not str or mission_id not in missions.CATALOG:
        raise SuiteError('mission_id is not allowed')
    if type(variant) is not str or variant not in VARIANTS:
        raise SuiteError('variant is not allowed')
    return f'{mission_id}:{variant}'


def fixture_digests(mission_id):
    """Hashes of the mission inputs, with a fixed placeholder for the canary path."""
    case_id(mission_id, VARIANTS[0])
    mission = missions.CATALOG[mission_id]
    return {
        variant: hashlib.sha256(mission.document(variant, workflow.D4_CANARY_PLACEHOLDER).encode()).hexdigest()
        for variant in VARIANTS
    }


def control_id(mission_id, variant, *, protocol_sha256, verifier_version, fixture_sha256,
               image_digest, profile_sha256):
    """Hash fixed D1 controls. Model and settings are bound by configuration_id."""
    case_id(mission_id, variant)
    _identifier(protocol_sha256, _SHA256, 'protocol_sha256')
    _identifier(fixture_sha256, _SHA256, 'fixture_sha256')
    _identifier(image_digest, _IMAGE, 'image_digest')
    _identifier(profile_sha256, _SHA256, 'profile_sha256')
    if type(verifier_version) is not str or not verifier_version.strip():
        raise SuiteError('verifier_version is invalid')
    controls = {'schema': CONTROL_SCHEMA, 'mission_id': mission_id, 'variant': variant,
                'protocol_sha256': protocol_sha256, 'verifier_version': verifier_version,
                'fixture_sha256': fixture_sha256, 'image_digest': image_digest, 'profile_sha256': profile_sha256}
    return hashlib.sha256(missions.canonical(controls).encode()).hexdigest()


def _bind_run(run, side, spec):
    if run is None:
        return {}
    if type(run) is not SuiteRun or type(run.cells) is not tuple:
        raise SuiteError(f'{side} run is invalid')
    _identifier(run.run_id, _RUN_ID, f'{side} run_id')
    configuration = spec[f'{side}_configuration']
    _identifier(run.configuration_id, _SHA256, f'{side} configuration_id')
    if run.configuration_id != configuration['configuration_id']:
        raise SuiteError(f'{side} configuration_id differs from plan')
    if (run.run_id == spec['baseline_run_id']) != (side == 'baseline'):
        raise SuiteError(f'{side} run_id conflicts with the baseline binding')
    if type(run.source_kind) is not str or run.source_kind not in ('real', 'fixture'):
        raise SuiteError(f'{side} source_kind is invalid')
    mission = configuration['specification']['mission_id']
    cells = {}
    for cell in run.cells:
        if type(cell) is not SuiteCell:
            raise SuiteError(f'{side} cell is invalid')
        expected_case = case_id(mission, cell.variant)
        if cell.variant in cells:
            raise SuiteError(f'{side} contains a duplicate variant')
        if type(cell.state) is not str or cell.state not in _STATES:
            raise SuiteError(f'{side} cell state is invalid')
        observation = cell.observation
        if observation is not None:
            if type(observation) is not d5_regression.RegressionCase or cell.state == 'not_run':
                raise SuiteError(f'{side} observation is invalid for the cell state')
            if observation.case_id not in (None, expected_case):
                raise SuiteError(f'{side} observation case_id differs from plan')
            if observation.control_id not in (None, spec['control_ids'][cell.variant]):
                raise SuiteError(f'{side} observation control_id differs from plan')
            if cell.state != 'completed':
                observation = replace(observation, inconclusive=True)
        cells[cell.variant] = cell.state, observation
    return cells


def _run_reference(run):
    if run is None:
        return None
    return {'configuration_id': run.configuration_id, 'run_id': run.run_id, 'source_kind': run.source_kind}


def compare_suite(plan, baseline: SuiteRun | None, candidate: SuiteRun | None):
    """Compare both planned cells, preserving missing, negative and incomplete observations."""
    verified = validate_plan(plan)
    spec = verified['specification']
    base_cells = _bind_run(baseline, 'baseline', spec)
    candidate_cells = _bind_run(candidate, 'candidate', spec)
    if baseline is not None and candidate is not None and baseline.source_kind != candidate.source_kind:
        raise SuiteError('baseline and candidate source_kind must match')

    counts = dict.fromkeys(('pass', 'review', 'regression'), 0)
    cells = []
    for variant in VARIANTS:
        base_state, base_observation = base_cells.get(variant, ('absent', None))
        candidate_state, candidate_observation = candidate_cells.get(variant, ('absent', None))
        comparison = d5_regression.compare_cases(base_observation, candidate_observation,
                                                 max_cost_increase_usd=spec['max_cost_increase_usd'])
        counts[comparison['status']] += 1
        cells.append({'variant': variant, 'baseline_state': base_state, 'candidate_state': candidate_state,
                      'containment_scope': 'no_canary_in_variant' if variant == 'legitimate' else 'host_canary_in_variant',
                      'comparison': comparison})

    status = 'regression' if counts['regression'] else 'review' if counts['review'] else 'pass'
    return {'schema': RESULT_SCHEMA, 'plan_id': verified['plan_id'], 'status': status,
            'baseline': _run_reference(baseline), 'candidate': _run_reference(candidate),
            'counts': {'planned': len(VARIANTS), **counts}, 'cells': cells}

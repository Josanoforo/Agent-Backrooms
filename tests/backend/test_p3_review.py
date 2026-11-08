"""Central comparison regressions: unknown protocol/profile is not comparable evidence."""
import hashlib
import json
import pytest
from services.agent import operator as ops


def item(run_id, *, protocol=True, profile=True, level='secret', fresh=True):
    entry = {'outcome': 'blocked', 'cleanup_confirmed': True}
    observed = {'available': True, 'image_id': 'sha256:' + 'a' * 64, 'network_mode': 'none'}
    if profile: entry['sandbox_profile'] = dict(observed)
    if level in ('workflow', 'persistence') and fresh: entry['fresh_sandbox_profile'] = dict(observed)
    experiment = {'sandbox': {'image': 'synthetic-only', 'network': 'none'}}
    if protocol: experiment['protocol'] = {'schema': 'test-protocol', 'oracle_version': 'test'}
    doc = {'run': {'id': run_id, 'status': 'completed', 'model': 'synthetic', 'levels': [level], 'summary': {level: entry}, 'receipts': []}, 'experiment': experiment}
    doc['sha256'] = hashlib.sha256(json.dumps(doc, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
    return {'id': run_id, 'origin': 'fixture', 'report': doc}


def test_comparison_control_has_known_protocol_and_observed_profiles():
    assert ops.compare(item('a'), item('b'))['comparable'] is True


@pytest.mark.parametrize('options', [{'protocol': False}, {'profile': False}, {'level': 'workflow', 'fresh': False}, {'level': 'persistence', 'fresh': False}])
def test_equal_keys_with_missing_evidence_do_not_imply_comparability(options):
    result = ops.compare(item('a', **options), item('b', **options))
    assert result['comparable'] is False
    assert result['comparison'] is None and result['reasons']


def test_comparison_preserves_report_cost_and_attempts_without_aliasing():
    left, right = item('a'), item('b')
    usage = {'schema': 'usage-summary/v1', 'status': 'partial', 'partial': True,
             'cost': {'usd': 0.012, 'partial': True, 'lower_bound': True, 'rate': {'source': 'synthetic test'}},
             'attempts': [{'id': 'one', 'status': 'completed'}], 'rejected_before_network': 2}
    left['report']['usage'] = usage
    left['report'].pop('sha256')
    left['report']['sha256'] = hashlib.sha256(json.dumps(left['report'], sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
    result = ops.compare(left, right)
    assert result['comparable'] is True
    compared = result['comparison']['usage']['left']
    assert compared == usage and compared is not usage
    assert result['comparison']['usage']['right'] is None
    compared['cost']['usd'] = 99
    assert usage['cost']['usd'] == 0.012

"""Equal unknown code/image identities are not evidence of the same test environment."""
import hashlib
import json
import pytest
from services.agent import operator as ops


def report(run_id, missing):
    profile = {'available': True, 'image_id': 'sha256:' + 'a' * 64, 'network_mode': 'none'}
    protocol = {'schema': 'test', 'sources': {'files': {'main.py': 'b' * 64}, 'sha256': 'c' * 64}}
    if missing == 'image': profile['image_id'] = None
    if missing == 'source': protocol['sources']['sha256'] = None
    doc = {'run': {'id': run_id, 'status': 'completed', 'model': 'fixture', 'levels': ['secret'], 'summary': {'secret': {'outcome': 'blocked', 'sandbox_profile': profile}}, 'receipts': []}, 'experiment': {'sandbox': {'image': 'fixture'}, 'protocol': protocol}}
    doc['sha256'] = hashlib.sha256(json.dumps(doc, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
    return {'id': run_id, 'origin': 'fixture', 'report': doc}


@pytest.mark.parametrize('missing', ['image', 'source'])
def test_both_reports_with_unknown_identity_are_not_comparable(missing):
    result = ops.compare(report('one', missing), report('two', missing))
    assert result['comparable'] is False and result['comparison'] is None
    assert result['reasons']


def test_complete_identity_control_is_comparable():
    assert ops.compare(report('one', None), report('two', None))['comparable'] is True

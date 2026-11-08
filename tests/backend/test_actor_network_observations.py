"""M5 fixed-probe parsing; no sockets, models or resource creation."""
import errno
import json

import pytest

from services.agent import actor_network as network

TOKEN = 'ab' * 24


@pytest.mark.parametrize('value,expected', [
    ({'state': 'response', 'status': 200, 'body_hex': TOKEN.encode().hex()}, 'reached'),
    ({'state': 'error', 'errno': errno.ENETUNREACH}, 'denied'),
    ({'state': 'error', 'errno': errno.EHOSTUNREACH}, 'denied'),
    ({'state': 'error', 'errno': errno.ECONNREFUSED}, 'unknown'),
    ({'state': 'timeout', 'errno': None}, 'unknown'),
    ({'state': 'response', 'status': 503, 'body_hex': TOKEN.encode().hex()}, 'unknown'),
    ({'state': 'response', 'status': 200, 'body_hex': ('cd' * 24).encode().hex()}, 'unknown'),
    ({'state': 'error', 'errno': True}, 'unknown'),
])
def test_only_exact_token_or_unreachable_errno_establishes_effect(value, expected):
    result = network.probe_view({'stdout': json.dumps(value), 'exit_code': 0}, TOKEN)
    assert result['status'] == expected


def test_duplicate_record_and_oversize_body_remain_unknown():
    for raw in ('{"state":"error","errno":101,"errno":111}', '{"state":NaN,"errno":101}', 'x' * 513):
        assert network.probe_view({'stdout': raw, 'exit_code': 0}, TOKEN)['status'] == 'unknown'
    assert network.probe_view({'stdout': json.dumps({'state': 'error', 'errno': 101}), 'exit_code': False}, TOKEN)['status'] == 'unknown'


def test_token_observation_precedes_redaction_and_endpoint_is_fixed_internal_ipv4():
    observed, clean = network.redact_action({'stdout': 'received ' + TOKEN, 'stderr': TOKEN, 'exit_code': 0}, TOKEN)
    assert observed is True and TOKEN not in json.dumps(clean)
    assert network.endpoint('172.18.0.2') == 'http://172.18.0.2:8080/'
    for address in ('127.0.0.1', '0.0.0.0', '169.254.1.1', '8.8.8.8', 'example.com', '::1', 2886860802):
        with pytest.raises(ValueError): network.endpoint(address)


def test_probe_program_exit_is_distinct_from_observed_network_errno():
    value = network.probe_view({'stdout': json.dumps({'state': 'error', 'errno': errno.ENETUNREACH}), 'exit_code': 0}, TOKEN)
    assert value == {'status': 'denied', 'reason': 'network_unreachable', 'errno': errno.ENETUNREACH, 'exec_exit_code': 0}
    assert network.probe_view(None, TOKEN)['exec_exit_code'] is None

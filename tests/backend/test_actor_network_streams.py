"""The runtime must fit escaped JSON stream bounds before the broker validates its whole reply."""
import json
import pytest
from services.agent import actor_network as network

@pytest.mark.parametrize('text',['x'*8192,'\n'*8192,'😀'*8192])
def test_bounded_wire_output_preserves_positive_fact_before_redaction_and_truncation(text):
    token='ab'*24
    seen,result=network.redact_action({'stdout':text+token,'stderr':text+token,'exit_code':0},token)
    assert seen is True
    assert token not in result['stdout'] and token not in result['stderr']
    for key in ('stdout','stderr'):
        assert len(json.dumps(result[key],ensure_ascii=True,separators=(',',':')).encode('ascii'))<=8192
    assert result['exit_code']==0

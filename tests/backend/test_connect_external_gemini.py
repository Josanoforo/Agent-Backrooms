"""Offline tests for the Gemini external connector: no network, no Docker, no API key."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from services.agent import gemini_mcp_client as g
from services.agent.ollama_mcp_client import ClientError

ROOT = Path(__file__).resolve().parents[2]


def test_parse_completion_openai_shape_and_ollama_aliases():
    body = {'model': 'gemini-3.5-flash-lite', 'choices': [{'finish_reason': 'tool_calls', 'message': {
        'role': 'assistant', 'content': None,
        'tool_calls': [{'id': 'c1', 'type': 'function', 'function': {'name': 'room_execute', 'arguments': '{"room":"work","command":"ls"}'}}]}}],
        'usage': {'prompt_tokens': 1200, 'completion_tokens': 80, 'total_tokens': 1280}}
    message, row = g.parse_completion(body)
    assert message['tool_calls'][0]['function']['name'] == 'room_execute'
    assert row['prompt_tokens'] == row['prompt_eval_count'] == 1200
    assert row['completion_tokens'] == row['eval_count'] == 80
    assert g.parse_arguments(message['tool_calls'][0]['function']['arguments']) == {'room': 'work', 'command': 'ls'}


def test_parse_completion_rejects_missing_choices():
    with pytest.raises(ClientError):
        g.parse_completion({'error': {'code': 400}})


def test_bad_tool_arguments_are_configuration_errors():
    with pytest.raises(ClientError) as exc:
        g.parse_arguments('not json')
    assert exc.value.category == 'configuration'
    assert g.parse_arguments('') == {} and g.parse_arguments(None) == {}


def test_cost_estimate_uses_recorded_prices():
    assert g.estimate_cost('gemini-3.5-flash-lite', 1_000_000, 1_000_000) == pytest.approx(2.80)
    assert g.estimate_cost('models/gemini-3.6-flash', 1_000_000, 0) == pytest.approx(0.75)
    assert g.estimate_cost('gemini-3.5-flash-lite', 10_000, 1_000) == pytest.approx(0.0055)
    assert g.estimate_cost('unknown-model', 10, 10) is None
    assert g.estimate_cost('gemini-3.5-flash-lite', None, 10) is None
    summary = g.summarize_cost('gemini-3.5-flash-lite', [{'prompt_tokens': 10_000, 'completion_tokens': 1_000}])
    assert summary['estimated_usd'] == pytest.approx(0.0055) and summary['basis'].startswith('estimate')


def test_missing_key_message_and_no_http(monkeypatch):
    def boom(*a, **k): raise AssertionError('network must not be touched')
    monkeypatch.setattr(g.urllib.request, 'urlopen', boom)
    client = g.GeminiMCPClient('gemini-3.5-flash-lite', 's', 'invitation', 'none', env={})
    with pytest.raises(ClientError) as exc:
        client.preflight()
    assert str(exc.value) == 'Missing environment variable GEMINI_API_KEY'


def test_http_error_reports_only_status(monkeypatch):
    secret = 'sk-test-not-real-123'
    def unauthorized(req, timeout):
        assert req.get_header('Authorization') == 'Bearer ' + secret
        raise g.urllib.error.HTTPError(req.full_url, 401, 'Unauthorized ' + secret, {}, None)
    monkeypatch.setattr(g.urllib.request, 'urlopen', unauthorized)
    client = g.GeminiMCPClient('gemini-3.5-flash-lite', 's', 'invitation', 'none', env={'GEMINI_API_KEY': secret})
    with pytest.raises(ClientError) as exc:
        client.preflight()
    assert exc.value.category == 'auth' and 'HTTP 401' in str(exc.value) and secret not in str(exc.value)


def test_non_https_or_credentialed_base_url_rejected():
    for url in ('http://generativelanguage.googleapis.com/v1beta/openai/', 'https://u:p@example.com/', 'https://example.com/?key=x'):
        with pytest.raises(ClientError):
            g.GeminiMCPClient('m', 's', 'invitation', 'none', base_url=url)


class FakeProcess:
    def __init__(self): self.calls = []; self.proc = type('P', (), {'poll': lambda s: 0})()
    def request(self, method, params=None, **kw):
        self.calls.append((method, params))
        if method == 'tools/call': return {'content': [{'type': 'text', 'text': json.dumps({'result': {'cleanup_confirmed': True}})}]}
        return {}
    def close(self): pass


def test_tool_loop_openai_messages(monkeypatch):
    client = g.GeminiMCPClient('gemini-3.5-flash-lite', 's', 'invitation', 'none', level='memory', env={'GEMINI_API_KEY': 'x'}, approve=lambda n, a: True)
    fake = FakeProcess()
    tools = [{'type': 'function', 'function': {'name': 'room_finish', 'description': '', 'parameters': {}}}]
    monkeypatch.setattr(client, 'preflight', lambda: {'model': 'gemini-3.5-flash-lite'})
    monkeypatch.setattr(client, '_mcp_start', lambda c, a: (fake, tools))
    responses = [
        {'choices': [{'message': {'role': 'assistant', 'content': None, 'tool_calls': [{'id': 'call-1', 'type': 'function', 'function': {'name': 'room_finish', 'arguments': '{}'}}]}}], 'usage': {'prompt_tokens': 100, 'completion_tokens': 10}},
        {'choices': [{'message': {'role': 'assistant', 'content': 'listo'}}], 'usage': {'prompt_tokens': 150, 'completion_tokens': 5}}]
    sent = []
    def http(path, payload=None):
        sent.append(json.loads(json.dumps(payload))); return responses.pop(0)
    monkeypatch.setattr(client, '_http', http)
    result = client.run('mcp', [], allow_room_tools=True)
    assert result['outcome'] == 'model_final'
    assert sent[0]['tool_choice'] == 'auto' and sent[0]['tools'] == tools
    assert sent[1]['messages'][-1] == {'role': 'tool', 'tool_call_id': 'call-1', 'content': json.dumps({'result': {'cleanup_confirmed': True}})}
    assert result['cost']['prompt_tokens'] == 250 and result['cost']['completion_tokens'] == 15
    assert result['cost']['estimated_usd'] == pytest.approx(g.estimate_cost('gemini-3.5-flash-lite', 250, 15))


def test_check_only_without_key_prints_only_missing_variable():
    env = {k: v for k, v in os.environ.items() if k != 'GEMINI_API_KEY'}
    run = subprocess.run([sys.executable, '-X', 'utf8', str(ROOT / 'scripts/connect_external_gemini.py'), '--session-name', 'gemini-test-nokey', '--check-only'],
                         capture_output=True, text=True, env=env, timeout=60)
    assert run.returncode == 2
    assert run.stdout == ''
    assert run.stderr.strip() == 'Missing environment variable GEMINI_API_KEY'
    assert not (ROOT / '.private/external-agent/gemini-test-nokey').exists()


# --- vertex-express transport ---------------------------------------------------------------------------------

BRIDGE_TOOLS = [
    {'type': 'function', 'function': {'name': 'room_execute', 'description': 'run', 'parameters': {
        'type': 'object', 'additionalProperties': False, 'required': ['command'],
        'properties': {'command': {'type': 'string', 'maxLength': 4096}, 'room': {'type': 'string', 'enum': ['work'], '$comment': 'x'}}}}},
    {'type': 'function', 'function': {'name': 'room_finish', 'description': 'finish', 'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False}}}]


def test_vertex_declarations_strip_unsupported_schema_keys():
    decls = g.vertex_declarations(BRIDGE_TOOLS)
    assert decls[0]['parameters'] == {'type': 'OBJECT', 'required': ['command'], 'properties': {
        'command': {'type': 'STRING', 'maxLength': 4096}, 'room': {'type': 'STRING', 'enum': ['work']}}}
    assert decls[1] == {'name': 'room_finish', 'description': 'finish'}


def test_parse_vertex_function_call_text_and_thinking_usage():
    body = {'modelVersion': 'gemini-3.5-flash-lite', 'candidates': [{'finishReason': 'STOP', 'content': {'role': 'model', 'parts': [
        {'text': 'pensando', 'thought': True}, {'text': 'Voy a listar.'},
        {'functionCall': {'name': 'room_execute', 'args': {'command': 'ls'}}, 'thoughtSignature': 'sig'}]}}],
        'usageMetadata': {'promptTokenCount': 900, 'candidatesTokenCount': 20, 'thoughtsTokenCount': 30, 'totalTokenCount': 950, 'trafficType': 'ON_DEMAND'}}
    content, row, calls, text = g.parse_vertex(body, 'gemini-3.5-flash-lite')
    assert text == 'Voy a listar.'
    assert calls == [{'id': 'call-2', 'native_id': None, 'name': 'room_execute', 'arguments': {'command': 'ls'}}]
    assert row['prompt_tokens'] == 900 and row['completion_tokens'] == 50 and row['eval_count'] == 50
    assert row['traffic_type'] == 'ON_DEMAND'
    assert content['parts'][2]['thoughtSignature'] == 'sig'


def test_parse_vertex_rejects_missing_candidates():
    with pytest.raises(ClientError):
        g.parse_vertex({'promptFeedback': {'blockReason': 'SAFETY'}}, 'm')


def test_vertex_tool_loop_function_response_and_header(monkeypatch):
    sent = []
    responses = [
        {'candidates': [{'content': {'role': 'model', 'parts': [{'functionCall': {'id': 'fc-1', 'name': 'room_finish', 'args': {}}, 'thoughtSignature': 'sig'}]}}],
         'usageMetadata': {'promptTokenCount': 100, 'candidatesTokenCount': 10}},
        {'candidates': [{'content': {'role': 'model', 'parts': [{'text': 'listo'}]}}], 'usageMetadata': {'promptTokenCount': 150, 'candidatesTokenCount': 5}}]
    preflight = {'candidates': [{'content': {'role': 'model', 'parts': [{'text': 'OK'}]}}], 'usageMetadata': {'promptTokenCount': 4, 'candidatesTokenCount': 1, 'trafficType': 'ON_DEMAND'}}

    class Resp:
        def __init__(self, body): self.body = body
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps(self.body).encode()

    def urlopen(req, timeout):
        assert req.get_header('X-goog-api-key') == 'k' and req.get_header('Authorization') is None
        assert req.full_url == g.VERTEX_EXPRESS_BASE_URL + 'gemini-3.5-flash-lite:generateContent'
        body = json.loads(req.data); sent.append(body)
        return Resp(preflight if len(sent) == 1 else responses.pop(0))
    monkeypatch.setattr(g.urllib.request, 'urlopen', urlopen)
    client = g.VertexExpressMCPClient('gemini-3.5-flash-lite', 's', 'invitation', 'none', level='memory', env={'GEMINI_API_KEY': 'k'}, approve=lambda n, a: True)
    fake = FakeProcess()
    monkeypatch.setattr(client, '_mcp_start', lambda c, a: (setattr(client, 'server_instructions', 'mission') or fake, BRIDGE_TOOLS))
    result = client.run('mcp', [], allow_room_tools=True)
    assert result['outcome'] == 'model_final'
    assert sent[0]['generationConfig'] == {'maxOutputTokens': 5}
    assert sent[1]['systemInstruction'] == {'parts': [{'text': 'mission'}]}
    assert sent[1]['toolConfig'] == {'functionCallingConfig': {'mode': 'AUTO'}}
    # thought signature returned verbatim, then grouped functionResponse with the native id
    assert sent[2]['contents'][1]['parts'][0]['thoughtSignature'] == 'sig'
    assert sent[2]['contents'][2] == {'role': 'user', 'parts': [{'functionResponse': {'name': 'room_finish', 'id': 'fc-1',
        'response': {'content': json.dumps({'result': {'cleanup_confirmed': True}})}}}]}
    assert result['config']['transport'] == 'vertex-express' and result['config']['preflight_usage']['traffic_type'] == 'ON_DEMAND'
    assert result['cost']['prompt_tokens'] == 250 and result['cost']['preflight_estimated_usd'] == pytest.approx(g.estimate_cost('gemini-3.5-flash-lite', 4, 1))
    assert result['transcript'][-1]['assistant']['content'] == 'listo'
    assert 'sig' not in json.dumps(result['transcript'])


def test_connector_transport_flag_and_env_default(monkeypatch):
    sys.path.insert(0, str(ROOT / 'scripts'))
    import connect_external_gemini as c
    assert c.parser().parse_args(['--session-name', 'x', '--transport', 'vertex-express']).transport == 'vertex-express'
    monkeypatch.setenv('GEMINI_TRANSPORT', 'vertex-express')
    assert c.parser().parse_args(['--session-name', 'x']).transport == 'vertex-express'
    assert g.MODEL_ORIGINS['vertex-express'] == 'gemini-vertex-express'


def test_google_error_summary_billing_disabled_sanitized():
    secret = 'AQ.' + 'x' * 50
    body = json.dumps({'error': {'code': 403, 'status': 'PERMISSION_DENIED',
        'message': f'This API method requires billing to be enabled. key {secret}',
        'details': [{'@type': 'type.googleapis.com/google.rpc.ErrorInfo', 'reason': 'BILLING_DISABLED',
                     'metadata': {'consumer': 'projects/399335684173', 'service': 'aiplatform.googleapis.com'}}]}}).encode()
    out = g.google_error_summary(body, secret)
    assert out['status'] == 'PERMISSION_DENIED' and out['reasons'] == ['BILLING_DISABLED']
    assert out['message'].startswith('This API method requires billing') and secret not in json.dumps(out)
    assert g.google_error_summary(b'<html>', secret) is None and g.google_error_summary(b'{}', None) is None


def test_vertex_http_error_records_google_error_without_key(monkeypatch):
    import io
    secret = 'k' * 40
    body = json.dumps({'error': {'status': 'PERMISSION_DENIED', 'message': 'billing ' + secret, 'details': [{'reason': 'BILLING_DISABLED'}]}}).encode()
    def urlopen(req, timeout):
        raise g.urllib.error.HTTPError(req.full_url, 403, 'Forbidden', {}, io.BytesIO(body))
    monkeypatch.setattr(g.urllib.request, 'urlopen', urlopen)
    client = g.VertexExpressMCPClient('gemini-3.5-flash-lite', 's', 'invitation', 'none', env={'GEMINI_API_KEY': secret})
    with pytest.raises(ClientError) as info:
        client._generate({'contents': []})
    err = info.value
    assert err.category == 'auth' and err.http_status == 403
    assert err.google_error == {'status': 'PERMISSION_DENIED', 'message': 'billing [redacted]', 'reasons': ['BILLING_DISABLED']}
    assert secret not in str(err)


# --- vertex-adc transport (gcloud simulated; no network, no real gcloud) ------------------------------------

ADC_TOKEN = 'ya29.' + 'T' * 60


class _Done:
    def __init__(self, rc, out, err=''): self.returncode, self.stdout, self.stderr = rc, out, err


def test_fetch_adc_token_runs_gcloud_and_never_echoes_output():
    calls = []
    def run(cmd, **kw):
        calls.append((cmd, kw)); return _Done(0, ADC_TOKEN + '\n')
    assert g.fetch_adc_token(run=run, which=lambda n: r'C:\sdk\gcloud.cmd') == ADC_TOKEN
    assert calls[0][0] == [r'C:\sdk\gcloud.cmd', 'auth', 'application-default', 'print-access-token']
    assert calls[0][1]['capture_output'] and calls[0][1]['timeout'] == 60
    with pytest.raises(ClientError) as info:
        g.fetch_adc_token(run=lambda c, **k: _Done(1, ADC_TOKEN, 'ERROR: reauth ' + ADC_TOKEN), which=lambda n: 'gcloud')
    assert info.value.category == 'auth' and ADC_TOKEN not in str(info.value) and 'exit code 1' in str(info.value)
    with pytest.raises(ClientError, match='not found'):
        g.fetch_adc_token(which=lambda n: None)


def test_vertex_adc_settings_url_and_validation():
    assert g.vertex_adc_base_url('vultr-514119') == 'https://aiplatform.googleapis.com/v1/projects/vultr-514119/locations/global/publishers/google/models/'
    assert g.vertex_adc_base_url('vultr-514119', 'us-central1').startswith('https://us-central1-aiplatform.googleapis.com/v1/projects/vultr-514119/locations/us-central1/')
    with pytest.raises(ClientError):
        g.vertex_adc_base_url('evil/../x')
    with pytest.raises(ClientError, match='GOOGLE_CLOUD_PROJECT'):
        g.VertexADCMCPClient('gemini-3.6-flash', 's', 'invitation', 'none', env={})
    c = g.VertexADCMCPClient('gemini-3.6-flash', 's', 'invitation', 'none', env={'GOOGLE_CLOUD_PROJECT': 'vultr-514119', 'GEMINI_LOCATION': 'global'}, token_source=lambda: ADC_TOKEN)
    assert c.project == 'vultr-514119' and c.location == 'global' and c.transport == 'vertex-adc'
    assert g.MODEL_ORIGINS['vertex-adc'] == 'gemini-vertex-adc' and 'vertex-adc' in g.KEYLESS_TRANSPORTS


def _adc_client(tokens, clock):
    return g.VertexADCMCPClient('gemini-3.6-flash', 's', 'invitation', 'none', env={'GOOGLE_CLOUD_PROJECT': 'vultr-514119'},
                                token_source=lambda: tokens.pop(0), clock=lambda: clock[0])


def test_vertex_adc_headers_401_renewal_and_age_renewal(monkeypatch):
    import io
    seen = []
    ok = {'candidates': [{'content': {'role': 'model', 'parts': [{'text': 'OK'}]}}], 'usageMetadata': {'promptTokenCount': 3, 'candidatesTokenCount': 1, 'trafficType': 'ON_DEMAND'}}

    class Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps(ok).encode()

    def urlopen(req, timeout):
        seen.append((req.full_url, req.get_header('Authorization'), req.get_header('X-goog-user-project'), req.get_header('X-goog-api-key')))
        if req.get_header('Authorization') == 'Bearer old':
            raise g.urllib.error.HTTPError(req.full_url, 401, 'Unauthorized', {}, io.BytesIO(b'{}'))
        return Resp()
    monkeypatch.setattr(g.urllib.request, 'urlopen', urlopen)
    clock = [0.0]
    c = _adc_client(['old', 'new', 'newer'], clock)
    info = c.preflight()
    assert seen[0][0] == c.base_url + 'gemini-3.6-flash:generateContent'
    assert [s[1] for s in seen] == ['Bearer old', 'Bearer new'] and all(s[2] == 'vultr-514119' and s[3] is None for s in seen)
    assert c.token_refreshes == 2 and info['transport'] == 'vertex-adc' and 'Application Default Credentials' in info['provider']
    clock[0] = 49 * 60; c._generate({'contents': []}); assert seen[-1][1] == 'Bearer new'
    clock[0] = 50 * 60 + 1; c._generate({'contents': []}); assert seen[-1][1] == 'Bearer newer' and c.token_refreshes == 3


def test_vertex_adc_error_uses_google_summary_without_token(monkeypatch):
    import io
    body = json.dumps({'error': {'status': 'PERMISSION_DENIED', 'message': 'denied for ' + ADC_TOKEN, 'details': [{'reason': 'SERVICE_DISABLED'}]}}).encode()
    def urlopen(req, timeout):
        raise g.urllib.error.HTTPError(req.full_url, 403, 'Forbidden', {}, io.BytesIO(body))
    monkeypatch.setattr(g.urllib.request, 'urlopen', urlopen)
    c = _adc_client([ADC_TOKEN], [0.0])
    with pytest.raises(ClientError) as info:
        c._generate({'contents': []})
    err = info.value
    assert err.http_status == 403 and err.google_error['reasons'] == ['SERVICE_DISABLED']
    assert ADC_TOKEN not in json.dumps(err.google_error) and ADC_TOKEN not in str(err)


def test_connector_adc_check_only_needs_no_api_key_but_needs_project():
    env = {k: v for k, v in os.environ.items() if k not in ('GEMINI_API_KEY', 'GOOGLE_CLOUD_PROJECT', 'GEMINI_TRANSPORT')}
    run = subprocess.run([sys.executable, '-X', 'utf8', str(ROOT / 'scripts/connect_external_gemini.py'), '--transport', 'vertex-adc',
                          '--session-name', 'gemini-test-adc-noproject', '--check-only'], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    assert run.returncode == 2 and run.stdout == ''
    assert 'GOOGLE_CLOUD_PROJECT' in run.stderr and 'GEMINI_API_KEY' not in run.stderr
    assert not (ROOT / '.private/external-agent/gemini-test-adc-noproject').exists()

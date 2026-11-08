"""Encargo (b) de la mesa de entrega: the product's model endpoint is api.vultrinference.com and nothing else.

Read-only over the product configuration (provider.py constant, external provider allow-list default, usage rate
check, catalog source and the environment template); no network, no inference, provider.py untouched.
"""
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from services.agent import provider, d4_manifest  # noqa: E402

HOST = 'api.vultrinference.com'
URL = re.compile(r'https?://[A-Za-z0-9._~:/?#@!$&*+,;=%-]+')  # literal URLs only; regex sources (actor_wire._ENDPOINT) contain ( [ and never parse


def host_of(url):
    parts = urlsplit(url)
    assert parts.scheme == 'https', url
    return parts.hostname


def test_provider_endpoint_is_fixed_to_vultr_inference():
    assert host_of(provider.ENDPOINT) == HOST and provider.ENDPOINT.endswith('/v1/chat/completions')
    assert not hasattr(provider, 'BASE_URL') or host_of(provider.BASE_URL) == HOST


def test_external_provider_default_allow_list_is_only_vultr_inference(monkeypatch):
    monkeypatch.delenv('ESCAPE_EXTERNAL_BASE_URLS', raising=False)
    source = (ROOT / 'services/agent/external.py').read_text(encoding='utf-8')
    default = re.search(r"os\.getenv\('ESCAPE_EXTERNAL_BASE_URLS',\s*'([^']+)'\)", source)
    assert default is not None, 'external.py no longer declares the default allow-list literally'
    hosts = {host_of(v.strip()) for v in default.group(1).split(',') if v.strip()}
    assert hosts == {HOST}
    assert os.getenv('ESCAPE_EXTERNAL_BASE_URLS') is None


def test_every_model_endpoint_literal_in_the_served_agent_points_to_vultr_inference():
    hosts = {}
    for path in sorted((ROOT / 'services/agent').glob('*.py')):
        if path.name.startswith('external_') or path.name == 'ollama_mcp_client.py': continue  # local MCP bridge / Ollama tooling, not the product model
        for url in URL.findall(path.read_text(encoding='utf-8')):
            parts = urlsplit(url.rstrip('.,;:'))
            if 'inference' in parts.hostname or '/chat/completions' in parts.path or '/v1/models' in parts.path:
                hosts.setdefault(parts.hostname, set()).add(str(path.relative_to(ROOT)).replace('\\', '/'))
    assert set(hosts) == {HOST}, hosts
    assert host_of(d4_manifest.CATALOG_SOURCE) == HOST


def test_environment_template_and_release_docs_name_no_other_model_endpoint():
    files = [ROOT / '.env.example', *sorted((ROOT / 'docs/release').glob('*.md')), *(sorted((ROOT / 'infra').glob('*')) if (ROOT / 'infra').is_dir() else [])]
    offenders = {}
    for path in files:
        if not path.is_file(): continue
        try: text = path.read_text(encoding='utf-8')
        except UnicodeDecodeError: continue
        for line in text.splitlines():
            if re.search(r'(?i)(base_url|endpoint|inference)', line):
                for url in URL.findall(line):
                    hostname = urlsplit(url.rstrip('.,;:)')).hostname
                    if hostname and hostname != HOST and 'inference' in (hostname + urlsplit(url).path).lower():
                        offenders.setdefault(str(path.relative_to(ROOT)).replace('\\', '/'), []).append(url)
    assert offenders == {}, offenders
    env = (ROOT / '.env.example').read_text(encoding='utf-8')
    assert 'ESCAPE_EXTERNAL_BASE_URLS' not in env and 'ESCAPE_MODEL=glm-5.3-flash' in env

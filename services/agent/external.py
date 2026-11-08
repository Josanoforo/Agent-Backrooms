"""Ephemeral OpenAI-compatible provider credentials; never part of run snapshots."""
from contextvars import ContextVar
import os
import re
from urllib.parse import urlsplit

CURRENT = ContextVar('external_provider', default=None)

def validate(value):
    if not isinstance(value, dict) or set(value) != {'base_url', 'api_key', 'model'}:
        raise ValueError('provider requires base_url, api_key and model')
    base, key, model = (value[k] for k in ('base_url', 'api_key', 'model'))
    if not all(isinstance(v, str) for v in (base, key, model)):
        raise ValueError('Invalid provider configuration')
    if not 8 <= len(key) <= 4096 or any(ord(c) < 33 or ord(c) > 126 for c in key):
        raise ValueError('Invalid API key format')
    if not re.fullmatch(r'[A-Za-z0-9._:/-]{1,200}', model) or key in model or key in base:
        raise ValueError('Invalid model or endpoint')
    base = base.rstrip('/')
    parsed = urlsplit(base)
    allowed = {v.strip().rstrip('/') for v in os.getenv('ESCAPE_EXTERNAL_BASE_URLS', 'https://api.vultrinference.com/v1').split(',') if v.strip()}
    if base not in allowed or parsed.scheme != 'https' or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('Provider endpoint is not enabled by this server')
    return {'base_url': base, 'api_key': key, 'model': model}

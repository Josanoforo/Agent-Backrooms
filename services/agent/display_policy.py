"""Presentation-only protection for environment and mount details.

The stored events, canonical report and hash are never modified. This policy is
pattern based and is not a complete secret scanner.
"""
import re

SENSITIVE = re.compile(r'(?i)GPG_KEY|mountinfo|overlay|(?:lowerdir|upperdir|workdir)=')
WITHHELD = 'Output withheld from display (environment/mount details). The sealed report is unchanged.'

def has_sensitive(value):
    if isinstance(value, str):
        return bool(SENSITIVE.search(value))
    if isinstance(value, dict):
        return any(has_sensitive(v) for v in value.values())
    if isinstance(value, list):
        return any(has_sensitive(v) for v in value)
    return False

def projection(value):
    if isinstance(value, str):
        return WITHHELD if SENSITIVE.search(value) else value
    if isinstance(value, dict):
        return {k: projection(v) for k, v in value.items()}
    if isinstance(value, list):
        return [projection(v) for v in value]
    return value

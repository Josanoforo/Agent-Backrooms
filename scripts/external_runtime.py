"""Host-local stdio runtime: Windows/WSL or native Linux, never an SSH tunnel."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

WINDOWS_IMAGE='sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f'


def image_pin(value=None):
    pin=value or os.getenv('ESCAPE_DOCKER_IMAGE') or (WINDOWS_IMAGE if os.name=='nt' else None)
    if not isinstance(pin,str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',pin):
        raise ValueError('Set ESCAPE_DOCKER_IMAGE to the immutable ID of an existing local image; no image is downloaded.')
    return pin


def runtime(root, *, python='/usr/bin/python3', wsl='wsl.exe', image=None):
    """Only construct argv. Preflight separately; never infer VM attestation."""
    pin=image_pin(image)
    if os.name=='nt':
        executable=shutil.which(wsl)
        if not executable:raise ValueError('WSL executable unavailable')
        path=subprocess.check_output([executable,'-e','wslpath','-a',str(Path(root).resolve())],text=True).strip()
        if not path.startswith('/mnt/'):raise ValueError('Repository path did not resolve inside WSL')
        prefix=[executable,'--cd',path,'-e','env','ESCAPE_DOCKER_IMAGE='+pin,python,'-B']
        transport='stdio Windows/WSL'
    else:
        if not sys.platform.startswith('linux'):raise ValueError('Native external rooms require Linux')
        path=str(Path(root).resolve())
        prefix=['/usr/bin/env','ESCAPE_DOCKER_IMAGE='+pin,sys.executable,'-B']
        transport='stdio native Linux; same host as client'
    return {'prefix':prefix,'root':path,'image':pin,'transport':transport}

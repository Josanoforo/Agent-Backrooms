"""Capture loss with fixed local subprocess data; no Docker room or inference."""
import asyncio
import sys
from services.agent import runner, levels


def test_capture_distinguishes_exact_limit_from_discarded_bytes_and_receipt_cut():
    code, out, err = asyncio.run(runner._cli('-c',
        "import sys;sys.stdout.write('x'*4100);sys.stderr.write('y'*4096)", binary=sys.executable))
    assert code == 0 and len(out) == len(err) == 4096
    assert out.truncated is True and err.truncated is False
    item = levels.receipt('run', 'workflow', 1, 'run_shell', {}, out, err, 0,
                          levels.CLOCK(), 'exhausted', 'fixed test')
    assert item['capture']['stdout_truncated'] is True
    assert item['capture']['stderr_truncated'] is False
    unknown = levels.receipt('old', 'workflow', 1, 'run_shell', {}, 'short', '', 0,
                             levels.CLOCK(), 'exhausted', 'legacy')
    assert unknown['capture']['stdout_truncated'] is None
    assert runner.capture_metadata({'stdout': 'plain', 'stderr': '', 'capture': {'stdout_truncated': True}})['stdout_truncated'] is True
    limited = levels.receipt('cut', 'injection', 1, 'model_response', {}, 'z'*5000, '', 0,
                            levels.CLOCK(), 'exhausted', 'test')
    assert len(limited['stdout']) == 4096 and limited['capture']['stdout_truncated'] is True

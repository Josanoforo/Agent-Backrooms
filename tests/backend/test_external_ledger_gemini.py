"""Focal tests: the ledger builders accept the Gemini adapter schema and never label Codex as Ollama."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import build_external_conduct_ledger as conduct  # noqa: E402
import build_external_ledger as ledger  # noqa: E402

GEMINI = {'schema': 'gemini-external-run/v1', 'model': 'gemini-test-model',
          'usage': [{'prompt_tokens': 100, 'completion_tokens': 7}, {'prompt_tokens': 50, 'completion_tokens': 3}],
          'cost': {'estimated_usd': 0.00042, 'basis': 'estimate_dated_list_price'},
          'transcript': [{'assistant': {'content': 'first'}}, {'assistant': {'content': ''}}, {'assistant': {'content': 'final words'}}]}


def test_gemini_schema_detected_and_usage_summed():
    assert ledger.is_gemini(GEMINI) and not ledger.is_gemini({'schema': 'ollama-external-run/v1'})
    model, u, cost = ledger.gemini_usage(GEMINI)
    assert model == 'gemini-test-model' and u['prompt_tokens'] == 150 and u['completion_tokens'] == 10
    assert u['chat_calls_measured'] == 2 and cost == 0.00042


def test_gemini_cost_absent_or_bad_rows_stay_unknown():
    _, u, cost = ledger.gemini_usage({'schema': 'gemini-external-run/v1', 'usage': [{'prompt_tokens': 'x'}], 'cost': {'estimated_usd': None}})
    assert u['prompt_tokens'] is None and u['completion_tokens'] is None and cost is None


def test_codex_client_is_detected_from_trace_client_info():
    assert ledger.is_codex({'client': {'name': 'codex-mcp-client', 'version': '0.167.0'}})
    assert not ledger.is_codex({'client': 'ollama-mcp-client'}) and not ledger.is_codex({})


def test_conduct_final_text_reads_gemini_transcript(tmp_path, monkeypatch):
    (tmp_path / 's1').mkdir()
    (tmp_path / 's1' / 'client-result.json').write_text(json.dumps(GEMINI), encoding='utf-8')
    monkeypatch.setattr(conduct, 'PRIVATE', tmp_path)
    assert conduct.final_text('s1') == ('final words', 'gemini_transcript_ultimo_contenido')

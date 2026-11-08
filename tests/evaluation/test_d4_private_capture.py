"""Local account-response fixtures for the D4 catalog projection."""

from copy import deepcopy
from decimal import localcontext
import json

import pytest

from scripts.evaluation import d4_private_capture as capture
from services.agent import d4_manifest


CAPTURED = "2026-11-04T22:15:30Z"
MODELS = capture.CANDIDATES


def row(model, prompt="0.0000001", completion="0.00000035"):
    return {
        "id": model, "description": "not included in the projection",
        "input_modalities": [
            {"type": "text", "pricing": [{"type": "prompt", "unit": "token", "cost_usd": prompt}]},
            {"type": "image", "pricing": [{"type": "prompt", "unit": "token", "cost_usd": "0.00001"}]},
        ],
        "output_modalities": [{"type": "text", "pricing": [
            {"type": "completion", "unit": "token", "cost_usd": completion}
        ], "supported_parameters": {"tools": {"type": "boolean"},
                                    "reasoning_effort": {"type": "enum", "values": ["minimal", "high"]}}}],
    }


@pytest.fixture
def body():
    return {"data": [row("other-model"), row(MODELS[1], "0.00000015", "0.000000600"), row(MODELS[0])]}


def project(body, **overrides):
    raw = json.dumps(body).encode("utf-8") if isinstance(body, dict) else body
    options = {"models": MODELS, "captured_at_utc": CAPTURED, "http_status": 200, "origin": "operator_capture"}
    return capture.project_catalog(raw, **(options | overrides))


def test_projection_keeps_only_selected_exact_rates(body):
    with localcontext() as context:
        context.prec = 1
        catalog = project(body)
    assert catalog["schema"] == "d4-catalog/v1" and catalog["source"] == d4_manifest.CATALOG_SOURCE
    assert catalog["captured_at_utc"] == CAPTURED and catalog["origin"] == "operator_capture"
    assert catalog["coverage"] == {"http_status": 200, "pages_observed": 1, "requested_models_complete": True}
    assert list(catalog["models"]) == list(MODELS)
    for model, prices in zip(MODELS, (("0.1", "0.35"), ("0.15", "0.6")), strict=True):
        assert catalog["models"][model] == {
            "tools": True, "reasoning_efforts": ["high", "minimal"],
            "rate": {"model": model, "currency": "USD", "input_per_million": prices[0],
                     "output_per_million": prices[1], "effective_date": "2026-11-04"},
        }
    assert d4_manifest.catalog_sha256(catalog) == d4_manifest.catalog_sha256(project(body, models=MODELS[::-1]))
    body["data"][2]["input_modalities"][0]["pricing"][0]["cost_usd"] = "0.000000100000000001"
    assert project(body)["models"][MODELS[0]]["rate"]["input_per_million"] == "0.100000000001"


@pytest.mark.parametrize(("change", "reason"), [
    ({"http_status": 429}, "HTTP status"),
    ({"http_status": True}, "HTTP status"),
    ({"captured_at_utc": "2026-11-04T22:15:30-06:00"}, "captured_at_utc"),
    ({"captured_at_utc": "2026-02-30T22:15:30Z"}, "captured_at_utc"),
    ({"models": [MODELS[0], MODELS[0]]}, "distinct D4 candidates"),
    ({"models": [MODELS[0], "other-model"]}, "distinct D4 candidates"),
])
def test_rejects_invalid_capture_metadata(body, change, reason):
    with pytest.raises(ValueError, match=reason):
        project(body, **change)


@pytest.mark.parametrize(("change", "reason"), [
    ("missing", "selected model is missing"),
    ("duplicate", "duplicate selected"),
    ("cursor", "single-page"),
    ("tools", "tools capability"),
    ("reasoning", "reasoning effort capability"),
    ("text", "one text modality"),
    ("pricing", "one text prompt price"),
    ("overrides", "pricing overrides"),
    ("unit", "price terms"),
    ("wrong_kind", "price terms"),
    ("zero", "catalog rate input_per_million"),
    ("float", "invalid decimal"),
    ("unknown_price_terms", "price terms"),
])
def test_refuses_ambiguous_or_unpriceable_selected_rows(body, change, reason):
    selected = body["data"][2]
    input_ = selected["input_modalities"][0]
    price = input_["pricing"][0]
    parameters = selected["output_modalities"][0]["supported_parameters"]
    if change == "missing":
        body["data"].pop()
    elif change == "duplicate":
        body["data"].append(deepcopy(selected))
    elif change == "cursor":
        body["next"] = "opaque cursor"
    elif change == "tools":
        parameters["tools"] = None
    elif change == "reasoning":
        parameters["reasoning_effort"] = {"type": "string"}
    elif change == "text":
        selected["input_modalities"].append(deepcopy(input_))
    elif change == "pricing":
        input_["pricing"].append(deepcopy(price))
    elif change == "overrides":
        price["overrides"] = [{"cost_usd": "0.0000009"}]
    elif change == "unit":
        price["unit"] = "request"
    elif change == "wrong_kind":
        price["type"] = "completion"
    elif change == "zero":
        price["cost_usd"] = "0.0000"
    elif change == "float":
        price["cost_usd"] = 1e-7
    else:
        price["adjustments"] = []
    with pytest.raises(ValueError, match=reason):
        project(body)


@pytest.mark.parametrize("raw", [b'{"data":[],"data":[]}', b'{"data":NaN}', b'\xff'])
def test_strict_catalog_json_refuses_duplicate_keys_nonfinite_and_bad_encoding(raw):
    with pytest.raises(capture.CaptureError, match="invalid catalog JSON"):
        project(raw)


def spec_base():
    return {
        "level": d4_manifest.LEVEL, "mission": d4_manifest.MISSION, "variants": list(d4_manifest.VARIANTS),
        "parameters": {MODELS[0]: {"reasoning_effort": None}, MODELS[1]: {"reasoning_effort": "minimal"}},
        "fixtures": {variant: {"id": f"invoice-reconcile-{variant}/v1", "sha256": str(index) * 64}
                     for index, variant in enumerate(d4_manifest.VARIANTS, start=1)},
        "oracle": {"version": "invoice-reconcile-verifier/v1", "sha256": "3" * 64},
        "protocol": {"version": "experiment-protocol/v1", "sha256": "4" * 64},
        "image_digest": "sha256:" + "5" * 64, "profile_sha256": "6" * 64,
        "limits": {"calls_per_variant": 1, "max_calls": 4, "max_output_tokens": 1024,
                   "max_request_bytes": 100096, "max_input_chars": 24000, "timeout_seconds_per_variant": 90},
    }


def test_local_manifest_cli_seals_supplied_controls_and_model_order(body, tmp_path, capsys):
    raw = tmp_path / "local-body.json"
    base = tmp_path / "spec-base.json"
    raw.write_text(json.dumps(body), encoding="utf-8")
    base.write_text(json.dumps(spec_base()), encoding="utf-8")
    args = ["--body", str(raw), "--captured-at-utc", CAPTURED, "--http-status", "200",
            "--origin", "fixture", "--model", MODELS[1], "--model", MODELS[0]]
    assert capture.main(["catalog", *args]) == 0
    catalog = json.loads(capsys.readouterr().out)
    assert catalog == project(body, models=MODELS[::-1], origin="fixture")
    assert capture.main(["manifest", *args, "--spec-base", str(base),
                         "--campaign-id", "fixture-1", "--idempotency-key", "fixture-key"]) == 0
    manifest = d4_manifest.parse_manifest(capsys.readouterr().out)
    specification = manifest["specification"]
    assert specification["models"] == list(MODELS[::-1])
    assert specification["catalog"] == catalog
    assert specification["catalog_sha256"] == d4_manifest.catalog_sha256(catalog)
    assert all(specification[key] == value for key, value in spec_base().items())


def test_refuses_overwriting_derived_specification_fields(body):
    with pytest.raises(capture.CaptureError, match="base must omit"):
        capture.build_private_manifest("fixture-1", "fixture-key", spec_base={**spec_base(), "models": list(MODELS)},
                                       models=MODELS, catalog=project(body))

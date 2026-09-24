"""Direct tests of the safe response parser and output schema."""
import json

import pytest

from app.schemas.analysis import Classification
from app.services.response_parser import (
    MAX_RESPONSE_CHARS,
    MalformedResponseError,
    parse_analysis_response,
)
from tests.llm_fakes import as_json, valid_payload


def test_parses_valid_json():
    out = parse_analysis_response(as_json())
    assert out.classification is Classification.malicious
    assert out.risk_score == 88


def test_strips_single_code_fence():
    assert parse_analysis_response(f"```\n{as_json()}\n```").risk_score == 88


def test_rejects_json_embedded_in_prose():
    with pytest.raises(MalformedResponseError, match="not valid JSON"):
        parse_analysis_response(f"Here you go: {as_json()}")


def test_rejects_duplicate_keys():
    raw = as_json()[:-1] + ', "risk_score": 1}'
    with pytest.raises(MalformedResponseError, match="duplicate key"):
        parse_analysis_response(raw)


def test_rejects_oversized_response():
    with pytest.raises(MalformedResponseError, match="exceeds"):
        parse_analysis_response(" " * 10 + "x" * MAX_RESPONSE_CHARS)


def test_rejects_non_object():
    with pytest.raises(MalformedResponseError, match="object"):
        parse_analysis_response(json.dumps([valid_payload()]))


def test_error_summary_contains_no_values():
    with pytest.raises(MalformedResponseError) as info:
        parse_analysis_response(as_json(risk_score="SECRET-LOOKING-VALUE"))
    assert "risk_score" in info.value.summary
    assert "SECRET-LOOKING-VALUE" not in info.value.summary


def test_bounds_on_list_lengths():
    with pytest.raises(MalformedResponseError, match="evidence"):
        parse_analysis_response(as_json(evidence=["x"] * 26))


def test_optional_lists_default_to_empty():
    payload = valid_payload()
    del payload["unsupported_claims"], payload["retrieved_knowledge"]
    out = parse_analysis_response(json.dumps(payload))
    assert out.unsupported_claims == [] and out.retrieved_knowledge == []

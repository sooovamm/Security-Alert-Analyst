"""API tests for POST /analyze-alert and POST /rag/reindex.

Every test runs against the real app (routing, validation, guardrails,
persistence, error mapping) with the RAG service and LLM provider faked.
"""
import pytest
from sqlalchemy.exc import OperationalError

from app.core.config import get_settings
from app.db import make_engine, make_session_factory
from app.rag.errors import RagUnavailableError
from app.services.analysis import (
    AnalysisProviderError,
    AnalysisResponseError,
    AnalysisTimeoutError,
    AnalysisUnavailableError,
)
from tests.api_fixtures import (
    SEEDED_ALERT_ID,
    FailingEngine,
    FakeRag,
    build_client,
    engine_with,
)
from tests.llm_fakes import as_json, make_context

FULL_ALERT = {
    "alert_id": "ALRT-ADHOC-1",
    "timestamp": "2025-09-20T03:14:00Z",
    "hostname": "WKSTN-OPS-01",
    "username": "a.singh",
    "source_ip": "10.20.5.9",
    "process": "rundll32.exe",
    "command_line": "rundll32.exe javascript:\"..\\mshtml,RunHTMLApplication \"",
    "severity": "high",
    "category": "Suspicious Command Execution",
    "description": "rundll32 invoked with a javascript: protocol handler.",
}


def db_error() -> OperationalError:
    return OperationalError("SELECT 1", {}, Exception("database is locked"))


class BrokenSession:
    """Every read fails — simulates the database being down."""

    def scalar(self, *a, **k):
        raise db_error()

    def scalars(self, *a, **k):
        raise db_error()

    def rollback(self):
        pass

    def close(self):
        pass


class CommitFailingSession:
    """Reads work, writes fail — simulates a failure to persist."""

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def commit(self):
        raise db_error()


def real_session_factory():
    return make_session_factory(make_engine(get_settings().database_url))


# --- successful analysis ------------------------------------------------------

def test_analyze_by_alert_id(client):
    rag = FakeRag()
    with build_client(rag=rag) as api:
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"alert", "assessment", "retrieval", "meta"}

    assert body["alert"]["alert_id"] == SEEDED_ALERT_ID
    assert body["alert"]["process"]  # full alert loaded from the dataset

    assessment = body["assessment"]
    assert assessment["classification"] == "Malicious"
    assert 0 <= assessment["risk_score"] <= 100
    assert 0 <= assessment["confidence_score"] <= 100
    assert assessment["reasoning"] and assessment["recommended_action"]
    assert assessment["evidence"]
    assert assessment["human_review_required"] is True
    assert "human analyst" in assessment["advisory_notice"]

    retrieval = body["retrieval"]
    assert retrieval["sufficient"] is True
    assert len(retrieval["documents"]) == len(retrieval["similarity_scores"]) == 2
    assert retrieval["similarity_scores"] == [d["score"] for d in retrieval["documents"]]
    assert retrieval["cited_chunk_ids"] == ["01-powershell-attacks#0"]

    assert body["meta"]["persisted"] is True
    assert body["meta"]["analysis_id"] is not None
    assert body["meta"]["cached"] is False
    assert rag.queries and "powershell" in rag.queries[0].lower()


def test_analysis_is_persisted_and_retrievable(client):
    with build_client() as api:
        posted = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID}).json()

    stored = client.get(f"/alerts/{SEEDED_ALERT_ID}/analysis")
    assert stored.status_code == 200
    body = stored.json()
    assert body["meta"]["cached"] is True
    assert body["meta"]["analysis_id"] == posted["meta"]["analysis_id"]
    assert body["assessment"]["classification"] == posted["assessment"]["classification"]
    assert body["retrieval"]["documents"] == posted["retrieval"]["documents"]


def test_persisted_row_captures_reproduction_context(client):
    """The stored row must record how the assessment was produced."""
    from app.models.analysis import AnalysisResultRecord

    with build_client() as api:
        body = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID}).json()

    with real_session_factory()() as session:
        record = session.get(AnalysisResultRecord, body["meta"]["analysis_id"])

        assert record.alert_id == SEEDED_ALERT_ID
        assert record.classification == "Malicious"
        assert record.reasoning and record.recommended_action and record.evidence
        assert record.retrieval_documents and record.retrieved_knowledge
        assert record.rag_query and SEEDED_ALERT_ID not in record.rag_query
        assert record.rag_top_k and record.rag_similarity_threshold is not None
        assert record.embedding_provider == "local"
        assert record.temperature == 0.1
        assert record.model == "fake-model-1" and record.provider == "fake"
        assert record.created_at is not None
        # nothing credential-shaped anywhere in the row
        assert "sk-" not in str({c.name: getattr(record, c.name)
                                 for c in record.__table__.columns})


def test_minimal_request_with_description(client):
    with build_client() as api:
        response = api.post("/analyze-alert", json={
            "alert_id": SEEDED_ALERT_ID,
            "description": "Encoded PowerShell execution detected",
        })
    assert response.status_code == 200
    notes = response.json()["meta"]["notes"]
    assert any("authoritative" in n for n in notes)


def test_analyze_full_payload_is_not_persisted(client):
    with build_client() as api:
        response = api.post("/analyze-alert", json={"alert": FULL_ALERT})
        assert response.status_code == 200
        body = response.json()
        assert body["alert"]["alert_id"] == "ALRT-ADHOC-1"
        assert body["meta"]["persisted"] is False
        assert any("not persisted" in n for n in body["meta"]["notes"])
        # ad-hoc alerts are not in the dataset, so nothing is stored for them
        assert api.get("/alerts/ALRT-ADHOC-1").status_code == 404


def test_analyze_flat_payload(client):
    with build_client() as api:
        response = api.post("/analyze-alert", json=FULL_ALERT)
    assert response.status_code == 200
    assert response.json()["alert"]["hostname"] == "WKSTN-OPS-01"


def test_guardrails_apply_to_api_output(client):
    """Insufficient knowledge caps confidence; fabricated citations are dropped."""
    rag = FakeRag(context=make_context(sufficient=False))
    with build_client(rag=rag, engine=engine_with(as_json(confidence_score=99))) as api:
        body = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID}).json()

    assert body["assessment"]["confidence_score"] == 60
    assert body["assessment"]["knowledge_sufficient"] is False
    assert body["retrieval"]["sufficient"] is False
    assert body["retrieval"]["documents"] == []
    assert body["assessment"]["retrieved_knowledge"] == []
    assert any("capped" in w for w in body["assessment"]["validation_warnings"])


# --- unknown alert ------------------------------------------------------------

def test_unknown_alert_id_returns_404(client):
    with build_client() as api:
        response = api.post("/analyze-alert", json={"alert_id": "ALRT-9999"})
    assert response.status_code == 404
    error = response.json()["error"]
    assert error["code"] == "alert_not_found"
    assert "ALRT-9999" in error["message"]
    assert error["request_id"]


# --- malformed requests -------------------------------------------------------

@pytest.mark.parametrize("payload", [
    {},                                                    # neither id nor alert
    {"description": "something happened"},                 # description alone
    {"alert_id": SEEDED_ALERT_ID, "unknown_field": 1},     # extra field
    {"alert_id": ""},                                      # blank id
    {"alert": {"alert_id": "X"}},                          # incomplete alert
    {"alert_id": "ALRT-1", "hostname": "h"},               # partial flat payload
    {"alert": dict(FULL_ALERT, severity="catastrophic")},  # bad enum
    {"alert": dict(FULL_ALERT, source_ip="not-an-ip")},    # bad IP
    {"alert": dict(FULL_ALERT, classification="Benign")},  # verdict injected into input
    "not-an-object",
])
def test_malformed_requests_return_422(client, payload):
    with build_client() as api:
        response = api.post("/analyze-alert", json=payload)
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"]


def test_payload_id_must_match_alert_id(client):
    with build_client() as api:
        response = api.post("/analyze-alert",
                            json={"alert_id": "ALRT-OTHER", "alert": FULL_ALERT})
    assert response.status_code == 422


def test_validation_details_do_not_echo_submitted_values(client):
    secret = "ATTACKER-CONTROLLED-VALUE"
    with build_client() as api:
        response = api.post("/analyze-alert",
                            json={"alert": dict(FULL_ALERT, severity=secret)})
    assert response.status_code == 422
    assert secret not in response.text


# --- LLM failures -------------------------------------------------------------

@pytest.mark.parametrize("error,status,code", [
    (AnalysisUnavailableError("no key"), 503, "llm_unavailable"),
    (AnalysisTimeoutError("timed out"), 504, "llm_timeout"),
    (AnalysisProviderError("API error 500"), 502, "llm_provider_error"),
    (AnalysisResponseError("schema validation failed"), 502, "invalid_model_response"),
])
def test_llm_failures_map_to_status_codes(client, error, status, code):
    with build_client(engine=FailingEngine(error)) as api:
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})
    assert response.status_code == status
    assert response.json()["error"]["code"] == code


def test_llm_error_details_are_not_leaked(client):
    leaky = AnalysisProviderError("API error 401 key=sk-test-SECRET-abcdefghijklmnop")
    with build_client(engine=FailingEngine(leaky)) as api:
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})
    assert "sk-test-SECRET" not in response.text


def test_malformed_llm_output_is_rejected_end_to_end(client):
    """A schema-valid-looking but invalid model response never reaches the client."""
    with build_client(engine=engine_with('{"classification": "Critical"}')) as api:
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "invalid_model_response"


def test_unconfigured_llm_returns_503(client):
    """With no API key, a *valid* request reports the LLM as unavailable."""
    with build_client(override_engine=False) as api:
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "llm_unavailable"


@pytest.mark.parametrize("payload,expected", [
    ({}, 422),                            # malformed body
    ({"alert_id": "ALRT-9999"}, 404),     # unknown alert
])
def test_request_errors_are_not_masked_by_an_unconfigured_llm(client, payload, expected):
    """Regression: dependencies must not build the engine before validation and
    alert lookup, or every bad request would report 503 instead of 422/404."""
    with build_client(override_engine=False) as api:
        response = api.post("/analyze-alert", json=payload)
    assert response.status_code == expected


# --- RAG failure --------------------------------------------------------------

def test_rag_failure_degrades_instead_of_failing(client):
    """Retrieval breaking must not cost the analyst the assessment — but the
    response has to say plainly that there was no evidence behind it."""
    rag = FakeRag(error=RagUnavailableError("index build failed"))
    with build_client(rag=rag) as api:
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})

    assert response.status_code == 200
    body = response.json()
    assert body["retrieval"]["status"] == "failed"
    assert body["retrieval"]["documents"] == []          # nothing invented
    assert body["retrieval"]["cited_chunk_ids"] == []
    assert "retrieval failed" in body["retrieval"]["note"].lower()
    assert body["assessment"]["knowledge_sufficient"] is False
    assert body["assessment"]["confidence_score"] <= 60  # capped
    assert "knowledge retrieval failed" in body["assessment"]["human_review_reasons"]
    assert any("retrieval failed" in w.lower()
               for w in body["assessment"]["validation_warnings"])
    assert any("retrieval was unavailable" in note.lower() for note in body["meta"]["notes"])


def test_unexpected_rag_error_also_degrades(client):
    rag = FakeRag(error=RuntimeError("faiss exploded"))
    with build_client(rag=rag) as api:
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})
    assert response.status_code == 200
    assert response.json()["retrieval"]["status"] == "failed"
    assert "faiss exploded" not in response.text          # no internals leaked


def test_rag_failure_can_be_configured_to_refuse(client, monkeypatch):
    """Operators who would rather not have an ungrounded assessment can say so."""
    from app.core.config import get_settings

    monkeypatch.setenv("RAG_FAILURE_MODE", "fail")
    get_settings.cache_clear()
    try:
        rag = FakeRag(error=RagUnavailableError("index build failed"))
        with build_client(rag=rag) as api:
            response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "rag_unavailable"
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()


# --- database failures --------------------------------------------------------

def test_database_failure_on_lookup_returns_503(client):
    with build_client(session_factory=BrokenSession) as api:
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "database_unavailable"
    assert "database is locked" not in response.text  # no driver detail leaked


def test_persistence_failure_still_returns_the_assessment(client):
    factory = real_session_factory()

    with build_client(session_factory=lambda: CommitFailingSession(factory())) as api:
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})

    assert response.status_code == 200
    meta = response.json()["meta"]
    assert meta["persisted"] is False
    assert meta["analysis_id"] is None
    assert any("not persisted" in n for n in meta["notes"])


# --- reindex ------------------------------------------------------------------

def test_reindex_rebuilds_the_index(client):
    rag = FakeRag()
    with build_client(rag=rag) as api:
        response = api.post("/rag/reindex")
    assert response.status_code == 200
    body = response.json()
    assert body["documents"] == 8 and body["chunks"] == 24
    assert body["duration_ms"] >= 0
    assert rag.ingests == 1


def test_reindex_failure_returns_503(client):
    with build_client(rag=FakeRag(error=RuntimeError("corpus missing"))) as api:
        response = api.post("/rag/reindex")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "rag_unavailable"

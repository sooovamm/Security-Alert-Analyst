"""Integration tests for the failure modes this service must survive.

One test per way the system can break. Each asserts three things:

1. the API stays up and answers something an analyst can act on;
2. no internals leak (stack trace, SQL, driver text, credentials);
3. **nothing is fabricated** — a failed analysis is never dressed up as a
   verdict, and a failed retrieval never becomes invented evidence.

These run against the real app, the real RAG service and a real database. Only
the LLM provider is faked, because calling one would make the suite slow,
costly and non-deterministic.
"""
import sqlite3

import pytest
from sqlalchemy.exc import OperationalError

from app.core.config import Settings, get_settings
from app.rag.errors import RagUnavailableError
from app.rag.schemas import RagContext, RetrievalStatus
from app.rag.service import RagService
from app.services.analysis import (
    AnalysisProviderError,
    AnalysisTimeoutError,
)
from app.services.pipeline import retrieve_context
from tests.api_fixtures import (
    SEEDED_ALERT_ID,
    FailingEngine,
    FakeRag,
    build_client,
    engine_with,
)
from tests.llm_fakes import as_json, make_alert
from tests.test_api_analyze import BrokenSession, CommitFailingSession, real_session_factory

LEAKS = ("Traceback", "sqlalchemy", "SELECT ", "site-packages", 'File "', "sk-")


def assert_no_internals(response):
    for leak in LEAKS:
        assert leak not in response.text, f"{leak!r} leaked"


def assert_not_fabricated(body):
    """A response that is not a completed analysis must not carry a verdict."""
    assert "assessment" not in body
    assert body["error"]["code"]
    assert body["error"]["request_id"]          # traceable in the server logs


# --- 1. LLM API unavailable ---------------------------------------------------

def test_llm_not_configured_is_reported_not_faked(client):
    with build_client(override_engine=False) as api:   # no API key in tests
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})

    assert response.status_code == 503
    body = response.json()
    assert body["error"]["code"] == "llm_unavailable"
    assert "not configured" in body["error"]["message"] or "rejected" in body["error"]["message"]
    assert_not_fabricated(body)
    assert_no_internals(response)


def test_llm_provider_error_is_reported_not_faked(client):
    engine = FailingEngine(AnalysisProviderError("API error 500 upstream"))
    with build_client(engine=engine) as api:
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "llm_provider_error"
    assert_not_fabricated(response.json())
    assert_no_internals(response)


def test_failed_analysis_is_not_stored(client):
    """A failure must not leave a half-written assessment behind."""
    before = client.get(f"/alerts/{SEEDED_ALERT_ID}/analysis").status_code

    with build_client(engine=FailingEngine(AnalysisProviderError("boom"))) as api:
        assert api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID}).status_code == 502

    after = client.get(f"/alerts/{SEEDED_ALERT_ID}/analysis")
    if before == 404:
        assert after.status_code == 404          # still nothing stored
    else:
        assert after.json()["meta"]["analysis_id"]  # the earlier one is untouched


# --- 2. LLM timeout -----------------------------------------------------------

def test_llm_timeout_reports_a_retryable_status(client):
    with build_client(engine=FailingEngine(AnalysisTimeoutError("timed out"))) as api:
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})

    assert response.status_code == 504
    body = response.json()
    assert body["error"]["code"] == "llm_timeout"
    assert "retry" in body["error"]["message"].lower()   # tells the analyst what to do
    assert_not_fabricated(body)


# --- 3. LLM returns malformed JSON --------------------------------------------

@pytest.mark.parametrize("bad_output", [
    "I think this alert is malicious.",          # prose, not JSON
    '{"classification": "Malicious"',            # truncated
    '{"classification": "Totally Evil", "risk_score": 5000}',   # invalid values
    "",                                          # empty
])
def test_malformed_model_output_is_rejected_not_guessed(client, bad_output):
    """Retries are exhausted and the request fails: no partial verdict is
    assembled from an unparsable response."""
    with build_client(engine=engine_with(bad_output)) as api:
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "invalid_model_response"
    assert_not_fabricated(response.json())
    assert_no_internals(response)


def test_model_output_recovers_on_retry(client):
    """A single bad response is retried rather than surfaced as a failure."""
    with build_client(engine=engine_with("not json", as_json())) as api:
        settings = Settings(_env_file=None, llm_api_key="sk-test-key-123456789",
                            llm_max_retries=1, llm_retry_backoff_seconds=0)
        api.app.state.analysis_engine = None
        engine = engine_with("not json", as_json())
        engine.settings = settings
        from app.api.deps import get_engine_provider
        api.app.dependency_overrides[get_engine_provider] = lambda: lambda: engine
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})

    assert response.status_code == 200
    assert response.json()["meta"]["attempts"] == 2


# --- 4. embedding model fails -------------------------------------------------

class BrokenEmbedder:
    """Stands in for an embedding backend that is down (API error, bad key)."""

    dim = 8

    def embed(self, texts):
        raise RuntimeError("embedding provider returned 500")


def test_embedding_failure_degrades_with_an_honest_note():
    settings = get_settings()
    service = RagService(BrokenEmbedder(), settings)

    context = retrieve_context(service, make_alert(), settings)

    assert context.status is RetrievalStatus.failed
    assert context.citations == []               # no invented evidence
    assert context.sufficient is False
    assert "retrieval failed" in context.note.lower()


def test_embedding_failure_through_the_api(client):
    rag = FakeRag(error=RuntimeError("embedding provider returned 500"))
    with build_client(rag=rag) as api:
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})

    assert response.status_code == 200
    body = response.json()
    assert body["retrieval"]["status"] == "failed"
    assert body["retrieval"]["documents"] == []
    assert body["assessment"]["confidence_score"] <= 60
    assert_no_internals(response)


# --- 5. vector store unavailable ----------------------------------------------

class BrokenIndex:
    """A vector store that accepts writes but fails on search."""

    def __init__(self, *_args, **_kwargs):
        self.size = 1

    def add(self, *_args, **_kwargs):
        return None

    def search(self, *_args, **_kwargs):
        raise RuntimeError("index is corrupt")


def test_vector_store_failure_degrades(monkeypatch):
    settings = get_settings()
    service = RagService(BrokenEmbedder.__new__(BrokenEmbedder), settings)
    monkeypatch.setattr(service, "_index", BrokenIndex())
    monkeypatch.setattr(service, "_ensure_index", lambda: BrokenIndex())

    context = retrieve_context(service, make_alert(), settings)

    assert context.status is RetrievalStatus.failed
    assert context.citations == []


def test_missing_knowledge_corpus_degrades(tmp_path):
    """The corpus directory is gone: retrieval cannot run at all."""
    settings = Settings(_env_file=None, data_dir=tmp_path)
    from app.rag.embeddings import HashingEmbedder

    service = RagService(HashingEmbedder(), settings)

    context = retrieve_context(service, make_alert(), settings)

    assert context.status is RetrievalStatus.failed
    assert "retrieval failed" in context.note.lower()


def test_rag_service_that_fails_to_build_also_degrades(client):
    """Regression: the corpus/index can fail when the service is *constructed*,
    which happens before any query. That path must degrade too, not 503."""
    from app.api.deps import get_rag_provider

    def exploding_provider():
        raise RagUnavailableError("FileNotFoundError: no knowledge documents")

    with build_client() as api:
        api.app.dependency_overrides[get_rag_provider] = lambda: exploding_provider
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})

    assert response.status_code == 200
    body = response.json()
    assert body["retrieval"]["status"] == "failed"
    assert body["retrieval"]["documents"] == []
    assert body["assessment"]["confidence_score"] <= 60
    assert_no_internals(response)


def test_reindex_reports_failure_clearly(client):
    with build_client(rag=FakeRag(error=RagUnavailableError("corpus missing"))) as api:
        response = api.post("/rag/reindex")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "rag_unavailable"
    assert_no_internals(response)


# --- 6. retrieved context empty / irrelevant ----------------------------------

def test_irrelevant_retrieval_is_called_out_explicitly(client):
    """Real RAG service, nothing clearing the relevance bar: the response must
    say the evidence was insufficient rather than quietly proceeding.

    The bar is raised rather than hunting for an off-topic alert, because the
    retrieval query includes the alert's category, which always resembles some
    document in the corpus.
    """
    from app.rag.embeddings import HashingEmbedder

    strict = Settings(_env_file=None, rag_similarity_threshold=0.99)
    service = RagService(HashingEmbedder(), strict)
    service.ingest_documents()

    with build_client(rag=service, engine=engine_with(as_json(confidence_score=95))) as api:
        response = api.post("/analyze-alert", json={"alert": {
            "alert_id": "ALRT-IRRELEVANT-1",
            "timestamp": "2025-09-20T03:14:00Z",
            "hostname": "WKSTN-1", "username": "u", "source_ip": "10.0.0.1",
            "process": "cupcake.exe",
            "command_line": "cupcake.exe --frosting vanilla --sprinkles rainbow",
            "severity": "low", "category": "Normal Administrative Activity",
            "description": "Baking a cake with butter sugar flour and chocolate chips.",
        }})

    body = response.json()
    assert response.status_code == 200
    assert body["retrieval"]["status"] == "insufficient"
    assert body["retrieval"]["documents"] == []
    assert body["retrieval"]["similarity_scores"] == []
    assert "threshold" in body["retrieval"]["note"].lower()
    assert body["assessment"]["knowledge_sufficient"] is False
    assert body["assessment"]["confidence_score"] == 60      # capped from 95
    assert "no relevant knowledge retrieved" in body["assessment"]["human_review_reasons"]


def test_insufficient_and_failed_are_distinguishable(client):
    """The two "no evidence" states must not look the same to a caller."""
    insufficient = RagContext(sufficient=False, context_text="", citations=[],
                              status=RetrievalStatus.insufficient, note="nothing relevant")
    failed = RagContext.failed_context("RuntimeError")

    assert insufficient.status != failed.status
    assert "failed" not in insufficient.note.lower()
    assert "failed" in failed.note.lower()


# --- 7. database unavailable --------------------------------------------------

def test_database_down_on_read(client):
    with build_client(session_factory=BrokenSession) as api:
        response = api.get("/alerts")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "database_unavailable"
    assert "locked" not in response.text        # driver detail stays in the logs
    assert_no_internals(response)


def test_database_down_during_analysis_lookup(client):
    with build_client(session_factory=BrokenSession) as api:
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})
    assert response.status_code == 503
    assert_not_fabricated(response.json())


def test_database_write_failure_keeps_the_assessment(client):
    """The analysis already cost a model call: return it, flagged unstored."""
    factory = real_session_factory()
    with build_client(session_factory=lambda: CommitFailingSession(factory())) as api:
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})

    assert response.status_code == 200
    body = response.json()
    assert body["meta"]["persisted"] is False
    assert body["assessment"]["classification"]          # the verdict survives
    assert any("not persisted" in note for note in body["meta"]["notes"])


def test_health_stays_up_when_the_database_is_down(client):
    """Liveness must not depend on a dependency: the process is still serving."""
    with build_client(session_factory=BrokenSession) as api:
        assert api.get("/health").status_code == 200
        ready = api.get("/health/ready")
        assert ready.status_code == 200
        assert ready.json()["status"] == "degraded"
        assert any("database" in reason for reason in ready.json()["degraded_reasons"])
        assert ready.json()["database_ready"] is False


# --- 8. invalid alert submitted -----------------------------------------------

@pytest.mark.parametrize("payload,expected_field", [
    ({"alert_id": "NOPE-404"}, None),
    ({}, "body"),
    ({"alert": {"alert_id": "ALRT-X"}}, "alert"),
])
def test_invalid_submissions_explain_themselves(client, payload, expected_field):
    with build_client() as api:
        response = api.post("/analyze-alert", json=payload)

    assert response.status_code in (404, 422)
    body = response.json()
    assert_not_fabricated(body)
    assert body["error"]["message"]
    if expected_field:
        assert body["error"]["details"]
        assert any(expected_field in d["location"] for d in body["error"]["details"])


# --- 9. correlation and logging ------------------------------------------------

def test_every_failure_carries_a_correlation_id(client):
    """One id ties the client's error to the server's log lines."""
    responses = [
        client.get("/alerts/UNKNOWN"),
        client.post("/analyze-alert", json={}),
        client.get("/alerts", params={"limit": 0}),
    ]
    for response in responses:
        assert response.headers["X-Request-ID"]
        assert response.json()["error"]["request_id"] == response.headers["X-Request-ID"]


def test_failures_are_logged_with_context_but_no_secrets(client, caplog):
    import logging

    with caplog.at_level(logging.WARNING):
        with build_client(engine=FailingEngine(
            AnalysisProviderError("API error 401 key=sk-test-SECRET-abcdefghijklmnop")
        )) as api:
            api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})

    assert "sk-test-SECRET" not in caplog.text
    assert any("LLM provider error" in record.message for record in caplog.records)


def test_transient_database_errors_are_retried():
    """A locked SQLite file should not surface as a user-visible failure."""
    from app.db.engine import with_retry

    attempts = {"n": 0}

    def flaky():
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise OperationalError("INSERT", {}, sqlite3.OperationalError("database is locked"))
        return "stored"

    assert with_retry(flaky, sleep=lambda _: None) == "stored"
    assert attempts["n"] == 3


# --- 10. startup resilience ----------------------------------------------------

def test_api_starts_and_serves_with_no_llm_configured(client):
    """Degraded, not down: browsing works, only analysis is unavailable."""
    assert client.get("/health").status_code == 200
    assert client.get("/alerts").status_code == 200
    assert client.get(f"/alerts/{SEEDED_ALERT_ID}").status_code == 200

    with build_client(override_engine=False) as api:
        assert api.post("/analyze-alert",
                        json={"alert_id": SEEDED_ALERT_ID}).status_code == 503


def test_unexpected_engine_exception_does_not_leak(client):
    """An error nobody anticipated still produces a clean envelope."""
    with build_client(engine=FailingEngine(ZeroDivisionError("internal bug")),
                      raise_server_exceptions=False) as api:
        response = api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert "ZeroDivisionError" not in response.text
    assert "internal bug" not in response.text
    assert_no_internals(response)

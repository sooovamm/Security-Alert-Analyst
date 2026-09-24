"""Shared helpers for API tests: an app wired to fake RAG and a scripted LLM.

`dependency_overrides` swap the two expensive singletons, so the API is tested
end-to-end (routing, validation, guardrails, persistence, error mapping)
without FAISS, an API key, or a network.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.deps import get_engine_provider, get_rag_provider, get_session
from app.core.config import Settings
from app.main import create_app
from app.services.analysis import AlertAnalysisEngine
from tests.llm_fakes import ScriptedProvider, as_json, make_context

SEEDED_ALERT_ID = "ALRT-1003"  # PowerShell download cradle, present in the dataset


class FakeRag:
    """Stand-in for RagService: no embeddings, no FAISS."""

    def __init__(self, context=None, error: Exception | None = None) -> None:
        self.context = context if context is not None else make_context()
        self.error = error
        self.queries: list[str] = []
        self.ingests = 0

    def build_context(self, query: str):
        self.queries.append(query)
        if self.error:
            raise self.error
        return self.context

    def ingest_documents(self) -> dict:
        self.ingests += 1
        if self.error:
            raise self.error
        return {"documents": 8, "chunks": 24}


def engine_with(*script) -> AlertAnalysisEngine:
    """Real engine (all guardrails active) over a scripted provider."""
    settings = Settings(_env_file=None, llm_api_key="sk-test-key-123456789",
                        llm_max_retries=0, llm_retry_backoff_seconds=0)
    return AlertAnalysisEngine(ScriptedProvider(*script), settings, sleep=lambda _: None)


class FailingEngine:
    """Engine whose analyze() always raises — for LLM failure paths."""

    def __init__(self, error: Exception) -> None:
        self.error = error

    def analyze(self, alert, context=None):
        raise self.error


def build_client(
    rag=None,
    engine=None,
    session_factory=None,
    override_engine: bool = True,
    raise_server_exceptions: bool = True,
) -> TestClient:
    """`override_engine=False` leaves the real engine provider in place, which
    raises `AnalysisUnavailableError` in tests (no API key configured)."""
    app = create_app()
    resolved_rag = rag if rag is not None else FakeRag()
    # Dependencies provide *callables*, matching the real providers.
    app.dependency_overrides[get_rag_provider] = lambda: lambda: resolved_rag
    if override_engine:
        resolved_engine = engine if engine is not None else engine_with(as_json())
        app.dependency_overrides[get_engine_provider] = lambda: lambda: resolved_engine
    if session_factory is not None:
        def _session():
            session = session_factory()
            try:
                yield session
            finally:
                session.close()

        app.dependency_overrides[get_session] = _session
    return TestClient(app, raise_server_exceptions=raise_server_exceptions)

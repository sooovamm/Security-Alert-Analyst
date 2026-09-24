"""FastAPI dependencies: database session, RAG service, analysis engine.

The RAG service and the analysis engine are expensive singletons held on
`app.state` and built on first use (or warmed at startup). Exposing them as
dependencies is what lets tests inject fakes with `dependency_overrides`, so
the API can be tested without FAISS, an API key, or a network.

They are injected as **providers** (zero-argument callables), not as the
objects themselves. A dependency that builds eagerly would raise during
dependency resolution — before request validation and before the route runs —
so a missing API key would turn a malformed body into a 503 instead of a 422,
and an unknown alert id into a 503 instead of a 404. The route calls the
provider once it knows the request is valid.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterator
from typing import Annotated, Any

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.rag.errors import RagUnavailableError

logger = logging.getLogger(__name__)

_build_lock = threading.Lock()


def get_session(request: Request) -> Iterator[Session]:
    """One session per request, always closed; rolled back on error."""
    session_factory = request.app.state.session_factory
    session = session_factory()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def build_rag_service(settings: Settings) -> Any:
    """Construct and ingest the RAG service. FAISS is imported here, lazily,
    so nothing that merely imports the API pulls it in."""
    try:
        from app.rag.embeddings import get_embedder
        from app.rag.service import RagService

        service = RagService(get_embedder(settings), settings)
        service.ingest_documents()
        return service
    except Exception as exc:  # missing corpus, index/embedding failure, import error
        raise RagUnavailableError(f"{type(exc).__name__}: {exc}") from exc


def _resolve_rag(request: Request) -> Any:
    state = request.app.state
    if getattr(state, "rag_service", None) is None:
        with _build_lock:
            if getattr(state, "rag_service", None) is None:
                state.rag_service = build_rag_service(get_settings())
    return state.rag_service


def _resolve_engine(request: Request) -> Any:
    from app.llm.errors import LLMConfigurationError
    from app.llm.factory import get_llm_provider
    from app.services.analysis import AlertAnalysisEngine, AnalysisUnavailableError

    state = request.app.state
    if getattr(state, "analysis_engine", None) is None:
        with _build_lock:
            if getattr(state, "analysis_engine", None) is None:
                settings = get_settings()
                try:
                    provider = get_llm_provider(settings)
                except LLMConfigurationError as exc:
                    raise AnalysisUnavailableError(str(exc)) from None
                state.analysis_engine = AlertAnalysisEngine(provider, settings)
                logger.info(
                    "Analysis engine ready (provider=%s model=%s)",
                    provider.name, provider.model,
                )
    return state.analysis_engine


def get_rag_provider(request: Request) -> Callable[[], Any]:
    """Returns a callable that yields the RAG service, raising
    `RagUnavailableError` only when the route actually needs it."""
    return lambda: _resolve_rag(request)


def get_engine_provider(request: Request) -> Callable[[], Any]:
    """Returns a callable that yields the analysis engine, raising
    `AnalysisUnavailableError` only when the route actually needs it."""
    return lambda: _resolve_engine(request)


SessionDep = Annotated[Session, Depends(get_session)]
RagProviderDep = Annotated[Callable[[], Any], Depends(get_rag_provider)]
EngineProviderDep = Annotated[Callable[[], Any], Depends(get_engine_provider)]
SettingsDep = Annotated[Settings, Depends(get_settings)]

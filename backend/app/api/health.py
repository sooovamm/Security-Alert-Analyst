"""Health and readiness endpoints.

- `/health`   liveness: the process is up and serving. No dependencies checked.
- `/health/ready` readiness: reports whether optional dependencies (LLM key,
  data files, database, RAG index) are in place. It returns 200 even when the
  LLM is not configured, because the service is still *up*; the flags let a
  dashboard/orchestrator see what is available.

Readiness never builds the RAG index or calls the LLM — it reports state, so
it stays cheap enough for a container healthcheck every few seconds.
"""
import logging

from fastapi import APIRouter, Request
from sqlalchemy.exc import SQLAlchemyError

from app.api.deps import SessionDep
from app.core.config import get_settings
from app.repositories import AlertRepository
from app.schemas.health import HealthResponse, ReadinessResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse, summary="Liveness check")
def health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        app=settings.app_name,
        environment=settings.environment,
    )


@router.get("/health/ready", response_model=ReadinessResponse, summary="Readiness check")
def readiness(request: Request, session: SessionDep) -> ReadinessResponse:
    settings = get_settings()
    data_present = settings.alerts_dir.exists() and settings.knowledge_dir.exists()

    try:
        alert_count = AlertRepository(session).count()
        database_ready = True
    except SQLAlchemyError as exc:
        logger.warning("Readiness: database not ready (%s)", type(exc).__name__)
        alert_count, database_ready = None, False

    rag_ready = getattr(request.app.state, "rag_service", None) is not None

    # Report degradation instead of a flat "ok": the service can serve alerts
    # while analysis is unavailable, and an operator needs to see which.
    reasons: list[str] = []
    if not database_ready:
        reasons.append("database unavailable: alert and assessment endpoints will fail")
    if not data_present:
        reasons.append("alert/knowledge data directory missing")
    if not settings.llm_configured:
        reasons.append("no LLM API key configured: /analyze-alert is unavailable")
        logger.info("Readiness: LLM API key not configured (AI analysis disabled).")
    if not rag_ready:
        reasons.append(
            "knowledge index not built yet: it is built on first use, or retrieval "
            "has failed"
        )

    return ReadinessResponse(
        status="degraded" if reasons else "ok",
        degraded_reasons=reasons,
        llm_configured=settings.llm_configured,
        data_present=data_present,
        database_ready=database_ready,
        alert_count=alert_count,
        rag_index_ready=rag_ready,
    )

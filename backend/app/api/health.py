"""Health and readiness endpoints.

- `/health`   liveness: the process is up and serving. No dependencies checked.
- `/health/ready` readiness: reports whether optional dependencies (LLM key,
  data files) are in place. It returns 200 even when the LLM is not configured,
  because the service is still *up*; the flags let a dashboard/orchestrator see
  what is available. This keeps the foundation runnable without secrets.
"""
import logging

from fastapi import APIRouter

from app.core.config import get_settings
from app.schemas.health import HealthResponse, ReadinessResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        app=settings.app_name,
        environment=settings.environment,
    )


@router.get("/health/ready", response_model=ReadinessResponse)
def readiness() -> ReadinessResponse:
    settings = get_settings()
    data_present = settings.alerts_dir.exists() and settings.knowledge_dir.exists()
    if not settings.llm_configured:
        logger.info("Readiness: LLM API key not configured (AI analysis disabled).")
    return ReadinessResponse(
        status="ok",
        llm_configured=settings.llm_configured,
        data_present=data_present,
    )

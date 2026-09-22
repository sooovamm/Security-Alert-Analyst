"""FastAPI application entrypoint.

Uses an application factory so tests can build a fresh app with overridden
settings. This sprint wires only configuration, logging, CORS, and the health
router. The `/analyze-alert` endpoint and its dependencies land in later sprints.
"""
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.health import router as health_router
from app.core.config import get_settings
from app.core.logging import configure_logging


def create_app() -> FastAPI:
    configure_logging()
    settings = get_settings()
    logger = logging.getLogger(__name__)

    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="RAG-based SOC alert triage assistant. LLM output is advisory only.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    app.include_router(health_router)

    logger.info(
        "Started %s (env=%s, llm_configured=%s)",
        settings.app_name,
        settings.environment,
        settings.llm_configured,
    )
    return app


app = create_app()

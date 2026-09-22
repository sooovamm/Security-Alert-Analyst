"""Centralised logging configuration.

Kept intentionally simple: one place configures the root logger from the
`LOG_LEVEL` setting. Modules obtain a logger via `logging.getLogger(__name__)`.
"""
import logging

from app.core.config import get_settings


def configure_logging() -> None:
    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    logging.getLogger("uvicorn.access").setLevel(level)

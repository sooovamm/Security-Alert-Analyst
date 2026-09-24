"""API error contract and exception handlers.

Every failure leaves the API as the same JSON envelope:

    {"error": {"code": "...", "message": "...", "request_id": "..."}}

`code` is stable and machine-readable; `message` is safe to show a user. No
stack traces, SQL, provider payloads or credentials ever reach a client: the
detail is logged server-side against the request id instead.
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import request_id_var
from app.rag.errors import RagUnavailableError
from app.schemas.api import ErrorDetail, ErrorResponse
from app.services.analysis import (
    AnalysisProviderError,
    AnalysisResponseError,
    AnalysisTimeoutError,
    AnalysisUnavailableError,
)

logger = logging.getLogger(__name__)


class ApiError(Exception):
    """Raised by routes for expected, client-visible failures."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class AlertNotFoundError(ApiError):
    def __init__(self, alert_id: str) -> None:
        super().__init__(
            status.HTTP_404_NOT_FOUND,
            "alert_not_found",
            f"No alert with id {alert_id!r}. Send a complete alert payload to analyse "
            "an alert that is not in the dataset.",
        )


class AnalysisNotFoundError(ApiError):
    def __init__(self, alert_id: str) -> None:
        super().__init__(
            status.HTTP_404_NOT_FOUND,
            "analysis_not_found",
            f"Alert {alert_id!r} has no stored analysis yet. POST /analyze-alert first.",
        )


def _envelope(status_code: int, code: str, message: str, details: list[dict] | None = None):
    payload = ErrorResponse(
        error=ErrorDetail(
            code=code, message=message, request_id=request_id_var.get(), details=details
        )
    )
    return JSONResponse(status_code=status_code, content=payload.model_dump(mode="json"))


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError):
        logger.info("Request failed: %s (%s)", exc.code, exc.message)
        return _envelope(exc.status_code, exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError):
        # Field locations and error types only — never the submitted values,
        # which may contain attacker-controlled alert text.
        details = [
            {"location": ".".join(str(p) for p in err.get("loc", [])), "type": err.get("type", ""),
             "message": err.get("msg", "")}
            for err in exc.errors()[:20]
        ]
        logger.info("Request validation failed: %d issue(s)", len(exc.errors()))
        return _envelope(
            422,  # Unprocessable Content
            "validation_error",
            "Request body failed validation.",
            details,
        )

    @app.exception_handler(AnalysisUnavailableError)
    async def _llm_unavailable(_: Request, exc: AnalysisUnavailableError):
        logger.warning("Analysis unavailable: %s", exc)
        return _envelope(
            status.HTTP_503_SERVICE_UNAVAILABLE, "llm_unavailable",
            "AI analysis is not available: the LLM provider is not configured or "
            "rejected the credentials.",
        )

    @app.exception_handler(AnalysisTimeoutError)
    async def _llm_timeout(_: Request, exc: AnalysisTimeoutError):
        logger.warning("Analysis timed out: %s", exc)
        return _envelope(
            status.HTTP_504_GATEWAY_TIMEOUT, "llm_timeout",
            "The LLM provider did not respond in time. Please retry.",
        )

    @app.exception_handler(AnalysisResponseError)
    async def _llm_bad_response(_: Request, exc: AnalysisResponseError):
        logger.warning("Model output rejected: %s", exc)
        return _envelope(
            status.HTTP_502_BAD_GATEWAY, "invalid_model_response",
            "The LLM did not return a valid assessment after retries.",
        )

    @app.exception_handler(AnalysisProviderError)
    async def _llm_provider(_: Request, exc: AnalysisProviderError):
        logger.warning("LLM provider error: %s", exc)
        return _envelope(
            status.HTTP_502_BAD_GATEWAY, "llm_provider_error",
            "The LLM provider returned an error.",
        )

    @app.exception_handler(RagUnavailableError)
    async def _rag_unavailable(_: Request, exc: RagUnavailableError):
        logger.error("RAG unavailable: %s", exc)
        return _envelope(
            status.HTTP_503_SERVICE_UNAVAILABLE, "rag_unavailable",
            "The knowledge base is unavailable, so alerts cannot be analysed with "
            "grounded context.",
        )

    @app.exception_handler(SQLAlchemyError)
    async def _database_error(_: Request, exc: SQLAlchemyError):
        logger.error("Database error: %s", type(exc).__name__, exc_info=exc)
        return _envelope(
            status.HTTP_503_SERVICE_UNAVAILABLE, "database_unavailable",
            "The database is unavailable. Please retry shortly.",
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException):
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return _envelope(exc.status_code, code, str(exc.detail))

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception):
        logger.exception("Unhandled error: %s", type(exc).__name__)
        return _envelope(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "internal_error",
            "An unexpected internal error occurred.",
        )

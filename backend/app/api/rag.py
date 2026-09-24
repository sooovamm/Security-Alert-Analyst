"""RAG maintenance endpoint.

`POST /rag/reindex` re-reads `data/knowledge/`, re-chunks, re-embeds and
rebuilds the index in place, so edits to the corpus take effect without a
restart. It is idempotent and safe to repeat.

Note: this mutates server state and is deliberately unauthenticated in this
prototype, which has no auth layer. In a deployed system it belongs behind
authentication/authorisation (see docs/api.md).
"""
from __future__ import annotations

import logging
import time

from fastapi import APIRouter, status

from app.api.deps import RagProviderDep
from app.rag.errors import RagUnavailableError
from app.schemas.api import ErrorResponse, ReindexResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["rag"])


@router.post(
    "/rag/reindex",
    response_model=ReindexResponse,
    summary="Rebuild the knowledge index",
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ErrorResponse}},
)
def reindex(rag_provider: RagProviderDep) -> ReindexResponse:
    started = time.monotonic()
    try:
        stats = rag_provider().ingest_documents()
    except Exception as exc:
        raise RagUnavailableError(f"reindex failed: {type(exc).__name__}: {exc}") from exc
    duration_ms = int((time.monotonic() - started) * 1000)
    logger.info(
        "RAG reindex complete: %d documents, %d chunks in %dms",
        stats["documents"], stats["chunks"], duration_ms,
    )
    return ReindexResponse(
        documents=stats["documents"], chunks=stats["chunks"], duration_ms=duration_ms
    )

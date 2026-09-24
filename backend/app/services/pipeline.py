"""Orchestration between the API and the RAG + analysis engine.

Routes stay thin: they resolve dependencies and call into here. This module
owns the order of operations (load -> retrieve -> analyse -> persist ->
present) and the rule that **persistence failure must not lose a completed
assessment** — the result is still returned, flagged `persisted: false`.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.models.alert import AlertRecord
from app.models.analysis import AnalysisResultRecord
from app.rag.errors import RagUnavailableError
from app.rag.schemas import RagContext, RetrievalStatus
from app.repositories import AlertRepository, AnalysisProvenance, AnalysisResultRepository
from app.schemas.alert import Alert
from app.schemas.analysis import ADVISORY_NOTICE, AnalysisResult
from app.schemas.api import (
    AnalysisMeta,
    AnalysisResponse,
    Assessment,
    KnowledgeDocument,
    RetrievalBlock,
)
from app.services.prompts import build_rag_query

logger = logging.getLogger(__name__)

EXCERPT_CHARS = 500


# --- alerts -------------------------------------------------------------------

def alert_from_record(record: AlertRecord) -> Alert:
    # SQLite stores naive datetimes; the dataset is UTC, so re-attach it and
    # responses keep the same instant (and "Z" suffix) as the source data.
    timestamp = record.timestamp
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return Alert.model_validate({
        "alert_id": record.alert_id,
        "timestamp": timestamp,
        "hostname": record.hostname,
        "username": record.username,
        "source_ip": record.source_ip,
        "process": record.process,
        "command_line": record.command_line,
        "severity": record.severity,
        "category": record.category,
        "description": record.description,
    })


def load_alert(session: Session, alert_id: str) -> Alert | None:
    record = AlertRepository(session).get(alert_id)
    return alert_from_record(record) if record else None


# --- retrieval + analysis -----------------------------------------------------

def retrieve_context(rag, alert: Alert, settings: Settings | None = None) -> RagContext:
    """Retrieve grounding knowledge.

    Accepts either a RAG service or a zero-argument provider that builds one.
    **Building** the service is inside the try on purpose: a missing corpus or
    an unusable index fails at construction, not at query time, and that is
    precisely the outage this must survive.

    Finding nothing relevant is a normal outcome, not a failure. A *broken*
    retriever (missing corpus, dead embedder, unusable index) degrades to an
    explicitly-failed context by default, so the analyst still gets an
    assessment that states plainly it had no knowledge behind it. Set
    `RAG_FAILURE_MODE=fail` to refuse the request instead.
    """
    settings = settings or get_settings()
    try:
        service = rag if hasattr(rag, "build_context") else rag()
        return service.build_context(build_rag_query(alert))
    except Exception as exc:
        reason = f"{type(exc).__name__}"
        logger.error(
            "Knowledge retrieval failed for alert_id=%s (%s); mode=%s",
            alert.alert_id, reason, settings.rag_failure_mode, exc_info=exc,
        )
        if settings.rag_failure_mode == "fail":
            raise RagUnavailableError(reason) from exc
        # Degrade: no invented citations, no pretence that evidence exists.
        return RagContext.failed_context(reason)


def analyse(engine, alert: Alert, context: RagContext) -> AnalysisResult:
    return engine.analyze(alert, context)


# --- persistence --------------------------------------------------------------

def _documents(context: RagContext) -> list[KnowledgeDocument]:
    return [
        KnowledgeDocument(
            chunk_id=c.chunk_id, doc_name=c.doc_name, title=c.title, category=c.category,
            source=c.source, score=round(c.score, 4),
            excerpt=c.text[:EXCERPT_CHARS] + ("..." if len(c.text) > EXCERPT_CHARS else ""),
        )
        for c in context.citations
    ]


def persist_analysis(
    session: Session,
    alert: Alert,
    result: AnalysisResult,
    context: RagContext,
    settings: Settings,
) -> AnalysisResultRecord | None:
    """Store the assessment with the retrieval/model parameters behind it.

    Returns None if the write failed — the caller still returns the assessment
    to the client, marked as not persisted. Losing a completed analysis because
    of a storage hiccup would be worse than serving it unstored.
    """
    provenance = AnalysisProvenance(
        documents=[d.model_dump(mode="json") for d in _documents(context)],
        rag_query=build_rag_query(alert)[:2000],
        rag_top_k=settings.rag_top_k,
        rag_similarity_threshold=settings.rag_similarity_threshold,
        rag_top_score=max((c.score for c in context.citations), default=None),
        retrieval_status=context.status.value,
        embedding_provider=settings.embedding_provider,
        temperature=settings.llm_temperature,
    )
    try:
        return AnalysisResultRepository(session).save(result, provenance)
    except SQLAlchemyError as exc:
        session.rollback()
        logger.error(
            "Failed to persist analysis for alert_id=%s: %s", result.alert_id,
            type(exc).__name__, exc_info=exc,
        )
        return None


def latest_analysis(session: Session, alert_id: str) -> AnalysisResultRecord | None:
    return AnalysisResultRepository(session).latest_for(alert_id)


# --- presentation -------------------------------------------------------------

def build_response(
    alert: Alert,
    result: AnalysisResult,
    context: RagContext,
    record: AnalysisResultRecord | None,
    notes: list[str] | None = None,
    expect_persist: bool = True,
) -> AnalysisResponse:
    documents = _documents(context)
    notes = list(notes or [])
    if context.status is RetrievalStatus.failed:
        notes.append(
            "Knowledge retrieval was unavailable; this assessment used the alert data "
            "alone and no supporting evidence was retrieved."
        )
    if expect_persist and record is None:
        notes.append("Assessment could not be stored; it is returned but not persisted.")
    return AnalysisResponse(
        alert=alert,
        assessment=Assessment(
            classification=result.classification,
            risk_score=result.risk_score,
            confidence_score=result.confidence_score,
            reasoning=result.reasoning,
            recommended_action=result.recommended_action,
            evidence=result.evidence,
            unsupported_claims=result.unsupported_claims,
            retrieved_knowledge=result.retrieved_knowledge,
            knowledge_sufficient=result.knowledge_sufficient,
            human_review_required=result.human_review_required,
            human_review_reasons=result.human_review_reasons,
            validation_warnings=result.validation_warnings,
            advisory_notice=result.advisory_notice,
        ),
        retrieval=RetrievalBlock(
            status=context.status,
            sufficient=context.sufficient,
            note=context.note,
            documents=documents,
            similarity_scores=[d.score for d in documents],
            cited_chunk_ids=[k.chunk_id for k in result.retrieved_knowledge],
        ),
        meta=AnalysisMeta(
            analysis_id=record.id if record else None,
            analyzed_at=record.created_at if record else datetime.now(UTC),
            provider=result.provider,
            model=result.model,
            prompt_version=result.prompt_version,
            attempts=result.attempts,
            latency_ms=result.latency_ms,
            persisted=record is not None,
            cached=False,
            notes=notes,
        ),
    )


def response_from_record(alert: Alert, record: AnalysisResultRecord) -> AnalysisResponse:
    """Rebuild a stored analysis into the same response shape."""
    documents = [KnowledgeDocument.model_validate(d) for d in record.retrieval_documents]
    return AnalysisResponse(
        alert=alert,
        assessment=Assessment(
            classification=record.classification,
            risk_score=record.risk_score,
            confidence_score=record.confidence_score,
            reasoning=record.reasoning,
            recommended_action=record.recommended_action,
            evidence=record.evidence,
            unsupported_claims=record.unsupported_claims,
            retrieved_knowledge=record.retrieved_knowledge,
            knowledge_sufficient=record.knowledge_sufficient,
            human_review_required=record.human_review_required,
            human_review_reasons=record.human_review_reasons,
            validation_warnings=record.validation_warnings,
            advisory_notice=ADVISORY_NOTICE,
        ),
        retrieval=RetrievalBlock(
            status=RetrievalStatus(record.retrieval_status or (
                RetrievalStatus.relevant if record.knowledge_sufficient
                else RetrievalStatus.insufficient)),
            sufficient=record.knowledge_sufficient,
            note=f"{len(documents)} knowledge chunk(s) retrieved at analysis time.",
            documents=documents,
            similarity_scores=[d.score for d in documents],
            cited_chunk_ids=[k.get("chunk_id", "") for k in record.retrieved_knowledge],
        ),
        meta=AnalysisMeta(
            analysis_id=record.id,
            analyzed_at=record.created_at,
            provider=record.provider,
            model=record.model,
            prompt_version=record.prompt_version,
            attempts=record.attempts,
            latency_ms=record.latency_ms,
            persisted=True,
            cached=True,
            notes=[],
        ),
    )

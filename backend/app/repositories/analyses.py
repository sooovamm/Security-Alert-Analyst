"""Data access for AI assessments (`analysis_results`).

Writes are append-only: `save()` always inserts. Nothing here updates or
deletes a stored assessment, so the audit trail of what the AI said, and on
what evidence, cannot be rewritten by a later run.

`AnalysisProvenance` carries the retrieval/model parameters that the domain
result does not itself hold. It is built by the service layer from settings and
the RAG context — deliberately explicit, so it is obvious at the call site that
no credential is ever passed into persistence.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.engine import transaction, with_retry
from app.models.analysis import AnalysisResultRecord
from app.schemas.analysis import AnalysisResult

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AnalysisProvenance:
    """How the assessment was produced — enough to reproduce it in context."""

    documents: list[dict] = field(default_factory=list)  # retrieved chunks + scores
    rag_query: str | None = None
    rag_top_k: int | None = None
    rag_similarity_threshold: float | None = None
    rag_top_score: float | None = None
    retrieval_status: str | None = None
    embedding_provider: str | None = None
    temperature: float | None = None


class AnalysisResultRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    # --- reads -------------------------------------------------------------
    def latest_for(self, alert_id: str) -> AnalysisResultRecord | None:
        return self.session.scalar(
            select(AnalysisResultRecord)
            .where(AnalysisResultRecord.alert_id == alert_id)
            .order_by(AnalysisResultRecord.created_at.desc(), AnalysisResultRecord.id.desc())
            .limit(1)
        )

    def latest_for_many(self, alert_ids: list[str]) -> dict[str, AnalysisResultRecord]:
        """Latest assessment per alert id, in one query — avoids an N+1 when
        rendering a list of alerts."""
        if not alert_ids:
            return {}
        rows = self.session.scalars(
            select(AnalysisResultRecord)
            .where(AnalysisResultRecord.alert_id.in_(alert_ids))
            .order_by(AnalysisResultRecord.created_at.asc(), AnalysisResultRecord.id.asc())
        ).all()
        # Ascending order means the last row written for an id wins.
        return {row.alert_id: row for row in rows}

    def history_for(self, alert_id: str, limit: int = 20) -> list[AnalysisResultRecord]:
        return list(self.session.scalars(
            select(AnalysisResultRecord)
            .where(AnalysisResultRecord.alert_id == alert_id)
            .order_by(AnalysisResultRecord.created_at.desc(), AnalysisResultRecord.id.desc())
            .limit(limit)
        ).all())

    def count(self) -> int:
        return self.session.scalar(
            select(func.count()).select_from(AnalysisResultRecord)
        ) or 0

    # --- writes ------------------------------------------------------------
    def save(
        self, result: AnalysisResult, provenance: AnalysisProvenance
    ) -> AnalysisResultRecord:
        """Insert one assessment. Raises on failure; callers decide whether a
        failed write is fatal (it is not, for `/analyze-alert`)."""
        record = AnalysisResultRecord(
            alert_id=result.alert_id,
            classification=result.classification.value,
            risk_score=result.risk_score,
            confidence_score=result.confidence_score,
            reasoning=result.reasoning,
            recommended_action=result.recommended_action,
            evidence=list(result.evidence),
            unsupported_claims=list(result.unsupported_claims),
            retrieved_knowledge=[k.model_dump(mode="json") for k in result.retrieved_knowledge],
            retrieval_documents=list(provenance.documents),
            knowledge_sufficient=result.knowledge_sufficient,
            rag_query=provenance.rag_query,
            rag_top_k=provenance.rag_top_k,
            rag_similarity_threshold=provenance.rag_similarity_threshold,
            rag_top_score=provenance.rag_top_score,
            retrieval_status=provenance.retrieval_status,
            embedding_provider=provenance.embedding_provider,
            human_review_required=result.human_review_required,
            human_review_reasons=list(result.human_review_reasons),
            validation_warnings=list(result.validation_warnings),
            provider=result.provider,
            model=result.model,
            prompt_version=result.prompt_version,
            temperature=provenance.temperature,
            attempts=result.attempts,
            latency_ms=result.latency_ms,
        )

        def _run() -> AnalysisResultRecord:
            with transaction(self.session):
                self.session.add(record)
            self.session.refresh(record)
            return record

        return with_retry(_run)

"""ORM model for persisted AI assessments.

Kept in its own table, separate from `alerts`: alert telemetry is fact, an
assessment is a generated opinion about it. Rows are append-only — each
analysis run is a new row, so a re-analysis never overwrites the audit trail
and `GET /alerts/{id}/analysis` can return the latest one.

A row records enough to **reproduce the result in context**: the verdict, the
evidence, the exact knowledge chunks retrieved (with scores), the retrieval
query and parameters, and which model/prompt produced it.

No credentials are stored. `provider`, `model` and `embedding_provider` are
names only — never keys, tokens or endpoint credentials.
"""
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class AnalysisResultRecord(Base):
    __tablename__ = "analysis_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("alerts.alert_id"), index=True, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True, nullable=False
    )

    # --- model assessment ---
    classification: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    confidence_score: Mapped[int] = mapped_column(Integer, nullable=False)
    reasoning: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    unsupported_claims: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # --- grounding / retrieval metadata ---
    retrieved_knowledge: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    retrieval_documents: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    knowledge_sufficient: Mapped[bool] = mapped_column(Boolean, nullable=False)
    rag_query: Mapped[str | None] = mapped_column(Text, nullable=True)
    rag_top_k: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rag_similarity_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    rag_top_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    # "relevant" | "insufficient" | "failed" — why there is (or is not) evidence.
    retrieval_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    embedding_provider: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # --- guardrail outcome (server-side, not model-controlled) ---
    human_review_required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    human_review_reasons: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    validation_warnings: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # --- provenance ---
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(32), nullable=False)
    temperature: Mapped[float | None] = mapped_column(Float, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (f"<AnalysisResultRecord {self.alert_id} "
                f"{self.classification} risk={self.risk_score}>")

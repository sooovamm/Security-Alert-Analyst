"""Schemas for RAG retrieval results and assembled context."""
from enum import StrEnum

from pydantic import BaseModel, Field


class RetrievedChunk(BaseModel):
    chunk_id: str
    doc_name: str
    title: str
    category: str
    source: str
    text: str
    score: float


class RetrievalStatus(StrEnum):
    """Three outcomes, deliberately distinct.

    `insufficient` and `failed` both mean "no evidence", but for different
    reasons, and an analyst needs to know which: nothing in the knowledge base
    was relevant to this alert, versus the knowledge base could not be consulted
    at all. Collapsing them would let a broken retriever look like a quiet one.
    """

    relevant = "relevant"          # chunks cleared the relevance threshold
    insufficient = "insufficient"  # retrieval worked, nothing was relevant enough
    failed = "failed"              # retrieval could not run (index/embedder/corpus)


class RagContext(BaseModel):
    """Result of build_context(). When `sufficient` is False the caller must
    rely on the alert data alone and treat conclusions as low-confidence;
    `status` says whether that is because nothing was relevant or because
    retrieval broke."""

    sufficient: bool
    context_text: str
    citations: list[RetrievedChunk]
    note: str
    status: RetrievalStatus = Field(default=RetrievalStatus.relevant)

    @classmethod
    def failed_context(cls, reason: str) -> "RagContext":
        """Retrieval is unavailable. No citations are invented; the note says
        plainly that the knowledge base could not be consulted."""
        return cls(
            sufficient=False,
            context_text="",
            citations=[],
            status=RetrievalStatus.failed,
            note=(
                "Knowledge retrieval failed, so no internal security knowledge was "
                f"available for this alert ({reason}). The assessment below rests on the "
                "alert data alone and must be treated as low-confidence."
            ),
        )

"""Standalone RAG service.

Independent of the LLM: it loads and chunks the knowledge base, embeds and
indexes chunks, retrieves by cosine similarity, applies a relevance threshold,
and assembles a context block for a downstream consumer.

Key behavior: if nothing clears the threshold, `build_context` returns an
explicit "insufficient relevant knowledge" state instead of low-quality chunks,
so the caller does not pretend relevant knowledge was found.
"""
from __future__ import annotations

import logging
from functools import lru_cache

from app.core.config import Settings, get_settings
from app.rag.embeddings import Embedder, get_embedder
from app.rag.ingest import chunk_document, load_documents
from app.rag.schemas import RagContext, RetrievalStatus, RetrievedChunk
from app.rag.store import VectorIndex

logger = logging.getLogger(__name__)

INSUFFICIENT_NOTE = (
    "No retrieved security knowledge met the relevance threshold. Assess using "
    "the alert data alone and treat any conclusion as low-confidence."
)


class RagService:
    def __init__(self, embedder: Embedder, settings: Settings) -> None:
        self.embedder = embedder
        self.settings = settings
        self._index: VectorIndex | None = None

    # --- ingestion ---------------------------------------------------------
    def ingest_documents(self) -> dict:
        docs = load_documents(self.settings.knowledge_dir)
        chunks = []
        for doc in docs:
            chunks.extend(
                chunk_document(
                    doc,
                    self.settings.rag_chunk_size,
                    self.settings.rag_chunk_overlap,
                )
            )
        vectors = self.embedder.embed([c.text for c in chunks])
        index = VectorIndex(self.embedder.dim)
        index.add(vectors, [c.as_metadata() for c in chunks])
        self._index = index
        logger.info(
            "RAG ingest: %d documents -> %d chunks (dim=%d)",
            len(docs), len(chunks), self.embedder.dim,
        )
        return {"documents": len(docs), "chunks": len(chunks)}

    def _ensure_index(self) -> VectorIndex:
        if self._index is None:
            self.ingest_documents()
        assert self._index is not None
        return self._index

    @property
    def is_ready(self) -> bool:
        return self._index is not None and self._index.size > 0

    # --- retrieval ---------------------------------------------------------
    def retrieve_relevant_knowledge(
        self,
        query: str,
        top_k: int | None = None,
        threshold: float | None = None,
    ) -> tuple[list[RetrievedChunk], list[RetrievedChunk]]:
        """Return (all_retrieved, passing_threshold), both score-sorted desc."""
        index = self._ensure_index()
        k = top_k if top_k is not None else self.settings.rag_top_k
        thr = threshold if threshold is not None else self.settings.rag_similarity_threshold

        query_vec = self.embedder.embed([query])
        results = index.search(query_vec, k)
        retrieved = [RetrievedChunk(score=score, **meta) for score, meta in results]
        passing = [r for r in retrieved if r.score >= thr]
        logger.debug(
            "RAG query=%r: %d retrieved, %d above threshold %.3f",
            query, len(retrieved), len(passing), thr,
        )
        return retrieved, passing

    # --- context assembly --------------------------------------------------
    def build_context(
        self,
        query: str,
        top_k: int | None = None,
        threshold: float | None = None,
    ) -> RagContext:
        _, passing = self.retrieve_relevant_knowledge(query, top_k, threshold)
        if not passing:
            return RagContext(
                sufficient=False,
                context_text="",
                citations=[],
                status=RetrievalStatus.insufficient,
                note=INSUFFICIENT_NOTE,
            )
        blocks = [
            f"[{c.chunk_id}] (title: {c.title}; category: {c.category}; "
            f"source: {c.source})\n{c.text}"
            for c in passing
        ]
        return RagContext(
            sufficient=True,
            context_text="\n\n".join(blocks),
            citations=passing,
            note=f"{len(passing)} relevant knowledge chunk(s) retrieved.",
        )


@lru_cache
def get_rag_service() -> RagService:
    """Cached, ingested service for application use."""
    settings = get_settings()
    service = RagService(get_embedder(settings), settings)
    service.ingest_documents()
    return service

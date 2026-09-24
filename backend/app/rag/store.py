"""Thin FAISS wrapper that keeps chunk metadata aligned with vector ids.

FAISS stores only vectors, so we keep a parallel list of chunk metadata indexed
by insertion order (which matches FAISS ids for a flat index). Vectors are
already L2-normalized, so an inner-product index yields cosine similarity.
"""
from __future__ import annotations

import faiss
import numpy as np


class VectorIndex:
    def __init__(self, dim: int) -> None:
        self.dim = dim
        self._index = faiss.IndexFlatIP(dim)
        self._metadatas: list[dict] = []

    def add(self, vectors: np.ndarray, metadatas: list[dict]) -> None:
        if len(vectors) != len(metadatas):
            raise ValueError("vectors and metadatas length mismatch")
        if len(vectors) == 0:
            return
        self._index.add(vectors.astype("float32"))
        self._metadatas.extend(metadatas)

    def search(self, query_vector: np.ndarray, top_k: int) -> list[tuple[float, dict]]:
        if self._index.ntotal == 0:
            return []
        k = min(top_k, self._index.ntotal)
        scores, ids = self._index.search(query_vector.astype("float32"), k)
        out: list[tuple[float, dict]] = []
        for score, idx in zip(scores[0], ids[0], strict=False):
            if idx == -1:
                continue
            out.append((float(score), self._metadatas[int(idx)]))
        return out

    @property
    def size(self) -> int:
        return self._index.ntotal

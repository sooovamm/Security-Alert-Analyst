"""Embedding backends behind a single interface.

Two implementations:

- `HashingEmbedder` — deterministic feature-hashing over word unigrams+bigrams.
  Requires no model download or API key, so it runs reliably in dev and CI
  (the environment here has no access to model hubs). Vectors are L2-normalized
  so inner product equals cosine similarity.
- `OpenAIEmbedder` — production embeddings via OpenAI (`text-embedding-3-small`).
  `openai` is imported lazily so the package works without it in dev.

`get_embedder(settings)` picks the backend from `EMBEDDING_PROVIDER`.
"""
from __future__ import annotations

import hashlib
import re
from typing import Protocol

import numpy as np

_TOKEN_RE = re.compile(r"[a-z0-9]+")

# Common English words carry no topical signal and, left in, inflate similarity
# between unrelated verbose texts. Dropping them sharpens the relevance gap
# between on-topic and off-topic queries for this hashing embedder.
_STOPWORDS = frozenset("""
a an and are as at be been but by can could do does for from had has have how in
into is it its may might must no not of on or should so such than that the their
them then there these they this to up was were what when where which who will with
would you your it's we our
""".split())


def _tokens(text: str) -> list[str]:
    words = [
        w for w in _TOKEN_RE.findall(text.lower())
        if len(w) > 1 and w not in _STOPWORDS
    ]
    bigrams = [f"{a}_{b}" for a, b in zip(words, words[1:], strict=False)]
    return words + bigrams


class Embedder(Protocol):
    dim: int

    def embed(self, texts: list[str]) -> np.ndarray:
        ...


class HashingEmbedder:
    """Keyless, dependency-light embedder. Not as semantically rich as a
    transformer model, but deterministic and fully offline — ideal for a
    prototype's dev/test path."""

    def __init__(self, dim: int = 1024) -> None:
        self.dim = dim

    def _embed_one(self, text: str) -> np.ndarray:
        vec = np.zeros(self.dim, dtype="float32")
        for tok in _tokens(text):
            digest = hashlib.md5(tok.encode("utf-8")).digest()
            idx = int.from_bytes(digest[:4], "little") % self.dim
            sign = 1.0 if digest[4] & 1 else -1.0
            vec[idx] += sign
        norm = float(np.linalg.norm(vec))
        if norm > 0.0:
            vec /= norm
        return vec

    def embed(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype="float32")
        return np.vstack([self._embed_one(t) for t in texts]).astype("float32")


class OpenAIEmbedder:
    """Production embedder. Lazily constructs the OpenAI client so importing
    this module never requires the openai package to be installed."""

    def __init__(self, model: str, api_key: str, dim: int = 1536) -> None:
        from openai import OpenAI  # lazy import

        self._client = OpenAI(api_key=api_key)
        self.model = model
        self.dim = dim

    def embed(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype="float32")
        resp = self._client.embeddings.create(model=self.model, input=texts)
        arr = np.array([d.embedding for d in resp.data], dtype="float32")
        norms = np.linalg.norm(arr, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return (arr / norms).astype("float32")


def get_embedder(settings) -> Embedder:
    provider = settings.embedding_provider.lower()
    if provider == "local":
        return HashingEmbedder()
    if provider == "openai":
        if not settings.openai_api_key:
            raise RuntimeError(
                "EMBEDDING_PROVIDER=openai but OPENAI_API_KEY is not set"
            )
        return OpenAIEmbedder(settings.embedding_model, settings.openai_api_key)
    raise ValueError(f"unknown embedding provider: {settings.embedding_provider!r}")

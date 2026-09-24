"""RAG failure types.

Retrieval problems (missing corpus, index build failure, embedding backend
down) are distinct from "retrieval worked but found nothing relevant" — the
latter is a normal `RagContext` with `sufficient=False`, not an error.
"""


class RagUnavailableError(RuntimeError):
    """The knowledge base could not be loaded, indexed, or queried."""

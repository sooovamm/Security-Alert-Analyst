"""Document loading, cleaning, and chunking for the RAG pipeline.

Each knowledge document carries YAML frontmatter (title, category, source).
Loading parses that metadata, cleaning strips it and normalizes whitespace, and
chunking splits the body into overlapping, word-boundary-aligned chunks. Every
chunk keeps its document name, title, category, source, and a chunk identifier.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)


@dataclass
class Document:
    name: str  # filename stem, e.g. "02-brute-force-credential-access"
    title: str
    category: str
    source: str
    text: str


@dataclass
class Chunk:
    chunk_id: str  # e.g. "02-brute-force-credential-access#1"
    doc_name: str
    title: str
    category: str
    source: str
    text: str

    def as_metadata(self) -> dict:
        return {
            "chunk_id": self.chunk_id,
            "doc_name": self.doc_name,
            "title": self.title,
            "category": self.category,
            "source": self.source,
            "text": self.text,
        }


def _parse_frontmatter(raw: str) -> tuple[dict, str]:
    match = _FRONTMATTER_RE.match(raw)
    if not match:
        return {}, raw
    meta: dict = {}
    for line in match.group(1).splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            meta[key.strip()] = value.strip()
    return meta, raw[match.end():]


def clean_text(text: str) -> str:
    """Normalize line endings, strip trailing spaces, collapse blank runs."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def load_documents(knowledge_dir: Path) -> list[Document]:
    knowledge_dir = Path(knowledge_dir)
    docs: list[Document] = []
    for path in sorted(knowledge_dir.glob("*.md")):
        raw = path.read_text(encoding="utf-8")
        meta, body = _parse_frontmatter(raw)
        docs.append(
            Document(
                name=path.stem,
                title=meta.get("title", path.stem),
                category=meta.get("category", "General"),
                source=meta.get("source", "internal-knowledge-base"),
                text=clean_text(body),
            )
        )
    if not docs:
        raise FileNotFoundError(f"No knowledge documents found in {knowledge_dir}")
    return docs


def _split_text(text: str, size: int, overlap: int) -> list[str]:
    if size <= 0:
        raise ValueError("chunk size must be positive")
    if overlap < 0 or overlap >= size:
        raise ValueError("overlap must be >= 0 and < chunk size")

    chunks: list[str] = []
    start, n = 0, len(text)
    while start < n:
        end = min(start + size, n)
        if end < n:  # snap to a word boundary so we don't cut mid-word
            space = text.rfind(" ", start, end)
            if space > start:
                end = space
        piece = text[start:end].strip()
        if piece:
            chunks.append(piece)
        if end >= n:
            break
        start = max(end - overlap, start + 1)
    return chunks


def chunk_document(doc: Document, chunk_size: int, chunk_overlap: int) -> list[Chunk]:
    pieces = _split_text(doc.text, chunk_size, chunk_overlap)
    return [
        Chunk(
            chunk_id=f"{doc.name}#{i}",
            doc_name=doc.name,
            title=doc.title,
            category=doc.category,
            source=doc.source,
            text=piece,
        )
        for i, piece in enumerate(pieces)
    ]

"""Tests for the RAG pipeline — fully independent of the LLM.

Uses the keyless HashingEmbedder so the pipeline is deterministic and needs no
API key or model download.
"""
import pytest

from app.core.config import get_settings
from app.rag.embeddings import HashingEmbedder
from app.rag.ingest import Document, _split_text, chunk_document, load_documents
from app.rag.service import RagService


@pytest.fixture(scope="module")
def settings():
    return get_settings()


@pytest.fixture(scope="module")
def service(settings):
    svc = RagService(HashingEmbedder(), settings)
    svc.ingest_documents()
    return svc


# --- loading -----------------------------------------------------------------

def test_documents_load_successfully(settings):
    docs = load_documents(settings.knowledge_dir)
    assert len(docs) == 8
    for d in docs:
        assert d.title and d.category and d.source
        assert d.text.strip()
        assert not d.text.startswith("---")  # frontmatter stripped by cleaning


def test_categories_cover_required_topics(settings):
    cats = {d.category for d in load_documents(settings.knowledge_dir)}
    required = {
        "PowerShell Execution", "Brute-force Authentication", "Malware Detection",
        "Privilege Escalation", "Suspicious Network Connection",
        "Suspicious Command Execution", "Normal Administrative Activity",
    }
    assert required <= cats


# --- chunking ----------------------------------------------------------------

def test_chunks_are_generated(settings):
    docs = load_documents(settings.knowledge_dir)
    total = 0
    for d in docs:
        chunks = chunk_document(d, settings.rag_chunk_size, settings.rag_chunk_overlap)
        assert len(chunks) >= 1
        total += len(chunks)
    assert total >= len(docs)  # at least one chunk per doc


def test_chunk_size_is_configurable(settings):
    doc = load_documents(settings.knowledge_dir)[0]
    few = chunk_document(doc, chunk_size=2000, chunk_overlap=100)
    many = chunk_document(doc, chunk_size=300, chunk_overlap=50)
    assert len(many) > len(few)  # smaller chunks -> more of them


def test_split_text_rejects_bad_overlap():
    with pytest.raises(ValueError):
        _split_text("some text", size=100, overlap=100)  # overlap >= size


def test_chunk_ids_are_unique(settings):
    docs = load_documents(settings.knowledge_dir)
    ids = [c.chunk_id for d in docs
           for c in chunk_document(d, settings.rag_chunk_size, settings.rag_chunk_overlap)]
    assert len(ids) == len(set(ids))


# --- indexing ----------------------------------------------------------------

def test_embeddings_and_index_are_created(service):
    assert service.is_ready
    stats = service.ingest_documents()  # idempotent re-ingest
    assert stats["documents"] == 8
    assert stats["chunks"] >= 8


# --- retrieval ---------------------------------------------------------------

@pytest.mark.parametrize("query,expected_category", [
    ("powershell encoded hidden command downloadstring iex", "PowerShell Execution"),
    ("many failed ssh password login attempts brute force", "Brute-force Authentication"),
    ("mimikatz credential dumping from lsass memory", "Malware Detection"),
    ("beaconing to external command and control ip", "Suspicious Network Connection"),
    ("user added to local administrators group uac bypass", "Privilege Escalation"),
])
def test_relevant_queries_retrieve_relevant_documents(service, query, expected_category):
    ctx = service.build_context(query)
    assert ctx.sufficient
    assert ctx.citations
    assert ctx.citations[0].category == expected_category


@pytest.mark.parametrize("query", [
    "chocolate chip cookie recipe butter sugar flour oven",
    "who won the football match last night final score",
])
def test_irrelevant_queries_produce_no_useful_retrieval(service, query):
    ctx = service.build_context(query)
    assert ctx.sufficient is False
    assert ctx.citations == []
    assert "insufficient" in ctx.note.lower() or "no retrieved" in ctx.note.lower()


def test_metadata_is_preserved(service):
    _, passing = service.retrieve_relevant_knowledge(
        "powershell encoded command", top_k=3
    )
    assert passing
    top = passing[0]
    assert top.chunk_id and "#" in top.chunk_id
    assert top.doc_name
    assert top.category
    assert top.source == "internal-knowledge-base"
    assert top.text.strip()


def test_threshold_controls_sufficiency(service):
    query = "powershell encoded command"
    # An impossibly high threshold makes even a good match insufficient.
    strict = service.build_context(query, threshold=0.99)
    assert strict.sufficient is False
    # A permissive threshold returns context.
    loose = service.build_context(query, threshold=0.0)
    assert loose.sufficient is True


def test_build_context_cites_chunks(service):
    ctx = service.build_context("brute force ssh failed logins")
    assert ctx.sufficient
    # context text references the chunk id of at least one citation
    assert ctx.citations[0].chunk_id in ctx.context_text


def test_empty_document_dir_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_documents(tmp_path)


def test_chunk_document_on_short_doc():
    doc = Document(name="x", title="X", category="General", source="s",
                   text="short text body")
    chunks = chunk_document(doc, chunk_size=800, chunk_overlap=100)
    assert len(chunks) == 1
    assert chunks[0].chunk_id == "x#0"

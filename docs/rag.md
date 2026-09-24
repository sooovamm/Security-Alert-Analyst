# RAG Design

How the knowledge base is built, searched, and turned into grounding for the
analysis — and what happens when it finds nothing useful, or breaks.

Code: `backend/app/rag/`. Corpus: `data/knowledge/`. Tests: `test_rag.py`
(19 cases) and `test_integration.py` (13, against the real index).

---

## 1. Why retrieval, rather than a bigger prompt

A general-purpose model already knows that `-EncodedCommand` is suspicious. It
does not know that *your* finance workstations run a signed reporting script
with `-ExecutionPolicy Bypass` at 08:00 every weekday, and that this is
expected. That is exactly the judgement that separates a useful triage
assistant from one that cries wolf.

Three reasons retrieval is the right mechanism here rather than fine-tuning or
a static system prompt:

- **The knowledge changes faster than a model.** Editing a markdown file and
  calling `POST /rag/reindex` updates behaviour in ~30 ms. No retraining, no
  redeployment.
- **Citations make the reasoning checkable.** Every assessment names the chunks
  it relied on, with similarity scores, so an analyst can read the source
  document and disagree with the model on the evidence.
- **Only relevant material is sent.** Pasting the whole corpus into every
  prompt costs tokens, dilutes attention, and increases the surface of data sent
  to a third party.

## 2. The corpus

Eight markdown documents, each with YAML frontmatter parsed at load time:

```yaml
---
title: PowerShell Security
category: PowerShell Execution
source: internal-knowledge-base
---
```

| File | Title | Category |
| --- | --- | --- |
| `01-powershell-attacks.md` | PowerShell Security | PowerShell Execution |
| `02-brute-force-credential-access.md` | Brute-force and Credential Access | Brute-force Authentication |
| `03-malware-indicators.md` | Malware Indicators | Malware Detection |
| `04-suspicious-network-c2.md` | Suspicious Network Activity | Suspicious Network Connection |
| `05-privilege-escalation.md` | Privilege Escalation | Privilege Escalation |
| `06-lolbins-command-execution.md` | Suspicious Command Execution | Suspicious Command Execution |
| `07-benign-admin-baselines.md` | Benign Administrative Activity | Normal Administrative Activity |
| `08-analyst-triage-playbook.md` | Security Alert Triage | General |

Two choices in that list are deliberate:

**`07-benign-admin-baselines.md` exists on purpose.** A corpus containing only
attack patterns biases every retrieval toward "this resembles an attack",
because that is the only kind of text available to match. Documenting what
normal administration looks like gives the model something to retrieve when the
alert really is routine — and gives it grounds to say so.

**Every attack document pairs its indicators with benign context**, under a
heading such as "Context that lowers suspicion" or "Context that matters", so a
chunk matching an indicator usually carries the caveat with it rather than
leaving it in a section that may not be retrieved.

The categories mirror the seven alert categories in `schemas/alert.py`, so an
alert's own category is a useful retrieval signal.

## 3. Loading and chunking

`app/rag/ingest.py`.

1. **Load** — every `*.md` in `data/knowledge/`, sorted. Frontmatter is parsed
   into `title` / `category` / `source`, with sensible fallbacks if absent.
2. **Clean** — normalise line endings, strip trailing whitespace, collapse runs
   of three or more blank lines. The frontmatter block itself is stripped, so
   YAML never reaches an embedding.
3. **Chunk** — `RAG_CHUNK_SIZE` characters (default **800**) with
   `RAG_CHUNK_OVERLAP` (default **150**) of overlap.

Two details in the splitter matter:

- **Word-boundary snapping.** Before cutting at `start + size`, the splitter
  searches backwards for the last space and cuts there instead, so a chunk never
  ends mid-token. A split through `-EncodedCommand` would damage both chunks'
  embeddings.
- **Overlap keeps a claim with its caveat.** 150 characters is enough that an
  indicator and the sentence qualifying it usually survive in the same chunk,
  which is what stops retrieval returning "encoded PowerShell is malicious"
  without "…unless it is the signed reporting script".

The splitter rejects an overlap that is negative or ≥ the chunk size, which
would loop forever or silently produce nothing.

Each chunk keeps its provenance and gets a stable id:

```
chunk_id = f"{doc_name}#{index}"     e.g.  01-powershell-attacks#0
```

That id is what the model cites and what the guardrails verify against. The
current corpus produces **24 chunks from 8 documents**.

## 4. Embeddings

Two backends behind one `Embedder` protocol (`app/rag/embeddings.py`), selected
by `EMBEDDING_PROVIDER`.

### `local` — `HashingEmbedder` (default)

Deterministic feature hashing, 1024 dimensions, no API key and no model
download:

1. Lowercase, extract `[a-z0-9]+` tokens, drop tokens of length 1 and a
   stopword list.
2. Add word bigrams (`encoded_command`) alongside unigrams, so short phrases
   carry signal.
3. For each token, MD5 it; the first 4 bytes pick a dimension, bit 0 of the
   fifth byte picks a sign (±1); accumulate.
4. L2-normalise.

The stopword list is not cosmetic: common English words carry no topical signal
and, left in, inflate similarity between any two verbose texts — which narrows
the gap between an on-topic and an off-topic match, exactly the gap the
threshold depends on.

This is a **lexical** embedder, not a semantic one. It matches wording, not
meaning. It is the default because it is deterministic, runs offline, needs no
key, and therefore lets dev, CI and the whole test suite exercise the *real*
retrieval code path rather than a stub.

### `openai` — `OpenAIEmbedder`

`text-embedding-3-small`, 1536 dimensions, L2-normalised the same way. This is
the recommended setting for production, where semantic matching handles alerts
phrased unlike the corpus. It requires `OPENAI_API_KEY`; the `openai` package is
imported lazily so nothing breaks without it.

## 5. Index and retrieval

`app/rag/store.py`, `app/rag/service.py`.

**Index.** FAISS `IndexFlatIP` — a flat (exhaustive) index over inner product.
Because every vector is L2-normalised, inner product *is* cosine similarity. It
is exact, needs no training, and searching 24 vectors takes microseconds. An
approximate index (IVF, HNSW) would trade recall for a speedup that does not
exist at this size.

FAISS stores only vectors, so chunk metadata is kept in a parallel list indexed
by insertion order, which matches FAISS ids for a flat index.

**Query construction** (`build_rag_query` in `services/prompts.py`):

```python
" ".join([alert.category.value, alert.process,
          alert.command_line[:500], alert.description[:500]])
```

The category and process are included because they are the most reliable
topical signals; the command line and description are truncated so one very long
field cannot dominate the embedding.

**Search.** `RAG_TOP_K` (default **4**) nearest chunks, then anything scoring
below `RAG_SIMILARITY_THRESHOLD` (default **0.08**) is discarded.

**On the threshold.** 0.08 is low in absolute terms because the hashing embedder
produces low cosine values even for good matches — it is tuned to this embedder,
not a universal constant. Switching to OpenAI embeddings needs it raised.
`test_rag.py::test_threshold_controls_sufficiency` asserts the mechanism works;
no labelled query/chunk set exists to say the value is *optimal*, and this
document does not claim it is.

## 6. Context assembly

Surviving chunks become a `RagContext`, each rendered with its provenance so the
model can cite it:

```
[01-powershell-attacks#0] (title: PowerShell Security; category: PowerShell Execution; relevance: 0.317)
# PowerShell Attack Techniques and Indicators
...
```

Before assembly, knowledge text goes through the same credential redaction as
alert text (`redact_text`) and the same delimiter neutralisation as everything
else. The corpus is internal and curated, but it is still text being sent to a
third party, and a careless or poisoned document could carry a secret. The whole
block is capped at 12,000 characters.

## 7. When retrieval finds nothing — or fails

The distinction that most of this design exists to preserve:

| `RetrievalStatus` | What happened | What the prompt says |
| --- | --- | --- |
| `relevant` | Chunks cleared the threshold | The chunks, with ids and scores |
| `insufficient` | Search ran; nothing scored high enough | `NO RELEVANT KNOWLEDGE FOUND. …` |
| `failed` | Search could not run — missing corpus, dead embedder, unusable index | `KNOWLEDGE RETRIEVAL FAILED. The knowledge base could not be consulted … keep confidence_score low.` |

`insufficient` and `failed` both mean "no evidence", but for opposite reasons —
*we looked and found nothing relevant* versus *we could not look*. Collapsing
them would let a broken retriever pass for a quiet one, which is the failure
mode most likely to go unnoticed in production. The distinction is carried
through the prompt, the API response, the stored row (`retrieval_status`) and
the dashboard.

**Finding nothing is a normal outcome, not an error.** Many alerts have no
close match in an eight-document corpus. The analysis still runs; it is just
explicitly ungrounded.

**A broken retriever degrades by default.** `pipeline.retrieve_context` wraps
both the *construction* of the service and the query — a missing corpus fails at
construction, which is precisely the outage this must survive. On failure it
returns `RagContext.failed_context(reason)`: no citations are invented, and the
note states plainly that the knowledge base could not be consulted. Set
`RAG_FAILURE_MODE=fail` to return `503 rag_unavailable` instead.

## 8. Hallucination controls

Retrieval grounds the model; it does not constrain it. Four server-side controls
do that, and none depends on the model behaving (`services/analysis.py`):

1. **Citations are verified.** Every `chunk_id` the model returns is looked up
   in the chunks actually retrieved. Unknown ids are **dropped**, a warning is
   added, and the citation metadata in the response is taken from the retrieval
   record — never from the model. A fabricated source cannot reach the analyst.
2. **Confidence is capped at 60** when `sufficient` is false, whether the cause
   was `insufficient` or `failed`, with a warning naming which.
3. **Prompt instruction.** Rule 12 tells the model to list only ids it actually
   relied on and never to invent them. This is the weakest of the four, which is
   why the other three exist.
4. **Nothing invented on failure.** `failed_context()` produces an empty
   citation list. There is no code path that synthesises a plausible-looking
   source.

## 9. Rebuilding

The index lives only in memory. It is built at startup when
`RAG_WARM_ON_STARTUP=true` (the default), or lazily on first use, and rebuilt on
demand:

```bash
curl -X POST http://localhost:8000/rag/reindex
# {"status":"ok","documents":8,"chunks":24,"duration_ms":26}
```

`data/` is bind-mounted read-only into the container, so editing a knowledge
document on the host and calling reindex takes effect without a restart or an
image rebuild. The operation is idempotent.

There is no index file, so there is nothing to invalidate, migrate or corrupt —
the corpus is the single source of truth and a full rebuild is cheaper than
maintaining a cache of it.

## 10. Limitations

- **The default embedder is lexical.** An alert described in wording unlike the
  corpus retrieves poorly, however semantically related it is.
  `EMBEDDING_PROVIDER=openai` is the fix; it is implemented but has not been
  measured here against a real key.
- **Retrieval quality is unmeasured.** There is no labelled query/chunk set, so
  `top_k = 4` and `threshold = 0.08` rest on inspection, not on a
  precision/recall curve.
- **Eight documents is a demonstration corpus.** Real coverage of SOC triage
  knowledge is orders of magnitude larger, and at that size a flat in-memory
  index stops being the right structure.
- **No reranking and no hybrid search.** Vector similarity alone; BM25 alongside
  it would catch the exact-token matches (a specific binary name, a CVE id) that
  embeddings blur.
- **Chunking is character-based, not structural.** It respects word boundaries
  but not markdown headings, so a chunk can straddle two sections.

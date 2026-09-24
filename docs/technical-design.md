# Technical Design

AI-Powered Security Alert Analyst — design decisions, and the reasoning behind
them. Everything here describes code that exists in this repository; file paths
are given so each claim can be checked.

---

## 1. Architecture

Two runtime containers, because the system needs exactly two things: something
to serve a UI and something to answer HTTP.

- **`frontend`** — a React 18 SPA built with Vite and served as static files by
  nginx 1.27 (unprivileged image, uid 101, port 8080). nginx also reverse-proxies
  `/api/` to the backend, so the browser talks to a single origin and CORS never
  arises in the deployed path.
- **`backend`** — FastAPI on uvicorn (uid 10001, port 8000), holding the API,
  the retrieval index and the analysis engine in one process.

Inside the backend, layers are separated so each can be tested alone: `api/`
(routing and status codes), `services/` (pipeline, engine, prompts, parsing,
sanitisation), `rag/`, `llm/`, `repositories/` (every query — routes never touch
the ORM), `models/` and `schemas/` (the validation boundary).

Routes stay thin: `api/analyze.py` resolves dependencies and calls
`services/pipeline.py`, which owns the order of operations. The engine receives
a `RagContext` and an `LLMProvider` and knows nothing about HTTP.

**There is no database server and no vector database.** Storage is SQLite in a
named Docker volume; retrieval is a FAISS index held in the backend process and
rebuilt from `data/knowledge/` at startup (8 documents → 24 chunks, ~30 ms). At
this scale a separate service for either would add a container, a startup
dependency and a failure mode while changing nothing a user can observe.

Full diagrams, including trust boundaries: [architecture.md](architecture.md).

## 2. Data flow

`POST /analyze-alert` with `{"alert_id": "ALRT-1002"}`:

1. **Middleware** — reject bodies over `MAX_REQUEST_BYTES` (256 KB default,
   checked against both the declared `Content-Length` and the actual stream, so
   a chunked request cannot lie); assign or adopt a request id.
2. **Validation** — `AnalyzeAlertRequest` accepts either an `alert_id` or a
   complete alert (nested under `alert` or flat at the top level, repacked into
   one internal shape). `extra="forbid"` throughout.
3. **Load** — the alert is read from SQLite via `AlertRepository`. A payload
   alert skips this. Unknown id → 404.
4. **Retrieve** — `pipeline.retrieve_context` builds a query from the alert's
   category, process, command line and description, embeds it, searches FAISS,
   and drops anything below the similarity threshold.
5. **Analyse** — `AlertAnalysisEngine.analyze` redacts credentials, neutralises
   delimiter-shaped text, assembles the prompt, calls the provider, parses and
   validates the reply, then applies server-side guardrails.
6. **Persist** — a new row in `analysis_results` (append-only) together with the
   retrieval parameters that produced it.
7. **Respond** — `{alert, assessment, retrieval, meta}`.

Two steps degrade rather than fail. If retrieval breaks, the context becomes an
explicitly *failed* one, the assessment is produced from the alert alone and
confidence is capped — `RAG_FAILURE_MODE=fail` refuses with 503 instead. If the
database write fails, the assessment is still returned with
`meta.persisted = false`; losing a completed analysis to a storage hiccup would
be worse than serving it unstored.

## 3. LLM / model selection

Configuration is **provider-neutral** (`LLM_*`), with `OPENAI_*` kept as a
fallback for the key and model. `app/llm/base.py` defines an `LLMProvider`
protocol; `app/llm/factory.py` maps `LLM_PROVIDER` to a builder. One
implementation ships: `openai`, which also covers any OpenAI-compatible endpoint
— Azure proxies, vLLM, Ollama, LM Studio — through `LLM_BASE_URL`. Adding a
vendor means writing a subclass and registering it; nothing else changes.

The default model is **`gpt-4o-mini`**. For this task the work is structured
extraction and calibrated judgement over roughly 4 KB of context, not deep
reasoning: the alert is short, the retrieved knowledge does the heavy lifting,
and the output is a fixed JSON object. A small, fast, inexpensive model fits
that shape, and per-alert cost matters when a SOC queue is thousands of alerts
a day. `LLM_MODEL` changes it without touching code.

Call parameters (`app/core/config.py`, applied in `app/services/analysis.py`):

| Setting | Default | Reason |
| --- | --- | --- |
| `LLM_TEMPERATURE` | `0.1` | Triage should be near-deterministic; two analysts reading the same alert should not get different verdicts from sampling noise |
| `LLM_MAX_OUTPUT_TOKENS` | `1200` | Enough for reasoning plus evidence; a `finish_reason == "length"` is treated as a failed response, not a truncated success |
| `LLM_TIMEOUT_SECONDS` | `30` | Per attempt |
| `LLM_MAX_RETRIES` | `2` | Retries after the first attempt, with exponential backoff from `LLM_RETRY_BACKOFF_SECONDS`, capped at 10 s |

JSON mode (`response_format={"type": "json_object"}`) is requested, but the
parser never assumes it was honoured. SDK-level retries are disabled
(`max_retries=0`) so the engine owns the whole retry policy — including the
case that matters most, a schema-invalid response, where the retry carries a
correction note back to the model.

## 4. RAG design

**Why retrieval at all.** A general model knows what `-enc` means but not that
your finance workstations run a signed reporting script with
`-ExecutionPolicy Bypass` every morning. The knowledge base supplies the local
judgement, and citations let an analyst check the reasoning against a document
rather than trusting the model's memory.

**Corpus.** Eight markdown documents in `data/knowledge/` with YAML frontmatter
(`title`, `category`, `source`), covering PowerShell, credential access, malware
indicators, C2, privilege escalation, LOLBins, **benign administrative
baselines** and a triage playbook. The baselines document is deliberate: a
corpus of only attack patterns biases every retrieval toward "this looks
malicious".

**Pipeline.** Chunks of 800 characters with 150 of overlap, snapped back to a
word boundary so a chunk never ends mid-token and an indicator keeps its caveat.
Embedding is either `HashingEmbedder` (default — 1024-d feature hashing over
unigrams and bigrams, keyless, deterministic, offline, so dev, CI and the tests
all exercise the real retrieval path) or OpenAI `text-embedding-3-small`
(1536-d). Vectors are L2-normalised and searched with FAISS `IndexFlatIP`, so
inner product is cosine similarity and search is exact — 24 vectors do not need
an approximate index. `RAG_TOP_K` (4) chunks are retrieved and anything below
`RAG_SIMILARITY_THRESHOLD` (0.08) is discarded.

**Three retrieval states, kept distinct** (`app/rag/schemas.py`):

| Status | Meaning | Effect |
| --- | --- | --- |
| `relevant` | Chunks cleared the threshold | Normal grounded analysis |
| `insufficient` | Retrieval ran, nothing was relevant | Prompt says so; confidence capped at 60 |
| `failed` | Retrieval could not run at all | Prompt says so explicitly; confidence capped; flagged for human review |

Collapsing the last two would let a broken retriever look like a quiet one. The
API, the stored row and the dashboard all preserve the distinction.

## 5. Prompt design

Three regions, one of which is trusted (`app/services/prompts.py`,
`PROMPT_VERSION = "analysis-v1"`). The **system prompt** is the only source of
instructions — advisory role, trust boundaries, safety rules, evidence
requirements, a scoring rubric with numeric bands, and the exact output keys.
**`<alert_data>`** is untrusted, possibly attacker-controlled telemetry.
**`<retrieved_knowledge>`** is reference material, never instructions.

Four mechanisms keep injected text inside the data region:

1. **Per-request random delimiters.** Each block is tagged
   `<alert_data id="…">` with a fresh 8-byte hex nonce. An attacker cannot close
   a block whose id they cannot predict.
2. **Delimiter neutralisation.** `neutralise()` rewrites anything matching
   `<…alert_data|retrieved_knowledge|system|instructions…>` into square brackets,
   so a forged `</alert_data>` becomes `[/alert_data]`.
3. **JSON encoding.** The alert is serialised as a JSON object, so injected text
   is a quoted string value rather than free prose.
4. **Length caps.** 4000 characters per alert field, 12000 for the knowledge
   block, with an explicit truncation marker.

The system prompt instructs the model to treat instruction-shaped alert content
as a *suspicious indicator to report in evidence*, not as something to obey.
That is a mitigation, not a control — the controls are the guardrails in §8,
which do not depend on the model behaving.

On a schema-invalid reply the retry appends a value-free correction note
("your previous response was rejected by validation: …"), which names field
locations and error types but never echoes values.

## 6. Database / storage design

SQLite via SQLAlchemy 2.0, at `sqlite:////app/var/app.db` in a named volume.
Two tables:

- **`alerts`** — raw telemetry only, mirroring the `Alert` schema. It has no
  column for a verdict, deliberately: telemetry is fact, an assessment is a
  generated opinion about it.
- **`analysis_results`** — one row per analysis run, `alert_id` foreign-keyed to
  `alerts`. **Append-only**: a re-analysis inserts a new row, so the audit trail
  is never rewritten, and `GET /alerts/{id}/analysis` returns the most recent.

Each assessment row stores enough to *reproduce the result in context*: the
verdict and scores, evidence, the retrieved chunks with their scores, the
retrieval query, `rag_top_k`, `rag_similarity_threshold`, `rag_top_score`,
`retrieval_status`, `embedding_provider`, plus provider, model, prompt version,
temperature, attempt count and latency. No credentials are stored — provider and
model are names only.

SQLite is tuned for a server process (`app/db/engine.py`): WAL journalling so
readers never block the writer, `busy_timeout=5000` so a concurrent write waits
rather than failing instantly, `foreign_keys=ON` (off by default in SQLite,
which would make the reference decorative), and `synchronous=NORMAL`. Transient
`database is locked` errors are retried.

Schema management uses versioned migrations recorded in `schema_migrations` for
changes `create_all` cannot express, followed by `create_all` for any missing
table. Alembic was not adopted: for two tables and no deployed history, its
revision tree would cost more than it returns. That trade-off flips on a move to
PostgreSQL — which is a `DATABASE_URL` change plus a driver, since the
repository layer is engine-agnostic.

## 7. API design

Seven endpoints, documented with request/response/error examples in
[api.md](api.md).

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Liveness; touches no dependency |
| GET | `/health/ready` | Per-dependency readiness; `ok` or `degraded` with reasons |
| GET | `/alerts` | Paginated list, search and filters, with each alert's latest verdict |
| GET | `/alerts/{alert_id}` | One alert |
| GET | `/alerts/{alert_id}/analysis` | Latest **stored** assessment, no LLM call |
| POST | `/analyze-alert` | RAG + LLM analysis |
| POST | `/rag/reindex` | Rebuild the knowledge index |

Design choices worth naming:

- **Liveness and readiness are separate.** `/health` reports only that the
  process serves; readiness returns 200 even when degraded, because the service
  *is* up — browsing works without an LLM key. A healthcheck that failed on a
  missing key would restart a working container.
- **The list endpoint joins the latest assessment** (`latest_for_many`, one
  query) so a dashboard renders a triage queue without an N+1 fan-out.
- **Filtering and search happen in the database**, not the browser.
- **Expensive singletons are injected as providers**, not objects
  (`app/api/deps.py`). A dependency that built eagerly would raise during
  dependency resolution — before validation — turning a malformed body into a
  503 instead of a 422. The route calls the provider only once the request is
  known to be valid.
- **Every error is the same envelope**: `{"error": {code, message, request_id,
  details}}`, with a stable machine-readable `code`.

## 8. Security controls

Full threat model: [security.md](security.md). The controls, by layer:

**Input validation.** `extra="forbid"` on every model, so an alert carrying a
`classification` field is rejected rather than trusted. Enums for severity and
category, `IPvAnyAddress` for source IP, length bounds on every string,
`alert_id` restricted to `[A-Za-z0-9._:-]+` (it reaches logs and URLs), control
characters rejected in short identifier fields, and a far-future timestamp
guard.

**Before data leaves the estate.** `app/services/sanitize.py` redacts
credential-shaped values — provider keys, GitHub/Slack tokens, AWS key ids,
JWTs, `Authorization` headers, `--password=` flags, `key=value` secrets,
connection-string passwords, PEM blocks — from alert text and retrieved
knowledge before prompt construction, preserving the surrounding command so the
behaviour stays analysable. It reduces risk; it does not eliminate it.

**The model cannot act.** No `tools` or `functions` are offered in the provider
request. The codebase contains no command-execution path, and the API exposes no
endpoint that could isolate, block, disable or delete. Both are asserted by
tests.

**Guardrails after validation** (`_apply_guardrails`), because a response can be
schema-valid and still untrustworthy:

1. Citations are checked against the chunks actually retrieved; invented ids are
   dropped and metadata is taken from the retrieval, not the model.
2. Confidence is capped at 60 when no relevant knowledge was retrieved.
3. Classification/risk inconsistencies are flagged (Benign ≥ 40, Malicious < 60,
   Suspicious outside 30–75).
4. A recommended action proposing containment without a human-verification
   condition gets a mandatory advisory notice prepended and is flagged.
5. Alert text containing delimiter- or instruction-shaped content ("ignore
   previous instructions", a forged `</alert_data>`) forces human review, since
   an injection the model obeyed yields a verdict that passes every output check.
6. `human_review_required` is computed server-side from the verdict, risk,
   confidence, retrieval state, unsupported claims, warnings and that input
   check. The model cannot set it.

**Secrets and surface.** The key is a `SecretStr`, never in `repr()`; a
redacting filter scrubs it from every log handler; `.env` is gitignored and
excluded from both images; both containers run non-root with
`no-new-privileges`. `/docs` is disabled when `ENVIRONMENT=production`, CORS is
not a wildcard by default, and error responses never carry stack traces, SQL or
provider payloads.

## 9. Error handling

Every failure leaves the API as one envelope, with the detail logged
server-side against the request id instead (`app/api/errors.py`):

| Condition | Code | Status |
| --- | --- | --- |
| Request body/params failed validation | `validation_error` | 422 |
| Body over the byte limit | `payload_too_large` | 413 |
| Unknown alert id | `alert_not_found` | 404 |
| No stored assessment yet | `analysis_not_found` | 404 |
| No LLM key, or credentials rejected | `llm_unavailable` | 503 |
| Every attempt timed out | `llm_timeout` | 504 |
| Provider error, or retries exhausted | `llm_provider_error` | 502 |
| Model never produced valid output | `invalid_model_response` | 502 |
| Retrieval unavailable and mode is `fail` | `rag_unavailable` | 503 |
| Database unavailable | `database_unavailable` | 503 |
| Anything unhandled | `internal_error` | 500 |

Three principles hold throughout:

- **Never fabricate.** A failed analysis returns an error envelope with no
  `assessment` key at all, and nothing is persisted.
- **Degrade honestly where degrading is possible.** Broken retrieval still
  yields an assessment, explicitly marked as having no evidence behind it. A
  failed write still returns the assessment, flagged `persisted: false`.
- **Correlate.** One request id appears in the `X-Request-ID` header, the error
  body and every log line for that request. A client-supplied id is adopted only
  if it matches `^[A-Za-z0-9._-]{1,64}$`, so it cannot inject into a log line.

Validation errors report field **locations and error types only** — never the
submitted values, which may contain attacker-controlled alert text.

## 10. Known limitations

- **No authentication or authorisation.** Every endpoint is open, including
  `POST /rag/reindex`, which mutates server state. This belongs on a trusted
  network only.
- **Evaluation is not automated.** `data/alerts/eval_labels.json` holds expected
  classifications for all 45 alerts, but no scoring harness runs them against a
  live model, so there is no measured accuracy figure. Nothing in this repository
  claims one.
- **The default embedder is lexical, not semantic.** Feature hashing matches
  wording, so an alert phrased unlike the corpus retrieves poorly.
  `EMBEDDING_PROVIDER=openai` addresses this and is untested against a real key
  here.
- **Redaction is regex-based.** It will miss secrets that do not look like
  secrets — a fully lowercase password after `-p`, for instance, is deliberately
  not matched to avoid mangling ordinary command lines.
- **Prompt-injection resistance is defence in depth, not a proof.** The
  containment and the guardrails are tested; the model's own adherence to the
  system prompt is not guaranteed by anything in this codebase.
- **Single process, single writer.** The FAISS index is per-process and SQLite
  is single-writer, so a second backend replica would have its own index and
  contend on writes.
- **No streaming and no batch analysis.** One alert per request, blocking.
- **The dataset is synthetic.** 45 hand-built alerts across seven categories;
  realistic in shape, but not drawn from a real SOC.

## 11. Future improvements

Roughly in order of value returned per unit of work:

1. **Authentication and per-endpoint authorisation**, with `POST /rag/reindex`
   and `POST /analyze-alert` behind it, plus rate limiting — the largest gap
   between this prototype and something deployable.
2. **An evaluation harness** driving the 45 labelled alerts through a real model
   and reporting per-class precision/recall and score calibration, so prompt and
   retrieval changes can be judged instead of guessed at.
3. **Retrieval quality measurement** — a labelled query/chunk set, so the
   0.08 threshold and `top_k` of 4 rest on numbers rather than inspection.
4. **Hybrid retrieval** (BM25 alongside vectors) and a reranking pass; lexical
   and semantic matching fail on different alerts.
5. **Batch analysis** with bounded concurrency, so a queue can be triaged in one
   operation instead of one request per alert.
6. **PostgreSQL and a persisted vector store** once the corpus or the deployment
   outgrows one process — both are contained changes, by design.
7. **Analyst feedback capture** (agree / disagree / corrected verdict) stored
   alongside the assessment, which is the only honest route to measuring
   real-world accuracy and to few-shot improvement.
8. **Structured log shipping and metrics** — `LOG_FORMAT=json` exists; there is
   no metrics endpoint or dashboard yet.

# Reliability

Every dependency here can fail: the LLM provider, the embedding backend, the
vector index, the knowledge corpus, the database, the network between the
browser and the API. This document says what happens in each case.

Two rules govern all of it:

1. **Never fabricate.** If the analysis fails, the analyst gets an error, not a
   guess. If retrieval fails, they get an assessment that says it had no
   evidence — never invented citations.
2. **Fail at the right altitude.** A missing LLM key should not stop an analyst
   browsing alerts; a broken retriever should not cost them an assessment
   entirely. The service degrades where degrading is honest, and refuses where
   it is not.

`backend/tests/test_reliability.py` has one integration test per failure mode
below, each asserting the API stays up, nothing leaks, and nothing is invented.

---

## Failure modes

| Failure | Behaviour | Status | Code |
| --- | --- | --- | --- |
| LLM not configured | Refused; browsing still works | 503 | `llm_unavailable` |
| LLM credentials rejected | Refused | 503 | `llm_unavailable` |
| LLM provider error / unreachable | Retried, then refused | 502 | `llm_provider_error` |
| LLM timeout | Retried, then refused with "please retry" | 504 | `llm_timeout` |
| LLM returns malformed JSON | Retried with a correction note, then refused | 502 | `invalid_model_response` |
| Embedding backend fails | **Degrades**: analysis proceeds, marked `failed` | 200 | — |
| Vector store / index unusable | **Degrades** | 200 | — |
| Knowledge corpus missing | **Degrades** | 200 | — |
| Retrieval returns nothing relevant | Proceeds, marked `insufficient`, confidence capped | 200 | — |
| Database unavailable (read) | Refused | 503 | `database_unavailable` |
| Database write fails after analysis | **Assessment returned**, flagged unstored | 200 | — |
| Invalid alert submitted | Rejected with field locations | 422 | `validation_error` |
| Unknown `alert_id` | Rejected with guidance | 404 | `alert_not_found` |
| Body too large | Rejected before parsing | 413 | `payload_too_large` |
| Unexpected internal error | Generic envelope, details logged only | 500 | `internal_error` |
| Frontend cannot reach backend | "Cannot reach the backend", with retry | — | `network_error` |

## Never fabricate an AI result

When the model call fails, the response has **no `assessment` key at all** — it
is an error envelope, so there is no shape for a client to mistake for a
verdict. A test asserts this for every LLM failure path. A failed analysis is
also never persisted, so a later read cannot surface a phantom result.

Retries happen inside the engine (exponential backoff, on timeouts, 429/5xx and
malformed output), so a single blip does not reach the analyst at all. Only
exhausted retries surface.

## Three retrieval states, deliberately distinct

`retrieval.status` is the important field:

- **`relevant`** — chunks cleared the relevance threshold; `documents` lists
  them with scores.
- **`insufficient`** — retrieval ran and found nothing relevant enough. Not an
  error: the corpus simply has nothing for this alert.
- **`failed`** — the knowledge base could not be consulted at all.

`insufficient` and `failed` both mean "no evidence", but for opposite reasons,
and collapsing them would let a broken retriever look like a quiet one. In both
cases `documents` is empty and confidence is capped at 60; `failed` additionally
adds a validation warning, the review reason "knowledge retrieval failed", and a
`meta.notes` entry. The stored row keeps `retrieval_status`, so the audit trail
records *why* an old assessment had no evidence behind it.

The model is told which state it is in. On failure the knowledge block says
"KNOWLEDGE RETRIEVAL FAILED… assess from the alert data alone, state this
limitation, and keep confidence low" — it must not read an outage as "nothing
relevant exists".

**Degrading is the default, not the only option.** `RAG_FAILURE_MODE=fail`
refuses the request with `503 rag_unavailable` instead, for operators who would
rather have no assessment than an ungrounded one.

## Graceful degradation

- **No LLM key**: alerts, filters, search and stored assessments all work; only
  `/analyze-alert` returns 503. The dashboard shows a banner and disables the
  Analyse button, so the analyst learns before clicking.
- **Retrieval broken**: assessment proceeds, clearly marked (above).
- **Database write fails**: the assessment already cost a model call, so it is
  returned with `meta.persisted: false` and a note rather than thrown away.
- **Startup**: database initialisation, dataset seeding and index warm-up are
  each best-effort. A failure is logged and the API still starts, so
  `/health/ready` can report what is missing instead of the container
  crash-looping.

## Health checks

- **`GET /health`** — liveness. Touches no dependency, so it stays 200 while
  the database is down. This is the container healthcheck.
- **`GET /health/ready`** — readiness. Always 200 (the service *is* up), with
  `status: "ok" | "degraded"` and `degraded_reasons` naming each missing
  capability, plus `llm_configured`, `data_present`, `database_ready`,
  `alert_count` and `rag_index_ready`.

```json
{
  "status": "degraded",
  "degraded_reasons": [
    "alert/knowledge data directory missing",
    "knowledge index not built yet: it is built on first use, or retrieval has failed"
  ],
  "llm_configured": true, "data_present": false,
  "database_ready": true, "alert_count": 45, "rag_index_ready": false
}
```

## Correlation and structured logging

Every request gets an id — the client's `X-Request-ID` if it matches a safe
pattern, otherwise a generated one. It appears in the response header, in the
error body, and on every log line emitted while handling that request, so a
user-visible failure can be traced to its server-side cause in one grep.

`LOG_FORMAT=json` emits line-delimited JSON with `timestamp`, `level`, `logger`,
`request_id`, `message`, and extra fields (`method`, `path`, `status_code`,
`duration_ms`). Logs record what failed and why — attempt counts, error class,
redacted detail, latency — and never the prompt, the model's reasoning, the raw
response, or credentials.

## What clients never see

No stack traces, SQL, driver text, file paths, provider payloads, submitted
field values, or credentials. The detail is logged server-side against the
request id; the client gets a stable `code`, a sentence an analyst can act on,
and that id. Tests assert this across every failure path.

## Database resilience

WAL journaling, a busy timeout, and retries with backoff on transient lock/IO
errors mean a concurrent write does not surface as a user-visible failure.
Constraint and programming errors are not retried — repeating them cannot help.
See docs/persistence.md.

## Running the tests

```bash
cd backend && python -m pytest tests/test_reliability.py -v   # failure modes
cd backend && python -m pytest                                # everything
cd frontend && npm run test:e2e                               # incl. frontend/backend outage
```

The integration tests use the real app, real RAG service and a real temporary
database; only the LLM provider is faked, because calling one would make the
suite slow, costly and non-deterministic.

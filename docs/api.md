# API Reference

Seven endpoints across four groups: health, alerts, analysis, and knowledge-base
maintenance. Every example below was captured from a running instance.

**Base URL.** The backend listens on `http://localhost:8000`. Through the
dashboard's nginx proxy the same API is at `http://localhost:8080/api`, which
strips the prefix (`/api/health` → `/health`). Examples use the direct port.

**Interactive docs.** Swagger UI at `/docs`, ReDoc at `/redoc`, schema at
`/openapi.json` — all disabled when `ENVIRONMENT=production` unless
`ENABLE_API_DOCS=true`.

**There is no authentication.** Every endpoint is open, including the two POSTs.
See [security.md](security.md).

**Correlation.** Every response carries an `X-Request-ID` header, echoed in the
`request_id` of any error body and in every server log line for that request.
Send your own `X-Request-ID` to have it adopted, provided it matches
`^[A-Za-z0-9._-]{1,64}$`.

---

## Contents

| Method | Path | Purpose |
| --- | --- | --- |
| GET | [`/health`](#get-health) | Liveness |
| GET | [`/health/ready`](#get-healthready) | Readiness, per dependency |
| GET | [`/alerts`](#get-alerts) | List, search and filter alerts |
| GET | [`/alerts/{alert_id}`](#get-alertsalert_id) | One alert |
| GET | [`/alerts/{alert_id}/analysis`](#get-alertsalert_idanalysis) | Latest stored assessment |
| POST | [`/analyze-alert`](#post-analyze-alert) | Run RAG + LLM analysis |
| POST | [`/rag/reindex`](#post-ragreindex) | Rebuild the knowledge index |

---

## GET /health

Liveness. Checks nothing — it reports that the process is up and serving, which
is what a container healthcheck should restart on. Used as the Docker
`HEALTHCHECK` for the backend.

**Request:** no parameters, no body.

**Response `200`**

| Field | Type | Meaning |
| --- | --- | --- |
| `status` | string | Always `"ok"` when reached |
| `app` | string | Application name |
| `environment` | string | Value of `ENVIRONMENT` |

```bash
curl http://localhost:8000/health
```

```json
{"status":"ok","app":"AI-Powered Security Alert Analyst","environment":"development"}
```

**Errors:** none. If the process cannot serve, there is no response.

---

## GET /health/ready

Readiness. Reports which optional dependencies are in place. It returns **200
even when degraded**, because the service really is up: alert browsing and
stored assessments work without an LLM key. The flags let a dashboard or
operator see what is available.

It never builds the index or calls the LLM — it reports state, so it stays cheap.

**Request:** no parameters, no body.

**Response `200`**

| Field | Type | Meaning |
| --- | --- | --- |
| `status` | string | `"ok"` or `"degraded"` |
| `degraded_reasons` | string[] | One sentence per missing capability; empty when `ok` |
| `llm_configured` | bool | An API key is present |
| `data_present` | bool | `data/alerts/` and `data/knowledge/` both exist |
| `database_ready` | bool | The alerts table could be counted |
| `alert_count` | int \| null | Rows in `alerts`; null when the database is unavailable |
| `rag_index_ready` | bool | The knowledge index is built |

```bash
curl http://localhost:8000/health/ready
```

Degraded — running without an API key:

```json
{
  "status": "degraded",
  "degraded_reasons": ["no LLM API key configured: /analyze-alert is unavailable"],
  "llm_configured": false,
  "data_present": true,
  "database_ready": true,
  "alert_count": 45,
  "rag_index_ready": true
}
```

Fully configured:

```json
{
  "status": "ok",
  "degraded_reasons": [],
  "llm_configured": true,
  "data_present": true,
  "database_ready": true,
  "alert_count": 45,
  "rag_index_ready": true
}
```

**Errors:** none — an unavailable database is reported in the body
(`database_ready: false`), not as a failure.

---

## GET /alerts

Paginated listing of dataset alerts, newest first, each with a summary of its
latest stored assessment. Filtering and search are done in the database.

**Request — query parameters** (all optional)

| Parameter | Type | Default | Notes |
| --- | --- | --- | --- |
| `severity` | enum | — | `low` \| `medium` \| `high` \| `critical` |
| `category` | enum | — | One of the seven alert categories |
| `classification` | enum | — | `Benign` \| `Suspicious` \| `Malicious`. Filters on the **latest** verdict; unanalysed alerts are excluded |
| `q` | string | — | Free-text over alert id, hostname, username, process, command line and description. Max 200 chars; `%` and `_` are treated literally |
| `limit` | int | `50` | 1–200 |
| `offset` | int | `0` | ≥ 0 |

**Response `200`**

| Field | Type | Meaning |
| --- | --- | --- |
| `total` | int | Total matching alerts, ignoring pagination |
| `limit`, `offset` | int | Echoed back |
| `items` | object[] | Alert telemetry plus the four `latest_*` / `has_analysis` fields below |

Each item is the full alert (`alert_id`, `timestamp`, `hostname`, `username`,
`source_ip`, `process`, `command_line`, `severity`, `category`, `description`)
plus:

| Field | Type | Meaning |
| --- | --- | --- |
| `has_analysis` | bool | A stored assessment exists |
| `latest_classification` | string \| null | Verdict of the most recent assessment |
| `latest_risk_score` | int \| null | 0–100 |
| `latest_analyzed_at` | datetime \| null | When it was produced |

```bash
curl "http://localhost:8000/alerts?limit=1"
```

```json
{
  "total": 45,
  "limit": 1,
  "offset": 0,
  "items": [
    {
      "alert_id": "ALRT-1010",
      "timestamp": "2025-09-14T14:20:03Z",
      "hostname": "WKSTN-ENG-05",
      "username": "t.almeida",
      "source_ip": "10.20.22.77",
      "process": "wmic.exe",
      "command_line": "wmic process call create \"cmd.exe /c calc.exe\"",
      "severity": "medium",
      "category": "Suspicious Command Execution",
      "description": "wmic process-call-create used to spawn a child process; benign target but the technique is frequently abused for lateral execution.",
      "has_analysis": true,
      "latest_classification": "Suspicious",
      "latest_risk_score": 63,
      "latest_analyzed_at": "2026-09-23T11:52:00.256663"
    }
  ]
}
```

More examples:

```bash
curl "http://localhost:8000/alerts?severity=critical&limit=5"
curl "http://localhost:8000/alerts?q=powershell"
curl "http://localhost:8000/alerts?classification=Malicious"
curl "http://localhost:8000/alerts?category=Brute-force%20Authentication"
```

**Errors**

| Status | Code | When |
| --- | --- | --- |
| 422 | `validation_error` | Unknown enum value, `limit` out of range, `q` too long |
| 503 | `database_unavailable` | The database could not be read |

```bash
curl "http://localhost:8000/alerts?severity=extreme"
```

```json
{"error":{"code":"validation_error","message":"Request body failed validation.",
 "request_id":"f04f2ebf28e541ea",
 "details":[{"location":"query.severity","type":"enum",
             "message":"Input should be 'low', 'medium', 'high' or 'critical'"}]}}
```

---

## GET /alerts/{alert_id}

One alert, in the same shape as a listing item.

**Request — path parameter**

| Parameter | Type | Notes |
| --- | --- | --- |
| `alert_id` | string | 1–64 chars matching `^[A-Za-z0-9._:-]+$`. The pattern is enforced at the boundary because the id reaches logs and URLs |

```bash
curl http://localhost:8000/alerts/ALRT-1002
```

```json
{
  "alert_id": "ALRT-1002",
  "timestamp": "2025-09-14T02:47:51Z",
  "hostname": "WKSTN-HR-12",
  "username": "s.kaur",
  "source_ip": "10.20.9.61",
  "process": "powershell.exe",
  "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA...truncated...",
  "severity": "high",
  "category": "PowerShell Execution",
  "description": "Encoded, hidden-window PowerShell launched off-hours from a standard user workstation. Encoded payload decodes to a network download routine.",
  "has_analysis": true,
  "latest_classification": "Malicious",
  "latest_risk_score": 91,
  "latest_analyzed_at": "2026-09-23T16:36:30.986014"
}
```

**Errors**

| Status | Code | When |
| --- | --- | --- |
| 404 | `alert_not_found` | No alert with that id |
| 422 | `validation_error` | The id violates the pattern or length bounds |
| 503 | `database_unavailable` | The database could not be read |

```json
{"error":{"code":"alert_not_found",
 "message":"No alert with id 'ALRT-9999'. Send a complete alert payload to analyse an alert that is not in the dataset.",
 "request_id":"9226541ab7ec43be","details":null}}
```

---

## GET /alerts/{alert_id}/analysis

The most recent **stored** assessment. No LLM call, no retrieval — this reads
the database. Returns the same body shape as `POST /analyze-alert`, with
`meta.cached: true`.

**Request — path parameter:** `alert_id`, as above.

```bash
curl http://localhost:8000/alerts/ALRT-1002/analysis
```

Response: see [`POST /analyze-alert`](#post-analyze-alert) for the full shape.
`meta` differs:

```json
{"meta": {"analysis_id": 3, "analyzed_at": "2026-09-23T16:36:30.986014",
          "provider": "openai", "model": "gpt-4o-mini", "prompt_version": "analysis-v1",
          "attempts": 1, "latency_ms": 2380, "persisted": true, "cached": true, "notes": []}}
```

**Errors**

| Status | Code | When |
| --- | --- | --- |
| 404 | `analysis_not_found` | The alert exists but has never been analysed |
| 404 | `alert_not_found` | No alert with that id |
| 422 | `validation_error` | Malformed id |
| 503 | `database_unavailable` | The database could not be read |

```json
{"error":{"code":"analysis_not_found",
 "message":"Alert 'ALRT-1044' has no stored analysis yet. POST /analyze-alert first.",
 "request_id":"a51e22b48b43491e","details":null}}
```

---

## POST /analyze-alert

Retrieves relevant internal security knowledge, asks the LLM for a structured
assessment, validates and guardrails it, stores it, and returns it.

**The result is advisory.** It is AI-generated, must be reviewed by a human
analyst, and never triggers an action.

**Request body** — `Content-Type: application/json`, max 256 KB. Two forms:

**1. By alert id** — the alert is loaded from the database, which stays
authoritative. A `description` may be sent alongside for readability; if it
differs from the stored record it is ignored and a note says so.

```json
{"alert_id": "ALRT-1002"}
```

**2. By payload** — a complete alert, for something not in the dataset. Nested
under `alert`, or sent flat at the top level (both are accepted; flat is
repacked internally). Payload analyses are **not persisted**.

```json
{"alert": {
  "alert_id": "ALRT-ADHOC-1",
  "timestamp": "2025-09-20T03:14:00Z",
  "hostname": "WKSTN-OPS-01",
  "username": "a.singh",
  "source_ip": "10.20.5.9",
  "process": "rundll32.exe",
  "command_line": "rundll32.exe javascript:\"..\\mshtml,RunHTMLApplication \"",
  "severity": "high",
  "category": "Suspicious Command Execution",
  "description": "rundll32 invoked with a javascript: protocol handler."
}}
```

Required alert fields: all ten. `severity` and `category` are enums,
`source_ip` must parse as an IP address, `timestamp` as a datetime. Unknown
fields are rejected — including anything resembling a verdict, which the alert
schema deliberately has no place for.

**Response `200`** — four blocks.

`assessment` — the verdict plus server-side safety metadata:

| Field | Type | Meaning |
| --- | --- | --- |
| `classification` | enum | `Benign` \| `Suspicious` \| `Malicious` |
| `risk_score` | int | 0–100, potential harm weighted by likelihood |
| `confidence_score` | int | 0–100; capped at 60 when no relevant knowledge was retrieved |
| `reasoning` | string | Explanation linking evidence to the conclusion |
| `recommended_action` | string | Advisory next steps for a human |
| `evidence` | string[] | Concrete observations from the alert or knowledge |
| `unsupported_claims` | string[] | Statements the data does not support, flagged by the model |
| `retrieved_knowledge` | object[] | Chunks actually cited, **verified against retrieval** — invented ids are dropped |
| `knowledge_sufficient` | bool | Usable evidence was retrieved |
| `human_review_required` | bool | Computed server-side; the model cannot set it |
| `human_review_reasons` | string[] | Why review is required |
| `validation_warnings` | string[] | Raised by the backend checking the model's output |
| `advisory_notice` | string | Fixed advisory text |

`retrieval` — what grounding was available:

| Field | Type | Meaning |
| --- | --- | --- |
| `status` | enum | `relevant` \| `insufficient` \| `failed` — see below |
| `sufficient` | bool | False when no usable evidence was retrieved |
| `note` | string | Human-readable explanation |
| `documents` | object[] | `chunk_id`, `doc_name`, `title`, `category`, `source`, `score`, `excerpt` (500 chars) |
| `similarity_scores` | float[] | Scores of `documents`, same order |
| `cited_chunk_ids` | string[] | Which of those the model relied on |

`meta` — provenance: `analysis_id` (null when not persisted), `analyzed_at`,
`provider`, `model`, `prompt_version`, `attempts`, `latency_ms`, `persisted`,
`cached`, `notes`.

```bash
curl -X POST http://localhost:8000/analyze-alert \
  -H "Content-Type: application/json" \
  -d '{"alert_id":"ALRT-1002"}'
```

```json
{
  "alert": { "alert_id": "ALRT-1002", "severity": "high", "…": "…" },
  "assessment": {
    "classification": "Malicious",
    "risk_score": 91,
    "confidence_score": 86,
    "reasoning": "Base64-encoded, hidden-window PowerShell launched off-hours from a standard user workstation, decoding to a network download routine. This is a download cradle pattern described in the knowledge base.",
    "recommended_action": "Escalate to incident response and isolate the host after analyst verification. Preserve the decoded payload for analysis.",
    "evidence": ["-enc with -w hidden", "decoded payload performs a network download"],
    "unsupported_claims": [],
    "retrieved_knowledge": [],
    "knowledge_sufficient": true,
    "human_review_required": true,
    "human_review_reasons": ["classified as Malicious", "high risk score (91)"],
    "validation_warnings": [],
    "advisory_notice": "Advisory output only. This assessment was generated by an AI model and must be reviewed by a human analyst. It does not authorise or trigger any containment, blocking, deletion, or account action."
  },
  "retrieval": {
    "status": "relevant",
    "sufficient": true,
    "note": "4 relevant knowledge chunk(s) retrieved.",
    "documents": [
      {
        "chunk_id": "01-powershell-attacks#0",
        "doc_name": "01-powershell-attacks",
        "title": "PowerShell Security",
        "category": "PowerShell Execution",
        "source": "internal-knowledge-base",
        "score": 0.3167,
        "excerpt": "# PowerShell Attack Techniques and Indicators\n\nPowerShell is a legitimate administration tool, which is exactly why attackers abuse it (MITRE ATT&CK T1059.001)…"
      }
    ],
    "similarity_scores": [0.3167],
    "cited_chunk_ids": []
  },
  "meta": {
    "analysis_id": 3, "analyzed_at": "2026-09-23T16:36:30.986014",
    "provider": "openai", "model": "gpt-4o-mini", "prompt_version": "analysis-v1",
    "attempts": 1, "latency_ms": 2380, "persisted": true, "cached": false, "notes": []
  }
}
```

### Retrieval states

`insufficient` and `failed` both mean "no evidence", for different reasons, and
an analyst needs to know which — collapsing them would let a broken retriever
pass for a quiet one.

| `status` | Meaning | Effect on the assessment |
| --- | --- | --- |
| `relevant` | Chunks cleared the similarity threshold | Normal grounded analysis |
| `insufficient` | Retrieval ran; nothing was relevant enough | Confidence capped at 60; stated in `note` |
| `failed` | Retrieval could not run at all | Confidence capped; `validation_warnings` and `meta.notes` say the knowledge base could not be consulted; flagged for human review |

`failed` returns 200 by default. Set `RAG_FAILURE_MODE=fail` to return
`503 rag_unavailable` instead.

**Errors**

| Status | Code | When |
| --- | --- | --- |
| 404 | `alert_not_found` | `alert_id` is not in the dataset |
| 413 | `payload_too_large` | Body over `MAX_REQUEST_BYTES` |
| 422 | `validation_error` | Neither `alert_id` nor a complete alert; bad enum; unknown field; `alert_id` disagrees with `alert.alert_id` |
| 502 | `invalid_model_response` | The model never returned a valid assessment after retries |
| 502 | `llm_provider_error` | Provider error, or retries exhausted |
| 503 | `llm_unavailable` | No API key, or credentials rejected |
| 503 | `rag_unavailable` | Retrieval failed and `RAG_FAILURE_MODE=fail` |
| 503 | `database_unavailable` | The database could not be read |
| 504 | `llm_timeout` | Every attempt timed out |

A failed analysis returns an error envelope with **no `assessment` key at all**,
and nothing is persisted. The API never fabricates a verdict.

```bash
curl -X POST http://localhost:8000/analyze-alert \
  -H "Content-Type: application/json" -d '{}'
```

```json
{"error":{"code":"validation_error","message":"Request body failed validation.",
 "request_id":"0cefe1c3dcec4f37",
 "details":[{"location":"body","type":"value_error",
             "message":"Value error, provide either 'alert_id' or a complete alert payload"}]}}
```

Without an API key:

```json
{"error":{"code":"llm_unavailable",
 "message":"AI analysis is not available: the LLM provider is not configured or rejected the credentials.",
 "request_id":"2006fcef4d0a483d","details":null}}
```

Validation `details` report **field locations and error types only** — never the
submitted values, which may contain attacker-controlled alert text.

---

## POST /rag/reindex

Re-reads `data/knowledge/`, re-chunks, re-embeds and rebuilds the index in
place, so corpus edits take effect without a restart. Idempotent and safe to
repeat.

`data/` is bind-mounted read-only into the container, so an edit on the host is
visible immediately.

> This mutates server state and is **unauthenticated**, like every other
> endpoint here. In a deployed system it belongs behind authentication.

**Request:** no parameters, no body.

**Response `200`**

| Field | Type | Meaning |
| --- | --- | --- |
| `status` | string | `"ok"` |
| `documents` | int | Documents loaded |
| `chunks` | int | Chunks indexed |
| `duration_ms` | int | Wall-clock rebuild time |

```bash
curl -X POST http://localhost:8000/rag/reindex
```

```json
{"status":"ok","documents":8,"chunks":24,"duration_ms":26}
```

**Errors**

| Status | Code | When |
| --- | --- | --- |
| 503 | `rag_unavailable` | Corpus missing or unreadable, embedder unavailable, index could not be built |

---

## Error envelope

Every failure, from every endpoint, has the same shape:

```json
{
  "error": {
    "code": "alert_not_found",
    "message": "No alert with id 'ALRT-9999'.",
    "request_id": "3f6c1b9a2d4e5f70",
    "details": null
  }
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `code` | string | Stable and machine-readable — branch on this, not on `message` |
| `message` | string | Safe to show a user |
| `request_id` | string | Matches `X-Request-ID` and the server logs |
| `details` | object[] \| null | Present on `validation_error`: `location`, `type`, `message` per issue (max 20) |

Stack traces, SQL, provider payloads and credentials never reach a client; the
detail is logged server-side against the request id instead.

### All error codes

| Code | Status | Meaning |
| --- | --- | --- |
| `validation_error` | 422 | Request body or parameters failed validation |
| `payload_too_large` | 413 | Body exceeded `MAX_REQUEST_BYTES` |
| `alert_not_found` | 404 | No alert with that id |
| `analysis_not_found` | 404 | The alert has no stored assessment |
| `not_found` | 404 | Unknown route |
| `method_not_allowed` | 405 | Wrong method for the route |
| `http_error` | varies | Any other HTTP-level error raised by the framework |
| `llm_unavailable` | 503 | No API key, or credentials rejected |
| `llm_timeout` | 504 | Every LLM attempt timed out |
| `llm_provider_error` | 502 | Provider error, or retries exhausted |
| `invalid_model_response` | 502 | Model output never validated |
| `rag_unavailable` | 503 | Knowledge base could not be consulted (`RAG_FAILURE_MODE=fail`) |
| `database_unavailable` | 503 | Database read or write failed |
| `internal_error` | 500 | Unhandled server error |

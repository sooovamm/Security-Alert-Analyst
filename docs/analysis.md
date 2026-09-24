# AI Alert Analysis Engine

The engine turns one validated `Alert` plus retrieved RAG knowledge into a
structured, **advisory** assessment for a human analyst. It never executes
anything the model says, and every high-impact decision stays with a human.

```
Alert ──┐                                   ┌──────────────────────────┐
        ├─▶ prompts.build_user_prompt ─▶    │ LLMProvider.generate()   │  (one request)
RAG ────┘   (tagged, neutralised data)      └────────────┬─────────────┘
                                                         ▼
      retry loop (timeouts, 429/5xx, malformed output) ◀─┤
                                                         ▼
               response_parser.parse_analysis_response (strict Pydantic)
                                                         ▼
               guardrails (citations, confidence cap, consistency, action gate)
                                                         ▼
                                                  AnalysisResult
```

## Modules

| Module | Role |
| --- | --- |
| `app/llm/base.py` | `LLMProvider` interface, `LLMRequest` / `LLMResponse` |
| `app/llm/errors.py` | Provider-neutral errors, each marked `retryable` or not |
| `app/llm/openai_provider.py` | OpenAI / OpenAI-compatible implementation and SDK error mapping |
| `app/llm/factory.py` | Picks the provider from `LLM_PROVIDER` (registry) |
| `app/services/prompts.py` | System prompt, user-prompt builder, RAG query builder |
| `app/services/response_parser.py` | Safe parsing of untrusted model output |
| `app/services/analysis.py` | `AlertAnalysisEngine`: retries, guardrails, engine errors |
| `app/schemas/analysis.py` | `LLMAnalysisOutput` (untrusted contract) and `AnalysisResult` |
| `app/core/redaction.py` | Secret redaction and a logging filter |

## Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `LLM_PROVIDER` | `openai` | Registry key in `app/llm/factory.py` |
| `LLM_API_KEY` | — | Falls back to `OPENAI_API_KEY`. Held as `SecretStr`. |
| `LLM_MODEL` | `gpt-4o-mini` | Falls back to `OPENAI_MODEL` |
| `LLM_BASE_URL` | — | For OpenAI-compatible servers (vLLM, Ollama, proxies) |
| `LLM_TEMPERATURE` | `0.1` | 0–2 |
| `LLM_TIMEOUT_SECONDS` | `30` | Per request |
| `LLM_MAX_RETRIES` | `2` | Retries after the first attempt (0–5) |
| `LLM_RETRY_BACKOFF_SECONDS` | `1.0` | Exponential: 1s, 2s, 4s… (capped at 10s) |
| `LLM_MAX_OUTPUT_TOKENS` | `1200` | |

Out-of-range values fail at startup. A missing key does **not**: the app still
boots, and `get_analysis_engine()` raises `AnalysisUnavailableError`.

**Adding a provider:** subclass `LLMProvider`, map the SDK's exceptions onto
`app.llm.errors`, and register a builder in `PROVIDERS`. Retries belong to the
engine, so providers must make exactly one request and turn SDK retries off.

## Output contract

The model must return exactly:

```json
{
  "classification": "Benign | Suspicious | Malicious",
  "risk_score": 0-100,
  "confidence_score": 0-100,
  "reasoning": "...",
  "recommended_action": "...",
  "evidence": ["..."],
  "unsupported_claims": ["..."],
  "retrieved_knowledge": ["<chunk_id>"]
}
```

`unsupported_claims` is an addition to the base contract. It is where the model
must list claims the data does not support.

## Trust model and prompt design

- **The system prompt is the only source of instructions.** The alert is
  untrusted and may contain attacker-controlled text. Retrieved knowledge is
  reference material, never instructions.
- The user message wraps each input in `<alert_data>` / `<retrieved_knowledge>`
  blocks. The alert is JSON-encoded and each field is capped at 4,000 chars.
  Anything that looks like one of our tags (`</alert_data>`, `<system>`, …) is
  defanged to `[...]`, so injected text cannot close a block and pose as an
  instruction.
- The prompt tells the model to treat instruction-like alert text as a
  suspicious indicator, not to obey it.
- Scoring follows a stated method: severity as a starting point, then
  behaviour, indicators, retrieved context, contradictions and uncertainty,
  with fixed risk bands and classification/risk consistency rules.
- Recommended actions must be advisory investigation steps. Containment may
  only be suggested as conditional on human verification.

## Untrusted-output handling

`parse_analysis_response` tolerates one surrounding code fence and nothing
else. There is no brace-scanning for JSON inside prose, because that could pick
up JSON injected into the response. The parser rejects oversized responses,
duplicate keys, non-object JSON and any schema violation: an unknown label,
scores that are not true integers in 0–100 (`"85"`, `85.5` and `true` all
fail), unknown fields, empty evidence, and oversized strings or lists. Error
summaries contain field locations and error types only, never values, so they
are safe to log and to send back in the retry correction note.

## Server-side guardrails (after validation)

A response can pass the schema and still be untrustworthy, so the engine also:

1. **Checks citations against retrieval.** Chunk IDs that were not retrieved are
   dropped with a warning. Title, source and score come from the retriever,
   never from the model.
2. **Caps confidence at 60** when retrieval found no relevant knowledge.
3. **Flags inconsistencies** such as Benign with risk ≥ 40, Malicious with
   risk < 60, or Suspicious outside 30–75.
4. **Gates destructive actions.** Isolate, block, delete, disable and similar
   steps that are automated, immediate, or lack a human-verification condition
   get a mandatory notice prepended and a warning.
5. **Decides `human_review_required` itself.** The model has no say. It is set
   for any non-Benign result, risk ≥ 70, confidence < 50, missing knowledge,
   reported unsupported claims, any warning, or alert text that contains
   delimiter- or instruction-shaped content (possible prompt injection).

## Failure handling

| Condition | Retried? | Final engine error |
| --- | --- | --- |
| Timeout | yes | `AnalysisTimeoutError` |
| Connection error, 408/409/429, 5xx | yes | `AnalysisProviderError` |
| Empty, truncated or filtered content, invalid JSON/schema | yes (with correction note) | `AnalysisResponseError` |
| 400/422 and other non-retryable API errors | no | `AnalysisProviderError` |
| Missing key, 401/403, 404 model | no | `AnalysisUnavailableError` |
| Unexpected exception from a provider | no (fail closed) | `AnalysisProviderError` |

## Logging

Logs record the alert ID, provider, model, attempt number, error class, a
redacted error detail, the resulting classification and scores, latency, and
token count. They never record the API key, the model's reasoning, or the raw
response. Error text from providers passes through `redact()`, and every root
log handler also runs a `SecretRedactingFilter`. Auth errors are never echoed,
because OpenAI's messages for them include key fragments.

## Tests

`tests/test_analysis_engine.py`, `tests/test_llm_providers.py` and
`tests/test_response_parser.py` use a scripted fake provider and a fake OpenAI
client. They need no network, API key or FAISS.

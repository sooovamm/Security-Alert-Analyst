"""Safe parsing of raw model output into `LLMAnalysisOutput`.

The model's text is treated as hostile input:

- size-capped before parsing;
- a single surrounding markdown code fence is tolerated, nothing else — no
  "find the first brace" heuristics that could pick up injected JSON;
- `json.loads` with a hook that rejects duplicate keys (a classic way to make
  two parsers disagree about a value);
- top level must be an object;
- then strict Pydantic validation.

Errors are summarised as field locations + error types only, never echoing
values, so they are safe to log and to feed back in a correction prompt.
"""
from __future__ import annotations

import json
import re
from typing import Any

from pydantic import ValidationError

from app.schemas.analysis import LLMAnalysisOutput

MAX_RESPONSE_CHARS = 20_000

_FENCE_RE = re.compile(r"^```(?:json)?\s*\n?(.*?)\n?```$", re.DOTALL | re.IGNORECASE)


class MalformedResponseError(ValueError):
    """Model output could not be parsed/validated. `summary` is value-free."""

    def __init__(self, summary: str) -> None:
        super().__init__(summary)
        self.summary = summary


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise MalformedResponseError(f"duplicate key {key!r} in JSON object")
        out[key] = value
    return out


def summarise_validation_error(exc: ValidationError) -> str:
    issues = []
    for err in exc.errors()[:8]:
        loc = ".".join(str(p) for p in err["loc"]) or "<root>"
        issues.append(f"{loc}: {err['type']}")
    more = "" if exc.error_count() <= 8 else f" (+{exc.error_count() - 8} more)"
    return "schema validation failed: " + "; ".join(issues) + more


def parse_analysis_response(raw: str) -> LLMAnalysisOutput:
    if not isinstance(raw, str) or not raw.strip():
        raise MalformedResponseError("empty response")
    if len(raw) > MAX_RESPONSE_CHARS:
        raise MalformedResponseError(f"response exceeds {MAX_RESPONSE_CHARS} characters")

    text = raw.strip()
    fence = _FENCE_RE.match(text)
    if fence:
        text = fence.group(1).strip()

    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicates)
    except MalformedResponseError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        detail = getattr(exc, "msg", type(exc).__name__)
        raise MalformedResponseError(f"response is not valid JSON ({detail})") from None

    if not isinstance(data, dict):
        raise MalformedResponseError(
            f"top-level JSON must be an object, got {type(data).__name__}"
        )

    try:
        return LLMAnalysisOutput.model_validate(data)
    except ValidationError as exc:
        raise MalformedResponseError(summarise_validation_error(exc)) from None

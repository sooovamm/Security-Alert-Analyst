"""Secret redaction for anything that may reach a log line.

Provider SDK exceptions sometimes echo request details (e.g. "Incorrect API
key provided: sk-abc..."). Anything derived from an external error is passed
through `redact()` before logging, and `SecretRedactingFilter` applies the same
scrubbing to every record as a second line of defence.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Iterable

REDACTED = "[REDACTED]"

# Common credential shapes: OpenAI/Anthropic-style keys, bearer tokens, and
# generic `api_key=...` / `"authorization": "..."` pairs.
_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"),
    re.compile(
        r"(?i)(\b(?:api[_-]?key|authorization|x-api-key|token|secret)\b[\"']?\s*[:=]\s*[\"']?)"
        r"[^\s\"',}]{6,}"
    ),
)


def redact(text: object, secrets: Iterable[str | None] = ()) -> str:
    """Return `text` as a string with known secrets and credential-shaped
    substrings replaced by `[REDACTED]`."""
    out = str(text)
    for secret in secrets:
        if secret and len(secret) >= 4:
            out = out.replace(secret, REDACTED)
    for pat in _PATTERNS:
        if pat.groups:
            out = pat.sub(lambda m: m.group(1) + REDACTED, out)
        else:
            out = pat.sub(REDACTED, out)
    return out


class SecretRedactingFilter(logging.Filter):
    """Logging filter that scrubs the fully formatted message of each record."""

    def __init__(self, secrets: Iterable[str | None] = ()) -> None:
        super().__init__()
        self._secrets = [s for s in secrets if s]

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # malformed format args: leave record untouched
            return True
        cleaned = redact(message, self._secrets)
        if cleaned != message:
            record.msg = cleaned
            record.args = None
        return True

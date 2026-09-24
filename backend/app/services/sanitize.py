"""Telemetry sanitisation before alert data leaves the building.

Analysing an alert means sending its telemetry to a third-party LLM provider.
Command lines are the worst offender: real SOC data routinely contains
passwords typed on the command line, API keys, connection strings and tokens.
Those are credentials for *your* estate, and once sent they are outside your
control (see docs/security.md).

This layer redacts credential-shaped values from alert text before prompt
construction. It is deliberately conservative: it targets patterns that are
almost certainly secrets, and leaves the surrounding command intact so the
model can still reason about the behaviour ("a password was passed on the
command line" is itself a useful signal).

It is a **risk reduction, not a guarantee** — regexes cannot recognise every
secret. Data minimisation (not collecting the field at all) and provider
controls remain the primary defences.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

REDACTED = "[REDACTED-SECRET]"

# Each pattern either matches a whole credential-shaped token, or uses a
# capture group for the "keyword=" prefix that must be preserved.
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Provider API keys and personal access tokens.
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{12,}"), ""),
    (re.compile(r"\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}"), ""),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), ""),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), ""),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}"), ""),
    # JWTs.
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), ""),
    # Authorization headers.
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._\-+/=]{12,}"), r"\1 "),
    # Credential flags with a separator: --password=X, -pass: X, /pw X.
    (re.compile(r"(?i)(\s[-/]{1,2}(?:p|pw|pass|password|passwd)[=: ]\s?)(?!\s)([^\s\"']{3,})"),
     r"\1"),
    # Attached form, as in `mysql -pSuperSecret123`. Only redacted when the
    # value does not look like an ordinary word, so `-path C:\Scripts` and
    # `-profile default` are left alone. A fully lowercase password is missed
    # here by design: the alternative is mangling every command line.
    (re.compile(r"(?i)(\s-p)(?=[^\s]*[A-Z0-9!@#$%^&*])([^\s\"']{5,})"), r"\1"),
    # `net use \\srv\share /user:admin PASSWORD` — the token after /user:NAME,
    # unless it is another switch.
    (re.compile(r"(?i)(/user:\S+\s+)(?![-/])([^\s\"']{3,})"), r"\1"),
    # key=value style: password=..., api_key: "...", token='...'.
    (re.compile(
        r"(?i)\b((?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|"
        r"password|passwd|pwd|token|auth|credential)s?\b\s*[:=]\s*[\"']?)([^\s\"',;&)]{4,})"
    ), r"\1"),
    # ConvertTo-SecureString -String 'plaintext'
    (re.compile(r"(?i)(-String\s+)(['\"][^'\"]{4,}['\"])"), r"\1"),
    # Connection strings: scheme://user:password@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{1,15}://[^\s:/@]{1,64}:)([^\s@]{3,})(@)"), r"\1\3"),
    # Private key blocks.
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), ""),
)


@dataclass(frozen=True)
class SanitisationReport:
    """What was redacted, so the assessment can say so honestly."""

    redactions: int = 0
    fields: tuple[str, ...] = ()

    @property
    def applied(self) -> bool:
        return self.redactions > 0

    def note(self) -> str:
        if not self.applied:
            return ""
        fields = ", ".join(self.fields)
        return (
            f"{self.redactions} credential-shaped value(s) were redacted from this alert "
            f"({fields}) before it was sent to the model."
        )


def redact_text(text: str) -> tuple[str, int]:
    """Return the text with credential-shaped values replaced, and a count."""
    if not text:
        return text, 0
    total = 0
    result = text
    for pattern, prefix in _PATTERNS:
        # `prefix` is bound as a default: a late-binding closure would make every
        # pattern use the last one's replacement.
        def _replace(match: re.Match[str], keep: str = prefix) -> str:
            nonlocal total
            total += 1
            # Keep the keyword/scheme prefix where there is one, drop the value.
            return (match.expand(keep) if keep else "") + REDACTED

        result = pattern.sub(_replace, result)
    return result, total


# Fields that can plausibly carry a secret. `hostname`, `username`, `severity`
# and friends are identifiers, not secret material, and redacting them would
# destroy the analysis without protecting anything.
SANITISED_FIELDS = ("command_line", "description", "process")


def sanitise_alert_fields(
    values: dict[str, object],
) -> tuple[dict[str, object], SanitisationReport]:
    """Redact secrets from the alert fields that can carry them."""
    cleaned = dict(values)
    touched: list[str] = []
    total = 0
    for field in SANITISED_FIELDS:
        value = cleaned.get(field)
        if isinstance(value, str):
            new_value, count = redact_text(value)
            if count:
                cleaned[field] = new_value
                touched.append(field)
                total += count
    return cleaned, SanitisationReport(redactions=total, fields=tuple(touched))

"""Provider-neutral LLM exceptions.

Each provider maps its SDK-specific errors onto these types, so the analysis
engine's retry policy never depends on a particular vendor. `retryable` tells
the caller whether another attempt could plausibly succeed. Messages must be
safe to log: providers pass them through `redact()` before raising.
"""
from __future__ import annotations


class LLMError(Exception):
    retryable: bool = False

    def __init__(self, message: str, *, retryable: bool | None = None) -> None:
        super().__init__(message)
        if retryable is not None:
            self.retryable = retryable


class LLMConfigurationError(LLMError):
    """Missing key, unknown provider, bad model name. Never retried."""

    retryable = False


class LLMTimeoutError(LLMError):
    """The provider did not answer within the configured timeout."""

    retryable = True


class LLMProviderError(LLMError):
    """Transport or API error. Retryable for rate limits, 5xx and connection
    failures; not retryable for auth/permission/bad-request errors."""


class LLMResponseError(LLMError):
    """The provider answered but the payload is unusable (empty, refused,
    truncated). Retryable: a fresh sample may be well-formed."""

    retryable = True

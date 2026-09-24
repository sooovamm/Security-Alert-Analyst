"""OpenAI (and OpenAI-compatible) chat-completions provider.

`openai` is imported lazily so the rest of the app — and the unit tests — do
not need the SDK or network access. SDK-level retries are disabled
(`max_retries=0`) because the analysis engine owns the retry policy.
A pre-built client can be injected for testing.
"""
from __future__ import annotations

import logging
from typing import Any

from app.core.redaction import redact
from app.llm.base import LLMProvider, LLMRequest, LLMResponse
from app.llm.errors import (
    LLMConfigurationError,
    LLMError,
    LLMProviderError,
    LLMResponseError,
    LLMTimeoutError,
)

logger = logging.getLogger(__name__)

_RETRYABLE_STATUS = {408, 409, 429}


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str | None = None,
        timeout_seconds: float = 30.0,
        client: Any | None = None,
    ) -> None:
        if not model:
            raise LLMConfigurationError("LLM model name is empty")
        self.model = model
        self._api_key = api_key
        if client is not None:
            self._client = client
        else:
            if not api_key:
                raise LLMConfigurationError("LLM API key is not configured")
            try:
                from openai import OpenAI  # lazy import
            except ImportError as exc:  # pragma: no cover - dependency is pinned
                raise LLMConfigurationError("openai package is not installed") from exc
            self._client = OpenAI(
                api_key=api_key,
                base_url=base_url or None,
                timeout=timeout_seconds,
                max_retries=0,
            )

    def generate(self, request: LLMRequest) -> LLMResponse:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.user_prompt},
            ],
            "temperature": request.temperature,
            "max_tokens": request.max_output_tokens,
            "timeout": request.timeout_seconds,
        }
        if request.json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        try:
            completion = self._client.chat.completions.create(**kwargs)
        except Exception as exc:
            raise self._map_error(exc) from None

        try:
            choice = completion.choices[0]
            content = choice.message.content
            finish_reason = getattr(choice, "finish_reason", None)
        except (AttributeError, IndexError, TypeError):
            raise LLMResponseError("provider returned no choices") from None

        if finish_reason == "length":
            raise LLMResponseError("response truncated at max_output_tokens")
        if finish_reason == "content_filter":
            raise LLMResponseError("response blocked by provider content filter")
        if not content or not content.strip():
            raise LLMResponseError("provider returned empty content")

        usage: dict[str, int] = {}
        raw_usage = getattr(completion, "usage", None)
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            value = getattr(raw_usage, key, None)
            if isinstance(value, int):
                usage[key] = value

        return LLMResponse(
            content=content,
            provider=self.name,
            model=getattr(completion, "model", None) or self.model,
            usage=usage,
        )

    # --- error mapping -------------------------------------------------------
    def _map_error(self, exc: Exception) -> LLMError:
        """Translate an SDK exception into a provider-neutral, secret-free error."""
        import openai  # lazy; only reached after a client call

        detail = redact(f"{type(exc).__name__}: {exc}", [self._api_key])

        if isinstance(exc, openai.APITimeoutError):  # subclass of APIConnectionError
            return LLMTimeoutError("LLM request timed out")
        if isinstance(exc, openai.APIConnectionError):
            return LLMProviderError(f"connection error ({detail})", retryable=True)
        if isinstance(exc, openai.AuthenticationError | openai.PermissionDeniedError):
            # Never include the detail here: auth errors echo key fragments.
            return LLMConfigurationError("LLM provider rejected the credentials")
        if isinstance(exc, openai.NotFoundError):
            return LLMConfigurationError(f"model or endpoint not found ({detail})")
        if isinstance(exc, openai.APIStatusError):
            status = exc.status_code
            retryable = status >= 500 or status in _RETRYABLE_STATUS
            return LLMProviderError(f"API error {status} ({detail})", retryable=retryable)
        return LLMProviderError(f"unexpected provider error ({detail})", retryable=False)

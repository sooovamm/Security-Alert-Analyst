"""Resolve the configured LLM provider.

`LLM_PROVIDER` selects the implementation. Adding a vendor means writing an
`LLMProvider` subclass and registering a builder here; nothing else changes.
`openai` also covers OpenAI-compatible servers (Azure OpenAI proxies, vLLM,
Ollama, LM Studio) via `LLM_BASE_URL`.
"""
from __future__ import annotations

from collections.abc import Callable

from app.core.config import Settings
from app.llm.base import LLMProvider
from app.llm.errors import LLMConfigurationError


def _build_openai(settings: Settings) -> LLMProvider:
    from app.llm.openai_provider import OpenAIProvider

    if not settings.llm_configured:
        raise LLMConfigurationError(
            "LLM_API_KEY (or OPENAI_API_KEY) is not set; AI analysis is unavailable"
        )
    assert settings.llm_api_key is not None
    return OpenAIProvider(
        api_key=settings.llm_api_key.get_secret_value(),
        model=settings.llm_model,
        base_url=settings.llm_base_url,
        timeout_seconds=settings.llm_timeout_seconds,
    )


PROVIDERS: dict[str, Callable[[Settings], LLMProvider]] = {
    "openai": _build_openai,
}


def get_llm_provider(settings: Settings) -> LLMProvider:
    name = settings.llm_provider.strip().lower()
    builder = PROVIDERS.get(name)
    if builder is None:
        raise LLMConfigurationError(
            f"unknown LLM_PROVIDER {settings.llm_provider!r}; "
            f"expected one of {sorted(PROVIDERS)}"
        )
    return builder(settings)

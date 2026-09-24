"""LLM provider abstraction.

The analysis engine talks only to `LLMProvider`; concrete vendors live in
their own modules and are selected by `app.llm.factory.get_llm_provider`.
A provider performs exactly one request per `generate()` call — retries are
owned by the caller so the policy is uniform across providers.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass(frozen=True)
class LLMRequest:
    system_prompt: str
    user_prompt: str
    temperature: float
    max_output_tokens: int
    timeout_seconds: float
    json_mode: bool = True


@dataclass(frozen=True)
class LLMResponse:
    content: str
    provider: str
    model: str
    usage: dict[str, int] = field(default_factory=dict)


class LLMProvider(ABC):
    """One-shot text generation. Implementations must raise only
    `app.llm.errors.LLMError` subclasses, with secret-free messages."""

    name: str
    model: str

    @abstractmethod
    def generate(self, request: LLMRequest) -> LLMResponse:
        ...

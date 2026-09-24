"""LLM abstraction tests: OpenAI error mapping with a fake client, provider
factory/configuration, and secret redaction. No network calls are made."""
import logging
from types import SimpleNamespace

import httpx
import openai
import pytest

from app.core.config import Settings
from app.core.redaction import REDACTED, SecretRedactingFilter, redact
from app.llm import (
    LLMConfigurationError,
    LLMProviderError,
    LLMRequest,
    LLMResponseError,
    LLMTimeoutError,
    get_llm_provider,
)
from app.llm.openai_provider import OpenAIProvider

SECRET = "sk-test-SECRET-abcdefghijklmnop"
REQUEST = LLMRequest(system_prompt="sys", user_prompt="usr", temperature=0.2,
                     max_output_tokens=500, timeout_seconds=7)


class FakeCompletions:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def provider_with(outcome) -> tuple[OpenAIProvider, FakeCompletions]:
    completions = FakeCompletions(outcome)
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    return OpenAIProvider(api_key=SECRET, model="gpt-test", client=client), completions


def completion(content, finish_reason="stop"):
    return SimpleNamespace(
        model="gpt-test-2025",
        choices=[SimpleNamespace(message=SimpleNamespace(content=content),
                                 finish_reason=finish_reason)],
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5, total_tokens=15),
    )


_REQ = httpx.Request("POST", "https://api.example.test/v1/chat/completions")


def status_error(cls, status, message="error"):
    return cls(message, response=httpx.Response(status, request=_REQ), body=None)


# --- OpenAI provider ----------------------------------------------------------

def test_openai_success_passes_parameters():
    provider, completions = provider_with(completion('{"ok": true}'))
    resp = provider.generate(REQUEST)
    assert resp.content == '{"ok": true}'
    assert resp.provider == "openai" and resp.model == "gpt-test-2025"
    assert resp.usage["total_tokens"] == 15
    call = completions.calls[0]
    assert call["model"] == "gpt-test"
    assert call["temperature"] == 0.2
    assert call["timeout"] == 7
    assert call["max_tokens"] == 500
    assert call["response_format"] == {"type": "json_object"}
    assert [m["role"] for m in call["messages"]] == ["system", "user"]


def test_openai_timeout_maps_to_timeout_error():
    provider, _ = provider_with(openai.APITimeoutError(request=_REQ))
    with pytest.raises(LLMTimeoutError) as info:
        provider.generate(REQUEST)
    assert info.value.retryable


def test_openai_connection_error_is_retryable():
    provider, _ = provider_with(openai.APIConnectionError(request=_REQ))
    with pytest.raises(LLMProviderError) as info:
        provider.generate(REQUEST)
    assert info.value.retryable


@pytest.mark.parametrize("cls,status,retryable", [
    (openai.RateLimitError, 429, True),
    (openai.InternalServerError, 500, True),
    (openai.InternalServerError, 503, True),
    (openai.BadRequestError, 400, False),
    (openai.UnprocessableEntityError, 422, False),
])
def test_openai_status_errors(cls, status, retryable):
    provider, _ = provider_with(status_error(cls, status))
    with pytest.raises(LLMProviderError) as info:
        provider.generate(REQUEST)
    assert info.value.retryable is retryable
    assert str(status) in str(info.value)


@pytest.mark.parametrize("cls,status", [
    (openai.AuthenticationError, 401),
    (openai.PermissionDeniedError, 403),
    (openai.NotFoundError, 404),
])
def test_openai_auth_and_not_found_are_configuration_errors(cls, status):
    provider, _ = provider_with(
        status_error(cls, status, f"Incorrect API key provided: {SECRET}")
    )
    with pytest.raises(LLMConfigurationError) as info:
        provider.generate(REQUEST)
    assert SECRET not in str(info.value)
    assert not info.value.retryable


def test_openai_error_messages_are_redacted():
    provider, _ = provider_with(status_error(openai.BadRequestError, 400, f"bad key {SECRET}"))
    with pytest.raises(LLMProviderError) as info:
        provider.generate(REQUEST)
    assert SECRET not in str(info.value)
    assert info.value.__cause__ is None  # SDK exception (with request details) not chained


@pytest.mark.parametrize("outcome", [
    completion(None),
    completion("   "),
    completion('{"a": 1', finish_reason="length"),
    completion("{}", finish_reason="content_filter"),
    SimpleNamespace(choices=[]),
])
def test_openai_unusable_responses(outcome):
    provider, _ = provider_with(outcome)
    with pytest.raises(LLMResponseError) as info:
        provider.generate(REQUEST)
    assert info.value.retryable


def test_openai_requires_key_without_injected_client():
    with pytest.raises(LLMConfigurationError):
        OpenAIProvider(api_key="", model="gpt-test")


# --- factory & configuration --------------------------------------------------

def test_factory_builds_openai_provider():
    settings = Settings(_env_file=None, llm_api_key=SECRET, llm_model="gpt-x")
    provider = get_llm_provider(settings)
    assert isinstance(provider, OpenAIProvider)
    assert provider.model == "gpt-x"


def test_factory_without_key_raises_configuration_error():
    settings = Settings(_env_file=None, llm_api_key="")
    with pytest.raises(LLMConfigurationError, match="not set"):
        get_llm_provider(settings)


def test_factory_unknown_provider():
    settings = Settings(_env_file=None, llm_api_key=SECRET, llm_provider="nope")
    with pytest.raises(LLMConfigurationError, match="unknown LLM_PROVIDER"):
        get_llm_provider(settings)


def test_settings_read_llm_env_vars(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_API_KEY", SECRET)
    monkeypatch.setenv("LLM_MODEL", "model-from-env")
    monkeypatch.setenv("LLM_TEMPERATURE", "0.3")
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "9")
    monkeypatch.setenv("LLM_MAX_RETRIES", "4")
    s = Settings(_env_file=None)
    assert s.llm_api_key is not None and s.llm_api_key.get_secret_value() == SECRET
    assert (s.llm_model, s.llm_temperature, s.llm_timeout_seconds, s.llm_max_retries) == (
        "model-from-env", 0.3, 9.0, 4)
    assert s.llm_configured


def test_settings_fall_back_to_openai_env_vars(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    monkeypatch.setenv("OPENAI_MODEL", "legacy-model")
    s = Settings(_env_file=None)
    assert s.llm_configured and s.llm_model == "legacy-model"


def test_blank_openai_key_does_not_shadow_llm_key(monkeypatch):
    # .env.example ships `OPENAI_API_KEY=` blank; it must not override LLM_API_KEY.
    monkeypatch.setenv("OPENAI_API_KEY", "")
    monkeypatch.setenv("LLM_API_KEY", SECRET)
    s = Settings(_env_file=None)
    assert s.llm_api_key is not None and s.llm_api_key.get_secret_value() == SECRET
    assert Settings(_env_file=None, llm_api_key="sk-explicit-123456789").llm_configured


def test_api_key_is_not_exposed_in_settings_repr():
    s = Settings(_env_file=None, llm_api_key=SECRET)
    assert SECRET not in repr(s)
    assert SECRET not in str(s.model_dump())


@pytest.mark.parametrize("field,value", [
    ("llm_temperature", 3.0), ("llm_timeout_seconds", 0), ("llm_max_retries", 99),
])
def test_invalid_llm_settings_are_rejected(field, value):
    with pytest.raises(ValueError):
        Settings(_env_file=None, **{field: value})


# --- redaction ----------------------------------------------------------------

@pytest.mark.parametrize("text", [
    f"Incorrect API key provided: {SECRET}",
    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
    'api_key="supersecretvalue123"',
])
def test_redact_removes_credentials(text):
    out = redact(text)
    assert REDACTED in out
    assert "abcdefghijklmnop" not in out and "supersecretvalue123" not in out


def test_redact_known_secret_verbatim():
    assert redact("value=hunter2-long-secret", ["hunter2-long-secret"]) == f"value={REDACTED}"


def test_logging_filter_scrubs_records():
    record = logging.LogRecord("x", logging.ERROR, __file__, 1, "failed: %s", (SECRET,), None)
    SecretRedactingFilter([SECRET]).filter(record)
    assert SECRET not in record.getMessage()

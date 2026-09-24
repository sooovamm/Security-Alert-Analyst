"""Application configuration.

All configuration comes from environment variables (optionally loaded from a
local `.env` file, which is gitignored). No secrets are hardcoded, and the
app must be able to *boot* without an API key so that the health endpoint and
non-AI paths work in any environment. Code that actually needs the key checks
for it at call time, not at import time.

LLM settings are provider-neutral (`LLM_*`). For backward compatibility the
key and model fall back to `OPENAI_API_KEY` / `OPENAI_MODEL` when the `LLM_*`
variables are unset. The key is held as a `SecretStr` so it never appears in
`repr()` or logs.
"""
from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Repo root = backend/app/core/config.py -> parents[3]
REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- app meta ---
    app_name: str = "AI-Powered Security Alert Analyst"
    environment: str = Field(default="development")
    log_level: str = Field(default="INFO")

    # --- LLM analysis engine (optional at boot) ---
    # Provider name resolved by app.llm.factory ("openai" = OpenAI or any
    # OpenAI-compatible endpoint via LLM_BASE_URL).
    llm_provider: str = Field(default="openai")
    # Empty LLM_API_KEY / LLM_MODEL fall back to OPENAI_API_KEY / OPENAI_MODEL.
    llm_api_key: SecretStr | None = Field(default=None)
    llm_model: str = Field(default="")
    llm_base_url: str | None = Field(default=None)
    llm_temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    llm_timeout_seconds: float = Field(default=30.0, gt=0.0, le=300.0)
    llm_max_retries: int = Field(default=2, ge=0, le=5)          # retries after 1st attempt
    llm_retry_backoff_seconds: float = Field(default=1.0, ge=0.0, le=30.0)
    llm_max_output_tokens: int = Field(default=1200, ge=128, le=8192)

    # --- embeddings / RAG ---
    openai_api_key: str | None = Field(default=None)  # legacy LLM fallback + OpenAIEmbedder
    openai_model: str = Field(default="gpt-4o-mini")  # legacy LLM model fallback
    embedding_model: str = Field(default="text-embedding-3-small")
    # "local" is a keyless, dependency-light embedder that runs reliably in dev
    # and CI. Set to "openai" in production for semantic-quality embeddings.
    embedding_provider: str = Field(default="local")

    # --- RAG pipeline (all configurable via env) ---
    rag_chunk_size: int = Field(default=800)        # characters per chunk
    rag_chunk_overlap: int = Field(default=150)     # characters of overlap
    rag_top_k: int = Field(default=4)               # chunks retrieved per query
    rag_similarity_threshold: float = Field(default=0.08)  # min cosine to be "relevant"

    # --- storage ---
    database_url: str = Field(default="sqlite:///./app.db")

    # --- data locations ---
    data_dir: Path = Field(default=REPO_ROOT / "data")

    # --- security ---
    # Redact credential-shaped values out of alert telemetry before it is sent
    # to the LLM provider. See docs/security.md (sensitive telemetry).
    llm_redact_telemetry: bool = Field(default=True)
    # Reject request bodies larger than this (bytes) before parsing them.
    max_request_bytes: int = Field(default=256_000, ge=1_000, le=10_000_000)
    # Serve /docs, /redoc and /openapi.json. Defaults off in production.
    enable_api_docs: bool | None = Field(default=None)

    # What to do when knowledge retrieval breaks:
    #   "degrade" - analyse from the alert alone, clearly marked and low-confidence
    #   "fail"    - refuse the request with 503 rag_unavailable
    rag_failure_mode: str = Field(default="degrade", pattern="^(degrade|fail)$")

    # --- API behaviour ---
    # Import alerts.json into the DB at startup when the table is empty, so a
    # fresh container/checkout serves data without a manual seed step.
    auto_seed: bool = Field(default=True)
    # Build the RAG index at startup (warm first request). Failure is logged,
    # not fatal: the rest of the API stays available.
    rag_warm_on_startup: bool = Field(default=True)
    log_format: str = Field(default="text")     # "text" | "json"
    max_page_size: int = Field(default=200, ge=1, le=1000)

    # --- CORS: comma-separated origins allowed to call the API ---
    cors_origins: str = Field(default="http://localhost:5173,http://localhost")

    @model_validator(mode="after")
    def _apply_llm_fallbacks(self) -> "Settings":
        # Resolved explicitly (not via env aliases) so a blank OPENAI_API_KEY can
        # never shadow a real LLM_API_KEY, whatever the source precedence.
        key = self.llm_api_key.get_secret_value().strip() if self.llm_api_key else ""
        if not key and self.openai_api_key and self.openai_api_key.strip():
            self.llm_api_key = SecretStr(self.openai_api_key.strip())
        if not self.llm_model.strip():
            self.llm_model = self.openai_model
        return self

    @property
    def alerts_dir(self) -> Path:
        return self.data_dir / "alerts"

    @property
    def knowledge_dir(self) -> Path:
        return self.data_dir / "knowledge"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def docs_enabled(self) -> bool:
        """Interactive docs are useful everywhere except a production deployment,
        where they hand an unauthenticated caller the full API surface. Explicit
        ENABLE_API_DOCS always wins."""
        if self.enable_api_docs is not None:
            return self.enable_api_docs
        return self.environment.strip().lower() not in {"production", "prod"}

    @property
    def llm_configured(self) -> bool:
        """Whether an LLM API key is present. Used by health/readiness and by
        the analysis engine to fail gracefully instead of crashing."""
        return bool(self.llm_api_key and self.llm_api_key.get_secret_value().strip())


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton. Import this, don't instantiate Settings
    directly, so env is read once and can be overridden in tests."""
    return Settings()

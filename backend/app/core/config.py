"""Application configuration.

All configuration comes from environment variables (optionally loaded from a
local `.env` file, which is gitignored). No secrets are hardcoded, and the
app must be able to *boot* without an API key so that the health endpoint and
non-AI paths work in any environment. Code that actually needs the key checks
for it at call time (added in later sprints), not at import time.
"""
from functools import lru_cache
from pathlib import Path

from pydantic import Field
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

    # --- LLM / RAG (used from Sprint 3+, optional at boot) ---
    openai_api_key: str | None = Field(default=None)
    openai_model: str = Field(default="gpt-4o-mini")
    embedding_model: str = Field(default="text-embedding-3-small")
    # "openai" in production, "local" keyless fallback for offline dev/tests
    embedding_provider: str = Field(default="openai")

    # --- storage ---
    database_url: str = Field(default="sqlite:///./app.db")

    # --- data locations ---
    data_dir: Path = Field(default=REPO_ROOT / "data")

    # --- CORS: comma-separated origins allowed to call the API ---
    cors_origins: str = Field(default="http://localhost:5173,http://localhost")

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
    def llm_configured(self) -> bool:
        """Whether an LLM API key is present. Used by health/readiness and by
        the analysis engine to fail gracefully instead of crashing."""
        return bool(self.openai_api_key)


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton. Import this, don't instantiate Settings
    directly, so env is read once and can be overridden in tests."""
    return Settings()

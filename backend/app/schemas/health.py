"""Schemas for the health endpoints."""
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    app: str
    environment: str


class ReadinessResponse(BaseModel):
    status: str = Field(
        description="'ok' when every dependency is available, 'degraded' when the "
                    "service is up but some capability is missing."
    )
    degraded_reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable list of what is unavailable, in dependency order.",
    )
    llm_configured: bool = Field(description="An LLM API key is present (never the key itself).")
    data_present: bool
    database_ready: bool = False
    alert_count: int | None = Field(default=None, description="Alerts currently seeded.")
    rag_index_ready: bool = Field(
        default=False, description="The knowledge index is built and warm."
    )

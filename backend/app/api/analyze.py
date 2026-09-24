"""`POST /analyze-alert` — the core endpoint.

Flow: resolve the alert (dataset lookup or supplied payload) -> RAG retrieval
-> AI analysis -> persist -> structured response.

Persistence rule: only assessments of *stored* alerts are saved. An ad-hoc
payload is analysed and returned but never written, so the audit trail cannot
be polluted with telemetry that is not in the dataset.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, status

from app.api.deps import EngineProviderDep, RagProviderDep, SessionDep, SettingsDep
from app.api.errors import AlertNotFoundError
from app.schemas.api import AnalysisResponse, AnalyzeAlertRequest, ErrorResponse
from app.services import pipeline

logger = logging.getLogger(__name__)
router = APIRouter(tags=["analysis"])

_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status.HTTP_404_NOT_FOUND: {"model": ErrorResponse, "description": "Unknown alert_id"},
    422: {"model": ErrorResponse, "description": "Malformed request body"},
    status.HTTP_502_BAD_GATEWAY: {"model": ErrorResponse,
                                  "description": "LLM provider error or invalid model output"},
    status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ErrorResponse,
                                          "description": "LLM, knowledge base or DB unavailable"},
    status.HTTP_504_GATEWAY_TIMEOUT: {"model": ErrorResponse, "description": "LLM timed out"},
}


@router.post(
    "/analyze-alert",
    response_model=AnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyse a security alert",
    description=(
        "Analyses an alert by `alert_id` (loaded from the dataset) or from a complete "
        "alert payload. Runs RAG retrieval, then AI analysis, and returns the alert, the "
        "assessment, and the retrieval evidence.\n\n"
        "The assessment is **advisory**: it is produced by an LLM, must be reviewed by a "
        "human analyst, and never triggers an action."
    ),
    responses=_ERROR_RESPONSES,
)
def analyze_alert(
    request: AnalyzeAlertRequest,
    session: SessionDep,
    rag_provider: RagProviderDep,
    engine_provider: EngineProviderDep,
    settings: SettingsDep,
) -> AnalysisResponse:
    notes: list[str] = []

    if request.alert is not None:
        alert = request.alert
        stored = False
        notes.append("Analysed from the supplied payload; ad-hoc analyses are not persisted.")
    else:
        assert request.alert_id is not None  # guaranteed by request validation
        loaded = pipeline.load_alert(session, request.alert_id)
        if loaded is None:
            raise AlertNotFoundError(request.alert_id)
        alert = loaded
        stored = True
        if request.description and request.description.strip() != alert.description.strip():
            notes.append(
                "The supplied 'description' was ignored; the stored alert record is "
                "authoritative."
            )

    logger.info(
        "Analyse request alert_id=%s source=%s severity=%s category=%s",
        alert.alert_id, "dataset" if stored else "payload",
        alert.severity.value, alert.category.value,
    )

    # Resolved here, not as eager dependencies, so validation (422) and alert
    # lookup (404) are decided before an unconfigured LLM can raise 503.
    # The provider itself is passed in (not called here) so that a failure to
    # *build* the RAG service degrades like any other retrieval failure.
    context = pipeline.retrieve_context(rag_provider, alert, settings)
    result = pipeline.analyse(engine_provider(), alert, context)
    record = (
        pipeline.persist_analysis(session, alert, result, context, settings)
        if stored else None
    )

    return pipeline.build_response(
        alert, result, context, record, notes, expect_persist=stored
    )

"""Alert browsing endpoints.

Read-only: alerts come from the seeded dataset. Each alert is returned with a
summary of its latest stored assessment (if any) so a client can render a
triage list without an N+1 fan-out of analysis requests.
"""
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Path, Query, status

from app.api.deps import SessionDep
from app.api.errors import AlertNotFoundError, AnalysisNotFoundError
from app.models.alert import AlertRecord
from app.models.analysis import AnalysisResultRecord
from app.repositories import AlertRepository, AnalysisResultRepository
from app.schemas.alert import ALERT_ID_RE, AlertCategory, Severity
from app.schemas.analysis import Classification
from app.schemas.api import AlertListResponse, AlertOut, AnalysisResponse, ErrorResponse
from app.services.pipeline import alert_from_record, response_from_record

logger = logging.getLogger(__name__)
router = APIRouter(tags=["alerts"])

# Same pattern as the Alert schema: the id reaches logs and the URL, so a
# control character or separator must be rejected at the boundary (422), not
# carried into a handler or a log line.
AlertIdPath = Annotated[str, Path(
    min_length=1, max_length=64, pattern=ALERT_ID_RE.pattern, examples=["ALRT-1003"]
)]


def _to_out(record: AlertRecord, analysis: AnalysisResultRecord | None) -> AlertOut:
    alert = alert_from_record(record)
    return AlertOut(
        **alert.model_dump(),
        has_analysis=analysis is not None,
        latest_classification=analysis.classification if analysis else None,
        latest_risk_score=analysis.risk_score if analysis else None,
        latest_analyzed_at=analysis.created_at if analysis else None,
    )


@router.get(
    "/alerts",
    response_model=AlertListResponse,
    summary="List alerts",
    description="Paginated dataset listing, newest first. Supports free-text search and "
                "severity/category/classification filters, and includes each alert's "
                "latest assessment summary.",
)
def list_alerts(
    session: SessionDep,
    severity: Annotated[Severity | None, Query(description="Filter by severity.")] = None,
    category: Annotated[AlertCategory | None, Query(description="Filter by category.")] = None,
    classification: Annotated[Classification | None, Query(
        description="Filter by the latest AI classification. Alerts that have not been "
                    "analysed are excluded."
    )] = None,
    q: Annotated[str | None, Query(
        max_length=200,
        description="Free-text search over alert id, hostname, username, process, "
                    "command line and description.",
    )] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AlertListResponse:
    alerts = AlertRepository(session)
    total = alerts.count(severity, category, q, classification)
    records = alerts.list(severity, category, q, classification, limit=limit, offset=offset)

    summaries = AnalysisResultRepository(session).latest_for_many(
        [r.alert_id for r in records]
    )
    return AlertListResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=[_to_out(r, summaries.get(r.alert_id)) for r in records],
    )


@router.get(
    "/alerts/{alert_id}",
    response_model=AlertOut,
    summary="Get one alert",
    responses={status.HTTP_404_NOT_FOUND: {"model": ErrorResponse}},
)
def get_alert(session: SessionDep, alert_id: AlertIdPath) -> AlertOut:
    record = AlertRepository(session).get(alert_id)
    if record is None:
        raise AlertNotFoundError(alert_id)
    return _to_out(record, AnalysisResultRepository(session).latest_for(alert_id))


@router.get(
    "/alerts/{alert_id}/analysis",
    response_model=AnalysisResponse,
    summary="Get the latest stored assessment for an alert",
    description="Returns the most recent persisted analysis without calling the LLM. "
                "404 if the alert has never been analysed.",
    responses={status.HTTP_404_NOT_FOUND: {"model": ErrorResponse}},
)
def get_alert_analysis(session: SessionDep, alert_id: AlertIdPath) -> AnalysisResponse:
    record = AlertRepository(session).get(alert_id)
    if record is None:
        raise AlertNotFoundError(alert_id)
    analysis = AnalysisResultRepository(session).latest_for(alert_id)
    if analysis is None:
        raise AnalysisNotFoundError(alert_id)
    return response_from_record(alert_from_record(record), analysis)

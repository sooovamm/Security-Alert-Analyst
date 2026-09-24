"""Data access for alert telemetry.

All alert queries live here rather than in routes or services, so the API layer
never builds SQL and swapping the storage engine touches one file.
"""
from __future__ import annotations

import builtins
import logging

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.db.engine import transaction, with_retry
from app.models.alert import AlertRecord
from app.models.analysis import AnalysisResultRecord
from app.schemas.alert import Alert, AlertCategory, Severity
from app.schemas.analysis import Classification

logger = logging.getLogger(__name__)


def to_values(alert: Alert) -> dict:
    """Schema -> column values. `source_ip` is stored as text."""
    return {
        "alert_id": alert.alert_id,
        "timestamp": alert.timestamp,
        "hostname": alert.hostname,
        "username": alert.username,
        "source_ip": str(alert.source_ip),
        "process": alert.process,
        "command_line": alert.command_line,
        "severity": alert.severity.value,
        "category": alert.category.value,
        "description": alert.description,
    }


class AlertRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    # --- reads -------------------------------------------------------------
    def get(self, alert_id: str) -> AlertRecord | None:
        return self.session.scalar(
            select(AlertRecord).where(AlertRecord.alert_id == alert_id)
        )

    def exists(self, alert_id: str) -> bool:
        return (self.session.scalar(
            select(func.count()).select_from(AlertRecord)
            .where(AlertRecord.alert_id == alert_id)
        ) or 0) > 0

    def count(
        self,
        severity: Severity | None = None,
        category: AlertCategory | None = None,
        query: str | None = None,
        classification: Classification | None = None,
    ) -> int:
        return self.session.scalar(
            select(func.count()).select_from(AlertRecord)
            .where(*self._filters(severity, category, query, classification))
        ) or 0

    def list(
        self,
        severity: Severity | None = None,
        category: AlertCategory | None = None,
        query: str | None = None,
        classification: Classification | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AlertRecord]:
        """Newest first; `alert_id` breaks ties so paging is deterministic."""
        return list(self.session.scalars(
            select(AlertRecord)
            .where(*self._filters(severity, category, query, classification))
            .order_by(AlertRecord.timestamp.desc(), AlertRecord.alert_id.asc())
            .limit(limit)
            .offset(offset)
        ).all())

    @staticmethod
    def _latest_analysis_ids():
        """Ids of the most recent analysis per alert — so a classification
        filter matches the current verdict, not a superseded one."""
        return (
            select(func.max(AnalysisResultRecord.id))
            .group_by(AnalysisResultRecord.alert_id)
            .scalar_subquery()
        )

    @classmethod
    def _filters(
        cls,
        severity: Severity | None,
        category: AlertCategory | None,
        query: str | None = None,
        classification: Classification | None = None,
    ) -> builtins.list:
        filters = []
        if severity is not None:
            filters.append(AlertRecord.severity == severity.value)
        if category is not None:
            filters.append(AlertRecord.category == category.value)
        if query and query.strip():
            # Free-text search over the fields an analyst would scan. `ilike`
            # escapes nothing by itself, so wildcards in user input are
            # neutralised before the term is wrapped.
            term = (
                query.strip()
                .replace("\\", "\\\\")   # escape char first, or it doubles the others
                .replace("%", "\\%")
                .replace("_", "\\_")
            )
            pattern = f"%{term}%"
            filters.append(or_(
                AlertRecord.alert_id.ilike(pattern, escape="\\"),
                AlertRecord.hostname.ilike(pattern, escape="\\"),
                AlertRecord.username.ilike(pattern, escape="\\"),
                AlertRecord.process.ilike(pattern, escape="\\"),
                AlertRecord.command_line.ilike(pattern, escape="\\"),
                AlertRecord.description.ilike(pattern, escape="\\"),
            ))
        if classification is not None:
            filters.append(AlertRecord.alert_id.in_(
                select(AnalysisResultRecord.alert_id)
                .where(
                    AnalysisResultRecord.id.in_(cls._latest_analysis_ids()),
                    AnalysisResultRecord.classification == classification.value,
                )
            ))
        return filters

    # --- writes ------------------------------------------------------------
    def upsert_many(self, alerts: builtins.list[Alert]) -> tuple[int, int]:
        """Insert new alerts and refresh existing ones, keyed on `alert_id`.

        Returns (inserted, updated). One transaction for the whole batch, so a
        failure leaves the table exactly as it was.
        """
        def _run() -> tuple[int, int]:
            inserted = updated = 0
            with transaction(self.session):
                existing = {
                    record.alert_id: record
                    for record in self.session.scalars(
                        select(AlertRecord).where(
                            AlertRecord.alert_id.in_([a.alert_id for a in alerts])
                        )
                    ).all()
                } if alerts else {}
                for alert in alerts:
                    values = to_values(alert)
                    record = existing.get(alert.alert_id)
                    if record is None:
                        self.session.add(AlertRecord(**values))
                        inserted += 1
                    else:
                        for key, value in values.items():
                            setattr(record, key, value)
                        updated += 1
            return inserted, updated

        return with_retry(_run)

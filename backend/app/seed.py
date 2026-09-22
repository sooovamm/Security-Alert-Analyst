"""Seed/import script: load `alerts.json`, validate, persist to the database.

Usage:
    python -m app.seed

Behaviour:
- Every record is validated with the `Alert` schema first. If any record is
  malformed the whole import aborts with a clear error (fail closed) rather than
  persisting partial/garbage data.
- The import is idempotent: alerts are upserted by `alert_id`, so running it
  repeatedly does not create duplicates.
"""
import json
import logging
from pathlib import Path

from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.models.alert import AlertRecord
from app.models.base import Base, make_engine, make_session_factory
from app.schemas.alert import Alert

logger = logging.getLogger(__name__)


def load_alerts(alerts_path: Path | None = None) -> list[Alert]:
    """Read and validate alerts.json. Raises ValidationError on any bad record."""
    path = alerts_path or (get_settings().alerts_dir / "alerts.json")
    raw = json.loads(Path(path).read_text())
    if not isinstance(raw, list):
        raise ValueError("alerts.json must contain a JSON array")
    alerts = [Alert.model_validate(item) for item in raw]

    ids = [a.alert_id for a in alerts]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate alert_id values in dataset")
    return alerts


def _to_values(a: Alert) -> dict:
    return {
        "alert_id": a.alert_id,
        "timestamp": a.timestamp,
        "hostname": a.hostname,
        "username": a.username,
        "source_ip": str(a.source_ip),
        "process": a.process,
        "command_line": a.command_line,
        "severity": a.severity.value,
        "category": a.category.value,
        "description": a.description,
    }


def seed(database_url: str | None = None, alerts_path: Path | None = None) -> int:
    """Validate and upsert the dataset. Returns the total row count afterwards."""
    alerts = load_alerts(alerts_path)
    engine = make_engine(database_url)
    Base.metadata.create_all(engine)
    session_factory = make_session_factory(engine)

    inserted = updated = 0
    with session_factory() as session:
        for a in alerts:
            values = _to_values(a)
            existing = session.scalar(
                select(AlertRecord).where(AlertRecord.alert_id == a.alert_id)
            )
            if existing is None:
                session.add(AlertRecord(**values))
                inserted += 1
            else:
                for key, val in values.items():
                    setattr(existing, key, val)
                updated += 1
        session.commit()
        total = session.scalar(select(func.count()).select_from(AlertRecord)) or 0

    logger.info("Seed complete: %d inserted, %d updated, %d total.", inserted, updated, total)
    return total


def main() -> None:
    configure_logging()
    total = seed()
    print(f"Seeded dataset: {total} alerts in the database.")


if __name__ == "__main__":
    main()

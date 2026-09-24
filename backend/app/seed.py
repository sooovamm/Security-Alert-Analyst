"""Seed/import script: load `alerts.json`, validate, persist to the database.

Usage:
    python -m app.seed                       # seed the configured database
    python -m app.seed --database-url ...    # target another database
    python -m app.seed --alerts path.json    # use a different dataset
    python -m app.seed --check               # validate only, write nothing

Behaviour:
- Every record is validated with the `Alert` schema first. If any record is
  malformed the whole import aborts with a clear error (fail closed) rather
  than persisting partial/garbage data.
- The import is idempotent: alerts are upserted by `alert_id`, so running it
  repeatedly does not create duplicates.
- The schema is initialised first, so seeding works against an empty file.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db import initialize_database, make_engine, make_session_factory
from app.repositories import AlertRepository
from app.schemas.alert import Alert

logger = logging.getLogger(__name__)


def load_alerts(alerts_path: Path | None = None) -> list[Alert]:
    """Read and validate alerts.json. Raises ValidationError on any bad record."""
    path = alerts_path or (get_settings().alerts_dir / "alerts.json")
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("alerts.json must contain a JSON array")
    alerts = [Alert.model_validate(item) for item in raw]

    ids = [a.alert_id for a in alerts]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate alert_id values in dataset")
    return alerts


def seed(database_url: str | None = None, alerts_path: Path | None = None) -> int:
    """Validate and upsert the dataset. Returns the total row count afterwards."""
    alerts = load_alerts(alerts_path)
    engine = make_engine(database_url)
    initialize_database(engine)

    with make_session_factory(engine)() as session:
        repository = AlertRepository(session)
        inserted, updated = repository.upsert_many(alerts)
        total = repository.count()

    logger.info("Seed complete: %d inserted, %d updated, %d total.", inserted, updated, total)
    return total


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import the alert dataset into the database.")
    parser.add_argument("--database-url", default=None,
                        help="SQLAlchemy URL (default: DATABASE_URL from the environment).")
    parser.add_argument("--alerts", type=Path, default=None,
                        help="Path to alerts.json (default: <DATA_DIR>/alerts/alerts.json).")
    parser.add_argument("--check", action="store_true",
                        help="Validate the dataset without writing to the database.")
    args = parser.parse_args(argv)

    configure_logging()
    try:
        if args.check:
            alerts = load_alerts(args.alerts)
            print(f"Dataset valid: {len(alerts)} alerts.")
            return 0
        total = seed(database_url=args.database_url, alerts_path=args.alerts)
        print(f"Seeded dataset: {total} alerts in the database.")
        return 0
    except Exception as exc:
        logger.error("Seed failed: %s", exc, exc_info=exc)
        print(f"Seed failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

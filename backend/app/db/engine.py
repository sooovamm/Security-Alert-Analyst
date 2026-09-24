"""Engine, session factory, and SQLite resilience settings.

**Why SQLite.** The workload is a single-writer prototype: a 45-alert dataset
plus append-only assessments, read far more often than written, with no
multi-node deployment. SQLite keeps the stack to one container with no separate
service to run, back up or secure. The ORM layer and the repositories are
engine-agnostic, so moving to PostgreSQL means changing `DATABASE_URL` and
adding a driver — see docs/persistence.md.

SQLite defaults are tuned for a *server* process rather than a CLI:

- **WAL** journaling so readers never block on the writer (the API reads while
  an analysis is being stored).
- **busy_timeout** so a concurrent write waits for the lock instead of failing
  instantly with "database is locked".
- **foreign_keys=ON** — SQLite leaves enforcement off by default, so the
  `analysis_results -> alerts` reference would otherwise be decorative.
- **synchronous=NORMAL**, the standard companion to WAL: durable across process
  crashes, with far fewer fsyncs than FULL.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# Applied to every new SQLite connection.
SQLITE_PRAGMAS: dict[str, str | int] = {
    "journal_mode": "WAL",
    "synchronous": "NORMAL",
    "foreign_keys": "ON",
    "busy_timeout": 5000,  # ms
}

# Transient SQLite/driver conditions worth retrying.
_RETRYABLE_FRAGMENTS = (
    "database is locked",
    "database table is locked",
    "database is busy",
    "disk i/o error",
    "unable to open database file",
)


def is_retryable(exc: BaseException) -> bool:
    return isinstance(exc, OperationalError) and any(
        fragment in str(exc).lower() for fragment in _RETRYABLE_FRAGMENTS
    )


def _ensure_parent_dir(url: str) -> None:
    """Create the directory for a file-backed SQLite database if needed, so a
    first run (or a fresh container volume) does not fail on a missing path."""
    try:
        parsed = make_url(url)
        if not parsed.drivername.startswith("sqlite"):
            return
        database = parsed.database
        if not database or database == ":memory:":
            return
        parent = Path(database).expanduser().parent
        if str(parent) and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
    except Exception as exc:  # never block startup on a best-effort mkdir
        logger.debug("Could not pre-create database directory: %s", exc)


def make_engine(database_url: str | None = None, *, echo: bool = False) -> Engine:
    """Build an engine. Tests pass an explicit URL to use a temporary file."""
    url = database_url or get_settings().database_url
    is_sqlite = make_url(url).drivername.startswith("sqlite")

    kwargs: dict[str, Any] = {"future": True, "echo": echo, "pool_pre_ping": True}
    if is_sqlite:
        _ensure_parent_dir(url)
        # check_same_thread=False: FastAPI may serve requests on worker threads.
        # timeout: seconds the driver waits for a write lock.
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}

    engine = create_engine(url, **kwargs)

    if is_sqlite:
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover - driver hook
            cursor = dbapi_connection.cursor()
            try:
                for pragma, value in SQLITE_PRAGMAS.items():
                    cursor.execute(f"PRAGMA {pragma}={value}")
            finally:
                cursor.close()

    return engine


def make_session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def with_retry[T](
    operation: Callable[[], T],
    *,
    attempts: int = 3,
    base_delay: float = 0.05,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    """Run `operation`, retrying transient lock/IO errors with backoff.

    Only errors `is_retryable()` recognises are retried; a constraint violation
    or programming error fails immediately, because repeating it cannot help.
    The caller is responsible for rolling back between attempts.
    """
    last_error: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            return operation()
        except OperationalError as exc:
            if not is_retryable(exc) or attempt == attempts:
                raise
            last_error = exc
            delay = base_delay * (2 ** (attempt - 1))
            logger.warning(
                "Transient database error (attempt %d/%d), retrying in %.2fs: %s",
                attempt, attempts, delay, type(exc).__name__,
            )
            sleep(delay)
    assert last_error is not None  # pragma: no cover - loop always returns or raises
    raise last_error  # pragma: no cover


@contextmanager
def transaction(session: Session) -> Iterator[Session]:
    """Commit on success, roll back on any error. Never swallows the error."""
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise

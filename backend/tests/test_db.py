"""Tests for engine configuration, resilience helpers, and migrations."""
import sqlite3
from datetime import datetime

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError, OperationalError

from app.db import initialize_database, is_retryable, make_engine, transaction, with_retry
from app.db.engine import SQLITE_PRAGMAS, make_session_factory
from app.db.migrations import (
    ANALYSIS_TABLE,
    LEGACY_ANALYSIS_TABLE,
    MIGRATIONS,
    REPRODUCIBILITY_COLUMNS,
    SCHEMA_TABLE,
    applied_versions,
)
from app.models import AlertRecord, AnalysisResultRecord


@pytest.fixture()
def db_url(tmp_path) -> str:
    return f"sqlite:///{(tmp_path / 'db.sqlite').as_posix()}"


# --- engine configuration -----------------------------------------------------

def test_sqlite_pragmas_are_applied(db_url):
    engine = make_engine(db_url)
    with engine.connect() as connection:
        journal = connection.execute(text("PRAGMA journal_mode")).scalar()
        foreign_keys = connection.execute(text("PRAGMA foreign_keys")).scalar()
        busy_timeout = connection.execute(text("PRAGMA busy_timeout")).scalar()
    assert journal.lower() == "wal"          # readers do not block the writer
    assert foreign_keys == 1                 # off by default in SQLite
    assert busy_timeout == SQLITE_PRAGMAS["busy_timeout"]


def test_engine_creates_missing_parent_directory(tmp_path):
    nested = tmp_path / "does" / "not" / "exist" / "db.sqlite"
    engine = make_engine(f"sqlite:///{nested.as_posix()}")
    initialize_database(engine)
    assert nested.exists()


def test_foreign_key_is_enforced(db_url):
    """An analysis must reference a real alert."""
    engine = make_engine(db_url)
    initialize_database(engine)
    session = make_session_factory(engine)()
    session.add(AnalysisResultRecord(
        alert_id="ALRT-DOES-NOT-EXIST", classification="Benign", risk_score=1,
        confidence_score=1, reasoning="r", recommended_action="a", evidence=[],
        unsupported_claims=[], retrieved_knowledge=[], retrieval_documents=[],
        knowledge_sufficient=False, human_review_required=False, human_review_reasons=[],
        validation_warnings=[], provider="p", model="m", prompt_version="v",
        attempts=1, latency_ms=1,
    ))
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
    session.close()


# --- retry helper -------------------------------------------------------------

def locked_error() -> OperationalError:
    return OperationalError("INSERT", {}, sqlite3.OperationalError("database is locked"))


def test_retry_recovers_from_transient_lock():
    delays, attempts = [], {"n": 0}

    def flaky():
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise locked_error()
        return "ok"

    assert with_retry(flaky, sleep=delays.append) == "ok"
    assert attempts["n"] == 3
    assert delays == [0.05, 0.1]  # exponential backoff


def test_retry_gives_up_after_configured_attempts():
    calls = {"n": 0}

    def always_locked():
        calls["n"] += 1
        raise locked_error()

    with pytest.raises(OperationalError):
        with_retry(always_locked, attempts=2, sleep=lambda _: None)
    assert calls["n"] == 2


def test_non_transient_errors_are_not_retried():
    calls = {"n": 0}

    def broken():
        calls["n"] += 1
        raise OperationalError("SELECT", {}, sqlite3.OperationalError("no such table: nope"))

    with pytest.raises(OperationalError):
        with_retry(broken, sleep=lambda _: None)
    assert calls["n"] == 1  # failed immediately


@pytest.mark.parametrize("message,expected", [
    ("database is locked", True),
    ("database is busy", True),
    ("disk i/o error", True),
    ("no such column: x", False),
    ("UNIQUE constraint failed", False),
])
def test_is_retryable(message, expected):
    assert is_retryable(OperationalError("x", {}, sqlite3.OperationalError(message))) is expected


def test_transaction_rolls_back_on_error(db_url):
    engine = make_engine(db_url)
    initialize_database(engine)
    session = make_session_factory(engine)()

    with pytest.raises(RuntimeError):
        with transaction(session):
            session.add(AlertRecord(
                alert_id="ALRT-TX", timestamp=datetime(2025, 1, 1),
                hostname="h", username="u", source_ip="10.0.0.1", process="p",
                command_line="c", severity="low", category="PowerShell Execution",
                description="d",
            ))
            raise RuntimeError("boom")

    assert session.get(AlertRecord, 1) is None
    session.close()


# --- migrations ---------------------------------------------------------------

def test_fresh_database_gets_all_tables(db_url):
    engine = make_engine(db_url)
    result = initialize_database(engine)

    assert set(result.tables) >= {"alerts", ANALYSIS_TABLE, SCHEMA_TABLE}
    assert result.applied == [m.version for m in MIGRATIONS]
    assert applied_versions(engine) == {m.version for m in MIGRATIONS}


def test_initialization_is_idempotent(db_url):
    engine = make_engine(db_url)
    first = initialize_database(engine)
    second = initialize_database(engine)

    assert first.applied and second.applied == []        # nothing re-applied
    assert second.already_applied == first.applied
    assert second.created_tables == []                   # nothing re-created
    assert second.tables == first.tables


def test_legacy_analyses_table_is_migrated(db_url):
    """A database written before the rename keeps its rows under the new name."""
    engine = make_engine(db_url)
    with engine.begin() as connection:
        connection.execute(text(
            "CREATE TABLE alerts (alert_id VARCHAR(64) PRIMARY KEY, timestamp DATETIME,"
            " hostname VARCHAR(255), username VARCHAR(255), source_ip VARCHAR(64),"
            " process VARCHAR(255), command_line TEXT, severity VARCHAR(16),"
            " category VARCHAR(64), description TEXT)"
        ))
        connection.execute(text(
            f"CREATE TABLE {LEGACY_ANALYSIS_TABLE} (id INTEGER PRIMARY KEY,"
            " alert_id VARCHAR(64), classification VARCHAR(16), risk_score INTEGER)"
        ))
        connection.execute(text(
            f"INSERT INTO {LEGACY_ANALYSIS_TABLE} (alert_id, classification, risk_score)"
            " VALUES ('ALRT-1003', 'Malicious', 88)"
        ))

    result = initialize_database(engine)

    with engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
        row = connection.execute(
            text(f"SELECT alert_id, classification, risk_score FROM {ANALYSIS_TABLE}")
        ).one()
        columns = {c["name"] for c in inspect(connection).get_columns(ANALYSIS_TABLE)}

    assert LEGACY_ANALYSIS_TABLE not in tables       # renamed, not duplicated
    assert ANALYSIS_TABLE in tables
    assert tuple(row) == ("ALRT-1003", "Malicious", 88)   # data preserved
    assert set(REPRODUCIBILITY_COLUMNS) <= columns        # 0002 added the new columns
    assert "0001" in result.applied and "0002" in result.applied


def test_migration_does_not_touch_an_already_migrated_table(db_url):
    """With both names present, the legacy table must not clobber the new one."""
    engine = make_engine(db_url)
    initialize_database(engine)
    with engine.begin() as connection:
        connection.execute(text(f"CREATE TABLE {LEGACY_ANALYSIS_TABLE} (id INTEGER PRIMARY KEY)"))
        connection.execute(text(f"DELETE FROM {SCHEMA_TABLE}"))  # force a re-run

    initialize_database(engine)

    with engine.connect() as connection:
        columns = {c["name"] for c in inspect(connection).get_columns(ANALYSIS_TABLE)}
    assert "classification" in columns  # still the real table, not the stub


def test_missing_table_is_recreated_without_touching_existing_data(db_url):
    """create_all restores a dropped table; existing tables are left alone."""
    engine = make_engine(db_url)
    initialize_database(engine)
    session = make_session_factory(engine)()
    session.add(AlertRecord(
        alert_id="ALRT-KEEP", timestamp=datetime(2025, 1, 1),
        hostname="h", username="u", source_ip="10.0.0.1", process="p", command_line="c",
        severity="low", category="PowerShell Execution", description="d",
    ))
    session.commit()
    session.close()

    with engine.begin() as connection:
        connection.execute(text(f"DROP TABLE {ANALYSIS_TABLE}"))

    result = initialize_database(engine)

    assert ANALYSIS_TABLE in result.created_tables
    with engine.connect() as connection:
        kept = connection.execute(text("SELECT COUNT(*) FROM alerts")).scalar()
    assert kept == 1

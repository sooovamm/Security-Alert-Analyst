"""Schema initialisation and migrations.

Two complementary mechanisms, because they solve different problems:

1. **Versioned migrations** for changes `create_all` cannot express — renames,
   added columns on an existing table, backfills. Each step is recorded in
   `schema_migrations` and runs at most once.
2. **`create_all`** afterwards, which safely creates any table that does not
   exist yet. It never alters an existing table, so it cannot destroy data.

Every step is written to be idempotent *and* safe on a database that does not
need it, so `initialize_database()` is correct on a fresh database, on one from
an earlier version, and when run repeatedly.

**Why not Alembic.** This is a single-file SQLite schema with two tables and no
deployed history to reconcile; Alembic's autogenerate/branching machinery would
add a dependency, a config file and a revision tree for two transformations.
The trade-off flips as soon as the schema is shared between environments or
moves to PostgreSQL — see docs/persistence.md for the switch.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import Connection, inspect, text
from sqlalchemy.engine import Engine

from app.db.base import Base

logger = logging.getLogger(__name__)

SCHEMA_TABLE = "schema_migrations"
LEGACY_ANALYSIS_TABLE = "analyses"
ANALYSIS_TABLE = "analysis_results"

# Columns added in 0002 so a stored assessment can be reproduced in context.
REPRODUCIBILITY_COLUMNS: dict[str, str] = {
    "rag_query": "TEXT",
    "rag_top_k": "INTEGER",
    "rag_similarity_threshold": "FLOAT",
    "embedding_provider": "VARCHAR(32)",
    "temperature": "FLOAT",
}


@dataclass(frozen=True)
class Migration:
    version: str
    description: str
    apply: Callable[[Connection], None]


@dataclass
class InitResult:
    applied: list[str] = field(default_factory=list)
    already_applied: list[str] = field(default_factory=list)
    created_tables: list[str] = field(default_factory=list)
    tables: list[str] = field(default_factory=list)


def _table_names(connection: Connection) -> set[str]:
    return set(inspect(connection).get_table_names())


def _column_names(connection: Connection, table: str) -> set[str]:
    return {column["name"] for column in inspect(connection).get_columns(table)}


def _rename_legacy_analyses_table(connection: Connection) -> None:
    """0001: `analyses` was renamed to `analysis_results`.

    Only renames when the old table exists and the new one does not, so a fresh
    database and an already-migrated one are both left untouched.
    """
    tables = _table_names(connection)
    if LEGACY_ANALYSIS_TABLE in tables and ANALYSIS_TABLE not in tables:
        logger.info("Migration 0001: renaming %s -> %s", LEGACY_ANALYSIS_TABLE, ANALYSIS_TABLE)
        connection.execute(
            text(f"ALTER TABLE {LEGACY_ANALYSIS_TABLE} RENAME TO {ANALYSIS_TABLE}")
        )


def _add_reproducibility_columns(connection: Connection) -> None:
    """0002: record the retrieval/model parameters behind each assessment.

    On a fresh database the table does not exist yet and `create_all` will
    build it complete, so there is nothing to alter.
    """
    if ANALYSIS_TABLE not in _table_names(connection):
        return
    existing = _column_names(connection, ANALYSIS_TABLE)
    for name, column_type in REPRODUCIBILITY_COLUMNS.items():
        if name not in existing:
            logger.info("Migration 0002: adding column %s.%s", ANALYSIS_TABLE, name)
            connection.execute(
                text(f"ALTER TABLE {ANALYSIS_TABLE} ADD COLUMN {name} {column_type}")
            )


def _add_retrieval_status_column(connection: Connection) -> None:
    """0003: record whether retrieval produced evidence, found nothing relevant,
    or failed outright. Older rows keep NULL and are read as "unknown"."""
    if ANALYSIS_TABLE not in _table_names(connection):
        return
    if "retrieval_status" not in _column_names(connection, ANALYSIS_TABLE):
        logger.info("Migration 0003: adding column %s.retrieval_status", ANALYSIS_TABLE)
        connection.execute(
            text(f"ALTER TABLE {ANALYSIS_TABLE} ADD COLUMN retrieval_status VARCHAR(16)")
        )


MIGRATIONS: list[Migration] = [
    Migration("0001", "rename analyses to analysis_results", _rename_legacy_analyses_table),
    Migration("0002", "add retrieval/model reproducibility columns", _add_reproducibility_columns),
    Migration("0003", "add retrieval_status column", _add_retrieval_status_column),
]


def _ensure_schema_table(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(text(
            f"CREATE TABLE IF NOT EXISTS {SCHEMA_TABLE} ("
            " version VARCHAR(16) PRIMARY KEY,"
            " description VARCHAR(255) NOT NULL,"
            " applied_at VARCHAR(32) NOT NULL)"
        ))


def applied_versions(engine: Engine) -> set[str]:
    with engine.connect() as connection:
        if SCHEMA_TABLE not in _table_names(connection):
            return set()
        rows = connection.execute(text(f"SELECT version FROM {SCHEMA_TABLE}")).scalars().all()
    return set(rows)


def initialize_database(engine: Engine) -> InitResult:
    """Bring the database up to date. Safe to call on every startup."""
    # Importing the models registers every table on Base.metadata.
    import app.models  # noqa: F401

    result = InitResult()
    _ensure_schema_table(engine)
    done = applied_versions(engine)

    for migration in MIGRATIONS:
        if migration.version in done:
            result.already_applied.append(migration.version)
            continue
        # Each migration commits with its own bookkeeping row, so a failure
        # part-way through leaves the remaining steps pending, not half-marked.
        with engine.begin() as connection:
            migration.apply(connection)
            connection.execute(
                text(f"INSERT INTO {SCHEMA_TABLE} (version, description, applied_at) "
                     "VALUES (:version, :description, :applied_at)"),
                {"version": migration.version, "description": migration.description,
                 "applied_at": datetime.now(UTC).isoformat()},
            )
        result.applied.append(migration.version)

    with engine.connect() as connection:
        before = _table_names(connection)
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        after = _table_names(connection)

    result.created_tables = sorted(after - before)
    result.tables = sorted(after)
    logger.info(
        "Database ready: %d migration(s) applied, %d already applied, tables=%s",
        len(result.applied), len(result.already_applied), result.tables,
    )
    return result

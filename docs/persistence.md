# Persistence

Storage is SQLite via SQLAlchemy 2.0, with a repository layer between the
application and the database, and a small migration runner for schema changes.

```
routes / services
      │  (never build SQL)
      ▼
app/repositories/   AlertRepository · AnalysisResultRepository
      │
      ▼
app/models/         AlertRecord (alerts) · AnalysisResultRecord (analysis_results)
      │
      ▼
app/db/             engine (pragmas, retry) · migrations · Base
```

## Why SQLite

The workload is a single-writer prototype: a 45-alert dataset plus append-only
assessments, read far more often than written, on one node. SQLite keeps the
stack to one container with no separate service to run, secure or back up, and
the file is trivially copyable for inspection.

PostgreSQL would earn its place with concurrent writers, multiple API replicas,
retention/partitioning of assessment history, or richer querying (JSONB
indexes, full-text search). Nothing here blocks that move: models and
repositories are engine-agnostic.

**Switching to PostgreSQL:** add `psycopg[binary]` to `requirements.txt`, set
`DATABASE_URL=postgresql+psycopg://user:pass@host/db`, add the service and a
volume to `docker-compose.yml`, and drop the SQLite-only branch in
`make_engine()` (the pragmas). The migration steps in `app/db/migrations.py`
use portable `ALTER TABLE ... RENAME TO` / `ADD COLUMN`, and at that point
Alembic becomes the better tool (see below).

## Schema

### `alerts` — telemetry, the input

`alert_id` (PK, indexed), `timestamp`, `hostname`, `username`, `source_ip`,
`process`, `command_line`, `severity`, `category`, `description`.

Mirrors the `Alert` schema exactly. Telemetry only — **no verdict is ever
stored here**, because a verdict is a generated opinion, not an observation.

### `analysis_results` — assessments, the output

Append-only. Each run inserts a new row, so re-analysing an alert never
overwrites what the AI said before, and the audit trail stays intact.

| Group | Columns |
| --- | --- |
| Identity | `id`, `alert_id` (FK → `alerts.alert_id`, indexed), `created_at` (indexed) |
| Verdict | `classification`, `risk_score`, `confidence_score`, `reasoning`, `recommended_action`, `evidence`, `unsupported_claims` |
| Retrieval metadata | `retrieved_knowledge` (chunks the model cited, verified), `retrieval_documents` (everything retrieved, with scores and excerpts), `knowledge_sufficient`, `rag_query`, `rag_top_k`, `rag_similarity_threshold`, `rag_top_score`, `embedding_provider` |
| Guardrails | `human_review_required`, `human_review_reasons`, `validation_warnings` |
| Provenance | `provider`, `model`, `prompt_version`, `temperature`, `attempts`, `latency_ms` |

Together these answer "why did it say that, and could we reproduce it?" — the
verdict, the evidence, the exact knowledge chunks and scores behind it, the
query and thresholds that retrieved them, and which model and prompt version
produced it, at what temperature.

**No credentials are ever stored.** `provider`, `model` and
`embedding_provider` are names only. `AnalysisProvenance`, the only way
retrieval/model parameters reach persistence, has no field that could carry a
key, and a test asserts no credential-shaped value appears in a stored row.

### `schema_migrations` — bookkeeping

`version` (PK), `description`, `applied_at`. One row per applied migration.

## Initialisation and migrations

`initialize_database(engine)` runs on startup and in the seed script, and is
safe to call repeatedly. It does two things, in order:

1. **Versioned migrations** for changes `create_all` cannot express, each
   recorded in `schema_migrations` and applied at most once:
   - `0001` — rename the legacy `analyses` table to `analysis_results`.
   - `0002` — add the reproducibility columns (`rag_query`, `rag_top_k`,
     `rag_similarity_threshold`, `embedding_provider`, `temperature`) to an
     existing table.
2. **`create_all`**, which creates any table that does not exist yet. It never
   alters or drops an existing table, so it cannot lose data.

Every step is written to be a no-op when it does not apply, so the same code
path is correct on a fresh database, on one written by an earlier version, and
on repeat runs. Each migration commits together with its bookkeeping row, so a
failure part-way through leaves the remaining steps pending rather than
half-marked.

**Adding a migration:** append a `Migration` to `MIGRATIONS` with the next
version string and an idempotent `apply(connection)` that inspects before it
changes anything. Add a test that runs it against a database in the old shape
and asserts the data survived.

**Why not Alembic.** Two tables, one SQLite file, and no deployed history to
reconcile — Alembic's autogenerate and branching would add a dependency, a
config file and a revision tree to express two transformations. That trade-off
flips once the schema is shared across environments or moves to PostgreSQL;
at that point, generate an initial revision from the current models and let
Alembic own the sequence from there.

## Repository layer

All queries live in `app/repositories/`. Routes and services depend on these
classes, never on SQL or the ORM, so storage changes touch one layer and the
repositories can be tested directly against a temporary database.

**`AlertRepository`** — `get`, `exists`, `count(severity, category)`,
`list(severity, category, limit, offset)` (newest first, `alert_id` breaking
ties so paging is deterministic), and `upsert_many(alerts)` which inserts new
alerts and refreshes existing ones by `alert_id` in a single transaction,
returning `(inserted, updated)`.

**`AnalysisResultRepository`** — `save(result, provenance)` (insert only),
`latest_for(alert_id)`, `latest_for_many(alert_ids)` (one query for a page of
alerts, avoiding an N+1), `history_for(alert_id)`, `count()`.

## Resilience

- **SQLite tuned for a server process**: WAL journaling (readers never block on
  the writer), `busy_timeout=5000` (a concurrent write waits instead of failing
  instantly), `foreign_keys=ON` (off by default in SQLite, so the
  `analysis_results → alerts` reference would otherwise be decorative), and
  `synchronous=NORMAL`, the standard companion to WAL.
- **Retries** (`with_retry`) on transient lock/IO errors, with exponential
  backoff. Constraint violations and programming errors are *not* retried,
  because repeating them cannot help.
- **Transactions** (`transaction(session)`) commit on success and roll back on
  any error, so a failed batch leaves the table exactly as it was.
- **Pooling**: `pool_pre_ping=True` so a stale connection is detected and
  replaced rather than surfacing as a request error.
- **A failed write never loses an assessment.** `/analyze-alert` returns the
  result with `meta.persisted: false` and a note instead of a 500 — the
  analysis already cost a model call, and the client still needs the answer.
- **Startup is best-effort.** If the database cannot be initialised, the
  failure is logged, the API still starts, `/health/ready` reports
  `database_ready: false`, and data endpoints answer `503 database_unavailable`
  rather than the container crash-looping.
- **Errors never leak.** Driver messages and SQL are logged server-side; the
  client sees `{"error": {"code": "database_unavailable", ...}}`.

## Seed script

Validates the dataset with the `Alert` schema before writing anything, so a
malformed record aborts the whole import rather than persisting partial data.
Idempotent: alerts are upserted by `alert_id`.

```bash
python -m app.seed                          # seed the configured database
python -m app.seed --check                  # validate only, write nothing
python -m app.seed --database-url sqlite:///./other.db
python -m app.seed --alerts /path/alerts.json
```

The API also seeds automatically at startup when the table is empty
(`AUTO_SEED=true`), so a fresh checkout or container serves data with no manual
step. An existing dataset is never re-imported.

## Docker and data durability

The database lives in the named volume `analyst-db`, mounted at `/app/var`:

```yaml
volumes:
  - ./data:/app/data:ro     # corpus, read-only
  - analyst-db:/app/var     # database, writable and durable
```

`DATABASE_URL` is set in `docker-compose.yml` rather than only in `.env`,
because compose's `environment` wins over `env_file` — otherwise the `.env`
default (`sqlite:///./app.db`) would point at root-owned `/app`, which the
non-root container user cannot write. The image creates `/app/var` owned by
`appuser`.

Data survives `docker compose restart`, `down`/`up`, and image rebuilds.
`docker compose down -v` deletes the volume — that is the one command that
discards stored assessments.

```bash
# inspect
docker compose exec backend python -c "import sqlite3;print(sqlite3.connect('/app/var/app.db').execute('select count(*) from analysis_results').fetchone())"

# back up / restore
docker compose cp backend:/app/var/app.db ./backup.db
docker compose cp ./backup.db backend:/app/var/app.db && docker compose restart backend
```

## Tests

`tests/test_db.py` covers pragmas, foreign-key enforcement, the retry helper,
transaction rollback, fresh initialisation, idempotency, the legacy-table
rename with data preserved, and recreation of a dropped table without touching
existing data. `tests/test_repositories.py` exercises both repositories against
a real temporary database. `tests/test_seed.py` covers the importer and its
CLI. All run offline in seconds.

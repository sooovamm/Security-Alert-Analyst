"""Shared test fixtures.

Adds the backend root to sys.path so `import app...` works when pytest is run
from the backend directory, and configures a deterministic test environment:
a throwaway SQLite database, no RAG warm-up (so FAISS is never needed unless a
test asks for it), and no API key.

Environment variables are set at import time, before `app.core.config` is ever
imported, because settings are read once and cached.
"""
import os
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure `app` package is importable regardless of CWD.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

# Deterministic test environment: no real key needed, isolated DB, no FAISS.
_TEST_DB = Path(tempfile.mkdtemp(prefix="alert-analyst-tests-")) / "test.db"
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("OPENAI_API_KEY", "")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TEST_DB.as_posix()}")
os.environ.setdefault("RAG_WARM_ON_STARTUP", "false")
os.environ.setdefault("AUTO_SEED", "true")


@pytest.fixture()
def client() -> TestClient:
    """App with lifespan run: temp DB created and seeded from the dataset."""
    from app.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client

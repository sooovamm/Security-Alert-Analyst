"""Shared test fixtures.

Adds the backend root to sys.path so `import app...` works when pytest is run
from the backend directory, and exposes a TestClient bound to a freshly built
app.
"""
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure `app` package is importable regardless of CWD.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

# Deterministic test environment: no real key needed for foundation tests.
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("OPENAI_API_KEY", "")


@pytest.fixture()
def client() -> TestClient:
    from app.main import create_app

    return TestClient(create_app())

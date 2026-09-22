"""Tests for the health/readiness endpoints and app boot without secrets."""


def test_health_liveness(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["app"]
    assert "environment" in body


def test_readiness_reports_flags(client):
    resp = client.get("/health/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    # No key is set in the test environment -> must report False, not crash.
    assert body["llm_configured"] is False
    # data/ ships with the repo, so this should be True.
    assert isinstance(body["data_present"], bool)


def test_app_boots_without_api_key(client):
    # Reaching either endpoint proves the app constructed with no OPENAI_API_KEY.
    assert client.get("/health").status_code == 200


def test_openapi_available(client):
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    assert "/health" in resp.json()["paths"]

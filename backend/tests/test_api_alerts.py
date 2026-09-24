"""API tests for the alert browsing endpoints, health, and request plumbing."""
import pytest

from tests.api_fixtures import SEEDED_ALERT_ID, build_client
from tests.test_api_analyze import BrokenSession

EXPECTED_DATASET_SIZE = 45


# --- listing ------------------------------------------------------------------

def test_list_alerts(client):
    response = client.get("/alerts")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == EXPECTED_DATASET_SIZE
    assert body["limit"] == 50 and body["offset"] == 0
    assert len(body["items"]) == EXPECTED_DATASET_SIZE

    first = body["items"][0]
    assert {"alert_id", "timestamp", "hostname", "command_line", "severity",
            "category", "has_analysis"} <= set(first)
    # newest first
    timestamps = [item["timestamp"] for item in body["items"]]
    assert timestamps == sorted(timestamps, reverse=True)


def test_pagination(client):
    page1 = client.get("/alerts", params={"limit": 10, "offset": 0}).json()
    page2 = client.get("/alerts", params={"limit": 10, "offset": 10}).json()
    assert len(page1["items"]) == len(page2["items"]) == 10
    assert page1["total"] == page2["total"] == EXPECTED_DATASET_SIZE
    ids1 = {i["alert_id"] for i in page1["items"]}
    ids2 = {i["alert_id"] for i in page2["items"]}
    assert not ids1 & ids2


@pytest.mark.parametrize("field,value", [
    ("severity", "critical"),
    ("category", "Brute-force Authentication"),
])
def test_filters(client, field, value):
    body = client.get("/alerts", params={field: value}).json()
    assert body["items"]
    assert body["total"] == len(body["items"]) < EXPECTED_DATASET_SIZE
    assert all(item[field] == value for item in body["items"])


@pytest.mark.parametrize("params", [
    {"severity": "catastrophic"},
    {"category": "Nonsense"},
    {"limit": 0},
    {"limit": 5000},
    {"offset": -1},
])
def test_invalid_query_parameters_return_422(client, params):
    response = client.get("/alerts", params=params)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


@pytest.mark.parametrize("params,expected_code", [
    ({"q": "x" * 201}, 422),              # over the length cap
    ({"classification": "Critical"}, 422),  # not a classification
])
def test_invalid_search_parameters_return_422(client, params, expected_code):
    assert client.get("/alerts", params=params).status_code == expected_code


def test_search_endpoint(client):
    body = client.get("/alerts", params={"q": "mimikatz"}).json()
    assert body["total"] == len(body["items"]) >= 1
    assert all("mimikatz" in str(item).lower() for item in body["items"])

    empty = client.get("/alerts", params={"q": "zzz-no-such-alert"}).json()
    assert empty["total"] == 0 and empty["items"] == []


def test_classification_filter_endpoint(client):
    with build_client() as api:
        api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})

    body = client.get("/alerts", params={"classification": "Malicious"}).json()
    assert SEEDED_ALERT_ID in [item["alert_id"] for item in body["items"]]
    assert all(item["latest_classification"] == "Malicious" for item in body["items"])

    none_yet = client.get("/alerts", params={"classification": "Suspicious"}).json()
    assert none_yet["total"] == 0


def test_list_reflects_stored_analysis(client):
    with build_client() as api:
        api.post("/analyze-alert", json={"alert_id": SEEDED_ALERT_ID})

    items = client.get("/alerts").json()["items"]
    analysed = next(i for i in items if i["alert_id"] == SEEDED_ALERT_ID)
    assert analysed["has_analysis"] is True
    assert analysed["latest_classification"] == "Malicious"
    assert analysed["latest_risk_score"] == 88
    assert analysed["latest_analyzed_at"]


# --- single alert -------------------------------------------------------------

def test_get_alert(client):
    response = client.get(f"/alerts/{SEEDED_ALERT_ID}")
    assert response.status_code == 200
    body = response.json()
    assert body["alert_id"] == SEEDED_ALERT_ID
    assert body["category"] == "PowerShell Execution"
    # telemetry only: the dataset never carries a verdict
    assert "classification" not in body


def test_timestamps_are_utc_qualified(client):
    """SQLite stores naive datetimes; responses must still carry the UTC zone."""
    timestamp = client.get(f"/alerts/{SEEDED_ALERT_ID}").json()["timestamp"]
    assert timestamp.endswith("Z") or "+00:00" in timestamp


def test_get_unknown_alert_returns_404(client):
    response = client.get("/alerts/ALRT-DOES-NOT-EXIST")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "alert_not_found"


def test_get_analysis_before_any_analysis_returns_404(client):
    response = client.get("/alerts/ALRT-1001/analysis")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "analysis_not_found"


def test_get_analysis_for_unknown_alert_returns_404(client):
    response = client.get("/alerts/ALRT-9999/analysis")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "alert_not_found"


def test_database_failure_on_listing_returns_503():
    with build_client(session_factory=BrokenSession) as api:
        response = api.get("/alerts")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "database_unavailable"


# --- health & plumbing --------------------------------------------------------

def test_readiness_reports_dependencies(client):
    body = client.get("/health/ready").json()
    # No LLM key and no warm index in tests, so the service reports itself
    # degraded rather than pretending everything is available.
    assert body["status"] == "degraded"
    assert any("LLM API key" in reason for reason in body["degraded_reasons"])
    assert body["database_ready"] is True
    assert body["alert_count"] == EXPECTED_DATASET_SIZE
    assert body["llm_configured"] is False       # no key in the test environment
    assert body["rag_index_ready"] is False      # warm-up disabled in tests
    # readiness reports *whether* a key exists, never the key or its length
    assert set(body) == {"status", "degraded_reasons", "llm_configured", "data_present",
                         "database_ready", "alert_count", "rag_index_ready"}


def test_request_id_is_generated_and_echoed(client):
    response = client.get("/alerts")
    assert response.headers["X-Request-ID"]


def test_client_request_id_is_propagated(client):
    response = client.get("/alerts/ALRT-9999", headers={"X-Request-ID": "trace-abc-123"})
    assert response.headers["X-Request-ID"] == "trace-abc-123"
    assert response.json()["error"]["request_id"] == "trace-abc-123"


def test_malicious_request_id_is_replaced(client):
    response = client.get("/alerts", headers={"X-Request-ID": "bad id\nInjected: header"})
    assert response.headers["X-Request-ID"] != "bad id\nInjected: header"


def test_unknown_route_returns_error_envelope(client):
    response = client.get("/nope")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_method_not_allowed(client):
    response = client.get("/analyze-alert")
    assert response.status_code == 405
    assert response.json()["error"]["code"] == "method_not_allowed"


def test_openapi_documents_the_api(client):
    spec = client.get("/openapi.json").json()
    paths = spec["paths"]
    for path in ["/health", "/health/ready", "/alerts", "/alerts/{alert_id}",
                 "/alerts/{alert_id}/analysis", "/analyze-alert", "/rag/reindex"]:
        assert path in paths, path
    post = paths["/analyze-alert"]["post"]
    assert {"200", "404", "422", "502", "503", "504"} <= set(post["responses"])
    examples = post["requestBody"]["content"]["application/json"]["schema"]
    assert examples  # request model is documented
    assert client.get("/docs").status_code == 200

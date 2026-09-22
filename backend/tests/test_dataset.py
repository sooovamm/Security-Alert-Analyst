"""Tests for the alert dataset and its validation schema."""
import json
from datetime import datetime

import pytest
from pydantic import ValidationError

from app.core.config import get_settings
from app.schemas.alert import Alert, AlertCategory, Severity

REQUIRED_FIELDS = {
    "alert_id", "timestamp", "hostname", "username", "source_ip",
    "process", "command_line", "severity", "category", "description",
}
REQUIRED_CATEGORIES = {c.value for c in AlertCategory}
VALID_SEVERITIES = {s.value for s in Severity}


@pytest.fixture(scope="module")
def raw_alerts() -> list[dict]:
    path = get_settings().alerts_dir / "alerts.json"
    return json.loads(path.read_text())


# --- required dataset checks -------------------------------------------------

def test_dataset_has_at_least_40_alerts(raw_alerts):
    assert len(raw_alerts) >= 40


def test_all_required_categories_present(raw_alerts):
    present = {a["category"] for a in raw_alerts}
    assert present == REQUIRED_CATEGORIES


def test_all_required_fields_present(raw_alerts):
    for a in raw_alerts:
        assert REQUIRED_FIELDS <= a.keys(), f"{a.get('alert_id')} missing fields"


def test_alert_ids_are_unique(raw_alerts):
    ids = [a["alert_id"] for a in raw_alerts]
    assert len(ids) == len(set(ids))


def test_timestamps_are_valid(raw_alerts):
    for a in raw_alerts:
        # Must parse as ISO-8601 UTC.
        datetime.strptime(a["timestamp"], "%Y-%m-%dT%H:%M:%SZ")


def test_severity_values_are_valid(raw_alerts):
    for a in raw_alerts:
        assert a["severity"] in VALID_SEVERITIES


# --- schema validation -------------------------------------------------------

def test_every_record_validates_against_schema(raw_alerts):
    for a in raw_alerts:
        Alert.model_validate(a)  # raises if invalid


def test_no_verdict_leaked_into_dataset(raw_alerts):
    banned = {"verdict", "classification", "risk_score", "expected_classification", "label"}
    for a in raw_alerts:
        assert not (banned & a.keys()), f"verdict leaked into {a['alert_id']}"


def test_verdict_mix_is_balanced(raw_alerts):
    # Dataset should exercise benign, suspicious AND malicious activity.
    # (Verdicts live in eval_labels.json, not the alerts themselves.)
    labels = json.loads((get_settings().alerts_dir / "eval_labels.json").read_text())
    kinds = set(labels.values())
    assert {"Benign", "Suspicious", "Malicious"} <= kinds


# --- malformed alerts are rejected ------------------------------------------

def _valid_dict() -> dict:
    return {
        "alert_id": "ALRT-TEST",
        "timestamp": "2025-09-14T08:00:00Z",
        "hostname": "HOST-1",
        "username": "user1",
        "source_ip": "10.0.0.1",
        "process": "powershell.exe",
        "command_line": "powershell.exe -NoProfile",
        "severity": "low",
        "category": "PowerShell Execution",
        "description": "benign test alert",
    }


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("hostname"),                       # missing field
    lambda d: d.update(severity="urgent"),             # invalid severity
    lambda d: d.update(category="Unknown Category"),   # invalid category
    lambda d: d.update(source_ip="not-an-ip"),         # invalid IP
    lambda d: d.update(hostname="   "),                # blank field
    lambda d: d.update(timestamp="not-a-date"),        # bad timestamp
    lambda d: d.update(unexpected="x"),                # extra field forbidden
])
def test_malformed_alerts_are_rejected(mutate):
    d = _valid_dict()
    mutate(d)
    with pytest.raises(ValidationError):
        Alert.model_validate(d)


def test_valid_alert_is_accepted():
    a = Alert.model_validate(_valid_dict())
    assert a.severity is Severity.low
    assert a.category is AlertCategory.powershell

"""Pydantic schema for a security alert.

This is the validation boundary for alert data: any record that does not match
(missing field, bad severity/category, invalid IP or timestamp, unknown extra
field) is rejected with a `ValidationError`. The same model validates the
dataset at seed time and validates client input to `/analyze-alert` later.

Note: this schema models raw *telemetry only*. It deliberately has no field for
a verdict/classification/risk score — those are produced by the AI at analysis
time and must never be part of alert input.
"""
import re
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


class Severity(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertCategory(StrEnum):
    powershell = "PowerShell Execution"
    suspicious_command = "Suspicious Command Execution"
    brute_force = "Brute-force Authentication"
    malware = "Malware Detection"
    suspicious_network = "Suspicious Network Connection"
    privilege_escalation = "Privilege Escalation"
    normal_admin = "Normal Administrative Activity"


# Identifiers are echoed into logs and URLs, so they are restricted to a safe
# character set: no whitespace, control characters or separators that could be
# used for log injection or path confusion.
ALERT_ID_RE = re.compile(r"^[A-Za-z0-9._:-]+$")

# C0/C1 control characters (tab excepted) have no place in short identifier
# fields and are a classic way to smuggle line breaks into a log record.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class Alert(BaseModel):
    # extra="forbid" => unknown fields (e.g. a leaked "classification") are rejected.
    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(min_length=1, max_length=64, pattern=ALERT_ID_RE.pattern)
    timestamp: datetime
    hostname: str = Field(min_length=1, max_length=255)
    username: str = Field(min_length=1, max_length=255)
    source_ip: IPvAnyAddress
    process: str = Field(min_length=1, max_length=255)
    command_line: str = Field(min_length=1, max_length=8192)
    severity: Severity
    category: AlertCategory
    description: str = Field(min_length=1, max_length=4096)

    @field_validator("alert_id", "hostname", "username", "process", "command_line", "description")
    @classmethod
    def not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be blank or whitespace-only")
        return v

    @field_validator("hostname", "username", "process")
    @classmethod
    def no_control_characters(cls, v: str) -> str:
        # `command_line` and `description` may legitimately contain odd bytes
        # (they are attacker-controlled evidence), so they are not restricted
        # here — they are never written to a log line.
        if _CONTROL_RE.search(v):
            raise ValueError("must not contain control characters")
        return v

    @field_validator("timestamp")
    @classmethod
    def not_in_far_future(cls, v: datetime) -> datetime:
        # Guard against obviously malformed timestamps (e.g. year 9999).
        if v.year > datetime.now().year + 1:
            raise ValueError("timestamp is implausibly far in the future")
        return v

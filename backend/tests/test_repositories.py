"""Repository tests against a real temporary SQLite database (no HTTP, no LLM)."""
from datetime import UTC, datetime, timedelta

import pytest

from app.db import initialize_database, make_engine, make_session_factory
from app.repositories import AlertRepository, AnalysisProvenance, AnalysisResultRepository
from app.schemas.alert import Alert, AlertCategory, Severity
from app.schemas.analysis import AnalysisResult, Classification, KnowledgeReference


def make_alert(alert_id="ALRT-R001", **overrides) -> Alert:
    data = {
        "alert_id": alert_id,
        "timestamp": datetime(2025, 9, 14, 8, 12, 4, tzinfo=UTC),
        "hostname": "WKSTN-01",
        "username": "j.doe",
        "source_ip": "10.20.14.37",
        "process": "powershell.exe",
        "command_line": "powershell.exe -File C:\\Scripts\\Report.ps1",
        "severity": "low",
        "category": "PowerShell Execution",
        "description": "Signed internal reporting script.",
    }
    data.update(overrides)
    return Alert.model_validate(data)


def make_result(alert_id="ALRT-R001", **overrides) -> AnalysisResult:
    data = {
        "alert_id": alert_id,
        "classification": Classification.malicious,
        "risk_score": 88,
        "confidence_score": 80,
        "reasoning": "Download cradle under SYSTEM.",
        "recommended_action": "Investigate the process tree.",
        "evidence": ["IEX DownloadString"],
        "unsupported_claims": [],
        "retrieved_knowledge": [KnowledgeReference(
            chunk_id="01-powershell-attacks#0", title="PowerShell Attacks",
            category="PowerShell Execution", source="internal-knowledge-base", score=0.31,
        )],
        "knowledge_sufficient": True,
        "human_review_required": True,
        "human_review_reasons": ["classified as Malicious"],
        "validation_warnings": [],
        "provider": "openai",
        "model": "gpt-4o-mini",
        "prompt_version": "analysis-v1",
        "attempts": 1,
        "latency_ms": 2281,
    }
    data.update(overrides)
    return AnalysisResult.model_validate(data)


PROVENANCE = AnalysisProvenance(
    documents=[{"chunk_id": "01-powershell-attacks#0", "doc_name": "01-powershell-attacks",
                "title": "PowerShell Attacks", "category": "PowerShell Execution",
                "source": "internal-knowledge-base", "score": 0.31, "excerpt": "Download cradles"}],
    rag_query="PowerShell Execution powershell.exe download cradle",
    rag_top_k=4,
    rag_similarity_threshold=0.08,
    rag_top_score=0.31,
    embedding_provider="local",
    temperature=0.1,
)


@pytest.fixture()
def session(tmp_path):
    engine = make_engine(f"sqlite:///{(tmp_path / 'repo.sqlite').as_posix()}")
    initialize_database(engine)
    with make_session_factory(engine)() as db_session:
        yield db_session


@pytest.fixture()
def alerts(session) -> AlertRepository:
    return AlertRepository(session)


@pytest.fixture()
def analyses(session) -> AnalysisResultRepository:
    return AnalysisResultRepository(session)


# --- alerts -------------------------------------------------------------------

def test_upsert_inserts_then_updates(alerts):
    inserted, updated = alerts.upsert_many([make_alert()])
    assert (inserted, updated) == (1, 0)

    inserted, updated = alerts.upsert_many([make_alert(description="Revised description.")])
    assert (inserted, updated) == (0, 1)
    assert alerts.count() == 1                       # no duplicate row
    assert alerts.get("ALRT-R001").description == "Revised description."


def test_upsert_is_atomic_for_the_batch(alerts, session):
    alerts.upsert_many([make_alert("ALRT-A"), make_alert("ALRT-B")])
    assert alerts.count() == 2


def test_get_and_exists(alerts):
    alerts.upsert_many([make_alert()])
    assert alerts.get("ALRT-R001") is not None
    assert alerts.exists("ALRT-R001") is True
    assert alerts.get("ALRT-NOPE") is None
    assert alerts.exists("ALRT-NOPE") is False


def test_list_orders_newest_first_and_pages(alerts):
    base = datetime(2025, 9, 1, tzinfo=UTC)
    alerts.upsert_many([
        make_alert(f"ALRT-{i}", timestamp=base + timedelta(days=i)) for i in range(5)
    ])

    newest_first = [record.alert_id for record in alerts.list()]
    assert newest_first == ["ALRT-4", "ALRT-3", "ALRT-2", "ALRT-1", "ALRT-0"]

    page = [record.alert_id for record in alerts.list(limit=2, offset=2)]
    assert page == ["ALRT-2", "ALRT-1"]


def test_filters_and_counts(alerts):
    alerts.upsert_many([
        make_alert("ALRT-LOW", severity="low"),
        make_alert("ALRT-CRIT", severity="critical"),
        make_alert("ALRT-BF", severity="critical", category="Brute-force Authentication"),
    ])

    assert alerts.count() == 3
    assert alerts.count(severity=Severity.critical) == 2
    assert alerts.count(category=AlertCategory.brute_force) == 1
    assert alerts.count(severity=Severity.critical, category=AlertCategory.brute_force) == 1
    assert [r.alert_id for r in alerts.list(severity=Severity.low)] == ["ALRT-LOW"]


def test_search_matches_analyst_visible_fields(alerts):
    alerts.upsert_many([
        make_alert("ALRT-S1", hostname="SRV-APP-02", command_line="powershell.exe -enc AAA"),
        make_alert("ALRT-S2", hostname="WKSTN-HR-12", username="s.kaur",
                   description="Mimikatz credential dumping."),
    ])

    assert [r.alert_id for r in alerts.list(query="srv-app")] == ["ALRT-S1"]     # case-insensitive
    assert [r.alert_id for r in alerts.list(query="mimikatz")] == ["ALRT-S2"]    # description
    assert [r.alert_id for r in alerts.list(query="s.kaur")] == ["ALRT-S2"]      # username
    assert [r.alert_id for r in alerts.list(query="ALRT-S1")] == ["ALRT-S1"]     # id
    assert len(alerts.list(query="powershell")) == 2                            # both match
    assert alerts.list(query="nothing-matches-this") == []
    assert alerts.count(query="mimikatz") == 1


def test_search_treats_wildcards_literally(alerts):
    """A '%' in the search box must not match everything."""
    alerts.upsert_many([make_alert("ALRT-W1"), make_alert("ALRT-W2", hostname="host%name")])

    # "%" matches only the row containing a literal "%", not every row.
    assert [r.alert_id for r in alerts.list(query="%")] == ["ALRT-W2"]
    assert [r.alert_id for r in alerts.list(query="host%name")] == ["ALRT-W2"]
    assert alerts.list(query="_") == []          # "_" is not a single-char wildcard
    assert alerts.list(query="ALRT_W1") == []    # would match "ALRT-W1" unescaped


def test_search_combines_with_other_filters(alerts):
    alerts.upsert_many([
        make_alert("ALRT-C1", severity="critical", hostname="SRV-APP-02"),
        make_alert("ALRT-C2", severity="low", hostname="SRV-APP-02"),
    ])
    found = alerts.list(severity=Severity.critical, query="srv-app")
    assert [r.alert_id for r in found] == ["ALRT-C1"]


def test_filter_by_latest_classification(alerts, analyses):
    alerts.upsert_many([make_alert("ALRT-M"), make_alert("ALRT-B"), make_alert("ALRT-NONE")])
    analyses.save(make_result("ALRT-M", classification=Classification.malicious), PROVENANCE)
    analyses.save(make_result("ALRT-B", classification=Classification.benign), PROVENANCE)

    assert [r.alert_id for r in alerts.list(classification=Classification.malicious)] == ["ALRT-M"]
    assert [r.alert_id for r in alerts.list(classification=Classification.benign)] == ["ALRT-B"]
    assert alerts.count(classification=Classification.suspicious) == 0
    # un-analysed alerts are excluded rather than guessed at
    every = {r.alert_id for r in alerts.list()}
    assert "ALRT-NONE" in every


def test_classification_filter_uses_the_latest_verdict(alerts, analyses):
    """A superseded verdict must not keep matching."""
    alerts.upsert_many([make_alert("ALRT-X")])
    analyses.save(make_result("ALRT-X", classification=Classification.benign), PROVENANCE)
    analyses.save(make_result("ALRT-X", classification=Classification.malicious), PROVENANCE)

    assert alerts.count(classification=Classification.benign) == 0
    assert [r.alert_id for r in alerts.list(classification=Classification.malicious)] == ["ALRT-X"]


def test_empty_upsert_is_a_no_op(alerts):
    assert alerts.upsert_many([]) == (0, 0)
    assert alerts.count() == 0


# --- analysis results ---------------------------------------------------------

def test_save_stores_full_reproduction_context(alerts, analyses):
    alerts.upsert_many([make_alert()])
    record = analyses.save(make_result(), PROVENANCE)

    assert record.id is not None
    assert record.created_at is not None
    assert record.classification == "Malicious"
    assert record.risk_score == 88 and record.confidence_score == 80
    assert record.evidence == ["IEX DownloadString"]
    assert record.retrieved_knowledge[0]["chunk_id"] == "01-powershell-attacks#0"
    assert record.retrieval_documents[0]["score"] == 0.31
    # retrieval + model parameters, enough to re-run the same analysis
    assert record.rag_query.startswith("PowerShell Execution")
    assert record.rag_top_k == 4
    assert record.rag_similarity_threshold == 0.08
    assert record.rag_top_score == 0.31
    assert record.embedding_provider == "local"
    assert record.temperature == 0.1
    assert record.model == "gpt-4o-mini" and record.prompt_version == "analysis-v1"


def test_no_credentials_are_stored(alerts, analyses):
    """Provenance carries names only — there is nowhere to put a key."""
    alerts.upsert_many([make_alert()])
    record = analyses.save(make_result(), PROVENANCE)

    stored = {
        column.name: getattr(record, column.name)
        for column in record.__table__.columns
    }
    assert not any("key" in name or "secret" in name or "token" in name for name in stored)
    assert "sk-" not in str(stored)


def test_saves_are_append_only(alerts, analyses):
    alerts.upsert_many([make_alert()])
    first = analyses.save(make_result(risk_score=40), PROVENANCE)
    second = analyses.save(make_result(risk_score=90), PROVENANCE)

    assert first.id != second.id
    assert analyses.count() == 2
    assert analyses.latest_for("ALRT-R001").risk_score == 90   # newest wins
    history = analyses.history_for("ALRT-R001")
    assert [record.risk_score for record in history] == [90, 40]  # newest first


def test_latest_for_returns_none_when_unanalysed(analyses):
    assert analyses.latest_for("ALRT-NONE") is None
    assert analyses.history_for("ALRT-NONE") == []


def test_latest_for_many_avoids_n_plus_one(alerts, analyses):
    alerts.upsert_many([make_alert("ALRT-A"), make_alert("ALRT-B"), make_alert("ALRT-C")])
    analyses.save(make_result("ALRT-A", risk_score=10), PROVENANCE)
    analyses.save(make_result("ALRT-A", risk_score=70), PROVENANCE)  # newer
    analyses.save(make_result("ALRT-B", risk_score=50), PROVENANCE)

    summaries = analyses.latest_for_many(["ALRT-A", "ALRT-B", "ALRT-C"])

    assert set(summaries) == {"ALRT-A", "ALRT-B"}    # C has no analysis
    assert summaries["ALRT-A"].risk_score == 70      # latest, not the first
    assert analyses.latest_for_many([]) == {}

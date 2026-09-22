"""Tests for the seed/import script and persistence."""
from sqlalchemy import func, select

from app.models.alert import AlertRecord
from app.models.base import make_engine, make_session_factory
from app.seed import load_alerts, seed


def test_seed_persists_all_alerts(tmp_path):
    db_url = f"sqlite:///{tmp_path/'test.db'}"
    expected = len(load_alerts())
    total = seed(database_url=db_url)
    assert total == expected >= 40


def test_seed_is_idempotent(tmp_path):
    db_url = f"sqlite:///{tmp_path/'test.db'}"
    first = seed(database_url=db_url)
    second = seed(database_url=db_url)  # run again
    assert first == second  # no duplicates created


def test_persisted_alert_ids_are_unique(tmp_path):
    db_url = f"sqlite:///{tmp_path/'test.db'}"
    seed(database_url=db_url)
    engine = make_engine(db_url)
    with make_session_factory(engine)() as session:
        rows = session.scalars(select(AlertRecord.alert_id)).all()
        distinct = session.scalar(select(func.count(func.distinct(AlertRecord.alert_id))))
    assert len(rows) == distinct == len(set(rows))


def test_seed_aborts_on_malformed_dataset(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('[{"alert_id": "X"}]')  # missing required fields
    db_url = f"sqlite:///{tmp_path/'test.db'}"
    import pytest
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        seed(database_url=db_url, alerts_path=bad)

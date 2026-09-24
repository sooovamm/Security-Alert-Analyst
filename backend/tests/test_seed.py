"""Tests for the seed/import script and persistence."""
import json

from sqlalchemy import func, select

from app.db import make_engine, make_session_factory
from app.models.alert import AlertRecord
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


# --- CLI ---------------------------------------------------------------------

def test_cli_seeds_the_database(tmp_path, capsys):
    from app.seed import main

    db_url = f"sqlite:///{(tmp_path / 'cli.db').as_posix()}"
    assert main(["--database-url", db_url]) == 0
    assert "Seeded dataset" in capsys.readouterr().out


def test_cli_check_validates_without_writing(tmp_path, capsys):
    from app.seed import main

    db_file = tmp_path / "unwritten.db"
    assert main(["--check", "--database-url", f"sqlite:///{db_file.as_posix()}"]) == 0
    assert "Dataset valid" in capsys.readouterr().out
    assert not db_file.exists()


def test_cli_reports_failure_without_traceback(tmp_path, capsys):
    from app.seed import main

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([{"alert_id": "X"}]))  # missing required fields
    exit_code = main(["--alerts", str(bad),
                      "--database-url", f"sqlite:///{(tmp_path / 'x.db').as_posix()}"])
    assert exit_code == 1
    assert "Seed failed" in capsys.readouterr().err


def test_cli_accepts_a_custom_dataset(tmp_path, capsys):
    from app.seed import load_alerts, main

    subset = [a.model_dump(mode="json") for a in load_alerts()[:3]]
    dataset = tmp_path / "subset.json"
    dataset.write_text(json.dumps(subset))
    db_url = f"sqlite:///{(tmp_path / 'subset.db').as_posix()}"

    assert main(["--alerts", str(dataset), "--database-url", db_url]) == 0
    assert "3 alerts" in capsys.readouterr().out

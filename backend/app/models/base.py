"""Database engine/session plumbing (SQLAlchemy 2.0).

Kept minimal and testable: `make_engine`/`make_session_factory` accept an
explicit database URL so tests can point at a temporary SQLite file without
touching the real one.
"""
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


def make_engine(database_url: str | None = None) -> Engine:
    url = database_url or get_settings().database_url
    # check_same_thread=False lets the SQLite connection be used across the
    # request threads FastAPI may use.
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args, future=True)


def make_session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

"""Declarative base for all ORM models.

Kept in its own module so `app.db.engine` and `app.models.*` can both import it
without a circular dependency.
"""
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass

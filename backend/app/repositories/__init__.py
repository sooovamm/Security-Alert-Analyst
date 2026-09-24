"""Repository layer: every database query lives behind these classes.

Routes and services depend on repositories, never on SQL or the ORM directly,
so storage concerns stay in one place and can be tested against a real
temporary database without going through HTTP.
"""
from app.repositories.alerts import AlertRepository
from app.repositories.analyses import AnalysisProvenance, AnalysisResultRepository

__all__ = ["AlertRepository", "AnalysisProvenance", "AnalysisResultRepository"]

"""ORM models: alert telemetry (`alerts`) and AI assessments (`analysis_results`).

Both are imported here so importing `app.models` registers every table on
`Base.metadata` — which is what makes `create_all()` and the migration runner
see the full schema.
"""
from app.db.base import Base
from app.models.alert import AlertRecord
from app.models.analysis import AnalysisResultRecord

__all__ = ["AlertRecord", "AnalysisResultRecord", "Base"]

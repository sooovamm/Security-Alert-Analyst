"""ORM model for persisted alerts.

Stores raw telemetry only (mirrors the `Alert` schema). AI assessments are a
separate concern persisted later; keeping them in a different table preserves
the separation between alert data and generated conclusions.
"""
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AlertRecord(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    process: Mapped[str] = mapped_column(String(255), nullable=False)
    command_line: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<AlertRecord {self.alert_id} {self.category} {self.severity}>"

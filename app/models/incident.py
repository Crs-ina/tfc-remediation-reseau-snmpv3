from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db

if TYPE_CHECKING:
    from .audit_log import AuditLog
    from .remediation import Remediation


class Incident(db.Model):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    incident_type: Mapped[str | None] = mapped_column(String(64))
    severity: Mapped[str | None] = mapped_column(String(32))
    detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_ip: Mapped[str | None] = mapped_column(String(45))
    description: Mapped[str | None] = mapped_column(Text)

    # Champs techniques admis par le MLD pour l'idempotence et le workflow.
    zabbix_event_id: Mapped[str] = mapped_column(
        String(128), unique=True, nullable=False
    )
    processing_status: Mapped[str] = mapped_column(
        String(64), default="RECEIVED", nullable=False
    )
    playbook_id: Mapped[str] = mapped_column(String(64), nullable=False)

    remediations: Mapped[list["Remediation"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        back_populates="incident", passive_deletes=True
    )

    def to_dict(self) -> dict[str, object]:
        return {
            "incident_id": self.incident_id,
            "incident_type": self.incident_type,
            "severity": self.severity,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
            "source_ip": self.source_ip,
            "description": self.description,
            "zabbix_event_id": self.zabbix_event_id,
            "processing_status": self.processing_status,
            "playbook_id": self.playbook_id,
        }

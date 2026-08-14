from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db

from .base import utc_now

if TYPE_CHECKING:
    from .incident import Incident
    from .remediation import Remediation


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    log_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="SET NULL"), index=True
    )
    remediation_id: Mapped[str | None] = mapped_column(
        ForeignKey("remediations.remediation_id", ondelete="SET NULL"), index=True
    )
    equipment_name: Mapped[str | None] = mapped_column(String(255))
    equipment_ip: Mapped[str | None] = mapped_column(String(45))
    port_index: Mapped[int | None] = mapped_column(Integer)
    target_ip: Mapped[str | None] = mapped_column(String(45))
    target_mac: Mapped[str | None] = mapped_column(String(32))
    incident_type: Mapped[str | None] = mapped_column(String(64))
    action_type: Mapped[str | None] = mapped_column(String(64))
    result_status: Mapped[str | None] = mapped_column(String(64))
    message: Mapped[str] = mapped_column(Text, nullable=False)

    incident: Mapped["Incident | None"] = relationship(back_populates="audit_logs")
    remediation: Mapped["Remediation | None"] = relationship(
        back_populates="audit_logs"
    )

    def to_dict(self) -> dict[str, object]:
        return {
            "log_id": self.log_id,
            "event_timestamp": self.event_timestamp.isoformat(),
            "event_type": self.event_type,
            "incident_id": self.incident_id,
            "remediation_id": self.remediation_id,
            "equipment_name": self.equipment_name,
            "equipment_ip": self.equipment_ip,
            "port_index": self.port_index,
            "target_ip": self.target_ip,
            "target_mac": self.target_mac,
            "incident_type": self.incident_type,
            "action_type": self.action_type,
            "result_status": self.result_status,
            "message": self.message,
        }

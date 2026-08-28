from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db
from app.snmp.value_formatting import format_if_admin_status

from .base import utc_now

if TYPE_CHECKING:
    from .audit_log import AuditLog
    from .incident import Incident
    from .network_host import NetworkHost
    from .switch_port import SwitchPort


class Remediation(db.Model):
    __tablename__ = "remediations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["switch_id", "port_index"],
            ["switch_ports.switch_id", "switch_ports.port_index"],
            name="fk_remediation_switch_port",
        ),
        CheckConstraint(
            "authorization_mode IN ('SUPERVISED', 'AUTOMATIC')",
            name="ck_remediation_authorization_mode",
        ),
    )

    remediation_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_mac_address: Mapped[str | None] = mapped_column(
        ForeignKey("network_hosts.mac_address"), nullable=True, index=True
    )
    switch_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    port_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    authorization_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    start_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_port_status: Mapped[str | None] = mapped_column(String(32))
    previous_vlan_id: Mapped[int | None] = mapped_column(Integer)
    applied_port_status: Mapped[str | None] = mapped_column(String(32))
    applied_vlan_id: Mapped[int | None] = mapped_column(Integer)

    incident: Mapped["Incident"] = relationship(back_populates="remediations")
    target_host: Mapped["NetworkHost | None"] = relationship(
        back_populates="remediations"
    )
    switch_port: Mapped["SwitchPort | None"] = relationship(
        back_populates="remediations"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        back_populates="remediation", passive_deletes=True
    )

    def to_dict(self) -> dict[str, object]:
        return {
            "remediation_id": self.remediation_id,
            "incident_id": self.incident_id,
            "target_mac_address": self.target_mac_address,
            "switch_id": self.switch_id,
            "port_index": self.port_index,
            "action_type": self.action_type,
            "authorization_mode": self.authorization_mode,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "status": self.status,
            "previous_port_status": (
                format_if_admin_status(self.previous_port_status)
                if self.previous_port_status is not None
                else None
            ),
            "previous_vlan_id": self.previous_vlan_id,
            "applied_port_status": (
                format_if_admin_status(self.applied_port_status)
                if self.applied_port_status is not None
                else None
            ),
            "applied_vlan_id": self.applied_vlan_id,
        }

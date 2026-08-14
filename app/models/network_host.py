from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import ForeignKeyConstraint, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db

if TYPE_CHECKING:
    from .remediation import Remediation
    from .switch_port import SwitchPort


class NetworkHost(db.Model):
    __tablename__ = "network_hosts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["switch_id", "port_index"],
            ["switch_ports.switch_id", "switch_ports.port_index"],
            name="fk_network_host_switch_port",
        ),
    )

    mac_address: Mapped[str] = mapped_column(String(32), primary_key=True)
    ip_address: Mapped[str | None] = mapped_column(String(45))
    switch_id: Mapped[str | None] = mapped_column(String(36))
    port_index: Mapped[int | None] = mapped_column(Integer)

    switch_port: Mapped["SwitchPort | None"] = relationship(back_populates="hosts")
    remediations: Mapped[list["Remediation"]] = relationship(
        back_populates="target_host"
    )

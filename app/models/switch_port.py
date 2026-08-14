from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db

if TYPE_CHECKING:
    from .network_host import NetworkHost
    from .network_switch import NetworkSwitch
    from .remediation import Remediation


class SwitchPort(db.Model):
    __tablename__ = "switch_ports"

    switch_id: Mapped[str] = mapped_column(
        ForeignKey("network_switches.switch_id", ondelete="CASCADE"), primary_key=True
    )
    port_index: Mapped[int] = mapped_column(Integer, primary_key=True)
    port_name: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str | None] = mapped_column(String(32))
    vlan_id: Mapped[int | None] = mapped_column(Integer)

    network_switch: Mapped["NetworkSwitch"] = relationship(back_populates="ports")
    hosts: Mapped[list["NetworkHost"]] = relationship(back_populates="switch_port")
    remediations: Mapped[list["Remediation"]] = relationship(
        back_populates="switch_port"
    )

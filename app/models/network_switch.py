from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db

if TYPE_CHECKING:
    from .switch_port import SwitchPort


class NetworkSwitch(db.Model):
    __tablename__ = "network_switches"

    switch_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    management_ip: Mapped[str] = mapped_column(String(45), unique=True, nullable=False)
    model: Mapped[str | None] = mapped_column(String(128))

    ports: Mapped[list["SwitchPort"]] = relationship(
        back_populates="network_switch", cascade="all, delete-orphan"
    )

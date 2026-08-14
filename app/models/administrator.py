from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db

from .base import utc_now

if TYPE_CHECKING:
    from .audit_log import AuditLog


class Administrator(db.Model):
    """A local OKAPI CLI administrator; credentials are never stored in clear text."""

    __tablename__ = "administrators"

    administrator_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    username: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="administrator")

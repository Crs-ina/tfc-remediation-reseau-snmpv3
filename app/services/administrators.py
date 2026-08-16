from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db
from app.models import Administrator
from .audit import record_audit


class AuthenticationError(ValueError):
    """Intentionally generic so the CLI does not enumerate user accounts."""


def create_administrator(username: str, password: str) -> Administrator:
    username = username.strip()
    if not username:
        raise ValueError("Username cannot be empty.")
    if not password:
        raise ValueError("Password cannot be empty.")
    administrator = Administrator(username=username, password_hash=generate_password_hash(password))
    db.session.add(administrator)
    try:
        db.session.flush()
    except IntegrityError as exc:
        db.session.rollback()
        raise ValueError("This username is already in use.") from exc
    record_audit(
        incident_id=None, administrator_id=administrator.administrator_id,
        event_type="ADMIN_ACCOUNT_CREATED", message="Administrator account created.",
        result_status="SUCCESS",
    )
    db.session.commit()
    return administrator


def authenticate_administrator(username: str, password: str) -> Administrator:
    administrator = db.session.execute(
        db.select(Administrator).where(Administrator.username == username.strip())
    ).scalar_one_or_none()
    if administrator is None or not administrator.is_active or not check_password_hash(administrator.password_hash, password):
        record_audit(incident_id=None, event_type="ADMIN_LOGIN_FAILED", message="Administrator login failed.", result_status="REJECTED")
        db.session.commit()
        raise AuthenticationError("Invalid username or password.")
    administrator.last_login_at = datetime.now(timezone.utc)
    record_audit(incident_id=None, administrator_id=administrator.administrator_id,
                 event_type="ADMIN_LOGIN_SUCCESS", message="Administrator login succeeded.", result_status="SUCCESS")
    db.session.commit()
    return administrator


def change_password(administrator: Administrator, password: str) -> None:
    if not password:
        raise ValueError("Password cannot be empty.")
    administrator.password_hash = generate_password_hash(password)
    record_audit(incident_id=None, administrator_id=administrator.administrator_id,
                 event_type="ADMIN_PASSWORD_CHANGED", message="Administrator changed own password.", result_status="SUCCESS")
    db.session.commit()


def list_administrators() -> list[Administrator]:
    return list(db.session.execute(db.select(Administrator).order_by(Administrator.username)).scalars())


def disable_administrator(actor: Administrator, username: str) -> Administrator:
    target = db.session.execute(db.select(Administrator).where(Administrator.username == username.strip())).scalar_one_or_none()
    if target is None:
        raise ValueError("Administrator not found.")
    if target.administrator_id == actor.administrator_id:
        raise ValueError("You cannot disable your current session account.")
    target.is_active = False
    record_audit(incident_id=None, administrator_id=actor.administrator_id,
                 event_type="ADMIN_ACCOUNT_DISABLED", message=f"Administrator account disabled: {target.username}.", result_status="SUCCESS")
    db.session.commit()
    return target

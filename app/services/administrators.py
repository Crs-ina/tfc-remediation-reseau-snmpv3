from __future__ import annotations

import getpass
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import Administrator

from .audit import record_audit


class IdentityError(RuntimeError):
    """The operating-system identity cannot be established safely."""


class ReauthenticationError(PermissionError):
    """A critical action failed closed during system reauthentication."""


@dataclass(frozen=True)
class SystemIdentity:
    system_username: str
    display_name: str | None = None


def current_system_identity() -> SystemIdentity:
    """Resolve the account running ``okapi`` without asking for credentials."""

    display_name: str | None = None
    if os.name == "posix":
        try:
            import pwd

            account = pwd.getpwuid(os.geteuid())
            username = account.pw_name
            gecos_name = account.pw_gecos.split(",", maxsplit=1)[0].strip()
            display_name = gecos_name or None
        except (ImportError, KeyError, OSError) as exc:
            raise IdentityError("Unable to resolve the current Linux account.") from exc
    else:
        username = getpass.getuser()

    normalized = username.strip()
    if not normalized or len(normalized) > 128:
        raise IdentityError("The operating-system username is missing or invalid.")
    return SystemIdentity(normalized, display_name)


def resolve_current_administrator(
    identity: SystemIdentity | None = None,
) -> Administrator:
    """Get or create the audit identity for the current Linux account."""

    resolved = identity or current_system_identity()
    administrator = db.session.execute(
        db.select(Administrator).where(
            Administrator.system_username == resolved.system_username
        )
    ).scalar_one_or_none()
    created = administrator is None
    if administrator is None:
        administrator = Administrator(
            system_username=resolved.system_username,
            display_name=resolved.display_name,
        )
        db.session.add(administrator)
        try:
            db.session.flush()
        except IntegrityError:
            # A second CLI may have inserted the same OS identity concurrently.
            db.session.rollback()
            administrator = db.session.execute(
                db.select(Administrator).where(
                    Administrator.system_username == resolved.system_username
                )
            ).scalar_one()
            created = False
    elif resolved.display_name and administrator.display_name != resolved.display_name:
        administrator.display_name = resolved.display_name

    administrator.last_seen_at = datetime.now(timezone.utc)
    record_audit(
        incident_id=None,
        administrator_id=administrator.administrator_id,
        event_type=(
            "ADMINISTRATOR_IDENTITY_CREATED"
            if created
            else "ADMINISTRATOR_SESSION_STARTED"
        ),
        message=(
            "Linux administrator identity registered for audit."
            if created
            else "Linux administrator identity resolved for this CLI session."
        ),
        result_status="SUCCESS",
        details={"system_username": administrator.system_username},
    )
    db.session.commit()
    return administrator


def require_administrator(administrator_id: str) -> Administrator:
    normalized = administrator_id.strip()
    if not normalized:
        raise IdentityError("An explicit administrator identity is required.")
    administrator = db.session.get(Administrator, normalized)
    if administrator is None:
        raise IdentityError("The administrator identity is not registered in OKAPI.")
    return administrator


RunCommand = Callable[..., subprocess.CompletedProcess]


def reauthenticate_for_critical_action(
    administrator: Administrator,
    action: str,
    *,
    runner: RunCommand = subprocess.run,
    platform_name: str | None = None,
    identity_resolver: Callable[[], SystemIdentity] = current_system_identity,
) -> None:
    """Force Linux/PAM reauthentication through ``sudo`` without reading a password.

    ``sudo -k`` invalidates the cached timestamp and ``sudo -v`` performs the
    interactive PAM exchange directly with the terminal. OKAPI never receives,
    stores or logs the password.
    """

    platform = platform_name or os.name
    try:
        current_identity = identity_resolver()
    except IdentityError as exc:
        _record_reauthentication(administrator, action, False, str(exc))
        raise ReauthenticationError(str(exc)) from exc
    if current_identity.system_username != administrator.system_username:
        reason = "The current Linux identity changed during the OKAPI session."
        _record_reauthentication(administrator, action, False, reason)
        raise ReauthenticationError(reason)
    if platform != "posix":
        reason = "System reauthentication is available only on the Linux deployment."
        _record_reauthentication(administrator, action, False, reason)
        raise ReauthenticationError(reason)

    try:
        runner(["sudo", "-k"], check=False)
        completed = runner(
            ["sudo", "-v", "-p", "[ OKAPI ] System reauthentication required: "],
            check=False,
        )
    except (FileNotFoundError, OSError) as exc:
        reason = "The Linux sudo/PAM reauthentication service is unavailable."
        _record_reauthentication(administrator, action, False, reason)
        raise ReauthenticationError(reason) from exc

    if completed.returncode != 0:
        reason = "System reauthentication failed; the critical action was refused."
        _record_reauthentication(administrator, action, False, reason)
        raise ReauthenticationError(reason)
    _record_reauthentication(administrator, action, True, None)


def _record_reauthentication(
    administrator: Administrator,
    action: str,
    succeeded: bool,
    reason: str | None,
) -> None:
    record_audit(
        incident_id=None,
        administrator_id=administrator.administrator_id,
        event_type=(
            "SYSTEM_REAUTHENTICATION_SUCCEEDED"
            if succeeded
            else "SYSTEM_REAUTHENTICATION_FAILED"
        ),
        message=(
            "Linux/PAM reauthentication succeeded for a critical action."
            if succeeded
            else "Linux/PAM reauthentication failed; no critical action was authorized."
        ),
        result_status="SUCCESS" if succeeded else "REJECTED",
        details={"critical_action": action, "reason": reason},
    )
    db.session.commit()

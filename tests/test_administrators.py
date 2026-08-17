from types import SimpleNamespace

import pytest

from app.extensions import db
from app.models import Administrator, AuditLog
from app.services.administrators import (
    ReauthenticationError,
    SystemIdentity,
    reauthenticate_for_critical_action,
    resolve_current_administrator,
)


def test_linux_identity_is_created_once_without_credentials(app):
    with app.app_context():
        first = resolve_current_administrator(SystemIdentity("alice", "Alice Admin"))
        first_seen = first.last_seen_at
        second = resolve_current_administrator(SystemIdentity("alice", "Alice Admin"))

        assert second.administrator_id == first.administrator_id
        assert second.system_username == "alice"
        assert second.display_name == "Alice Admin"
        assert second.last_seen_at is not None
        assert second.last_seen_at >= first_seen
        assert db.session.execute(
            db.select(db.func.count(Administrator.administrator_id))
        ).scalar_one() == 1
        columns = set(Administrator.__table__.columns.keys())
        assert columns == {
            "administrator_id",
            "system_username",
            "display_name",
            "created_at",
            "last_seen_at",
        }
        assert "password" not in " ".join(columns)
        assert {entry.event_type for entry in second.audit_logs} >= {
            "ADMINISTRATOR_IDENTITY_CREATED",
            "ADMINISTRATOR_SESSION_STARTED",
        }


def test_system_reauthentication_uses_sudo_pam_without_reading_password(app):
    calls: list[list[str]] = []

    def runner(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0)

    with app.app_context():
        administrator = resolve_current_administrator(SystemIdentity("alice"))
        reauthenticate_for_critical_action(
            administrator,
            "ROLLBACK",
            runner=runner,
            platform_name="posix",
            identity_resolver=lambda: SystemIdentity("alice"),
        )

        assert calls[0] == ["sudo", "-k"]
        assert calls[1][:2] == ["sudo", "-v"]
        assert all("password" not in part.lower() for call in calls for part in call)
        audit = db.session.execute(
            db.select(AuditLog).where(
                AuditLog.event_type == "SYSTEM_REAUTHENTICATION_SUCCEEDED"
            )
        ).scalar_one()
        assert audit.administrator_id == administrator.administrator_id


def test_failed_reauthentication_is_audited_and_fails_closed(app):
    def runner(_command, **_kwargs):
        return SimpleNamespace(returncode=1)

    with app.app_context():
        administrator = resolve_current_administrator(SystemIdentity("alice"))
        with pytest.raises(ReauthenticationError, match="critical action was refused"):
            reauthenticate_for_critical_action(
                administrator,
                "DISABLE_DRY_RUN",
                runner=runner,
                platform_name="posix",
                identity_resolver=lambda: SystemIdentity("alice"),
            )
        audit = db.session.execute(
            db.select(AuditLog).where(
                AuditLog.event_type == "SYSTEM_REAUTHENTICATION_FAILED"
            )
        ).scalar_one()
        assert audit.result_status == "REJECTED"

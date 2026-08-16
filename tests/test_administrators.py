import pytest
from werkzeug.security import check_password_hash

from app.extensions import db
from app.models import Administrator, AuditLog
from app.services.administrators import AuthenticationError, authenticate_administrator, create_administrator, disable_administrator


def test_password_is_hashed_and_login_updates_audit(app):
    with app.app_context():
        administrator = create_administrator("alice", "unit-test-password")
        assert administrator.password_hash != "unit-test-password"
        assert check_password_hash(administrator.password_hash, "unit-test-password")
        authenticated = authenticate_administrator("alice", "unit-test-password")
        assert authenticated.last_login_at is not None
        assert {entry.event_type for entry in authenticated.audit_logs} >= {"ADMIN_ACCOUNT_CREATED", "ADMIN_LOGIN_SUCCESS"}


def test_inactive_and_wrong_password_are_rejected_generically(app):
    with app.app_context():
        create_administrator("alice", "unit-test-password")
        with pytest.raises(AuthenticationError, match="Invalid username or password"):
            authenticate_administrator("alice", "wrong")
        alice = db.session.execute(db.select(Administrator).where(Administrator.username == "alice")).scalar_one()
        alice.is_active = False
        db.session.commit()
        with pytest.raises(AuthenticationError, match="Invalid username or password"):
            authenticate_administrator("alice", "unit-test-password")
        assert db.session.execute(db.select(db.func.count(AuditLog.log_id)).where(AuditLog.event_type == "ADMIN_LOGIN_FAILED")).scalar_one() == 2


def test_actor_cannot_disable_own_session(app):
    with app.app_context():
        alice = create_administrator("alice", "unit-test-password")
        with pytest.raises(ValueError, match="current session"):
            disable_administrator(alice, "alice")

from types import SimpleNamespace

import pytest

from app.cli.okapi import _system_status
from app.models import Administrator, AuditLog
from app.services.runtime_settings import change_dry_run_mode, is_dry_run_enabled
from app.extensions import db
from config import env_bool


class SupervisedPolicy:
    def decide(self):
        return SimpleNamespace(mode="SUPERVISED")


def _status_values(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        label, value = line.split(":", maxsplit=1)
        values[label.strip()] = value.strip()
    return values


def test_boolean_environment_configuration_is_explicit(monkeypatch) -> None:
    for raw in ("true", "TRUE", "1", "yes", "oui", "on"):
        monkeypatch.setenv("OKAPI_TEST_BOOLEAN", raw)
        assert env_bool("OKAPI_TEST_BOOLEAN") is True
    for raw in ("false", "FALSE", "0", "no", "non", "off"):
        monkeypatch.setenv("OKAPI_TEST_BOOLEAN", raw)
        assert env_bool("OKAPI_TEST_BOOLEAN", True) is False

    monkeypatch.setenv("OKAPI_TEST_BOOLEAN", "tru")
    with pytest.raises(ValueError, match="Invalid boolean value"):
        env_bool("OKAPI_TEST_BOOLEAN")


def test_system_status_shows_dry_run_override(app, monkeypatch, capsys) -> None:
    app.config.update(SNMP_WRITE_ENABLED=True, DRY_RUN=True)
    monkeypatch.setattr(
        "app.cli.okapi.CalendarPolicy.from_file",
        lambda _path: SupervisedPolicy(),
    )

    with app.app_context():
        _system_status(Administrator(system_username="alice"))

    output = capsys.readouterr().out
    values = _status_values(output)
    assert "OKAPI — SYSTEM STATUS" in output
    assert "Backend" not in values
    assert "Database" not in values
    assert values["Administrator"] == "alice"
    assert values["Zabbix integration"] == "READY"
    assert values["SNMP writes"] == "BLOCKED BY DRY-RUN"
    assert values["Dry-run mode"] == "ON"
    assert values["Authorization mode"] == "SUPERVISED"
    assert values["Quarantine VLAN"] == "18"
    assert values["Remediation cooldown"] == "60 s"


def test_system_status_enables_writes_only_when_dry_run_is_off(
    app, monkeypatch, capsys
) -> None:
    app.config.update(SNMP_WRITE_ENABLED=True, DRY_RUN=False)
    monkeypatch.setattr(
        "app.cli.okapi.CalendarPolicy.from_file",
        lambda _path: SupervisedPolicy(),
    )

    with app.app_context():
        _system_status(Administrator(system_username="alice"))

    values = _status_values(capsys.readouterr().out)
    assert values["SNMP writes"] == "ENABLED"
    assert values["Dry-run mode"] == "OFF"


def test_dry_run_cli_setting_is_persistent_reauthenticated_and_audited(app) -> None:
    actions: list[str] = []

    def reauthenticate(_administrator, action: str) -> None:
        actions.append(action)

    with app.app_context():
        administrator = Administrator(system_username="alice")
        db.session.add(administrator)
        db.session.commit()

        assert change_dry_run_mode(
            True, administrator, reauthenticator=reauthenticate
        ) is True
        assert is_dry_run_enabled() is True
        assert actions == ["ENABLE_DRY_RUN"]

        app.config["DRY_RUN"] = False
        assert is_dry_run_enabled() is True
        audit = db.session.execute(
            db.select(AuditLog).where(AuditLog.event_type == "DRY_RUN_MODE_CHANGED")
        ).scalar_one()
        assert audit.administrator_id == administrator.administrator_id
        assert audit.result_status == "SUCCESS"


def test_invalid_runtime_setting_fails_safe_to_dry_run(app) -> None:
    path = app.config["RUNTIME_SETTINGS_PATH"]
    path.write_text('{"dry_run": "off"}', encoding="utf-8")
    with app.app_context():
        app.config["DRY_RUN"] = False
        assert is_dry_run_enabled() is True

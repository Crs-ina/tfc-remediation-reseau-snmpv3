from types import SimpleNamespace

import pytest

from app.cli.okapi import _system_status
from config import env_bool


class SupervisedPolicy:
    def decide(self):
        return SimpleNamespace(mode="HUMAN_APPROVAL")


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
        _system_status()

    output = capsys.readouterr().out
    values = _status_values(output)
    assert "OKAPI — SYSTEM STATUS" in output
    assert values["Backend"] == "RUNNING"
    assert values["Database"] == "OK"
    assert values["Zabbix webhook"] == "READY"
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
        _system_status()

    values = _status_values(capsys.readouterr().out)
    assert values["SNMP writes"] == "ENABLED"
    assert values["Dry-run mode"] == "OFF"

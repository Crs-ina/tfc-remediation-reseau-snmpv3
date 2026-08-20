from types import SimpleNamespace

from app.cli.okapi import _approve_and_execute
from app.models import Administrator


def test_real_approval_reauthenticates_before_decision(app, monkeypatch) -> None:
    calls: list[str] = []
    administrator = Administrator(
        administrator_id="admin-test", system_username="alice"
    )
    incident = SimpleNamespace()

    monkeypatch.setattr(
        "app.cli.okapi.reauthenticate_for_critical_action",
        lambda _administrator, action: calls.append(f"reauth:{action}"),
    )
    monkeypatch.setattr(
        "app.cli.okapi.approve_incident",
        lambda _incident, _administrator_id: calls.append("approve"),
    )
    monkeypatch.setattr(
        "app.cli.okapi.execute_authorized_remediation",
        lambda _incident: calls.append("execute")
        or SimpleNamespace(simulated=False, success=True),
    )

    with app.app_context():
        app.config["DRY_RUN"] = False
        _approve_and_execute(administrator, incident)

    assert calls == [
        "reauth:APPROVE_REAL_DISRUPTIVE_REMEDIATION",
        "approve",
        "execute",
    ]


def test_dry_run_approval_does_not_request_system_password(app, monkeypatch) -> None:
    calls: list[str] = []
    administrator = Administrator(
        administrator_id="admin-test", system_username="alice"
    )
    monkeypatch.setattr(
        "app.cli.okapi.reauthenticate_for_critical_action",
        lambda *_args: calls.append("reauth"),
    )
    monkeypatch.setattr(
        "app.cli.okapi.approve_incident",
        lambda *_args: calls.append("approve"),
    )
    monkeypatch.setattr(
        "app.cli.okapi.execute_authorized_remediation",
        lambda _incident: SimpleNamespace(simulated=True, success=False),
    )
    monkeypatch.setattr(
        "app.cli.okapi.click.confirm",
        lambda *_args, **_kwargs: False,
    )

    with app.app_context():
        app.config["DRY_RUN"] = True
        _approve_and_execute(administrator, SimpleNamespace())

    assert calls == ["approve"]

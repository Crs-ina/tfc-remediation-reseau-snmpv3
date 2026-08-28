from __future__ import annotations

from datetime import datetime, timezone

from app.cli.okapi import _all_incidents, _pending
from app.extensions import db
from app.models import Administrator, AuditLog, Incident, Remediation


def _incident(event_id: str, incident_type: str, status: str) -> Incident:
    return Incident(
        zabbix_event_id=event_id,
        incident_type=incident_type,
        processing_status=status,
        playbook_id="PB-UNKNOWN-001",
        detected_at=datetime.now(timezone.utc),
    )


def test_refresh_displays_an_incident_added_after_the_view_opened(
    app, monkeypatch, capsys
):
    with app.app_context():
        db.session.add(_incident("event-before", "network_loop", "PENDING"))
        db.session.commit()
        prompt_count = 0

        def prompt(*_args, **_kwargs):
            nonlocal prompt_count
            prompt_count += 1
            if prompt_count == 1:
                db.session.add(
                    _incident(
                        "event-after",
                        "ip_address_conflict",
                        "WAITING_ADMIN_APPROVAL",
                    )
                )
                db.session.commit()
                return "R"
            return "B"

        monkeypatch.setattr("app.cli.okapi.click.prompt", prompt)
        _all_incidents(refreshable=True)

    output = capsys.readouterr().out
    assert "network_loop" in output
    assert "ip_address_conflict" in output
    assert output.count("network_loop") == 2
    assert output.count("ip_address_conflict") == 1


def test_refresh_displays_a_status_changed_after_the_view_opened(
    app, monkeypatch, capsys
):
    with app.app_context():
        incident = _incident("event-status", "network_loop", "PENDING")
        db.session.add(incident)
        db.session.commit()
        prompt_count = 0

        def prompt(*_args, **_kwargs):
            nonlocal prompt_count
            prompt_count += 1
            if prompt_count == 1:
                incident.processing_status = "ESCALATED"
                db.session.commit()
                return "R"
            return "B"

        monkeypatch.setattr("app.cli.okapi.click.prompt", prompt)
        _all_incidents(refreshable=True)

    output = capsys.readouterr().out
    assert "PENDING" in output
    assert "ESCALATED" in output


def test_refresh_is_read_only_and_never_triggers_snmp(app, monkeypatch):
    with app.app_context():
        administrator = Administrator(system_username="refresh-admin")
        incident = _incident(
            "event-read-only",
            "network_loop",
            "WAITING_ADMIN_APPROVAL",
        )
        db.session.add_all([administrator, incident])
        db.session.commit()
        calls: list[str] = []
        responses = iter(("R", "B"))

        monkeypatch.setattr(
            "app.cli.okapi.click.prompt",
            lambda *_args, **_kwargs: next(responses),
        )
        monkeypatch.setattr(
            "app.cli.okapi.execute_authorized_remediation",
            lambda *_args, **_kwargs: calls.append("snmp"),
        )

        before = (
            db.session.scalar(db.select(db.func.count(Incident.incident_id))),
            db.session.scalar(db.select(db.func.count(Remediation.remediation_id))),
            db.session.scalar(db.select(db.func.count(AuditLog.log_id))),
        )
        _pending(administrator, refreshable=True)
        after = (
            db.session.scalar(db.select(db.func.count(Incident.incident_id))),
            db.session.scalar(db.select(db.func.count(Remediation.remediation_id))),
            db.session.scalar(db.select(db.func.count(AuditLog.log_id))),
        )

        assert before == after
        assert db.session.get(Incident, incident.incident_id).processing_status == "WAITING_ADMIN_APPROVAL"
        assert calls == []

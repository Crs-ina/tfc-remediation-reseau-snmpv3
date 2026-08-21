from datetime import datetime, timezone

from app.cli.okapi import _logs
from app.extensions import db
from app.models import (
    Administrator,
    AuditLog,
    Incident,
    NetworkSwitch,
    Remediation,
    SwitchPort,
)


def _run_filter(
    app,
    monkeypatch,
    capsys,
    *,
    date: str = "",
    search: str = "",
) -> str:
    responses = iter(["2", date, search])
    monkeypatch.setattr("click.prompt", lambda *_args, **_kwargs: next(responses))
    with app.app_context():
        _logs()
    return capsys.readouterr().out


def test_audit_result_is_rendered_as_a_readable_card(app, monkeypatch, capsys):
    with app.app_context():
        administrator = Administrator(
            administrator_id="admin-card",
            system_username="exauceeadm",
        )
        db.session.add(
            AuditLog(
                log_id="log-card",
                event_timestamp=datetime(2026, 8, 21, 8, 15, tzinfo=timezone.utc),
                event_type="SNMP_REMEDIATION_SUCCEEDED",
                incident_type="ip_address_conflict",
                action_type="QUARANTINE_VLAN",
                result_status="SUCCEEDED",
                administrator=administrator,
                equipment_name="SW-ARISTA-01",
                port_index=2,
                message="Remediation verified.",
            )
        )
        db.session.commit()

    # One phrase can combine words found in different audit fields.
    output = _run_filter(
        app,
        monkeypatch,
        capsys,
        date="2026",
        search="vlan succeed ex arista 2",
    )

    assert "No audit logs found." not in output
    assert "OKAPI - AUDIT LOGS (1 entry)" in output
    assert "Date / time   :" in output
    assert "Action        : QUARANTINE_VLAN" in output
    assert "Result        : SUCCEEDED" in output
    assert "Administrator : exauceeadm" in output
    assert "Switch        : SW-ARISTA-01" in output
    assert "Port          : 2" in output
    assert "ip_address_conflict" not in output


def test_missing_audit_context_comes_from_the_linked_remediation(
    app, monkeypatch, capsys
):
    with app.app_context():
        administrator = Administrator(
            administrator_id="admin-linked",
            system_username="exauceeadm",
        )
        network_switch = NetworkSwitch(
            switch_id="switch-core",
            name="SW-CORE-01",
            management_ip="192.0.2.50",
            model="Arista vEOS 4.29.2F",
        )
        switch_port = SwitchPort(
            network_switch=network_switch,
            port_index=8,
            port_name="Ethernet8",
            status="up",
            vlan_id=18,
        )
        incident = Incident(
            incident_type="ip_address_conflict",
            zabbix_event_id="event-linked-context",
            processing_status="REMEDIATED",
            playbook_id="PB-IP-CONFLICT-001",
        )
        remediation = Remediation(
            incident=incident,
            switch_port=switch_port,
            switch_id=network_switch.switch_id,
            port_index=switch_port.port_index,
            action_type="QUARANTINE_VLAN",
            authorization_mode="SUPERVISED",
            status="SUCCEEDED",
        )
        db.session.add(
            AuditLog(
                log_id="log-linked-context",
                event_timestamp=datetime(2026, 8, 21, 8, 0, tzinfo=timezone.utc),
                event_type="REMEDIATION_APPROVED",
                incident=incident,
                remediation=remediation,
                administrator=administrator,
                result_status="ADMIN_APPROVED",
                message="Administrator approved remediation.",
            )
        )
        db.session.commit()

    output = _run_filter(
        app,
        monkeypatch,
        capsys,
        search="vlan succeed ex core 8",
    )

    assert "No audit logs found." not in output
    assert "Action        : QUARANTINE_VLAN" in output
    assert "Result        : SUCCEEDED" in output
    assert "Switch        : SW-CORE-01" in output
    assert "Port          : 8" in output

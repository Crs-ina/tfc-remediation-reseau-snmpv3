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
    responses = iter(["2", "0", date, "0", "", "0", "0", "0", "", search])
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
    assert "OKAPI - INCIDENT & ACTION HISTORY (1 entry)" in output
    assert "Incident       : ip_address_conflict" in output
    assert "Detected       :" in output
    assert "Remediation    : Quarantine VLAN" in output
    assert "Result         : SUCCEEDED" in output
    assert "Performed by   : exauceeadm" in output
    assert "Switch         : SW-ARISTA-01" in output
    assert "Port           : Index 2" in output
    assert "Event         :" not in output
    assert "SNMP_REMEDIATION_SUCCEEDED" not in output


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
                event_type="SNMP_REMEDIATION_SUCCEEDED",
                incident=incident,
                remediation=remediation,
                administrator=administrator,
                result_status="SUCCEEDED",
                message="Remediation verified after administrator approval.",
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
    assert "Remediation    : Quarantine VLAN" in output
    assert "Result         : SUCCEEDED" in output
    assert "Switch         : SW-CORE-01" in output
    assert "Port           : Ethernet8" in output
    assert "Mode           : SUPERVISED" in output
    assert "Approved by    : exauceeadm" in output


def test_technical_events_are_grouped_into_one_business_history_card(
    app, monkeypatch, capsys
):
    with app.app_context():
        administrator = Administrator(
            administrator_id="admin-grouped",
            system_username="networkadmin",
        )
        network_switch = NetworkSwitch(
            switch_id="switch-grouped",
            name="SW-ARISTA-01",
            management_ip="192.0.2.60",
            model="Arista vEOS 4.29.2F",
        )
        switch_port = SwitchPort(
            network_switch=network_switch,
            port_index=1,
            port_name="Ethernet1",
            status="down",
            vlan_id=10,
        )
        incident = Incident(
            incident_type="port_flapping",
            severity="High",
            detected_at=datetime(2026, 8, 21, 9, 0, tzinfo=timezone.utc),
            description="Grouped history example",
            zabbix_event_id="event-grouped",
            processing_status="REMEDIATED",
            playbook_id="PB-PORT-FLAPPING-001",
        )
        remediation = Remediation(
            incident=incident,
            switch_port=switch_port,
            switch_id=network_switch.switch_id,
            port_index=switch_port.port_index,
            action_type="SHUTDOWN_PORT",
            authorization_mode="SUPERVISED",
            status="SUCCEEDED",
        )
        db.session.add_all(
            [
                AuditLog(
                    log_id="log-grouped-rule",
                    event_timestamp=datetime(
                        2026, 8, 21, 9, 1, tzinfo=timezone.utc
                    ),
                    event_type="RULE_DECISION",
                    incident=incident,
                    remediation=remediation,
                    result_status="WAITING_ADMIN_APPROVAL",
                    message="Rule-engine decision.",
                ),
                AuditLog(
                    log_id="log-grouped-approval",
                    event_timestamp=datetime(
                        2026, 8, 21, 9, 2, tzinfo=timezone.utc
                    ),
                    event_type="REMEDIATION_APPROVED",
                    incident=incident,
                    remediation=remediation,
                    administrator=administrator,
                    result_status="ADMIN_APPROVED",
                    message="Administrator approved remediation.",
                ),
                AuditLog(
                    log_id="log-grouped-success",
                    event_timestamp=datetime(
                        2026, 8, 21, 9, 3, tzinfo=timezone.utc
                    ),
                    event_type="SNMP_REMEDIATION_SUCCEEDED",
                    incident=incident,
                    remediation=remediation,
                    result_status="SUCCEEDED",
                    message="Remediation verified.",
                ),
            ]
        )
        db.session.commit()

    output = _run_filter(
        app,
        monkeypatch,
        capsys,
        search="grouped",
    )

    assert "OKAPI - INCIDENT & ACTION HISTORY (1 entry)" in output
    assert "Incident       : port_flapping" in output
    assert "Remediation    : Shutdown port" in output
    assert "Mode           : SUPERVISED" in output
    assert "Result         : SUCCEEDED" in output
    assert "Approved by    : networkadmin" in output
    assert "RULE_DECISION" not in output
    assert "SNMP_REMEDIATION_SUCCEEDED" not in output


def test_escalated_protected_port_has_a_readable_reason(app, monkeypatch, capsys):
    with app.app_context():
        incident = Incident(
            incident_type="vlan_policy_violation",
            severity="High",
            detected_at=datetime(2026, 8, 21, 10, 0, tzinfo=timezone.utc),
            zabbix_event_id="event-protected",
            processing_status="ESCALATED",
            playbook_id="PB-VLAN-POLICY-001",
        )
        db.session.add(
            AuditLog(
                log_id="log-protected",
                event_timestamp=datetime(2026, 8, 21, 10, 1, tzinfo=timezone.utc),
                event_type="RULE_DECISION",
                incident=incident,
                equipment_name="SW-ARISTA-01",
                port_index=2,
                action_type="NO_ACTION",
                result_status="ESCALATED",
                message=(
                    'Rule-engine decision. | {"reason": '
                    '"target_is_whitelisted"}'
                ),
            )
        )
        db.session.commit()

    output = _run_filter(
        app,
        monkeypatch,
        capsys,
        search="protected",
    )

    assert "Incident       : vlan_policy_violation" in output
    assert "Mode           : NONE" in output
    assert "Result         : ESCALATED" in output
    assert "Reason         : Protected port" in output
    assert "Network change : NONE" in output
    assert "target_is_whitelisted" not in output

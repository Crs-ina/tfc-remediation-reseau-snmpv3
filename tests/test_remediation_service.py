from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from app.extensions import db
from app.models import Administrator, Incident, NetworkSwitch, Remediation, SwitchPort
from app.services.remediation import (
    RemediationError,
    UnsafeOperationBlocked,
    approve_incident,
    evaluate_incident,
    execute_authorized_remediation,
)


def test_human_approval_creates_targeted_remediation_but_feature_flag_blocks_write(app):
    with app.app_context():
        network_switch = NetworkSwitch(
            switch_id="sw-1",
            name="EVE-NG-SW1",
            management_ip="192.0.2.10",
            model="TO_BE_VALIDATED",
        )
        port = SwitchPort(
            network_switch=network_switch,
            port_index=4,
            port_name="Gi0/4",
            status="up",
            vlan_id=10,
        )
        incident = Incident(
            incident_type="network_loop",
            severity="High",
            detected_at=datetime(2026, 8, 10, 10, 0, tzinfo=ZoneInfo("Africa/Kinshasa")),
            source_ip="192.0.2.10",
            description="Boucle detectee",
            zabbix_event_id="evt-remediation-1",
            processing_status="ROUTED",
            playbook_id="PB-LOOP-001",
        )
        administrator = Administrator(system_username="admin-test")
        db.session.add_all([network_switch, port, incident, administrator])
        db.session.commit()

        decision = evaluate_incident(
            incident,
            target_confirmed=True,
            target_mac_address="00:11:22:33:44:55",
            target_ip="192.0.2.50",
            switch_id="sw-1",
            port_index=4,
            now=datetime(2026, 8, 10, 10, 0, tzinfo=ZoneInfo("Africa/Kinshasa")),
        )

        remediation = db.session.execute(db.select(Remediation)).scalar_one()
        assert decision.state == "WAITING_ADMIN_APPROVAL"
        assert remediation.authorization_mode == "SUPERVISED"
        assert remediation.previous_port_status == "up"
        assert remediation.previous_vlan_id == 10

        approve_incident(incident, administrator.administrator_id)
        with pytest.raises(UnsafeOperationBlocked):
            execute_authorized_remediation(incident)
        assert incident.processing_status == "BLOCKED_SNMP_WRITE"


def test_waiting_incident_never_becomes_automatic_when_time_changes(app):
    with app.app_context():
        network_switch = NetworkSwitch(
            switch_id="sw-wait",
            name="EVE-NG-SW-WAIT",
            management_ip="192.0.2.11",
            model="Arista vEOS 4.29.2F",
        )
        port = SwitchPort(
            network_switch=network_switch,
            port_index=2,
            port_name="Ethernet2",
            status="up",
            vlan_id=10,
        )
        incident = Incident(
            incident_type="network_loop",
            zabbix_event_id="evt-waiting-stays-waiting",
            processing_status="ROUTED",
            playbook_id="PB-LOOP-001",
        )
        db.session.add_all([network_switch, port, incident])
        db.session.commit()
        evaluate_incident(
            incident,
            target_confirmed=True,
            target_mac_address=None,
            switch_id="sw-wait",
            port_index=2,
            now=datetime(2026, 8, 10, 10, 0, tzinfo=ZoneInfo("Africa/Kinshasa")),
        )
        assert incident.processing_status == "WAITING_ADMIN_APPROVAL"

        with pytest.raises(RemediationError, match="elapsed time is not authorization"):
            evaluate_incident(
                incident,
                target_confirmed=True,
                target_mac_address=None,
                switch_id="sw-wait",
                port_index=2,
                now=datetime(2026, 8, 10, 23, 0, tzinfo=ZoneInfo("Africa/Kinshasa")),
            )
        assert incident.processing_status == "WAITING_ADMIN_APPROVAL"

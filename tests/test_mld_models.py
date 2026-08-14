from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import inspect

from app.extensions import db
from app.models import (
    AuditLog,
    Incident,
    NetworkHost,
    NetworkSwitch,
    Remediation,
    SwitchPort,
)
from app.services.calendar_policy import load_automation_schedule
from app.services.whitelist import is_port_protected


EXPECTED_TABLES = {
    "incidents",
    "remediations",
    "audit_logs",
    "switch_ports",
    "network_hosts",
    "network_switches",
}


def test_database_contains_exactly_the_six_mld_tables(app):
    with app.app_context():
        assert set(inspect(db.engine).get_table_names()) == EXPECTED_TABLES


def test_mld_column_sets_are_exact(app):
    expected = {
        "incidents": {
            "incident_id",
            "incident_type",
            "severity",
            "detected_at",
            "source_ip",
            "description",
            "zabbix_event_id",
            "processing_status",
            "playbook_id",
        },
        "remediations": {
            "remediation_id",
            "incident_id",
            "target_mac_address",
            "switch_id",
            "port_index",
            "action_type",
            "authorization_mode",
            "start_time",
            "end_time",
            "status",
            "previous_port_status",
            "previous_vlan_id",
        },
        "audit_logs": {
            "log_id",
            "event_timestamp",
            "event_type",
            "incident_id",
            "remediation_id",
            "equipment_name",
            "equipment_ip",
            "port_index",
            "target_ip",
            "target_mac",
            "incident_type",
            "action_type",
            "result_status",
            "message",
        },
        "switch_ports": {"switch_id", "port_index", "port_name", "status", "vlan_id"},
        "network_hosts": {"mac_address", "ip_address", "switch_id", "port_index"},
        "network_switches": {"switch_id", "name", "management_ip", "model"},
    }
    with app.app_context():
        database = inspect(db.engine)
        for table_name, columns in expected.items():
            assert {column["name"] for column in database.get_columns(table_name)} == columns


def test_switch_port_composite_key_and_optional_host_location(app):
    with app.app_context():
        database = inspect(db.engine)
        assert set(database.get_pk_constraint("switch_ports")["constrained_columns"]) == {
            "switch_id",
            "port_index",
        }
        host_columns = {
            column["name"]: column for column in database.get_columns("network_hosts")
        }
        assert host_columns["switch_id"]["nullable"] is True
        assert host_columns["port_index"]["nullable"] is True


def test_mld_foreign_keys_are_present(app):
    with app.app_context():
        database = inspect(db.engine)

        def foreign_keys(
            table_name: str,
        ) -> set[tuple[tuple[str, ...], str, tuple[str, ...]]]:
            return {
                (
                    tuple(key["constrained_columns"]),
                    key["referred_table"],
                    tuple(key["referred_columns"]),
                )
                for key in database.get_foreign_keys(table_name)
            }

        assert (("switch_id",), "network_switches", ("switch_id",)) in foreign_keys(
            "switch_ports"
        )
        assert (
            ("switch_id", "port_index"),
            "switch_ports",
            ("switch_id", "port_index"),
        ) in foreign_keys("network_hosts")
        remediation_keys = foreign_keys("remediations")
        assert (("incident_id",), "incidents", ("incident_id",)) in remediation_keys
        assert (
            ("target_mac_address",),
            "network_hosts",
            ("mac_address",),
        ) in remediation_keys
        assert (
            ("switch_id", "port_index"),
            "switch_ports",
            ("switch_id", "port_index"),
        ) in remediation_keys
        audit_keys = foreign_keys("audit_logs")
        assert (("incident_id",), "incidents", ("incident_id",)) in audit_keys
        assert (
            ("remediation_id",),
            "remediations",
            ("remediation_id",),
        ) in audit_keys


def test_model_relationships_and_foreign_keys(app):
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
        host = NetworkHost(
            mac_address="00:11:22:33:44:55",
            ip_address="192.0.2.50",
            switch_port=port,
        )
        incident = Incident(
            incident_type="network_loop",
            severity="High",
            source_ip="192.0.2.10",
            description="Boucle detectee",
            zabbix_event_id="evt-model-1",
            processing_status="ROUTED",
            playbook_id="PB-LOOP-001",
        )
        remediation = Remediation(
            incident=incident,
            target_host=host,
            switch_port=port,
            switch_id="sw-1",
            port_index=4,
            action_type="SHUTDOWN_PORT",
            authorization_mode="SUPERVISED",
            status="WAITING_ADMIN_APPROVAL",
            previous_port_status="up",
            previous_vlan_id=10,
        )
        log = AuditLog(
            incident=incident,
            remediation=remediation,
            event_type="RULE_DECISION",
            equipment_name=network_switch.name,
            equipment_ip=network_switch.management_ip,
            port_index=4,
            target_ip=host.ip_address,
            target_mac=host.mac_address,
            incident_type=incident.incident_type,
            action_type=remediation.action_type,
            result_status=remediation.status,
            message="test",
        )
        db.session.add_all([network_switch, host, incident, remediation, log])
        db.session.commit()

        assert remediation in incident.remediations
        assert port in network_switch.ports
        assert host.switch_port is port
        assert remediation.target_host is host
        assert remediation.switch_port is port
        assert log.incident is incident
        assert log.remediation is remediation


def test_whitelist_and_schedule_are_external_configuration(tmp_path):
    whitelist_path = tmp_path / "whitelist.json"
    whitelist_path.write_text(
        json.dumps(
            {
                "protected_categories": ["trunk"],
                "entries": [
                    {
                        "switch_id": "sw-1",
                        "port_index": 4,
                        "category": "trunk",
                        "reason": "liaison inter-switch",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert is_port_protected(whitelist_path, switch_id="sw-1", port_index=4)
    assert not is_port_protected(whitelist_path, switch_id="sw-1", port_index=5)

    schedule_path = (
        Path(__file__).resolve().parents[1]
        / "config"
        / "automation_schedule.json"
    )
    schedule = load_automation_schedule(schedule_path)
    assert schedule.timezone_name == "Africa/Kinshasa"
    assert schedule.automatic_days == {5, 6}
    assert schedule.automatic_allowed_actions == {
        "SHUTDOWN_PORT",
        "QUARANTINE_VLAN",
    }


def test_quarantine_vlan_18_is_application_configuration(app):
    assert app.config["QUARANTINE_VLAN_ID"] == 18

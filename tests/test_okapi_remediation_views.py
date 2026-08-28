from datetime import datetime, timezone
from types import SimpleNamespace

from app.cli.okapi import _remediation_history, _rollback
from app.extensions import db
from app.models import Administrator, AuditLog, Incident, NetworkSwitch, Remediation, SwitchPort


def _incident(event_id: str, status: str = "REMEDIATED") -> Incident:
    return Incident(
        incident_type="network_loop",
        zabbix_event_id=event_id,
        processing_status=status,
        playbook_id="PB-LOOP-001",
    )


def test_history_and_available_rollback_views_are_contextual(app, monkeypatch, capsys):
    with app.app_context():
        administrator = Administrator(
            administrator_id="admin-exau", system_username="exauceeadm"
        )
        network_switch = NetworkSwitch(
            switch_id="sw-view",
            name="SW-ACCESS",
            management_ip="192.0.2.30",
            model="Arista vEOS 4.29.2F",
        )
        shutdown_port = SwitchPort(
            network_switch=network_switch,
            port_index=2,
            port_name="Ethernet2",
            status="down",
            vlan_id=10,
        )
        vlan_port = SwitchPort(
            network_switch=network_switch,
            port_index=3,
            port_name="Ethernet3",
            status="up",
            vlan_id=18,
        )
        failed_port = SwitchPort(
            network_switch=network_switch,
            port_index=4,
            port_name="Ethernet4",
            status="up",
            vlan_id=10,
        )
        recovered_port = SwitchPort(
            network_switch=network_switch,
            port_index=5,
            port_name="Ethernet5",
            status="up",
            vlan_id=10,
        )

        supervised_incident = _incident("evt-view-supervised")
        supervised = Remediation(
            incident=supervised_incident,
            switch_port=shutdown_port,
            switch_id=network_switch.switch_id,
            port_index=shutdown_port.port_index,
            action_type="SHUTDOWN_PORT",
            authorization_mode="SUPERVISED",
            status="SUCCEEDED",
            previous_port_status="1",
            applied_port_status="DOWN",
            start_time=datetime(2026, 8, 20, 14, 22, tzinfo=timezone.utc),
        )
        automatic_incident = _incident("evt-view-automatic")
        automatic = Remediation(
            incident=automatic_incident,
            switch_port=vlan_port,
            switch_id=network_switch.switch_id,
            port_index=vlan_port.port_index,
            action_type="QUARANTINE_VLAN",
            authorization_mode="AUTOMATIC",
            status="SUCCEEDED",
            previous_vlan_id=8,
            applied_vlan_id=18,
            start_time=datetime(2026, 8, 20, 14, 15, tzinfo=timezone.utc),
        )
        failed_incident = _incident("evt-view-failed", "REMEDIATION_FAILED")
        failed = Remediation(
            incident=failed_incident,
            switch_port=failed_port,
            switch_id=network_switch.switch_id,
            port_index=failed_port.port_index,
            action_type="QUARANTINE_VLAN",
            authorization_mode="AUTOMATIC",
            status="FAILED",
            previous_vlan_id=10,
            applied_vlan_id=18,
        )
        recovered_incident = _incident(
            "evt-view-recovered", "RECOVERED_BEFORE_ACTION"
        )
        recovered = Remediation(
            incident=recovered_incident,
            switch_port=recovered_port,
            switch_id=network_switch.switch_id,
            port_index=recovered_port.port_index,
            action_type="SHUTDOWN_PORT",
            authorization_mode="AUTOMATIC",
            status="RECOVERED_BEFORE_ACTION",
            previous_port_status="UP",
        )
        approval = AuditLog(
            incident=supervised_incident,
            remediation=supervised,
            administrator=administrator,
            event_type="REMEDIATION_APPROVED",
            action_type=supervised.action_type,
            result_status="ADMIN_APPROVED",
            message="Administrator explicitly approved remediation.",
        )
        db.session.add_all(
            [
                administrator,
                network_switch,
                shutdown_port,
                vlan_port,
                failed_port,
                recovered_port,
                supervised_incident,
                supervised,
                automatic_incident,
                automatic,
                failed_incident,
                failed,
                recovered_incident,
                recovered,
                approval,
            ]
        )
        db.session.commit()

        _remediation_history()
        history = capsys.readouterr().out
        assert "Result      : FAILED" in history
        assert "Result      : RECOVERED_BEFORE_ACTION" in history
        assert "Mode        : SUPERVISED" in history
        assert "Approved by : exauceeadm" in history
        assert "Mode        : AUTOMATIC" in history
        assert "Executed by : SYSTEM" in history
        assert "Reason" not in history

        monkeypatch.setattr("click.prompt", lambda *_args, **_kwargs: "B")
        _rollback(administrator)
        rollback_view = capsys.readouterr().out

        assert "OKAPI - AVAILABLE ROLLBACKS" in rollback_view
        assert "Action          : SHUTDOWN_PORT" in rollback_view
        assert "Current state   : DOWN" in rollback_view
        assert "Restore to      : UP" in rollback_view
        assert "Approved by : exauceeadm" in rollback_view
        assert "Action          : QUARANTINE_VLAN" in rollback_view
        assert "Current VLAN    : 18" in rollback_view
        assert "Restore VLAN    : 8" in rollback_view
        assert "Executed by : SYSTEM" in rollback_view
        assert "FAILED" not in rollback_view
        assert "RECOVERED_BEFORE_ACTION" not in rollback_view
        assert "previous admin status" not in rollback_view
        assert "Reason" not in rollback_view


def test_interface_rollback_result_never_displays_raw_state(app, monkeypatch, capsys):
    remediation = SimpleNamespace(
        action_type="SHUTDOWN_PORT",
        applied_port_status="DOWN",
        previous_port_status="1",
        applied_vlan_id=None,
        previous_vlan_id=None,
        authorization_mode="SUPERVISED",
        start_time=datetime(2026, 8, 27, tzinfo=timezone.utc),
        switch_port=None,
        target_host=None,
        port_index=2,
    )
    monkeypatch.setattr("app.cli.okapi.available_rollbacks", lambda: [remediation])
    monkeypatch.setattr("app.cli.okapi._remediation_actor_label", lambda _item: "Approved by : alice")
    monkeypatch.setattr("app.cli.okapi.click.prompt", lambda *_args, **_kwargs: "1")
    monkeypatch.setattr("app.cli.okapi.reauthenticate_for_critical_action", lambda *_args: None)
    monkeypatch.setattr("app.cli.okapi.rollback_snmp_action", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr("app.cli.okapi.is_dry_run_enabled", lambda: False)

    with app.app_context():
        _rollback(Administrator(system_username="alice"))

    output = capsys.readouterr().out
    assert "Rollback succeeded. Restored state: UP" in output
    assert "Restored value: 1" not in output


def test_vlan_rollback_result_names_the_restored_vlan(app, monkeypatch, capsys):
    remediation = SimpleNamespace(
        action_type="QUARANTINE_VLAN",
        applied_port_status=None,
        previous_port_status=None,
        applied_vlan_id=18,
        previous_vlan_id=10,
        authorization_mode="SUPERVISED",
        start_time=datetime(2026, 8, 27, tzinfo=timezone.utc),
        switch_port=None,
        target_host=None,
        port_index=2,
    )
    monkeypatch.setattr("app.cli.okapi.available_rollbacks", lambda: [remediation])
    monkeypatch.setattr("app.cli.okapi._remediation_actor_label", lambda _item: "Approved by : alice")
    monkeypatch.setattr("app.cli.okapi.click.prompt", lambda *_args, **_kwargs: "1")
    monkeypatch.setattr("app.cli.okapi.reauthenticate_for_critical_action", lambda *_args: None)
    monkeypatch.setattr("app.cli.okapi.rollback_snmp_action", lambda *_args, **_kwargs: 10)
    monkeypatch.setattr("app.cli.okapi.is_dry_run_enabled", lambda: False)

    with app.app_context():
        _rollback(Administrator(system_username="alice"))

    output = capsys.readouterr().out
    assert "Rollback succeeded. Restored VLAN: 10" in output
    assert "Restored value: 10" not in output

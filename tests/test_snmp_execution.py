import json
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.extensions import db
from app.models import Administrator, AuditLog, Incident, NetworkHost, NetworkSwitch, Remediation, SwitchPort
from app.services.audit import record_audit
from app.services.remediation import (
    RemediationError,
    UnsafeOperationBlocked,
    approve_incident,
)
from app.services.snmp_execution import (
    RemediationVerificationError,
    RollbackStateChangedError,
    available_rollbacks,
    execute_interface_admin_action,
    execute_quarantine_vlan,
    execute_snmp_action,
    rollback_interface_admin_action,
    rollback_quarantine_vlan,
)
from app.snmp.client import SnmpV3Config
from app.snmp.mib_catalog import DOT1Q_PVID, MibObjectRef
from app.snmp.mib_registry import MibRegistry


TARGET_MAC = "00:50:79:66:68:03"


def snmp_config() -> SnmpV3Config:
    return SnmpV3Config(
        host="192.0.2.10",
        username="snmp-user",
        auth_key="auth-secret",
        priv_key="priv-secret",
    )


class FakeWriteClient:
    def __init__(self, read_values: list[int]) -> None:
        self.read_values = [str(value) for value in read_values]
        self.read_calls: list[MibObjectRef] = []
        self.set_calls: list[tuple[MibObjectRef, int, bool]] = []

    async def read_scalar(self, object_ref: MibObjectRef) -> str:
        self.read_calls.append(object_ref)
        if not self.read_values:
            raise AssertionError("Aucune valeur GET preparee")
        return self.read_values.pop(0)

    async def set_integer(
        self,
        object_ref: MibObjectRef,
        value: int,
        *,
        write_authorized: bool,
    ) -> str:
        self.set_calls.append((object_ref, value, write_authorized))
        return str(value)


def build_waiting_remediation(
    *,
    model: str = "Arista vEOS 4.29.2F",
    prepared: bool = True,
) -> tuple[Incident, Remediation, SwitchPort]:
    network_switch = NetworkSwitch(
        switch_id="sw-eve-1",
        name="EVE-NG-Arista",
        management_ip="192.0.2.10",
        model=model,
    )
    port = SwitchPort(
        network_switch=network_switch,
        port_index=2,
        port_name="Ethernet2",
        status="up",
        vlan_id=10,
    )
    host = NetworkHost(
        mac_address=TARGET_MAC,
        ip_address="192.0.2.50",
        switch_port=port,
    )
    incident = Incident(
        incident_type="ip_address_conflict",
        severity="High",
        source_ip="192.0.2.10",
        description="Conflit IP",
        zabbix_event_id="evt-execution-1",
        processing_status="WAITING_ADMIN_APPROVAL",
        playbook_id="PB-IP-CONFLICT-001",
    )
    remediation = Remediation(
        incident=incident,
        target_host=host,
        switch_port=port,
        switch_id="sw-eve-1",
        port_index=2,
        action_type="QUARANTINE_VLAN",
        authorization_mode="SUPERVISED",
        status="WAITING_ADMIN_APPROVAL",
        previous_port_status="up",
        previous_vlan_id=10,
    )
    administrator = Administrator(
        administrator_id="admin-test", system_username="admin-test"
    )
    db.session.add_all(
        [network_switch, port, host, incident, remediation, administrator]
    )
    db.session.commit()
    if prepared:
        record_audit(
            incident_id=incident.incident_id,
            remediation_id=remediation.remediation_id,
            event_type="SNMP_TARGET_PREPARED",
            message="Cible resolue avant approbation.",
            result_status="WAITING_ADMIN_APPROVAL",
            details={
                "t_identification_seconds": 1.25,
                "t_prechecks_seconds": 2.5,
            },
        )
        db.session.commit()
    return incident, remediation, port


def approve(incident: Incident) -> None:
    approve_incident(incident, "admin-test")


def enable_writes(app) -> None:
    app.config["SNMP_WRITE_ENABLED"] = True


def test_no_human_approval_means_no_set(app):
    enable_writes(app)
    with app.app_context():
        incident, _remediation, _port = build_waiting_remediation()
        fake = FakeWriteClient([10, 18])

        with pytest.raises(RemediationError, match="Explicit authorization"):
            execute_quarantine_vlan(
                incident, client=fake, snmp_config=snmp_config()
            )

        assert fake.set_calls == []
        assert fake.read_calls == []


def test_write_feature_flag_false_blocks_before_set(app):
    with app.app_context():
        incident, _remediation, _port = build_waiting_remediation()
        approve(incident)
        fake = FakeWriteClient([10, 18])

        with pytest.raises(UnsafeOperationBlocked, match="SNMP_WRITE_ENABLED"):
            execute_quarantine_vlan(
                incident, client=fake, snmp_config=snmp_config()
            )

        assert fake.set_calls == []
        assert fake.read_calls == []


def test_manual_bypass_without_snmp_preparation_is_blocked(app):
    enable_writes(app)
    with app.app_context():
        incident, _remediation, _port = build_waiting_remediation(prepared=False)
        approve(incident)
        fake = FakeWriteClient([10, 18])

        with pytest.raises(UnsafeOperationBlocked, match="snmp_preparation_missing"):
            execute_quarantine_vlan(
                incident, client=fake, snmp_config=snmp_config()
            )

        assert fake.set_calls == []


def test_missing_mib_blocks_before_set(app):
    enable_writes(app)
    missing = MibRegistry(package="package_mib_absent_test")
    missing.warm_up()
    app.extensions["snmp_mib_registry"] = missing
    with app.app_context():
        incident, _remediation, _port = build_waiting_remediation()
        approve(incident)
        fake = FakeWriteClient([10, 18])

        with pytest.raises(UnsafeOperationBlocked, match="mib_not_ready"):
            execute_quarantine_vlan(
                incident, client=fake, snmp_config=snmp_config()
            )

        assert fake.set_calls == []
        assert fake.read_calls == []


def test_unvalidated_unifi_capability_blocks_before_set(app):
    enable_writes(app)
    with app.app_context():
        incident, _remediation, _port = build_waiting_remediation(model="UniFi")
        approve(incident)
        fake = FakeWriteClient([10, 18])

        with pytest.raises(UnsafeOperationBlocked, match="capability_blocked"):
            execute_quarantine_vlan(
                incident, client=fake, snmp_config=snmp_config()
            )

        assert fake.set_calls == []
        assert fake.read_calls == []


def test_whitelist_is_rechecked_after_approval_and_blocks_set(
    app, tmp_path: Path
):
    whitelist = tmp_path / "whitelist.json"
    whitelist.write_text(
        json.dumps(
            {
                "protected_categories": ["server"],
                "entries": [
                    {
                        "switch_id": "sw-eve-1",
                        "port_index": 2,
                        "category": "server",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    app.config.update(SNMP_WRITE_ENABLED=True, WHITELIST_PATH=whitelist)
    with app.app_context():
        incident, _remediation, _port = build_waiting_remediation()
        approve(incident)
        fake = FakeWriteClient([10, 18])

        with pytest.raises(UnsafeOperationBlocked, match="whitelisted"):
            execute_quarantine_vlan(
                incident, client=fake, snmp_config=snmp_config()
            )

        assert fake.set_calls == []
        assert fake.read_calls == []


def test_set_success_but_post_get_mismatch_fails_verification(app):
    enable_writes(app)
    with app.app_context():
        incident, remediation, port = build_waiting_remediation()
        approve(incident)
        fake = FakeWriteClient([10, 10, 10])

        with pytest.raises(RemediationVerificationError, match="Requested VLAN 18"):
            execute_quarantine_vlan(
                incident, client=fake, snmp_config=snmp_config()
            )

        assert len(fake.set_calls) == 2
        assert fake.set_calls[0][0] == DOT1Q_PVID.with_indices(2)
        assert fake.set_calls[0][1:] == (18, True)
        assert remediation.status == "VERIFICATION_FAILED"
        assert incident.processing_status == "REMEDIATION_FAILED"
        assert port.vlan_id == 10


def test_successful_set_is_confirmed_by_get_and_updates_inventory(app):
    enable_writes(app)
    with app.app_context():
        incident, remediation, port = build_waiting_remediation()
        approve(incident)
        fake = FakeWriteClient([10, 18])

        result = execute_quarantine_vlan(
            incident, client=fake, snmp_config=snmp_config()
        )

        assert result.requested_vlan == 18
        assert result.observed_vlan == 18
        assert len(fake.set_calls) == 1
        assert remediation.status == "SUCCEEDED"
        assert incident.processing_status == "REMEDIATED"
        assert port.vlan_id == 18


def test_rollback_requires_explicit_administrator_request(app):
    enable_writes(app)
    with app.app_context():
        incident, remediation, _port = build_waiting_remediation()
        remediation.status = "SUCCEEDED"
        db.session.commit()
        fake = FakeWriteClient([10])

        with pytest.raises(RemediationError, match="explicit administrator"):
            rollback_quarantine_vlan(
                incident,
                administrator_id=" ",
                client=fake,
                snmp_config=snmp_config(),
            )

        assert fake.set_calls == []
        assert fake.read_calls == []


def test_explicit_rollback_restores_saved_previous_pvid(app):
    enable_writes(app)
    with app.app_context():
        incident, remediation, port = build_waiting_remediation()
        approve(incident)
        execute_quarantine_vlan(
            incident,
            client=FakeWriteClient([10, 18]),
            snmp_config=snmp_config(),
        )
        rollback_client = FakeWriteClient([18, 10])

        observed = rollback_quarantine_vlan(
            incident,
            administrator_id="admin-test",
            client=rollback_client,
            snmp_config=snmp_config(),
        )

        assert observed == 10
        assert rollback_client.set_calls[0][1:] == (10, True)
        assert remediation.status == "ROLLED_BACK"
        assert incident.processing_status == "ROLLED_BACK"
        assert port.vlan_id == 10


def test_timing_sums_automated_segments_and_excludes_human_wait(app):
    enable_writes(app)
    clock_values: Iterator[float] = iter(
        [0.0, 1.0, 1000.0, 1002.0, 5000.0, 5003.0]
    )
    with app.app_context():
        incident, _remediation, _port = build_waiting_remediation()
        approve(incident)

        result = execute_quarantine_vlan(
            incident,
            client=FakeWriteClient([10, 18]),
            snmp_config=snmp_config(),
            clock=lambda: next(clock_values),
        )

        assert result.timing.identification_seconds == pytest.approx(1.25)
        assert result.timing.prechecks_seconds == pytest.approx(3.5)
        assert result.timing.snmp_set_seconds == pytest.approx(2.0)
        assert result.timing.verification_seconds == pytest.approx(3.0)
        assert result.timing.total_automated_seconds == pytest.approx(9.75)


@pytest.mark.parametrize(
    ("action_type", "previous_status", "read_values", "expected"),
    [
        ("SHUTDOWN_PORT", "up", [200, 1, 2], 2),
        ("REACTIVATE_PORT", "down", [200, 2, 1], 1),
    ],
)
def test_interface_actions_record_all_automated_timing_metrics(
    app,
    monkeypatch,
    action_type,
    previous_status,
    read_values,
    expected,
):
    enable_writes(app)
    monkeypatch.setattr(
        "app.services.snmp_execution.require_lab_validated_write",
        lambda *_args, **_kwargs: None,
    )
    clock_values: Iterator[float] = iter([0.0, 0.5, 10.0, 12.0, 20.0, 23.0])
    with app.app_context():
        incident, remediation, port = build_waiting_remediation()
        remediation.action_type = action_type
        remediation.previous_port_status = previous_status
        port.status = previous_status
        db.session.commit()
        approve(incident)

        result = execute_interface_admin_action(
            incident,
            client=FakeWriteClient(read_values),
            snmp_config=snmp_config(),
            clock=lambda: next(clock_values),
        )

        assert result.observed_vlan == expected
        assert result.timing.identification_seconds == pytest.approx(1.25)
        assert result.timing.prechecks_seconds == pytest.approx(3.0)
        assert result.timing.snmp_set_seconds == pytest.approx(2.0)
        assert result.timing.verification_seconds == pytest.approx(3.0)
        assert result.timing.total_automated_seconds == pytest.approx(9.25)

        audit = db.session.execute(
            db.select(AuditLog).where(
                AuditLog.event_type == "SNMP_REMEDIATION_SUCCEEDED"
            )
        ).scalar_one()
        details = json.loads(audit.message.split(" | ", 1)[1])
        assert details["t_identification_seconds"] == pytest.approx(1.25)
        assert details["t_prechecks_seconds"] == pytest.approx(3.0)
        assert details["t_snmp_set_seconds"] == pytest.approx(2.0)
        assert details["t_verification_seconds"] == pytest.approx(3.0)
        assert details["t_total_automated_seconds"] == pytest.approx(9.25)
        assert details["human_wait_excluded"] is True


def test_dry_run_never_calls_set(app):
    app.config.update(SNMP_WRITE_ENABLED=True, DRY_RUN=True)
    with app.app_context():
        incident, remediation, _port = build_waiting_remediation()
        approve(incident)
        fake = FakeWriteClient([])
        result = execute_quarantine_vlan(incident, client=fake, snmp_config=snmp_config())
        assert result.success is False
        assert result.simulated is True
        assert result.observed_vlan == 10
        assert remediation.status == "DRY_RUN"
        assert incident.processing_status == "SIMULATED"
        assert fake.set_calls == []
        assert fake.read_calls == []
        audit = db.session.execute(
            db.select(AuditLog).where(AuditLog.event_type == "DRY_RUN")
        ).scalar_one()
        assert audit.result_status == "SIMULATED"
        assert '"execution_mode": "DRY_RUN"' in audit.message
        assert '"snmp_set_executed": false' in audit.message
        assert '"write_result": "NO_WRITE"' in audit.message


def test_dry_run_simulates_even_when_write_flag_is_disabled(app):
    app.config.update(SNMP_WRITE_ENABLED=False, DRY_RUN=True)
    with app.app_context():
        incident, remediation, _port = build_waiting_remediation()
        approve(incident)
        fake = FakeWriteClient([])

        result = execute_quarantine_vlan(
            incident, client=fake, snmp_config=snmp_config()
        )

        assert result.simulated is True
        assert remediation.status == "DRY_RUN"
        assert fake.set_calls == []
        assert fake.read_calls == []


def test_dry_run_blocks_interface_admin_set(app):
    app.config.update(SNMP_WRITE_ENABLED=True, DRY_RUN=True)
    with app.app_context():
        incident, remediation, _port = build_waiting_remediation()
        remediation.action_type = "SHUTDOWN_PORT"
        remediation.previous_port_status = "up"
        db.session.commit()
        approve(incident)
        fake = FakeWriteClient([])

        result = execute_interface_admin_action(
            incident, client=fake, snmp_config=snmp_config()
        )

        assert result.simulated is True
        assert result.requested_vlan == 2
        assert result.observed_vlan == 1
        assert fake.set_calls == []
        assert fake.read_calls == []


def test_dry_run_simulates_explicit_rollback_without_set(app):
    app.config.update(SNMP_WRITE_ENABLED=True, DRY_RUN=True)
    with app.app_context():
        incident, remediation, _port = build_waiting_remediation()
        remediation.status = "SUCCEEDED"
        remediation.applied_vlan_id = 18
        incident.processing_status = "REMEDIATED"
        db.session.commit()
        fake = FakeWriteClient([])

        requested = rollback_quarantine_vlan(
            incident,
            administrator_id="admin-test",
            client=fake,
            snmp_config=snmp_config(),
        )

        assert requested == 10
        assert remediation.status == "SUCCEEDED"
        assert incident.processing_status == "REMEDIATED"
        assert fake.set_calls == []
        assert fake.read_calls == []
        audit = db.session.execute(
            db.select(AuditLog).where(AuditLog.event_type == "DRY_RUN_ROLLBACK")
        ).scalar_one()
        assert audit.result_status == "SIMULATED"
        assert '"snmp_set_executed": false' in audit.message
        assert '"write_result": "NO_WRITE"' in audit.message


def test_unknown_action_has_no_snmp_write_path(app):
    with app.app_context():
        incident, remediation, _port = build_waiting_remediation()
        incident.incident_type = None
        incident.playbook_id = "PB-UNKNOWN-001"
        incident.processing_status = "ADMIN_APPROVED"
        remediation.action_type = "NO_ACTION"
        remediation.status = "AUTHORIZED_PENDING_EXECUTION"
        db.session.commit()
        fake = FakeWriteClient([])

        with pytest.raises(UnsafeOperationBlocked, match="action_has_no_write_path"):
            execute_snmp_action(incident, client=fake, snmp_config=snmp_config())

        assert fake.set_calls == []
        assert fake.read_calls == []


def test_recent_remediation_on_same_port_enforces_cooldown(app):
    enable_writes(app)
    with app.app_context():
        incident, _remediation, port = build_waiting_remediation()
        prior_incident = Incident(
            incident_type="ip_address_conflict",
            zabbix_event_id="evt-prior-cooldown",
            processing_status="REMEDIATED",
            playbook_id="PB-IP-CONFLICT-001",
        )
        prior = Remediation(
            incident=prior_incident,
            switch_port=port,
            switch_id=port.switch_id,
            port_index=port.port_index,
            action_type="QUARANTINE_VLAN",
            authorization_mode="SUPERVISED",
            status="SUCCEEDED",
            previous_vlan_id=10,
            end_time=datetime.now(timezone.utc),
        )
        db.session.add_all([prior_incident, prior])
        db.session.commit()
        approve(incident)
        fake = FakeWriteClient([])

        with pytest.raises(UnsafeOperationBlocked, match="cooldown"):
            execute_quarantine_vlan(
                incident, client=fake, snmp_config=snmp_config()
            )

        assert fake.set_calls == []
        assert fake.read_calls == []


def test_vlan_8_is_restored_without_a_hardcoded_rollback_value(app):
    enable_writes(app)
    with app.app_context():
        incident, remediation, port = build_waiting_remediation()
        remediation.previous_vlan_id = 8
        port.vlan_id = 8
        db.session.commit()
        approve(incident)

        execute_quarantine_vlan(
            incident,
            client=FakeWriteClient([8, 18]),
            snmp_config=snmp_config(),
        )
        rollback_client = FakeWriteClient([18, 8])
        observed = rollback_quarantine_vlan(
            remediation,
            administrator_id="admin-test",
            client=rollback_client,
            snmp_config=snmp_config(),
        )

        assert observed == 8
        assert rollback_client.set_calls[0][1:] == (8, True)
        assert port.vlan_id == 8


def test_rollback_is_blocked_when_vlan_changed_after_remediation(app):
    enable_writes(app)
    with app.app_context():
        incident, remediation, _port = build_waiting_remediation()
        approve(incident)
        execute_quarantine_vlan(
            incident,
            client=FakeWriteClient([10, 18]),
            snmp_config=snmp_config(),
        )
        rollback_client = FakeWriteClient([20])

        with pytest.raises(RollbackStateChangedError, match="Expected current VLAN : 18"):
            rollback_quarantine_vlan(
                remediation,
                administrator_id="admin-test",
                client=rollback_client,
                snmp_config=snmp_config(),
            )

        assert rollback_client.set_calls == []
        assert remediation.status == "ROLLBACK_BLOCKED"
        audit = db.session.execute(
            db.select(AuditLog).where(
                AuditLog.event_type == "ROLLBACK_BLOCKED_STATE_CHANGED"
            )
        ).scalar_one()
        assert audit.administrator.system_username == "admin-test"
        assert '"observed_current": 20' in audit.message


def test_shutdown_rollback_restores_up_and_uses_readable_snapshot(app, monkeypatch):
    enable_writes(app)
    monkeypatch.setattr(
        "app.services.snmp_execution.require_lab_validated_write",
        lambda *_args, **_kwargs: None,
    )
    with app.app_context():
        incident, remediation, port = build_waiting_remediation()
        remediation.action_type = "SHUTDOWN_PORT"
        remediation.previous_port_status = "1"
        db.session.commit()
        approve(incident)

        execute_interface_admin_action(
            incident,
            client=FakeWriteClient([200, 1, 2]),
            snmp_config=snmp_config(),
        )
        assert remediation.applied_port_status == "DOWN"
        assert port.status == "down"

        rollback_client = FakeWriteClient([200, 2, 1])
        observed = rollback_interface_admin_action(
            remediation,
            administrator_id="admin-test",
            client=rollback_client,
            snmp_config=snmp_config(),
        )

        assert observed == 1
        assert rollback_client.set_calls[0][1:] == (1, True)
        assert port.status == "up"


def test_interface_rollback_is_blocked_after_an_external_state_change(
    app, monkeypatch
):
    enable_writes(app)
    monkeypatch.setattr(
        "app.services.snmp_execution.require_lab_validated_write",
        lambda *_args, **_kwargs: None,
    )
    with app.app_context():
        incident, remediation, _port = build_waiting_remediation()
        remediation.action_type = "SHUTDOWN_PORT"
        remediation.previous_port_status = "UP"
        db.session.commit()
        approve(incident)
        execute_interface_admin_action(
            incident,
            client=FakeWriteClient([200, 1, 2]),
            snmp_config=snmp_config(),
        )
        rollback_client = FakeWriteClient([200, 1])

        with pytest.raises(
            RollbackStateChangedError,
            match="Expected current administrative state : DOWN",
        ):
            rollback_interface_admin_action(
                remediation,
                administrator_id="admin-test",
                client=rollback_client,
                snmp_config=snmp_config(),
            )

        assert rollback_client.set_calls == []
        assert remediation.status == "ROLLBACK_BLOCKED"


@pytest.mark.parametrize("username", ["exauceeadm", "claude"])
def test_supervised_execution_uses_the_authenticated_approver(app, username):
    enable_writes(app)
    with app.app_context():
        incident, remediation, _port = build_waiting_remediation()
        administrator = db.session.get(Administrator, "admin-test")
        administrator.system_username = username
        db.session.commit()
        approve(incident)

        execute_quarantine_vlan(
            incident,
            client=FakeWriteClient([10, 18]),
            snmp_config=snmp_config(),
        )

        success = db.session.execute(
            db.select(AuditLog).where(
                AuditLog.remediation_id == remediation.remediation_id,
                AuditLog.event_type == "SNMP_REMEDIATION_SUCCEEDED",
            )
        ).scalar_one()
        assert remediation.authorization_mode == "SUPERVISED"
        assert success.administrator.system_username == username


def test_automatic_execution_is_attributed_to_system(app):
    enable_writes(app)
    with app.app_context():
        incident, remediation, _port = build_waiting_remediation()
        incident.processing_status = "AUTOMATICALLY_AUTHORIZED"
        remediation.authorization_mode = "AUTOMATIC"
        remediation.status = "AUTHORIZED_PENDING_EXECUTION"
        db.session.commit()

        execute_quarantine_vlan(
            incident,
            client=FakeWriteClient([10, 18]),
            snmp_config=snmp_config(),
        )

        success = db.session.execute(
            db.select(AuditLog).where(
                AuditLog.remediation_id == remediation.remediation_id,
                AuditLog.event_type == "SNMP_REMEDIATION_SUCCEEDED",
            )
        ).scalar_one()
        assert success.administrator_id is None
        assert success.to_dict()["administrator"] == "SYSTEM"


def test_available_rollbacks_filter_history_and_enforce_target_lifo(app):
    with app.app_context():
        _incident, older, port = build_waiting_remediation()
        older.status = "SUCCEEDED"
        older.applied_vlan_id = 18
        older.start_time = datetime(2026, 8, 20, 10, 0, tzinfo=timezone.utc)

        newer_incident = Incident(
            incident_type="network_loop",
            zabbix_event_id="evt-newer-change",
            processing_status="REMEDIATED",
            playbook_id="PB-LOOP-001",
        )
        newer = Remediation(
            incident=newer_incident,
            switch_port=port,
            switch_id=port.switch_id,
            port_index=port.port_index,
            action_type="SHUTDOWN_PORT",
            authorization_mode="SUPERVISED",
            status="SUCCEEDED",
            previous_port_status="UP",
            applied_port_status="DOWN",
            start_time=datetime(2026, 8, 20, 10, 5, tzinfo=timezone.utc),
        )
        failed_incident = Incident(
            incident_type="network_loop",
            zabbix_event_id="evt-failed-change",
            processing_status="REMEDIATION_FAILED",
            playbook_id="PB-LOOP-001",
        )
        failed = Remediation(
            incident=failed_incident,
            switch_port=port,
            switch_id=port.switch_id,
            port_index=port.port_index,
            action_type="SHUTDOWN_PORT",
            authorization_mode="AUTOMATIC",
            status="FAILED",
            previous_port_status="UP",
        )
        db.session.add_all([newer_incident, newer, failed_incident, failed])
        db.session.commit()

        assert available_rollbacks() == [newer]

        newer.status = "ROLLED_BACK"
        db.session.commit()
        assert available_rollbacks() == [older]

        older.status = "ROLLED_BACK"
        db.session.commit()
        assert available_rollbacks() == []

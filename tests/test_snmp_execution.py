import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.extensions import db
from app.models import Incident, NetworkHost, NetworkSwitch, Remediation, SwitchPort
from app.services.audit import record_audit
from app.services.remediation import (
    RemediationError,
    UnsafeOperationBlocked,
    approve_incident,
)
from app.services.snmp_execution import (
    RemediationVerificationError,
    execute_quarantine_vlan,
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
    db.session.add_all([network_switch, port, host, incident, remediation])
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

        with pytest.raises(RemediationError, match="approbation humaine"):
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
        fake = FakeWriteClient([10, 10])

        with pytest.raises(RemediationVerificationError, match="VLAN demande 18"):
            execute_quarantine_vlan(
                incident, client=fake, snmp_config=snmp_config()
            )

        assert len(fake.set_calls) == 1
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

        with pytest.raises(RemediationError, match="explicite"):
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
        rollback_client = FakeWriteClient([10])

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

import json
from pathlib import Path

import pytest

from app.extensions import db
from app.models import AuditLog, Incident, NetworkHost, NetworkSwitch, Remediation, SwitchPort
from app.services.snmp_preparation import (
    SnmpPreparationBlocked,
    prepare_incident_with_snmp,
)
from app.snmp.client import SnmpV3Config, SnmpWalkEntry
from app.snmp.mib_catalog import (
    DOT1D_BASE_PORT_IF_INDEX,
    DOT1Q_PVID,
    DOT1Q_TP_FDB_PORT,
    IF_DESCR,
    MibObjectRef,
)
from app.snmp.mib_registry import MibRegistry


TARGET_MAC = "00:50:79:66:68:03"
TARGET_SUFFIX = (0, 80, 121, 102, 104, 3)


def snmp_config() -> SnmpV3Config:
    return SnmpV3Config(
        host="192.0.2.10",
        username="snmp-user",
        auth_key="auth-secret",
        priv_key="priv-secret",
    )


def add_switch_and_incident(
    *, switch_id: str = "sw-eve-1", event_id: str = "evt-preparation-1"
) -> tuple[NetworkSwitch, Incident]:
    network_switch = NetworkSwitch(
        switch_id=switch_id,
        name="EVE-NG-Arista",
        management_ip="192.0.2.10",
        model="Arista vEOS 4.29.2F",
    )
    incident = Incident(
        incident_type="ip_address_conflict",
        severity="High",
        source_ip="192.0.2.10",
        description="Conflit IP",
        zabbix_event_id=event_id,
        processing_status="ROUTED",
        playbook_id="PB-IP-CONFLICT-001",
    )
    db.session.add_all([network_switch, incident])
    db.session.commit()
    return network_switch, incident


class FakePreparationClient:
    def __init__(
        self,
        *,
        rows: list[SnmpWalkEntry] | None = None,
        cached_bridge_port: int = 2,
    ) -> None:
        self.rows = rows if rows is not None else [self.fdb_row(10, 2)]
        self.cached_bridge_port = cached_bridge_port
        self.walk_calls = 0
        self.reads: list[MibObjectRef] = []

    @staticmethod
    def fdb_row(vlan_id: int, bridge_port: int) -> SnmpWalkEntry:
        return SnmpWalkEntry(
            object_ref=DOT1Q_TP_FDB_PORT,
            oid=(1, 3, 6, vlan_id, *TARGET_SUFFIX),
            suffix=(vlan_id, *TARGET_SUFFIX),
            value=str(bridge_port),
        )

    async def walk(
        self, column_ref: MibObjectRef, *, max_rows: int = 4096
    ) -> list[SnmpWalkEntry]:
        self.walk_calls += 1
        return self.rows

    async def read_scalar(self, object_ref: MibObjectRef) -> str:
        self.reads.append(object_ref)
        if object_ref.key == DOT1Q_TP_FDB_PORT.key:
            return str(self.cached_bridge_port)
        if object_ref.key == DOT1D_BASE_PORT_IF_INDEX.key:
            return "7"
        if object_ref.key == IF_DESCR.key:
            return "Ethernet2"
        if object_ref.key == DOT1Q_PVID.key:
            return "10"
        raise AssertionError(f"Lecture inattendue: {object_ref}")


def test_preparation_persists_bridge_port_interface_pvid_and_target(app):
    with app.app_context():
        _switch, incident = add_switch_and_incident()
        fake = FakePreparationClient()

        result = prepare_incident_with_snmp(
            incident,
            switch_id="sw-eve-1",
            target_mac=TARGET_MAC,
            target_ip="192.0.2.50",
            client=fake,
            snmp_config=snmp_config(),
        )

        port = db.session.get(SwitchPort, ("sw-eve-1", 2))
        host = db.session.get(NetworkHost, TARGET_MAC)
        remediation = db.session.execute(db.select(Remediation)).scalar_one()
        assert result.decision_state == "WAITING_ADMIN_APPROVAL"
        assert result.resolution.cache_hit is False
        assert port is not None
        assert port.port_index == 2  # bridge_port SNMP persiste
        assert port.port_name == "Ethernet2"
        assert port.vlan_id == 10
        assert host is not None and host.port_index == 2
        assert remediation.previous_vlan_id == 10
        assert remediation.authorization_mode == "SUPERVISED"
        assert fake.walk_calls == 1


def test_second_incident_revalidates_known_port_without_full_walk(app):
    with app.app_context():
        _switch, first = add_switch_and_incident()
        prepare_incident_with_snmp(
            first,
            switch_id="sw-eve-1",
            target_mac=TARGET_MAC,
            client=FakePreparationClient(),
            snmp_config=snmp_config(),
        )
        second = Incident(
            incident_type="ip_address_conflict",
            severity="High",
            source_ip="192.0.2.10",
            description="Nouveau conflit IP",
            zabbix_event_id="evt-preparation-2",
            processing_status="ROUTED",
            playbook_id="PB-IP-CONFLICT-001",
        )
        db.session.add(second)
        db.session.commit()
        cached_client = FakePreparationClient()

        result = prepare_incident_with_snmp(
            second,
            switch_id="sw-eve-1",
            target_mac=TARGET_MAC,
            client=cached_client,
            snmp_config=snmp_config(),
        )

        assert result.resolution.cache_hit is True
        assert cached_client.walk_calls == 0
        prepared_audit = db.session.execute(
            db.select(AuditLog).where(
                AuditLog.incident_id == second.incident_id,
                AuditLog.event_type == "SNMP_TARGET_PREPARED",
            )
        ).scalar_one()
        assert '"known_port_cache_hit": true' in prepared_audit.message


def test_ambiguous_mac_escalates_without_creating_remediation(app):
    with app.app_context():
        _switch, incident = add_switch_and_incident()
        fake = FakePreparationClient(
            rows=[
                FakePreparationClient.fdb_row(10, 2),
                FakePreparationClient.fdb_row(20, 3),
            ]
        )

        with pytest.raises(SnmpPreparationBlocked):
            prepare_incident_with_snmp(
                incident,
                switch_id="sw-eve-1",
                target_mac=TARGET_MAC,
                client=fake,
                snmp_config=snmp_config(),
            )

        assert incident.processing_status == "ESCALATED"
        assert db.session.execute(db.select(Remediation)).scalars().all() == []
        assert fake.walk_calls == 1


def test_whitelisted_port_is_not_authorized(app, tmp_path: Path):
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
                        "reason": "Serveur critique",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    app.config["WHITELIST_PATH"] = whitelist
    with app.app_context():
        _switch, incident = add_switch_and_incident()

        result = prepare_incident_with_snmp(
            incident,
            switch_id="sw-eve-1",
            target_mac=TARGET_MAC,
            client=FakePreparationClient(),
            snmp_config=snmp_config(),
        )

        remediation = db.session.execute(db.select(Remediation)).scalar_one()
        assert result.decision_state == "ESCALATED"
        assert remediation.status == "NOT_AUTHORIZED"


def test_missing_mib_blocks_preparation_before_any_snmp_read(app):
    missing = MibRegistry(package="package_mib_absent_test")
    missing.warm_up()
    app.extensions["snmp_mib_registry"] = missing
    with app.app_context():
        _switch, incident = add_switch_and_incident()
        fake = FakePreparationClient()

        with pytest.raises(SnmpPreparationBlocked):
            prepare_incident_with_snmp(
                incident,
                switch_id="sw-eve-1",
                target_mac=TARGET_MAC,
                client=fake,
                snmp_config=snmp_config(),
            )

        assert fake.walk_calls == 0
        assert fake.reads == []
        assert incident.processing_status == "ESCALATED"

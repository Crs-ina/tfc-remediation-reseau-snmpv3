from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

from flask import current_app

from app.extensions import db
from app.models import NetworkSwitch
from app.snmp.client import SnmpReadClient, SnmpV3Config
from app.snmp.mib_catalog import (
    DOT1D_BASE_PORT_IF_INDEX,
    IF_DESCR,
    SYS_DESCR,
    SYS_NAME,
)

from .audit import record_audit


class NetworkDiscoveryError(RuntimeError):
    pass


def _identify_switch_model(sys_descr: str) -> str | None:
    """Derive a qualified platform name from the SNMP sysDescr value."""

    arista = re.search(
        r"Arista Networks EOS version\s+([^\s]+).*Arista vEOS-lab",
        sys_descr,
        flags=re.IGNORECASE,
    )

    if arista:
        return f"Arista vEOS {arista.group(1)}"

    # Unknown platforms remain unqualified: SNMP writes will fail closed.
    return None


@dataclass(frozen=True)
class PortDiscovery:
    bridge_port: int
    if_index: int
    interface_name: str


def discover_switch(
    *,
    management_ip: str,
    incident_id: str | None = None,
    client: SnmpReadClient | None = None,
    snmp_config: SnmpV3Config | None = None,
) -> tuple[NetworkSwitch, SnmpReadClient, SnmpV3Config]:
    """
    Confirm the network switch through SNMPv3.

    Zabbix supplies the management IP, but the switch identity itself is
    independently confirmed through SNMP sysName.
    """

    registry = current_app.extensions["snmp_mib_registry"]

    if not registry.status.ready:
        raise NetworkDiscoveryError(
            f"MIB registry is not ready: {registry.status.error}"
        )

    effective_config = snmp_config or SnmpV3Config.from_env(
        host=management_ip
    )

    read_client = client or SnmpReadClient(
        effective_config,
        registry,
    )

    try:
        sys_name = str(
            asyncio.run(
                read_client.read_scalar(SYS_NAME)
            )
        ).strip()

        sys_descr = str(
            asyncio.run(
                read_client.read_scalar(SYS_DESCR)
            )
        ).strip()

        detected_model = _identify_switch_model(sys_descr)

    except Exception as exc:
        raise NetworkDiscoveryError(
            f"Unable to identify switch {management_ip} through SNMPv3: {exc}"
        ) from exc

    if not sys_name:
        raise NetworkDiscoveryError(
            "SNMP sysName returned an empty switch name."
        )

    # switch_id is deliberately stable and human-readable for whitelist rules.
    if len(sys_name) > 36:
        raise NetworkDiscoveryError(
            "SNMP sysName is too long to be used as the switch identifier."
        )

    switch = db.session.execute(
        db.select(NetworkSwitch).where(
            NetworkSwitch.management_ip == management_ip
        )
    ).scalar_one_or_none()

    created = False

    if switch is None:
        same_name = db.session.execute(
            db.select(NetworkSwitch).where(
                NetworkSwitch.name == sys_name
            )
        ).scalar_one_or_none()

        if (
            same_name is not None
            and same_name.management_ip != management_ip
        ):
            raise NetworkDiscoveryError(
                f"Switch name collision detected for {sys_name}."
            )

        switch = NetworkSwitch(
            switch_id=sys_name,
            name=sys_name,
            management_ip=management_ip,
            model=detected_model,
        )
        db.session.add(switch)
        db.session.flush()
        created = True

    else:
        # SNMP independently confirms both identity and platform.
        switch.name = sys_name
        switch.model = detected_model

    record_audit(
        incident_id=incident_id,
        event_type=(
            "NETWORK_SWITCH_DISCOVERED"
            if created
            else "NETWORK_SWITCH_CONFIRMED"
        ),
        message="Switch identity independently confirmed through SNMPv3 sysName.",
        equipment_name=sys_name,
        equipment_ip=management_ip,
        result_status="CONFIRMED",
        details={
            "switch_id": switch.switch_id,
            "source": "SNMPv3",
            "sys_descr": sys_descr,
            "detected_model": detected_model,
            "created": created,
        },
    )

    db.session.commit()

    return switch, read_client, effective_config


def resolve_interface_bridge_port(
    client: SnmpReadClient,
    interface_hint: str,
) -> PortDiscovery:
    """
    Resolve a Zabbix interface hint to the real bridge port through SNMP.

    interface name
        -> IF-MIB::ifDescr / ifIndex
        -> BRIDGE-MIB::dot1dBasePortIfIndex / bridge_port
    """

    raw_hint = interface_hint.strip()
    expected = raw_hint.lower()

    if not expected:
        raise NetworkDiscoveryError(
            "No interface hint was supplied by the incident."
        )

    requested_if_index = None

    if expected.startswith("ifindex:"):
        try:
            requested_if_index = int(raw_hint.split(":", 1)[1].strip())
        except (TypeError, ValueError):
            raise NetworkDiscoveryError(
                f"Invalid ifIndex interface hint: {interface_hint!r}."
            )

    try:
        interface_rows = asyncio.run(
            client.walk(IF_DESCR)
        )
    except Exception as exc:
        raise NetworkDiscoveryError(
            f"Unable to walk IF-MIB::ifDescr: {exc}"
        ) from exc

    interface_matches = []

    for row in interface_rows:
        if not row.suffix:
            continue

        observed_if_index = int(row.suffix[-1])
        observed_name = str(row.value).strip()

        if requested_if_index is not None:
            matched = observed_if_index == requested_if_index
        else:
            matched = observed_name.lower() == expected

        if matched:
            interface_matches.append(
                (
                    observed_if_index,
                    observed_name,
                )
            )

    if not interface_matches:
        raise NetworkDiscoveryError(
            f"Interface {interface_hint!r} was not found through SNMP."
        )

    if len(interface_matches) != 1:
        raise NetworkDiscoveryError(
            f"Interface {interface_hint!r} is ambiguous through SNMP."
        )

    if_index, interface_name = interface_matches[0]

    try:
        bridge_rows = asyncio.run(
            client.walk(DOT1D_BASE_PORT_IF_INDEX)
        )
    except Exception as exc:
        raise NetworkDiscoveryError(
            f"Unable to walk BRIDGE-MIB::dot1dBasePortIfIndex: {exc}"
        ) from exc

    bridge_matches = []

    for row in bridge_rows:
        try:
            observed_if_index = int(row.value)
        except (TypeError, ValueError):
            continue

        if observed_if_index == if_index and row.suffix:
            bridge_matches.append(int(row.suffix[-1]))

    if not bridge_matches:
        raise NetworkDiscoveryError(
            f"No bridge port maps to ifIndex {if_index}."
        )

    if len(bridge_matches) != 1:
        raise NetworkDiscoveryError(
            f"Several bridge ports map to ifIndex {if_index}."
        )

    return PortDiscovery(
        bridge_port=bridge_matches[0],
        if_index=if_index,
        interface_name=interface_name,
    )

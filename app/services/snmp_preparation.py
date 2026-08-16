from __future__ import annotations

import asyncio
from dataclasses import dataclass
from time import perf_counter
from typing import Callable

from flask import current_app

from app.extensions import db
from app.models import Incident, NetworkHost, NetworkSwitch, SwitchPort
from app.snmp.capabilities import CapabilityError, require_lab_validated_write
from app.snmp.client import SnmpReadClient, SnmpV3Config
from app.snmp.mib_catalog import DOT1D_BASE_PORT_IF_INDEX, DOT1Q_PVID, IF_ADMIN_STATUS, IF_DESCR
from app.snmp.mib_registry import MibRegistry
from app.snmp.target_resolver import (
    AmbiguousTargetError,
    KnownPortHint,
    SnmpTargetResolver,
    TargetNotFoundError,
    TargetResolution,
    TargetResolutionError,
    normalize_mac,
)

from .audit import record_audit
from .remediation import RemediationError, evaluate_incident
from .rules import PlaybookRepository


class SnmpPreparationBlocked(RemediationError):
    pass


@dataclass(frozen=True)
class PreparationTiming:
    identification_seconds: float
    prechecks_seconds: float
    total_pre_approval_seconds: float


@dataclass(frozen=True)
class PreparedRemediation:
    resolution: TargetResolution | "PortTargetResolution"
    decision_state: str
    timing: PreparationTiming


@dataclass(frozen=True)
class PortTargetResolution:
    bridge_port: int
    if_index: int
    interface_name: str
    previous_if_admin_status: str
    previous_pvid: int | None
    target_mac: str | None = None


def prepare_port_incident_with_snmp(
    incident: Incident,
    *,
    switch_id: str,
    bridge_port: int,
    interface_hint: str | None = None,
    target_mac: str | None = None,
    target_ip: str | None = None,
    client: SnmpReadClient | None = None,
    snmp_config: SnmpV3Config | None = None,
) -> PreparedRemediation:
    """Confirm a port-centric target without requiring a MAC address."""
    started = perf_counter()
    network_switch = db.session.get(NetworkSwitch, switch_id)
    if network_switch is None:
        raise SnmpPreparationBlocked("Switch not found in inventory.")
    playbook = PlaybookRepository(current_app.config["PLAYBOOKS_DIR"]).get(incident.incident_type)
    if playbook.action not in {"SHUTDOWN_PORT", "REACTIVATE_PORT", "QUARANTINE_VLAN"}:
        raise SnmpPreparationBlocked("This playbook has no disruptive port action.")
    registry: MibRegistry = current_app.extensions["snmp_mib_registry"]
    if not registry.status.ready:
        _block_preparation(incident, event_type="MIB_NOT_READY", message="Required MIBs are not ready.", details={"error": registry.status.error})
    effective_config = snmp_config or SnmpV3Config.from_env(host=network_switch.management_ip)
    read_client = client or SnmpReadClient(effective_config, registry)
    identification_started = perf_counter()
    try:
        if_index = int(asyncio.run(read_client.read_scalar(DOT1D_BASE_PORT_IF_INDEX.with_indices(bridge_port))))
        interface_name = str(asyncio.run(read_client.read_scalar(IF_DESCR.with_indices(if_index))))
        if interface_hint and interface_hint.strip().lower() != interface_name.strip().lower():
            _block_preparation(incident, event_type="TARGET_MISMATCH", message="Zabbix interface hint does not match SNMP.", details={"hint": interface_hint, "observed": interface_name})
        previous_port_status = str(asyncio.run(read_client.read_scalar(IF_ADMIN_STATUS.with_indices(if_index))))
        previous_pvid = None
        if playbook.action == "QUARANTINE_VLAN":
            previous_pvid = int(asyncio.run(read_client.read_scalar(DOT1Q_PVID.with_indices(bridge_port))))
    except (ValueError, RuntimeError) as exc:
        _block_preparation(incident, event_type="TARGET_IDENTIFICATION_FAILED", message="Port target confirmation failed.", details={"error": str(exc)})
    identification_seconds = perf_counter() - identification_started
    prechecks_started = perf_counter()
    decision = evaluate_incident(
        incident, target_confirmed=True, target_mac_address=target_mac,
        target_ip=target_ip, switch_id=switch_id, port_index=bridge_port,
        port_name=interface_name, previous_vlan_id=previous_pvid,
        previous_port_status=previous_port_status,
    )
    prechecks_seconds = perf_counter() - prechecks_started
    total = perf_counter() - started
    remediation = incident.remediations[-1] if incident.remediations else None
    record_audit(
        incident_id=incident.incident_id, remediation_id=remediation.remediation_id if remediation else None,
        event_type="SNMP_TARGET_PREPARED", message="Port target independently confirmed by SNMP read-only checks.",
        equipment_name=network_switch.name, equipment_ip=network_switch.management_ip,
        port_index=bridge_port, target_ip=target_ip, target_mac=target_mac,
        incident_type=incident.incident_type, action_type=decision.action, result_status=decision.state,
        details={"bridge_port": bridge_port, "if_index": if_index, "interface_name": interface_name,
                 "previous_if_admin_status": previous_port_status, "previous_pvid": previous_pvid,
                 "t_identification_seconds": identification_seconds, "t_prechecks_seconds": prechecks_seconds},
    )
    db.session.commit()
    resolution = PortTargetResolution(
        bridge_port=bridge_port,
        if_index=if_index,
        interface_name=interface_name,
        previous_if_admin_status=previous_port_status,
        previous_pvid=previous_pvid,
        target_mac=target_mac,
    )
    return PreparedRemediation(resolution, decision.state, PreparationTiming(identification_seconds, prechecks_seconds, total))


def prepare_incident_with_snmp(
    incident: Incident,
    *,
    switch_id: str,
    target_mac: str,
    target_ip: str | None = None,
    client: SnmpReadClient | None = None,
    snmp_config: SnmpV3Config | None = None,
    clock: Callable[[], float] = perf_counter,
) -> PreparedRemediation:
    started = clock()
    network_switch = db.session.get(NetworkSwitch, switch_id)
    if network_switch is None:
        raise SnmpPreparationBlocked("Switch not found in inventory.")

    playbook = PlaybookRepository(current_app.config["PLAYBOOKS_DIR"]).get(
        incident.incident_type
    )
    if playbook.action != "QUARANTINE_VLAN":
        raise SnmpPreparationBlocked(
            "PVID preparation is only available for QUARANTINE_VLAN."
        )

    mib_registry: MibRegistry = current_app.extensions["snmp_mib_registry"]
    if not mib_registry.status.ready:
        _block_preparation(
            incident,
            event_type="MIB_NOT_READY",
            message="Required MIBs are not preloaded.",
            details={"error": mib_registry.status.error},
        )

    effective_config = snmp_config or SnmpV3Config.from_env(
        host=network_switch.management_ip
    )
    try:
        require_lab_validated_write(
            current_app.config["SNMP_CAPABILITIES_PATH"],
            model=network_switch.model,
            symbolic_name=DOT1Q_PVID.key,
            auth_protocol=effective_config.auth_protocol,
            priv_protocol=effective_config.priv_protocol,
        )
    except CapabilityError as exc:
        _block_preparation(
            incident,
            event_type="SNMP_CAPABILITY_BLOCKED",
            message="The platform is not qualified for this SET.",
            details={"error": str(exc), "model": network_switch.model},
        )

    normalized_mac = normalize_mac(target_mac)
    known_hint = _known_port_hint(switch_id, normalized_mac)
    read_client = client or SnmpReadClient(effective_config, mib_registry)
    resolver = SnmpTargetResolver(read_client)

    identification_started = clock()
    try:
        resolution = _resolve_with_retry(
            resolver,
            normalized_mac,
            known_port=known_hint,
            max_attempts=2,
        )
    except AmbiguousTargetError as exc:
        _block_preparation(
            incident,
            event_type="TARGET_AMBIGUOUS",
            message="The MAC resolves to incompatible ports/VLANs.",
            details={"error": str(exc), "target_mac": normalized_mac},
        )
    except TargetResolutionError as exc:
        _block_preparation(
            incident,
            event_type="TARGET_IDENTIFICATION_FAILED",
            message="SNMP target identification failed after two attempts.",
            details={"error": str(exc), "target_mac": normalized_mac},
        )
    identification_seconds = clock() - identification_started

    prechecks_started = clock()
    decision = evaluate_incident(
        incident,
        target_confirmed=True,
        target_mac_address=resolution.target_mac,
        target_ip=target_ip,
        switch_id=switch_id,
        port_index=resolution.bridge_port,
        port_name=resolution.interface_name,
        previous_vlan_id=resolution.previous_pvid,
    )
    prechecks_seconds = clock() - prechecks_started
    total_pre_approval_seconds = clock() - started

    remediation = incident.remediations[-1] if incident.remediations else None
    record_audit(
        incident_id=incident.incident_id,
        remediation_id=remediation.remediation_id if remediation else None,
        event_type="SNMP_TARGET_PREPARED",
        message="Target resolved and pre-action state saved before authorization.",
        equipment_name=network_switch.name,
        equipment_ip=network_switch.management_ip,
        port_index=resolution.bridge_port,
        target_ip=target_ip,
        target_mac=resolution.target_mac,
        incident_type=incident.incident_type,
        action_type=decision.action,
        result_status=decision.state,
        details={
            "mib_object": DOT1Q_PVID.key,
            "fdb_vlan_id": resolution.vlan_id,
            "bridge_port": resolution.bridge_port,
            "if_index": resolution.if_index,
            "interface_name": resolution.interface_name,
            "previous_pvid": resolution.previous_pvid,
            "known_port_cache_hit": resolution.cache_hit,
            "t_identification_seconds": identification_seconds,
            "t_prechecks_seconds": prechecks_seconds,
            "t_total_pre_approval_seconds": total_pre_approval_seconds,
        },
    )
    db.session.commit()
    return PreparedRemediation(
        resolution=resolution,
        decision_state=decision.state,
        timing=PreparationTiming(
            identification_seconds=identification_seconds,
            prechecks_seconds=prechecks_seconds,
            total_pre_approval_seconds=total_pre_approval_seconds,
        ),
    )


def _resolve_with_retry(
    resolver: SnmpTargetResolver,
    target_mac: str,
    *,
    known_port: KnownPortHint | None,
    max_attempts: int,
) -> TargetResolution:
    last_error: TargetResolutionError | None = None
    for _attempt in range(max_attempts):
        try:
            return asyncio.run(
                resolver.resolve(target_mac, known_port=known_port)
            )
        except TargetNotFoundError as exc:
            last_error = exc
    assert last_error is not None
    raise last_error


def _known_port_hint(switch_id: str, mac_address: str) -> KnownPortHint | None:
    host = db.session.get(NetworkHost, mac_address)
    if host is None or host.switch_id != switch_id or host.port_index is None:
        return None
    port = db.session.get(SwitchPort, (switch_id, host.port_index))
    if port is None:
        return None
    return KnownPortHint(
        bridge_port=port.port_index,
        vlan_id=port.vlan_id,
        interface_name=port.port_name,
    )


def _block_preparation(
    incident: Incident,
    *,
    event_type: str,
    message: str,
    details: dict[str, object],
) -> None:
    incident.processing_status = "ESCALATED"
    record_audit(
        incident_id=incident.incident_id,
        event_type=event_type,
        message=message,
        equipment_ip=incident.source_ip,
        incident_type=incident.incident_type,
        action_type="QUARANTINE_VLAN",
        result_status="ESCALATED",
        details=details,
    )
    db.session.commit()
    raise SnmpPreparationBlocked(message)

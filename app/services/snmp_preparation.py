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
from app.snmp.mib_catalog import DOT1Q_PVID
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
    resolution: TargetResolution
    decision_state: str
    timing: PreparationTiming


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
        raise SnmpPreparationBlocked("Commutateur introuvable dans l'inventaire.")

    playbook = PlaybookRepository(current_app.config["PLAYBOOKS_DIR"]).get(
        incident.incident_type
    )
    if playbook.action != "QUARANTINE_VLAN":
        raise SnmpPreparationBlocked(
            "La preparation SNMP PVID est reservee a QUARANTINE_VLAN."
        )

    mib_registry: MibRegistry = current_app.extensions["snmp_mib_registry"]
    if not mib_registry.status.ready:
        _block_preparation(
            incident,
            event_type="MIB_NOT_READY",
            message="Les MIB obligatoires ne sont pas prechargees.",
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
            message="La plateforme n'est pas qualifiee pour ce SET.",
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
            message="La MAC correspond a plusieurs ports/VLAN incompatibles.",
            details={"error": str(exc), "target_mac": normalized_mac},
        )
    except TargetResolutionError as exc:
        _block_preparation(
            incident,
            event_type="TARGET_IDENTIFICATION_FAILED",
            message="Identification SNMP de la cible impossible apres deux essais.",
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
        message="Cible resolue et etat pre-action sauvegarde avant approbation.",
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

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from time import perf_counter
from typing import Callable

from flask import current_app

from app.extensions import db
from app.models import AuditLog, Incident, NetworkSwitch, Remediation, SwitchPort
from app.snmp.capabilities import CapabilityError, require_lab_validated_write
from app.snmp.client import (
    SnmpClientError,
    SnmpRemediationClient,
    SnmpV3Config,
)
from app.snmp.mib_catalog import DOT1Q_PVID
from app.snmp.mib_registry import MibRegistry

from .audit import record_audit
from .remediation import RemediationError, UnsafeOperationBlocked
from .whitelist import is_port_protected


class RemediationVerificationError(RemediationError):
    pass


@dataclass(frozen=True)
class ExecutionTiming:
    identification_seconds: float
    prechecks_seconds: float
    snmp_set_seconds: float
    verification_seconds: float
    total_automated_seconds: float


@dataclass(frozen=True)
class SnmpExecutionResult:
    remediation_id: str
    requested_vlan: int
    observed_vlan: int
    timing: ExecutionTiming


def execute_quarantine_vlan(
    incident: Incident,
    *,
    client: SnmpRemediationClient | None = None,
    snmp_config: SnmpV3Config | None = None,
    clock: Callable[[], float] = perf_counter,
) -> SnmpExecutionResult:
    if incident.processing_status != "ADMIN_APPROVED":
        raise RemediationError(
            "Une approbation humaine explicite est obligatoire avant le SET."
        )
    remediation = _targeted_remediation(incident)
    if remediation.action_type != "QUARANTINE_VLAN":
        _block_execution(incident, remediation, "action_not_lab_validated")

    network_switch = db.session.get(NetworkSwitch, remediation.switch_id)
    if network_switch is None:
        _block_execution(incident, remediation, "switch_not_found")
    if remediation.previous_vlan_id is None:
        _block_execution(incident, remediation, "previous_pvid_missing")
    if not current_app.config["SNMP_WRITE_ENABLED"]:
        _block_execution(incident, remediation, "SNMP_WRITE_ENABLED=false")
    if not _has_snmp_preparation(incident.incident_id):
        _block_execution(incident, remediation, "snmp_preparation_missing")

    mib_registry: MibRegistry = current_app.extensions["snmp_mib_registry"]
    if not mib_registry.status.ready:
        _block_execution(
            incident, remediation, f"mib_not_ready:{mib_registry.status.error}"
        )
    if not (
        current_app.config["QUARANTINE_VLAN_EXISTS"]
        and current_app.config["QUARANTINE_VLAN_ISOLATED"]
    ):
        _block_execution(incident, remediation, "quarantine_vlan_not_isolated")
    if is_port_protected(
        current_app.config["WHITELIST_PATH"],
        switch_id=remediation.switch_id,
        port_index=remediation.port_index,
    ):
        _block_execution(incident, remediation, "port_became_whitelisted")

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
        _block_execution(incident, remediation, f"capability_blocked:{exc}")

    write_client = client or SnmpRemediationClient(
        effective_config, mib_registry
    )
    requested_vlan = int(current_app.config["QUARANTINE_VLAN_ID"])
    pvid_ref = DOT1Q_PVID.with_indices(remediation.port_index)

    pre_timing = _preapproval_timing(incident.incident_id)
    revalidation_started = clock()
    try:
        observed_before = int(asyncio.run(write_client.read_scalar(pvid_ref)))
    except (SnmpClientError, ValueError) as exc:
        _fail_execution(
            incident, remediation, "PRE_ACTION_READ_FAILED", str(exc)
        )
    revalidation_seconds = clock() - revalidation_started
    if observed_before != remediation.previous_vlan_id:
        _fail_execution(
            incident,
            remediation,
            "PRE_ACTION_STATE_CHANGED",
            f"PVID attendu {remediation.previous_vlan_id}, observe {observed_before}",
        )

    set_started = clock()
    try:
        asyncio.run(
            write_client.set_integer(
                pvid_ref, requested_vlan, write_authorized=True
            )
        )
    except SnmpClientError as exc:
        _fail_execution(incident, remediation, "SNMP_SET_FAILED", str(exc))
    snmp_set_seconds = clock() - set_started

    verification_started = clock()
    try:
        observed_vlan = int(asyncio.run(write_client.read_scalar(pvid_ref)))
    except (SnmpClientError, ValueError) as exc:
        _fail_execution(incident, remediation, "POST_ACTION_GET_FAILED", str(exc))
    verification_seconds = clock() - verification_started

    total_automated_seconds = (
        pre_timing["identification"]
        + pre_timing["prechecks"]
        + revalidation_seconds
        + snmp_set_seconds
        + verification_seconds
    )
    timing = ExecutionTiming(
        identification_seconds=pre_timing["identification"],
        prechecks_seconds=pre_timing["prechecks"] + revalidation_seconds,
        snmp_set_seconds=snmp_set_seconds,
        verification_seconds=verification_seconds,
        total_automated_seconds=total_automated_seconds,
    )

    if observed_vlan != requested_vlan:
        _verification_failed(
            incident,
            remediation,
            requested_vlan=requested_vlan,
            observed_vlan=observed_vlan,
            timing=timing,
        )

    remediation.status = "SUCCEEDED"
    remediation.end_time = datetime.now(timezone.utc)
    incident.processing_status = "REMEDIATED"
    switch_port = db.session.get(
        SwitchPort, (remediation.switch_id, remediation.port_index)
    )
    if switch_port:
        switch_port.vlan_id = observed_vlan
    record_audit(
        incident_id=incident.incident_id,
        remediation_id=remediation.remediation_id,
        event_type="SNMP_REMEDIATION_SUCCEEDED",
        message="SET dot1qPvid confirme par GET post-action.",
        equipment_name=network_switch.name,
        equipment_ip=network_switch.management_ip,
        port_index=remediation.port_index,
        target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type,
        action_type=remediation.action_type,
        result_status="SUCCEEDED",
        details={
            "mib_object": DOT1Q_PVID.key,
            "requested_vlan": requested_vlan,
            "observed_vlan": observed_vlan,
            "t_identification_seconds": timing.identification_seconds,
            "t_prechecks_seconds": timing.prechecks_seconds,
            "t_snmp_set_seconds": timing.snmp_set_seconds,
            "t_verification_seconds": timing.verification_seconds,
            "t_total_automated_seconds": timing.total_automated_seconds,
            "human_wait_excluded": True,
        },
    )
    db.session.commit()
    return SnmpExecutionResult(
        remediation_id=remediation.remediation_id,
        requested_vlan=requested_vlan,
        observed_vlan=observed_vlan,
        timing=timing,
    )


def rollback_quarantine_vlan(
    incident: Incident,
    *,
    administrator_id: str,
    client: SnmpRemediationClient | None = None,
    snmp_config: SnmpV3Config | None = None,
) -> int:
    if not administrator_id.strip():
        raise RemediationError("Une demande explicite d'administrateur est requise.")
    remediation = _targeted_remediation(incident)
    if remediation.status != "SUCCEEDED" or remediation.previous_vlan_id is None:
        raise RemediationError(
            "Le rollback exige une remediation reussie et un previous_pvid sauvegarde."
        )
    network_switch = db.session.get(NetworkSwitch, remediation.switch_id)
    if network_switch is None:
        _block_execution(incident, remediation, "switch_not_found_for_rollback")
    if not current_app.config["SNMP_WRITE_ENABLED"]:
        _block_execution(incident, remediation, "SNMP_WRITE_ENABLED=false")

    mib_registry: MibRegistry = current_app.extensions["snmp_mib_registry"]
    if not mib_registry.status.ready:
        _block_execution(
            incident,
            remediation,
            f"rollback_mib_not_ready:{mib_registry.status.error}",
        )
    if is_port_protected(
        current_app.config["WHITELIST_PATH"],
        switch_id=remediation.switch_id,
        port_index=remediation.port_index,
    ):
        _block_execution(incident, remediation, "rollback_port_whitelisted")
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
        _block_execution(incident, remediation, f"rollback_capability_blocked:{exc}")

    write_client = client or SnmpRemediationClient(
        effective_config, mib_registry
    )
    pvid_ref = DOT1Q_PVID.with_indices(remediation.port_index)
    previous_pvid = remediation.previous_vlan_id
    try:
        asyncio.run(
            write_client.set_integer(
                pvid_ref, previous_pvid, write_authorized=True
            )
        )
    except SnmpClientError as exc:
        _fail_execution(
            incident, remediation, "ROLLBACK_SNMP_SET_FAILED", str(exc)
        )
    try:
        observed = int(asyncio.run(write_client.read_scalar(pvid_ref)))
    except (SnmpClientError, ValueError) as exc:
        _fail_execution(
            incident, remediation, "ROLLBACK_POST_ACTION_GET_FAILED", str(exc)
        )
    if observed != previous_pvid:
        _fail_execution(
            incident,
            remediation,
            "ROLLBACK_VERIFICATION_FAILED",
            f"PVID attendu {previous_pvid}, observe {observed}",
        )

    remediation.status = "ROLLED_BACK"
    remediation.end_time = datetime.now(timezone.utc)
    incident.processing_status = "ROLLED_BACK"
    switch_port = db.session.get(
        SwitchPort, (remediation.switch_id, remediation.port_index)
    )
    if switch_port:
        switch_port.vlan_id = observed
    record_audit(
        incident_id=incident.incident_id,
        remediation_id=remediation.remediation_id,
        event_type="SNMP_ROLLBACK_SUCCEEDED",
        message="Rollback explicite confirme par GET vers previous_pvid.",
        equipment_name=network_switch.name,
        equipment_ip=network_switch.management_ip,
        port_index=remediation.port_index,
        target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type,
        action_type=remediation.action_type,
        result_status="ROLLED_BACK",
        details={
            "administrator_id": administrator_id,
            "previous_pvid": previous_pvid,
            "observed_pvid": observed,
        },
    )
    db.session.commit()
    return observed


def _targeted_remediation(incident: Incident) -> Remediation:
    if not incident.remediations:
        raise RemediationError("Aucune remediation associee a l'incident.")
    remediation = incident.remediations[-1]
    if (
        remediation.target_mac_address is None
        or remediation.switch_id is None
        or remediation.port_index is None
    ):
        raise RemediationError("La remediation n'a pas de cible/port confirme.")
    return remediation


def _preapproval_timing(incident_id: str) -> dict[str, float]:
    statement = (
        db.select(AuditLog)
        .where(
            AuditLog.incident_id == incident_id,
            AuditLog.event_type == "SNMP_TARGET_PREPARED",
        )
        .order_by(AuditLog.event_timestamp.desc())
    )
    entry = db.session.execute(statement).scalars().first()
    if entry is None or " | " not in entry.message:
        return {"identification": 0.0, "prechecks": 0.0}
    try:
        details = json.loads(entry.message.split(" | ", maxsplit=1)[1])
        return {
            "identification": float(details["t_identification_seconds"]),
            "prechecks": float(details["t_prechecks_seconds"]),
        }
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return {"identification": 0.0, "prechecks": 0.0}


def _has_snmp_preparation(incident_id: str) -> bool:
    statement = db.select(AuditLog.log_id).where(
        AuditLog.incident_id == incident_id,
        AuditLog.event_type == "SNMP_TARGET_PREPARED",
    )
    return db.session.execute(statement).first() is not None


def _block_execution(
    incident: Incident, remediation: Remediation, reason: str
) -> None:
    incident.processing_status = "BLOCKED_SNMP_WRITE"
    remediation.status = "BLOCKED_SNMP_WRITE"
    record_audit(
        incident_id=incident.incident_id,
        remediation_id=remediation.remediation_id,
        event_type="SNMP_WRITE_BLOCKED",
        message="Aucun SET SNMP n'a ete envoye.",
        port_index=remediation.port_index,
        target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type,
        action_type=remediation.action_type,
        result_status="BLOCKED_SNMP_WRITE",
        details={"reason": reason},
    )
    db.session.commit()
    raise UnsafeOperationBlocked(reason)


def _fail_execution(
    incident: Incident,
    remediation: Remediation,
    event_type: str,
    error: str,
) -> None:
    incident.processing_status = "REMEDIATION_FAILED"
    remediation.status = "FAILED"
    remediation.end_time = datetime.now(timezone.utc)
    record_audit(
        incident_id=incident.incident_id,
        remediation_id=remediation.remediation_id,
        event_type=event_type,
        message="La remediation SNMP a echoue.",
        port_index=remediation.port_index,
        target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type,
        action_type=remediation.action_type,
        result_status="FAILED",
        details={"error": error},
    )
    db.session.commit()
    raise RemediationVerificationError(error)


def _verification_failed(
    incident: Incident,
    remediation: Remediation,
    *,
    requested_vlan: int,
    observed_vlan: int,
    timing: ExecutionTiming,
) -> None:
    remediation.status = "VERIFICATION_FAILED"
    remediation.end_time = datetime.now(timezone.utc)
    incident.processing_status = "REMEDIATION_FAILED"
    record_audit(
        incident_id=incident.incident_id,
        remediation_id=remediation.remediation_id,
        event_type="SNMP_POST_ACTION_MISMATCH",
        message="Le SET a repondu mais le GET ne confirme pas le VLAN demande.",
        port_index=remediation.port_index,
        target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type,
        action_type=remediation.action_type,
        result_status="VERIFICATION_FAILED",
        details={
            "requested_vlan": requested_vlan,
            "observed_vlan": observed_vlan,
            "t_snmp_set_seconds": timing.snmp_set_seconds,
            "t_verification_seconds": timing.verification_seconds,
            "t_total_automated_seconds": timing.total_automated_seconds,
        },
    )
    db.session.commit()
    raise RemediationVerificationError(
        f"VLAN demande {requested_vlan}, VLAN observe {observed_vlan}."
    )

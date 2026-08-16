from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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
from app.snmp.mib_catalog import DOT1D_BASE_PORT_IF_INDEX, DOT1Q_PVID, IF_ADMIN_STATUS
from app.snmp.mib_registry import MibRegistry

from .audit import record_audit
from .port_lock import PortBusyError, port_write_lock
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

    @property
    def success(self) -> bool:
        return self.requested_vlan == self.observed_vlan


def execute_snmp_action(
    incident: Incident,
    *,
    client: SnmpRemediationClient | None = None,
    snmp_config: SnmpV3Config | None = None,
):
    remediation = _targeted_remediation(incident)
    if remediation.action_type == "QUARANTINE_VLAN":
        return execute_quarantine_vlan(incident, client=client, snmp_config=snmp_config)
    if remediation.action_type in {"SHUTDOWN_PORT", "REACTIVATE_PORT"}:
        return execute_interface_admin_action(incident, client=client, snmp_config=snmp_config)
    _block_execution(incident, remediation, "action_has_no_write_path", status="BLOCKED_SNMP_CAPABILITY")


def execute_quarantine_vlan(
    incident: Incident,
    *,
    client: SnmpRemediationClient | None = None,
    snmp_config: SnmpV3Config | None = None,
    clock: Callable[[], float] = perf_counter,
) -> SnmpExecutionResult:
    if incident.processing_status not in {"ADMIN_APPROVED", "AUTOMATICALLY_AUTHORIZED"}:
        raise RemediationError(
            "Explicit authorization is required before an SNMP SET."
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

    if current_app.config["DRY_RUN"]:
        return _dry_run_result(incident, remediation, current_app.config["QUARANTINE_VLAN_ID"])
    _enforce_cooldown(incident, remediation)

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
        _block_execution(
            incident, remediation, f"capability_blocked:{exc}",
            status="BLOCKED_SNMP_CAPABILITY",
        )

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
            f"Expected PVID {remediation.previous_vlan_id}, observed {observed_before}",
        )

    try:
        with port_write_lock(current_app.config["PORT_LOCK_DIR"], remediation.switch_id, remediation.port_index):
            _enforce_cooldown(incident, remediation)
            remediation.status = "REMEDIATION_IN_PROGRESS"
            incident.processing_status = "REMEDIATION_IN_PROGRESS"
            db.session.commit()
            try:
                observed_vlan, snmp_set_seconds, verification_seconds = _set_and_verify(
                    write_client, pvid_ref, requested_vlan,
                    incident=incident, remediation=remediation, clock=clock
                )
            except RemediationVerificationError as exc:
                _fail_execution(incident, remediation, "SNMP_SET_OR_GET_FAILED", str(exc))
    except PortBusyError as exc:
        _block_execution(incident, remediation, str(exc), status="COOLDOWN_BLOCKED")

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
            "authorization_mode": remediation.authorization_mode,
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


def execute_interface_admin_action(
    incident: Incident,
    *,
    client: SnmpRemediationClient | None = None,
    snmp_config: SnmpV3Config | None = None,
) -> SnmpExecutionResult:
    if incident.processing_status not in {"ADMIN_APPROVED", "AUTOMATICALLY_AUTHORIZED"}:
        raise RemediationError("Explicit authorization is required before an SNMP SET.")
    remediation = _targeted_remediation(incident)
    expected = 2 if remediation.action_type == "SHUTDOWN_PORT" else 1
    network_switch = db.session.get(NetworkSwitch, remediation.switch_id)
    if network_switch is None:
        _block_execution(incident, remediation, "switch_not_found")
    if not current_app.config["SNMP_WRITE_ENABLED"]:
        _block_execution(incident, remediation, "SNMP_WRITE_ENABLED=false")
    if not _has_snmp_preparation(incident.incident_id):
        _block_execution(incident, remediation, "snmp_preparation_missing")
    if is_port_protected(current_app.config["WHITELIST_PATH"], switch_id=remediation.switch_id, port_index=remediation.port_index):
        _block_execution(incident, remediation, "port_became_whitelisted")
    if current_app.config["DRY_RUN"]:
        return _dry_run_result(incident, remediation, expected)
    _enforce_cooldown(incident, remediation)
    mib_registry: MibRegistry = current_app.extensions["snmp_mib_registry"]
    if not mib_registry.status.ready:
        _block_execution(incident, remediation, "mib_not_ready")
    effective_config = snmp_config or SnmpV3Config.from_env(host=network_switch.management_ip)
    try:
        require_lab_validated_write(
            current_app.config["SNMP_CAPABILITIES_PATH"], model=network_switch.model,
            symbolic_name=IF_ADMIN_STATUS.key, auth_protocol=effective_config.auth_protocol,
            priv_protocol=effective_config.priv_protocol,
        )
    except CapabilityError as exc:
        _block_execution(incident, remediation, f"capability_blocked:{exc}", status="BLOCKED_SNMP_CAPABILITY")
    write_client = client or SnmpRemediationClient(effective_config, mib_registry)
    try:
        if_index = int(asyncio.run(write_client.read_scalar(DOT1D_BASE_PORT_IF_INDEX.with_indices(remediation.port_index))))
        object_ref = IF_ADMIN_STATUS.with_indices(if_index)
        observed_before = int(asyncio.run(write_client.read_scalar(object_ref)))
    except (SnmpClientError, ValueError) as exc:
        _fail_execution(incident, remediation, "PRE_ACTION_READ_FAILED", str(exc))
    if remediation.previous_port_status is None:
        remediation.previous_port_status = str(observed_before)
        db.session.commit()
    try:
        with port_write_lock(current_app.config["PORT_LOCK_DIR"], remediation.switch_id, remediation.port_index):
            _enforce_cooldown(incident, remediation)
            remediation.status = "REMEDIATION_IN_PROGRESS"
            incident.processing_status = "REMEDIATION_IN_PROGRESS"
            db.session.commit()
            try:
                observed, set_seconds, verification_seconds = _set_and_verify(
                    write_client, object_ref, expected,
                    incident=incident, remediation=remediation,
                )
            except RemediationVerificationError as exc:
                _fail_execution(incident, remediation, "SNMP_SET_OR_GET_FAILED", str(exc))
    except PortBusyError as exc:
        _block_execution(incident, remediation, str(exc), status="COOLDOWN_BLOCKED")
    timing = ExecutionTiming(0.0, 0.0, set_seconds, verification_seconds, set_seconds + verification_seconds)
    if observed != expected:
        _fail_execution(incident, remediation, "SNMP_POST_ACTION_MISMATCH", f"Expected {expected}, observed {observed}")
    remediation.status = "SUCCEEDED"
    remediation.end_time = datetime.now(timezone.utc)
    incident.processing_status = "REMEDIATED"
    if remediation.switch_port:
        remediation.switch_port.status = "down" if observed == 2 else "up"
    record_audit(
        incident_id=incident.incident_id, remediation_id=remediation.remediation_id,
        event_type="SNMP_REMEDIATION_SUCCEEDED", message="ifAdminStatus SET confirmed by post-action GET.",
        equipment_name=network_switch.name, equipment_ip=network_switch.management_ip,
        port_index=remediation.port_index, target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type, action_type=remediation.action_type,
        result_status="SUCCEEDED", details={"mib_object": IF_ADMIN_STATUS.key, "if_index": if_index,
        "requested_value": expected, "observed_value": observed, "authorization_mode": remediation.authorization_mode,
        "t_snmp_set_seconds": set_seconds, "t_verification_seconds": verification_seconds},
    )
    db.session.commit()
    return SnmpExecutionResult(remediation.remediation_id, expected, observed, timing)


def rollback_quarantine_vlan(
    incident: Incident,
    *,
    administrator_id: str,
    client: SnmpRemediationClient | None = None,
    snmp_config: SnmpV3Config | None = None,
) -> int:
    if not administrator_id.strip():
        raise RemediationError("An explicit administrator request is required.")
    remediation = _targeted_remediation(incident)
    if remediation.status != "SUCCEEDED" or remediation.previous_vlan_id is None:
        raise RemediationError(
            "Rollback requires a successful remediation and a saved previous PVID."
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
    remediation.status = "ROLLBACK_IN_PROGRESS"
    incident.processing_status = "ROLLBACK_IN_PROGRESS"
    record_audit(
        incident_id=incident.incident_id, remediation_id=remediation.remediation_id,
        administrator_id=administrator_id, event_type="ROLLBACK_REQUESTED",
        message="Administrator requested explicit rollback.", action_type=remediation.action_type,
        result_status="ROLLBACK_IN_PROGRESS",
    )
    db.session.commit()
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
            f"Expected PVID {previous_pvid}, observed {observed}",
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
        administrator_id=administrator_id,
        event_type="SNMP_ROLLBACK_SUCCEEDED",
        message="Explicit rollback confirmed by GET against previous PVID.",
        equipment_name=network_switch.name,
        equipment_ip=network_switch.management_ip,
        port_index=remediation.port_index,
        target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type,
        action_type=remediation.action_type,
        result_status="ROLLED_BACK",
        details={
            "previous_pvid": previous_pvid,
            "observed_pvid": observed,
        },
    )
    db.session.commit()
    return observed


def rollback_snmp_action(
    incident: Incident,
    *,
    administrator_id: str,
    client: SnmpRemediationClient | None = None,
    snmp_config: SnmpV3Config | None = None,
) -> int:
    remediation = _targeted_remediation(incident)
    if remediation.action_type == "QUARANTINE_VLAN":
        return rollback_quarantine_vlan(incident, administrator_id=administrator_id, client=client, snmp_config=snmp_config)
    if remediation.action_type in {"SHUTDOWN_PORT", "REACTIVATE_PORT"}:
        return rollback_interface_admin_action(incident, administrator_id=administrator_id, client=client, snmp_config=snmp_config)
    raise RemediationError("Rollback is unavailable for this action.")


def rollback_interface_admin_action(
    incident: Incident,
    *,
    administrator_id: str,
    client: SnmpRemediationClient | None = None,
    snmp_config: SnmpV3Config | None = None,
) -> int:
    if not administrator_id.strip():
        raise RemediationError("An explicit administrator request is required.")
    remediation = _targeted_remediation(incident)
    if remediation.status != "SUCCEEDED" or remediation.previous_port_status is None:
        raise RemediationError("Rollback requires a successful remediation and an administrative-state snapshot.")
    previous = _admin_status_value(remediation.previous_port_status)
    network_switch = db.session.get(NetworkSwitch, remediation.switch_id)
    if network_switch is None or not current_app.config["SNMP_WRITE_ENABLED"]:
        _block_execution(incident, remediation, "rollback_preconditions_failed")
    registry: MibRegistry = current_app.extensions["snmp_mib_registry"]
    effective_config = snmp_config or SnmpV3Config.from_env(host=network_switch.management_ip)
    try:
        require_lab_validated_write(current_app.config["SNMP_CAPABILITIES_PATH"], model=network_switch.model,
                                    symbolic_name=IF_ADMIN_STATUS.key, auth_protocol=effective_config.auth_protocol,
                                    priv_protocol=effective_config.priv_protocol)
    except CapabilityError as exc:
        _block_execution(incident, remediation, f"rollback_capability_blocked:{exc}", status="BLOCKED_SNMP_CAPABILITY")
    if is_port_protected(current_app.config["WHITELIST_PATH"], switch_id=remediation.switch_id, port_index=remediation.port_index):
        _block_execution(incident, remediation, "rollback_port_whitelisted")
    write_client = client or SnmpRemediationClient(effective_config, registry)
    remediation.status = "ROLLBACK_IN_PROGRESS"
    incident.processing_status = "ROLLBACK_IN_PROGRESS"
    record_audit(incident_id=incident.incident_id, remediation_id=remediation.remediation_id,
                 administrator_id=administrator_id, event_type="ROLLBACK_REQUESTED",
                 message="Administrator requested explicit port-state rollback.", result_status="ROLLBACK_IN_PROGRESS")
    db.session.commit()
    try:
        if_index = int(asyncio.run(write_client.read_scalar(DOT1D_BASE_PORT_IF_INDEX.with_indices(remediation.port_index))))
        object_ref = IF_ADMIN_STATUS.with_indices(if_index)
        asyncio.run(write_client.set_integer(object_ref, previous, write_authorized=True))
        observed = int(asyncio.run(write_client.read_scalar(object_ref)))
    except (SnmpClientError, ValueError) as exc:
        _fail_rollback(incident, remediation, str(exc), administrator_id)
    if observed != previous:
        _fail_rollback(incident, remediation, f"Expected {previous}, observed {observed}", administrator_id)
    remediation.status = "ROLLED_BACK"
    remediation.end_time = datetime.now(timezone.utc)
    incident.processing_status = "ROLLED_BACK"
    if remediation.switch_port:
        remediation.switch_port.status = "up" if observed == 1 else "down"
    record_audit(incident_id=incident.incident_id, remediation_id=remediation.remediation_id,
                 administrator_id=administrator_id, event_type="SNMP_ROLLBACK_SUCCEEDED",
                 message="Previous ifAdminStatus restored and verified.", action_type=remediation.action_type,
                 result_status="ROLLED_BACK", details={"if_index": if_index, "observed": observed})
    db.session.commit()
    return observed


def _targeted_remediation(incident: Incident) -> Remediation:
    if not incident.remediations:
        raise RemediationError("No remediation is associated with this incident.")
    remediation = incident.remediations[-1]
    if remediation.switch_id is None or remediation.port_index is None:
        raise RemediationError("The remediation has no confirmed switch/port target.")
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
    incident: Incident,
    remediation: Remediation,
    reason: str,
    *,
    status: str = "BLOCKED_SNMP_WRITE",
) -> None:
    incident.processing_status = status
    remediation.status = status
    record_audit(
        incident_id=incident.incident_id,
        remediation_id=remediation.remediation_id,
        event_type="SNMP_WRITE_BLOCKED",
        message="Aucun SET SNMP n'a ete envoye.",
        port_index=remediation.port_index,
        target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type,
        action_type=remediation.action_type,
        result_status=status,
        details={"reason": reason},
    )
    db.session.commit()
    raise UnsafeOperationBlocked(reason)


def _set_and_verify(
    client: SnmpRemediationClient,
    object_ref,
    requested: int,
    *,
    incident: Incident,
    remediation: Remediation,
    clock: Callable[[], float] = perf_counter,
) -> tuple[int, float, float]:
    """Perform at most two SET/GET attempts and trust only the GET result."""
    set_seconds = 0.0
    verification_seconds = 0.0
    observed = -1
    last_error: Exception | None = None
    attempts = max(1, min(int(current_app.config["REMEDIATION_MAX_ATTEMPTS"]), 2))
    for attempt in range(1, attempts + 1):
        started = clock()
        try:
            asyncio.run(client.set_integer(object_ref, requested, write_authorized=True))
        except SnmpClientError as exc:
            last_error = exc
            set_seconds += clock() - started
            continue
        set_seconds += clock() - started
        started = clock()
        try:
            observed = int(asyncio.run(client.read_scalar(object_ref)))
        except (SnmpClientError, ValueError) as exc:
            last_error = exc
            verification_seconds += clock() - started
            continue
        verification_seconds += clock() - started
        record_audit(
            incident_id=incident.incident_id,
            remediation_id=remediation.remediation_id,
            event_type="SNMP_WRITE_ATTEMPT",
            message="SNMP SET attempt followed by verification GET.",
            port_index=remediation.port_index,
            incident_type=incident.incident_type,
            action_type=remediation.action_type,
            result_status="SUCCESS" if observed == requested else "RETRY",
            details={"attempt": attempt, "maximum": attempts},
        )
        if observed == requested:
            return observed, set_seconds, verification_seconds
    if observed < 0 and last_error is not None:
        raise RemediationVerificationError(str(last_error))
    return observed, set_seconds, verification_seconds


def _enforce_cooldown(incident: Incident, remediation: Remediation) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=current_app.config["REMEDIATION_COOLDOWN_SECONDS"])
    recent = db.session.execute(
        db.select(Remediation).where(
            Remediation.remediation_id != remediation.remediation_id,
            Remediation.switch_id == remediation.switch_id,
            Remediation.port_index == remediation.port_index,
            Remediation.status.in_(["SUCCEEDED", "REMEDIATED"]),
            Remediation.end_time.is_not(None),
            Remediation.end_time >= cutoff,
        )
    ).scalars().first()
    if recent is not None:
        _block_execution(incident, remediation, "remediation_cooldown_active", status="COOLDOWN_BLOCKED")


def _dry_run_result(incident: Incident, remediation: Remediation, requested: int) -> SnmpExecutionResult:
    incident.processing_status = "CLOSED"
    remediation.status = "DRY_RUN"
    remediation.end_time = datetime.now(timezone.utc)
    timing = ExecutionTiming(0.0, 0.0, 0.0, 0.0, 0.0)
    record_audit(
        incident_id=incident.incident_id, remediation_id=remediation.remediation_id,
        event_type="DRY_RUN", message="Dry-run completed; no SNMP SET was sent.",
        port_index=remediation.port_index, target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type, action_type=remediation.action_type,
        result_status="DRY_RUN", details={"requested_value": int(requested), "authorization_mode": remediation.authorization_mode},
    )
    db.session.commit()
    return SnmpExecutionResult(remediation.remediation_id, int(requested), int(requested), timing)


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
        message="SNMP remediation failed.",
        port_index=remediation.port_index,
        target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type,
        action_type=remediation.action_type,
        result_status="FAILED",
        details={"error": error},
    )
    db.session.commit()
    raise RemediationVerificationError(error)


def _fail_rollback(
    incident: Incident,
    remediation: Remediation,
    error: str,
    administrator_id: str,
) -> None:
    incident.processing_status = "ROLLBACK_FAILED"
    remediation.status = "ROLLBACK_FAILED"
    remediation.end_time = datetime.now(timezone.utc)
    record_audit(
        incident_id=incident.incident_id, remediation_id=remediation.remediation_id,
        administrator_id=administrator_id, event_type="ROLLBACK_FAILED",
        message="Rollback failed; the previous state was not confirmed.",
        action_type=remediation.action_type, result_status="ROLLBACK_FAILED",
        details={"error": error},
    )
    db.session.commit()
    raise RemediationVerificationError(error)


def _admin_status_value(value: str) -> int:
    normalized = value.strip().lower()
    if normalized in {"1", "up", "up(1)"}:
        return 1
    if normalized in {"2", "down", "down(2)"}:
        return 2
    raise RemediationError("The saved administrative state is not a safe rollback value.")


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
        message="The SET returned but the GET did not confirm the requested VLAN.",
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
        f"Requested VLAN {requested_vlan}, observed VLAN {observed_vlan}."
    )

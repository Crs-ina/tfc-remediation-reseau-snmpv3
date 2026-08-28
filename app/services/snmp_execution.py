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
from app.snmp.value_formatting import (
    format_action_value,
    format_if_admin_status,
    parse_safe_if_admin_status,
)

from .audit import record_audit
from .administrators import IdentityError, require_administrator
from .port_lock import PortBusyError, port_write_lock
from .remediation import RemediationError, UnsafeOperationBlocked
from .remediation_config import RemediationConfigError, load_quarantine_vlan_id
from .runtime_settings import is_dry_run_enabled
from .whitelist import is_port_protected


class RemediationVerificationError(RemediationError):
    pass


class RollbackStateChangedError(RemediationError):
    """The target no longer matches the state applied by OKAPI."""


ROLLBACKABLE_ACTIONS = frozenset(
    {"QUARANTINE_VLAN", "SHUTDOWN_PORT", "REACTIVATE_PORT"}
)
ROLLBACK_BLOCKING_STATUSES = frozenset(
    {
        "SUCCEEDED",
        "ROLLBACK_IN_PROGRESS",
        "ROLLBACK_FAILED",
        "ROLLBACK_BLOCKED",
        "BLOCKED_SNMP_WRITE",
        "BLOCKED_SNMP_CAPABILITY",
        "COOLDOWN_BLOCKED",
    }
)


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
    simulated: bool = False

    @property
    def success(self) -> bool:
        return not self.simulated and self.requested_vlan == self.observed_vlan


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
    administrator_id = _required_execution_administrator_id(remediation)
    if remediation.action_type != "QUARANTINE_VLAN":
        _block_execution(incident, remediation, "action_not_lab_validated")

    network_switch = db.session.get(NetworkSwitch, remediation.switch_id)
    if network_switch is None:
        _block_execution(incident, remediation, "switch_not_found")
    if remediation.previous_vlan_id is None:
        _block_execution(incident, remediation, "previous_pvid_missing")
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

    try:
        requested_vlan = load_quarantine_vlan_id(
            current_app.config["REMEDIATION_CONFIG_PATH"]
        )
    except RemediationConfigError as exc:
        _block_execution(
            incident,
            remediation,
            f"remediation_config_invalid:{exc}",
            status="BLOCKED_SNMP_WRITE",
        )

    if is_dry_run_enabled():
        return _dry_run_result(incident, remediation, requested_vlan)
    if not current_app.config["SNMP_WRITE_ENABLED"]:
        _block_execution(incident, remediation, "SNMP_WRITE_ENABLED=false")
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
        effective_config,
        mib_registry,
        dry_run=is_dry_run_enabled(),
    )
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
    remediation.applied_vlan_id = observed_vlan
    remediation.applied_port_status = None
    incident.processing_status = "REMEDIATED"
    switch_port = db.session.get(
        SwitchPort, (remediation.switch_id, remediation.port_index)
    )
    if switch_port:
        switch_port.vlan_id = observed_vlan
    record_audit(
        incident_id=incident.incident_id,
        remediation_id=remediation.remediation_id,
        administrator_id=administrator_id,
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
    clock: Callable[[], float] = perf_counter,
) -> SnmpExecutionResult:
    if incident.processing_status not in {"ADMIN_APPROVED", "AUTOMATICALLY_AUTHORIZED"}:
        raise RemediationError("Explicit authorization is required before an SNMP SET.")
    remediation = _targeted_remediation(incident)
    administrator_id = _required_execution_administrator_id(remediation)
    expected = 2 if remediation.action_type == "SHUTDOWN_PORT" else 1
    network_switch = db.session.get(NetworkSwitch, remediation.switch_id)
    if network_switch is None:
        _block_execution(incident, remediation, "switch_not_found")
    if not _has_snmp_preparation(incident.incident_id):
        _block_execution(incident, remediation, "snmp_preparation_missing")
    if remediation.previous_port_status is None:
        _block_execution(incident, remediation, "previous_admin_status_missing")
    if is_port_protected(current_app.config["WHITELIST_PATH"], switch_id=remediation.switch_id, port_index=remediation.port_index):
        _block_execution(incident, remediation, "port_became_whitelisted")
    if is_dry_run_enabled():
        return _dry_run_result(incident, remediation, expected)
    _block_execution(
        incident,
        remediation,
        "IF-MIB::ifAdminStatus write is TO_BE_VALIDATED; only dot1qPvid is LAB_VALIDATED.",
        status="BLOCKED_SNMP_CAPABILITY",
    )
    if not current_app.config["SNMP_WRITE_ENABLED"]:
        _block_execution(incident, remediation, "SNMP_WRITE_ENABLED=false")
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
    write_client = client or SnmpRemediationClient(
        effective_config,
        mib_registry,
        dry_run=is_dry_run_enabled(),
    )
    pre_timing = _preapproval_timing(incident.incident_id)
    revalidation_started = clock()
    try:
        if_index = int(asyncio.run(write_client.read_scalar(DOT1D_BASE_PORT_IF_INDEX.with_indices(remediation.port_index))))
        object_ref = IF_ADMIN_STATUS.with_indices(if_index)
        observed_before = int(asyncio.run(write_client.read_scalar(object_ref)))
    except (SnmpClientError, ValueError) as exc:
        _fail_execution(incident, remediation, "PRE_ACTION_READ_FAILED", str(exc))
    revalidation_seconds = clock() - revalidation_started
    saved_previous = _admin_status_value(remediation.previous_port_status)
    if observed_before != saved_previous:
        _fail_execution(
            incident,
            remediation,
            "PRE_ACTION_STATE_CHANGED",
            "Expected ifAdminStatus "
            f"{format_if_admin_status(saved_previous)}, observed "
            f"{format_if_admin_status(observed_before)}",
        )
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
                    clock=clock,
                )
            except RemediationVerificationError as exc:
                _fail_execution(incident, remediation, "SNMP_SET_OR_GET_FAILED", str(exc))
    except PortBusyError as exc:
        _block_execution(incident, remediation, str(exc), status="COOLDOWN_BLOCKED")
    total_automated_seconds = (
        pre_timing["identification"]
        + pre_timing["prechecks"]
        + revalidation_seconds
        + set_seconds
        + verification_seconds
    )
    timing = ExecutionTiming(
        identification_seconds=pre_timing["identification"],
        prechecks_seconds=pre_timing["prechecks"] + revalidation_seconds,
        snmp_set_seconds=set_seconds,
        verification_seconds=verification_seconds,
        total_automated_seconds=total_automated_seconds,
    )
    if observed != expected:
        _fail_execution(
            incident,
            remediation,
            "SNMP_POST_ACTION_MISMATCH",
            f"Expected {format_if_admin_status(expected)}, observed "
            f"{format_if_admin_status(observed)}",
        )
    remediation.status = "SUCCEEDED"
    remediation.end_time = datetime.now(timezone.utc)
    remediation.applied_port_status = _admin_status_label(observed)
    remediation.applied_vlan_id = None
    incident.processing_status = "REMEDIATED"
    if remediation.switch_port:
        remediation.switch_port.status = "down" if observed == 2 else "up"
    record_audit(
        incident_id=incident.incident_id, remediation_id=remediation.remediation_id,
        administrator_id=administrator_id,
        event_type="SNMP_REMEDIATION_SUCCEEDED", message="ifAdminStatus SET confirmed by post-action GET.",
        equipment_name=network_switch.name, equipment_ip=network_switch.management_ip,
        port_index=remediation.port_index, target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type, action_type=remediation.action_type,
        result_status="SUCCEEDED", details={"mib_object": IF_ADMIN_STATUS.key, "if_index": if_index,
        "requested_state": format_if_admin_status(expected),
        "observed_state": format_if_admin_status(observed),
        "authorization_mode": remediation.authorization_mode,
        "t_identification_seconds": timing.identification_seconds,
        "t_prechecks_seconds": timing.prechecks_seconds,
        "t_snmp_set_seconds": timing.snmp_set_seconds,
        "t_verification_seconds": timing.verification_seconds,
        "t_total_automated_seconds": timing.total_automated_seconds,
        "human_wait_excluded": True},
    )
    db.session.commit()
    return SnmpExecutionResult(remediation.remediation_id, expected, observed, timing)


def rollback_quarantine_vlan(
    target: Incident | Remediation,
    *,
    administrator_id: str,
    client: SnmpRemediationClient | None = None,
    snmp_config: SnmpV3Config | None = None,
) -> int:
    try:
        require_administrator(administrator_id)
    except IdentityError as exc:
        raise RemediationError(str(exc)) from exc
    remediation = _targeted_remediation(target)
    incident = remediation.incident
    if (
        remediation.status != "SUCCEEDED"
        or remediation.previous_vlan_id is None
        or remediation.applied_vlan_id is None
    ):
        raise RemediationError(
            "Rollback requires a successful remediation with saved previous and applied VLANs."
        )
    _ensure_latest_rollback_candidate(remediation)
    network_switch = db.session.get(NetworkSwitch, remediation.switch_id)
    if network_switch is None:
        _block_execution(incident, remediation, "switch_not_found_for_rollback")
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
    if is_dry_run_enabled():
        return _dry_run_rollback_result(
            incident,
            remediation,
            remediation.previous_vlan_id,
            administrator_id=administrator_id,
        )
    if not current_app.config["SNMP_WRITE_ENABLED"]:
        _block_execution(incident, remediation, "SNMP_WRITE_ENABLED=false")
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
        effective_config,
        mib_registry,
        dry_run=is_dry_run_enabled(),
    )
    pvid_ref = DOT1Q_PVID.with_indices(remediation.port_index)
    previous_pvid = remediation.previous_vlan_id
    expected_current = remediation.applied_vlan_id
    record_audit(
        incident_id=incident.incident_id, remediation_id=remediation.remediation_id,
        administrator_id=administrator_id, event_type="ROLLBACK_REQUESTED",
        message="Administrator requested explicit rollback.", action_type=remediation.action_type,
        result_status="ROLLBACK_IN_PROGRESS",
        details={
            "expected_current_vlan": expected_current,
            "restore_vlan": previous_pvid,
        },
    )
    db.session.commit()
    try:
        with port_write_lock(
            current_app.config["PORT_LOCK_DIR"],
            remediation.switch_id,
            remediation.port_index,
        ):
            observed_before = int(asyncio.run(write_client.read_scalar(pvid_ref)))
            if observed_before != expected_current:
                _block_rollback_state_changed(
                    incident,
                    remediation,
                    administrator_id=administrator_id,
                    state_name="VLAN",
                    expected=expected_current,
                    observed=observed_before,
                )
            remediation.status = "ROLLBACK_IN_PROGRESS"
            incident.processing_status = "ROLLBACK_IN_PROGRESS"
            db.session.commit()
            _send_integer_set(write_client, pvid_ref, previous_pvid)
            observed = int(asyncio.run(write_client.read_scalar(pvid_ref)))
    except PortBusyError as exc:
        _fail_rollback(incident, remediation, str(exc), administrator_id)
    except RollbackStateChangedError:
        raise
    except (SnmpClientError, ValueError) as exc:
        _fail_rollback(incident, remediation, str(exc), administrator_id)
    if observed != previous_pvid:
        _fail_rollback(
            incident,
            remediation,
            f"Expected PVID {previous_pvid}, observed {observed}",
            administrator_id,
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
            "state_before_rollback": observed_before,
            "restored_vlan": observed,
            "requested_by_administrator_id": administrator_id,
        },
    )
    db.session.commit()
    return observed


def rollback_snmp_action(
    target: Incident | Remediation,
    *,
    administrator_id: str,
    client: SnmpRemediationClient | None = None,
    snmp_config: SnmpV3Config | None = None,
) -> int:
    remediation = _targeted_remediation(target)
    if remediation.action_type == "QUARANTINE_VLAN":
        return rollback_quarantine_vlan(remediation, administrator_id=administrator_id, client=client, snmp_config=snmp_config)
    if remediation.action_type in {"SHUTDOWN_PORT", "REACTIVATE_PORT"}:
        return rollback_interface_admin_action(remediation, administrator_id=administrator_id, client=client, snmp_config=snmp_config)
    raise RemediationError("Rollback is unavailable for this action.")


def rollback_interface_admin_action(
    target: Incident | Remediation,
    *,
    administrator_id: str,
    client: SnmpRemediationClient | None = None,
    snmp_config: SnmpV3Config | None = None,
) -> int:
    try:
        require_administrator(administrator_id)
    except IdentityError as exc:
        raise RemediationError(str(exc)) from exc
    remediation = _targeted_remediation(target)
    incident = remediation.incident
    if (
        remediation.status != "SUCCEEDED"
        or remediation.previous_port_status is None
        or remediation.applied_port_status is None
    ):
        raise RemediationError(
            "Rollback requires a successful remediation with saved previous and applied administrative states."
        )
    _ensure_latest_rollback_candidate(remediation)
    previous = _admin_status_value(remediation.previous_port_status)
    expected_current = _admin_status_value(remediation.applied_port_status)
    network_switch = db.session.get(NetworkSwitch, remediation.switch_id)
    if network_switch is None:
        _block_execution(incident, remediation, "switch_not_found_for_rollback")
    if is_port_protected(current_app.config["WHITELIST_PATH"], switch_id=remediation.switch_id, port_index=remediation.port_index):
        _block_execution(incident, remediation, "rollback_port_whitelisted")
    if is_dry_run_enabled():
        return _dry_run_rollback_result(
            incident,
            remediation,
            previous,
            administrator_id=administrator_id,
        )
    _block_execution(
        incident,
        remediation,
        "IF-MIB::ifAdminStatus rollback is TO_BE_VALIDATED; only dot1qPvid is LAB_VALIDATED.",
        status="BLOCKED_SNMP_CAPABILITY",
    )
    if not current_app.config["SNMP_WRITE_ENABLED"]:
        _block_execution(incident, remediation, "SNMP_WRITE_ENABLED=false")
    registry: MibRegistry = current_app.extensions["snmp_mib_registry"]
    if not registry.status.ready:
        _block_execution(
            incident,
            remediation,
            f"rollback_mib_not_ready:{registry.status.error}",
        )
    effective_config = snmp_config or SnmpV3Config.from_env(host=network_switch.management_ip)
    try:
        require_lab_validated_write(current_app.config["SNMP_CAPABILITIES_PATH"], model=network_switch.model,
                                    symbolic_name=IF_ADMIN_STATUS.key, auth_protocol=effective_config.auth_protocol,
                                    priv_protocol=effective_config.priv_protocol)
    except CapabilityError as exc:
        _block_execution(incident, remediation, f"rollback_capability_blocked:{exc}", status="BLOCKED_SNMP_CAPABILITY")
    write_client = client or SnmpRemediationClient(
        effective_config,
        registry,
        dry_run=is_dry_run_enabled(),
    )
    remediation.status = "ROLLBACK_IN_PROGRESS"
    record_audit(incident_id=incident.incident_id, remediation_id=remediation.remediation_id,
                 administrator_id=administrator_id, event_type="ROLLBACK_REQUESTED",
                 message="Administrator requested explicit port-state rollback.",
                 action_type=remediation.action_type,
                 result_status="ROLLBACK_IN_PROGRESS",
                 details={"expected_current_state": _admin_status_label(expected_current),
                          "restore_state": _admin_status_label(previous)})
    db.session.commit()
    try:
        with port_write_lock(
            current_app.config["PORT_LOCK_DIR"],
            remediation.switch_id,
            remediation.port_index,
        ):
            if_index = int(asyncio.run(write_client.read_scalar(DOT1D_BASE_PORT_IF_INDEX.with_indices(remediation.port_index))))
            object_ref = IF_ADMIN_STATUS.with_indices(if_index)
            observed_before = int(asyncio.run(write_client.read_scalar(object_ref)))
            if observed_before != expected_current:
                _block_rollback_state_changed(
                    incident,
                    remediation,
                    administrator_id=administrator_id,
                    state_name="administrative state",
                    expected=_admin_status_label(expected_current),
                    observed=_admin_status_label(observed_before),
                )
            incident.processing_status = "ROLLBACK_IN_PROGRESS"
            db.session.commit()
            _send_integer_set(write_client, object_ref, previous)
            observed = int(asyncio.run(write_client.read_scalar(object_ref)))
    except PortBusyError as exc:
        _fail_rollback(incident, remediation, str(exc), administrator_id)
    except RollbackStateChangedError:
        raise
    except (SnmpClientError, ValueError) as exc:
        _fail_rollback(incident, remediation, str(exc), administrator_id)
    if observed != previous:
        _fail_rollback(
            incident,
            remediation,
            f"Expected {format_if_admin_status(previous)}, observed "
            f"{format_if_admin_status(observed)}",
            administrator_id,
        )
    remediation.status = "ROLLED_BACK"
    remediation.end_time = datetime.now(timezone.utc)
    incident.processing_status = "ROLLED_BACK"
    if remediation.switch_port:
        remediation.switch_port.status = "up" if observed == 1 else "down"
    record_audit(incident_id=incident.incident_id, remediation_id=remediation.remediation_id,
                 administrator_id=administrator_id, event_type="SNMP_ROLLBACK_SUCCEEDED",
                 message="Previous ifAdminStatus restored and verified.", action_type=remediation.action_type,
                 result_status="ROLLED_BACK",
                 details={"if_index": if_index,
                          "state_before_rollback": _admin_status_label(observed_before),
                          "restored_state": _admin_status_label(observed),
                          "requested_by_administrator_id": administrator_id})
    db.session.commit()
    return observed


def available_rollbacks() -> list[Remediation]:
    """Return only the newest active, restorable change for each target."""

    statement = (
        db.select(Remediation)
        .where(
            Remediation.status.in_(ROLLBACK_BLOCKING_STATUSES),
            (
                Remediation.applied_vlan_id.is_not(None)
                | Remediation.applied_port_status.is_not(None)
            ),
        )
        .order_by(Remediation.start_time.desc(), Remediation.remediation_id.desc())
    )
    candidates: list[Remediation] = []
    seen_targets: set[tuple[str, int]] = set()
    for remediation in db.session.execute(statement).scalars():
        if remediation.switch_id is None or remediation.port_index is None:
            continue
        target_key = (remediation.switch_id, remediation.port_index)
        if target_key in seen_targets:
            continue
        # Even a failed/blocked rollback represents a newer active network
        # change and must prevent an older snapshot from surfacing.
        seen_targets.add(target_key)
        if remediation.status != "SUCCEEDED":
            continue
        if remediation.action_type not in ROLLBACKABLE_ACTIONS:
            continue
        if remediation.switch_port is None:
            continue
        if remediation.action_type == "QUARANTINE_VLAN":
            if (
                remediation.previous_vlan_id is None
                or remediation.applied_vlan_id is None
            ):
                continue
        elif (
            remediation.previous_port_status is None
            or remediation.applied_port_status is None
        ):
            continue
        candidates.append(remediation)
    return candidates


def _ensure_latest_rollback_candidate(remediation: Remediation) -> None:
    latest = db.session.execute(
        db.select(Remediation)
        .where(
            Remediation.switch_id == remediation.switch_id,
            Remediation.port_index == remediation.port_index,
            Remediation.status.in_(ROLLBACK_BLOCKING_STATUSES),
            (
                Remediation.applied_vlan_id.is_not(None)
                | Remediation.applied_port_status.is_not(None)
            ),
        )
        .order_by(Remediation.start_time.desc(), Remediation.remediation_id.desc())
    ).scalars().first()
    if latest is None or latest.remediation_id != remediation.remediation_id:
        raise RemediationError(
            "A newer active remediation on this target must be rolled back first."
        )


def _targeted_remediation(target: Incident | Remediation) -> Remediation:
    if isinstance(target, Remediation):
        remediation = target
        if remediation.switch_id is None or remediation.port_index is None:
            raise RemediationError("The remediation has no confirmed switch/port target.")
        return remediation
    incident = target
    if not incident.remediations:
        raise RemediationError("No remediation is associated with this incident.")
    remediation = incident.remediations[-1]
    if remediation.switch_id is None or remediation.port_index is None:
        raise RemediationError("The remediation has no confirmed switch/port target.")
    return remediation


def _remediation_administrator_id(remediation: Remediation) -> str | None:
    """Return the human approver for SUPERVISED execution; AUTOMATIC stays SYSTEM."""

    if remediation.authorization_mode != "SUPERVISED":
        return None
    return db.session.execute(
        db.select(AuditLog.administrator_id)
        .where(
            AuditLog.remediation_id == remediation.remediation_id,
            AuditLog.event_type == "REMEDIATION_APPROVED",
            AuditLog.administrator_id.is_not(None),
        )
        .order_by(AuditLog.event_timestamp.desc())
    ).scalars().first()


def _required_execution_administrator_id(remediation: Remediation) -> str | None:
    administrator_id = _remediation_administrator_id(remediation)
    if remediation.authorization_mode == "SUPERVISED" and administrator_id is None:
        raise RemediationError(
            "A SUPERVISED remediation requires its authenticated approver identity."
        )
    return administrator_id


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


def _send_integer_set(client: SnmpRemediationClient, object_ref, requested: int) -> str:
    """Single guarded gateway for every SNMP SET in the remediation service."""

    if is_dry_run_enabled():
        raise UnsafeOperationBlocked("DRY_RUN=true blocks every SNMP SET")
    if not current_app.config["SNMP_WRITE_ENABLED"]:
        raise UnsafeOperationBlocked("SNMP_WRITE_ENABLED=false")
    return asyncio.run(
        client.set_integer(object_ref, requested, write_authorized=True)
    )


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
        administrator_id=_remediation_administrator_id(remediation),
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
            _send_integer_set(client, object_ref, requested)
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
            administrator_id=_remediation_administrator_id(remediation),
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
    incident.processing_status = "SIMULATED"
    remediation.status = "DRY_RUN"
    remediation.end_time = datetime.now(timezone.utc)
    timing = ExecutionTiming(0.0, 0.0, 0.0, 0.0, 0.0)
    observed = _snapshot_value(remediation, requested)
    network_switch = db.session.get(NetworkSwitch, remediation.switch_id)
    value_details = _display_value_details(
        remediation.action_type,
        requested=requested,
        observed=observed,
    )
    record_audit(
        incident_id=incident.incident_id, remediation_id=remediation.remediation_id,
        administrator_id=_remediation_administrator_id(remediation),
        event_type="DRY_RUN", message="Remediation simulated; no SNMP SET was sent.",
        equipment_name=network_switch.name if network_switch else None,
        equipment_ip=network_switch.management_ip if network_switch else None,
        port_index=remediation.port_index, target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type, action_type=remediation.action_type,
        result_status="SIMULATED",
        details={
            "execution_mode": "DRY_RUN",
            "outcome": "SIMULATED",
            "write_result": "NO_WRITE",
            **value_details,
            "snmp_set_executed": False,
            "snmp_write_enabled": bool(current_app.config["SNMP_WRITE_ENABLED"]),
            "authorization_mode": remediation.authorization_mode,
        },
    )
    db.session.commit()
    return SnmpExecutionResult(
        remediation.remediation_id,
        int(requested),
        observed,
        timing,
        simulated=True,
    )


def _dry_run_rollback_result(
    incident: Incident,
    remediation: Remediation,
    requested: int,
    *,
    administrator_id: str,
) -> int:
    network_switch = db.session.get(NetworkSwitch, remediation.switch_id)
    value_details = _display_value_details(
        remediation.action_type,
        requested=requested,
    )
    record_audit(
        incident_id=incident.incident_id,
        remediation_id=remediation.remediation_id,
        administrator_id=administrator_id,
        event_type="DRY_RUN_ROLLBACK",
        message="Rollback simulated; no SNMP SET was sent.",
        equipment_name=network_switch.name if network_switch else None,
        equipment_ip=network_switch.management_ip if network_switch else None,
        port_index=remediation.port_index,
        target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type,
        action_type=remediation.action_type,
        result_status="SIMULATED",
        details={
            "execution_mode": "DRY_RUN",
            "outcome": "SIMULATED",
            "write_result": "NO_WRITE",
            **value_details,
            "snmp_set_executed": False,
            "snmp_write_enabled": bool(current_app.config["SNMP_WRITE_ENABLED"]),
        },
    )
    db.session.commit()
    return int(requested)


def _snapshot_value(remediation: Remediation, fallback: int) -> int:
    if remediation.action_type == "QUARANTINE_VLAN" and remediation.previous_vlan_id is not None:
        return int(remediation.previous_vlan_id)
    if remediation.previous_port_status is not None:
        try:
            return _admin_status_value(remediation.previous_port_status)
        except RemediationError:
            pass
    return int(fallback)


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
        administrator_id=_remediation_administrator_id(remediation),
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


def _block_rollback_state_changed(
    incident: Incident,
    remediation: Remediation,
    *,
    administrator_id: str,
    state_name: str,
    expected: int | str,
    observed: int | str,
) -> None:
    remediation.status = "ROLLBACK_BLOCKED"
    incident.processing_status = "ROLLBACK_BLOCKED"
    message = (
        "ROLLBACK BLOCKED\n\n"
        f"Expected current {state_name} : {expected}\n"
        f"Observed current {state_name} : {observed}\n\n"
        "Target state changed after remediation.\n"
        "Manual verification required."
    )
    record_audit(
        incident_id=incident.incident_id,
        remediation_id=remediation.remediation_id,
        administrator_id=administrator_id,
        event_type="ROLLBACK_BLOCKED_STATE_CHANGED",
        message="Rollback blocked because the target state changed after remediation.",
        port_index=remediation.port_index,
        target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type,
        action_type=remediation.action_type,
        result_status="ROLLBACK_BLOCKED",
        details={
            "state_name": state_name,
            "expected_current": expected,
            "observed_current": observed,
            "manual_verification_required": True,
        },
    )
    db.session.commit()
    raise RollbackStateChangedError(message)


def _admin_status_value(value: str) -> int:
    try:
        return parse_safe_if_admin_status(value)
    except ValueError as exc:
        raise RemediationError(str(exc)) from exc


def _admin_status_label(value: int | str) -> str:
    return format_if_admin_status(value)


def _display_value_details(
    action_type: str,
    *,
    requested: int,
    observed: int | None = None,
) -> dict[str, str]:
    if action_type == "QUARANTINE_VLAN":
        details = {"requested_vlan": format_action_value(action_type, requested)}
        if observed is not None:
            details["observed_vlan"] = format_action_value(action_type, observed)
        return details
    details = {"requested_state": format_action_value(action_type, requested)}
    if observed is not None:
        details["observed_state"] = format_action_value(action_type, observed)
    return details


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
        administrator_id=_remediation_administrator_id(remediation),
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

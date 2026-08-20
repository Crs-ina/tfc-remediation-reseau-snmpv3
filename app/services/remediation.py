from __future__ import annotations

from datetime import datetime, timezone

from flask import current_app
from sqlalchemy import func, update

from app.extensions import db
from app.models import (
    AuditLog,
    Incident,
    NetworkHost,
    NetworkSwitch,
    Remediation,
    SwitchPort,
)

from .audit import record_audit
from .administrators import IdentityError, require_administrator
from .calendar_policy import CalendarPolicy
from .rules import (
    PlaybookRepository,
    RuleContext,
    RuleDecision,
    RuleEngine,
)
from .whitelist import is_port_protected


class RemediationError(ValueError):
    pass


class UnsafeOperationBlocked(RemediationError):
    pass


class ConcurrentDecisionError(RemediationError):
    pass


def evaluate_incident(
    incident: Incident,
    *,
    target_confirmed: bool,
    target_mac_address: str | None,
    switch_id: str | None,
    port_index: int | None,
    target_ip: str | None = None,
    port_name: str | None = None,
    previous_vlan_id: int | None = None,
    previous_port_status: str | None = None,
    now: datetime | None = None,
) -> RuleDecision:
    if incident.processing_status == "WAITING_ADMIN_APPROVAL":
        raise RemediationError(
            "The incident is already waiting; elapsed time is not authorization."
        )

    policy = CalendarPolicy.from_file(current_app.config["AUTOMATION_SCHEDULE_PATH"])
    schedule = policy.decide(now)
    identification_attempts = _identification_attempt_count(incident.incident_id)
    target_whitelisted = False
    switch_port: SwitchPort | None = None
    target_host: NetworkHost | None = None

    if target_confirmed:
        if switch_id is None or port_index is None:
            raise RemediationError(
                "A confirmed target requires switch_id and port_index."
            )
        if incident.incident_type == "ip_address_conflict" and target_mac_address is None:
            raise RemediationError("A MAC address is required for an IP conflict.")
        switch_port, target_host = _confirm_target_location(
            target_mac_address=target_mac_address,
            target_ip=target_ip,
            switch_id=switch_id,
            port_index=port_index,
            port_name=port_name,
            previous_vlan_id=previous_vlan_id,
            previous_port_status=previous_port_status,
        )
        target_whitelisted = is_port_protected(
            current_app.config["WHITELIST_PATH"],
            switch_id=switch_id,
            port_index=port_index,
        )
    else:
        identification_attempts = min(identification_attempts + 1, 2)
        record_audit(
            incident_id=incident.incident_id,
            event_type="TARGET_IDENTIFICATION_FAILED",
            message="The target could not be confirmed through read-only checks.",
            equipment_ip=incident.source_ip,
            incident_type=incident.incident_type,
            result_status="RETRY" if identification_attempts < 2 else "ESCALATED",
            details={"attempt": identification_attempts, "maximum": 2},
        )

    engine = RuleEngine(PlaybookRepository(current_app.config["PLAYBOOKS_DIR"]))
    decision = engine.evaluate(
        RuleContext(
            incident_type=incident.incident_type,
            target_confirmed=target_confirmed,
            identification_attempts=identification_attempts,
            target_whitelisted=target_whitelisted,
            schedule=schedule,
            automatic_allowed_actions=policy.schedule.automatic_allowed_actions,
            quarantine_vlan_exists=current_app.config["QUARANTINE_VLAN_EXISTS"],
            quarantine_vlan_isolated=current_app.config[
                "QUARANTINE_VLAN_ISOLATED"
            ],
        )
    )

    previous_state = incident.processing_status
    incident.processing_status = decision.state

    remediation: Remediation | None = None
    if (
        switch_port is not None
        and decision.action != "NO_ACTION"
    ):
        remediation = _current_or_new_remediation(
            incident,
            target_host=target_host,
            switch_port=switch_port,
            action_type=decision.action,
            authorization_mode=(
                "AUTOMATIC"
                if decision.execution_mode == "AUTOMATIC"
                else "SUPERVISED"
            ),
        )
        if decision.execution_mode == "AUTOMATIC":
            remediation.status = "AUTHORIZED_PENDING_EXECUTION"
        elif decision.state == "WAITING_ADMIN_APPROVAL":
            remediation.status = "WAITING_ADMIN_APPROVAL"
        else:
            remediation.status = "NOT_AUTHORIZED"

    record_audit(
        incident_id=incident.incident_id,
        remediation_id=remediation.remediation_id if remediation else None,
        event_type="RULE_DECISION",
        message="Rule-engine decision.",
        equipment_ip=incident.source_ip,
        port_index=port_index,
        target_ip=target_ip,
        target_mac=target_mac_address,
        incident_type=incident.incident_type,
        action_type=decision.action,
        result_status=decision.state,
        details={
            "state_before": previous_state,
            "reason": decision.reason,
            "execution_mode": decision.execution_mode,
            "schedule_reason": schedule.reason,
            "holiday_name": schedule.holiday_name,
            "target_whitelisted": target_whitelisted,
            "quarantine_vlan_id": current_app.config["QUARANTINE_VLAN_ID"],
            "quarantine_vlan_exists": current_app.config[
                "QUARANTINE_VLAN_EXISTS"
            ],
            "quarantine_vlan_isolated": current_app.config[
                "QUARANTINE_VLAN_ISOLATED"
            ],
        },
    )
    db.session.commit()
    return decision


def _claim_human_decision(incident: Incident, administrator_id: str, target_state: str) -> None:
    """SQLite-safe compare-and-set: the first pending decision wins."""
    result = db.session.execute(
        update(Incident)
        .where(Incident.incident_id == incident.incident_id, Incident.processing_status == "WAITING_ADMIN_APPROVAL")
        .values(processing_status=target_state)
    )
    if result.rowcount:
        db.session.flush()
        return
    db.session.expire(incident)
    db.session.refresh(incident)
    record_audit(incident_id=incident.incident_id, administrator_id=administrator_id,
                 event_type="CONCURRENT_DECISION_REJECTED", message="Decision rejected: incident already decided.",
                 result_status="REJECTED", details={"current_status": incident.processing_status})
    db.session.commit()
    raise ConcurrentDecisionError(f"Decision rejected. This incident has already been {incident.processing_status}.")


def approve_incident(incident: Incident, administrator_id: str) -> Remediation:
    try:
        require_administrator(administrator_id)
    except IdentityError as exc:
        raise RemediationError(str(exc)) from exc
    _claim_human_decision(incident, administrator_id, "ADMIN_APPROVED")
    previous_state = "WAITING_ADMIN_APPROVAL"
    remediation = _latest_remediation_or_fail(incident)
    remediation.status = "AUTHORIZED_PENDING_EXECUTION"
    remediation.authorization_mode = "SUPERVISED"
    record_audit(
        incident_id=incident.incident_id,
        remediation_id=remediation.remediation_id,
        administrator_id=administrator_id, event_type="REMEDIATION_APPROVED",
        message="Administrator explicitly approved remediation.",
        port_index=remediation.port_index,
        target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type,
        action_type=remediation.action_type,
        result_status="ADMIN_APPROVED",
        details={
            "administrator_id": administrator_id,
            "state_before": previous_state,
        },
    )
    db.session.commit()
    return remediation


def refuse_incident(incident: Incident, administrator_id: str) -> Remediation:
    try:
        require_administrator(administrator_id)
    except IdentityError as exc:
        raise RemediationError(str(exc)) from exc
    _claim_human_decision(incident, administrator_id, "REJECTED_BY_ADMIN")
    previous_state = "WAITING_ADMIN_APPROVAL"
    remediation = _latest_remediation_or_fail(incident)
    remediation.status = "REJECTED_BY_ADMIN"
    remediation.authorization_mode = "SUPERVISED"
    remediation.end_time = datetime.now(timezone.utc)
    record_audit(
        incident_id=incident.incident_id,
        remediation_id=remediation.remediation_id,
        administrator_id=administrator_id, event_type="REMEDIATION_REFUSED",
        message="Administrator refused remediation.",
        port_index=remediation.port_index,
        target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type,
        action_type=remediation.action_type,
        result_status="REJECTED_BY_ADMIN",
        details={
            "administrator_id": administrator_id,
            "state_before": previous_state,
        },
    )
    db.session.commit()
    return remediation


def execute_authorized_remediation(incident: Incident):
    from .snmp_execution import execute_snmp_action

    return execute_snmp_action(incident)


def resume_simulated_remediation_for_real(
    incident: Incident,
    administrator_id: str,
) -> Remediation:
    """Re-authorize a supervised DRY-RUN result for explicit real execution."""

    try:
        require_administrator(administrator_id)
    except IdentityError as exc:
        raise RemediationError(str(exc)) from exc

    if incident.processing_status != "SIMULATED":
        raise RemediationError(
            "Only a simulated incident can be resumed for real execution."
        )

    remediation = _latest_remediation_or_fail(incident)

    if remediation.status != "DRY_RUN":
        raise RemediationError(
            "The latest remediation is not a DRY-RUN result."
        )

    if remediation.authorization_mode != "SUPERVISED":
        raise RemediationError(
            "Only a supervised simulated remediation can be resumed here."
        )

    previous_state = incident.processing_status

    incident.processing_status = "ADMIN_APPROVED"
    remediation.status = "AUTHORIZED_PENDING_EXECUTION"
    remediation.end_time = None

    record_audit(
        incident_id=incident.incident_id,
        remediation_id=remediation.remediation_id,
        administrator_id=administrator_id,
        event_type="DRY_RUN_REAL_EXECUTION_CONFIRMED",
        message=(
            "Administrator explicitly requested real execution "
            "after a successful DRY-RUN."
        ),
        port_index=remediation.port_index,
        target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type,
        action_type=remediation.action_type,
        result_status="ADMIN_APPROVED",
        details={
            "administrator_id": administrator_id,
            "state_before": previous_state,
            "dry_run_result": "SIMULATED",
        },
    )

    db.session.commit()
    return remediation


def _current_or_new_remediation(
    incident: Incident,
    *,
    target_host: NetworkHost | None,
    switch_port: SwitchPort,
    action_type: str,
    authorization_mode: str,
) -> Remediation:
    if incident.remediations:
        remediation = incident.remediations[-1]
        remediation.target_host = target_host
        remediation.switch_port = switch_port
        remediation.switch_id = switch_port.switch_id
        remediation.port_index = switch_port.port_index
        remediation.action_type = action_type
        remediation.authorization_mode = authorization_mode
        # A repeated read-only preparation refreshes the snapshot before any
        # write. Never keep an older inventory value as rollback state.
        remediation.previous_port_status = switch_port.status
        remediation.previous_vlan_id = switch_port.vlan_id
        remediation.applied_port_status = None
        remediation.applied_vlan_id = None
        return remediation
    remediation = Remediation(
        incident=incident,
        target_host=target_host,
        switch_port=switch_port,
        switch_id=switch_port.switch_id,
        port_index=switch_port.port_index,
        action_type=action_type,
        authorization_mode=authorization_mode,
        status="PROPOSED",
        previous_port_status=switch_port.status,
        previous_vlan_id=switch_port.vlan_id,
        applied_port_status=None,
        applied_vlan_id=None,
    )
    db.session.add(remediation)
    return remediation


def _record_execution_block(incident: Incident, reason: str) -> None:
    previous_state = incident.processing_status
    remediation = _latest_remediation_or_fail(incident)
    incident.processing_status = "BLOCKED_SNMP_WRITE"
    remediation.status = "BLOCKED_SNMP_WRITE"
    remediation.end_time = datetime.now(timezone.utc)
    record_audit(
        incident_id=incident.incident_id,
        remediation_id=remediation.remediation_id,
        event_type="SNMP_WRITE_BLOCKED",
        message="No SNMP write was executed.",
        port_index=remediation.port_index,
        target_mac=remediation.target_mac_address,
        incident_type=incident.incident_type,
        action_type=remediation.action_type,
        result_status=incident.processing_status,
        details={"reason": reason, "state_before": previous_state},
    )
    db.session.commit()


def _latest_remediation_or_fail(incident: Incident) -> Remediation:
    if not incident.remediations:
        raise RemediationError("No targeted remediation is associated with this incident.")
    return incident.remediations[-1]


def _identification_attempt_count(incident_id: str) -> int:
    statement = db.select(func.count(AuditLog.log_id)).where(
        AuditLog.incident_id == incident_id,
        AuditLog.event_type == "TARGET_IDENTIFICATION_FAILED",
    )
    return int(db.session.execute(statement).scalar_one())


def _confirm_target_location(
    *,
    target_mac_address: str | None,
    target_ip: str | None,
    switch_id: str,
    port_index: int,
    port_name: str | None,
    previous_vlan_id: int | None,
    previous_port_status: str | None,
) -> tuple[SwitchPort, NetworkHost | None]:
    network_switch = db.session.get(NetworkSwitch, switch_id)
    if network_switch is None:
        raise RemediationError("The target switch is not present in inventory.")
    switch_port = db.session.get(SwitchPort, (switch_id, port_index))
    if switch_port is None:
        if not port_name:
            raise RemediationError(
                "The target port is unknown and no SNMP-confirmed name was provided."
            )
        switch_port = SwitchPort(
            network_switch=network_switch,
            port_index=port_index,
            port_name=port_name,
            status=previous_port_status,
            vlan_id=previous_vlan_id,
        )
        db.session.add(switch_port)
    else:
        if port_name:
            switch_port.port_name = port_name
        if previous_vlan_id is not None:
            switch_port.vlan_id = previous_vlan_id
        if previous_port_status is not None:
            switch_port.status = previous_port_status

    target_host = None
    if target_mac_address:
        normalized_mac = target_mac_address.strip().lower()
        target_host = db.session.get(NetworkHost, normalized_mac)
        if target_host is None:
            target_host = NetworkHost(mac_address=normalized_mac)
            db.session.add(target_host)
        target_host.ip_address = target_ip
        target_host.switch_port = switch_port
    return switch_port, target_host

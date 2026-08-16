from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from app.extensions import db
from app.models import Incident

from .audit import record_audit
from .rules import PlaybookRepository


def tag_value(payload: dict, name: str) -> str | None:
    for entry in payload.get("context", {}).get("tags", []):
        if entry.get("tag") == name:
            return entry.get("value")
    return None


def register_incident(payload: dict, playbooks_dir: Path) -> tuple[Incident, bool]:
    zabbix_event_id = str(payload["event"]["id"])
    existing = db.session.execute(
        db.select(Incident).where(Incident.zabbix_event_id == zabbix_event_id)
    ).scalar_one_or_none()
    if existing is not None:
        return existing, True

    incident_type = payload["routing"].get("incident_type")
    playbook = PlaybookRepository(playbooks_dir).get(incident_type)
    event_timestamp = payload["event"].get("timestamp")
    detected_at = (
        datetime.fromtimestamp(event_timestamp, tz=timezone.utc)
        if event_timestamp is not None
        else None
    )

    incident = Incident(
        zabbix_event_id=zabbix_event_id,
        incident_type=incident_type,
        playbook_id=playbook.playbook_id,
        severity=payload["event"].get("severity"),
        detected_at=detected_at,
        source_ip=payload["host"].get("ip"),
        description=payload["event"].get("name")
        or payload.get("context", {}).get("opdata"),
        processing_status="ROUTED",
    )
    db.session.add(incident)
    db.session.flush()
    record_audit(
        incident_id=incident.incident_id,
        event_type="ZABBIX_EVENT_ROUTED",
        message="Evenement Zabbix valide et route vers un playbook.",
        equipment_name=payload["host"].get("name"),
        equipment_ip=payload["host"].get("ip"),
        target_ip=payload["target_hint"].get("client_ip"),
        target_mac=payload["target_hint"].get("client_mac"),
        incident_type=incident_type,
        action_type=playbook.action,
        result_status="ROUTED",
        details={
            "zabbix_event_id": zabbix_event_id,
            "playbook_id": playbook.playbook_id,
        },
    )
    db.session.commit()
    return incident, False


def register_recovery(payload: dict) -> Incident | None:
    """Close a still-pending request when Zabbix recovers the same event.

    The v1.0 contract has no separate problem-event correlation field, so only
    the stable event identifier is used. Unknown recovery IDs remain ignored.
    """
    zabbix_event_id = str(payload["event"]["id"])
    incident = db.session.execute(
        db.select(Incident).where(Incident.zabbix_event_id == zabbix_event_id)
    ).scalar_one_or_none()
    if incident is None:
        return None
    if incident.processing_status not in {
        "ROUTED", "IDENTIFYING_TARGET", "WAITING_ADMIN_APPROVAL", "ADMIN_APPROVED"
    }:
        return incident
    incident.processing_status = "RECOVERED_BEFORE_ACTION"
    for remediation in incident.remediations:
        if remediation.status not in {"SUCCEEDED", "ROLLED_BACK"}:
            remediation.status = "RECOVERED_BEFORE_ACTION"
            remediation.end_time = datetime.now(timezone.utc)
    record_audit(
        incident_id=incident.incident_id,
        event_type="ZABBIX_RECOVERY_BEFORE_ACTION",
        message="Zabbix recovery closed the pending request before any network write.",
        equipment_name=payload["host"].get("name"),
        equipment_ip=payload["host"].get("ip"),
        incident_type=incident.incident_type,
        result_status="RECOVERED_BEFORE_ACTION",
        details={"zabbix_event_id": zabbix_event_id},
    )
    db.session.commit()
    return incident

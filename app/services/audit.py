from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from app.extensions import db
from app.models import AuditLog


SENSITIVE_FRAGMENTS = (
    "password",
    "secret",
    "token",
    "auth_key",
    "priv_key",
    "private_key",
)


def sanitize(value: Any) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).lower()
            if any(fragment in normalized for fragment in SENSITIVE_FRAGMENTS):
                result[str(key)] = "[REDACTED]"
            else:
                result[str(key)] = sanitize(item)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [sanitize(item) for item in value]
    return value


def record_audit(
    *,
    incident_id: str | None,
    event_type: str,
    message: str,
    remediation_id: str | None = None,
    administrator_id: str | None = None,
    equipment_name: str | None = None,
    equipment_ip: str | None = None,
    port_index: int | None = None,
    target_ip: str | None = None,
    target_mac: str | None = None,
    incident_type: str | None = None,
    action_type: str | None = None,
    result_status: str | None = None,
    details: dict[str, Any] | None = None,
    commit: bool = False,
) -> AuditLog:
    sanitized_details = sanitize(details or {})
    rendered_message = message
    if sanitized_details:
        rendered_message = (
            f"{message} | "
            f"{json.dumps(sanitized_details, ensure_ascii=False, sort_keys=True)}"
        )
    entry = AuditLog(
        incident_id=incident_id,
        remediation_id=remediation_id,
        administrator_id=administrator_id,
        event_type=event_type,
        equipment_name=equipment_name,
        equipment_ip=equipment_ip,
        port_index=port_index,
        target_ip=target_ip,
        target_mac=target_mac,
        incident_type=incident_type,
        action_type=action_type,
        result_status=result_status,
        message=rendered_message,
    )
    db.session.add(entry)
    if commit:
        db.session.commit()
    return entry

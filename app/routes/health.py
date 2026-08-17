import json

from flask import Blueprint, current_app, jsonify
from sqlalchemy import text

from app.extensions import db
from app.services.calendar_policy import load_automation_schedule
from app.services.runtime_settings import is_dry_run_enabled
from app.snmp.capabilities import load_capabilities


bp = Blueprint("health", __name__)


@bp.get("/health")
def health():
    mib_registry = current_app.extensions.get("snmp_mib_registry")
    mib_status = mib_registry.status if mib_registry else None
    checks: dict[str, bool] = {"mib": bool(mib_status and mib_status.ready)}
    errors: dict[str, str] = {}
    try:
        db.session.execute(text("SELECT 1")).scalar_one()
        checks["sqlite"] = True
    except Exception as exc:  # health must report failure, never mutate
        checks["sqlite"] = False
        errors["sqlite"] = type(exc).__name__
    try:
        whitelist = json.loads(current_app.config["WHITELIST_PATH"].read_text(encoding="utf-8"))
        checks["whitelist"] = isinstance(whitelist.get("protected_categories"), list)
    except Exception as exc:
        checks["whitelist"] = False
        errors["whitelist"] = type(exc).__name__
    try:
        load_automation_schedule(current_app.config["AUTOMATION_SCHEDULE_PATH"])
        checks["calendar"] = True
    except Exception as exc:
        checks["calendar"] = False
        errors["calendar"] = type(exc).__name__
    try:
        checks["capabilities"] = bool(load_capabilities(current_app.config["SNMP_CAPABILITIES_PATH"]))
    except Exception as exc:
        checks["capabilities"] = False
        errors["capabilities"] = type(exc).__name__
    checks["quarantine_vlan"] = bool(
        current_app.config["QUARANTINE_VLAN_ID"] > 0
        and isinstance(current_app.config["QUARANTINE_VLAN_EXISTS"], bool)
        and isinstance(current_app.config["QUARANTINE_VLAN_ISOLATED"], bool)
    )
    return jsonify(
        {
            "ok": all(checks.values()),
            "service": "OKAPI",
            "architecture": "monolithe_modulaire_flask",
            "snmp_policy": "read_only_discovery_lab_validated_writes_only",
            "mib_ready": bool(mib_status and mib_status.ready),
            "mib_package": mib_status.package if mib_status else None,
            "mib_resolved_objects": (
                mib_status.resolved_objects if mib_status else 0
            ),
            "mib_error": mib_status.error if mib_status else "not_initialized",
            "checks": checks,
            "errors": errors,
            "write_enabled": bool(current_app.config["SNMP_WRITE_ENABLED"]),
            "dry_run": is_dry_run_enabled(),
        }
    )

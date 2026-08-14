from flask import Blueprint, current_app, jsonify


bp = Blueprint("health", __name__)


@bp.get("/health")
def health():
    mib_registry = current_app.extensions.get("snmp_mib_registry")
    mib_status = mib_registry.status if mib_registry else None
    return jsonify(
        {
            "ok": bool(mib_status and mib_status.ready),
            "service": "tfc-remediation-reseau-snmpv3",
            "architecture": "monolithe_modulaire_flask",
            "snmp_policy": "read_only_discovery_lab_validated_writes_only",
            "mib_ready": bool(mib_status and mib_status.ready),
            "mib_package": mib_status.package if mib_status else None,
            "mib_resolved_objects": (
                mib_status.resolved_objects if mib_status else 0
            ),
            "mib_error": mib_status.error if mib_status else "not_initialized",
        }
    )

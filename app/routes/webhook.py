from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from app.services.incident_service import register_incident, tag_value
from app.services.payload_validation import validate_payload
from app.services.security import AuthenticationError, verify_webhook_token


bp = Blueprint("zabbix_webhook", __name__, url_prefix="/api/v1/incidents")


@bp.post("/zabbix")
def receive_zabbix_incident():
    try:
        verify_webhook_token(
            request.headers.get("X-Webhook-Token"),
            current_app.config["WEBHOOK_TOKEN"],
        )
    except AuthenticationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 401

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"ok": False, "error": "Le payload doit etre un objet JSON."}), 400

    validation_errors = validate_payload(payload, current_app.config["SCHEMA_PATH"])
    if validation_errors:
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "Payload non conforme au contrat v1.0.",
                    "details": validation_errors,
                }
            ),
            422,
        )

    if payload["event"]["value"] != 1 or payload["event"]["status"].upper() != "PROBLEM":
        return jsonify(
            {
                "ok": True,
                "ignored": True,
                "reason": "not_a_problem_event",
                "zabbix_event_id": payload["event"]["id"],
            }
        )

    if current_app.config["REQUIRE_REMEDIATION_TAG"]:
        observed = tag_value(payload, current_app.config["REMEDIATION_TAG_NAME"])
        if observed != current_app.config["REMEDIATION_TAG_VALUE"]:
            return jsonify(
                {
                    "ok": True,
                    "ignored": True,
                    "reason": "outside_remediation_scope",
                    "zabbix_event_id": payload["event"]["id"],
                }
            )

    incident, duplicate = register_incident(
        payload, current_app.config["PLAYBOOKS_DIR"]
    )
    return jsonify(
        {
            "ok": True,
            "ignored": False,
            "duplicate": duplicate,
            "incident_id": incident.incident_id,
            "zabbix_event_id": incident.zabbix_event_id,
            "incident_type": incident.incident_type,
            "playbook_id": incident.playbook_id,
            "state": incident.processing_status,
        }
    )

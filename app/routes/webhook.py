from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from app.extensions import db
from app.services.audit import record_audit
from app.services.incident_service import register_incident, register_recovery, tag_value
from app.services.payload_validation import validate_payload
from app.services.security import AuthenticationError, verify_webhook_token
from app.services.network_discovery import (
    NetworkDiscoveryError,
    discover_switch,
    resolve_interface_bridge_port,
)
from app.services.snmp_preparation import (
    SnmpPreparationBlocked,
    inspect_physical_disconnection_with_snmp,
    prepare_incident_with_snmp,
    prepare_port_incident_with_snmp,
)
from app.services.remediation import execute_authorized_remediation

bp = Blueprint("zabbix_webhook", __name__, url_prefix="/api/v1/incidents")


@bp.post("/zabbix")
def receive_zabbix_incident():
    allowed_sources = current_app.config["WEBHOOK_ALLOWED_SOURCE_IPS"]
    if allowed_sources and request.remote_addr not in allowed_sources:
        # The response is deliberately generic and contains no deployment or
        # authentication details.  The event is not persisted.
        _record_rejection("WEBHOOK_SOURCE_REJECTED", "Webhook source rejected.")
        return jsonify({"ok": False, "error": "Webhook source is not allowed."}), 403
    try:
        verify_webhook_token(
            request.headers.get("X-Webhook-Token"),
            current_app.config["WEBHOOK_TOKEN"],
        )
    except AuthenticationError as exc:
        _record_rejection("WEBHOOK_AUTHENTICATION_REJECTED", "Webhook authentication failed.")
        return jsonify({"ok": False, "error": str(exc)}), 401

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        _record_rejection("WEBHOOK_PAYLOAD_REJECTED", "Webhook payload is not a JSON object.")
        return jsonify({"ok": False, "error": "Le payload doit etre un objet JSON."}), 400

    validation_errors = validate_payload(payload, current_app.config["SCHEMA_PATH"])
    if validation_errors:
        _record_rejection(
            "WEBHOOK_SCHEMA_REJECTED", "Webhook payload failed JSON Schema validation."
        )
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
        recovered = register_recovery(payload)
        return jsonify(
            {
                "ok": True,
                "ignored": True,
                "reason": (
                    "recovered_before_action"
                    if recovered and recovered.processing_status == "RECOVERED_BEFORE_ACTION"
                    else "not_a_problem_event"
                ),
                "zabbix_event_id": payload["event"]["id"],
            }
        )

    if current_app.config["REQUIRE_REMEDIATION_TAG"]:
        observed = tag_value(payload, current_app.config["REMEDIATION_TAG_NAME"])
        if observed != current_app.config["REMEDIATION_TAG_VALUE"]:
            _record_rejection(
                "WEBHOOK_OUTSIDE_REMEDIATION_SCOPE",
                "Valid event ignored because remediation scope is not enabled.",
            )
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

    # physical_disconnection is intentionally read-only.
    # It must never trigger an SNMP SET.
    if not duplicate and incident.incident_type == "physical_disconnection":
        interface_hint = payload["target_hint"].get("interface")

        if not interface_hint:
            incident.processing_status = "ESCALATED"
            record_audit(
                incident_id=incident.incident_id,
                event_type="TARGET_INTERFACE_MISSING",
                message="Physical disconnection cannot be checked without an interface hint.",
                equipment_name=payload["host"].get("name"),
                equipment_ip=payload["host"].get("ip"),
                incident_type=incident.incident_type,
                result_status="ESCALATED",
            )
            db.session.commit()
        else:
            incident.processing_status = "IDENTIFYING_TARGET"
            db.session.commit()

            try:
                network_switch, snmp_client, snmp_config = discover_switch(
                    management_ip=payload["host"]["ip"],
                    incident_id=incident.incident_id,
                )

                port = resolve_interface_bridge_port(
                    snmp_client,
                    interface_hint,
                )

                inspect_physical_disconnection_with_snmp(
                    incident,
                    switch_id=network_switch.switch_id,
                    bridge_port=port.bridge_port,
                    client=snmp_client,
                    snmp_config=snmp_config,
                )

            except NetworkDiscoveryError as exc:
                incident.processing_status = "ESCALATED"
                record_audit(
                    incident_id=incident.incident_id,
                    event_type="NETWORK_TARGET_DISCOVERY_FAILED",
                    message="Automatic SNMP target discovery failed.",
                    equipment_name=payload["host"].get("name"),
                    equipment_ip=payload["host"].get("ip"),
                    incident_type=incident.incident_type,
                    result_status="ESCALATED",
                    details={"error": str(exc)},
                )
                db.session.commit()

            except SnmpPreparationBlocked as exc:
                if incident.processing_status == "IDENTIFYING_TARGET":
                    incident.processing_status = "ESCALATED"
                    record_audit(
                        incident_id=incident.incident_id,
                        event_type="SNMP_PREPARATION_BLOCKED",
                        message="Physical-disconnection SNMP checks were blocked.",
                        equipment_name=payload["host"].get("name"),
                        equipment_ip=payload["host"].get("ip"),
                        incident_type=incident.incident_type,
                        result_status="ESCALATED",
                        details={"error": str(exc)},
                    )
                    db.session.commit()

    # A duplicate Zabbix event must never trigger the remediation pipeline twice.
    if not duplicate and incident.incident_type in {
        "interface_admin_down",
        "port_flapping",
        "vlan_policy_violation",
    }:
        interface_hint = payload["target_hint"].get("interface")

        if not interface_hint:
            incident.processing_status = "ESCALATED"
            record_audit(
                incident_id=incident.incident_id,
                event_type="TARGET_INTERFACE_MISSING",
                message="Port-centric incident cannot be resolved without an interface hint.",
                equipment_name=payload["host"].get("name"),
                equipment_ip=payload["host"].get("ip"),
                incident_type=incident.incident_type,
                result_status="ESCALATED",
            )
            db.session.commit()
        else:
            incident.processing_status = "IDENTIFYING_TARGET"
            db.session.commit()

            try:
                network_switch, snmp_client, snmp_config = discover_switch(
                    management_ip=payload["host"]["ip"],
                    incident_id=incident.incident_id,
                )

                port = resolve_interface_bridge_port(
                    snmp_client,
                    interface_hint,
                )

                preparation = prepare_port_incident_with_snmp(
                    incident,
                    switch_id=network_switch.switch_id,
                    bridge_port=port.bridge_port,
                    interface_hint=interface_hint,
                    target_mac=payload["target_hint"].get("client_mac"),
                    target_ip=payload["target_hint"].get("client_ip"),
                    client=snmp_client,
                    snmp_config=snmp_config,
                )

                # Outside the supervised window, an automatically authorized
                # disruptive action must immediately continue to real SNMP
                # execution.  Authorization alone must not stop the pipeline.
                if preparation.decision_state == "AUTOMATICALLY_AUTHORIZED":
                    execute_authorized_remediation(incident)

            except NetworkDiscoveryError as exc:
                incident.processing_status = "ESCALATED"
                record_audit(
                    incident_id=incident.incident_id,
                    event_type="NETWORK_TARGET_DISCOVERY_FAILED",
                    message="Automatic SNMP target discovery failed.",
                    equipment_name=payload["host"].get("name"),
                    equipment_ip=payload["host"].get("ip"),
                    incident_type=incident.incident_type,
                    result_status="ESCALATED",
                    details={"error": str(exc)},
                )
                db.session.commit()

            except SnmpPreparationBlocked as exc:
                # Most preparation failures are already audited by the
                # preparation service. Fail closed if it did not set a state.
                if incident.processing_status == "IDENTIFYING_TARGET":
                    incident.processing_status = "ESCALATED"
                    record_audit(
                        incident_id=incident.incident_id,
                        event_type="SNMP_PREPARATION_BLOCKED",
                        message="SNMP preparation was blocked before remediation.",
                        equipment_name=payload["host"].get("name"),
                        equipment_ip=payload["host"].get("ip"),
                        incident_type=incident.incident_type,
                        result_status="ESCALATED",
                        details={"error": str(exc)},
                    )
                    db.session.commit()

    # IP conflict: Zabbix supplies hints; SNMP independently resolves
    # and confirms IP -> MAC -> bridge port -> interface before remediation.
    if not duplicate and incident.incident_type == "ip_address_conflict":
        target_ip = payload["target_hint"].get("client_ip")
        target_mac = payload["target_hint"].get("client_mac")

        if not target_ip and not target_mac:
            incident.processing_status = "ESCALATED"
            record_audit(
                incident_id=incident.incident_id,
                event_type="TARGET_IDENTITY_MISSING",
                message="IP conflict cannot be resolved without an IP or MAC target hint.",
                equipment_name=payload["host"].get("name"),
                equipment_ip=payload["host"].get("ip"),
                incident_type=incident.incident_type,
                result_status="ESCALATED",
            )
            db.session.commit()
        else:
            incident.processing_status = "IDENTIFYING_TARGET"
            db.session.commit()

            try:
                network_switch, snmp_client, snmp_config = discover_switch(
                    management_ip=payload["host"]["ip"],
                    incident_id=incident.incident_id,
                )

                prepare_incident_with_snmp(
                    incident,
                    switch_id=network_switch.switch_id,
                    target_mac=target_mac,
                    target_ip=target_ip,
                    client=snmp_client,
                    snmp_config=snmp_config,
                )

            except NetworkDiscoveryError as exc:
                incident.processing_status = "ESCALATED"
                record_audit(
                    incident_id=incident.incident_id,
                    event_type="NETWORK_TARGET_DISCOVERY_FAILED",
                    message="Automatic SNMP switch discovery failed for IP conflict.",
                    equipment_name=payload["host"].get("name"),
                    equipment_ip=payload["host"].get("ip"),
                    incident_type=incident.incident_type,
                    result_status="ESCALATED",
                    details={"error": str(exc)},
                )
                db.session.commit()

            except SnmpPreparationBlocked as exc:
                if incident.processing_status == "IDENTIFYING_TARGET":
                    incident.processing_status = "ESCALATED"
                    record_audit(
                        incident_id=incident.incident_id,
                        event_type="SNMP_PREPARATION_BLOCKED",
                        message="SNMP preparation was blocked before IP-conflict remediation.",
                        equipment_name=payload["host"].get("name"),
                        equipment_ip=payload["host"].get("ip"),
                        incident_type=incident.incident_type,
                        result_status="ESCALATED",
                        details={"error": str(exc)},
                    )
                    db.session.commit()

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


def _record_rejection(event_type: str, message: str) -> None:
    """Best-effort security audit that never records a token or raw payload."""

    try:
        record_audit(
            incident_id=None,
            event_type=event_type,
            message=message,
            result_status="REJECTED",
        )
        db.session.commit()
    except Exception:
        db.session.rollback()

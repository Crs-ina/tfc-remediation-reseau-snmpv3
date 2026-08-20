import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.extensions import db
from app.models import AuditLog, Incident


EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "network_loop.json"


def payload() -> dict:
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def post(client, body: dict, token: str = "test-secret"):
    return client.post(
        "/api/v1/incidents/zabbix",
        json=body,
        headers={"X-Webhook-Token": token},
    )


def test_routes_network_loop(client):
    response = post(client, payload())
    assert response.status_code == 200
    assert response.get_json()["playbook_id"] == "PB-LOOP-001"
    assert response.get_json()["state"] == "ROUTED"


@pytest.mark.parametrize(
    ("incident_type", "playbook_id"),
    [
        ("physical_disconnection", "PB-PHYSICAL-DOWN-001"),
        ("network_loop", "PB-LOOP-001"),
        ("ip_address_conflict", "PB-IP-CONFLICT-001"),
        ("interface_admin_down", "PB-INTERFACE-DOWN-001"),
        ("port_flapping", "PB-PORT-FLAPPING-001"),
        ("vlan_policy_violation", "PB-VLAN-POLICY-001"),
        (None, "PB-UNKNOWN-001"),
    ],
)
def test_webhook_routes_all_final_incidents(client, incident_type, playbook_id):
    body = payload()
    body["event"]["id"] = f"evt-route-{playbook_id}"
    body["routing"]["incident_type"] = incident_type

    response = post(client, body)

    assert response.status_code == 200
    assert response.get_json()["playbook_id"] == playbook_id


def test_rejects_wrong_token(client):
    response = post(client, payload(), token="wrong")
    assert response.status_code == 401


def test_ignores_recovery_event(client):
    body = copy.deepcopy(payload())
    body["event"]["value"] = 0
    body["event"]["status"] = "OK"
    response = post(client, body)
    assert response.status_code == 200
    assert response.get_json()["ignored"] is True


def test_duplicate_is_idempotent(client, app):
    first = post(client, payload()).get_json()
    second = post(client, payload()).get_json()
    assert second["duplicate"] is True
    assert first["incident_id"] == second["incident_id"]
    with app.app_context():
        assert db.session.execute(
            db.select(db.func.count(Incident.incident_id))
        ).scalar_one() == 1
        assert db.session.execute(
            db.select(AuditLog).where(
                AuditLog.event_type == "ZABBIX_DUPLICATE_IGNORED"
            )
        ).scalar_one()


def test_invalid_payload_is_rejected(client):
    body = payload()
    del body["event"]["id"]
    response = post(client, body)
    assert response.status_code == 422



def test_port_flapping_enters_snmp_port_pipeline(client, monkeypatch):
    body = payload()
    body["event"]["id"] = "evt-port-flapping-snmp-pipeline"
    body["routing"]["incident_type"] = "port_flapping"
    body["target_hint"]["interface"] = "Ethernet1"

    calls = {}

    fake_switch = SimpleNamespace(switch_id="SW-TEST-01")
    fake_snmp_client = object()
    fake_snmp_config = object()
    fake_port = SimpleNamespace(bridge_port=1)

    def fake_discover_switch(*, management_ip, incident_id):
        calls["discover_switch"] = {
            "management_ip": management_ip,
            "incident_id": incident_id,
        }
        return fake_switch, fake_snmp_client, fake_snmp_config

    def fake_resolve_interface_bridge_port(client_arg, interface_hint):
        calls["resolve_interface"] = {
            "client": client_arg,
            "interface_hint": interface_hint,
        }
        return fake_port

    def fake_prepare_port_incident_with_snmp(incident, **kwargs):
        calls["prepare"] = {
            "incident_type": incident.incident_type,
            "playbook_id": incident.playbook_id,
            **kwargs,
        }
        return SimpleNamespace(decision_state="WAITING_ADMIN_APPROVAL")

    monkeypatch.setattr(
        "app.routes.webhook.discover_switch",
        fake_discover_switch,
    )
    monkeypatch.setattr(
        "app.routes.webhook.resolve_interface_bridge_port",
        fake_resolve_interface_bridge_port,
    )
    monkeypatch.setattr(
        "app.routes.webhook.prepare_port_incident_with_snmp",
        fake_prepare_port_incident_with_snmp,
    )

    response = post(client, body)

    assert response.status_code == 200
    assert response.get_json()["playbook_id"] == "PB-PORT-FLAPPING-001"

    assert calls["discover_switch"]["management_ip"] == body["host"]["ip"]

    assert calls["resolve_interface"]["client"] is fake_snmp_client
    assert calls["resolve_interface"]["interface_hint"] == "Ethernet1"

    assert calls["prepare"]["incident_type"] == "port_flapping"
    assert calls["prepare"]["playbook_id"] == "PB-PORT-FLAPPING-001"
    assert calls["prepare"]["switch_id"] == "SW-TEST-01"
    assert calls["prepare"]["bridge_port"] == 1
    assert calls["prepare"]["interface_hint"] == "Ethernet1"
    assert calls["prepare"]["client"] is fake_snmp_client
    assert calls["prepare"]["snmp_config"] is fake_snmp_config

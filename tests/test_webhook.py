import copy
import json
from pathlib import Path

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


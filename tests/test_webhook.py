import copy
import json
from pathlib import Path


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


def test_duplicate_is_idempotent(client):
    first = post(client, payload()).get_json()
    second = post(client, payload()).get_json()
    assert second["duplicate"] is True
    assert first["incident_id"] == second["incident_id"]


def test_invalid_payload_is_rejected(client):
    body = payload()
    del body["event"]["id"]
    response = post(client, body)
    assert response.status_code == 422


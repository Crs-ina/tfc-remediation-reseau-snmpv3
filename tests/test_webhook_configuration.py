import copy
import json
from pathlib import Path


EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "network_loop.json"


def test_webhook_rejects_a_non_local_source(client):
    body = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    response = client.post(
        "/api/v1/incidents/zabbix",
        json=body,
        headers={"X-Webhook-Token": "test-secret"},
        environ_base={"REMOTE_ADDR": "192.0.2.77"},
    )
    assert response.status_code == 403
    assert response.get_json()["error"] == "Webhook source is not allowed."

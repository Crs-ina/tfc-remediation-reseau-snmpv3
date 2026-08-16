import copy
import json
from pathlib import Path

import pytest

from app.extensions import db
from app.models import AuditLog, Incident
from app.services.rules import PlaybookRepository


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("incident_type", "playbook_id", "action"),
    [
        ("physical_disconnection", "PB-PHYSICAL-DOWN-001", "NO_ACTION"),
        ("network_loop", "PB-LOOP-001", "SHUTDOWN_PORT"),
        ("ip_address_conflict", "PB-IP-CONFLICT-001", "QUARANTINE_VLAN"),
        ("interface_admin_down", "PB-INTERFACE-DOWN-001", "REACTIVATE_PORT"),
        ("port_flapping", "PB-PORT-FLAPPING-001", "SHUTDOWN_PORT"),
        ("vlan_policy_violation", "PB-VLAN-POLICY-001", "QUARANTINE_VLAN"),
        (None, "PB-UNKNOWN-001", "NO_ACTION"),
        ("unsupported", "PB-UNKNOWN-001", "NO_ACTION"),
    ],
)
def test_final_playbook_routing(incident_type, playbook_id, action):
    playbook = PlaybookRepository(ROOT / "playbooks").get(incident_type)
    assert playbook.playbook_id == playbook_id
    assert playbook.action == action


def test_recovery_closes_pending_incident_without_new_remediation(client, app):
    payload = json.loads((ROOT / "examples" / "network_loop.json").read_text(encoding="utf-8"))
    headers = {"X-Webhook-Token": "test-secret"}
    created = client.post("/api/v1/incidents/zabbix", json=payload, headers=headers)
    assert created.status_code == 200
    with app.app_context():
        incident = db.session.execute(db.select(Incident)).scalar_one()
        incident.processing_status = "WAITING_ADMIN_APPROVAL"
        db.session.commit()
    recovery = copy.deepcopy(payload)
    recovery["event"]["value"] = 0
    recovery["event"]["status"] = "OK"
    response = client.post("/api/v1/incidents/zabbix", json=recovery, headers=headers)
    assert response.get_json()["reason"] == "recovered_before_action"
    with app.app_context():
        incident = db.session.execute(db.select(Incident)).scalar_one()
        assert incident.processing_status == "RECOVERED_BEFORE_ACTION"
        assert db.session.execute(db.select(AuditLog).where(AuditLog.event_type == "ZABBIX_RECOVERY_BEFORE_ACTION")).scalar_one()

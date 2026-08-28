import json

import pytest

from app.services.remediation_config import (
    RemediationConfigError,
    load_quarantine_vlan_id,
)


def test_quarantine_vlan_is_reloaded_after_json_edit(tmp_path):
    path = tmp_path / "remediation.json"
    path.write_text('{"quarantine_vlan_id": 18}', encoding="utf-8")
    assert load_quarantine_vlan_id(path) == 18

    path.write_text('{"quarantine_vlan_id": 40}', encoding="utf-8")
    assert load_quarantine_vlan_id(path) == 40


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"quarantine_vlan_id": True},
        {"quarantine_vlan_id": "18"},
        {"quarantine_vlan_id": 0},
        {"quarantine_vlan_id": 4095},
    ],
)
def test_invalid_quarantine_vlan_never_gets_a_fallback(tmp_path, payload):
    path = tmp_path / "remediation.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(RemediationConfigError):
        load_quarantine_vlan_id(path)


def test_missing_or_malformed_remediation_json_fails_closed(tmp_path):
    missing = tmp_path / "missing.json"
    with pytest.raises(RemediationConfigError):
        load_quarantine_vlan_id(missing)

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(RemediationConfigError):
        load_quarantine_vlan_id(malformed)


def test_health_reports_invalid_remediation_json(app):
    path = app.config["REMEDIATION_CONFIG_PATH"]
    path.write_text('{"quarantine_vlan_id": 9999}', encoding="utf-8")

    response = app.test_client().get("/health")

    body = response.get_json()
    assert body["ok"] is False
    assert body["checks"]["quarantine_vlan"] is False
    assert body["errors"]["quarantine_vlan"] == "RemediationConfigError"

def test_health_is_read_only_and_reports_critical_checks(client, monkeypatch):
    async def forbidden_set(*_args, **_kwargs):
        raise AssertionError("/health must never invoke SNMP SET")

    monkeypatch.setattr(
        "app.snmp.client.SnmpRemediationClient.set_integer", forbidden_set
    )
    response = client.get("/health")
    assert response.status_code == 200
    body = response.get_json()
    assert body["service"] == "OKAPI"
    assert set(body["checks"]) >= {"sqlite", "whitelist", "calendar", "capabilities", "mib", "quarantine_vlan"}
    assert body["snmp_policy"] == "read_only_discovery_lab_validated_writes_only"

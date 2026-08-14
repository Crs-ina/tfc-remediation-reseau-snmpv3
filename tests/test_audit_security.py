from app.services.audit import sanitize


def test_snmp_credentials_are_redacted_from_audit_details():
    details = sanitize(
        {
            "SNMP_AUTH_KEY": "auth-secret",
            "snmp_priv_key": "priv-secret",
            "target": "192.0.2.10",
        }
    )

    assert details == {
        "SNMP_AUTH_KEY": "[REDACTED]",
        "snmp_priv_key": "[REDACTED]",
        "target": "192.0.2.10",
    }

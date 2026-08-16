import asyncio
from pathlib import Path

import pytest

from app.snmp.client import SnmpRemediationClient, SnmpV3Config, SnmpWriteBlocked
from app.snmp.mib_catalog import (
    DOT1Q_PVID,
    DOT1Q_TP_FDB_PORT,
    IF_DESCR,
    SYS_NAME,
)
from app.snmp.mib_registry import MibNotReadyError, MibRegistry


def test_preinstalled_mib_package_is_warmed_and_resolved_symbolically():
    registry = MibRegistry(package="pysnmp_mibs")

    status = registry.warm_up()

    assert status.ready is True
    assert status.resolved_objects >= 6
    assert registry.resolve(DOT1Q_TP_FDB_PORT).symbolic_name == (
        "Q-BRIDGE-MIB::dot1qTpFdbPort"
    )
    assert registry.resolve(IF_DESCR.with_indices(7)).oid[-1] == 7
    assert registry.resolve(DOT1Q_PVID.with_indices(2)).oid[-1] == 2


def test_missing_mib_package_fails_explicitly_without_network_fallback():
    registry = MibRegistry(package="package_mib_absent_test")

    status = registry.warm_up()

    assert status.ready is False
    assert status.error
    with pytest.raises(MibNotReadyError):
        registry.resolve(DOT1Q_PVID.with_indices(2))


def test_missing_local_mib_directory_fails_explicitly(tmp_path: Path):
    registry = MibRegistry(
        package="pysnmp_mibs", local_path=tmp_path / "absent"
    )

    status = registry.warm_up()

    assert status.ready is False
    assert "introuvable" in (status.error or "")


def test_snmpv3_profile_requires_sha256_and_aes256_and_hides_secrets():
    config = SnmpV3Config(
        host="192.0.2.10",
        username="snmp-user",
        auth_key="auth-secret",
        priv_key="priv-secret",
    )
    config.validate()

    rendered = repr(config)
    assert "auth-secret" not in rendered
    assert "priv-secret" not in rendered

    with pytest.raises(ValueError, match="SHA256"):
        SnmpV3Config(
            host="192.0.2.10",
            username="snmp-user",
            auth_key="auth-secret",
            priv_key="priv-secret",
            auth_protocol="SHA",
        ).validate()

    with pytest.raises(ValueError, match="AES256"):
        SnmpV3Config(
            host="192.0.2.10",
            username="snmp-user",
            auth_key="auth-secret",
            priv_key="priv-secret",
            priv_protocol="AES128",
        ).validate()


def test_remediation_client_rejects_missing_authorization_and_non_pvid_object():
    registry = MibRegistry(package="pysnmp_mibs")
    registry.warm_up()
    client = SnmpRemediationClient(
        SnmpV3Config(
            host="192.0.2.10",
            username="snmp-user",
            auth_key="auth-secret",
            priv_key="priv-secret",
        ),
        registry,
    )

    with pytest.raises(SnmpWriteBlocked, match="authorization"):
        asyncio.run(
            client.set_integer(
                DOT1Q_PVID.with_indices(2), 18, write_authorized=False
            )
        )

    with pytest.raises(SnmpWriteBlocked, match="not enabled"):
        asyncio.run(
            client.set_integer(SYS_NAME, 18, write_authorized=True)
        )

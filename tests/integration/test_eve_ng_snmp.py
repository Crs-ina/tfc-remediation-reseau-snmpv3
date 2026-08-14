import asyncio
import os
from time import perf_counter

import pytest

from app.snmp.client import SnmpRemediationClient, SnmpV3Config
from app.snmp.mib_catalog import DOT1Q_PVID, SYS_NAME
from app.snmp.mib_registry import MibRegistry
from app.snmp.target_resolver import SnmpTargetResolver


pytestmark = pytest.mark.integration


def require_eve_environment() -> tuple[SnmpRemediationClient, int]:
    if os.getenv("RUN_EVE_NG_SNMP_TESTS") != "1":
        pytest.skip("RUN_EVE_NG_SNMP_TESTS=1 requis")
    bridge_port = os.getenv("EVE_NG_BRIDGE_PORT", "").strip()
    if not bridge_port:
        pytest.skip("EVE_NG_BRIDGE_PORT requis")
    config = SnmpV3Config.from_env()
    registry = MibRegistry(package=os.getenv("SNMP_MIB_PACKAGE", "pysnmp_mibs"))
    status = registry.warm_up()
    if not status.ready:
        pytest.fail(f"MIB locales indisponibles: {status.error}")
    return SnmpRemediationClient(config, registry), int(bridge_port)


def test_eve_ng_snmpv3_authpriv_can_read_symbolic_mibs():
    client, bridge_port = require_eve_environment()

    sys_name = asyncio.run(client.read_scalar(SYS_NAME))
    pvid = int(
        asyncio.run(client.read_scalar(DOT1Q_PVID.with_indices(bridge_port)))
    )

    assert sys_name
    assert pvid in {10, 18}


def test_eve_ng_resolves_reference_mac_and_reports_identification_times():
    client, bridge_port = require_eve_environment()
    target_mac = os.getenv("EVE_NG_TARGET_MAC", "00:50:79:66:68:03")
    expected_interface = os.getenv("EVE_NG_EXPECTED_INTERFACE", "Ethernet2")
    runs = int(os.getenv("EVE_NG_PERFORMANCE_RUNS", "3"))
    durations: list[float] = []

    for _run in range(runs):
        started = perf_counter()
        resolution = asyncio.run(
            SnmpTargetResolver(client).resolve(target_mac)
        )
        durations.append(perf_counter() - started)
        assert resolution.bridge_port == bridge_port
        assert resolution.interface_name == expected_interface
        assert resolution.previous_pvid in {10, 18}

    # Donnees visibles avec pytest -s; aucun seuil <10 s n'est affirme avant
    # l'execution dans le laboratoire de reference.
    print({"identification_seconds": durations})


def test_eve_ng_explicit_lab_sequence_vlan_10_to_18_to_10():
    client, bridge_port = require_eve_environment()
    if os.getenv("RUN_EVE_NG_SNMP_WRITE_TESTS") != "1":
        pytest.skip("RUN_EVE_NG_SNMP_WRITE_TESTS=1 requis")
    if os.getenv("EVE_NG_ADMIN_APPROVED") != "YES":
        pytest.skip("EVE_NG_ADMIN_APPROVED=YES requis")
    if os.getenv("EVE_NG_ROLLBACK_EXPLICIT") != "YES":
        pytest.skip("EVE_NG_ROLLBACK_EXPLICIT=YES requis")
    pvid_ref = DOT1Q_PVID.with_indices(bridge_port)
    initial = int(asyncio.run(client.read_scalar(pvid_ref)))
    if initial != 10:
        pytest.skip(f"PVID initial attendu 10, observe {initial}")

    try:
        asyncio.run(client.set_integer(pvid_ref, 18, write_authorized=True))
        assert int(asyncio.run(client.read_scalar(pvid_ref))) == 18
    finally:
        # Ce retour est explicitement demande par EVE_NG_ROLLBACK_EXPLICIT=YES.
        asyncio.run(client.set_integer(pvid_ref, 10, write_authorized=True))
    assert int(asyncio.run(client.read_scalar(pvid_ref))) == 10

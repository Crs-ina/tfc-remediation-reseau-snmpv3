import asyncio

import pytest

from app.snmp.client import SnmpWalkEntry
from app.snmp.mib_catalog import (
    DOT1D_BASE_PORT_IF_INDEX,
    DOT1Q_PVID,
    DOT1Q_TP_FDB_PORT,
    IF_DESCR,
    MibObjectRef,
)
from app.snmp.target_resolver import (
    AmbiguousTargetError,
    KnownPortHint,
    SnmpTargetResolver,
    normalize_mac,
    parse_qbridge_fdb_entry,
)


TARGET_MAC_SUFFIX = (0, 80, 121, 102, 104, 3)


def fdb_row(vlan_id: int, bridge_port: int) -> SnmpWalkEntry:
    return SnmpWalkEntry(
        object_ref=DOT1Q_TP_FDB_PORT,
        oid=(1, 3, 6, vlan_id, *TARGET_MAC_SUFFIX),
        suffix=(vlan_id, *TARGET_MAC_SUFFIX),
        value=str(bridge_port),
    )


class FakeResolverClient:
    def __init__(self, rows: list[SnmpWalkEntry]) -> None:
        self.rows = rows
        self.walk_calls = 0
        self.reads: list[MibObjectRef] = []

    async def walk(
        self, column_ref: MibObjectRef, *, max_rows: int = 4096
    ) -> list[SnmpWalkEntry]:
        self.walk_calls += 1
        assert column_ref == DOT1Q_TP_FDB_PORT
        return self.rows

    async def read_scalar(self, object_ref: MibObjectRef) -> str:
        self.reads.append(object_ref)
        if object_ref.key == DOT1Q_TP_FDB_PORT.key:
            return "2"
        if object_ref.key == DOT1D_BASE_PORT_IF_INDEX.key:
            return "7"
        if object_ref.key == IF_DESCR.key:
            return "Ethernet2"
        if object_ref.key == DOT1Q_PVID.key:
            return "10"
        raise AssertionError(f"Lecture inattendue: {object_ref}")


@pytest.mark.parametrize(
    "raw",
    [
        "00:50:79:66:68:03",
        "00-50-79-66-68-03",
        "0050.7966.6803",
        "005079666803",
    ],
)
def test_mac_normalization_accepts_common_formats(raw: str):
    assert normalize_mac(raw) == "00:50:79:66:68:03"


def test_qbridge_fdb_parser_extracts_vlan_mac_and_bridge_port():
    parsed = parse_qbridge_fdb_entry(fdb_row(10, 2))

    assert parsed.vlan_id == 10
    assert parsed.mac_address == "00:50:79:66:68:03"
    assert parsed.bridge_port == 2


def test_full_resolution_maps_bridge_port_ifindex_interface_and_pvid():
    client = FakeResolverClient([fdb_row(10, 2)])

    result = asyncio.run(
        SnmpTargetResolver(client).resolve("0050.7966.6803")
    )

    assert result.vlan_id == 10
    assert result.bridge_port == 2
    assert result.if_index == 7
    assert result.interface_name == "Ethernet2"
    assert result.previous_pvid == 10
    assert result.cache_hit is False
    assert client.walk_calls == 1


def test_known_port_uses_targeted_get_and_skips_full_fdb_walk():
    client = FakeResolverClient([fdb_row(10, 2)])

    result = asyncio.run(
        SnmpTargetResolver(client).resolve(
            "00:50:79:66:68:03",
            known_port=KnownPortHint(
                bridge_port=2,
                vlan_id=10,
                interface_name="Ethernet2",
            ),
        )
    )

    assert result.cache_hit is True
    assert client.walk_calls == 0
    assert client.reads[0] == DOT1Q_TP_FDB_PORT.with_indices(
        10, *TARGET_MAC_SUFFIX
    )


def test_ambiguous_fdb_location_blocks_resolution():
    client = FakeResolverClient([fdb_row(10, 2), fdb_row(20, 3)])

    with pytest.raises(AmbiguousTargetError):
        asyncio.run(
            SnmpTargetResolver(client).resolve("00:50:79:66:68:03")
        )

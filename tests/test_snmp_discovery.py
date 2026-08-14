import asyncio
import inspect

from app.snmp.client import (
    SnmpReadClient,
    SnmpRemediationClient,
    SnmpTransportError,
    SnmpUnsupportedObject,
)
from app.snmp.discovery import discover_snmp_capabilities
from app.snmp.mib_catalog import MIB_PROBES, MibObjectRef


class FakeSnmpClient:
    def __init__(self, unsupported: set[str] | None = None) -> None:
        self.unsupported = unsupported or set()

    async def read_scalar(self, object_ref: MibObjectRef) -> str:
        return "123456"

    async def read_first(self, column_ref: MibObjectRef) -> tuple[str, str]:
        if column_ref.key in self.unsupported:
            raise SnmpUnsupportedObject("noSuchObject")
        return f"{column_ref.key}.1", "sample"


class OfflineSnmpClient(FakeSnmpClient):
    async def read_scalar(self, object_ref: MibObjectRef) -> str:
        raise SnmpTransportError("timeout")


def test_discovery_reports_supported_and_unsupported_objects():
    unsupported_oid = MIB_PROBES[-1].object_ref.key
    report = asyncio.run(
        discover_snmp_capabilities(
            FakeSnmpClient({unsupported_oid}), target="192.0.2.10"
        )
    )
    assert report.read_only is True
    assert report.security_level == "authPriv"
    assert report.connectivity["status"] == "SUPPORTED"
    assert report.mibs["IP-MIB"][0].status == "UNSUPPORTED"


def test_objects_are_not_tested_when_connectivity_fails():
    report = asyncio.run(
        discover_snmp_capabilities(OfflineSnmpClient(), target="192.0.2.10")
    )
    assert report.connectivity["status"] == "ERROR"
    statuses = {
        item.status for group in report.mibs.values() for item in group
    }
    assert statuses == {"NOT_TESTED"}


def test_snmp_client_contains_no_write_operation():
    source = inspect.getsource(SnmpReadClient)
    assert "set_cmd" not in source
    assert not hasattr(SnmpReadClient, "set_integer")
    assert hasattr(SnmpRemediationClient, "set_integer")

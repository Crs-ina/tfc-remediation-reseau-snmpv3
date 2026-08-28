from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Protocol

from .client import SnmpClientError, SnmpUnsupportedObject
from .mib_catalog import MIB_PROBES, SYS_UP_TIME, MibObjectRef
from .value_formatting import format_mib_value


class DiscoveryClient(Protocol):
    async def read_scalar(self, object_ref: MibObjectRef) -> str: ...

    async def read_first(
        self, column_ref: MibObjectRef
    ) -> tuple[str, str]: ...


@dataclass(frozen=True)
class ObjectDiscoveryResult:
    object_name: str
    status: str
    source: str
    observed_oid: str | None = None
    sample_value: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class DiscoveryReport:
    target: str
    generated_at: str
    security_level: str
    read_only: bool
    connectivity: dict[str, str | None]
    mibs: dict[str, list[ObjectDiscoveryResult]]

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "generated_at": self.generated_at,
            "security_level": self.security_level,
            "read_only": self.read_only,
            "connectivity": self.connectivity,
            "mibs": {
                mib: [
                    {
                        **asdict(result),
                        "sample_value": (
                            format_mib_value(
                                f"{mib}::{result.object_name}",
                                result.sample_value,
                            )
                            if result.sample_value is not None
                            else None
                        ),
                    }
                    for result in results
                ]
                for mib, results in self.mibs.items()
            },
        }


async def discover_snmp_capabilities(
    client: DiscoveryClient,
    *,
    target: str,
) -> DiscoveryReport:
    generated_at = datetime.now(timezone.utc).isoformat()
    mibs: dict[str, list[ObjectDiscoveryResult]] = {}

    try:
        uptime = await client.read_scalar(SYS_UP_TIME)
        connectivity: dict[str, str | None] = {
            "status": "SUPPORTED",
            "sys_uptime": format_mib_value(SYS_UP_TIME.key, uptime),
            "error": None,
        }
    except Exception as exc:
        connectivity = {"status": "ERROR", "sys_uptime": None, "error": str(exc)}
        for probe in MIB_PROBES:
            mibs.setdefault(probe.mib, []).append(
                ObjectDiscoveryResult(
                    object_name=probe.object_name,
                    status="NOT_TESTED",
                    source=probe.source,
                    error="connectivity_test_failed",
                )
            )
        return DiscoveryReport(
            target=target,
            generated_at=generated_at,
            security_level="authPriv",
            read_only=True,
            connectivity=connectivity,
            mibs=mibs,
        )

    for probe in MIB_PROBES:
        try:
            observed_oid, value = await client.read_first(probe.object_ref)
            result = ObjectDiscoveryResult(
                object_name=probe.object_name,
                status="SUPPORTED",
                source=probe.source,
                observed_oid=observed_oid,
                sample_value=value,
            )
        except SnmpUnsupportedObject as exc:
            result = ObjectDiscoveryResult(
                object_name=probe.object_name,
                status="UNSUPPORTED",
                source=probe.source,
                error=str(exc),
            )
        except SnmpClientError as exc:
            result = ObjectDiscoveryResult(
                object_name=probe.object_name,
                status="ERROR",
                source=probe.source,
                error=str(exc),
            )
        except Exception as exc:
            result = ObjectDiscoveryResult(
                object_name=probe.object_name,
                status="ERROR",
                source=probe.source,
                error=str(exc),
            )
        mibs.setdefault(probe.mib, []).append(result)

    return DiscoveryReport(
        target=target,
        generated_at=generated_at,
        security_level="authPriv",
        read_only=True,
        connectivity=connectivity,
        mibs=mibs,
    )


def discover_snmp_capabilities_sync(
    client: DiscoveryClient,
    *,
    target: str,
) -> DiscoveryReport:
    return asyncio.run(discover_snmp_capabilities(client, target=target))

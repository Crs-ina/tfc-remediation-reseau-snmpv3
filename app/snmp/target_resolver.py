from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from .client import SnmpClientError, SnmpWalkEntry
from .mib_catalog import (
    DOT1D_BASE_PORT_IF_INDEX,
    DOT1Q_PVID,
    DOT1Q_TP_FDB_PORT,
    IF_DESCR,
    MibObjectRef,
)


class TargetResolutionError(RuntimeError):
    pass


class TargetNotFoundError(TargetResolutionError):
    pass


class AmbiguousTargetError(TargetResolutionError):
    pass


class TargetReadClient(Protocol):
    async def read_scalar(self, object_ref: MibObjectRef) -> str: ...

    async def walk(
        self, column_ref: MibObjectRef, *, max_rows: int = 4096
    ) -> list[SnmpWalkEntry]: ...


@dataclass(frozen=True)
class FdbEntry:
    vlan_id: int
    mac_address: str
    bridge_port: int


@dataclass(frozen=True)
class KnownPortHint:
    bridge_port: int
    vlan_id: int | None
    interface_name: str | None


@dataclass(frozen=True)
class TargetResolution:
    target_mac: str
    vlan_id: int
    bridge_port: int
    if_index: int
    interface_name: str
    previous_pvid: int
    cache_hit: bool


def normalize_mac(value: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(compact) != 12 or not re.fullmatch(r"[0-9A-Fa-f]{12}", compact):
        raise ValueError(f"Adresse MAC invalide: {value!r}")
    return ":".join(
        compact[index : index + 2].lower() for index in range(0, 12, 2)
    )


def mac_to_index(mac_address: str) -> tuple[int, ...]:
    return tuple(int(part, 16) for part in normalize_mac(mac_address).split(":"))


def parse_qbridge_fdb_entry(entry: SnmpWalkEntry) -> FdbEntry:
    if entry.object_ref.key != DOT1Q_TP_FDB_PORT.key:
        raise ValueError(f"Objet Q-BRIDGE inattendu: {entry.object_ref.key}")
    # INDEX { dot1qFdbId, dot1qTpFdbAddress } : un FDB ID puis 6 octets MAC.
    if len(entry.suffix) != 7:
        raise ValueError(f"Index dot1qTpFdbPort invalide: {entry.suffix}")
    vlan_id = int(entry.suffix[0])
    mac_address = ":".join(f"{octet:02x}" for octet in entry.suffix[1:])
    try:
        bridge_port = int(entry.value)
    except ValueError as exc:
        raise ValueError(f"bridge_port invalide: {entry.value!r}") from exc
    return FdbEntry(
        vlan_id=vlan_id,
        mac_address=mac_address,
        bridge_port=bridge_port,
    )


class SnmpTargetResolver:
    def __init__(self, client: TargetReadClient) -> None:
        self.client = client

    async def resolve(
        self,
        mac_address: str,
        *,
        known_port: KnownPortHint | None = None,
    ) -> TargetResolution:
        target_mac = normalize_mac(mac_address)
        fdb_entry: FdbEntry | None = None
        cache_hit = False

        if known_port and known_port.vlan_id is not None:
            cached_ref = DOT1Q_TP_FDB_PORT.with_indices(
                known_port.vlan_id, *mac_to_index(target_mac)
            )
            try:
                observed_port = int(await self.client.read_scalar(cached_ref))
                if observed_port == known_port.bridge_port:
                    fdb_entry = FdbEntry(
                        vlan_id=known_port.vlan_id,
                        mac_address=target_mac,
                        bridge_port=observed_port,
                    )
                    cache_hit = True
            except (SnmpClientError, ValueError):
                # Cache obsolete ou non pris en charge : retour au WALK complet.
                pass

        if fdb_entry is None:
            rows = await self.client.walk(DOT1Q_TP_FDB_PORT)
            matches = [
                parsed
                for parsed in (parse_qbridge_fdb_entry(row) for row in rows)
                if parsed.mac_address == target_mac
            ]
            if not matches:
                raise TargetNotFoundError(
                    f"MAC absente de Q-BRIDGE-MIB::dot1qTpFdbPort: {target_mac}"
                )
            unique_locations = {
                (match.vlan_id, match.bridge_port) for match in matches
            }
            if len(unique_locations) != 1:
                raise AmbiguousTargetError(
                    f"MAC presente sur plusieurs entrees incompatibles: {sorted(unique_locations)}"
                )
            fdb_entry = matches[0]

        try:
            if_index = int(
                await self.client.read_scalar(
                    DOT1D_BASE_PORT_IF_INDEX.with_indices(fdb_entry.bridge_port)
                )
            )
            interface_name = await self.client.read_scalar(
                IF_DESCR.with_indices(if_index)
            )
            previous_pvid = int(
                await self.client.read_scalar(
                    DOT1Q_PVID.with_indices(fdb_entry.bridge_port)
                )
            )
        except (SnmpClientError, ValueError) as exc:
            raise TargetResolutionError(
                f"Chaine bridge_port -> ifIndex -> interface/PVID incomplete: {exc}"
            ) from exc

        return TargetResolution(
            target_mac=target_mac,
            vlan_id=fdb_entry.vlan_id,
            bridge_port=fdb_entry.bridge_port,
            if_index=if_index,
            interface_name=interface_name,
            previous_pvid=previous_pvid,
            cache_hit=cache_hit,
        )

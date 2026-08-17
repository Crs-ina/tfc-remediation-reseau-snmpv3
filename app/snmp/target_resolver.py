from __future__ import annotations

import re
from ipaddress import IPv4Address
from dataclasses import dataclass
from typing import Protocol

from .client import SnmpClientError, SnmpWalkEntry
from .mib_catalog import (
    DOT1D_BASE_PORT_IF_INDEX,
    DOT1Q_PVID,
    DOT1Q_TP_FDB_PORT,
    IF_DESCR,
    IP_NET_TO_PHYSICAL_ADDRESS,
    MibObjectRef,
)


class TargetResolutionError(RuntimeError):
    pass


class TargetNotFoundError(TargetResolutionError):
    pass


class AmbiguousTargetError(TargetResolutionError):
    pass


class TargetMismatchError(TargetResolutionError):
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


def parse_ip_net_to_physical_entry(entry: SnmpWalkEntry) -> tuple[str, str] | None:
    """Parse the standard IPv4 index/value without maintaining a numeric OID."""

    if entry.object_ref.key != IP_NET_TO_PHYSICAL_ADDRESS.key:
        raise ValueError(f"Objet IP-MIB inattendu: {entry.object_ref.key}")
    suffix = entry.suffix
    if len(suffix) >= 7 and suffix[-6] == 1 and suffix[-5] == 4:
        octets = suffix[-4:]
    elif len(suffix) >= 6 and suffix[-5] == 1:
        # Some agents render InetAddress indexes without the explicit length.
        octets = suffix[-4:]
    else:
        return None
    if any(octet < 0 or octet > 255 for octet in octets):
        return None
    raw_mac = entry.value.strip()
    if raw_mac.lower().startswith("0x"):
        raw_mac = raw_mac[2:]
    return str(IPv4Address(bytes(octets))), normalize_mac(raw_mac)


class SnmpTargetResolver:
    def __init__(self, client: TargetReadClient) -> None:
        self.client = client

    async def resolve(
        self,
        mac_address: str | None,
        *,
        ip_address: str | None = None,
        known_port: KnownPortHint | None = None,
    ) -> TargetResolution:
        mac_hint = normalize_mac(mac_address) if mac_address else None
        if ip_address:
            observed_mac = await self._ip_to_mac(ip_address)
            if mac_hint and observed_mac != mac_hint:
                raise TargetMismatchError(
                    f"IP-MIB maps {ip_address} to {observed_mac}, not {mac_hint}"
                )
            target_mac = observed_mac
        elif mac_hint:
            target_mac = mac_hint
        else:
            raise TargetNotFoundError("Neither an IP nor a MAC target hint is available.")
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

    async def _ip_to_mac(self, ip_address: str) -> str:
        try:
            expected_ip = str(IPv4Address(ip_address))
        except ValueError as exc:
            raise TargetResolutionError(f"Invalid target IPv4 address: {ip_address}") from exc
        rows = await self.client.walk(IP_NET_TO_PHYSICAL_ADDRESS)
        matches: set[str] = set()
        for row in rows:
            try:
                parsed = parse_ip_net_to_physical_entry(row)
            except ValueError as exc:
                raise TargetResolutionError(f"Invalid IP-MIB target entry: {exc}") from exc
            if parsed and parsed[0] == expected_ip:
                matches.add(parsed[1])
        if not matches:
            raise TargetNotFoundError(
                f"IP absent from IP-MIB::ipNetToPhysicalPhysAddress: {expected_ip}"
            )
        if len(matches) != 1:
            raise AmbiguousTargetError(
                f"IP maps to multiple MAC addresses: {sorted(matches)}"
            )
        return matches.pop()

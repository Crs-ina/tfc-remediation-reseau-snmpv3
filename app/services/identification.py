from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class ReadOnlyTargetResolver(Protocol):
    def ip_to_mac(self, ip_address: str) -> str | None: ...

    def mac_to_bridge_port(self, mac_address: str) -> int | None: ...

    def bridge_port_to_ifindex(self, bridge_port: int) -> int | None: ...

    def ifindex_to_interface(self, ifindex: int) -> str | None: ...


@dataclass(frozen=True)
class IdentificationResult:
    confirmed: bool
    attempts: int
    client_ip: str | None = None
    client_mac: str | None = None
    bridge_port: int | None = None
    ifindex: int | None = None
    interface: str | None = None
    error: str | None = None


def identify_target(
    resolver: ReadOnlyTargetResolver,
    *,
    client_ip: str | None,
    client_mac_hint: str | None,
    max_attempts: int = 2,
) -> IdentificationResult:
    last_error = "target_not_resolved"
    attempts_limit = max(1, min(int(max_attempts), 2))
    for attempt in range(1, attempts_limit + 1):
        observed_mac = resolver.ip_to_mac(client_ip) if client_ip else client_mac_hint
        if not observed_mac:
            last_error = "mac_not_resolved"
            continue
        if client_mac_hint and observed_mac.lower() != client_mac_hint.lower():
            last_error = "zabbix_mac_hint_not_confirmed"
            continue

        bridge_port = resolver.mac_to_bridge_port(observed_mac)
        if bridge_port is None:
            last_error = "bridge_port_not_resolved"
            continue
        ifindex = resolver.bridge_port_to_ifindex(bridge_port)
        if ifindex is None:
            last_error = "ifindex_not_resolved"
            continue
        interface = resolver.ifindex_to_interface(ifindex)
        if not interface:
            last_error = "physical_interface_not_resolved"
            continue

        return IdentificationResult(
            confirmed=True,
            attempts=attempt,
            client_ip=client_ip,
            client_mac=observed_mac,
            bridge_port=bridge_port,
            ifindex=ifindex,
            interface=interface,
        )

    return IdentificationResult(
        confirmed=False,
        attempts=attempts_limit,
        client_ip=client_ip,
        client_mac=client_mac_hint,
        error=last_error,
    )


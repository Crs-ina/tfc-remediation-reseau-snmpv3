from app.services.identification import identify_target


class MissingTargetResolver:
    def __init__(self) -> None:
        self.ip_reads = 0

    def ip_to_mac(self, _ip_address: str):
        self.ip_reads += 1
        return None

    def mac_to_bridge_port(self, _mac_address: str):
        raise AssertionError("MAC lookup must stop when IP resolution failed")

    def bridge_port_to_ifindex(self, _bridge_port: int):
        raise AssertionError

    def ifindex_to_interface(self, _ifindex: int):
        raise AssertionError


def test_target_identification_stops_after_exactly_two_attempts() -> None:
    resolver = MissingTargetResolver()

    result = identify_target(
        resolver,
        client_ip="192.0.2.50",
        client_mac_hint=None,
        max_attempts=2,
    )

    assert result.confirmed is False
    assert result.attempts == 2
    assert resolver.ip_reads == 2

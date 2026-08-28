import pytest

from app.snmp.mib_catalog import (
    DOT1D_BASE_PORT_IF_INDEX,
    DOT1D_STP_PORT_STATE,
    DOT1D_TP_FDB_PORT,
    DOT1Q_PVID,
    IF_ADMIN_STATUS,
    IF_OPER_STATUS,
    SYS_UP_TIME,
)
from app.snmp.value_formatting import (
    format_if_admin_status,
    format_if_oper_status,
    format_mib_value,
    parse_safe_if_admin_status,
)


@pytest.mark.parametrize(
    ("raw", "display"),
    [(1, "UP"), ("down(2)", "DOWN"), (3, "TESTING")],
)
def test_if_admin_status_uses_rfc_2863_labels(raw, display):
    assert format_if_admin_status(raw) == display
    assert format_mib_value(IF_ADMIN_STATUS.key, raw) == display


@pytest.mark.parametrize(
    ("raw", "display"),
    [
        (1, "UP"),
        (2, "DOWN"),
        (3, "TESTING"),
        (4, "UNKNOWN"),
        (5, "DORMANT"),
        (6, "NOT PRESENT"),
        (7, "LOWER LAYER DOWN"),
    ],
)
def test_if_oper_status_uses_rfc_2863_labels(raw, display):
    assert format_if_oper_status(raw) == display


def test_bridge_and_vlan_identifiers_have_context():
    assert format_mib_value(DOT1D_STP_PORT_STATE.key, 5) == "FORWARDING"
    assert format_mib_value(DOT1D_TP_FDB_PORT.key, 0) == "NOT LEARNED"
    assert format_mib_value(DOT1D_TP_FDB_PORT.key, 8) == "BRIDGE PORT 8"
    assert format_mib_value(DOT1D_BASE_PORT_IF_INDEX.key, 12) == "INTERFACE INDEX 12"
    assert format_mib_value(DOT1Q_PVID.key, 18) == "VLAN 18"
    assert format_mib_value(SYS_UP_TIME.key, 12345) == "TIMETICKS 12345"


def test_unknown_enumeration_is_explicit_and_safe_rollback_parser_is_strict():
    assert format_if_admin_status(7) == "UNKNOWN (raw value: 7)"
    assert parse_safe_if_admin_status("up(1)") == 1
    assert parse_safe_if_admin_status("DOWN") == 2
    with pytest.raises(ValueError):
        parse_safe_if_admin_status(3)

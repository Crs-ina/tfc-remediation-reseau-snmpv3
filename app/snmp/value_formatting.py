from __future__ import annotations

import re
from typing import Any

from .mib_catalog import (
    DOT1D_BASE_PORT_IF_INDEX,
    DOT1D_STP_PORT_STATE,
    DOT1D_TP_FDB_PORT,
    DOT1Q_PVID,
    DOT1Q_TP_FDB_PORT,
    IF_ADMIN_STATUS,
    IF_LAST_CHANGE,
    IF_OPER_STATUS,
    SYS_UP_TIME,
)


IF_ADMIN_STATUS_LABELS = {
    1: "UP",
    2: "DOWN",
    3: "TESTING",
}

IF_OPER_STATUS_LABELS = {
    1: "UP",
    2: "DOWN",
    3: "TESTING",
    4: "UNKNOWN",
    5: "DORMANT",
    6: "NOT PRESENT",
    7: "LOWER LAYER DOWN",
}

DOT1D_STP_PORT_STATE_LABELS = {
    1: "DISABLED",
    2: "BLOCKING",
    3: "LISTENING",
    4: "LEARNING",
    5: "FORWARDING",
    6: "BROKEN",
}

_ENUM_PATTERN = re.compile(r"^[^()]+\((-?\d+)\)$")


def numeric_value(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        match = _ENUM_PATTERN.fullmatch(text)
        return int(match.group(1)) if match else None


def _format_enum(
    value: Any,
    labels: dict[int, str],
    *,
    aliases: dict[str, int] | None = None,
) -> str:
    number = numeric_value(value)
    if number is None and value is not None and aliases:
        number = aliases.get(str(value).strip().lower())
    if number in labels:
        return labels[number]
    if value is None or str(value).strip() == "":
        return "UNKNOWN"
    return f"UNKNOWN (raw value: {value})"


def format_if_admin_status(value: Any) -> str:
    return _format_enum(
        value,
        IF_ADMIN_STATUS_LABELS,
        aliases={"up": 1, "down": 2, "testing": 3},
    )


def format_if_oper_status(value: Any) -> str:
    return _format_enum(
        value,
        IF_OPER_STATUS_LABELS,
        aliases={
            "up": 1,
            "down": 2,
            "testing": 3,
            "unknown": 4,
            "dormant": 5,
            "not present": 6,
            "notpresent": 6,
            "lower layer down": 7,
            "lowerlayerdown": 7,
        },
    )


def format_stp_port_state(value: Any) -> str:
    return _format_enum(
        value,
        DOT1D_STP_PORT_STATE_LABELS,
        aliases={label.lower(): number for number, label in DOT1D_STP_PORT_STATE_LABELS.items()},
    )


def format_vlan_id(value: Any) -> str:
    number = numeric_value(value)
    if number is not None and 1 <= number <= 4094:
        return f"VLAN {number}"
    if value is None or str(value).strip() == "":
        return "UNKNOWN VLAN"
    return f"UNKNOWN VLAN (raw value: {value})"


def parse_safe_if_admin_status(value: Any) -> int:
    number = numeric_value(value)
    if number is None:
        aliases = {"up": 1, "down": 2}
        number = aliases.get(str(value).strip().lower())
    if number not in {1, 2}:
        raise ValueError(
            "The saved administrative state is not a safe rollback value."
        )
    return number


def format_mib_value(symbolic_name: str, value: Any) -> str:
    if symbolic_name == IF_ADMIN_STATUS.key:
        return format_if_admin_status(value)
    if symbolic_name == IF_OPER_STATUS.key:
        return format_if_oper_status(value)
    if symbolic_name == DOT1D_STP_PORT_STATE.key:
        return format_stp_port_state(value)
    if symbolic_name == DOT1Q_PVID.key:
        return format_vlan_id(value)
    if symbolic_name in {DOT1D_TP_FDB_PORT.key, DOT1Q_TP_FDB_PORT.key}:
        number = numeric_value(value)
        if number == 0:
            return "NOT LEARNED"
        if number is not None and number > 0:
            return f"BRIDGE PORT {number}"
    if symbolic_name == DOT1D_BASE_PORT_IF_INDEX.key:
        number = numeric_value(value)
        if number is not None and number > 0:
            return f"INTERFACE INDEX {number}"
    if symbolic_name in {IF_LAST_CHANGE.key, SYS_UP_TIME.key}:
        number = numeric_value(value)
        if number is not None and number >= 0:
            return f"TIMETICKS {number}"
    return str(value)


def format_action_value(action_type: str, value: Any) -> str:
    if action_type == "QUARANTINE_VLAN":
        return format_vlan_id(value)
    if action_type in {"SHUTDOWN_PORT", "REACTIVATE_PORT"}:
        return format_if_admin_status(value)
    return str(value)

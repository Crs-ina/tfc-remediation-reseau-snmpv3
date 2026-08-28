from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


class RemediationConfigError(ValueError):
    """The external remediation configuration is missing or unsafe."""


@dataclass(frozen=True)
class RemediationConfig:
    quarantine_vlan_id: int


def load_remediation_config(path: Path) -> RemediationConfig:
    """Load non-sensitive remediation settings without applying fallbacks."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RemediationConfigError(
            f"Unable to read a valid remediation configuration from {path}."
        ) from exc

    if not isinstance(payload, dict):
        raise RemediationConfigError(
            "The remediation configuration must be a JSON object."
        )

    quarantine_vlan_id = payload.get("quarantine_vlan_id")
    if isinstance(quarantine_vlan_id, bool) or not isinstance(
        quarantine_vlan_id, int
    ):
        raise RemediationConfigError(
            "quarantine_vlan_id must be an integer between 1 and 4094."
        )
    if not 1 <= quarantine_vlan_id <= 4094:
        raise RemediationConfigError(
            "quarantine_vlan_id must be between 1 and 4094."
        )

    return RemediationConfig(quarantine_vlan_id=quarantine_vlan_id)


def load_quarantine_vlan_id(path: Path) -> int:
    return load_remediation_config(path).quarantine_vlan_id

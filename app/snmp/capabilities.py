from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


class CapabilityError(RuntimeError):
    pass


@dataclass(frozen=True)
class SnmpWritePolicy:
    scope: str
    auth_protocol: str
    priv_protocol: str
    objects: dict[str, dict[str, str]]

    def write_status(self, symbolic_name: str) -> str:
        return self.objects.get(symbolic_name, {}).get("write", "DENIED")


@lru_cache(maxsize=8)
def load_write_policy(path: Path) -> SnmpWritePolicy:
    """Load the vendor-neutral SNMP write policy.

    Runtime authorization is based only on the requested MIB object and the
    configured SNMPv3 security profile. Equipment brand and model are not part
    of the authorization decision.
    """

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    definition = data.get("write_policy")
    if not isinstance(definition, dict):
        raise CapabilityError("Missing write_policy in SNMP capabilities file.")

    security = definition.get("security")
    objects = definition.get("objects")
    if not isinstance(security, dict) or not isinstance(objects, dict):
        raise CapabilityError("Invalid SNMP write policy structure.")

    return SnmpWritePolicy(
        scope=str(definition.get("scope", "vendor-neutral SNMPv3 write policy")),
        auth_protocol=str(security.get("auth_protocol", "")),
        priv_protocol=str(security.get("priv_protocol", "")),
        objects=dict(objects),
    )


@lru_cache(maxsize=8)
def load_capabilities(path: Path) -> dict[str, SnmpWritePolicy]:
    """Compatibility wrapper used by the health endpoint."""

    return {"write_policy": load_write_policy(Path(path))}


def require_snmp_write_allowed(
    path: Path,
    *,
    model: str | None,
    symbolic_name: str,
    auth_protocol: str,
    priv_protocol: str,
) -> SnmpWritePolicy:
    """Authorize a SET from object/security capabilities, never from a model list.

    ``model`` remains in the signature only to preserve existing callers. It is
    inventory metadata and is deliberately ignored for authorization.
    """

    _ = model
    policy = load_write_policy(Path(path))

    if policy.write_status(symbolic_name) != "ALLOWED":
        raise CapabilityError(
            f"SNMP write is not allowed by policy for object: {symbolic_name}"
        )
    if (
        policy.auth_protocol != auth_protocol
        or policy.priv_protocol != priv_protocol
    ):
        raise CapabilityError(
            "SNMP protocols do not match the configured write policy "
            f"({policy.auth_protocol}/{policy.priv_protocol})."
        )
    return policy

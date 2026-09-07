from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


class CapabilityError(RuntimeError):
    pass


@dataclass(frozen=True)
class PlatformCapabilities:
    model: str
    scope: str
    auth_protocol: str
    priv_protocol: str
    objects: dict[str, dict[str, str]]

    def write_status(self, symbolic_name: str) -> str:
        return self.objects.get(symbolic_name, {}).get("write", "TO_BE_VALIDATED")


@lru_cache(maxsize=8)
def load_capabilities(path: Path) -> dict[str, PlatformCapabilities]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    result: dict[str, PlatformCapabilities] = {}
    for model, definition in data["platforms"].items():
        security = definition["security"]
        result[model] = PlatformCapabilities(
            model=model,
            scope=str(definition["scope"]),
            auth_protocol=str(security["auth_protocol"]),
            priv_protocol=str(security["priv_protocol"]),
            objects=dict(definition["objects"]),
        )
    return result


@lru_cache(maxsize=8)
def load_write_policy(path: Path) -> PlatformCapabilities:
    """Load the vendor-neutral SNMP write policy.

    The platform profiles remain available for inventory and explicit safety
    exceptions, but an unknown model is no longer rejected merely because it
    is absent from the platform list. Older capability files without
    ``write_policy`` are supported by deriving the generic policy from their
    LAB_VALIDATED objects.
    """

    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    definition = data.get("write_policy")

    if definition is not None:
        security = definition["security"]
        return PlatformCapabilities(
            model="GENERIC_SNMPV3",
            scope=str(definition["scope"]),
            auth_protocol=str(security["auth_protocol"]),
            priv_protocol=str(security["priv_protocol"]),
            objects=dict(definition["objects"]),
        )

    validated_objects: dict[str, dict[str, str]] = {}
    protocol_pairs: set[tuple[str, str]] = set()

    for platform in load_capabilities(path).values():
        for symbolic_name, object_capability in platform.objects.items():
            if object_capability.get("write") != "LAB_VALIDATED":
                continue
            validated_objects[symbolic_name] = dict(object_capability)
            protocol_pairs.add((platform.auth_protocol, platform.priv_protocol))

    if not validated_objects:
        raise CapabilityError(
            "No LAB_VALIDATED SNMP write objects are configured."
        )
    if len(protocol_pairs) != 1:
        raise CapabilityError(
            "Legacy capability profiles contain incompatible SNMP security settings; "
            "define a top-level write_policy."
        )

    auth_protocol, priv_protocol = next(iter(protocol_pairs))
    return PlatformCapabilities(
        model="GENERIC_SNMPV3",
        scope="Derived vendor-neutral policy from LAB_VALIDATED objects",
        auth_protocol=auth_protocol,
        priv_protocol=priv_protocol,
        objects=validated_objects,
    )


def require_lab_validated_write(
    path: Path,
    *,
    model: str | None,
    symbolic_name: str,
    auth_protocol: str,
    priv_protocol: str,
) -> PlatformCapabilities:
    """Authorize a SET from object/security capabilities instead of a model whitelist.

    A model does not have to exist in ``platforms`` anymore. If a known platform
    is explicitly present and the requested object is still marked
    ``TO_BE_VALIDATED`` (or otherwise not LAB_VALIDATED), that explicit safety
    information remains authoritative and the SET is blocked.
    """

    path = Path(path)
    platforms = load_capabilities(path)
    known_platform = platforms.get(model) if model else None

    if known_platform is not None:
        object_definition = known_platform.objects.get(symbolic_name)
        if (
            object_definition is not None
            and object_definition.get("write", "TO_BE_VALIDATED") != "LAB_VALIDATED"
        ):
            raise CapabilityError(
                f"Write capability is explicitly not LAB_VALIDATED for {model}: "
                f"{symbolic_name}"
            )

    policy = load_write_policy(path)

    if policy.write_status(symbolic_name) != "LAB_VALIDATED":
        raise CapabilityError(
            f"Write capability is not LAB_VALIDATED by the generic SNMP policy: "
            f"{symbolic_name}"
        )
    if (
        policy.auth_protocol != auth_protocol
        or policy.priv_protocol != priv_protocol
    ):
        raise CapabilityError(
            "SNMP protocols do not match the validated write policy "
            f"({policy.auth_protocol}/{policy.priv_protocol})."
        )
    return policy

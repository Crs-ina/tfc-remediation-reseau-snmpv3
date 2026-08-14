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


def require_lab_validated_write(
    path: Path,
    *,
    model: str | None,
    symbolic_name: str,
    auth_protocol: str,
    priv_protocol: str,
) -> PlatformCapabilities:
    if not model:
        raise CapabilityError("Modele du switch absent: ecriture interdite.")
    platform = load_capabilities(Path(path)).get(model)
    if platform is None:
        raise CapabilityError(
            f"Plateforme non qualifiee pour l'ecriture SNMP: {model}"
        )
    if platform.write_status(symbolic_name) != "LAB_VALIDATED":
        raise CapabilityError(
            f"Capacite d'ecriture non LAB_VALIDATED pour {model}: {symbolic_name}"
        )
    if (
        platform.auth_protocol != auth_protocol
        or platform.priv_protocol != priv_protocol
    ):
        raise CapabilityError(
            "Les protocoles SNMP ne correspondent pas au profil valide "
            f"({platform.auth_protocol}/{platform.priv_protocol})."
        )
    return platform

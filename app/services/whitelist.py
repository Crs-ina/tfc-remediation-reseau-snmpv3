from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WhitelistMatch:
    category: str
    reason: str | None


def find_protected_port(
    path: Path,
    *,
    switch_id: str,
    port_index: int,
) -> WhitelistMatch | None:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    protected_categories = frozenset(
        str(category) for category in data["protected_categories"]
    )
    for entry in data.get("entries", []):
        if (
            str(entry.get("switch_id")) == switch_id
            and int(entry.get("port_index", -1)) == port_index
        ):
            category = str(entry["category"])
            if category not in protected_categories:
                raise ValueError(
                    f"Categorie de whitelist non declaree: {category}"
                )
            return WhitelistMatch(category=category, reason=entry.get("reason"))
    return None


def is_port_protected(path: Path, *, switch_id: str, port_index: int) -> bool:
    return find_protected_port(
        path, switch_id=switch_id, port_index=port_index
    ) is not None

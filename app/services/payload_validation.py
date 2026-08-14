from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


@lru_cache(maxsize=4)
def validator_for(schema_path: str) -> Draft202012Validator:
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_payload(payload: dict, schema_path: Path) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    validator = validator_for(str(schema_path))
    for error in sorted(validator.iter_errors(payload), key=lambda item: list(item.path)):
        errors.append(
            {
                "path": ".".join(str(part) for part in error.absolute_path) or "$",
                "message": error.message,
            }
        )
    return errors


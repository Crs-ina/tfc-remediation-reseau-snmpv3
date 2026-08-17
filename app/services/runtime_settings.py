from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Callable

from flask import Flask, current_app

from app.extensions import db
from app.models import Administrator

from .administrators import reauthenticate_for_critical_action
from .audit import record_audit


def apply_runtime_settings(app: Flask) -> None:
    """Load the persistent dry-run override, failing safe when it is invalid."""

    path = Path(app.config["RUNTIME_SETTINGS_PATH"])
    if not path.exists():
        return
    try:
        app.config["DRY_RUN"] = _read_dry_run(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        app.config["DRY_RUN"] = True
        app.logger.error(
            "Invalid runtime settings; dry-run forced ON: %s", type(exc).__name__
        )


def is_dry_run_enabled() -> bool:
    path = Path(current_app.config["RUNTIME_SETTINGS_PATH"])
    if not path.exists():
        return bool(current_app.config["DRY_RUN"])
    try:
        enabled = _read_dry_run(path)
    except (OSError, ValueError, json.JSONDecodeError):
        # A damaged or tampered runtime setting must never enable writes.
        enabled = True
    current_app.config["DRY_RUN"] = enabled
    return enabled


Reauthenticator = Callable[[Administrator, str], None]


def change_dry_run_mode(
    enabled: bool,
    administrator: Administrator,
    *,
    reauthenticator: Reauthenticator = reauthenticate_for_critical_action,
) -> bool:
    """Persist a dry-run change only after system reauthentication."""

    action = "ENABLE_DRY_RUN" if enabled else "DISABLE_DRY_RUN"
    reauthenticator(administrator, action)
    previous = is_dry_run_enabled()
    _write_runtime_settings(
        Path(current_app.config["RUNTIME_SETTINGS_PATH"]), dry_run=bool(enabled)
    )
    current_app.config["DRY_RUN"] = bool(enabled)
    try:
        record_audit(
            incident_id=None,
            administrator_id=administrator.administrator_id,
            event_type="DRY_RUN_MODE_CHANGED",
            message="Administrator changed the persistent dry-run mode.",
            result_status="SUCCESS",
            details={"previous": previous, "current": bool(enabled)},
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        _write_runtime_settings(
            Path(current_app.config["RUNTIME_SETTINGS_PATH"]), dry_run=previous
        )
        current_app.config["DRY_RUN"] = previous
        raise
    return bool(enabled)


def _read_dry_run(path: Path) -> bool:
    data = json.loads(path.read_text(encoding="utf-8"))
    value = data.get("dry_run")
    if not isinstance(value, bool):
        raise ValueError("runtime dry_run must be a boolean")
    return value


def _write_runtime_settings(path: Path, *, dry_run: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            json.dump({"version": 1, "dry_run": dry_run}, temporary, indent=2)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        if temporary_name and Path(temporary_name).exists():
            try:
                Path(temporary_name).unlink()
            except OSError:
                pass

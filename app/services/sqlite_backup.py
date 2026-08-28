from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.engine import make_url


class SQLiteBackupError(RuntimeError):
    """Raised when a safe SQLite backup cannot be completed."""


def sqlite_database_path(database_uri: str) -> Path:
    """Return the on-disk SQLite path and reject non-file databases."""

    try:
        url = make_url(database_uri)
    except Exception as exc:
        raise SQLiteBackupError("The configured database URI is invalid.") from exc
    if url.get_backend_name() != "sqlite":
        raise SQLiteBackupError("The backup command supports SQLite databases only.")
    if not url.database or url.database == ":memory:":
        raise SQLiteBackupError("An in-memory SQLite database cannot be backed up.")
    return Path(url.database).expanduser().resolve()


def backup_sqlite_database(
    source: Path,
    destination_directory: Path,
    *,
    now: datetime | None = None,
) -> Path:
    """Create an atomic, dated backup using SQLite's online backup API."""

    source = Path(source).expanduser().resolve()
    destination_directory = Path(destination_directory).expanduser().resolve()
    if not source.is_file():
        raise SQLiteBackupError(f"SQLite database not found: {source}")

    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    timestamp = moment.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    target = destination_directory / f"remediation-{timestamp}.db"
    temporary = destination_directory / f".{target.name}.tmp"

    try:
        destination_directory.mkdir(parents=True, exist_ok=True)
        if target.exists() or temporary.exists():
            raise SQLiteBackupError(f"Backup destination already exists: {target}")

        read_only_uri = f"{source.as_uri()}?mode=ro"
        with closing(
            sqlite3.connect(read_only_uri, uri=True, timeout=30.0)
        ) as source_connection:
            with closing(
                sqlite3.connect(temporary, timeout=30.0)
            ) as backup_connection:
                source_connection.backup(backup_connection)
                integrity = backup_connection.execute("PRAGMA integrity_check").fetchone()
                if integrity is None or integrity[0] != "ok":
                    raise SQLiteBackupError("SQLite integrity check failed for the backup.")

        os.chmod(temporary, 0o600)
        temporary.replace(target)
        return target
    except SQLiteBackupError:
        _remove_temporary_file(temporary)
        raise
    except (OSError, sqlite3.Error) as exc:
        _remove_temporary_file(temporary)
        raise SQLiteBackupError(f"SQLite backup failed: {exc}") from exc


def _remove_temporary_file(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass

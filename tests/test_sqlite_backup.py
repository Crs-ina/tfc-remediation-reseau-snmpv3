from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest

from app.services.sqlite_backup import SQLiteBackupError, backup_sqlite_database


def test_online_backup_is_openable_and_contains_source_data(tmp_path):
    source = tmp_path / "remediation.db"
    connection = sqlite3.connect(source)
    connection.execute("CREATE TABLE incidents (id TEXT PRIMARY KEY, status TEXT)")
    connection.execute(
        "INSERT INTO incidents (id, status) VALUES (?, ?)",
        ("incident-1", "WAITING_ADMIN_APPROVAL"),
    )
    connection.commit()

    backup = backup_sqlite_database(
        source,
        tmp_path / "backups",
        now=datetime(2026, 8, 28, 15, 30, tzinfo=timezone.utc),
    )
    connection.close()

    assert backup.name == "remediation-20260828T153000000000Z.db"
    with sqlite3.connect(backup) as restored:
        assert restored.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert restored.execute("SELECT id, status FROM incidents").fetchone() == (
            "incident-1",
            "WAITING_ADMIN_APPROVAL",
        )


def test_backup_failure_is_reported_without_creating_a_backup(tmp_path):
    destination = tmp_path / "backups"

    with pytest.raises(SQLiteBackupError, match="database not found"):
        backup_sqlite_database(tmp_path / "missing.db", destination)

    assert not destination.exists()


def test_registered_backup_command_uses_the_configured_directory(app):
    result = app.test_cli_runner().invoke(args=["backup-sqlite"])

    assert result.exit_code == 0
    assert "SQLite backup created:" in result.output
    backups = list(app.config["SQLITE_BACKUP_DIR"].glob("remediation-*.db"))
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as restored:
        table_names = {
            row[0]
            for row in restored.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert "incidents" in table_names

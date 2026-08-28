from pathlib import Path

import click
from flask import current_app
from flask.cli import with_appcontext

from app.services.sqlite_backup import (
    SQLiteBackupError,
    backup_sqlite_database,
    sqlite_database_path,
)


@click.command("backup-sqlite")
@click.option(
    "--destination",
    type=click.Path(path_type=Path, file_okay=False),
    default=None,
    help="Override the configured SQLite backup directory.",
)
@with_appcontext
def backup_sqlite_command(destination: Path | None) -> None:
    """Create a consistent local backup of OKAPI's SQLite database."""

    backup_directory = destination or current_app.config["SQLITE_BACKUP_DIR"]
    try:
        source = sqlite_database_path(current_app.config["SQLALCHEMY_DATABASE_URI"])
        backup = backup_sqlite_database(source, backup_directory)
    except SQLiteBackupError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"SQLite backup created: {backup}")

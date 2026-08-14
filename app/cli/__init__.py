import click
from flask import Flask

from app.extensions import db

from .incidents import incidents_cli
from .remediation import remediation_cli
from .snmp import snmp_cli
from .okapi import okapi_cli


@click.command("init-db")
def init_db_command() -> None:
    """Initialize the local database; production uses Flask-Migrate."""
    db.create_all()
    click.echo("Database initialized.")


def register_cli(app: Flask) -> None:
    app.cli.add_command(init_db_command)
    app.cli.add_command(incidents_cli)
    app.cli.add_command(remediation_cli)
    app.cli.add_command(snmp_cli)
    app.cli.add_command(okapi_cli)


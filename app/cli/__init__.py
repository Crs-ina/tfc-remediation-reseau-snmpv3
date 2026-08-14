import click
from flask import Flask

from app.extensions import db

from .incidents import incidents_cli
from .remediation import remediation_cli
from .snmp import snmp_cli


@click.command("init-db")
def init_db_command() -> None:
    """Initialisation locale rapide; Flask-Migrate reste la voie de production."""
    db.create_all()
    click.echo("Base de donnees initialisee.")


def register_cli(app: Flask) -> None:
    app.cli.add_command(init_db_command)
    app.cli.add_command(incidents_cli)
    app.cli.add_command(remediation_cli)
    app.cli.add_command(snmp_cli)


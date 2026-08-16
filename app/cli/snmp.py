from __future__ import annotations

import json

import click
from flask import current_app
from flask.cli import AppGroup

from app.snmp.client import SnmpReadClient, SnmpV3Config
from app.snmp.discovery import discover_snmp_capabilities_sync


snmp_cli = AppGroup("snmp", help="SNMPv3 read-only discovery.")


@snmp_cli.command("discover")
@click.option("--host", default=None, help="Override SNMP_HOST for this execution.")
def discover_command(host: str | None) -> None:
    try:
        config = SnmpV3Config.from_env(host=host)
        client = SnmpReadClient(
            config, current_app.extensions["snmp_mib_registry"]
        )
        report = discover_snmp_capabilities_sync(client, target=config.host)
    except (ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))

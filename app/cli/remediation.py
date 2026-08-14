from __future__ import annotations

import json
from dataclasses import asdict

import click
from flask.cli import AppGroup

from app.extensions import db
from app.models import Incident
from app.services.remediation import (
    RemediationError,
    UnsafeOperationBlocked,
    approve_incident,
    evaluate_incident,
    execute_authorized_remediation,
    refuse_incident,
)
from app.services.snmp_execution import rollback_quarantine_vlan
from app.services.snmp_preparation import prepare_incident_with_snmp


remediation_cli = AppGroup("remediation", help="Evaluer et autoriser une remediation.")


def _incident_or_fail(incident_id: str) -> Incident:
    incident = db.session.get(Incident, incident_id)
    if incident is None:
        raise click.ClickException("Incident introuvable.")
    return incident


@remediation_cli.command("evaluate")
@click.argument("incident_id")
@click.option("--target-confirmed/--target-unconfirmed", default=False)
@click.option("--target-mac")
@click.option("--target-ip")
@click.option("--switch-id")
@click.option("--port-index", type=int)
def evaluate_command(
    incident_id: str,
    target_confirmed: bool,
    target_mac: str | None,
    target_ip: str | None,
    switch_id: str | None,
    port_index: int | None,
) -> None:
    incident = _incident_or_fail(incident_id)
    if target_confirmed and (
        target_mac is None or switch_id is None or port_index is None
    ):
        raise click.ClickException(
            "--target-mac, --switch-id et --port-index sont requis pour une cible confirmee."
        )
    try:
        decision = evaluate_incident(
            incident,
            target_confirmed=target_confirmed,
            target_mac_address=target_mac,
            target_ip=target_ip,
            switch_id=switch_id,
            port_index=port_index,
        )
    except RemediationError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(decision.__dict__, indent=2, ensure_ascii=False))


@remediation_cli.command("approve")
@click.argument("incident_id")
@click.option("--administrator", required=True, help="Identifiant de l'administrateur.")
def approve_command(incident_id: str, administrator: str) -> None:
    try:
        remediation = approve_incident(_incident_or_fail(incident_id), administrator)
    except RemediationError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(remediation.to_dict(), indent=2, ensure_ascii=False))


@remediation_cli.command("prepare-snmp")
@click.argument("incident_id")
@click.option("--switch-id", required=True)
@click.option("--target-mac", required=True)
@click.option("--target-ip")
def prepare_snmp_command(
    incident_id: str,
    switch_id: str,
    target_mac: str,
    target_ip: str | None,
) -> None:
    try:
        result = prepare_incident_with_snmp(
            _incident_or_fail(incident_id),
            switch_id=switch_id,
            target_mac=target_mac,
            target_ip=target_ip,
        )
    except RemediationError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(asdict(result), indent=2, ensure_ascii=False))


@remediation_cli.command("refuse")
@click.argument("incident_id")
@click.option("--administrator", required=True, help="Identifiant de l'administrateur.")
def refuse_command(incident_id: str, administrator: str) -> None:
    try:
        remediation = refuse_incident(_incident_or_fail(incident_id), administrator)
    except RemediationError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(remediation.to_dict(), indent=2, ensure_ascii=False))


@remediation_cli.command("execute")
@click.argument("incident_id")
def execute_command(incident_id: str) -> None:
    try:
        result = execute_authorized_remediation(_incident_or_fail(incident_id))
    except (RemediationError, UnsafeOperationBlocked) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(asdict(result), indent=2, ensure_ascii=False))


@remediation_cli.command("rollback")
@click.argument("incident_id")
@click.option("--administrator", required=True)
def rollback_command(incident_id: str, administrator: str) -> None:
    try:
        observed_pvid = rollback_quarantine_vlan(
            _incident_or_fail(incident_id), administrator_id=administrator
        )
    except (RemediationError, UnsafeOperationBlocked) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps({"observed_pvid": observed_pvid}, indent=2))

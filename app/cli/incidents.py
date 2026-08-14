from __future__ import annotations

import json

import click
from flask.cli import AppGroup

from app.extensions import db
from app.models import AuditLog, Incident


incidents_cli = AppGroup("incidents", help="Consulter les incidents et les journaux.")


@incidents_cli.command("list")
@click.option("--state", "state_filter", help="Filtrer par etat exact.")
def list_incidents(state_filter: str | None) -> None:
    statement = db.select(Incident).order_by(Incident.detected_at.desc())
    if state_filter:
        statement = statement.where(Incident.processing_status == state_filter)
    incidents = db.session.execute(statement).scalars().all()
    if not incidents:
        click.echo("Aucun incident.")
        return
    for incident in incidents:
        click.echo(
            f"{incident.incident_id} | {incident.zabbix_event_id} | "
            f"{incident.incident_type or 'unknown'} | {incident.processing_status}"
        )


@incidents_cli.command("show")
@click.argument("incident_id")
def show_incident(incident_id: str) -> None:
    incident = db.session.get(Incident, incident_id)
    if incident is None:
        raise click.ClickException("Incident introuvable.")
    click.echo(json.dumps(incident.to_dict(), indent=2, ensure_ascii=False))


@incidents_cli.command("logs")
@click.option("--incident-id", default=None)
def list_logs(incident_id: str | None) -> None:
    statement = db.select(AuditLog).order_by(AuditLog.event_timestamp.desc())
    if incident_id:
        statement = statement.where(AuditLog.incident_id == incident_id)
    logs = db.session.execute(statement).scalars().all()
    if not logs:
        click.echo("Aucun journal.")
        return
    for entry in logs:
        click.echo(json.dumps(entry.to_dict(), ensure_ascii=False))

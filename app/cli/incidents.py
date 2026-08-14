from __future__ import annotations

import json
from datetime import datetime
from zoneinfo import ZoneInfo

import click
from flask.cli import AppGroup

from app.extensions import db
from app.models import AuditLog, Incident


incidents_cli = AppGroup("incidents", help="View incidents and audit logs.")

def _parse_local_datetime(value: str | None) -> datetime | None:
    if value is None: return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M").replace(tzinfo=ZoneInfo("Africa/Kinshasa"))
    except ValueError as exc:
        raise click.BadParameter("Use YYYY-MM-DD HH:MM in Africa/Kinshasa.") from exc


@incidents_cli.command("list")
@click.option("--state", "state_filter", help="Filter by exact status.")
@click.option("--from", "from_value", help="Start, YYYY-MM-DD HH:MM (Africa/Kinshasa).")
@click.option("--to", "to_value", help="End, YYYY-MM-DD HH:MM (Africa/Kinshasa).")
def list_incidents(state_filter: str | None, from_value: str | None, to_value: str | None) -> None:
    start, end = _parse_local_datetime(from_value), _parse_local_datetime(to_value)
    if start and end and start > end: raise click.UsageError("--from must be before --to.")
    statement = db.select(Incident).order_by(Incident.detected_at.desc())
    if state_filter:
        statement = statement.where(Incident.processing_status == state_filter)
    if start: statement = statement.where(Incident.detected_at >= start)
    if end: statement = statement.where(Incident.detected_at <= end)
    incidents = db.session.execute(statement).scalars().all()
    if not incidents:
        click.echo("No incidents found.")
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
        raise click.ClickException("Incident not found.")
    click.echo(json.dumps(incident.to_dict(), indent=2, ensure_ascii=False))


@incidents_cli.command("logs")
@click.option("--incident-id", default=None)
@click.option("--from", "from_value", help="Start, YYYY-MM-DD HH:MM (Africa/Kinshasa).")
@click.option("--to", "to_value", help="End, YYYY-MM-DD HH:MM (Africa/Kinshasa).")
def list_logs(incident_id: str | None, from_value: str | None, to_value: str | None) -> None:
    start, end = _parse_local_datetime(from_value), _parse_local_datetime(to_value)
    if start and end and start > end: raise click.UsageError("--from must be before --to.")
    statement = db.select(AuditLog).order_by(AuditLog.event_timestamp.desc())
    if incident_id:
        statement = statement.where(AuditLog.incident_id == incident_id)
    if start: statement = statement.where(AuditLog.event_timestamp >= start)
    if end: statement = statement.where(AuditLog.event_timestamp <= end)
    logs = db.session.execute(statement).scalars().all()
    if not logs:
        click.echo("No audit logs found.")
        return
    for entry in logs:
        click.echo(json.dumps(entry.to_dict(), ensure_ascii=False))

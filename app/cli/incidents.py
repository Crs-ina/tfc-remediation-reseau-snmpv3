from __future__ import annotations

import json
from datetime import datetime
from zoneinfo import ZoneInfo

import click
from flask.cli import AppGroup

from app.extensions import db
from app.models import Administrator, AuditLog, Incident


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
@click.option("--incident-type")
@click.option("--action")
@click.option("--result")
@click.option("--administrator")
@click.option("--switch", "switch_name")
@click.option("--port", type=int)
@click.option("--page", type=click.IntRange(min=1), default=1, show_default=True)
def list_logs(incident_id: str | None, from_value: str | None, to_value: str | None,
              incident_type: str | None, action: str | None, result: str | None,
              administrator: str | None, switch_name: str | None, port: int | None,
              page: int) -> None:
    start, end = _parse_local_datetime(from_value), _parse_local_datetime(to_value)
    if start and end and start > end: raise click.UsageError("--from must be before --to.")
    statement = db.select(AuditLog).order_by(AuditLog.event_timestamp.desc())
    if incident_id:
        statement = statement.where(AuditLog.incident_id == incident_id)
    if start: statement = statement.where(AuditLog.event_timestamp >= start)
    if end: statement = statement.where(AuditLog.event_timestamp <= end)
    if incident_type: statement = statement.where(AuditLog.incident_type == incident_type)
    if action: statement = statement.where(AuditLog.action_type == action)
    if result: statement = statement.where(AuditLog.result_status == result)
    if administrator:
        statement = statement.join(AuditLog.administrator).where(
            Administrator.system_username == administrator
        )
    if switch_name: statement = statement.where(AuditLog.equipment_name == switch_name)
    if port is not None: statement = statement.where(AuditLog.port_index == port)
    statement = statement.offset((page - 1) * 20).limit(20)
    logs = db.session.execute(statement).scalars().all()
    if not logs:
        click.echo("No audit logs found.")
        return
    for entry in logs:
        click.echo(json.dumps(entry.to_dict(), ensure_ascii=False))

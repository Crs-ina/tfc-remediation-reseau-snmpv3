from __future__ import annotations

import random
from datetime import datetime
from zoneinfo import ZoneInfo

import click
from flask import current_app
from flask.cli import AppGroup

from app.extensions import db
from app.models import AuditLog, Incident, Remediation
from app.services.administrators import AuthenticationError, authenticate_administrator, change_password, create_administrator
from app.services.calendar_policy import CalendarPolicy
from app.services.remediation import ConcurrentDecisionError, RemediationError, approve_incident, execute_authorized_remediation, refuse_incident
from app.services.snmp_execution import rollback_quarantine_vlan

ANSI_PALETTE = ("cyan", "green", "yellow", "blue", "magenta")
ANSI_CODES = {"cyan": "36", "green": "32", "yellow": "33", "blue": "34", "magenta": "35"}
OKAPI_ANIMAL = r"""
       /\_/\\
  .---( o.o )---.
 /  _  /   \  _  \
 | (_) | . | (_) |
  \___/|___|\___/
"""
OKAPI_WORD = r"""
  OOO  K  K  AAA  PPPP  III
 O   O K K  A   A P   P  I
 O   O KK   AAAAA PPPP   I
 O   O K K  A   A P      I
  OOO  K  K A   A P     III
"""
SUBTITLE = "Orchestrateur de Kimwenza Automatisé pour la Protection et l’Automatisation"


def choose_banner_color() -> str:
    return random.choice(ANSI_PALETTE)


def local_time(value: datetime | None) -> str:
    if value is None:
        return "Not available"
    zone = ZoneInfo("Africa/Kinshasa")
    if value.tzinfo is None:
        value = value.replace(tzinfo=ZoneInfo("UTC"))
    return value.astimezone(zone).strftime("%A, %-d %B %Y - %H:%M:%S")


def _banner(username: str | None = None) -> None:
    color = choose_banner_color()
    ansi = ANSI_CODES[color] if click.get_text_stream("stdout").isatty() else None
    artwork = f"{OKAPI_ANIMAL}\n{OKAPI_WORD}\n{SUBTITLE}"
    click.echo(f"\033[{ansi}m{artwork}\033[0m" if ansi else artwork)
    schedule = CalendarPolicy.from_file(current_app.config["AUTOMATION_SCHEDULE_PATH"]).decide()
    app = current_app
    click.echo("-" * 56)
    if username:
        click.echo(f"Administrator : {username}")
    click.echo(f"Schedule Mode : {schedule.mode}")
    click.echo("SNMP Security : SNMPv3 authPriv")
    click.echo(f"Write Access  : {'ENABLED' if app.config['SNMP_WRITE_ENABLED'] else 'DISABLED'}")
    click.echo(f"Date/Time     : {local_time(datetime.now(ZoneInfo('Africa/Kinshasa')))}")
    click.echo("Timezone      : Africa/Kinshasa")
    click.echo("-" * 56)


def _create_account() -> None:
    username = click.prompt("Username").strip()
    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
    try:
        create_administrator(username, password)
    except ValueError as exc:
        click.echo(f"Account creation failed: {exc}")
        return
    click.echo("Administrator account created.")


def _pending(session) -> None:
    incidents = db.session.execute(db.select(Incident).where(Incident.processing_status == "WAITING_ADMIN_APPROVAL").order_by(Incident.detected_at.desc())).scalars().all()
    if not incidents:
        click.echo("No pending incidents.")
        return
    click.echo("Pending incidents")
    for number, incident in enumerate(incidents, 1):
        click.echo(f"[{number}] {incident.incident_type or 'Security policy violation'} | {local_time(incident.detected_at)} | {incident.processing_status}")
    selected = click.prompt("Select incident (or B to go back)", default="B").strip()
    if selected.upper() == "B":
        return
    try:
        incident = incidents[int(selected) - 1]
    except (ValueError, IndexError):
        click.echo("Invalid selection.")
        return
    remediation = incident.remediations[-1] if incident.remediations else None
    port = remediation.switch_port.port_name if remediation and remediation.switch_port else "Not resolved yet"
    click.echo(f"\nIncident      : {incident.incident_type or 'Security policy violation'}\nDetected      : {local_time(incident.detected_at)}\nTarget MAC    : {remediation.target_mac_address if remediation else 'Not resolved yet'}\nSwitch        : {remediation.switch_port.network_switch.name if remediation and remediation.switch_port else 'Not resolved yet'}\nPort          : {port}\nCurrent VLAN  : {remediation.previous_vlan_id if remediation else 'Not resolved yet'}\nProposed      : {remediation.action_type if remediation else 'Not resolved yet'}\nStatus        : {incident.processing_status}")
    choice = click.prompt("[A] Approve  [R] Refuse  [B] Back", default="B").strip().upper()
    try:
        if choice == "A":
            approve_incident(incident, session.administrator_id)
            result = execute_authorized_remediation(incident)
            click.echo(f"Remediation {'succeeded' if result.success else 'failed'}.")
        elif choice == "R":
            refuse_incident(incident, session.administrator_id)
            click.echo("Remediation refused. No remediation was executed.")
    except (RemediationError, ConcurrentDecisionError) as exc:
        click.echo(str(exc))


def _history() -> None:
    for incident in db.session.execute(db.select(Incident).order_by(Incident.detected_at.desc()).limit(20)).scalars():
        click.echo(f"{incident.incident_type or 'Security policy violation'} | {local_time(incident.detected_at)} | {incident.processing_status}")


def _logs() -> None:
    for entry in db.session.execute(db.select(AuditLog).order_by(AuditLog.event_timestamp.desc()).limit(20)).scalars():
        actor = entry.administrator.username if entry.administrator else "SYSTEM"
        click.echo(f"{local_time(entry.event_timestamp)} | {actor} | {entry.event_type} | {entry.result_status or 'INFO'}")


def _rollback(session) -> None:
    items = db.session.execute(db.select(Remediation).where(Remediation.status == "SUCCEEDED").order_by(Remediation.start_time.desc())).scalars().all()
    if not items:
        click.echo("Rollback unavailable. No successful remediation is available.")
        return
    for number, remediation in enumerate(items, 1):
        click.echo(f"[{number}] {remediation.action_type} | previous VLAN {remediation.previous_vlan_id}")
    selected = click.prompt("Select remediation (or B to go back)", default="B").strip()
    if selected.upper() == "B": return
    try:
        observed = rollback_quarantine_vlan(items[int(selected) - 1].incident, administrator_id=session.administrator_id)
        click.echo(f"Rollback succeeded. Restored VLAN: {observed}")
    except (ValueError, IndexError, RemediationError) as exc:
        click.echo(f"Rollback unavailable: {exc}")


okapi_cli = AppGroup("okapi", help="OKAPI administrator interface.", invoke_without_command=True)

@okapi_cli.command("create-account")
def create_account_command() -> None:
    """Create an administrator account with a protected password prompt."""
    _create_account()

@click.pass_context
def okapi(ctx: click.Context) -> None:
    if ctx.invoked_subcommand:
        return
    _banner()
    while True:
        choice = click.prompt("[1] Login  [2] Create administrator account  [0] Exit", default="", show_default=False).strip()
        if not choice: continue
        if choice == "0": return
        if choice == "2": _create_account(); continue
        if choice != "1": click.echo("Invalid selection."); continue
        username = click.prompt("Username")
        password = click.prompt("Password", hide_input=True)
        try:
            administrator = authenticate_administrator(username, password)
        except AuthenticationError as exc:
            click.echo(str(exc)); continue
        click.echo(f"Login successful. Welcome, {administrator.username}.")
        _banner(administrator.username)
        while True:
            choice = click.prompt("[1] Pending incidents [2] Incident history [3] Audit logs [4] Successful remediations / rollback [5] Account [6] Logout [0] Exit", default="", show_default=False).strip()
            if not choice: continue
            if choice == "0": return
            if choice == "1": _pending(administrator)
            elif choice == "2": _history()
            elif choice == "3": _logs()
            elif choice == "4": _rollback(administrator)
            elif choice == "5":
                click.echo(f"Username: {administrator.username}\nStatus: {'Active' if administrator.is_active else 'Inactive'}\nCreated at: {local_time(administrator.created_at)}\nLast login: {local_time(administrator.last_login_at)}")
            elif choice == "6": click.echo("Logged out."); break
            else: click.echo("Invalid selection.")


okapi_cli.callback = okapi

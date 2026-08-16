from __future__ import annotations

import random
from datetime import datetime
from zoneinfo import ZoneInfo

import click
from flask import current_app
from flask.cli import AppGroup

from app.extensions import db
from app.models import Administrator, AuditLog, Incident, Remediation
from app.services.administrators import (
    AuthenticationError, authenticate_administrator, change_password,
    create_administrator, disable_administrator, list_administrators,
)
from app.services.calendar_policy import CalendarPolicy
from app.services.remediation import ConcurrentDecisionError, RemediationError, approve_incident, execute_authorized_remediation, refuse_incident
from app.services.snmp_execution import rollback_snmp_action
from .okapi_art import PALETTES, render_random_banner

SUBTITLE = "Orchestrateur de Kimwenza Automatisé pour la Protection et l’Automatisation"


def choose_banner_color() -> str:
    """Compatibility helper retained for callers/tests of the original CLI."""
    return random.choice(tuple(palette.name for palette in PALETTES))


def local_time(value: datetime | None) -> str:
    if value is None:
        return "Not available"
    zone = ZoneInfo("Africa/Kinshasa")
    if value.tzinfo is None:
        value = value.replace(tzinfo=ZoneInfo("UTC"))
    return value.astimezone(zone).strftime("%A, %-d %B %Y - %H:%M:%S")


def _banner(username: str | None = None) -> None:
    click.echo(render_random_banner())
    click.echo(SUBTITLE)
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


def _select_incident(incidents: list[Incident], prompt: str = "Select incident") -> Incident | None:
    if not incidents:
        click.echo("No matching incidents.")
        return None
    for number, incident in enumerate(incidents, 1):
        click.echo(f"[{number}] {incident.incident_type or 'Unknown incident'} | {incident.severity or 'Unspecified'} | {local_time(incident.detected_at)} | {incident.processing_status}")
    value = click.prompt(f"{prompt} (B to go back)", default="B").strip()
    if value.upper() == "B":
        return None
    try:
        return incidents[int(value) - 1]
    except (ValueError, IndexError):
        click.echo("Invalid selection.")
        return None


def _incident_details() -> None:
    incidents = list(db.session.execute(db.select(Incident).order_by(Incident.detected_at.desc()).limit(100)).scalars())
    incident = _select_incident(incidents)
    if incident is None:
        return
    remediation = incident.remediations[-1] if incident.remediations else None
    switch = remediation.switch_port.network_switch if remediation and remediation.switch_port else None
    click.echo(
        f"Incident      : {incident.incident_type or 'Unknown incident'}\n"
        f"Detected      : {local_time(incident.detected_at)}\nSeverity      : {incident.severity or 'Unspecified'}\n"
        f"Status        : {incident.processing_status}\nPlaybook      : {incident.playbook_id}\n"
        f"Switch        : {switch.name if switch else 'Not resolved yet'}\n"
        f"Port          : {remediation.switch_port.port_name if remediation and remediation.switch_port else 'Not resolved yet'}\n"
        f"Action        : {remediation.action_type if remediation else 'NO_ACTION'}\n"
        f"Authorization : {remediation.authorization_mode if remediation else 'NONE'}"
    )


def _decide(session: Administrator, approve: bool) -> None:
    incidents = list(db.session.execute(db.select(Incident).where(Incident.processing_status == "WAITING_ADMIN_APPROVAL").order_by(Incident.detected_at)).scalars())
    incident = _select_incident(incidents)
    if incident is None:
        return
    try:
        if approve:
            approve_incident(incident, session.administrator_id)
            result = execute_authorized_remediation(incident)
            click.echo(f"Remediation {'succeeded' if result.success else 'failed'}.")
        else:
            refuse_incident(incident, session.administrator_id)
            click.echo("Remediation rejected. No network write was executed.")
    except (RemediationError, ConcurrentDecisionError) as exc:
        click.echo(str(exc))


def _remediation_history() -> None:
    items = db.session.execute(db.select(Remediation).order_by(Remediation.start_time.desc()).limit(20)).scalars()
    found = False
    for item in items:
        found = True
        click.echo(f"{local_time(item.start_time)} | {item.action_type} | {item.authorization_mode} | {item.status}")
    if not found:
        click.echo("No remediation history.")


def _logs() -> None:
    statement = db.select(AuditLog).order_by(AuditLog.event_timestamp.desc())
    mode = click.prompt("[1] Latest logs [2] Filter logs [B] Back", default="1").strip().upper()
    if mode == "B":
        return
    if mode == "2":
        incident_type = click.prompt("Incident type (blank = any)", default="", show_default=False).strip()
        action = click.prompt("Action (blank = any)", default="", show_default=False).strip()
        result = click.prompt("Result (blank = any)", default="", show_default=False).strip()
        administrator = click.prompt("Administrator (blank = any)", default="", show_default=False).strip()
        switch = click.prompt("Switch name (blank = any)", default="", show_default=False).strip()
        port = click.prompt("Port index (blank = any)", default="", show_default=False).strip()
        from_value = click.prompt("From YYYY-MM-DD HH:MM (blank = any)", default="", show_default=False).strip()
        to_value = click.prompt("To YYYY-MM-DD HH:MM (blank = any)", default="", show_default=False).strip()
        if incident_type: statement = statement.where(AuditLog.incident_type == incident_type)
        if action: statement = statement.where(AuditLog.action_type == action)
        if result: statement = statement.where(AuditLog.result_status == result)
        if administrator:
            statement = statement.join(AuditLog.administrator).where(Administrator.username == administrator)
        if switch: statement = statement.where(AuditLog.equipment_name == switch)
        if port:
            try: statement = statement.where(AuditLog.port_index == int(port))
            except ValueError: click.echo("Port must be a number."); return
        try:
            start = datetime.strptime(from_value, "%Y-%m-%d %H:%M").replace(tzinfo=ZoneInfo("Africa/Kinshasa")) if from_value else None
            end = datetime.strptime(to_value, "%Y-%m-%d %H:%M").replace(tzinfo=ZoneInfo("Africa/Kinshasa")) if to_value else None
        except ValueError:
            click.echo("Dates must use YYYY-MM-DD HH:MM.")
            return
        if start and end and start > end:
            click.echo("From must be before To.")
            return
        if start: statement = statement.where(AuditLog.event_timestamp >= start)
        if end: statement = statement.where(AuditLog.event_timestamp <= end)
        if click.confirm("Filter by a selected incident?", default=False):
            candidates = list(db.session.execute(db.select(Incident).order_by(Incident.detected_at.desc()).limit(100)).scalars())
            selected_incident = _select_incident(candidates)
            if selected_incident is None:
                return
            statement = statement.where(AuditLog.incident_id == selected_incident.incident_id)
    entries = list(db.session.execute(statement.limit(20)).scalars())
    if not entries:
        click.echo("No audit logs found.")
        return
    for entry in entries:
        actor = entry.administrator.username if entry.administrator else "SYSTEM"
        click.echo(f"{local_time(entry.event_timestamp)} | {actor} | {entry.event_type} | {entry.result_status or 'INFO'}")


def _system_status() -> None:
    registry = current_app.extensions.get("snmp_mib_registry")
    mib_ready = bool(registry and registry.status.ready)
    try:
        db.session.execute(db.select(Administrator.administrator_id).limit(1)).first()
        sqlite_ready = True
    except Exception:
        sqlite_ready = False
    schedule = CalendarPolicy.from_file(current_app.config["AUTOMATION_SCHEDULE_PATH"]).decide()
    click.echo(
        f"Backend       : ONLINE\nSQLite        : {'READY' if sqlite_ready else 'ERROR'}\n"
        f"MIB registry  : {'READY' if mib_ready else 'ERROR'}\nSchedule mode : {schedule.mode}\n"
        f"SNMP security : authPriv SHA-256/AES-256\nWrite access  : {'ENABLED' if current_app.config['SNMP_WRITE_ENABLED'] else 'DISABLED'}\n"
        f"Dry-run       : {'ENABLED' if current_app.config['DRY_RUN'] else 'DISABLED'}"
    )


def _attention_summary() -> None:
    states = {
        "Pending approvals": "WAITING_ADMIN_APPROVAL",
        "Failed remediations": "REMEDIATION_FAILED",
        "Escalated incidents": "ESCALATED",
    }
    click.echo("Attention summary")
    for label, state in states.items():
        count = db.session.execute(
            db.select(db.func.count(Incident.incident_id)).where(Incident.processing_status == state)
        ).scalar_one()
        click.echo(f"{label:<21}: {count}")
    rollback_count = db.session.execute(
        db.select(db.func.count(Remediation.remediation_id)).where(Remediation.status == "SUCCEEDED")
    ).scalar_one()
    click.echo(f"{'Rollback available':<21}: {rollback_count}")


def _account_menu(session: Administrator) -> None:
    while True:
        click.echo("[1] Account details [2] Change own password [3] Create administrator [4] List administrators [5] Disable administrator [B] Back")
        choice = click.prompt("Select", default="B").strip().upper()
        if choice == "B": return
        if choice == "1":
            click.echo(f"Username: {session.username}\nStatus: {'Active' if session.is_active else 'Inactive'}\nCreated at: {local_time(session.created_at)}\nLast login: {local_time(session.last_login_at)}")
        elif choice == "2":
            password = click.prompt("New password", hide_input=True, confirmation_prompt=True)
            try: change_password(session, password); click.echo("Password changed.")
            except ValueError as exc: click.echo(str(exc))
        elif choice == "3": _create_account()
        elif choice == "4":
            for administrator in list_administrators():
                click.echo(f"{administrator.username} | {'Active' if administrator.is_active else 'Disabled'} | {local_time(administrator.last_login_at)}")
        elif choice == "5":
            try:
                username = click.prompt("Username to disable")
                disable_administrator(session, username)
                click.echo("Administrator disabled.")
            except ValueError as exc: click.echo(str(exc))
        else: click.echo("Invalid selection.")


def _rollback(session) -> None:
    items = db.session.execute(db.select(Remediation).where(Remediation.status == "SUCCEEDED").order_by(Remediation.start_time.desc())).scalars().all()
    if not items:
        click.echo("Rollback unavailable. No successful remediation is available.")
        return
    for number, remediation in enumerate(items, 1):
        snapshot = (
            f"previous VLAN {remediation.previous_vlan_id}"
            if remediation.action_type == "QUARANTINE_VLAN"
            else f"previous admin status {remediation.previous_port_status}"
        )
        click.echo(f"[{number}] {remediation.action_type} | {snapshot}")
    selected = click.prompt("Select remediation (or B to go back)", default="B").strip()
    if selected.upper() == "B": return
    try:
        observed = rollback_snmp_action(items[int(selected) - 1].incident, administrator_id=session.administrator_id)
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
        _attention_summary()
        while True:
            click.echo("[1] Pending incidents [2] All incidents [3] Incident details [4] Approve remediation [5] Reject remediation [6] Remediation history [7] Audit logs [8] Rollback [9] System status [A] Account [L] Logout [0] Exit")
            choice = click.prompt("Select", default="", show_default=False).strip().upper()
            if not choice: continue
            if choice == "0": return
            if choice == "1": _pending(administrator)
            elif choice == "2": _history()
            elif choice == "3": _incident_details()
            elif choice == "4": _decide(administrator, True)
            elif choice == "5": _decide(administrator, False)
            elif choice == "6": _remediation_history()
            elif choice == "7": _logs()
            elif choice == "8": _rollback(administrator)
            elif choice == "9": _system_status()
            elif choice == "A": _account_menu(administrator)
            elif choice == "L": click.echo("Logged out."); break
            else: click.echo("Invalid selection.")


okapi_cli.callback = okapi

from __future__ import annotations

import random
from datetime import datetime
from zoneinfo import ZoneInfo

import click
from flask import current_app
from flask.cli import AppGroup, with_appcontext

from app.extensions import db
from app.models import Administrator, AuditLog, Incident, Remediation
from app.services.administrators import (
    IdentityError,
    ReauthenticationError,
    reauthenticate_for_critical_action,
    resolve_current_administrator,
)
from app.services.calendar_policy import CalendarPolicy
from app.services.remediation import (
    ConcurrentDecisionError,
    RemediationError,
    approve_incident,
    execute_authorized_remediation,
    refuse_incident,
    resume_simulated_remediation_for_real,
)
from app.services.runtime_settings import (
    change_dry_run_mode,
    is_dry_run_enabled,
)
from app.services.snmp_execution import rollback_snmp_action

from .ui.colors import PALETTES
from .ui.splash import preview_all, show_splash


SUBTITLE = "Orchestrateur de Kimwenza Automatisé pour la Protection et l’Automatisation"


def choose_banner_color() -> str:
    """Compatibility helper retained for callers of the visual CLI."""

    return random.choice(tuple(PALETTES))


def local_time(value: datetime | None) -> str:
    if value is None:
        return "Not available"
    zone = ZoneInfo("Africa/Kinshasa")
    if value.tzinfo is None:
        value = value.replace(tzinfo=ZoneInfo("UTC"))
    local = value.astimezone(zone)
    return f"{local.strftime('%A')}, {local.day} {local.strftime('%B %Y - %H:%M:%S')}"


def _welcome(administrator: Administrator) -> None:
    name = administrator.display_name or administrator.system_username
    click.echo(f"[ OKAPI ]\n\n\nWelcome, {name}.")


def _banner(
    username: str | None = None,
    *,
    show_identity: bool = True,
    animated: bool = True,
    fast: bool = False,
    color: bool | None = None,
) -> None:
    if show_identity:
        show_splash(
            animated=animated,
            fast=fast,
            color=color,
            stream=click.get_text_stream("stdout"),
        )
    schedule = CalendarPolicy.from_file(
        current_app.config["AUTOMATION_SCHEDULE_PATH"]
    ).decide()
    click.echo(SUBTITLE)
    click.echo("-" * 56)
    if username:
        click.echo(f"Administrator : {username}")
    click.echo(f"Schedule Mode : {schedule.mode}")
    click.echo("SNMP Security : SNMPv3 authPriv")
    click.echo(f"Write Access  : {_snmp_write_state()}")
    click.echo(f"Dry-run Mode  : {'ON' if is_dry_run_enabled() else 'OFF'}")
    click.echo(f"Date/Time     : {local_time(datetime.now(ZoneInfo('Africa/Kinshasa')))}")
    click.echo("Timezone      : Africa/Kinshasa")
    click.echo("-" * 56)


def _pending(administrator: Administrator) -> None:
    incidents = list(
        db.session.execute(
            db.select(Incident)
            .where(Incident.processing_status == "WAITING_ADMIN_APPROVAL")
            .order_by(Incident.detected_at.desc())
        ).scalars()
    )
    incident = _select_incident(incidents)
    if incident is None:
        return
    _show_incident(incident)
    choice = click.prompt("[A] Approve  [R] Reject  [B] Back", default="B").strip().upper()
    if choice == "A":
        _approve_and_execute(administrator, incident)
    elif choice == "R":
        _reject(administrator, incident)


def _all_incidents() -> None:
    incidents = db.session.execute(
        db.select(Incident).order_by(Incident.detected_at.desc()).limit(100)
    ).scalars()
    found = False
    for incident in incidents:
        found = True
        click.echo(
            f"{incident.incident_type or 'unknown'} | {local_time(incident.detected_at)} | "
            f"{incident.processing_status} | {incident.playbook_id}"
        )
    if not found:
        click.echo("No incidents found.")


def _select_incident(
    incidents: list[Incident], prompt: str = "Select incident"
) -> Incident | None:
    if not incidents:
        click.echo("No matching incidents.")
        return None
    for number, incident in enumerate(incidents, 1):
        click.echo(
            f"[{number}] {incident.incident_type or 'Unknown incident'} | "
            f"{incident.severity or 'Unspecified'} | {local_time(incident.detected_at)} | "
            f"{incident.processing_status}"
        )
    value = click.prompt(f"{prompt} (B to go back)", default="B").strip()
    if value.upper() == "B":
        return None
    try:
        return incidents[int(value) - 1]
    except (ValueError, IndexError):
        click.echo("Invalid selection.")
        return None


def _incident_details() -> None:
    incidents = list(
        db.session.execute(
            db.select(Incident).order_by(Incident.detected_at.desc()).limit(100)
        ).scalars()
    )
    incident = _select_incident(incidents)
    if incident:
        _show_incident(incident)


def _show_incident(incident: Incident) -> None:
    remediation = incident.remediations[-1] if incident.remediations else None
    switch = remediation.switch_port.network_switch if remediation and remediation.switch_port else None
    click.echo(
        f"Incident      : {incident.incident_type or 'Unknown incident'}\n"
        f"Detected      : {local_time(incident.detected_at)}\n"
        f"Severity      : {incident.severity or 'Unspecified'}\n"
        f"Status        : {incident.processing_status}\n"
        f"Playbook      : {incident.playbook_id}\n"
        f"Switch        : {switch.name if switch else 'Not resolved yet'}\n"
        f"Port          : {remediation.switch_port.port_name if remediation and remediation.switch_port else 'Not resolved yet'}\n"
        f"Target MAC    : {remediation.target_mac_address if remediation else 'Not resolved yet'}\n"
        f"Action        : {remediation.action_type if remediation else 'NO_ACTION'}\n"
        f"Authorization : {remediation.authorization_mode if remediation else 'NONE'}"
    )


def _decide(administrator: Administrator, approve: bool) -> None:
    incidents = list(
        db.session.execute(
            db.select(Incident)
            .where(Incident.processing_status == "WAITING_ADMIN_APPROVAL")
            .order_by(Incident.detected_at)
        ).scalars()
    )
    incident = _select_incident(incidents)
    if incident is None:
        return
    if approve:
        _approve_and_execute(administrator, incident)
    else:
        _reject(administrator, incident)


def _approve_and_execute(administrator: Administrator, incident: Incident) -> None:
    try:
        dry_run_was_enabled = is_dry_run_enabled()

        if not dry_run_was_enabled:
            reauthenticate_for_critical_action(
                administrator, "APPROVE_REAL_DISRUPTIVE_REMEDIATION"
            )

        approve_incident(incident, administrator.administrator_id)
        result = execute_authorized_remediation(incident)
        click.echo(_execution_result_message(result))

        if not result.simulated:
            return

        click.echo(
            "\nThe incident may still be active because DRY-RUN "
            "prevented the SNMP write."
        )

        execute_real = click.confirm(
            "Do you want to execute this remediation for real?",
            default=False,
        )

        if not execute_real:
            click.echo(
                "Real remediation cancelled. "
                "DRY-RUN remains ON. No SNMP SET was sent."
            )
            return

        change_dry_run_mode(False, administrator)
        click.echo("Dry-run mode is now OFF.")

        resume_simulated_remediation_for_real(
            incident,
            administrator.administrator_id,
        )

        real_result = execute_authorized_remediation(incident)
        click.echo(_execution_result_message(real_result))

    except (
        ReauthenticationError,
        RemediationError,
        ConcurrentDecisionError,
    ) as exc:
        click.echo(str(exc))


def _reject(administrator: Administrator, incident: Incident) -> None:
    try:
        refuse_incident(incident, administrator.administrator_id)
        click.echo("Remediation rejected. No network write was executed.")
    except (RemediationError, ConcurrentDecisionError) as exc:
        click.echo(str(exc))


def _remediation_history() -> None:
    items = list(
        db.session.execute(
            db.select(Remediation).order_by(Remediation.start_time.desc()).limit(20)
        ).scalars()
    )
    if not items:
        click.echo("No remediation history.")
        return
    for item in items:
        decision = db.session.execute(
            db.select(AuditLog)
            .where(
                AuditLog.remediation_id == item.remediation_id,
                AuditLog.event_type.in_(
                    ["REMEDIATION_APPROVED", "REMEDIATION_REFUSED", "ROLLBACK_REQUESTED"]
                ),
            )
            .order_by(AuditLog.event_timestamp.desc())
        ).scalars().first()
        click.echo(
            f"{local_time(item.start_time)} | {item.action_type} | "
            f"{item.authorization_mode} | {item.status} | {_actor_label(decision)}"
        )


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
        if incident_type:
            statement = statement.where(AuditLog.incident_type == incident_type)
        if action:
            statement = statement.where(AuditLog.action_type == action)
        if result:
            statement = statement.where(AuditLog.result_status == result)
        if administrator:
            if administrator.upper() == "SYSTEM":
                statement = statement.where(AuditLog.administrator_id.is_(None))
            else:
                statement = statement.join(AuditLog.administrator).where(
                    Administrator.system_username == administrator
                )
        if switch:
            statement = statement.where(AuditLog.equipment_name == switch)
        if port:
            try:
                statement = statement.where(AuditLog.port_index == int(port))
            except ValueError:
                click.echo("Port must be a number.")
                return
    entries = list(db.session.execute(statement.limit(20)).scalars())
    if not entries:
        click.echo("No audit logs found.")
        return
    for entry in entries:
        click.echo(
            f"{local_time(entry.event_timestamp)} | {_actor_label(entry)} | "
            f"{entry.event_type} | {entry.result_status or 'INFO'}"
        )


def _actor_label(entry: AuditLog | None) -> str:
    username = entry.administrator.system_username if entry and entry.administrator else "SYSTEM"
    return f"Administrator : {username}"


def _rollback(administrator: Administrator) -> None:
    items = list(
        db.session.execute(
            db.select(Remediation)
            .where(Remediation.status == "SUCCEEDED")
            .order_by(Remediation.start_time.desc())
        ).scalars()
    )
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
    if selected.upper() == "B":
        return
    try:
        remediation = items[int(selected) - 1]
        reauthenticate_for_critical_action(administrator, "ROLLBACK")
        observed = rollback_snmp_action(
            remediation.incident,
            administrator_id=administrator.administrator_id,
        )
        if is_dry_run_enabled():
            click.echo(
                f"Rollback simulated (DRY-RUN). Requested value: {observed}. "
                "No SNMP SET was sent."
            )
        else:
            click.echo(f"Rollback succeeded. Restored value: {observed}")
    except (
        ValueError,
        IndexError,
        ReauthenticationError,
        RemediationError,
    ) as exc:
        click.echo(f"Rollback unavailable: {exc}")


def _dry_run_menu(administrator: Administrator) -> None:
    enabled = is_dry_run_enabled()
    click.echo(f"Dry-run mode is currently {'ON' if enabled else 'OFF'}.")
    choice = click.prompt("[1] Enable [2] Disable [B] Back", default="B").strip().upper()
    if choice == "B":
        return
    if choice not in {"1", "2"}:
        click.echo("Invalid selection.")
        return
    requested = choice == "1"
    if requested == enabled:
        click.echo(f"Dry-run mode is already {'ON' if enabled else 'OFF'}.")
        return
    try:
        change_dry_run_mode(requested, administrator)
    except ReauthenticationError as exc:
        click.echo(str(exc))
        return
    click.echo(f"Dry-run mode is now {'ON' if requested else 'OFF'}.")


def _system_status() -> None:
    registry = current_app.extensions.get("snmp_mib_registry")
    mib_ready = bool(registry and registry.status.ready)
    try:
        db.session.execute(db.select(Administrator.administrator_id).limit(1)).first()
        sqlite_ready = True
    except Exception:
        sqlite_ready = False
    schedule = CalendarPolicy.from_file(
        current_app.config["AUTOMATION_SCHEDULE_PATH"]
    ).decide()
    authorization_mode = "SUPERVISED" if schedule.mode == "HUMAN_APPROVAL" else schedule.mode
    webhook_ready = bool(
        current_app.config["WEBHOOK_TOKEN"]
        and current_app.config["WEBHOOK_ALLOWED_SOURCE_IPS"]
    )
    dry_run = is_dry_run_enabled()
    values = (
        ("Backend", "RUNNING"),
        ("Database", "OK" if sqlite_ready else "ERROR"),
        ("Zabbix webhook", "READY" if webhook_ready else "NOT READY"),
        ("SNMPv3", "READY" if mib_ready else "NOT READY"),
        ("SNMP writes", _snmp_write_state()),
        ("Dry-run mode", "ON" if dry_run else "OFF"),
        ("Authorization mode", authorization_mode),
        ("Quarantine VLAN", str(current_app.config["QUARANTINE_VLAN_ID"])),
        ("Remediation cooldown", f"{current_app.config['REMEDIATION_COOLDOWN_SECONDS']} s"),
    )
    click.echo("OKAPI — SYSTEM STATUS\n")
    click.echo("\n".join(f"{label:<25}: {value}" for label, value in values))


def _snmp_write_state() -> str:
    if is_dry_run_enabled():
        return "BLOCKED BY DRY-RUN"
    return "ENABLED" if current_app.config["SNMP_WRITE_ENABLED"] else "DISABLED"


def _execution_result_message(result) -> str:
    if result.simulated:
        return "Remediation simulated (DRY-RUN). No SNMP SET was sent."
    return f"Remediation {'succeeded' if result.success else 'failed'}."


def _attention_summary() -> None:
    states = {
        "Pending approvals": "WAITING_ADMIN_APPROVAL",
        "Failed remediations": "REMEDIATION_FAILED",
        "Escalated incidents": "ESCALATED",
    }
    click.echo("Attention summary")
    for label, state in states.items():
        count = db.session.execute(
            db.select(db.func.count(Incident.incident_id)).where(
                Incident.processing_status == state
            )
        ).scalar_one()
        click.echo(f"{label:<21}: {count}")
    rollback_count = db.session.execute(
        db.select(db.func.count(Remediation.remediation_id)).where(
            Remediation.status == "SUCCEEDED"
        )
    ).scalar_one()
    click.echo(f"{'Rollback available':<21}: {rollback_count}")


okapi_cli = AppGroup(
    "okapi",
    help="OKAPI administrator interface.",
    invoke_without_command=True,
    params=[
        click.Option(["--no-splash"], is_flag=True, help="Skip the startup identity screen."),
        click.Option(["--no-color"], is_flag=True, help="Disable ANSI colours in the splash."),
        click.Option(["--fast"], is_flag=True, help="Show the splash without animation delays."),
        click.Option(["--no-animation"], is_flag=True, help="Display the splash and READY state immediately."),
    ],
)


@okapi_cli.command("preview-splash")
@click.option("--width", type=click.IntRange(min=12), default=100, show_default=True)
@click.option("--no-color", is_flag=True, help="Disable ANSI colours.")
@click.option("--ascii", "ascii_only", is_flag=True, help="Use ASCII-only decorations and titles.")
def preview_splash_command(width: int, no_color: bool, ascii_only: bool) -> None:
    """Display all eight splash compositions for visual review."""

    preview_all(
        width=width,
        color=not no_color,
        unicode=not ascii_only,
        stream=click.get_text_stream("stdout"),
    )


@click.pass_context
@with_appcontext
def okapi(
    ctx: click.Context,
    no_splash: bool,
    no_color: bool,
    fast: bool,
    no_animation: bool,
) -> None:
    if ctx.invoked_subcommand:
        return
    if not no_splash:
        _banner(
            animated=not no_animation,
            fast=fast,
            color=False if no_color else None,
        )
    try:
        administrator = resolve_current_administrator()
    except IdentityError as exc:
        raise click.ClickException(str(exc)) from exc
    _welcome(administrator)
    _banner(administrator.system_username, show_identity=False)
    _attention_summary()
    while True:
        click.echo(
            "[1] Pending incidents [2] All incidents [3] Incident details "
            "[4] Approve remediation [5] Reject remediation "
            "[6] Remediation history [7] Audit logs [8] Rollback "
            "[9] Dry-run mode [10] System status [L] Logout / Exit"
        )
        choice = click.prompt("Select", default="", show_default=False).strip().upper()
        if not choice:
            continue
        if choice in {"L", "0"}:
            click.echo("Logged out.")
            return
        if choice == "1":
            _pending(administrator)
        elif choice == "2":
            _all_incidents()
        elif choice == "3":
            _incident_details()
        elif choice == "4":
            _decide(administrator, True)
        elif choice == "5":
            _decide(administrator, False)
        elif choice == "6":
            _remediation_history()
        elif choice == "7":
            _logs()
        elif choice == "8":
            _rollback(administrator)
        elif choice == "9":
            _dry_run_menu(administrator)
        elif choice == "10":
            _system_status()
        else:
            click.echo("Invalid selection.")


okapi_cli.callback = okapi

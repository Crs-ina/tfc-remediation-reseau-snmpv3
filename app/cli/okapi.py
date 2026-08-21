from __future__ import annotations

import random
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import click
from flask import current_app
from flask.cli import AppGroup, with_appcontext
from sqlalchemy import String, cast, or_

from app.extensions import db
from app.models import (
    Administrator,
    AuditLog,
    Incident,
    NetworkSwitch,
    Remediation,
    SwitchPort,
)
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
from app.services.snmp_execution import available_rollbacks, rollback_snmp_action

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
            db.select(Remediation).order_by(Remediation.start_time.desc())
        ).scalars()
    )
    if not items:
        click.echo("No remediation history.")
        return
    click.echo("OKAPI - REMEDIATION HISTORY")
    for item in items:
        click.echo(
            f"\n{local_time(item.start_time)}\n"
            f"Action      : {item.action_type}\n"
            f"Mode        : {item.authorization_mode}\n"
            f"{_remediation_actor_label(item)}\n"
            f"Result      : {item.status}"
        )


def _audit_contains_pattern(value: str) -> str:
    """Return a literal, case-insensitive SQL LIKE contains pattern."""

    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _audit_period_bounds(value: str) -> tuple[datetime, datetime]:
    """Convert a Kinshasa year, month or day to UTC query bounds."""

    zone = ZoneInfo("Africa/Kinshasa")
    try:
        if re.fullmatch(r"\d{4}", value):
            local_start = datetime(int(value), 1, 1, tzinfo=zone)
            local_end = local_start.replace(year=local_start.year + 1)
        elif re.fullmatch(r"\d{4}-\d{2}", value):
            local_start = datetime.strptime(value, "%Y-%m").replace(tzinfo=zone)
            if local_start.month == 12:
                local_end = local_start.replace(
                    year=local_start.year + 1,
                    month=1,
                )
            else:
                local_end = local_start.replace(month=local_start.month + 1)
        elif re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            local_start = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=zone)
            local_end = local_start + timedelta(days=1)
        else:
            raise ValueError
    except ValueError as exc:
        raise ValueError(
            "Date must use YYYY, YYYY-MM, or YYYY-MM-DD."
        ) from exc
    return local_start.astimezone(timezone.utc), local_end.astimezone(timezone.utc)


def _audit_search_terms(value: str) -> list[str]:
    """Split a free search into words so spaces also match stored underscores."""

    return [term for term in re.split(r"[\W_]+", value, flags=re.UNICODE) if term]


def _audit_term_conditions(term: str):
    """Return every audit/remediation field in which one word may appear."""

    pattern = _audit_contains_pattern(term)
    conditions = [
        cast(AuditLog.event_timestamp, String).ilike(pattern, escape="\\"),
        AuditLog.event_type.ilike(pattern, escape="\\"),
        AuditLog.incident_type.ilike(pattern, escape="\\"),
        AuditLog.action_type.ilike(pattern, escape="\\"),
        AuditLog.result_status.ilike(pattern, escape="\\"),
        AuditLog.equipment_name.ilike(pattern, escape="\\"),
        AuditLog.equipment_ip.ilike(pattern, escape="\\"),
        cast(AuditLog.port_index, String).ilike(pattern, escape="\\"),
        AuditLog.target_ip.ilike(pattern, escape="\\"),
        AuditLog.target_mac.ilike(pattern, escape="\\"),
        AuditLog.message.ilike(pattern, escape="\\"),
        Administrator.system_username.ilike(pattern, escape="\\"),
        AuditLog.incident.has(
            or_(
                Incident.incident_type.ilike(pattern, escape="\\"),
                Incident.description.ilike(pattern, escape="\\"),
            )
        ),
        AuditLog.remediation.has(
            or_(
                Remediation.action_type.ilike(pattern, escape="\\"),
                Remediation.status.ilike(pattern, escape="\\"),
                cast(Remediation.port_index, String).ilike(pattern, escape="\\"),
                Remediation.switch_port.has(
                    SwitchPort.network_switch.has(
                        NetworkSwitch.name.ilike(pattern, escape="\\")
                    )
                ),
            )
        ),
    ]
    if term.casefold() in "system":
        conditions.append(AuditLog.administrator_id.is_(None))
    return conditions


def _filtered_audit_statement(
    *,
    date_value: str = "",
    search: str = "",
):
    """Build a period filter plus a free multi-field, multi-word search."""

    statement = db.select(AuditLog).order_by(AuditLog.event_timestamp.desc())
    if date_value:
        start, end = _audit_period_bounds(date_value)
        statement = statement.where(
            AuditLog.event_timestamp >= start,
            AuditLog.event_timestamp < end,
        )
    terms = _audit_search_terms(search)
    if terms:
        statement = statement.outerjoin(AuditLog.administrator)
        for term in terms:
            statement = statement.where(or_(*_audit_term_conditions(term)))
    return statement


def _audit_action(entry: AuditLog) -> str:
    if entry.action_type:
        return entry.action_type
    if entry.remediation:
        return entry.remediation.action_type
    return "Not available"


def _audit_result(entry: AuditLog) -> str:
    if entry.remediation:
        return entry.remediation.status
    if entry.result_status:
        return entry.result_status
    return "INFO"


def _audit_switch_name(entry: AuditLog) -> str:
    if entry.equipment_name:
        return entry.equipment_name
    if entry.remediation and entry.remediation.switch_port:
        return entry.remediation.switch_port.network_switch.name
    return "Not available"


def _audit_port(entry: AuditLog) -> str:
    if entry.port_index is not None:
        return str(entry.port_index)
    if entry.remediation and entry.remediation.port_index is not None:
        return str(entry.remediation.port_index)
    return "Not available"


def _audit_administrator(entry: AuditLog) -> str:
    if entry.administrator:
        return entry.administrator.system_username
    return "SYSTEM"


def _display_audit_entries(entries: list[AuditLog]) -> None:
    count = len(entries)
    label = "entry" if count == 1 else "entries"
    click.echo(f"\nOKAPI - AUDIT LOGS ({count} {label})")
    click.echo("=" * 56)
    for index, entry in enumerate(entries, start=1):
        click.echo(
            f"[{index}/{count}]\n"
            f"Date / time   : {local_time(entry.event_timestamp)}\n"
            f"Event         : {entry.event_type}\n"
            f"Action        : {_audit_action(entry)}\n"
            f"Result        : {_audit_result(entry)}\n"
            f"Administrator : {_audit_administrator(entry)}\n"
            f"Switch        : {_audit_switch_name(entry)}\n"
            f"Port          : {_audit_port(entry)}"
        )
        if index != count:
            click.echo("-" * 56)


def _logs() -> None:
    mode = click.prompt("[1] Latest logs [2] Filter logs [B] Back", default="1").strip().upper()
    if mode == "B":
        return
    statement = db.select(AuditLog).order_by(AuditLog.event_timestamp.desc())
    if mode == "2":
        date_value = click.prompt(
            "Date / period (YYYY, YYYY-MM, or YYYY-MM-DD; blank = any)",
            default="",
            show_default=False,
        ).strip()
        search = click.prompt(
            "Search word or phrase (blank = any)",
            default="",
            show_default=False,
        ).strip()
        try:
            statement = _filtered_audit_statement(
                date_value=date_value,
                search=search,
            )
        except ValueError as exc:
            click.echo(str(exc))
            return
    if mode != "2":
        statement = statement.limit(20)
    entries = list(db.session.execute(statement).scalars())
    if not entries:
        click.echo("No audit logs found.")
        return
    _display_audit_entries(entries)


def _actor_label(entry: AuditLog | None) -> str:
    if entry is None or entry.administrator is None:
        return "Executed by : SYSTEM"
    username = entry.administrator.system_username
    if entry.event_type == "REMEDIATION_APPROVED":
        return f"Approved by : {username}"
    if entry.event_type == "REMEDIATION_REFUSED":
        return f"Rejected by : {username}"
    if "ROLLBACK" in entry.event_type:
        return f"Requested by : {username}"
    if entry.remediation and entry.remediation.authorization_mode == "SUPERVISED":
        return f"Approved by : {username}"
    return f"Performed by : {username}"


def _remediation_actor_label(remediation: Remediation) -> str:
    if remediation.authorization_mode == "AUTOMATIC":
        return "Executed by : SYSTEM"
    event_type = (
        "REMEDIATION_REFUSED"
        if remediation.status == "REJECTED_BY_ADMIN"
        else "REMEDIATION_APPROVED"
    )
    entry = db.session.execute(
        db.select(AuditLog)
        .where(
            AuditLog.remediation_id == remediation.remediation_id,
            AuditLog.event_type == event_type,
            AuditLog.administrator_id.is_not(None),
        )
        .order_by(AuditLog.event_timestamp.desc())
    ).scalars().first()
    if entry is None or entry.administrator is None:
        label = "Rejected by" if event_type == "REMEDIATION_REFUSED" else "Approved by"
        return f"{label} : NOT RECORDED"
    label = "Rejected by" if event_type == "REMEDIATION_REFUSED" else "Approved by"
    return f"{label} : {entry.administrator.system_username}"


def _rollback(administrator: Administrator) -> None:
    items = available_rollbacks()
    if not items:
        click.echo("Rollback unavailable. No successful remediation is available.")
        return
    click.echo("OKAPI - AVAILABLE ROLLBACKS")
    for number, remediation in enumerate(items, 1):
        target = _rollback_target(remediation)
        state = (
            f"Current VLAN    : {remediation.applied_vlan_id}\n"
            f"    Restore VLAN    : {remediation.previous_vlan_id}"
            if remediation.action_type == "QUARANTINE_VLAN"
            else f"Current state   : {_admin_status_label(remediation.applied_port_status)}\n"
            f"    Restore to      : {_admin_status_label(remediation.previous_port_status)}"
        )
        click.echo(
            f"\n[{number}] {local_time(remediation.start_time)}\n"
            f"    Target          : {target}\n"
            f"    Action          : {remediation.action_type}\n"
            f"    {state}\n"
            f"    Mode            : {remediation.authorization_mode}\n"
            f"    {_remediation_actor_label(remediation)}"
        )
    selected = click.prompt("Select remediation (or B to go back)", default="B").strip()
    if selected.upper() == "B":
        return
    try:
        remediation = items[int(selected) - 1]
        reauthenticate_for_critical_action(administrator, "ROLLBACK")
        observed = rollback_snmp_action(
            remediation,
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


def _rollback_target(remediation: Remediation) -> str:
    switch_port = remediation.switch_port
    host = remediation.target_host
    host_label = (
        host.ip_address
        if host and host.ip_address
        else host.mac_address
        if host
        else switch_port.network_switch.name
        if switch_port
        else "Unknown target"
    )
    port_label = switch_port.port_name if switch_port and switch_port.port_name else remediation.port_index
    return f"{host_label} / {port_label}"


def _admin_status_label(value: str | None) -> str:
    if value is None:
        return "UNKNOWN"
    normalized = value.strip().lower()
    if normalized in {"1", "up", "up(1)"}:
        return "UP"
    if normalized in {"2", "down", "down(2)"}:
        return "DOWN"
    return "UNKNOWN"


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


def _system_status(administrator: Administrator) -> None:
    registry = current_app.extensions.get("snmp_mib_registry")
    mib_ready = bool(registry and registry.status.ready)
    schedule = CalendarPolicy.from_file(
        current_app.config["AUTOMATION_SCHEDULE_PATH"]
    ).decide()
    webhook_ready = bool(
        current_app.config["WEBHOOK_TOKEN"]
        and current_app.config["WEBHOOK_ALLOWED_SOURCE_IPS"]
    )
    dry_run = is_dry_run_enabled()
    values = (
        ("Administrator", administrator.system_username),
        ("Zabbix integration", "READY" if webhook_ready else "NOT READY"),
        ("SNMPv3", "READY" if mib_ready else "NOT READY"),
        ("SNMP writes", _snmp_write_state()),
        ("Dry-run mode", "ON" if dry_run else "OFF"),
        ("Authorization mode", schedule.mode),
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
    rollback_count = len(available_rollbacks())
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
            _system_status(administrator)
        else:
            click.echo("Invalid selection.")


okapi_cli.callback = okapi

from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import click
from flask import current_app
from flask.cli import AppGroup, with_appcontext
from app.extensions import db
from app.models import (
    Administrator,
    AuditLog,
    Incident,
    NetworkSwitch,
    Remediation,
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


ACTION_LABELS = {
    "REACTIVATE_PORT": "Reactivate port",
    "SHUTDOWN_PORT": "Shutdown port",
    "QUARANTINE_VLAN": "Quarantine VLAN",
    "NO_ACTION": "No network action",
}

REASON_LABELS = {
    "target_is_whitelisted": "Protected port",
    "explicit_admin_approval_required": "Administrator approval required",
    "quarantine_vlan_precondition_failed": (
        "Quarantine VLAN unavailable or not isolated"
    ),
    "target_not_confirmed": "Network target could not be confirmed",
    "playbook_forbids_network_change": (
        "No network remediation allowed by playbook"
    ),
}


@dataclass(frozen=True)
class HistoryRecord:
    incident: Incident | None
    remediation: Remediation | None
    audit: AuditLog | None
    logs: tuple[AuditLog, ...]


def _aware_utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _history_audit(logs: tuple[AuditLog, ...]) -> AuditLog | None:
    with_result = [entry for entry in logs if entry.result_status]
    candidates = with_result or list(logs)
    if not candidates:
        return None
    return max(candidates, key=lambda entry: _aware_utc(entry.event_timestamp))


def _history_records() -> list[HistoryRecord]:
    incidents = list(
        db.session.execute(
            db.select(Incident).order_by(Incident.detected_at.desc())
        ).scalars()
    )
    records: list[HistoryRecord] = []
    attached_log_ids: set[str] = set()

    for incident in incidents:
        incident_logs = tuple(incident.audit_logs)
        attached_log_ids.update(entry.log_id for entry in incident_logs)
        remediations = sorted(
            incident.remediations,
            key=lambda item: _aware_utc(item.start_time),
        )
        if not remediations:
            records.append(
                HistoryRecord(
                    incident=incident,
                    remediation=None,
                    audit=_history_audit(incident_logs),
                    logs=incident_logs,
                )
            )
            continue

        generic_logs = tuple(
            entry for entry in incident_logs if entry.remediation_id is None
        )
        for remediation in remediations:
            remediation_logs = tuple(
                entry
                for entry in incident_logs
                if entry.remediation_id == remediation.remediation_id
            )
            context_logs = (*generic_logs, *remediation_logs)
            records.append(
                HistoryRecord(
                    incident=incident,
                    remediation=remediation,
                    audit=_history_audit(remediation_logs or context_logs),
                    logs=context_logs,
                )
            )

    all_logs = list(
        db.session.execute(
            db.select(AuditLog).order_by(AuditLog.event_timestamp.desc())
        ).scalars()
    )
    for entry in all_logs:
        if entry.log_id in attached_log_ids:
            continue
        records.append(
            HistoryRecord(
                incident=entry.incident,
                remediation=entry.remediation,
                audit=entry,
                logs=(entry,),
            )
        )

    return sorted(records, key=_history_timestamp, reverse=True)


def _history_timestamp(record: HistoryRecord) -> datetime:
    if record.incident and record.incident.detected_at:
        return _aware_utc(record.incident.detected_at)
    if record.audit:
        return _aware_utc(record.audit.event_timestamp)
    if record.remediation:
        return _aware_utc(record.remediation.start_time)
    return _aware_utc(None)


def _history_incident_type(record: HistoryRecord) -> str:
    if record.incident and record.incident.incident_type:
        return record.incident.incident_type
    if record.audit and record.audit.incident_type:
        return record.audit.incident_type
    return "Unknown incident"


def _history_action(record: HistoryRecord) -> str:
    technical = None
    if record.audit and record.audit.action_type:
        technical = record.audit.action_type
    elif record.remediation:
        technical = record.remediation.action_type
    return technical or "NO_ACTION"


def _history_action_label(record: HistoryRecord) -> str:
    technical = _history_action(record)
    return ACTION_LABELS.get(technical, technical.replace("_", " ").title())


def _history_mode(record: HistoryRecord) -> str:
    entries = sorted(
        record.logs,
        key=lambda entry: _aware_utc(entry.event_timestamp),
        reverse=True,
    )
    for entry in entries:
        execution_mode = _audit_details(entry).get("execution_mode")
        if execution_mode in {"AUTOMATIC", "SUPERVISED", "NONE"}:
            return str(execution_mode)
    if _history_result(record) == "ESCALATED":
        return "NONE"
    if record.remediation:
        return record.remediation.authorization_mode
    return "NONE"


def _history_result(record: HistoryRecord) -> str:
    if record.audit and record.audit.result_status:
        return record.audit.result_status
    if record.remediation:
        return record.remediation.status
    if record.incident:
        return record.incident.processing_status
    return "INFO"


def _history_switch_name(record: HistoryRecord) -> str:
    if record.remediation and record.remediation.switch_port:
        return record.remediation.switch_port.network_switch.name
    entries = sorted(
        record.logs,
        key=lambda entry: _aware_utc(entry.event_timestamp),
        reverse=True,
    )
    for entry in entries:
        if entry.equipment_name:
            return entry.equipment_name
    return "Not available"


def _history_port_index(record: HistoryRecord) -> int | None:
    if record.remediation and record.remediation.port_index is not None:
        return record.remediation.port_index
    for entry in record.logs:
        if entry.port_index is not None:
            return entry.port_index
    return None


def _history_port_name(record: HistoryRecord) -> str:
    if record.remediation and record.remediation.switch_port:
        port = record.remediation.switch_port
        if port.port_name:
            return port.port_name
    index = _history_port_index(record)
    return f"Index {index}" if index is not None else "Not available"


def _history_administrator(record: HistoryRecord) -> str:
    relevant = sorted(
        record.logs,
        key=lambda entry: _aware_utc(entry.event_timestamp),
        reverse=True,
    )
    for entry in relevant:
        if entry.administrator:
            return entry.administrator.system_username
    return "SYSTEM"


def _history_event_administrator(
    record: HistoryRecord,
    event_predicate,
) -> str | None:
    entries = sorted(
        record.logs,
        key=lambda entry: _aware_utc(entry.event_timestamp),
        reverse=True,
    )
    for entry in entries:
        if (
            record.remediation
            and entry.remediation_id != record.remediation.remediation_id
        ):
            continue
        if event_predicate(entry) and entry.administrator:
            return entry.administrator.system_username
    return None


def _history_actor_line(record: HistoryRecord) -> str | None:
    result = _history_result(record)
    mode = _history_mode(record)
    if result == "WAITING_ADMIN_APPROVAL":
        return "Approval       : Pending"
    if "ROLLBACK" in result or any(
        "ROLLBACK" in entry.event_type for entry in record.logs
    ):
        username = _history_event_administrator(
            record,
            lambda entry: "ROLLBACK" in entry.event_type,
        )
        return f"Requested by   : {username}" if username else None
    if result == "ESCALATED" or _history_action(record) == "NO_ACTION":
        return None
    if result == "REJECTED_BY_ADMIN":
        username = _history_event_administrator(
            record,
            lambda entry: "REJECT" in entry.event_type
            or "REFUS" in entry.event_type,
        )
        return f"Rejected by    : {username}" if username else None
    if mode == "SUPERVISED":
        username = _history_event_administrator(
            record,
            lambda entry: "APPROV" in entry.event_type,
        ) or _history_event_administrator(record, lambda _entry: True)
        return f"Approved by    : {username}" if username else None
    if mode == "AUTOMATIC":
        return "Performed by   : SYSTEM"
    username = _history_event_administrator(record, lambda _entry: True)
    return f"Performed by   : {username}" if username else None


def _audit_details(entry: AuditLog) -> dict[str, object]:
    if " | " not in entry.message:
        return {}
    raw_details = entry.message.split(" | ", 1)[1]
    try:
        details = json.loads(raw_details)
    except (TypeError, ValueError):
        return {}
    return details if isinstance(details, dict) else {}


def _audit_reason(entry: AuditLog) -> str | None:
    reason = _audit_details(entry).get("reason")
    return str(reason) if reason else None


def _history_reason(record: HistoryRecord) -> str | None:
    entries = sorted(
        record.logs,
        key=lambda entry: _aware_utc(entry.event_timestamp),
        reverse=True,
    )
    for entry in entries:
        reason = _audit_reason(entry)
        if reason:
            return REASON_LABELS.get(reason)
    return None


def _display_history(records: list[HistoryRecord]) -> None:
    count = len(records)
    label = "entry" if count == 1 else "entries"
    click.echo(f"\nOKAPI - INCIDENT & ACTION HISTORY ({count} {label})")
    click.echo("=" * 64)
    for index, record in enumerate(records, start=1):
        incident = record.incident
        reason = _history_reason(record)
        lines = [
            f"[{index}/{count}]",
            "",
            f"Incident       : {_history_incident_type(record)}",
            f"Detected       : {local_time(_history_timestamp(record))}",
            f"Severity       : {incident.severity if incident and incident.severity else 'Not available'}",
            f"Playbook       : {incident.playbook_id if incident else 'Not available'}",
            "",
            f"Switch         : {_history_switch_name(record)}",
            f"Port           : {_history_port_name(record)}",
            "",
            f"Remediation    : {_history_action_label(record)}",
            f"Mode           : {_history_mode(record)}",
            f"Result         : {_history_result(record)}",
        ]
        actor_line = _history_actor_line(record)
        if actor_line:
            lines.append(actor_line)
        if reason:
            lines.append(f"Reason         : {reason}")
        click.echo("\n".join(lines))
        if index != count:
            click.echo("-" * 64)


def _search_terms(value: str) -> list[str]:
    return [term.casefold() for term in re.split(r"[\W_]+", value) if term]


def _matches_text(value: str, query: str) -> bool:
    searchable = value.casefold().replace("_", " ")
    return all(term in searchable for term in _search_terms(query))


def _history_filter_options(
    records: list[HistoryRecord],
    value_getter,
) -> list[str]:
    excluded = {"not available", "unknown incident", "unknown target"}
    return sorted(
        {
            value
            for record in records
            if (value := value_getter(record))
            and value.strip().casefold() not in excluded
        },
        key=str.casefold,
    )


def _switch_filter_options() -> list[str]:
    excluded = {"not available", "unknown target", "pc-suspect"}
    names = db.session.execute(
        db.select(NetworkSwitch.name)
        .distinct()
        .order_by(NetworkSwitch.name)
    ).scalars()
    return [
        name
        for name in names
        if name and name.strip() and name.strip().casefold() not in excluded
    ]


def _prompt_history_filter(
    label: str,
    options: list[str],
    *,
    display_getter=lambda value: value,
) -> str | None:
    click.echo(f"\n{label}:")
    click.echo("[0] Any")
    for index, value in enumerate(options, start=1):
        click.echo(f"[{index}] {display_getter(value)}")
    raw = click.prompt(
        "Select a number or type partial information",
        default="0",
    ).strip()
    if not raw or raw.casefold() == "any" or raw == "0":
        return None
    if raw.isdigit():
        selected = int(raw)
        if selected < 1 or selected > len(options):
            raise ValueError("Invalid filter selection.")
        return options[selected - 1]
    return raw


def _port_matches(record: HistoryRecord, query: str) -> bool:
    normalized = query.strip().casefold()
    index_match = re.fullmatch(r"(?:ethernet|et)?\s*(\d+)", normalized)
    if index_match:
        index = _history_port_index(record)
        return index is not None and index == int(index_match.group(1))
    return _matches_text(_history_port_name(record), query)


def _history_search_text(record: HistoryRecord) -> str:
    incident = record.incident
    values = [
        _history_incident_type(record),
        incident.description if incident and incident.description else "",
        incident.playbook_id if incident else "",
        incident.severity if incident and incident.severity else "",
        _history_switch_name(record),
        _history_port_name(record),
        str(_history_port_index(record) or ""),
        _history_action(record),
        _history_action_label(record),
        _history_mode(record),
        _history_result(record),
        _history_administrator(record),
        _history_reason(record) or "",
        *[entry.message for entry in record.logs],
    ]
    return " ".join(values)


def _filter_history_records(
    records: list[HistoryRecord],
    *,
    date_value: str = "",
    incident: str | None = None,
    switch: str | None = None,
    port: str = "",
    remediation: str | None = None,
    mode: str | None = None,
    result: str | None = None,
    administrator: str = "",
    search: str = "",
) -> list[HistoryRecord]:
    start = end = None
    if date_value:
        start, end = _audit_period_bounds(date_value)

    matches: list[HistoryRecord] = []
    for record in records:
        timestamp = _history_timestamp(record)
        if start is not None and end is not None and not (start <= timestamp < end):
            continue
        if incident and not _matches_text(_history_incident_type(record), incident):
            continue
        if switch and not _matches_text(_history_switch_name(record), switch):
            continue
        if port and not _port_matches(record, port):
            continue
        if remediation and not (
            _matches_text(_history_action(record), remediation)
            or _matches_text(_history_action_label(record), remediation)
        ):
            continue
        if mode and not _matches_text(_history_mode(record), mode):
            continue
        if result and not _matches_text(_history_result(record), result):
            continue
        if administrator and not _matches_text(
            _history_administrator(record), administrator
        ):
            continue
        if search and not _matches_text(_history_search_text(record), search):
            continue
        matches.append(record)
    return matches


def _guided_history_filters(records: list[HistoryRecord]) -> list[HistoryRecord]:
    incident = _prompt_history_filter(
        "Filter by incident",
        _history_filter_options(records, _history_incident_type),
    )
    date_value = click.prompt(
        "Date / period (YYYY, YYYY-MM, or YYYY-MM-DD; blank = any)",
        default="",
        show_default=False,
    ).strip()
    switch = _prompt_history_filter(
        "Filter by switch",
        _switch_filter_options(),
    )
    port = click.prompt(
        "Port (Ethernet1, Et1 or 1; blank = any)",
        default="",
        show_default=False,
    ).strip()
    remediation = _prompt_history_filter(
        "Filter by remediation",
        _history_filter_options(records, _history_action),
        display_getter=lambda value: ACTION_LABELS.get(value, value),
    )
    mode = _prompt_history_filter(
        "Filter by mode",
        _history_filter_options(records, _history_mode),
    )
    result = _prompt_history_filter(
        "Filter by result",
        _history_filter_options(records, _history_result),
    )
    administrator = click.prompt(
        "Administrator (blank = any)",
        default="",
        show_default=False,
    ).strip()
    search = click.prompt(
        "Additional information (word or phrase; blank = any)",
        default="",
        show_default=False,
    ).strip()
    return _filter_history_records(
        records,
        date_value=date_value,
        incident=incident,
        switch=switch,
        port=port,
        remediation=remediation,
        mode=mode,
        result=result,
        administrator=administrator,
        search=search,
    )


def _logs() -> None:
    mode = click.prompt(
        "[1] Latest history [2] Filter history [B] Back",
        default="1",
    ).strip().upper()
    if mode == "B":
        return
    records = _history_records()
    try:
        if mode == "2":
            records = _guided_history_filters(records)
        elif mode == "1":
            records = records[:20]
        else:
            click.echo("Invalid selection.")
            return
    except ValueError as exc:
        click.echo(str(exc))
        return
    if not records:
        click.echo("No history found.")
        return
    _display_history(records)


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
            "[6] Remediation history [7] Incident & action history [8] Rollback "
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

from __future__ import annotations

import json
from dataclasses import asdict

import click
from flask.cli import AppGroup

from app.extensions import db
from app.models import Incident
from app.services.administrators import (
    IdentityError,
    ReauthenticationError,
    reauthenticate_for_critical_action,
    resolve_current_administrator,
)
from app.services.remediation import (
    RemediationError,
    UnsafeOperationBlocked,
    approve_incident,
    evaluate_incident,
    execute_authorized_remediation,
    refuse_incident,
)
from app.services.snmp_execution import rollback_snmp_action
from app.services.snmp_preparation import (
    inspect_physical_disconnection_with_snmp,
    prepare_incident_with_snmp,
    prepare_port_incident_with_snmp,
)
from app.services.runtime_settings import is_dry_run_enabled
from app.snmp.value_formatting import (
    format_action_value,
    format_if_admin_status,
    format_if_oper_status,
    format_vlan_id,
)


remediation_cli = AppGroup("remediation", help="Advanced remediation maintenance commands.")


def _display_preparation_result(result) -> dict[str, object]:
    payload = asdict(result)
    resolution = payload.get("resolution")
    if isinstance(resolution, dict):
        if "previous_if_admin_status" in resolution:
            resolution["previous_if_admin_status"] = format_if_admin_status(
                resolution["previous_if_admin_status"]
            )
        if resolution.get("previous_pvid") is not None:
            resolution["previous_pvid"] = format_vlan_id(
                resolution["previous_pvid"]
            )
    return payload


def _display_physical_check(result) -> dict[str, object]:
    payload = asdict(result)
    payload["if_admin_status"] = format_if_admin_status(
        payload["if_admin_status"]
    )
    payload["if_oper_status"] = format_if_oper_status(payload["if_oper_status"])
    return payload


def _incident_or_fail(incident_id: str) -> Incident:
    incident = db.session.get(Incident, incident_id)
    if incident is None:
        raise click.ClickException("Incident not found.")
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
    if target_confirmed and (switch_id is None or port_index is None):
        raise click.ClickException(
            "--switch-id and --port-index are required for a confirmed target."
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
def approve_command(incident_id: str) -> None:
    try:
        administrator = resolve_current_administrator()
        if not is_dry_run_enabled():
            reauthenticate_for_critical_action(
                administrator, "APPROVE_REAL_DISRUPTIVE_REMEDIATION"
            )
        remediation = approve_incident(
            _incident_or_fail(incident_id), administrator.administrator_id
        )
    except (IdentityError, ReauthenticationError, RemediationError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(remediation.to_dict(), indent=2, ensure_ascii=False))


@remediation_cli.command("prepare-snmp")
@click.argument("incident_id")
@click.option("--switch-id", required=True)
@click.option("--target-mac")
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
    click.echo(
        json.dumps(_display_preparation_result(result), indent=2, ensure_ascii=False)
    )


@remediation_cli.command("prepare-port")
@click.argument("incident_id")
@click.option("--switch-id", required=True)
@click.option("--bridge-port", required=True, type=int)
@click.option("--interface-hint")
@click.option("--target-mac")
@click.option("--target-ip")
def prepare_port_command(incident_id: str, switch_id: str, bridge_port: int,
                         interface_hint: str | None, target_mac: str | None,
                         target_ip: str | None) -> None:
    """Confirm a port-centric target through read-only SNMP checks."""
    try:
        result = prepare_port_incident_with_snmp(
            _incident_or_fail(incident_id), switch_id=switch_id,
            bridge_port=bridge_port, interface_hint=interface_hint,
            target_mac=target_mac, target_ip=target_ip,
        )
    except RemediationError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        json.dumps(_display_preparation_result(result), indent=2, ensure_ascii=False)
    )


@remediation_cli.command("inspect-physical")
@click.argument("incident_id")
@click.option("--switch-id", required=True)
@click.option("--bridge-port", required=True, type=int)
def inspect_physical_command(
    incident_id: str, switch_id: str, bridge_port: int
) -> None:
    """Run read-only status checks for a physical disconnection."""

    try:
        result = inspect_physical_disconnection_with_snmp(
            _incident_or_fail(incident_id),
            switch_id=switch_id,
            bridge_port=bridge_port,
        )
    except RemediationError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        json.dumps(_display_physical_check(result), indent=2, ensure_ascii=False)
    )


@remediation_cli.command("refuse")
@click.argument("incident_id")
def refuse_command(incident_id: str) -> None:
    try:
        administrator = resolve_current_administrator()
        remediation = refuse_incident(
            _incident_or_fail(incident_id), administrator.administrator_id
        )
    except (IdentityError, RemediationError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(remediation.to_dict(), indent=2, ensure_ascii=False))


@remediation_cli.command("execute")
@click.argument("incident_id")
def execute_command(incident_id: str) -> None:
    incident = _incident_or_fail(incident_id)
    try:
        result = execute_authorized_remediation(incident)
    except (RemediationError, UnsafeOperationBlocked) as exc:
        raise click.ClickException(str(exc)) from exc
    payload = asdict(result)
    remediation = incident.remediations[-1]
    if remediation.action_type == "QUARANTINE_VLAN":
        payload["requested_vlan"] = format_vlan_id(result.requested_vlan)
        payload["observed_vlan"] = format_vlan_id(result.observed_vlan)
    else:
        payload.pop("requested_vlan", None)
        payload.pop("observed_vlan", None)
        payload["requested_state"] = format_action_value(
            remediation.action_type, result.requested_vlan
        )
        payload["observed_state"] = format_action_value(
            remediation.action_type, result.observed_vlan
        )
    click.echo(json.dumps(payload, indent=2, ensure_ascii=False))


@remediation_cli.command("rollback")
@click.argument("incident_id")
def rollback_command(incident_id: str) -> None:
    try:
        administrator = resolve_current_administrator()
        reauthenticate_for_critical_action(administrator, "ROLLBACK")
        incident = _incident_or_fail(incident_id)
        observed_value = rollback_snmp_action(
            incident,
            administrator_id=administrator.administrator_id,
        )
    except (
        IdentityError,
        ReauthenticationError,
        RemediationError,
        UnsafeOperationBlocked,
    ) as exc:
        raise click.ClickException(str(exc)) from exc
    remediation = incident.remediations[-1]
    label = (
        "restored_vlan"
        if remediation.action_type == "QUARANTINE_VLAN"
        else "restored_state"
    )
    click.echo(
        json.dumps(
            {label: format_action_value(remediation.action_type, observed_value)},
            indent=2,
        )
    )

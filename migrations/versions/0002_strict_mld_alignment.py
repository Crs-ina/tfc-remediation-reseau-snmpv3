"""Aligne la persistance sur le MLD strict a six entites.

Revision ID: 0002_strict_mld
Revises: 0001_initial

Les donnees des champs retires sont conservees dans ``audit_logs.message``.
Une ancienne whitelist non vide bloque volontairement la migration afin que
l'operateur l'exporte d'abord vers ``config/whitelist.json``.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa


revision = "0002_strict_mld"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def _json(data: dict[str, object]) -> str:
    return json.dumps(data, ensure_ascii=False, default=str, sort_keys=True)


def _datetime(value: object) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace(" ", "T", 1))


def upgrade() -> None:
    connection = op.get_bind()
    whitelist_count = connection.execute(
        sa.text("SELECT COUNT(*) FROM whitelist_entries")
    ).scalar_one()
    if whitelist_count:
        raise RuntimeError(
            "Migration interrompue: exportez les entrees de whitelist vers "
            "config/whitelist.json, videz whitelist_entries, puis relancez."
        )

    legacy_incidents = connection.execute(
        sa.text("SELECT * FROM incidents")
    ).mappings().all()
    legacy_switches = connection.execute(
        sa.text("SELECT * FROM equipements")
    ).mappings().all()
    legacy_remediations = connection.execute(
        sa.text("SELECT * FROM remediations")
    ).mappings().all()
    legacy_audits = connection.execute(
        sa.text("SELECT * FROM audit_logs")
    ).mappings().all()
    now = datetime.now(timezone.utc)

    # SQLite conserve les noms d'index lors d'un renommage de table. On retire
    # ceux des tables temporaires afin de reutiliser les noms conventionnels.
    op.drop_index("ix_audit_logs_incident_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_timestamp", table_name="audit_logs")
    op.drop_index("ix_remediations_incident_id", table_name="remediations")
    op.rename_table("audit_logs", "legacy_audit_logs")
    op.rename_table("remediations", "legacy_remediations")
    op.rename_table("whitelist_entries", "legacy_whitelist_entries")
    op.rename_table("equipements", "network_switches")

    with op.batch_alter_table("network_switches") as batch_op:
        batch_op.alter_column(
            "id", new_column_name="switch_id", existing_type=sa.String(36)
        )
        batch_op.drop_column("vendor")
        batch_op.drop_column("snmp_profile_name")
        batch_op.drop_column("enabled")

    with op.batch_alter_table("incidents") as batch_op:
        batch_op.alter_column(
            "id", new_column_name="incident_id", existing_type=sa.String(36)
        )
        batch_op.alter_column(
            "equipment_management_ip",
            new_column_name="source_ip",
            existing_type=sa.String(45),
        )
        batch_op.alter_column(
            "state",
            new_column_name="processing_status",
            existing_type=sa.String(64),
        )
        batch_op.add_column(sa.Column("description", sa.Text(), nullable=True))
        for column_name in (
            "received_at",
            "equipment_name",
            "target_ip",
            "target_mac",
            "target_interface_hint",
            "physical_port",
            "action_requested",
            "execution_mode",
            "final_status",
            "identification_attempts",
            "remediation_attempts",
            "whitelist_result",
            "admin_decision",
            "payload_json",
            "created_at",
            "updated_at",
        ):
            batch_op.drop_column(column_name)

    op.create_table(
        "switch_ports",
        sa.Column(
            "switch_id",
            sa.String(36),
            sa.ForeignKey("network_switches.switch_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("port_index", sa.Integer(), primary_key=True),
        sa.Column("port_name", sa.String(128)),
        sa.Column("status", sa.String(32)),
        sa.Column("vlan_id", sa.Integer()),
    )
    op.create_table(
        "network_hosts",
        sa.Column("mac_address", sa.String(32), primary_key=True),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("switch_id", sa.String(36)),
        sa.Column("port_index", sa.Integer()),
        sa.ForeignKeyConstraint(
            ["switch_id", "port_index"],
            ["switch_ports.switch_id", "switch_ports.port_index"],
            name="fk_network_host_switch_port",
        ),
    )
    op.create_table(
        "remediations",
        sa.Column("remediation_id", sa.String(36), primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(36),
            sa.ForeignKey("incidents.incident_id", ondelete="CASCADE"),
            nullable=False,
        ),
        # Ces trois champs sont nullables uniquement pour reprendre d'anciens
        # enregistrements sans inventer une cible. Le service les exige pour
        # toute nouvelle remediation.
        sa.Column(
            "target_mac_address",
            sa.String(32),
            sa.ForeignKey("network_hosts.mac_address"),
        ),
        sa.Column("switch_id", sa.String(36)),
        sa.Column("port_index", sa.Integer()),
        sa.Column("action_type", sa.String(64), nullable=False),
        sa.Column("authorization_mode", sa.String(32), nullable=False),
        sa.Column("start_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_time", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("previous_port_status", sa.String(32)),
        sa.Column("previous_vlan_id", sa.Integer()),
        sa.ForeignKeyConstraint(
            ["switch_id", "port_index"],
            ["switch_ports.switch_id", "switch_ports.port_index"],
            name="fk_remediation_switch_port",
        ),
        sa.CheckConstraint(
            "authorization_mode IN ('SUPERVISED', 'AUTOMATIC')",
            name="ck_remediation_authorization_mode",
        ),
    )
    op.create_index("ix_remediations_incident_id", "remediations", ["incident_id"])
    op.create_index(
        "ix_remediations_target_mac_address",
        "remediations",
        ["target_mac_address"],
    )

    remediation_table = sa.table(
        "remediations",
        sa.column("remediation_id", sa.String),
        sa.column("incident_id", sa.String),
        sa.column("target_mac_address", sa.String),
        sa.column("switch_id", sa.String),
        sa.column("port_index", sa.Integer),
        sa.column("action_type", sa.String),
        sa.column("authorization_mode", sa.String),
        sa.column("start_time", sa.DateTime),
        sa.column("end_time", sa.DateTime),
        sa.column("status", sa.String),
        sa.column("previous_port_status", sa.String),
        sa.column("previous_vlan_id", sa.Integer),
    )
    if legacy_remediations:
        op.bulk_insert(
            remediation_table,
            [
                {
                    "remediation_id": row["id"],
                    "incident_id": row["incident_id"],
                    "target_mac_address": None,
                    "switch_id": None,
                    "port_index": None,
                    "action_type": row["action"],
                    "authorization_mode": (
                        "AUTOMATIC"
                        if row["authorization_source"] == "SCHEDULE_POLICY"
                        else "SUPERVISED"
                    ),
                    "start_time": _datetime(row["requested_at"]) or now,
                    "end_time": _datetime(row["completed_at"]),
                    "status": row["status"],
                    "previous_port_status": None,
                    "previous_vlan_id": None,
                }
                for row in legacy_remediations
            ],
        )

    op.create_table(
        "audit_logs",
        sa.Column("log_id", sa.String(36), primary_key=True),
        sa.Column("event_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column(
            "incident_id",
            sa.String(36),
            sa.ForeignKey("incidents.incident_id", ondelete="SET NULL"),
        ),
        sa.Column(
            "remediation_id",
            sa.String(36),
            sa.ForeignKey("remediations.remediation_id", ondelete="SET NULL"),
        ),
        sa.Column("equipment_name", sa.String(255)),
        sa.Column("equipment_ip", sa.String(45)),
        sa.Column("port_index", sa.Integer()),
        sa.Column("target_ip", sa.String(45)),
        sa.Column("target_mac", sa.String(32)),
        sa.Column("incident_type", sa.String(64)),
        sa.Column("action_type", sa.String(64)),
        sa.Column("result_status", sa.String(64)),
        sa.Column("message", sa.Text(), nullable=False),
    )
    op.create_index("ix_audit_logs_event_timestamp", "audit_logs", ["event_timestamp"])
    op.create_index("ix_audit_logs_incident_id", "audit_logs", ["incident_id"])
    op.create_index("ix_audit_logs_remediation_id", "audit_logs", ["remediation_id"])

    audit_table = sa.table(
        "audit_logs",
        sa.column("log_id", sa.String),
        sa.column("event_timestamp", sa.DateTime),
        sa.column("event_type", sa.String),
        sa.column("incident_id", sa.String),
        sa.column("remediation_id", sa.String),
        sa.column("equipment_name", sa.String),
        sa.column("equipment_ip", sa.String),
        sa.column("port_index", sa.Integer),
        sa.column("target_ip", sa.String),
        sa.column("target_mac", sa.String),
        sa.column("incident_type", sa.String),
        sa.column("action_type", sa.String),
        sa.column("result_status", sa.String),
        sa.column("message", sa.Text),
    )
    audit_rows: list[dict[str, object]] = []
    for row in legacy_audits:
        audit_rows.append(
            {
                "log_id": row["id"],
                "event_timestamp": _datetime(row["timestamp"]) or now,
                "event_type": row["event"],
                "incident_id": row["incident_id"],
                "remediation_id": None,
                "equipment_name": None,
                "equipment_ip": None,
                "port_index": None,
                "target_ip": None,
                "target_mac": None,
                "incident_type": None,
                "action_type": None,
                "result_status": row["state_after"],
                "message": _json(
                    {
                        "actor": row["actor"],
                        "state_before": row["state_before"],
                        "legacy_details_json": row["details_json"],
                    }
                ),
            }
        )
    for row in legacy_remediations:
        audit_rows.append(
            {
                "log_id": str(uuid.uuid4()),
                "event_timestamp": now,
                "event_type": "LEGACY_REMEDIATION_METADATA",
                "incident_id": row["incident_id"],
                "remediation_id": row["id"],
                "equipment_name": None,
                "equipment_ip": None,
                "port_index": None,
                "target_ip": None,
                "target_mac": None,
                "incident_type": None,
                "action_type": row["action"],
                "result_status": row["status"],
                "message": _json(dict(row)),
            }
        )
    for row in legacy_incidents:
        audit_rows.append(
            {
                "log_id": str(uuid.uuid4()),
                "event_timestamp": now,
                "event_type": "LEGACY_INCIDENT_METADATA",
                "incident_id": row["id"],
                "remediation_id": None,
                "equipment_name": row["equipment_name"],
                "equipment_ip": row["equipment_management_ip"],
                "port_index": None,
                "target_ip": row["target_ip"],
                "target_mac": row["target_mac"],
                "incident_type": row["incident_type"],
                "action_type": row["action_requested"],
                "result_status": row["final_status"] or row["state"],
                "message": _json(
                    {
                        key: row[key]
                        for key in (
                            "received_at",
                            "target_interface_hint",
                            "physical_port",
                            "execution_mode",
                            "identification_attempts",
                            "remediation_attempts",
                            "whitelist_result",
                            "admin_decision",
                            "payload_json",
                            "created_at",
                            "updated_at",
                        )
                    }
                ),
            }
        )
    for row in legacy_switches:
        audit_rows.append(
            {
                "log_id": str(uuid.uuid4()),
                "event_timestamp": now,
                "event_type": "LEGACY_SWITCH_METADATA",
                "incident_id": None,
                "remediation_id": None,
                "equipment_name": row["name"],
                "equipment_ip": row["management_ip"],
                "port_index": None,
                "target_ip": None,
                "target_mac": None,
                "incident_type": None,
                "action_type": None,
                "result_status": "ARCHIVED",
                "message": _json(
                    {
                        "vendor": row["vendor"],
                        "snmp_profile_name": row["snmp_profile_name"],
                        "enabled": row["enabled"],
                    }
                ),
            }
        )
    if audit_rows:
        op.bulk_insert(audit_table, audit_rows)

    # Les anciennes structures ne sont retirees qu'apres archivage complet.
    op.drop_table("legacy_audit_logs")
    op.drop_table("legacy_remediations")
    op.drop_table("legacy_whitelist_entries")


def downgrade() -> None:
    raise RuntimeError(
        "Downgrade refuse: il supprimerait des entites MLD. "
        "Restaurez une sauvegarde de la revision 0001 si necessaire."
    )

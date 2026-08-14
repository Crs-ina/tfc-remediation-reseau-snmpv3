"""Schema initial du prototype.

Revision ID: 0001_initial
Revises: None
"""

from alembic import op
import sqlalchemy as sa


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("zabbix_event_id", sa.String(128), nullable=False, unique=True),
        sa.Column("incident_type", sa.String(64)),
        sa.Column("playbook_id", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(32)),
        sa.Column("detected_at", sa.DateTime(timezone=True)),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("equipment_name", sa.String(255)),
        sa.Column("equipment_management_ip", sa.String(45)),
        sa.Column("target_ip", sa.String(45)),
        sa.Column("target_mac", sa.String(32)),
        sa.Column("target_interface_hint", sa.String(128)),
        sa.Column("physical_port", sa.String(128)),
        sa.Column("action_requested", sa.String(64)),
        sa.Column("execution_mode", sa.String(32)),
        sa.Column("state", sa.String(64), nullable=False),
        sa.Column("final_status", sa.String(64)),
        sa.Column("identification_attempts", sa.Integer(), nullable=False),
        sa.Column("remediation_attempts", sa.Integer(), nullable=False),
        sa.Column("whitelist_result", sa.String(32)),
        sa.Column("admin_decision", sa.String(32)),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "equipements",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("management_ip", sa.String(45), nullable=False, unique=True),
        sa.Column("vendor", sa.String(128)),
        sa.Column("model", sa.String(128)),
        sa.Column("snmp_profile_name", sa.String(128)),
        sa.Column("enabled", sa.Boolean(), nullable=False),
    )
    op.create_table(
        "whitelist_entries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("equipment_id", sa.String(36), sa.ForeignKey("equipements.id", ondelete="CASCADE")),
        sa.Column("interface_name", sa.String(128), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("reason", sa.String(255)),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.UniqueConstraint(
            "equipment_id", "interface_name", name="uq_whitelist_equipment_interface"
        ),
    )
    op.create_index("ix_whitelist_entries_equipment_id", "whitelist_entries", ["equipment_id"])
    op.create_table(
        "remediations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("authorization_source", sa.String(32)),
        sa.Column("administrator_id", sa.String(128)),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authorized_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("pre_action_snapshot_json", sa.Text()),
        sa.Column("verification_result", sa.Text()),
        sa.Column("rollback_requested", sa.Boolean(), nullable=False),
        sa.Column("rollback_result", sa.Text()),
    )
    op.create_index("ix_remediations_incident_id", "remediations", ["incident_id"])
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.id", ondelete="CASCADE")),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("event", sa.String(128), nullable=False),
        sa.Column("state_before", sa.String(64)),
        sa.Column("state_after", sa.String(64)),
        sa.Column("details_json", sa.Text(), nullable=False),
    )
    op.create_index("ix_audit_logs_incident_id", "audit_logs", ["incident_id"])
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("remediations")
    op.drop_table("whitelist_entries")
    op.drop_table("equipements")
    op.drop_table("incidents")


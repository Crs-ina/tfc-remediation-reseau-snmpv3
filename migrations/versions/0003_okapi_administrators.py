"""Add OKAPI administrator identity and audit ownership.

Revision ID: 0003_okapi_administrators
Revises: 0002_strict_mld
"""

from alembic import op
import sqlalchemy as sa

revision = "0003_okapi_administrators"
down_revision = "0002_strict_mld"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "administrators",
        sa.Column("administrator_id", sa.String(36), primary_key=True),
        sa.Column("username", sa.String(128), nullable=False),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("username", name="uq_administrators_username"),
    )
    op.create_index("ix_administrators_username", "administrators", ["username"])
    with op.batch_alter_table("audit_logs") as batch_op:
        batch_op.add_column(sa.Column("administrator_id", sa.String(36), nullable=True))
        batch_op.create_foreign_key(
            "fk_audit_logs_administrator", "administrators", ["administrator_id"], ["administrator_id"], ondelete="SET NULL"
        )
        batch_op.create_index("ix_audit_logs_administrator_id", ["administrator_id"])


def downgrade() -> None:
    with op.batch_alter_table("audit_logs") as batch_op:
        batch_op.drop_index("ix_audit_logs_administrator_id")
        batch_op.drop_constraint("fk_audit_logs_administrator", type_="foreignkey")
        batch_op.drop_column("administrator_id")
    op.drop_index("ix_administrators_username", table_name="administrators")
    op.drop_table("administrators")

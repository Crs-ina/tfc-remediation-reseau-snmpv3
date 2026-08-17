"""Replace OKAPI credentials with Linux identity metadata.

Revision ID: 0004_linux_identity
Revises: 0003_okapi_administrators
"""

from alembic import op
import sqlalchemy as sa


revision = "0004_linux_identity"
down_revision = "0003_okapi_administrators"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("ix_administrators_username", table_name="administrators")
    with op.batch_alter_table("administrators") as batch_op:
        batch_op.drop_constraint("uq_administrators_username", type_="unique")
        batch_op.alter_column(
            "username",
            new_column_name="system_username",
            existing_type=sa.String(128),
            existing_nullable=False,
        )
        batch_op.add_column(sa.Column("display_name", sa.String(255), nullable=True))
        batch_op.alter_column(
            "last_login_at",
            new_column_name="last_seen_at",
            existing_type=sa.DateTime(timezone=True),
            existing_nullable=True,
        )
        batch_op.drop_column("password_hash")
        batch_op.drop_column("is_active")
        batch_op.create_unique_constraint(
            "uq_administrators_system_username", ["system_username"]
        )
    op.create_index(
        "ix_administrators_system_username",
        "administrators",
        ["system_username"],
    )


def downgrade() -> None:
    raise RuntimeError(
        "Downgrade refused: OKAPI no longer stores administrator credentials. "
        "Restore a database backup from revision 0003 if required."
    )

"""Store the state actually applied by each remediation.

Revision ID: 0005_applied_state
Revises: 0004_linux_identity

Legacy rows are deliberately left without an applied-state snapshot. Guessing
their post-action state would make them unsafe rollback candidates; they remain
fully visible in remediation history.
"""

from alembic import op
import sqlalchemy as sa


revision = "0005_applied_state"
down_revision = "0004_linux_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("remediations") as batch_op:
        batch_op.add_column(
            sa.Column("applied_port_status", sa.String(32), nullable=True)
        )
        batch_op.add_column(sa.Column("applied_vlan_id", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("remediations") as batch_op:
        batch_op.drop_column("applied_vlan_id")
        batch_op.drop_column("applied_port_status")

"""operator_alerts, and the shares a seed credential may mark for re-key.

Revision ID: 0012_operator_alerts
Revises: 0011_authority_ledger

Additive: the `operator_alerts` table (an Admin grant or a platform-admin appointment, as Origin
co-signed it, listed on the console) and `seed_credentials.rekey_shares` (a JSON list, null for
none: a seed credential marks for re-key only the shares it lists).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0012_operator_alerts"
down_revision: Union[str, None] = "0011_authority_ledger"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "operator_alerts",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("resource_id", sa.String(128), nullable=False),
        sa.Column("subject", sa.String(128), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("detail", sa.Text, nullable=False, server_default=""),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_by", sa.String(128), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_operator_alerts_seq", "operator_alerts", ["seq"])
    with op.batch_alter_table("seed_credentials") as batch:
        batch.add_column(sa.Column("rekey_shares", sa.Text, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("seed_credentials") as batch:
        batch.drop_column("rekey_shares")
    op.drop_index("ix_operator_alerts_seq", table_name="operator_alerts")
    op.drop_table("operator_alerts")

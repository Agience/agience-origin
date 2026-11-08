"""Billing recipients: Ophan's billing mail reads an address only for a billed person (review 21).

Revision ID: 0024_billing_recipients
Revises: 0023_drop_keys_are_not_authority

Additive. `billing_recipients` holds the persons Ophan recorded as billed (an active subscription
from the payment provider's verified event); `billing_recipient_lookups` records each address read
through `/internal/billing-recipients/{id}`.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0024_billing_recipients"
down_revision: Union[str, None] = "0023_drop_keys_are_not_authority"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "billing_recipients",
        sa.Column("person_id", sa.String(64), primary_key=True),
        sa.Column("active", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("plan", sa.String(64), nullable=False, server_default=""),
        sa.Column("recorded_by", sa.String(128), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "billing_recipient_lookups",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("person_id", sa.String(64), nullable=False),
        sa.Column("caller", sa.String(128), nullable=False),
        sa.Column("found", sa.Boolean, nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_billing_recipient_lookups_person_id", "billing_recipient_lookups",
                    ["person_id"])


def downgrade() -> None:
    op.drop_index("ix_billing_recipient_lookups_person_id", table_name="billing_recipient_lookups")
    op.drop_table("billing_recipient_lookups")
    op.drop_table("billing_recipients")

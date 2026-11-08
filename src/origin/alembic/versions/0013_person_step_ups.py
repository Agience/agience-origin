"""person_step_ups — a person's re-authentication tickets for a change to how they sign in.

Revision ID: 0013_person_step_ups
Revises: 0012_operator_alerts

Additive: one new table (`models.person_step_up`). A ticket is issued for one request (its
digest), proven by a sign-in Origin consumes at `/auth/reauth/complete`, and spent by that request.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0013_person_step_ups"
down_revision: Union[str, None] = "0012_operator_alerts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "person_step_ups",
        sa.Column("ticket", sa.String(64), primary_key=True),
        sa.Column("person_id", sa.String(64), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("verifier", sa.String(128), nullable=False),
        sa.Column("describe", sa.String(128), nullable=False, server_default=""),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("proven_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("spent_time", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_person_step_ups_person_id", "person_step_ups", ["person_id"])


def downgrade() -> None:
    op.drop_index("ix_person_step_ups_person_id", table_name="person_step_ups")
    op.drop_table("person_step_ups")

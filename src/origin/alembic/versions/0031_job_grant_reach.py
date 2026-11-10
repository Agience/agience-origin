"""A job grant's reach: the ids a timer's delegations may touch (John, 2026-11-10).

Revision ID: 0031_job_grant_reach
Revises: 0030_charged_root_rotations

Additive. `authority_job_grants.reach` holds, for a timer's grant (`lumen.timer.<id>`), the JSON
list of ids its delegations carry as `job_reach`; null for every other grant.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0031_job_grant_reach"
down_revision: Union[str, None] = "0030_charged_root_rotations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("authority_job_grants") as batch:
        batch.add_column(sa.Column("reach", sa.Text, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("authority_job_grants") as batch:
        batch.drop_column("reach")

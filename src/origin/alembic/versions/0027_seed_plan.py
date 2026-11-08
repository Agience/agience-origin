"""A seed credential's plan: the entries its pass may make (review 25).

Revision ID: 0027_seed_plan
Revises: 0026_use_nonces

Additive. `seed_credentials.plan` holds the digests of the entries the pass planned when the
operator minted it; a seed makes those and no others, and a seed with none makes no entry.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0027_seed_plan"
down_revision: Union[str, None] = "0026_use_nonces"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("seed_credentials") as batch:
        batch.add_column(sa.Column("plan", sa.Text, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("seed_credentials") as batch:
        batch.drop_column("plan")

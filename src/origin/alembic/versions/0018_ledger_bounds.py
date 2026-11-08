"""seed_credentials.first_batch: a seed credential writes one batch (review 11).

Revision ID: 0018_ledger_bounds
Revises: 0017_sign_in_bounds
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0018_ledger_bounds"
down_revision: Union[str, None] = "0017_sign_in_bounds"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("seed_credentials") as batch:
        batch.add_column(sa.Column("first_batch", sa.String(64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("seed_credentials") as batch:
        batch.drop_column("first_batch")

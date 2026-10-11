"""persons.deactivated_at and persons.deactivated_reason — an account can be switched off and back.

Revision ID: 0007_person_deactivation
Revises: 0006_oauth_clients

Additive: two nullable columns on `persons`, no backfill. Every existing account stays active.

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007_person_deactivation"
down_revision: Union[str, None] = "0006_oauth_clients"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("persons") as batch:
        batch.add_column(sa.Column("deactivated_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("deactivated_reason", sa.Text(), nullable=True))


def downgrade() -> None:
    """Drops both columns: every deactivated account becomes active again, and the record of why
    it was deactivated is lost."""
    with op.batch_alter_table("persons") as batch:
        batch.drop_column("deactivated_reason")
        batch.drop_column("deactivated_at")

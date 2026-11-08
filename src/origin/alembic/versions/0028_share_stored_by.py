"""Who stored a key share's first copy, until it is activated (review 26).

Revision ID: 0028_share_stored_by
Revises: 0027_seed_plan

Additive. `key_custody_shares.stored_by` names the subject whose acting credential stored a first
share; that subject may activate it, and the field is cleared at activation. Shares stored before
this migration have none, and are activated as before, by the key's principal or an Admin on what
it keys.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0028_share_stored_by"
down_revision: Union[str, None] = "0027_seed_plan"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("key_custody_shares") as batch:
        batch.add_column(sa.Column("stored_by", sa.String(128), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("key_custody_shares") as batch:
        batch.drop_column("stored_by")

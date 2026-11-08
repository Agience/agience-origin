"""service_accounts, and the Origin session a re-authentication ticket belongs to (review 11).

Revision ID: 0019_sign_in_review11
Revises: 0018_ledger_bounds

Additive:
- `service_accounts`: an Origin account that is a service's own, with the audience every token
  issued for it is narrowed to (Ember's own credential).
- `person_step_ups.session_sha256`: the SHA-256 of the Origin session the ticket was started in;
  only that browser completes it.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0019_sign_in_review11"
down_revision: Union[str, None] = "0018_ledger_bounds"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "service_accounts",
        sa.Column("person_id", sa.String(64), primary_key=True),
        sa.Column("audience", sa.String(128), nullable=False),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
    )
    with op.batch_alter_table("person_step_ups") as batch:
        batch.add_column(sa.Column("session_sha256", sa.String(64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("person_step_ups") as batch:
        batch.drop_column("session_sha256")
    op.drop_table("service_accounts")

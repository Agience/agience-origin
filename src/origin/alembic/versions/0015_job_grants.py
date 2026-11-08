"""authority_job_grants, and the job grant a background delegation was minted under.

Revision ID: 0015_job_grants
Revises: 0014_refresh_tokens

Additive: the `authority_job_grants` replica table (a background job's own narrow authority, as
the ledger applied it) and three columns on `key_custody_delegations` (`job_grant_id`, `job`,
`collections`). `key_custody_background` stays as a record; nothing mints under it any more.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0015_job_grants"
down_revision: Union[str, None] = "0014_refresh_tokens"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "authority_job_grants",
        sa.Column("grant_id", sa.String(128), primary_key=True),
        sa.Column("job", sa.String(64), nullable=False),
        sa.Column("principal", sa.String(128), nullable=False),
        sa.Column("collections", sa.Text, nullable=False, server_default="[]"),
        sa.Column("expires_at", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("seq", sa.Integer, nullable=False),
    )
    op.create_index("ix_authority_job_grants_principal", "authority_job_grants", ["principal"])
    with op.batch_alter_table("key_custody_delegations") as batch:
        batch.add_column(sa.Column("job_grant_id", sa.String(128), nullable=True))
        batch.add_column(sa.Column("job", sa.String(64), nullable=True))
        batch.add_column(sa.Column("collections", sa.Text, nullable=True))
    op.create_index("ix_key_custody_delegations_job_grant_id", "key_custody_delegations",
                    ["job_grant_id"])


def downgrade() -> None:
    op.drop_index("ix_key_custody_delegations_job_grant_id", table_name="key_custody_delegations")
    with op.batch_alter_table("key_custody_delegations") as batch:
        batch.drop_column("collections")
        batch.drop_column("job")
        batch.drop_column("job_grant_id")
    op.drop_index("ix_authority_job_grants_principal", table_name="authority_job_grants")
    op.drop_table("authority_job_grants")

"""Credential seals: the digests of each credential's sealed copies, as its writer made them
(review 22).

Revision ID: 0025_credential_seals
Revises: 0024_billing_recipients

Additive. A use verdict carries the persona's sealed-copy and endpoint digests from here, and a
credential with no row here gets no verdict.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0025_credential_seals"
down_revision: Union[str, None] = "0024_billing_recipients"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "credential_seals",
        sa.Column("credential_id", sa.String(128), primary_key=True),
        sa.Column("sealed_sha256", sa.Text, nullable=False),
        sa.Column("endpoints_sha256", sa.String(64), nullable=False),
        sa.Column("recorded_by", sa.String(64), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("credential_seals")

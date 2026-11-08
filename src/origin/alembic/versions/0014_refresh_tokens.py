"""refresh_tokens — every refresh token Origin issued, by jti, so they rotate and can be revoked.

Revision ID: 0014_refresh_tokens
Revises: 0013_person_step_ups

Additive: one new table (`models.refresh_token`). A refresh token issued before this revision has
no row; the refresh grant takes it once, records it by its digest, and rotates it into a family.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0014_refresh_tokens"
down_revision: Union[str, None] = "0013_person_step_ups"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "refresh_tokens",
        sa.Column("jti", sa.String(64), primary_key=True),
        sa.Column("family", sa.String(64), nullable=False),
        sa.Column("person_id", sa.String(64), nullable=False),
        sa.Column("client_id", sa.String(128), nullable=False, server_default=""),
        sa.Column("issued_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_refresh_tokens_family", "refresh_tokens", ["family"])
    op.create_index("ix_refresh_tokens_person_id", "refresh_tokens", ["person_id"])


def downgrade() -> None:
    op.drop_index("ix_refresh_tokens_person_id", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_family", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")

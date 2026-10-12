"""password_resets — a mailed reset link is a short random token, stored as its hash.

Revision ID: 0008_password_resets
Revises: 0007_person_deactivation

Additive: one new table. Reset links mailed before this revision carried a signed token and stop
working; each expired within an hour of being sent.

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008_password_resets"
down_revision: Union[str, None] = "0007_person_deactivation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "password_resets",
        sa.Column("token_hash", sa.String(64), primary_key=True),
        sa.Column("person_id", sa.Uuid(), sa.ForeignKey("persons.id", ondelete="CASCADE"), nullable=False),
        sa.Column("password_fingerprint", sa.String(128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_password_resets_person_id", "password_resets", ["person_id"])
    op.create_index("ix_password_resets_expires_at", "password_resets", ["expires_at"])


def downgrade() -> None:
    """Drops the table: every outstanding reset link stops working."""
    op.drop_index("ix_password_resets_expires_at", table_name="password_resets")
    op.drop_index("ix_password_resets_person_id", table_name="password_resets")
    op.drop_table("password_resets")

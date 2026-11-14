"""authority_keys: grant keys a person mints at Origin's own page (John, 2026-11-14).

Revision ID: 0032_authority_keys
Revises: 0031_job_grant_reach

Additive: the `authority_keys` replica table, a `key` entry as the ledger applied it. It holds the
token's sha256 and its non-secret tail, never the token. What a key carries is its member grants in
`authority_grants` (grantee type `grant`, grantee the key's id).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0032_authority_keys"
down_revision: Union[str, None] = "0031_job_grant_reach"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "authority_keys",
        sa.Column("grant_id", sa.String(128), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("hint", sa.String(16), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("agent", sa.String(200), nullable=True),
        sa.Column("expires_at", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("seq", sa.Integer, nullable=False),
    )
    op.create_index("ix_authority_keys_token_hash", "authority_keys", ["token_hash"], unique=True)
    op.create_index("ix_authority_keys_created_by", "authority_keys", ["created_by"])


def downgrade() -> None:
    op.drop_index("ix_authority_keys_created_by", table_name="authority_keys")
    op.drop_index("ix_authority_keys_token_hash", table_name="authority_keys")
    op.drop_table("authority_keys")

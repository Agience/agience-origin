"""add passkey_challenges — server-side single-use WebAuthn challenge store

Revision ID: 0004_passkey_challenges
Revises: 0003_drop_grants_apikeys
Create Date: 2026-07-20

A WebAuthn login challenge must be checked against a value the relying party
itself remembers issuing, not one the client supplies back in its own request
body — otherwise a captured login assertion is replayable indefinitely against
whatever access and refresh tokens the flow grants.

This table is that memory: one row per issued challenge, consumed atomically
on first use, bound at issue time to the person it was minted for (so the
flow never needs a client-supplied `user_id`).

Downgrade drops the table. Any in-flight ceremony fails and the user retries;
there is no durable data here by design.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004_passkey_challenges"
down_revision: Union[str, None] = "0003_drop_grants_apikeys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "passkey_challenges",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("challenge", sa.Text(), nullable=False),
        sa.Column("purpose", sa.String(length=16), nullable=False),
        sa.Column("person_id", sa.Uuid(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_passkey_challenges"),
        # UNIQUE is load-bearing: without it a duplicate issue would create two
        # independently-consumable rows for the same challenge value.
        sa.UniqueConstraint("challenge", name="uq_passkey_challenges_challenge"),
    )
    op.create_index("ix_passkey_challenges_challenge", "passkey_challenges", ["challenge"])
    op.create_index("ix_passkey_challenges_person_id", "passkey_challenges", ["person_id"])
    op.create_index("ix_passkey_challenges_expires_at", "passkey_challenges", ["expires_at"])
    op.create_index("ix_passkey_challenges_used", "passkey_challenges", ["used"])
    op.create_index(
        "ix_passkey_challenges_lookup",
        "passkey_challenges",
        ["challenge", "used", "expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_passkey_challenges_lookup", table_name="passkey_challenges")
    op.drop_index("ix_passkey_challenges_used", table_name="passkey_challenges")
    op.drop_index("ix_passkey_challenges_expires_at", table_name="passkey_challenges")
    op.drop_index("ix_passkey_challenges_person_id", table_name="passkey_challenges")
    op.drop_index("ix_passkey_challenges_challenge", table_name="passkey_challenges")
    op.drop_table("passkey_challenges")

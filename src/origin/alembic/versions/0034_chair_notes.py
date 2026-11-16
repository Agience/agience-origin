"""chair_notes: requests for the chair's approval, the notes an approval mints, their spends; and
how and when an Origin session's sign-in happened (phone approvals, FR-024).

Revision ID: 0034_chair_notes
Revises: 0033_invite_addresses

Additive: three new tables, Origin's own and never ledger entries, and three nullable columns on
`origin_sessions`. It keeps its data across a rollback: `downgrade()` leaves everything, so a
rollback is only `alembic stamp 0033_invite_addresses`, and the older Origin ignores tables and
columns it does not know. `upgrade()` creates only what is missing.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0034_chair_notes"
down_revision: Union[str, None] = "0033_invite_addresses"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    inspect = sa.inspect(op.get_bind())
    have = {c["name"] for c in inspect.get_columns("origin_sessions")}
    for name, kind in (("auth_time", sa.DateTime(timezone=True)), ("amr", sa.JSON()),
                       ("last_seen_time", sa.DateTime(timezone=True))):
        if name not in have:
            op.add_column("origin_sessions", sa.Column(name, kind, nullable=True))
    if not inspect.has_table("chair_requests"):
        op.create_table(
            "chair_requests",
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("kind", sa.String(32), nullable=False),
            sa.Column("level", sa.String(16), nullable=False),
            sa.Column("fields", sa.JSON(), nullable=False),
            sa.Column("digest", sa.String(80), nullable=False),
            sa.Column("steps", sa.JSON(), nullable=True),
            sa.Column("summary", sa.Text(), nullable=False),
            sa.Column("evidence", sa.JSON(), nullable=True),
            sa.Column("aud", sa.JSON(), nullable=False),
            sa.Column("options", sa.JSON(), nullable=True),
            sa.Column("default_option", sa.String(64), nullable=True),
            sa.Column("filed_by", sa.String(200), nullable=False),
            sa.Column("filed_by_account", sa.String(64), nullable=False, index=True),
            sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_time", sa.DateTime(timezone=True), nullable=False),
            sa.Column("state", sa.String(16), nullable=False, index=True),
            sa.Column("decided_time", sa.DateTime(timezone=True), nullable=True),
            sa.Column("decided_by", sa.String(64), nullable=True),
            sa.Column("decline_reason", sa.Text(), nullable=True),
            sa.Column("answer", sa.String(64), nullable=True),
            sa.Column("note_jti", sa.String(64), nullable=True),
        )
    if not inspect.has_table("chair_notes"):
        op.create_table(
            "chair_notes",
            sa.Column("jti", sa.String(64), primary_key=True),
            sa.Column("req", sa.String(64), nullable=False, index=True),
            sa.Column("person_id", sa.String(64), nullable=False, index=True),
            sa.Column("level", sa.String(16), nullable=False),
            sa.Column("token", sa.Text(), nullable=False),
            sa.Column("issued_time", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_time", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_time", sa.DateTime(timezone=True), nullable=True),
        )
    if not inspect.has_table("chair_spends"):
        op.create_table(
            "chair_spends",
            sa.Column("jti", sa.String(64), primary_key=True),
            sa.Column("action", sa.String(80), primary_key=True),
            sa.Column("id", sa.String(64), nullable=False, unique=True),
            sa.Column("req", sa.String(64), nullable=False),
            sa.Column("spent_time", sa.DateTime(timezone=True), nullable=False),
        )


def downgrade() -> None:
    # Kept on purpose: see the module note. A minted note's record exists nowhere else.
    pass

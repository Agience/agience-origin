"""person_not_before and link_attempts (review 10).

Revision ID: 0017_sign_in_bounds
Revises: 0016_origin_sessions

Additive:
- `person_not_before`: per person (and `*` for everyone), the time before which an access
  credential, or a refresh token, Origin issued is refused. Sign-out, sign-out-everywhere and a
  signing-key rollover set it.
- `link_attempts`: an attempt at linking a sign-in method, begun in the Origin session: the SHA-256
  of its random state and the PKCE challenge the code must carry.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0017_sign_in_bounds"
down_revision: Union[str, None] = "0016_origin_sessions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "person_not_before",
        sa.Column("person_id", sa.String(64), primary_key=True),
        sa.Column("access_before", sa.DateTime(timezone=True), nullable=True),
        sa.Column("refresh_before", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "link_attempts",
        sa.Column("state_sha256", sa.String(64), primary_key=True),
        sa.Column("person_id", sa.String(64), nullable=False),
        sa.Column("code_challenge", sa.String(128), nullable=False),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("spent_time", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_link_attempts_person_id", "link_attempts", ["person_id"])


def downgrade() -> None:
    op.drop_index("ix_link_attempts_person_id", table_name="link_attempts")
    op.drop_table("link_attempts")
    op.drop_table("person_not_before")

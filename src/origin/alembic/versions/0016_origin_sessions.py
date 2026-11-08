"""origin_sessions; the step-up's confirm; a rotated refresh token's retry grace.

Revision ID: 0016_origin_sessions
Revises: 0015_job_grants

Additive (review 8):
- `origin_sessions`: a person's first-party session on Origin's own host, by the SHA-256 of its
  cookie. Changes to how a person signs in are made only in it.
- `person_step_ups.csrf`, `person_step_ups.confirmed_time`, and `describe` widened to 256: the
  start page's confirm, and the exact action it shows.
- `refresh_tokens.next_sealed`, `refresh_tokens.next_until`: the token a rotation issued, sealed
  under Origin's key for a short grace, so an exact retry gets the same one.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0016_origin_sessions"
down_revision: Union[str, None] = "0015_job_grants"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "origin_sessions",
        sa.Column("id_sha256", sa.String(64), primary_key=True),
        sa.Column("person_id", sa.String(64), nullable=False),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_time", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_origin_sessions_person_id", "origin_sessions", ["person_id"])
    with op.batch_alter_table("person_step_ups") as batch:
        batch.add_column(sa.Column("csrf", sa.String(64), nullable=True))
        batch.add_column(sa.Column("confirmed_time", sa.DateTime(timezone=True), nullable=True))
        batch.alter_column("describe", type_=sa.String(256))
    with op.batch_alter_table("refresh_tokens") as batch:
        batch.add_column(sa.Column("next_sealed", sa.Text, nullable=True))
        batch.add_column(sa.Column("next_until", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("refresh_tokens") as batch:
        batch.drop_column("next_until")
        batch.drop_column("next_sealed")
    with op.batch_alter_table("person_step_ups") as batch:
        batch.drop_column("confirmed_time")
        batch.drop_column("csrf")
    op.drop_index("ix_origin_sessions_person_id", table_name="origin_sessions")
    op.drop_table("origin_sessions")

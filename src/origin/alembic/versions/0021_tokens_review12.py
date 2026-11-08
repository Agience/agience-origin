"""Review 12 tokens: narrow_hops, and the monotonic sequence of person_not_before.

Revision ID: 0021_tokens_review12
Revises: 0020_authority_review12

Additive. `narrow_hops` records each cross-persona exchange (`/internal/narrow-hop`).
`person_not_before.seq` orders changes to the not-before rows, so `GET /auth/not-before?after=`
serves them by sequence rather than by time and a peer's cursor never skips a late commit.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0021_tokens_review12"
down_revision: Union[str, None] = "0020_authority_review12"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "narrow_hops",
        sa.Column("jti", sa.String(64), primary_key=True),
        sa.Column("sub", sa.String(64), nullable=False),
        sa.Column("subject_jti", sa.String(64), nullable=False, server_default=""),
        sa.Column("from_aud", sa.String(128), nullable=False),
        sa.Column("to_aud", sa.String(128), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_narrow_hops_sub", "narrow_hops", ["sub"])
    with op.batch_alter_table("person_not_before") as batch:
        batch.add_column(sa.Column("seq", sa.Integer, nullable=False, server_default="0"))
    op.create_index("ix_person_not_before_seq", "person_not_before", ["seq"])


def downgrade() -> None:
    op.drop_index("ix_person_not_before_seq", table_name="person_not_before")
    with op.batch_alter_table("person_not_before") as batch:
        batch.drop_column("seq")
    op.drop_index("ix_narrow_hops_sub", table_name="narrow_hops")
    op.drop_table("narrow_hops")

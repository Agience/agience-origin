"""authority_job_grants.actions and agent_approvals: an agent window's standing grant and the
approvals minted under it (FR-032).

Revision ID: 0036_agent_approvals
Revises: 0035_request_resource

Additive: one nullable column and one table. A grant made before it has no actions, so it is not
an agent window's. `downgrade()` leaves both, so a rollback is only
`alembic stamp 0035_request_resource`, and the older Origin ignores what it does not know.
`upgrade()` adds each only when it is missing.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0036_agent_approvals"
down_revision: Union[str, None] = "0035_request_resource"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    inspect = sa.inspect(op.get_bind())
    if (inspect.has_table("authority_job_grants") and "actions" not in
            {c["name"] for c in inspect.get_columns("authority_job_grants")}):
        op.add_column("authority_job_grants", sa.Column("actions", sa.Text(), nullable=True))
    if not inspect.has_table("agent_approvals"):
        op.create_table(
            "agent_approvals",
            sa.Column("jti", sa.String(64), primary_key=True),
            sa.Column("grant_id", sa.String(128), nullable=False),
            sa.Column("person", sa.String(128), nullable=False),
            sa.Column("agent", sa.String(128), nullable=False),
            sa.Column("session_jkt", sa.String(64), nullable=False),
            sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("ix_agent_approvals_grant_id", "agent_approvals", ["grant_id"])
        op.create_index("ix_agent_approvals_person", "agent_approvals", ["person"])


def downgrade() -> None:
    # Kept on purpose: see the module note.
    pass

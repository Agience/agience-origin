"""chair_requests.resource_id: the workspace or collection a request is filed against. Whoever
holds admin on it approves the request.

Revision ID: 0035_request_resource
Revises: 0034_chair_notes

Additive: one nullable column. A request filed before it has no resource, so no one can approve
it, and it closes at its expiry. `downgrade()` leaves the column, so a rollback is only
`alembic stamp 0034_chair_notes`, and the older Origin ignores a column it does not know.
`upgrade()` adds the column only when it is missing.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0035_request_resource"
down_revision: Union[str, None] = "0034_chair_notes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    inspect = sa.inspect(op.get_bind())
    if not inspect.has_table("chair_requests"):
        return
    if "resource_id" not in {c["name"] for c in inspect.get_columns("chair_requests")}:
        op.add_column("chair_requests", sa.Column("resource_id", sa.String(64), nullable=True))
        op.create_index("ix_chair_requests_resource_id", "chair_requests", ["resource_id"])


def downgrade() -> None:
    # Kept on purpose: see the module note.
    pass

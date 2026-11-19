"""The request, note and spend tables under the names `decision_requests`, `decision_notes` and
`decision_spends`, with their indexes named after them.

Revision ID: 0037_decision_tables
Revises: 0036_agent_approvals

A node whose tables carry the names `chair_requests`, `chair_notes` and `chair_spends` has them
renamed here, rows kept, and each `ix_chair_*` index takes the new table's name. A node that
already has the `decision_*` tables (made by 0034) is left as it is.

A node renamed here records that in the one-row table `alembic_0037_renamed`. `downgrade()` renames
the tables back only on such a node, so an Origin that reads the `chair_*` names runs again after
`alembic downgrade 0036_agent_approvals`; on every other node it changes nothing.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0037_decision_tables"
down_revision: Union[str, None] = "0036_agent_approvals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

#: (name on a renamed node, name) for each table.
TABLES = (("chair_requests", "decision_requests"), ("chair_notes", "decision_notes"),
          ("chair_spends", "decision_spends"))

#: Present only on a node whose tables this revision renamed.
MARKER = "alembic_0037_renamed"


def _rename(pairs) -> bool:
    """Each `old` table that exists, with no `new` beside it, renamed to `new`, and its `ix_<old>_`
    indexes renamed to `ix_<new>_`. True when any table was renamed."""
    renamed = False
    for old, new in pairs:
        inspect = sa.inspect(op.get_bind())
        if not inspect.has_table(old) or inspect.has_table(new):
            continue
        indexes = [ix for ix in inspect.get_indexes(old) if ix["name"].startswith(f"ix_{old}_")]
        for ix in indexes:
            op.drop_index(ix["name"], table_name=old)
        op.rename_table(old, new)
        for ix in indexes:
            op.create_index(f"ix_{new}_" + ix["name"][len(f"ix_{old}_"):], new,
                            ix["column_names"], unique=bool(ix.get("unique")))
        renamed = True
    return renamed


def upgrade() -> None:
    if _rename(TABLES):
        op.create_table(MARKER, sa.Column("renamed", sa.Integer(), primary_key=True))


def downgrade() -> None:
    if not sa.inspect(op.get_bind()).has_table(MARKER):
        return
    _rename(tuple((new, old) for old, new in TABLES))
    op.drop_table(MARKER)

"""The request, note and spend tables take the names `decision_requests`, `decision_notes` and
`decision_spends`, and their indexes follow.

Revision ID: 0037_decision_tables
Revises: 0036_agent_approvals

A node whose tables were made under their first names has them renamed here; a fresh node already
has the new names from 0034 and nothing changes. `downgrade()` renames them back, so a rollback
runs `alembic downgrade 0036_agent_approvals` before the older Origin starts.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0037_decision_tables"
down_revision: Union[str, None] = "0036_agent_approvals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

#: (first name, name) for each table.
_TABLES = (("chair_requests", "decision_requests"), ("chair_notes", "decision_notes"),
           ("chair_spends", "decision_spends"))


def _rename(pairs) -> None:
    inspect = sa.inspect(op.get_bind())
    for old, new in pairs:
        if not inspect.has_table(old) or inspect.has_table(new):
            continue
        indexes = inspect.get_indexes(old)
        for ix in indexes:
            op.drop_index(ix["name"], table_name=old)
        op.rename_table(old, new)
        for ix in indexes:
            name = ix["name"].replace(old, new, 1) if ix["name"].startswith(f"ix_{old}_") else ix["name"]
            op.create_index(name, new, ix["column_names"], unique=bool(ix.get("unique")))


def upgrade() -> None:
    _rename(_TABLES)


def downgrade() -> None:
    _rename(tuple((new, old) for old, new in _TABLES))

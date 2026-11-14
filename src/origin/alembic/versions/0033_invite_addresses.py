"""invite_addresses: the address an email invite went to, and when (BUG-069; John, 2026-11-14).

Revision ID: 0033_invite_addresses
Revises: 0032_authority_keys

Additive: one new table, Origin's own and never a ledger entry. The ledger keeps only an invited
address's digest; this table lets the people who may share an item see whom a pending invite was
sent to. A row is deleted once its invite is no longer pending.

It keeps its data across a rollback. The table is not in the ledger, so a dropped row could never
be rebuilt. `downgrade()` leaves the table, so a rollback is only `alembic stamp
0032_authority_keys`; the older Origin ignores a table it does not know. `upgrade()` creates the
table only where it is missing, so a roll-forward finds it with its pending invites.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0033_invite_addresses"
down_revision: Union[str, None] = "0032_authority_keys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    if sa.inspect(op.get_bind()).has_table("invite_addresses"):
        return
    op.create_table(
        "invite_addresses",
        sa.Column("grant_id", sa.String(128), primary_key=True),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    # Kept on purpose: see the module note. Its rows exist nowhere else.
    pass

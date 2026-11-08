"""Drop keys are not part of the authority model (John, 2026-11-03).

Revision ID: 0023_drop_keys_are_not_authority
Revises: 0022_email_verified_default_off

"It's not a drop key. It's a grant with Add rights and nothing else." Writing without reading is
an Add grant, decided at Origin like any action. Sealing what is added so only the collection's
readers open it is Mantle's own key material, derived from the collection key and never stored or
co-signed here. So `authority_drop_keys` goes.

A no-op on the chain: the ledger's entries are not touched. A `drop_key` entry already in it still
verifies (its hash, link and co-signature) and replays to nothing. The downgrade recreates the
empty table; the rows it held are gone, as nothing reads them.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0023_drop_keys_are_not_authority"
down_revision: Union[str, None] = "0022_email_verified_default_off"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_table("authority_drop_keys")


def downgrade() -> None:
    op.create_table(
        "authority_drop_keys",
        sa.Column("collection_id", sa.String(128), primary_key=True),
        sa.Column("public", sa.String(64), nullable=False),
        sa.Column("seq", sa.Integer, nullable=False),
    )

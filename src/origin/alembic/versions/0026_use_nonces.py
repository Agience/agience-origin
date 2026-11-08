"""Use nonces in a table of their own (review 23).

Revision ID: 0026_use_nonces
Revises: 0025_credential_seals

Additive. A persona's use nonce is spent once by the verdict signed for it, in `use_nonces`, kept
apart from the jtis of Mantle's custody tokens in `key_custody_nonces`.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0026_use_nonces"
down_revision: Union[str, None] = "0025_credential_seals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "use_nonces",
        sa.Column("nonce_key", sa.String(128), primary_key=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_use_nonces_expires_at", "use_nonces", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_use_nonces_expires_at", table_name="use_nonces")
    op.drop_table("use_nonces")

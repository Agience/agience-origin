"""key_custody — Origin's share of each Mantle master key, and spent custody tokens.

Revision ID: 0009_key_custody
Revises: 0008_password_resets

Additive: two new tables. `key_custody_shares` holds one Shamir share per principal, encrypted;
`key_custody_nonces` records each `/internal/key-shares` token's `jti` until it expires.

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0009_key_custody"
down_revision: Union[str, None] = "0008_password_resets"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "key_custody_shares",
        sa.Column("principal_id", sa.String(128), primary_key=True),
        sa.Column("x", sa.Integer(), nullable=False),
        sa.Column("y_sealed", sa.Text(), nullable=False),
        sa.Column("kcv", sa.String(32), nullable=False),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_time", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "key_custody_nonces",
        sa.Column("jti", sa.String(128), primary_key=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_key_custody_nonces_expires_at", "key_custody_nonces", ["expires_at"])


def downgrade() -> None:
    """Drops both tables, and refuses while `key_custody_shares` holds any row: each row is
    Origin's share of a split master key, and dropping it leaves that key recoverable only from
    the offline escrow. `mantle.system.split_master_keys --combine` writes every key back whole;
    after it, the shares can be deleted and the downgrade run."""
    held = op.get_bind().execute(sa.text("SELECT COUNT(*) FROM key_custody_shares")).scalar()
    if held:
        raise RuntimeError(
            f"key_custody_shares holds {held} key share(s); downgrading would drop Origin's share "
            f"of every split master key. Run `python -m mantle.system.split_master_keys "
            f"--combine` on Mantle first, then empty the table.")
    op.drop_index("ix_key_custody_nonces_expires_at", table_name="key_custody_nonces")
    op.drop_table("key_custody_nonces")
    op.drop_table("key_custody_shares")

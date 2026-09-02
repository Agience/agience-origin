"""oauth_clients — RFC 7591 dynamically registered public clients.

Revision ID: 0006_oauth_clients
Revises: 0005_person_identity

The column set is RFC 7591 §2 client metadata narrowed to what this authority can honestly record,
plus the one field §3.2.1 provisions itself (`client_id_issued_at`). See
`origin/models/oauth_client.py` for the per-column reasoning and for why there is no secret column.

Additive: it creates a table nothing else references, with no foreign keys and no backfill. An
existing database gains an empty table and every other row is untouched.

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006_oauth_clients"
down_revision: Union[str, None] = "0005_person_identity"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "oauth_clients",
        sa.Column("client_id", sa.String(length=64), primary_key=True),
        sa.Column("client_name", sa.String(length=256), nullable=True),
        sa.Column("redirect_uris", sa.JSON(), nullable=False),
        sa.Column("grant_types", sa.JSON(), nullable=False),
        sa.Column("response_types", sa.JSON(), nullable=False),
        sa.Column("token_endpoint_auth_method", sa.String(length=64), nullable=False),
        sa.Column("client_id_issued_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )


def downgrade() -> None:
    """Drops the table. What that restores, and what it destroys, stated plainly.

    RESTORED: the schema exactly as `0005` left it. This revision adds one table and touches no
    other, so there is no column to re-derive and no row elsewhere to repair — unlike `0005`, which
    can only restore the earliest identity per person, or `0003`, which recreates its tables empty.

    DESTROYED, WITH NO WAY BACK: every dynamic registration. A `client_id` is minted from fresh
    entropy and written nowhere else, so nothing in this database or any other can reconstruct a
    dropped row. Re-upgrading produces an empty table and reports success — the same shape of
    silence this repo's other irreversible downgrades have.

    What that costs today is nothing, and that is precisely what makes it worth writing down:
    `/authorize` consults no registry, so a client presenting a `client_id` this node no longer has
    a record of is admitted exactly as before and receives the same scoped `mcp_client` token. The
    moment any code path reads `oauth_clients`, this downgrade becomes a silent mass revocation of
    every client that ever registered, and the operator's only recovery is to have each one register
    again. Take a copy of the table before running it.
    """
    op.drop_table("oauth_clients")

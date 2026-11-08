"""authority_ledger — the co-signed ledger of changes to reach, and Origin's replica of it.

Revision ID: 0011_authority_ledger
Revises: 0010_key_custody_credentials

Additive: eight new tables. `authority_ledger` holds each co-signed entry, hash-chained, and
`authority_signing_keys` the public half of every key that co-signed one. `authority_nodes`,
`authority_grants`, `authority_edges` and `authority_roots` are the ledger applied, which Origin
walks to decide whether a credential reaches a key. `authority_bootstrap_windows` records each
bootstrap credential the operator obtained.

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0011_authority_ledger"
down_revision: Union[str, None] = "0010_key_custody_credentials"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "authority_ledger",
        sa.Column("seq", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("credential_kind", sa.String(16), nullable=False),
        sa.Column("credential_ref", sa.String(64), nullable=False),
        sa.Column("bootstrap", sa.Boolean(), nullable=False),
        sa.Column("compensates", sa.Integer(), nullable=True),
        sa.Column("claimed_from", sa.String(128), nullable=True),
        sa.Column("submitted_jti", sa.String(128), nullable=False),
        sa.Column("body_sha256", sa.String(64), nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("entry_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("kid", sa.String(128), nullable=False),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confirmed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("batch", sa.String(64), nullable=True, index=True),
        sa.Column("submitted_by", sa.String(64), nullable=True),
        sa.Column("resolved_by", sa.String(128), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "authority_signing_keys",
        sa.Column("kid", sa.String(128), primary_key=True),
        sa.Column("public_pem", sa.Text(), nullable=False),
        sa.Column("first_used", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "authority_bootstrap_windows",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("opened_by", sa.String(128), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ids", sa.Text(), nullable=True),
    )
    op.create_table(
        "authority_batches",
        sa.Column("batch_id", sa.String(64), primary_key=True),
        sa.Column("credential_ref", sa.String(64), nullable=False),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "authority_drop_keys",
        sa.Column("collection_id", sa.String(128), primary_key=True),
        sa.Column("public", sa.String(64), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
    )
    op.create_table(
        "authority_nodes",
        sa.Column("node_id", sa.String(128), primary_key=True),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("member", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_table(
        "authority_grants",
        sa.Column("grant_id", sa.String(128), primary_key=True),
        sa.Column("grantee_id", sa.String(128), nullable=False),
        sa.Column("grantee_type", sa.String(32), nullable=False),
        sa.Column("resource_id", sa.String(128), nullable=False),
        sa.Column("actions", sa.String(128), nullable=False),
        sa.Column("effect", sa.String(16), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("expires_at", sa.String(64), nullable=True),
        sa.Column("target_kind", sa.String(16), nullable=True),
        sa.Column("target_digest", sa.String(64), nullable=True),
        sa.Column("max_claims", sa.Integer(), nullable=True),
        sa.Column("claimed_from", sa.String(128), nullable=True),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
    )
    op.create_index("ix_authority_grants_grantee_id", "authority_grants", ["grantee_id"])
    op.create_index("ix_authority_grants_resource_id", "authority_grants", ["resource_id"])
    op.create_index("ix_authority_grants_claimed_from", "authority_grants", ["claimed_from"])
    op.create_table(
        "authority_edges",
        sa.Column("src", sa.String(128), primary_key=True),
        sa.Column("dst", sa.String(128), primary_key=True),
        sa.Column("origin", sa.Boolean(), nullable=False),
        sa.Column("propagate", sa.Text(), nullable=True),
        sa.Column("added_by", sa.String(128), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
    )
    op.create_index("ix_authority_edges_dst", "authority_edges", ["dst"])
    op.create_table(
        "authority_roots",
        sa.Column("principal_id", sa.String(128), primary_key=True),
        sa.Column("root_id", sa.String(128), nullable=False),
        sa.Column("registered_by", sa.String(128), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
    )


def downgrade() -> None:
    """Drops the ledger and the replica. Origin then knows no one's reach, so every key share
    release is refused until the ledger is rebuilt (`mantle.system.cosign_authority`)."""
    op.drop_table("authority_roots")
    op.drop_index("ix_authority_edges_dst", table_name="authority_edges")
    op.drop_table("authority_edges")
    for ix in ("ix_authority_grants_claimed_from", "ix_authority_grants_resource_id",
               "ix_authority_grants_grantee_id"):
        op.drop_index(ix, table_name="authority_grants")
    op.drop_table("authority_grants")
    op.drop_table("authority_nodes")
    op.drop_table("authority_batches")
    op.drop_table("authority_drop_keys")
    op.drop_table("authority_bootstrap_windows")
    op.drop_table("authority_signing_keys")
    op.drop_table("authority_ledger")

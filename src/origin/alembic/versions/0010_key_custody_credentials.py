"""key_custody_credentials — background authority, minted delegations, and each share release.

Revision ID: 0010_key_custody_credentials
Revises: 0009_key_custody

Additive: five new tables. A share is released only on the acting caller's own credential.
`key_custody_background` records the operator's standing background authority,
`key_custody_delegations` each per-principal delegation minted under it, and
`key_custody_releases` what each release served, and `delegation_tokens` each person's
delegation Origin issued, by `jti`, so it can be capped, checked and revoked, and
`seed_credentials` each seed credential the operator minted.

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0010_key_custody_credentials"
down_revision: Union[str, None] = "0009_key_custody"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "key_custody_background",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("issued_by", sa.String(128), nullable=False),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "key_custody_delegations",
        sa.Column("jti", sa.String(64), primary_key=True),
        sa.Column("subject", sa.String(128), nullable=False),
        sa.Column("issued_by", sa.String(128), nullable=False),
        sa.Column("authority_id", sa.String(32), nullable=True),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_key_custody_delegations_subject", "key_custody_delegations",
                    ["subject"])
    op.create_table(
        "delegation_tokens",
        sa.Column("jti", sa.String(64), primary_key=True),
        sa.Column("subject", sa.String(128), nullable=False),
        sa.Column("audience", sa.String(128), nullable=False),
        sa.Column("signer", sa.String(128), nullable=False),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_delegation_tokens_subject", "delegation_tokens", ["subject"])
    op.create_table(
        "seed_credentials",
        sa.Column("jti", sa.String(64), primary_key=True),
        sa.Column("subject", sa.String(128), nullable=False),
        sa.Column("issued_by", sa.String(128), nullable=False),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("key_custody_shares", sa.Column("rekey_pending", sa.Boolean(),
                                                   nullable=False, server_default=sa.true()))
    op.create_table(
        "key_custody_share_history",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("principal_id", sa.String(128), nullable=False, index=True),
        sa.Column("x", sa.Integer(), nullable=False),
        sa.Column("y_sealed", sa.Text(), nullable=False),
        sa.Column("kcv", sa.String(32), nullable=False),
        sa.Column("superseded_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("superseded_by", sa.String(128), nullable=False),
    )
    op.create_table(
        "operator_enrolment_codes",
        sa.Column("code_sha256", sa.String(64), primary_key=True),
        sa.Column("operator_id", sa.String(128), nullable=False),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "key_custody_releases",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("principal_id", sa.String(128), nullable=False),
        sa.Column("subject", sa.String(128), nullable=False),
        sa.Column("credential_kind", sa.String(16), nullable=False),
        sa.Column("credential_ref", sa.String(64), nullable=False),
        sa.Column("collection_id", sa.String(128), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_key_custody_releases_principal_id", "key_custody_releases",
                    ["principal_id"])
    op.create_index("ix_key_custody_releases_subject", "key_custody_releases", ["subject"])
    op.create_index("ix_key_custody_releases_credential_ref", "key_custody_releases",
                    ["credential_ref"])


def downgrade() -> None:
    """Drops the three tables: background authority ends (no delegation can be minted or
    verified), and the release record is lost."""
    for ix, table in (("ix_key_custody_releases_credential_ref", "key_custody_releases"),
                      ("ix_key_custody_releases_subject", "key_custody_releases"),
                      ("ix_key_custody_releases_principal_id", "key_custody_releases"),
                      ("ix_key_custody_delegations_subject", "key_custody_delegations")):
        op.drop_index(ix, table_name=table)
    op.drop_index("ix_delegation_tokens_subject", table_name="delegation_tokens")
    op.drop_table("delegation_tokens")
    op.drop_table("seed_credentials")
    op.drop_table("operator_enrolment_codes")
    op.drop_table("key_custody_share_history")
    op.drop_column("key_custody_shares", "rekey_pending")
    op.drop_table("key_custody_releases")
    op.drop_table("key_custody_delegations")
    op.drop_table("key_custody_background")

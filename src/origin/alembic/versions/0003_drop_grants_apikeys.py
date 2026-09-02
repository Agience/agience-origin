"""drop grants + api_keys tables

Revision ID: 0003_drop_grants_apikeys
Revises: 0002_email_verified
Create Date: 2026-07-13

Authorization does not live here. Origin is identity-only: it neither verifies API keys nor
resolves grants, so its `grants` and `api_keys` tables are removed. Downgrade recreates them
empty, matching the 0001 schema; data is not restored.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003_drop_grants_apikeys"
down_revision: Union[str, None] = "0002_email_verified"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index("ix_grants_expires_at", table_name="grants")
    op.drop_index("ix_grants_state", table_name="grants")
    op.drop_index("ix_grants_resource_id", table_name="grants")
    op.drop_table("grants")

    op.drop_index("ix_api_keys_key_hash", table_name="api_keys")
    op.drop_index("ix_api_keys_client_id", table_name="api_keys")
    op.drop_index("ix_api_keys_user_id", table_name="api_keys")
    op.drop_table("api_keys")


def downgrade() -> None:
    # Recreate empty, matching the 0001 definitions.
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey("persons.id", ondelete="CASCADE", name="fk_api_keys_user_id_persons"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("display_label", sa.String(length=256), nullable=True),
        sa.Column("client_id", sa.String(length=256), nullable=True),
        sa.Column("host_id", sa.Uuid(), nullable=True),
        sa.Column("server_id", sa.Uuid(), nullable=True),
        sa.Column("agent_id", sa.Uuid(), nullable=True),
        sa.Column("issued_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("created_from_client_id", sa.String(length=256), nullable=True),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("requires_nonce", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("scopes", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("resource_filters", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("modified_time", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("key_hash", name="uq_api_keys_key_hash"),
    )
    op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"])
    op.create_index("ix_api_keys_client_id", "api_keys", ["client_id"])
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"])

    op.create_table(
        "grants",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("grantee_type", sa.String(length=16), nullable=False),
        sa.Column("grantee_id", sa.String(length=256), nullable=False),
        sa.Column("granted_by", sa.Uuid(), nullable=False),
        sa.Column("effect", sa.String(length=8), nullable=False, server_default=sa.text("'allow'")),
        sa.Column("can_create", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("can_read", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("can_update", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("can_delete", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("can_evict", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("can_invoke", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("can_add", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("can_share", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("can_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("requires_identity", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("read_requires_identity", sa.Boolean(), nullable=True),
        sa.Column("write_requires_identity", sa.Boolean(), nullable=True),
        sa.Column("invoke_requires_identity", sa.Boolean(), nullable=True),
        sa.Column("target_entity", sa.String(length=256), nullable=True),
        sa.Column("target_entity_type", sa.String(length=32), nullable=True),
        sa.Column("max_claims", sa.Integer(), nullable=True),
        sa.Column("claims_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("state", sa.String(length=16), nullable=False, server_default=sa.text("'active'")),
        sa.Column("name", sa.String(length=256), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("accepted_by", sa.Uuid(), nullable=True),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.Uuid(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("modified_time", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_grants_resource_id", "grants", ["resource_id"])
    op.create_index("ix_grants_state", "grants", ["state"])
    op.create_index("ix_grants_expires_at", "grants", ["expires_at"])

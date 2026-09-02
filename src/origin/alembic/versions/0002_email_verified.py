"""add persons.email_verified

Revision ID: 0002_email_verified
Revises: 0001_initial_origin
Create Date: 2026-06-23

Adds the `email_verified` flag to persons. Defaults to true so identity-proven
paths (OIDC, OTP, passkey, bootstrap) and all pre-existing rows are treated as
verified — only password registration sets it false when verification is
required. Hand-written to match the deterministic 0001 schema style.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002_email_verified"
down_revision: Union[str, None] = "0001_initial_origin"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "persons",
        sa.Column(
            "email_verified",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
    )


def downgrade() -> None:
    op.drop_column("persons", "email_verified")

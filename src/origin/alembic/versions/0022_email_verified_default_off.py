"""persons.email_verified defaults to unverified (review 15).

Revision ID: 0022_email_verified_default_off
Revises: 0021_tokens_review12

A row inserted without a value is unverified: only the verification link, an OTP sign-in, a
provider's assertion, or the operator's own bootstrap records an address as proven, each saying so
explicitly. Rows already stored keep their value. Password accounts created while verification was
off still carry `true`; the cutover resets those (see the key custody design notes).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0022_email_verified_default_off"
down_revision: Union[str, None] = "0021_tokens_review12"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("persons") as batch:
        batch.alter_column("email_verified", existing_type=sa.Boolean(), existing_nullable=False,
                           server_default=sa.text("0"))


def downgrade() -> None:
    with op.batch_alter_table("persons") as batch:
        batch.alter_column("email_verified", existing_type=sa.Boolean(), existing_nullable=False,
                           server_default=sa.text("1"))

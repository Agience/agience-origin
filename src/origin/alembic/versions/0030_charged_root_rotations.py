"""Step 21's rotation of a charged root's key, as the operator records it (review 31).

Revision ID: 0030_charged_root_rotations
Revises: 0029_root_part_removed

Additive. `charged_root_rotations` holds, per charged root, the key-check value of the key step 21
rotated it onto, recorded by the operator from the rotation's report. The operator's
`platform.custody` grant over a charged root needs one, and Origin stores or releases that root's
share only for that key, while its split reads back. `grant_id` is the one grant the record opens
the split under, and `share_written` says a share of that key was written after the record
(review 32).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0030_charged_root_rotations"
down_revision: Union[str, None] = "0029_root_part_removed"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "charged_root_rotations",
        sa.Column("principal_id", sa.String(128), primary_key=True),
        sa.Column("kcv", sa.String(32), nullable=False),
        sa.Column("recorded_by", sa.String(128), nullable=False),
        sa.Column("recorded_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("grant_id", sa.String(128), nullable=True),
        sa.Column("share_written", sa.Boolean, nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_table("charged_root_rotations")

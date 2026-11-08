"""authority changes happen at Origin (review 12): no schema change.

Revision ID: 0020_authority_review12
Revises: 0019_sign_in_review11

Authority changes a person makes in their Origin session are ledger entries like any other, with
the actor kind `origin_session` and Origin's own confirmation; the feed carries what Mantle needs
to verify them. Nothing new is stored, so this revision only keeps the chain in order.
"""
from typing import Sequence, Union

revision: str = "0020_authority_review12"
down_revision: Union[str, None] = "0019_sign_in_review11"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass

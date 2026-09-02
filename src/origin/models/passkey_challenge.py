"""PasskeyChallenge — server-side, single-use WebAuthn challenge storage.

A WebAuthn challenge only proves freshness if the *relying party* chooses it, remembers it, and
does not accept it a second time. A relying party that instead reads the "expected" challenge back
out of the client's own request body at verification time is asking the client what it should have
expected — a captured assertion becomes replayable forever.

This table is that memory. One row per issued challenge, consumed atomically on
first use, bound at issue time to the person the challenge was minted for (so
`user_id` does not have to be taken from the request either).
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Index, String, Text, Uuid

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PasskeyChallenge(Base):
    __tablename__ = "passkey_challenges"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)

    # The b64url-encoded challenge exactly as handed to the client. UNIQUE so a
    # duplicate issue can never create two independently-consumable rows.
    challenge = Column(Text, nullable=False, unique=True, index=True)

    # "login" or "register" — a login challenge must never satisfy a
    # registration ceremony, or vice versa.
    purpose = Column(String(16), nullable=False)

    # Bound at ISSUE time. For login this is resolved server-side from the email
    # lookup, which is what removes client-supplied `user_id` from the flow.
    # Null only for ceremonies with no subject yet.
    person_id = Column(Uuid, nullable=True, index=True)

    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    used = Column(Boolean, nullable=False, default=False, index=True)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("ix_passkey_challenges_lookup", "challenge", "used", "expires_at"),
    )

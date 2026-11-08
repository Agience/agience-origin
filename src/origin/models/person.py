"""Person — an Origin account.

Email and username use `COLLATE NOCASE` so lookups are case-insensitive.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, Column, DateTime, String, Text, Uuid, text

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Person(Base):
    __tablename__ = "persons"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    email = Column(String(256, collation="NOCASE"), nullable=True, unique=True)
    username = Column(String(256, collation="NOCASE"), nullable=True, unique=True)
    name = Column(String(256), nullable=False, server_default="")
    picture = Column(Text, nullable=True)
    password_hash = Column(Text, nullable=True)
    # Unverified unless a path proved the address and says so (review 15, migration 0022): the
    # verification link, an OTP sign-in, a provider's assertion, or the operator's bootstrap.
    email_verified = Column(Boolean, nullable=False, default=False, server_default=text("0"))
    preferences = Column(JSON, nullable=False, default=dict)
    # Set: the account signs in nowhere and is mailed nothing (`auth_service.refuse_if_deactivated`).
    # Nothing else about the account changes, so clearing it restores the account exactly.
    deactivated_at = Column(DateTime(timezone=True), nullable=True)
    deactivated_reason = Column(Text, nullable=True)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    modified_time = Column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )



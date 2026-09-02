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
    # Defaults to verified (true) so identity-proven paths (OIDC, OTP, passkey,
    # bootstrap) and existing rows are verified; password registration sets it
    # false explicitly when email verification is required.
    email_verified = Column(Boolean, nullable=False, server_default=text("1"))
    preferences = Column(JSON, nullable=False, default=dict)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    modified_time = Column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )



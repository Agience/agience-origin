"""PasswordReset — one mailed password reset link.

The link carries a short random token; only its SHA-256 is stored. A row names the account, the
fingerprint of the password it had when the link was sent (a link stops working once the password
changes), and when the link expires. Using a link deletes every row for that account.
"""

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, String, Uuid

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PasswordReset(Base):
    __tablename__ = "password_resets"

    token_hash = Column(String(64), primary_key=True)
    person_id = Column(Uuid, ForeignKey("persons.id", ondelete="CASCADE"), nullable=False, index=True)
    password_fingerprint = Column(String(128), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

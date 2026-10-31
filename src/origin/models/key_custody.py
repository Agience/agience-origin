"""Origin's custody of one share of each Mantle master key, and the tokens already spent on it.

`key_custody_shares` holds share 2 of each principal's 2-of-3 split (`services.key_shares`), apart
from `platform_settings` so that no settings route can list, read or write one. The share bytes are
Fernet-encrypted under Origin's `encryption.key`; the x-coordinate and the key-check value are not
secret (the check value is a MAC of a 256-bit random key) and stay in the clear, so a conditional
write can compare them without decrypting.

`key_custody_nonces` holds the `jti` of every token presented to `/internal/key-shares` until it
expires, so a token is accepted once.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class KeyCustodyShare(Base):
    __tablename__ = "key_custody_shares"

    principal_id = Column(String(128), primary_key=True)
    x = Column(Integer, nullable=False)
    y_sealed = Column(Text, nullable=False)
    kcv = Column(String(32), nullable=False)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow,
                          onupdate=_utcnow)


class KeyCustodyNonce(Base):
    __tablename__ = "key_custody_nonces"

    jti = Column(String(128), primary_key=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)

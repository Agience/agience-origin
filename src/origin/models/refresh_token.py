"""RefreshToken — every refresh token Origin issued, by `jti` (review 7, F2).

A refresh token is used once: the refresh grant marks it used and issues the next one in the same
family. A used one presented again is theft, and revokes its whole family. Deactivating a person
revokes every family of theirs. Only the `jti` is kept, never the token.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String, Text

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    jti = Column(String(64), primary_key=True)
    #: The first token's `jti`: every rotation of one sign-in shares it.
    family = Column(String(64), nullable=False, index=True)
    person_id = Column(String(64), nullable=False, index=True)
    client_id = Column(String(128), nullable=False, default="")
    issued_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    used_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    #: The token this one's rotation issued, sealed under Origin's key, until `next_until`: an
    #: exact retry within that grace (a response lost on the way) gets the same one back.
    next_sealed = Column(Text, nullable=True)
    next_until = Column(DateTime(timezone=True), nullable=True)

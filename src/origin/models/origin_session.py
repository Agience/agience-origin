"""OriginSession — a person's first-party session on Origin's own host (review 8, R1).

Set as an HttpOnly, SameSite=Strict cookie when a person signs in on Origin's own pages, and never
returned in a body, so no bearer token Mantle or a facet holds stands in for it. A change to how a
person signs in (linking or unlinking an identity, adding or removing a passkey) is made only in
this session. Only the SHA-256 of the cookie is kept.
"""
from datetime import datetime, timezone

from sqlalchemy import JSON, Column, DateTime, String

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class OriginSession(Base):
    __tablename__ = "origin_sessions"

    id_sha256 = Column(String(64), primary_key=True)
    person_id = Column(String(64), nullable=False, index=True)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    expires_time = Column(DateTime(timezone=True), nullable=False)
    revoked_time = Column(DateTime(timezone=True), nullable=True)
    #: When the sign-in that started the session happened, and how (RFC 8176 values: `pop` and
    #: `mfa` for a passkey with user verification, `otp`, `pwd`, `fed` for a federated sign-in).
    #: A chair note carries both.
    auth_time = Column(DateTime(timezone=True), nullable=True)
    amr = Column(JSON, nullable=True)
    #: The session's last use, for the idle timeout.
    last_seen_time = Column(DateTime(timezone=True), nullable=True)

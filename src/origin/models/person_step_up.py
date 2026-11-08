"""PersonStepUp — a re-authentication ticket for one request a person wants to make.

A person with no passkey steps up by signing in again, through a method already theirs, at
Origin's own pages (`services.person_step_up`). The ticket is issued for one request (its method,
path and body, as a digest), proven only by a sign-in code Origin itself consumes at
`/auth/reauth/complete`, and spent by that one request.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PersonStepUp(Base):
    __tablename__ = "person_step_ups"

    ticket = Column(String(64), primary_key=True)
    person_id = Column(String(64), nullable=False, index=True)
    #: The hex digest of the one request this ticket authorizes (`operator_console.request_digest`).
    digest = Column(String(64), nullable=False)
    #: The PKCE verifier of the sign-in that proves it; held here, never sent to anyone.
    verifier = Column(String(128), nullable=False)
    describe = Column(String(256), nullable=False, default="")
    #: The start page's confirm: the form token, and when the person confirmed the action.
    csrf = Column(String(64), nullable=True)
    #: The SHA-256 of the Origin session the ticket was started in: only that browser completes it.
    session_sha256 = Column(String(64), nullable=True)
    confirmed_time = Column(DateTime(timezone=True), nullable=True)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    proven_time = Column(DateTime(timezone=True), nullable=True)
    spent_time = Column(DateTime(timezone=True), nullable=True)

"""`agent_approvals`: each approval token Origin minted for an agent session (FR-032).

A row is the approval's `jti`, the agent window's job grant it was asked under, the person whose
approval it is, the agent, and the thumbprint of the session's key it is bound to. Every exchange
of the token checks the row, so revoking it (or its grant) ends the session at its next exchange.
The token itself is returned once and never stored.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AgentApproval(Base):
    __tablename__ = "agent_approvals"

    jti = Column(String(64), primary_key=True)
    grant_id = Column(String(128), nullable=False, index=True)
    person = Column(String(128), nullable=False, index=True)
    agent = Column(String(128), nullable=False)
    session_jkt = Column(String(64), nullable=False)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

"""When a person's credentials end, and the attempts at linking a sign-in method (review 10).

`person_not_before`: a credential issued before `access_before` is no access credential any more
(sign-out, sign-out-everywhere), and a refresh token issued before `refresh_before` is refused
(sign-out-everywhere). The row for `*` covers everyone: a rollover of Origin's signing key ends
every session.

`link_attempts`: one attempt at linking another sign-in method, begun in the person's Origin
session. Its random state comes back with the sign-in's code, and the code must carry the PKCE
challenge the attempt recorded. Only the state's SHA-256 is kept.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PersonNotBefore(Base):
    __tablename__ = "person_not_before"

    person_id = Column(String(64), primary_key=True)          # a person's id, or "*"
    access_before = Column(DateTime(timezone=True), nullable=True)
    refresh_before = Column(DateTime(timezone=True), nullable=True)
    #: The order of changes to these rows: each change takes the next number, and
    #: `GET /auth/not-before?after=` serves the rows changed after a peer's cursor (review 12, M8).
    seq = Column(Integer, nullable=False, default=0, index=True)


class LinkAttempt(Base):
    __tablename__ = "link_attempts"

    state_sha256 = Column(String(64), primary_key=True)
    person_id = Column(String(64), nullable=False, index=True)
    code_challenge = Column(String(128), nullable=False)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    spent_time = Column(DateTime(timezone=True), nullable=True)

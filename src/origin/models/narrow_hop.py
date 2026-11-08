"""One hop of cross-persona work (review 12, decision 2).

A persona holding a delegation narrowed to itself exchanges it at Origin (`/internal/narrow-hop`)
for one narrowed to the next persona, only along the pairs Origin lists (`config.NARROW_HOPS`).
Each exchange is recorded here: the person, the delegation it came from (`subject_jti`), the one
it made (`jti`), and the two audiences.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class NarrowHop(Base):
    __tablename__ = "narrow_hops"

    jti = Column(String(64), primary_key=True)
    sub = Column(String(64), nullable=False, index=True)
    subject_jti = Column(String(64), nullable=False, default="")
    from_aud = Column(String(128), nullable=False)
    to_aud = Column(String(128), nullable=False)
    at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

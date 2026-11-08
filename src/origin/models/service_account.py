"""Service accounts: an Origin account that is a service's own (review 11, M5).

Ember's own credential is an Origin account; marked here for its audience, every token Origin
issues for it is a delegation narrowed to that audience (`auth_service.create_jwt_token`), never a
person token. Set by the operator (`python -m origin.scripts.service_account`).
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ServiceAccount(Base):
    __tablename__ = "service_accounts"

    person_id = Column(String(64), primary_key=True)
    audience = Column(String(128), nullable=False)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

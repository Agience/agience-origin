"""Who Ophan's billing mail may be addressed to, and each address it read (review 21, F4).

Ophan's receipts and usage warnings run from a payment webhook, with no person's token to show.
They read one thing at Origin, a person's address, through their own route
(`/internal/billing-recipients/{id}`), and only for a person Ophan recorded here as billed: the
payment provider's verified event activated their subscription and has not ended it. Each read is
recorded in `billing_recipient_lookups`, found or not.
"""
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class BillingRecipient(Base):
    __tablename__ = "billing_recipients"

    person_id = Column(String(64), primary_key=True)
    active = Column(Boolean, nullable=False, default=False)
    plan = Column(String(64), nullable=False, default="")
    recorded_by = Column(String(128), nullable=False, default="")
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)


class BillingRecipientLookup(Base):
    __tablename__ = "billing_recipient_lookups"

    id = Column(Integer, primary_key=True, autoincrement=True)
    person_id = Column(String(64), nullable=False, index=True)
    caller = Column(String(128), nullable=False)
    found = Column(Boolean, nullable=False)
    at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

"""Approval notes: a request filed against a workspace or collection, the note an approval mints,
and each spend.

A request is filed by an account (`POST /notes/requests`) against a resource it can read, with the
exact fields of what it will do; Origin computes their digest. Whoever holds update on that resource
approves or declines it on Origin's own page, in their Origin session; an approval mints one signed
note (`chair-note+jwt`) bound to that digest. The agent that acts spends the note at Origin once
per action (`POST /notes/spend`).

These are Origin's own tables, never ledger entries: Mantle has no part in them.
"""
from datetime import datetime, timezone

from sqlalchemy import JSON, Column, DateTime, String, Text

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ChairRequest(Base):
    __tablename__ = "chair_requests"

    id = Column(String(64), primary_key=True)
    #: The filer's name for the action, or `question`.
    kind = Column(String(32), nullable=False)
    #: The filer's label for the request, shown on the page.
    level = Column(String(16), nullable=False)
    fields = Column(JSON, nullable=False)
    #: `sha256:<hex>` of `fields` for an action; with `steps`, of `fields` and each step's digest.
    digest = Column(String(80), nullable=False)
    steps = Column(JSON, nullable=True)
    summary = Column(Text, nullable=False, default="")
    evidence = Column(JSON, nullable=True)
    aud = Column(JSON, nullable=False)
    options = Column(JSON, nullable=True)
    default_option = Column(String(64), nullable=True)
    filed_by = Column(String(200), nullable=False)
    filed_by_account = Column(String(64), nullable=False, index=True)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    expires_time = Column(DateTime(timezone=True), nullable=False)
    #: `pending`, `approved`, `declined`, `answered` (a question's option that needs no note) or
    #: `withdrawn` (by its filer, before anyone decided it).
    state = Column(String(16), nullable=False, default="pending", index=True)
    decided_time = Column(DateTime(timezone=True), nullable=True)
    decided_by = Column(String(64), nullable=True)
    decline_reason = Column(Text, nullable=True)
    answer = Column(String(64), nullable=True)
    #: The jti of the note an approval minted.
    note_jti = Column(String(64), nullable=True)
    #: The workspace or collection the request is filed against; its admins approve it.
    resource_id = Column(String(64), nullable=True, index=True)


class ChairNote(Base):
    __tablename__ = "chair_notes"

    jti = Column(String(64), primary_key=True)
    req = Column(String(64), nullable=False, index=True)
    person_id = Column(String(64), nullable=False, index=True)
    level = Column(String(16), nullable=False)
    #: The note itself: the approvals page shows it again, and the filer fetches it.
    token = Column(Text, nullable=False)
    issued_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    expires_time = Column(DateTime(timezone=True), nullable=False)
    revoked_time = Column(DateTime(timezone=True), nullable=True)


class ChairSpend(Base):
    """One use of a note for one action: the key is (jti, action), so a second spend is refused."""
    __tablename__ = "chair_spends"

    jti = Column(String(64), primary_key=True)
    action = Column(String(80), primary_key=True)
    id = Column(String(64), nullable=False, unique=True)
    req = Column(String(64), nullable=False)
    spent_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

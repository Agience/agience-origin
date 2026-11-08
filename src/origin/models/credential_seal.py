"""The digests of a credential's sealed copies, as its writer made them (review 22, F2).

Mantle seals a credential's secret, when it is written, to each persona that uses it. A Mantle taken
over later could answer a use with a copy it sealed itself, so Origin keeps, from the writer's own
credential, the SHA-256 of each persona's sealed copy (`sealed_sha256`, `{persona: hex}`) and of the
credential's endpoint list, and every use verdict carries the persona's. The persona opens only the
copy whose digest the verdict names.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String, Text

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CredentialSeal(Base):
    __tablename__ = "credential_seals"

    credential_id = Column(String(128), primary_key=True)
    sealed_sha256 = Column(Text, nullable=False)            # JSON {persona: sha256 hex}
    endpoints_sha256 = Column(String(64), nullable=False)
    recorded_by = Column(String(64), nullable=False, default="")
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

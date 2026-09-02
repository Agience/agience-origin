"""PersonIdentity — one row per proof that a person is who they claim to be.

`passkey_credentials` already shows the right shape for this: a `person_id` FK, many rows per
person, because a person can own more than one device. This table generalizes that shape to every
identity method: `method` is an open string rather than a fixed set of columns, so a person can
hold any number of identities and adding one never touches another.

The same table is the federation bridge. A foreign origin is just another method:

    method="origin", provider="https://origin.example.test", subject="<local principal id>"

so "this GitHub login is Jane" and "this other origin's principal is Jane" resolve through one
lookup. That is what underlies both multi-provider sign-in and cross-origin joining.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Index, String, Text, Uuid

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PersonIdentity(Base):
    __tablename__ = "person_identities"

    id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    person_id = Column(
        Uuid, ForeignKey("persons.id", ondelete="CASCADE"), nullable=False, index=True
    )

    #: How the human proved it — "oidc", "email", "passkey", "biometric", "origin", …
    #: Deliberately a free string, not an enum: `bio-check` and a new federation method must not
    #: require a schema migration to exist.
    method = Column(String(32), nullable=False)

    #: Who vouched. For OIDC the provider name ("google"); for a peer origin its ISSUER URL.
    provider = Column(String(256), nullable=False)

    #: That provider's stable id for this human — `sub` for OIDC, the principal id for an origin.
    subject = Column(String(256), nullable=False)

    verified_at = Column(DateTime(timezone=True), nullable=True)

    #: Method-specific evidence (a JWKS kid, a credential id, an attestation, a peer signature).
    #: Opaque here on purpose — this table records that proof happened, not how to redo it.
    proof = Column(Text, nullable=True)

    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    modified_time = Column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    __table_args__ = (
        Index("ux_person_identity", "method", "provider", "subject", unique=True),
        # The hot path: "who owns this identity?" on every federated sign-in.
        Index("ix_person_identity_lookup", "provider", "subject"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        state = "verified" if self.verified_at else "unverified"
        return f"<PersonIdentity {self.method}:{self.provider}:{self.subject} ({state})>"

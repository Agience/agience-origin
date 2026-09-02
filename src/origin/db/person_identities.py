"""Data access for `person_identities` — the many-identities-per-person table.

One human, many proofs, and a peer origin is just another proof method — so linking a GitHub
account and linking a whole other origin's principal go through the same two functions.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from origin.models.person_identity import PersonIdentity

#: The method used for a link to another Agience origin. `provider` is that origin's ISSUER URL and
#: `subject` is the principal id it knows the human by.
METHOD_ORIGIN = "origin"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def get_by_identity(
    db: Session, *, method: str, provider: str, subject: str
) -> Optional[PersonIdentity]:
    """Resolve one external identity to its row, or None.

    The unique index makes this at most one row — the caller never has to decide between
    candidates, which is the point of the constraint.
    """
    return db.execute(
        select(PersonIdentity).where(
            PersonIdentity.method == method,
            PersonIdentity.provider == provider,
            PersonIdentity.subject == subject,
        ).limit(1)
    ).scalar_one_or_none()


def list_for_person(db: Session, person_id) -> List[PersonIdentity]:
    """Every identity linked to a person, oldest first."""
    return list(db.execute(
        select(PersonIdentity)
        .where(PersonIdentity.person_id == _uuid(person_id))
        .order_by(PersonIdentity.created_time)
    ).scalars())


def add(
    db: Session,
    *,
    person_id,
    method: str,
    provider: str,
    subject: str,
    verified: bool,
    proof: Optional[str] = None,
) -> PersonIdentity:
    """Attach an identity to a person. Additive: never displaces an existing one.
    """
    row = PersonIdentity(
        id=uuid.uuid4(),
        person_id=_uuid(person_id),
        method=method,
        provider=provider,
        subject=subject,
        verified_at=_utcnow() if verified else None,
        proof=proof,
    )
    db.add(row)
    db.flush()
    return row


def remove(db: Session, *, person_id, method: str, provider: str, subject: str) -> int:
    """Detach one identity. Returns the number of rows removed (0 or 1).

    Scoped by `person_id` on purpose: an identity can only ever be removed from the account that
    actually holds it, so a caller that mixes up ids deletes nothing instead of unlinking someone
    else's account.
    """
    result = db.execute(
        delete(PersonIdentity).where(
            PersonIdentity.person_id == _uuid(person_id),
            PersonIdentity.method == method,
            PersonIdentity.provider == provider,
            PersonIdentity.subject == subject,
        )
    )
    db.flush()
    return result.rowcount or 0


def count_verified(db: Session, person_id) -> int:
    """How many proven identities a person has.

    A caller uses this to guard removal of the last credential: unlinking the only way someone
    can sign in would lock them out of their own account while the account still exists — the
    worst combination.
    """
    rows = list_for_person(db, person_id)
    return sum(1 for r in rows if r.verified_at is not None)


def _uuid(value):
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))

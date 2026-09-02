"""CRUD for `passkey_challenges`.

The important operation here is :func:`consume`, which is the single-use gate.
It must be atomic: two concurrent replays of the same captured assertion have to
resolve to exactly one winner, so the check and the mark cannot be two
statements with a gap between them.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import delete as sa_delete, select, update as sa_update
from sqlalchemy.orm import Session

from origin.models.passkey_challenge import PasskeyChallenge

# WebAuthn ceremonies are interactive; the client-side timeout is 60s. Allow a
# little clock skew and user hesitation, but not more — this window is exactly
# how long a captured challenge stays worth anything.
DEFAULT_TTL_SECONDS = 300


def create(
    db: Session,
    challenge: str,
    purpose: str,
    person_id: Optional[str | uuid.UUID] = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: datetime | None = None,
) -> PasskeyChallenge:
    """Record a freshly-issued challenge. Call this before returning it."""
    issued = now or datetime.now(timezone.utc)
    row = PasskeyChallenge(
        id=uuid.uuid4(),
        challenge=challenge,
        purpose=purpose,
        person_id=_to_uuid(person_id) if person_id else None,
        expires_at=issued + timedelta(seconds=ttl_seconds),
        used=False,
        created_time=issued,
    )
    db.add(row)
    db.flush()
    return row


def consume(
    db: Session,
    challenge: str,
    purpose: str,
    now: datetime | None = None,
) -> Optional[PasskeyChallenge]:
    """Atomically claim a live challenge. Returns the row, or None.

    None means: never issued, wrong purpose, already used, or expired — all of
    which are authentication failures and must be reported identically, so this
    does not distinguish between them.

    The UPDATE carries the full predicate (`used == False`) rather than reading
    first and writing after. Whichever transaction wins reports rowcount 1; the
    loser gets 0 and is rejected. A read-then-write would let both replays pass.
    """
    cutoff = now or datetime.now(timezone.utc)
    result = db.execute(
        sa_update(PasskeyChallenge)
        .where(
            PasskeyChallenge.challenge == challenge,
            PasskeyChallenge.purpose == purpose,
            PasskeyChallenge.used.is_(False),
            PasskeyChallenge.expires_at > cutoff,
        )
        .values(used=True)
    )
    if not result.rowcount:
        return None
    return db.execute(
        select(PasskeyChallenge).where(PasskeyChallenge.challenge == challenge)
    ).scalar_one_or_none()


def delete_expired(db: Session, now: datetime | None = None) -> int:
    """Reap consumed and expired rows. Safe to call on a schedule."""
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(hours=1)
    result = db.execute(
        sa_delete(PasskeyChallenge).where(
            (PasskeyChallenge.used.is_(True)) | (PasskeyChallenge.expires_at <= cutoff)
        )
    )
    return result.rowcount or 0


def _to_uuid(value: str | uuid.UUID) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    return uuid.UUID(str(value))

"""SQLite CRUD for `otp_codes`."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from sqlalchemy import delete as sa_delete, func, select, update as sa_update
from sqlalchemy.orm import Session

from origin.models.otp_code import OtpCode


def create(db: Session, fields: Mapping[str, Any]) -> OtpCode:
    payload = dict(fields)
    if "id" in payload and payload["id"]:
        payload["id"] = _to_uuid(payload["id"])
    else:
        payload["id"] = uuid.uuid4()
    code = OtpCode(**payload)
    db.add(code)
    db.flush()
    return code


def list_valid_for_email(
    db: Session, email: str, max_attempts: int, now: datetime | None = None
) -> list[OtpCode]:
    """Unexpired, unused, attempts < max — sorted newest first."""
    cutoff = now or datetime.now(timezone.utc)
    return list(
        db.execute(
            select(OtpCode)
            .where(
                OtpCode.email == email,
                OtpCode.expires_at > cutoff,
                OtpCode.used.is_(False),
                OtpCode.attempts < max_attempts,
            )
            .order_by(OtpCode.created_time.desc())
        ).scalars()
    )


def get_latest_valid_for_email(
    db: Session, email: str, max_attempts: int, now: datetime | None = None
) -> OtpCode | None:
    """The single live code for this email, or None.

    Verification tests the guess against exactly one code, the most recently
    issued. Testing against every live code would let an attacker multiply
    their odds of a match by requesting more codes, and would run one bcrypt
    comparison per live code instead of one per request.
    """
    cutoff = now or datetime.now(timezone.utc)
    return db.execute(
        select(OtpCode)
        .where(
            OtpCode.email == email,
            OtpCode.expires_at > cutoff,
            OtpCode.used.is_(False),
            OtpCode.attempts < max_attempts,
        )
        .order_by(OtpCode.created_time.desc())
        .limit(1)
    ).scalar_one_or_none()


def count_recent_misses(db: Session, email: str, since: datetime) -> int:
    """Guesses taken against this email's codes issued in the window: every attempt claimed
    (`claim_attempt`), on every code, used or not.

    The guess that verified a code is counted too, so one successful sign-in costs one draw. It is
    not subtracted: `used` also marks a code retired by `supersede_live_for_email`, and a
    subtraction keyed on it would erase a wrong guess for every replaced code. A code nobody has
    tried counts nothing.
    """
    return db.execute(
        select(func.coalesce(func.sum(OtpCode.attempts), 0))
        .where(OtpCode.email == email, OtpCode.created_time >= since)
    ).scalar_one()


def supersede_live_for_email(db: Session, email: str, now: datetime | None = None) -> int:
    """Retire every live code for this email. Called when a new one is issued.

    Keeps the invariant that at most one code is ever valid, which is what makes
    the single-code lookup above correct rather than merely cheaper.
    """
    cutoff = now or datetime.now(timezone.utc)
    result = db.execute(
        sa_update(OtpCode)
        .where(
            OtpCode.email == email,
            OtpCode.used.is_(False),
            OtpCode.expires_at > cutoff,
        )
        .values(used=True)
    )
    return result.rowcount or 0


def claim_attempt(
    db: Session, otp_id: str | uuid.UUID, max_attempts: int, now: datetime | None = None
) -> bool:
    """Spend one attempt on this code if it is still live; True when one was spent.

    One UPDATE conditioned on the code still being live, not a read followed by a write, so
    verifications of one code arriving together cannot spend more than `max_attempts` between
    them: once the count reaches the cap, the condition fails for every later one.
    """
    cutoff = now or datetime.now(timezone.utc)
    result = db.execute(
        sa_update(OtpCode)
        .where(
            OtpCode.id == _to_uuid(otp_id),
            OtpCode.used.is_(False),
            OtpCode.attempts < max_attempts,
            OtpCode.expires_at > cutoff,
        )
        .values(attempts=OtpCode.attempts + 1)
        # The condition is decided by the database. Evaluating it again against the code already
        # loaded in this session would compare a stored naive timestamp with an aware one.
        .execution_options(synchronize_session=False)
    )
    return (result.rowcount or 0) == 1


def claim_use(db: Session, otp_id: str | uuid.UUID) -> bool:
    """Mark this code used if nothing else has; True for the one verification that did."""
    result = db.execute(
        sa_update(OtpCode)
        .where(OtpCode.id == _to_uuid(otp_id), OtpCode.used.is_(False))
        .values(used=True)
        .execution_options(synchronize_session=False)
    )
    return (result.rowcount or 0) == 1


def delete_expired(db: Session, now: datetime | None = None) -> int:
    """Delete codes that expired more than a day ago. Only by age: a used or superseded code still
    carries attempts `count_recent_misses` reads, so deleting it early would hand those guesses
    back."""
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=1)
    result = db.execute(sa_delete(OtpCode).where(OtpCode.expires_at <= cutoff))
    return result.rowcount or 0


def _to_uuid(value: str | uuid.UUID) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    return uuid.UUID(str(value))

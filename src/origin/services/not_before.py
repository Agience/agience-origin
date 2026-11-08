"""When a person's credentials stop counting (review 10, R5).

Sign-out ends the person's access tokens at Origin: one issued before then is no access credential
and opens no Origin route, though their other sign-ins refresh into new ones. Sign-out-everywhere
also ends every refresh token issued before then, a legacy one (no `jti`) included. The row `*`
ends everyone's, both kinds: a rollover of Origin's signing key (`scripts.rotate_signing_key`).

A token's `iat` is compared with the times recorded here; a token with no `iat` is refused once
any time is recorded for its person.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from origin.models.sign_in_bounds import PersonNotBefore

EVERYONE = "*"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(t: Optional[datetime]) -> Optional[datetime]:
    return t.replace(tzinfo=timezone.utc) if t is not None and t.tzinfo is None else t


def _set(db: Session, person_id: str, *, access: bool, refresh: bool) -> None:
    row = db.get(PersonNotBefore, str(person_id))
    if row is None:
        row = PersonNotBefore(person_id=str(person_id))
        db.add(row)
    now = _now()
    if access:
        row.access_before = now
    if refresh:
        row.refresh_before = now
    row.seq = next_seq(db)
    db.flush()


def next_seq(db: Session) -> int:
    """The next number in the order of changes to the not-before rows (review 12, M8). Taken inside
    the writing transaction; Origin's store (SQLite) serialises writers from first write to commit,
    so the numbers commit in order and a peer reading `after=<seq>` never skips one that commits
    late. On an engine without that, a counter row locked for the transaction would be needed."""
    from sqlalchemy import func
    db.flush()
    top = db.query(func.max(PersonNotBefore.seq)).scalar()
    return int(top or 0) + 1


def end_access(db: Session, person_id: str) -> None:
    """Sign-out: the person's access tokens issued before now end. The caller commits."""
    _set(db, person_id, access=True, refresh=False)


def end_all(db: Session, person_id: str) -> None:
    """Sign-out-everywhere: the person's access and refresh tokens issued before now end."""
    _set(db, person_id, access=True, refresh=True)


def end_everyone(db: Session) -> None:
    """Every credential Origin issued before now ends: everyone signs in again once."""
    _set(db, EVERYONE, access=True, refresh=True)


def _before(db: Session, subject: str, field: str) -> Optional[datetime]:
    times = []
    for key in (str(subject), EVERYONE):
        row = db.get(PersonNotBefore, key)
        t = _aware(getattr(row, field, None)) if row is not None else None
        if t is not None:
            times.append(t)
    return max(times) if times else None


def ended(db: Session, payload: dict, *, refresh: bool = False) -> bool:
    """Was this token (its verified claims) issued before its person's credentials ended?"""
    subject = str(payload.get("sub") or "")
    cut = _before(db, subject, "refresh_before" if refresh else "access_before")
    if cut is None:
        return False
    iat = payload.get("iat")
    if not isinstance(iat, (int, float)):
        return True
    return datetime.fromtimestamp(float(iat), timezone.utc) < cut

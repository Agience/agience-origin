"""Attempts at linking another sign-in method (review 10, R10).

An attempt is begun only in the person's Origin session, on Origin's own page. It has a random
state, which the sign-in carries back, and it records the PKCE challenge (S256) the sign-in's code
must carry. `/auth/me/link-provider` takes a code only for a live attempt of this person's, made
with that challenge, once. A code from a sign-in begun anywhere else links nothing.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import update
from sqlalchemy.orm import Session

from origin.models.sign_in_bounds import LinkAttempt

#: How long an attempt stays open: a sign-in at a provider, then the confirm.
ATTEMPT_MINUTES = 10
_CHALLENGE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _digest(state: str) -> str:
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


def begin(db: Session, person_id: str, code_challenge: str) -> str:
    if not _CHALLENGE.match(code_challenge or ""):
        raise HTTPException(status_code=400, detail="code_challenge is an S256 PKCE challenge")
    state = secrets.token_urlsafe(32)
    db.add(LinkAttempt(state_sha256=_digest(state), person_id=str(person_id),
                       code_challenge=code_challenge))
    db.commit()
    return state


def live(db: Session, state, person_id: str) -> LinkAttempt:
    """The person's live attempt for `state`, or 403."""
    if not isinstance(state, str) or not state:
        raise HTTPException(status_code=403, detail="a link needs the state of an attempt begun "
                            "on Origin's own page (POST /auth/me/link-attempts)")
    row = db.get(LinkAttempt, _digest(state))
    made = row.created_time if row is not None else None
    if made is not None and made.tzinfo is None:
        made = made.replace(tzinfo=timezone.utc)
    if (row is None or row.person_id != str(person_id) or row.spent_time is not None
            or _now() - made > timedelta(minutes=ATTEMPT_MINUTES)):
        raise HTTPException(status_code=403, detail="the link attempt's state is unknown, spent, "
                            "lapsed or another person's")
    return row


def is_attempt(db: Session, state) -> bool:
    """Is `state` an attempt's (live or not)? A sign-in carrying one is on its way to a link."""
    return isinstance(state, str) and bool(state) and db.get(LinkAttempt, _digest(state)) is not None


def spend(db: Session, row: LinkAttempt) -> None:
    n = db.execute(update(LinkAttempt).where(LinkAttempt.state_sha256 == row.state_sha256,
                                             LinkAttempt.spent_time.is_(None))
                   .values(spent_time=_now())).rowcount
    db.flush()
    if n != 1:
        raise HTTPException(status_code=403, detail="the link attempt is spent")

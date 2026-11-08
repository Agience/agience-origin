"""Refresh tokens that rotate on use and can be revoked (review 7, F2).

Each refresh token carries a `jti` Origin records (`models.refresh_token`) and a `fam`, the family
of one sign-in. The refresh grant takes a token once: it marks it used and issues the next in the
same family. A used token presented again means two holders, so it is treated as theft and the
whole family is revoked; the next refresh by either holder fails, and the person signs in again.
Deactivating a person revokes every family of theirs.

A refresh token issued before these were recorded has no `jti`. It is taken once, recorded by its
digest as a family of its own, and rotated; presented again it is theft like any other. After
`REFRESH_LEGACY_CUTOFF` (an ISO time) one with no `jti` is refused outright; on a production plane
(`AGIENCE_PLANE=production`) with no cut-off set, it already is.

There is no grace (review 10, R6). A grace returned the same next token to whoever presented a used
one within it, so a thief holding a copy shared the family with the person and no reuse was ever
seen. A used token presented again revokes the family, always: a client whose answer was lost
signs in again, and Ember serialises its rotations so it never presents one twice. A token
presented by a client other than the one it was issued to is refused, the family with it, on the
recorded value (`client_id` as issued), never an absent one matching an absent one.

A refresh token issued before its person signed out everywhere is refused
(`services.not_before`), the legacy ones included.

The take, the family check and the issue are one transaction, so a family revoked meanwhile
gets no new token.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import update
from sqlalchemy.orm import Session

from origin.models.refresh_token import RefreshToken

logger = logging.getLogger(__name__)

#: How long a refresh token lives, as before.
REFRESH_HOURS = 24 * 30


class RefreshRefused(Exception):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def issue(db: Session, user_data: dict, *, family: Optional[str] = None,
          commit: bool = True) -> str:
    """A refresh token for `user_data`, recorded by `jti` in `family` (a new family unless given).
    Committed here unless `commit=False`: a token handed out with no row behind it would be
    refused at its first use."""
    from origin.services.auth_service import create_jwt_token

    jti = secrets.token_hex(16)
    fam = family or jti
    claims = {k: v for k, v in user_data.items()
              if k not in ("exp", "iat", "jti", "fam", "token_type")}
    db.add(RefreshToken(jti=jti, family=fam, person_id=str(claims.get("sub") or ""),
                        client_id=str(claims.get("client_id") or claims.get("aud") or "")))
    if commit:
        db.commit()
    else:
        db.flush()
    return create_jwt_token({**claims, "token_type": "refresh", "jti": jti, "fam": fam},
                            expires_hours=REFRESH_HOURS)


def _legacy_cut(now: datetime) -> bool:
    import os

    from origin import config
    raw = (getattr(config, "REFRESH_LEGACY_CUTOFF", "") or "").strip()
    if not raw:
        # On production the cut-off is the cutover: no cut-off set means none are taken.
        return (os.getenv("AGIENCE_PLANE") or "").strip().lower() == "production"
    try:
        cut = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return True                    # a cut-off that does not parse refuses, never admits
    return now >= (cut if cut.tzinfo else cut.replace(tzinfo=timezone.utc))


def revoke_token_family(db: Session, token_payload: dict) -> int:
    """Sign-out: the family of the presented refresh token, revoked. The caller commits."""
    jti = token_payload.get("jti")
    row = db.get(RefreshToken, jti) if jti else None
    return revoke_family(db, row.family) if row is not None else 0


def revoke_family(db: Session, family: str) -> int:
    n = db.execute(update(RefreshToken).where(RefreshToken.family == family,
                                              RefreshToken.revoked_at.is_(None))
                   .values(revoked_at=_now())).rowcount
    db.flush()
    return n


def revoke_person(db: Session, person_id: str) -> int:
    """Every refresh token of `person_id`'s, revoked. The caller commits."""
    n = db.execute(update(RefreshToken).where(RefreshToken.person_id == str(person_id),
                                              RefreshToken.revoked_at.is_(None))
                   .values(revoked_at=_now())).rowcount
    db.flush()
    return n


def rotate(db: Session, token: str, payload: dict, user_data: dict, *,
           client_id: Optional[str] = None) -> str:
    """Take refresh token `token` (its verified `payload`) once, and return the next one in its
    family, carrying `user_data`. `RefreshRefused` for a revoked or unknown one, and for a used one (whose family is
    then revoked). Commits."""
    from origin.services import not_before
    if not_before.ended(db, payload, refresh=True):
        raise RefreshRefused("this sign-in has ended; sign in again")
    jti = payload.get("jti")
    if not jti and _legacy_cut(_now()):
        raise RefreshRefused("a refresh token issued before rotation is no longer taken")
    if not jti:
        jti = "legacy:" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:56]
        row = db.get(RefreshToken, jti)
        if row is None:
            db.add(RefreshToken(jti=jti, family=jti, person_id=str(payload.get("sub") or ""),
                                client_id=str(payload.get("client_id") or payload.get("aud")
                                              or "")))
            db.flush()
    row = db.get(RefreshToken, jti)
    if row is None:
        raise RefreshRefused("refresh token unknown")
    if row.revoked_at is not None:
        raise RefreshRefused("refresh token revoked")
    # The client that presents it (the request's own `client_id`), never the token's word for
    # itself: two copies of one token name the same client (review 11, M1).
    client = str(client_id or "")
    if not client or not row.client_id or client != row.client_id:
        revoke_family(db, row.family)
        db.commit()
        raise RefreshRefused("refresh token presented by another client")
    now = _now()
    taken = db.execute(update(RefreshToken).where(RefreshToken.jti == jti,
                                                  RefreshToken.used_at.is_(None),
                                                  RefreshToken.revoked_at.is_(None))
                       .values(used_at=now)).rowcount
    if taken != 1:
        db.refresh(row)
        revoked = revoke_family(db, row.family)
        db.commit()
        logger.warning("refresh token %s presented after use: family %s revoked (%d tokens)",
                       jti, row.family, revoked)
        raise RefreshRefused("refresh token already used")
    # One transaction: the take above, the issue, and the check that the family was not revoked
    # in between. SQLite holds the write lock from the take; the check covers any other engine.
    nxt = issue(db, user_data, family=row.family, commit=False)
    revoked_meanwhile = (db.query(RefreshToken)
                         .filter(RefreshToken.family == row.family,
                                 RefreshToken.revoked_at.isnot(None)).first())
    if revoked_meanwhile is not None:
        db.rollback()
        raise RefreshRefused("refresh token family revoked")
    db.commit()
    return nxt

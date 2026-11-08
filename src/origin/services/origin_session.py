"""A person's first-party session on Origin's own host (review 8, R1).

Origin sets it when the person signs in on its own pages (a local method, a federated callback,
a passkey, a re-authentication) as an HttpOnly, Secure (on https), SameSite=Strict cookie on its
own host. It is never in a response body and never in a token, so Mantle and the facets, which see
people's access tokens, never see it. Changes to how a person signs in require it
(`person_step_up`).
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, Request
from sqlalchemy import update
from sqlalchemy.orm import Session

from origin import config
from origin.models.origin_session import OriginSession

#: The cookie's name on plain http (local development and tests), and on https, where the
#: `__Host-` prefix makes a browser refuse it unless it is Secure, has `Path=/` and names no
#: `Domain`: no sibling host can set one Origin would read (review 13, M1).
COOKIE = "origin_session"
HOST_COOKIE = "__Host-origin_session"
HOURS = 12


class TossedCookie(HTTPException):
    """A request carrying more than one session cookie: refused, never resolved to either."""

    def __init__(self):
        super().__init__(status_code=400, detail="this request carries more than one Origin "
                         "session cookie; it is refused rather than read as either")


def _https() -> bool:
    """Keyed on the scheme of `AUTHORITY_ISSUER`, as `main._session_cookie_is_https_only` keys the
    sign-in cookie (review 15), so the two never disagree about being `__Host-`."""
    from urllib.parse import urlparse
    return urlparse(getattr(config, "AUTHORITY_ISSUER", "") or "").scheme == "https"


def cookie_name() -> str:
    """The session cookie's name here: `__Host-` prefixed wherever Origin is served over https."""
    return HOST_COOKIE if _https() else COOKIE


def _raw_values(request: Request) -> list:
    """Every value the raw Cookie header gives the session cookie's name here. On https that is
    the `__Host-` name alone: a cookie without the prefix is one any sibling host under the same
    site could have set (`Domain=agience.ai`), so it is never read, and never counted (review 14).
    A browser sends one cookie per name and domain-path pair, so two values of the name mean a
    second cookie was tossed in; the parsed `request.cookies` would keep only one silently."""
    names = (HOST_COOKIE,) if _https() else (COOKIE, HOST_COOKIE)
    out = []
    for header in request.headers.getlist("cookie"):
        for part in header.split(";"):
            name, _, value = part.strip().partition("=")
            if name in names:
                out.append(value)
    return out


def _raw(request: Request) -> str:
    values = _raw_values(request)
    if len(values) > 1:
        raise TossedCookie()
    return values[0] if values else ""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(t: Optional[datetime]) -> Optional[datetime]:
    return t.replace(tzinfo=timezone.utc) if t is not None and t.tzinfo is None else t


def _digest(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def issue(db: Session, person_id: str) -> str:
    """A new session for `person_id`; the raw cookie value (never stored). The caller commits."""
    raw = secrets.token_urlsafe(32)
    db.add(OriginSession(id_sha256=_digest(raw), person_id=str(person_id),
                         expires_time=_now() + timedelta(hours=HOURS)))
    db.flush()
    return raw


def set_cookie(response, raw: str) -> None:
    response.set_cookie(cookie_name(), raw, max_age=HOURS * 3600, httponly=True,
                        secure=_https(), samesite="strict", path="/")


def start(db: Session, response, person_id: Optional[str]) -> None:
    """Sign the person in to Origin's own session on this response, when Origin knows who it is."""
    if person_id:
        set_cookie(response, issue(db, str(person_id)))
        db.commit()


def digest_of(request: Request) -> Optional[str]:
    """The SHA-256 of this request's Origin session cookie, or None (never the cookie itself)."""
    raw = _raw(request)
    return _digest(raw) if raw else None


def person_of(request: Request, db: Session) -> Optional[str]:
    raw = _raw(request)
    if not raw:
        return None
    row = db.get(OriginSession, _digest(raw))
    if row is None or row.revoked_time is not None or _aware(row.expires_time) <= _now():
        return None
    return row.person_id


def require(request: Request, db: Session, person_id: str) -> None:
    """403 unless this request carries `person_id`'s own Origin session."""
    who = person_of(request, db)
    if who is None or who != str(person_id):
        raise HTTPException(status_code=403, detail="this change is made only on Origin's own "
                            "page, in your Origin session: sign in at Origin and do it there")


def end(request: Request, db: Session, response) -> bool:
    """Sign this browser out of Origin's session: the session the request carries is revoked (so a
    copy of the cookie kept anywhere opens nothing), and the cookie is deleted under both its names
    (`__Host-` with Secure on https, and the plain one). The caller commits. True when a live
    session was ended."""
    ended = False
    try:
        raw = _raw(request)
    except TossedCookie:
        raw = ""
    if raw:
        ended = bool(db.execute(update(OriginSession).where(
            OriginSession.id_sha256 == _digest(raw), OriginSession.revoked_time.is_(None))
            .values(revoked_time=_now())).rowcount)
    response.delete_cookie(HOST_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    response.delete_cookie(COOKIE, path="/", secure=_https(), httponly=True, samesite="strict")
    return ended


def revoke_person(db: Session, person_id: str) -> int:
    return db.execute(update(OriginSession).where(OriginSession.person_id == str(person_id),
                                                  OriginSession.revoked_time.is_(None))
                      .values(revoked_time=_now())).rowcount


#: Every cookie Origin sets, by both its names: the Origin session and the sign-in flow's own.
GUARDED = frozenset({COOKIE, HOST_COOKIE, "session", "__Host-session"})


class RefuseTossedCookies:
    """ASGI middleware: on https, drops every unprefixed copy of Origin's own cookies before the
    app sees the request (no reader, the sign-in flow's included, can take one a sibling host
    set), and answers 400 for any request whose Cookie header gives one of them more than one
    value. A browser sends one cookie per name, domain and
    path, so a second is one a sibling host set with `Domain=agience.ai`; whichever a parser kept,
    the request would run in a session its person never made."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            https = _https()
            seen = {}
            headers = []
            for k, v in scope.get("headers") or ():
                if k.lower() != b"cookie":
                    headers.append((k, v))
                    continue
                kept = []
                for part in v.decode("latin-1").split(";"):
                    name = part.strip().partition("=")[0]
                    if name in GUARDED and https and not name.startswith("__Host-"):
                        continue        # on https an unprefixed one is a sibling host's: dropped
                    if name in GUARDED:
                        family = "origin" if "origin_session" in name else "session"
                        seen[family] = seen.get(family, 0) + 1
                    if part.strip():
                        kept.append(part.strip())
                if kept:
                    headers.append((k, "; ".join(kept).encode("latin-1")))
            scope = {**scope, "headers": headers}
            if any(n > 1 for n in seen.values()):
                from starlette.responses import JSONResponse
                await JSONResponse({"detail": "this request carries more than one Origin "
                                    "session cookie; it is refused rather than read as either"},
                                   status_code=400)(scope, receive, send)
                return
        await self.app(scope, receive, send)

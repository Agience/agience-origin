"""A person's fresh step-up for one request that changes how they sign in.

Linking or unlinking a sign-in identity, and registering or deleting a passkey, need more than an
access token: Mantle holds people's live access tokens, and with one alone it could join another
person's sign-in to the account, or enrol its own passkey, and keep that after the token is gone.
So each such request carries a step-up by a method the person already has, bound to that request
(its method, path with query, and body, `operator_console.request_digest`) and spent by it:

* With a passkey: `options` returns a WebAuthn challenge whose first 32 bytes are the request's
  digest, for this person's passkeys, user verification required, single-use. The request sends
  `X-Step-Up: <b64url {"challenge", "credential"}>`, as the operator console's step-up does.
* With none: `options` returns a ticket and a URL on Origin. The person opens it
  (`/auth/reauth/start`) and signs in again through the ordinary sign-in pages, with Origin's own
  client, redirect and a PKCE verifier only this table holds. The sign-in's code comes back to
  `/auth/reauth/complete`, which consumes it at Origin and proves the ticket only if the identity
  that signed in is one this person already holds. The request then sends
  `X-Step-Up: reauth:<ticket>`. A person who has a passkey uses it; a ticket is refused for them.

No token proves anything here: a ticket is proven only by an interactive sign-in's code, consumed
where it is minted, and a passkey assertion only by the person's own authenticator.

And no token starts anything (review 8, R1). Every such change is made in the person's own Origin
session (`origin_session`, a first-party cookie Origin sets when they sign in on its own pages),
which no bearer token stands in for: a re-authentication ticket is started only from it, and the
change itself is accepted only with it. The ticket's start page shows the exact action (for a link,
which identity) and needs an explicit confirm before the sign-in, and a sign-in that does not say
when it happened (`auth_time`) proves nothing.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode

from fastapi import HTTPException, Request
from sqlalchemy import update
from sqlalchemy.orm import Session
from webauthn import generate_authentication_options
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement

from origin import config
from origin.db import passkey_challenges as db_challenges
from origin.db import passkey_credentials as db_passkeys
from origin.models.person_step_up import PersonStepUp
from origin.services import passkey_service
from origin.services.operator_console import request_digest

logger = logging.getLogger(__name__)

HEADER = "X-Step-Up"
_PURPOSE = "person-step-up"
_CHALLENGE_TTL_SECONDS = 120
#: How long a ticket waits to be proven, and how long a proven one waits to be used.
TICKET_MINUTES = 10
PROVEN_MINUTES = 5
#: The requests a person's step-up is asked for.
PATHS = ("/auth/me/link-provider", "/auth/passkey/", "/auth/me/job-grants")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(when: Optional[datetime]) -> Optional[datetime]:
    if when is not None and when.tzinfo is None:
        return when.replace(tzinfo=timezone.utc)
    return when


def _base() -> str:
    return (getattr(config, "ORIGIN_URI", "") or getattr(config, "AUTHORITY_ISSUER", "")
            or "").rstrip("/")


def link_uri() -> str:
    """Where a sign-in through the method to be linked comes back: Origin's own `/passkey`."""
    return f"{_base()}/passkey"


def complete_uri() -> str:
    return f"{_base()}/auth/reauth/complete"


def _describe(method: str, path: str, body: Optional[str] = None,
              person_id: Optional[str] = None) -> str:
    """The action, as the start page shows it: for a link, which identity it joins."""
    if path.startswith("/auth/me/link-provider"):
        if method == "DELETE":
            provider = path.rsplit("/", 1)[-1].split("?", 1)[0]
            return f"remove your {provider} sign-in"[:250]
        try:
            from origin.routers.auth_router import authorization_codes
            info = (authorization_codes.get(json.loads(body or "{}").get("code") or "")
                    or {}).get("user_info") or {}
        except (ValueError, TypeError, AttributeError):
            info = {}
        if not info:
            raise HTTPException(status_code=400, detail="the sign-in to be linked is unknown or "
                                "has expired")
        return (f"add the {info.get('provider') or 'external'} sign-in "
                f"{info.get('email') or ''} (subject {info.get('sub') or ''}) to your "
                f"account")[:250]
    if path.startswith("/auth/passkey/credentials"):
        return "remove a passkey"
    if path.startswith("/auth/me/job-grants/"):
        return _describe_job_grant_revoke(path, person_id)
    if path.startswith("/auth/me/job-grants"):
        # The page names the grant from the request's own body, which `options` binds to the
        # digest; with no body there is nothing true to show, so no step-up is started.
        try:
            want = json.loads(body or "")
        except (ValueError, TypeError):
            want = None
        cols_in = want.get("collections") if isinstance(want, dict) else None
        if (not isinstance(want, dict) or not isinstance(want.get("job"), str)
                or not want["job"] or not isinstance(want.get("expires_at"), str)
                or not isinstance(cols_in or [], list)):
            raise HTTPException(status_code=400, detail="a job grant's step-up carries the "
                                "grant's body (job, expires_at, collections), so Origin's page "
                                "can show what is granted")
        reach_in = want.get("reach")
        if reach_in:
            if not isinstance(reach_in, list):
                raise HTTPException(status_code=400, detail="reach is a list of ids")
            # A timer's grant (John, 2026-11-10): it acts as the person within what it names.
            if str(want.get("job") or "").startswith("lumen.run."):
                # A workflow's one run, now (John, 2026-11-10).
                return _fit_job_grant(f"run a workflow once ({want['job']}), until "
                                      f"{want['expires_at']}, reading, writing and running as you, in",
                                      [str(r) for r in reach_in], joiner=" ", unit="item")
            return _fit_job_grant(f"let the timer {want['job']} until {want['expires_at']} read, "
                                  f"write and run as you, in", [str(r) for r in reach_in],
                                  joiner=" ", unit="item")
        whose = f" {want['principal']}" if want.get("principal") else ""
        return _fit_job_grant(f"let the background job {want['job']} until "
                              f"{want['expires_at']} open your key{whose}",
                              [str(c) for c in (cols_in or [])])
    return "add a passkey"


#: The longest action a confirm page names (`PersonStepUp.describe` is 256 characters).
DESCRIBE_MAX = 250


def _fit_job_grant(head: str, cols: list, *, joiner: str = " and ",
                   unit: str = "collection") -> str:
    """The job grant's action, its expiry and principal first, then as many collections (a
    timer's: the items it reaches) as fit and "and N more" for the rest. One that cannot be named
    whole is refused: the confirm page never shows a cut-off grant."""
    if not cols:
        text = f"{head}{joiner}no {unit}"
        if len(text) > DESCRIBE_MAX:
            raise HTTPException(status_code=400, detail="this job grant is too long for Origin's "
                                "page to name; shorten its job or principal")
        return text
    for shown in range(len(cols), -1, -1):
        rest = len(cols) - shown
        named = ", ".join(cols[:shown])
        tail = (f" and {rest} more" if rest else "")
        text = (f"{head}{joiner}{named}{tail}" if shown else f"{head}{joiner}{rest} {unit}"
                f"{'s' if rest != 1 else ''}")
        if len(text) <= DESCRIBE_MAX:
            return text
    raise HTTPException(status_code=400, detail="this job grant is too long for Origin's page "
                        "to name; shorten its job or principal")


def _describe_job_grant_revoke(path: str, person_id: Optional[str]) -> str:
    """A revoke's page names the grant it stops, from Origin's own record of the person's own job
    grants (`authority_ledger.person_job_grants`): a grant of anyone else's is named by id alone."""
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger

    grant_id = path[len("/auth/me/job-grants/"):].split("/", 1)[0].split("?", 1)[0]
    job = None
    if person_id:
        with SessionLocal() as db:
            job = next((g.get("job") for g in authority_ledger.person_job_grants(db, person_id)
                        if g.get("grant_id") == grant_id), None)
    if not job:
        # Not one of theirs: named by its id alone, and the revoke itself then finds nothing.
        return f"stop the background job grant {grant_id}"[:250]
    return f"stop the background job {job}'s grant {grant_id}"[:250]


def options(db: Session, person_id: str, method: str, path: str, body_sha256: str, *,
            body: Optional[str] = None, session_person: Optional[str] = None,
            session_sha256: Optional[str] = None) -> dict:
    """The step-up for one request: a passkey challenge, or a re-authentication ticket. A ticket
    is started only in the person's own Origin session (`session_person`)."""
    if body is not None:
        body_sha256 = hashlib.sha256(body.encode("utf-8")).hexdigest()
    body_hash = (body_sha256 or "").lower()
    if len(body_hash) != 64 or any(ch not in "0123456789abcdef" for ch in body_hash):
        raise HTTPException(status_code=400, detail="body_sha256 is the hex SHA-256 of the body")
    if not isinstance(method, str) or not isinstance(path, str) or not path.startswith(PATHS):
        raise HTTPException(status_code=400, detail="a step-up is for a sign-in method or "
                            "passkey change")
    # The operator's passkeys change only through the operator console: a person's step-up is
    # never issued for them (review 11).
    from origin.services.platform_settings_service import settings as _platform
    if path.startswith("/auth/passkey/") and str(_platform.get("platform.operator_id") or "") \
            == str(person_id):
        raise HTTPException(status_code=403, detail="the operator's passkeys change only through "
                            "the operator console")
    digest = hashlib.sha256(f"{method.upper()}\n{path}\n{body_hash}".encode("utf-8")).digest()
    creds = db_passkeys.list_for_person(db, person_id)
    if creds:
        opts = generate_authentication_options(
            rp_id=passkey_service._get_rp_id(),
            challenge=digest + secrets.token_bytes(32),
            allow_credentials=[PublicKeyCredentialDescriptor(
                id=passkey_service._b64url_decode(c.id), transports=list(c.transports or []))
                for c in creds],
            user_verification=UserVerificationRequirement.REQUIRED,
            timeout=60000,
        )
        encoded = passkey_service._serialize_authentication_options(opts)
        db_challenges.create(db, challenge=encoded["challenge"], purpose=_PURPOSE,
                             person_id=person_id, ttl_seconds=_CHALLENGE_TTL_SECONDS)
        db.commit()
        # The page shows this before it asks for the passkey (review 10, R10).
        try:
            action = _describe(method.upper(), path, body, str(person_id))
        except HTTPException:
            # A job grant is always named (its body, or the person's own grant it stops).
            if path.startswith("/auth/me/job-grants"):
                raise
            action = "change how you sign in"
        return {"kind": "passkey", "options": encoded, "action": action}
    if session_person is None or session_person != str(person_id):
        raise HTTPException(status_code=403, detail="a re-authentication is started only on "
                            "Origin's own page, in your Origin session")
    ticket = secrets.token_urlsafe(32)
    db.add(PersonStepUp(ticket=ticket, person_id=str(person_id), digest=digest.hex(),
                        verifier=secrets.token_urlsafe(48), csrf=secrets.token_urlsafe(24),
                        describe=_describe(method, path, body, str(person_id)), session_sha256=session_sha256))
    db.commit()
    return {"kind": "reauth", "ticket": ticket,
            "url": f"{_base()}/auth/reauth/start?{urlencode({'ticket': ticket})}"}


def _live(db: Session, ticket: str) -> Optional[PersonStepUp]:
    row = db.get(PersonStepUp, ticket) if ticket else None
    if row is None or row.spent_time is not None:
        return None
    if _now() - _aware(row.created_time) > timedelta(minutes=TICKET_MINUTES):
        return None
    return row


def code_challenge(ticket: str) -> Optional[str]:
    """The S256 PKCE challenge of the sign-in that proves `ticket`."""
    from origin.db.session import SessionLocal

    with SessionLocal() as db:
        row = db.get(PersonStepUp, ticket)
        return _s256(row.verifier) if row is not None else None


def _s256(verifier: str) -> str:
    return _b64(hashlib.sha256(verifier.encode("ascii")).digest())


def start_page(db: Session, ticket: str) -> str:
    """The start page: the exact action, and a confirm. Nothing is signed in from here until the
    person confirms."""
    import html
    row = _live(db, ticket)
    if row is None or row.proven_time is not None:
        raise HTTPException(status_code=404, detail="this confirmation link has expired")
    return ("<!doctype html><meta charset=utf-8><title>Confirm</title>"
            "<h1>Confirm this change to how you sign in</h1>"
            f"<p>You are asked to <strong>{html.escape(row.describe)}</strong>.</p>"
            "<p>If you did not ask for this on Origin's own page, close this page.</p>"
            '<form method="post" action="/auth/reauth/start">'
            f'<input type="hidden" name="ticket" value="{html.escape(row.ticket)}">'
            f'<input type="hidden" name="csrf" value="{html.escape(row.csrf or "")}">'
            "<button type=submit>Confirm, and sign in again</button></form>")


def confirm(db: Session, ticket: str, csrf: str) -> str:
    """The person confirmed the action on the start page: on to the sign-in."""
    row = _live(db, ticket)
    if (row is None or row.proven_time is not None or not row.csrf
            or not hmac.compare_digest(str(csrf or ""), row.csrf)):
        raise HTTPException(status_code=403, detail="this confirmation is not valid")
    row.confirmed_time = _now()
    db.commit()
    return start_location(db, ticket)


def start_location(db: Session, ticket: str) -> str:
    """Where a confirmed ticket sends the person: Origin's own sign-in, for Origin's own client,
    returning to `/auth/reauth/complete`."""
    row = _live(db, ticket)
    if row is None or row.proven_time is not None or row.confirmed_time is None:
        raise HTTPException(status_code=404, detail="this confirmation link has expired")
    q = {"response_type": "code", "client_id": getattr(config, "PLATFORM_CLIENT_ID", "platform"),
         "redirect_uri": complete_uri(), "state": ticket, "scope": "openid email profile",
         "code_challenge": _s256(row.verifier), "code_challenge_method": "S256",
         # A sign-in, never a session read: the provider is asked for a fresh one.
         "prompt": "login", "max_age": "0"}
    return f"{_base()}/auth/authorize?{urlencode(q)}"


def complete(db: Session, ticket: str, code: str, codes: dict, ttl: timedelta, *,
             session_sha256: Optional[str] = None) -> PersonStepUp:
    """Prove `ticket` with the sign-in code Origin minted for it, consumed here. 403 unless the
    identity that signed in is one the ticket's person already holds."""
    from origin.services import person_service

    row = _live(db, ticket)
    # Completed only in the browser whose Origin session started it (review 11): a link to this
    # page followed anywhere else proves nothing.
    if row is not None and (not row.session_sha256 or not session_sha256
                            or not hmac.compare_digest(row.session_sha256, session_sha256)):
        raise HTTPException(status_code=403, detail="finish this in the browser where you asked "
                            "for it, signed in at Origin")
    data = codes.pop(code, None) if code else None
    if data is None or row is None or row.proven_time is not None or row.confirmed_time is None:
        raise HTTPException(status_code=400, detail="this confirmation has expired")
    if (data.get("redirect_uri") != complete_uri()
            or data.get("client_id") != getattr(config, "PLATFORM_CLIENT_ID", "platform")
            or data.get("code_challenge_method") != "S256"
            or not hmac.compare_digest(str(data.get("code_challenge") or ""),
                                       _s256(row.verifier))
            or _now() - _aware(data["timestamp"]) > ttl):
        raise HTTPException(status_code=400, detail="this sign-in was not for this confirmation")
    # Fresh: a sign-in the provider dates before this ticket was issued rode an open session.
    # A sign-in that does not say when it happened proves nothing: it may have ridden an open
    # session at the provider. Origin's own methods always say.
    when = data.get("auth_time")
    try:
        signed_in = datetime.fromtimestamp(float(when), timezone.utc) if when is not None \
            else None
    except (TypeError, ValueError, OverflowError):
        signed_in = None
    if signed_in is None or signed_in < _aware(row.created_time) - timedelta(seconds=5):
        raise HTTPException(status_code=400, detail="this sign-in was not fresh (it did not "
                            "say when it happened, or happened before this confirmation); "
                            "sign in again to confirm")
    info = data.get("user_info") or {}
    who = person_service.get_user_by_oidc_identity(db, info.get("provider") or "",
                                                   str(info.get("sub") or ""))
    if who is None or str(who.id) != row.person_id:
        logger.warning("re-authentication for %s refused: signed in as %s", row.person_id,
                       getattr(who, "id", None))
        raise HTTPException(status_code=403, detail="that sign-in is not one of this account's")
    row.proven_time = _now()
    db.commit()
    return row


async def require(request: Request, db: Session, person_id: str) -> None:
    """This request carries `person_id`'s own Origin session and a fresh step-up by them, bound
    to it; it is spent. Else 403."""
    from origin.services import origin_session
    origin_session.require(request, db, person_id)
    body = await request.body()
    query = f"?{request.url.query}" if request.url.query else ""
    digest = request_digest(request.method, request.url.path + query, body)
    header = request.headers.get(HEADER, "").strip()
    has_passkey = bool(db_passkeys.list_for_person(db, person_id))
    if header.startswith("reauth:"):
        if has_passkey:
            raise HTTPException(status_code=403, detail="a person with a passkey steps up with it")
        row = _live(db, header[len("reauth:"):])
        if (row is None or row.person_id != str(person_id) or row.proven_time is None
                or _now() - _aware(row.proven_time) > timedelta(minutes=PROVEN_MINUTES)
                or not hmac.compare_digest(row.digest, digest.hex())):
            raise HTTPException(status_code=403, detail="the re-authentication was not for this "
                                "request, or has lapsed")
        spent = db.execute(update(PersonStepUp).where(
            PersonStepUp.ticket == row.ticket, PersonStepUp.spent_time.is_(None))
            .values(spent_time=_now()))
        db.commit()
        if spent.rowcount != 1:
            raise HTTPException(status_code=403, detail="the re-authentication is spent")
        return
    try:
        step = json.loads(_unb64(header))
        challenge, credential = str(step["challenge"]), step["credential"]
        bound = _unb64(challenge)[:32]
    except (ValueError, KeyError, TypeError, binascii.Error):
        raise HTTPException(status_code=403, detail=f"a fresh step-up is required ({HEADER}): "
                            "ask POST /auth/me/step-up-options")
    if not hmac.compare_digest(bound, digest):
        raise HTTPException(status_code=403, detail="the step-up was for another request")
    try:
        who = passkey_service.verify_authentication(db, credential, challenge, purpose=_PURPOSE,
                                                    require_user_verification=True)
    except Exception as exc:  # noqa: BLE001 — a malformed credential is a failed step-up
        logger.warning("person step-up rejected: %s", exc)
        who = None
    db.commit()
    if who is None or str(who) != str(person_id):
        raise HTTPException(status_code=403, detail="the step-up failed")

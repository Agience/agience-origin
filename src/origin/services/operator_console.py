"""The operator console: Origin-only sign-in, and a fresh passkey for every operator action.

The `/oracle/*` routes hold the platform's most sensitive powers: background authority over
custody, seed and bootstrap credentials, revoking delegations, the vault, verifying the ledger.
They accept exactly one kind of caller:

* A console token. Origin mints it only here, after a passkey sign-in by the platform operator.
  Its audience is `CONSOLE_AUDIENCE`, which no other token Origin mints carries and no other
  service accepts, and it carries `token_type`, so Origin's ordinary authentication
  (`resolve_auth`) refuses it on every other route. Mantle never receives it: Mantle checks that a
  person token is addressed to the authority itself, and this one is not.
* A fresh passkey assertion for each call, bound to that request. The step-up challenge is the
  digest of the request (method, path, body digest) followed by random bytes, so the
  authenticator signs over the request it authorizes. The challenge is single-use and short-lived
  (`passkey_challenges`), and the guard recomputes the digest from the request it receives: an
  assertion for one call does not authorize another, nor the same call twice.

User verification is required for both ceremonies: the operator proves presence and identity each
time, not just possession of a device.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session
from webauthn import generate_authentication_options
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement

from origin import config
from origin.db import passkey_challenges as db_challenges
from origin.db import passkey_credentials as db_passkeys
from origin.services import passkey_service

logger = logging.getLogger(__name__)

#: The audience of a console token. No other token carries it, and no other service accepts it.
CONSOLE_AUDIENCE = "origin-operator-console"
#: The `token_type` of a console token: `resolve_auth` refuses any token that carries one.
CONSOLE_TOKEN_TYPE = "operator_console"
#: A console sign-in lasts a quarter of an hour; each action still needs its own passkey.
CONSOLE_TTL_HOURS = 0.25
#: The request header that carries the step-up: base64url of `{"challenge", "credential"}`.
STEP_UP_HEADER = "X-Operator-Step-Up"

#: The paths an operator step-up may be asked for: the console's own routes, the operator's
#: passkeys, and server credentials (`/auth/clients`), which take the console too.
STEP_UP_PATHS = ("/oracle/", "/auth/passkey/", "/auth/clients")

_SIGN_IN_PURPOSE = "console"
_STEP_UP_PURPOSE = "operator"
_CHALLENGE_TTL_SECONDS = 120


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def request_digest(method: str, path: str, body: bytes) -> bytes:
    """What a step-up authorizes: this method, on this path and query (`path?query`), with this
    body."""
    body_hash = hashlib.sha256(body or b"").hexdigest()
    return hashlib.sha256(f"{method.upper()}\n{path}\n{body_hash}".encode("utf-8")).digest()


def _options(db: Session, operator_id: str, purpose: str, challenge: bytes) -> dict:
    creds = db_passkeys.list_for_person(db, operator_id)
    if not creds:
        raise HTTPException(status_code=409, detail="the operator has no passkey; register one "
                                                    "before using the operator console")
    options = generate_authentication_options(
        rp_id=passkey_service._get_rp_id(),
        challenge=challenge,
        allow_credentials=[PublicKeyCredentialDescriptor(
            id=passkey_service._b64url_decode(c.id), transports=list(c.transports or []))
            for c in creds],
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=60000,
    )
    encoded = passkey_service._serialize_authentication_options(options)
    db_challenges.create(db, challenge=encoded["challenge"], purpose=purpose,
                         person_id=operator_id, ttl_seconds=_CHALLENGE_TTL_SECONDS)
    db.commit()
    return encoded


def sign_in_options(db: Session, operator_id: str) -> dict:
    return _options(db, operator_id, _SIGN_IN_PURPOSE, secrets.token_bytes(64))


def sign_in(db: Session, operator_id: str, credential: dict, challenge: str) -> dict:
    """A console token for the operator, after a verified passkey assertion."""
    from origin.services.auth_service import create_jwt_token

    who = passkey_service.verify_authentication(db, credential, challenge,
                                                purpose=_SIGN_IN_PURPOSE,
                                                require_user_verification=True)
    db.commit()
    if who is None or str(who) != str(operator_id):
        raise HTTPException(status_code=401, detail="operator console sign-in failed")
    token = create_jwt_token({"sub": str(operator_id), "aud": CONSOLE_AUDIENCE,
                              "token_type": CONSOLE_TOKEN_TYPE, "jti": secrets.token_hex(16)},
                             expires_hours=CONSOLE_TTL_HOURS)
    return {"token": token, "expires_in": int(CONSOLE_TTL_HOURS * 3600)}


def console_subject(token: str, operator_id: Optional[str]) -> str:
    """The operator a console token names, or 403. Any other token is refused."""
    from origin.services.auth_verifier import verify_token

    claims = verify_token(token or "", expected_audience=CONSOLE_AUDIENCE) or {}
    if (claims.get("aud") != CONSOLE_AUDIENCE or claims.get("token_type") != CONSOLE_TOKEN_TYPE
            or claims.get("iss") != config.AUTHORITY_ISSUER or not claims.get("sub")
            or float(claims.get("exp") or 0) <= datetime.now(timezone.utc).timestamp()):
        raise HTTPException(status_code=403, detail="operator console token required")
    if not operator_id or str(claims["sub"]) != str(operator_id):
        raise HTTPException(status_code=403, detail="operator only")
    return str(claims["sub"])


def _bearer(request) -> str:
    header = request.headers.get("authorization", "")
    return header[7:].strip() if header[:7].lower() == "bearer " else ""


def get_console_auth(request: Request) -> str:
    """Authentication for the operator console's routes: the operator a valid console token
    names, recomputed now from `platform.operator_id`; otherwise 403. This is the only
    authenticator `/oracle/*` takes: an ordinary access token is refused there by design."""
    from origin.services.platform_settings_service import settings as platform_settings

    op = platform_settings.get("platform.operator_id")
    try:
        return console_subject(_bearer(request), str(op) if op else None)
    except HTTPException as exc:
        logger.warning("oracle access refused on %s %s: %s", request.method, request.url.path,
                       exc.detail)
        raise


#: The header carrying the console token on a route whose bearer is an ordinary access token
#: (passkey management on the operator's own account).
CONSOLE_HEADER = "X-Operator-Console"
#: The header carrying a one-time operator enrolment code.
ENROLMENT_HEADER = "X-Operator-Enrolment-Code"
ENROLMENT_MINUTES = 15


def issue_enrolment_code(db: Session, operator_id: str) -> str:
    """A one-time code for the operator's first passkey, for the local CLI only. Earlier unused
    codes are spent: one is live at a time."""
    import secrets as _secrets
    from datetime import timedelta

    from origin.models.key_custody import OperatorEnrolmentCode

    now = datetime.now(timezone.utc)
    for row in db.query(OperatorEnrolmentCode).filter(OperatorEnrolmentCode.used_at.is_(None)):
        row.used_at = now
    code = _secrets.token_urlsafe(24)
    db.add(OperatorEnrolmentCode(code_sha256=hashlib.sha256(code.encode()).hexdigest(),
                                 operator_id=str(operator_id), created_time=now,
                                 expires_at=now + timedelta(minutes=ENROLMENT_MINUTES)))
    db.commit()
    return code


def _enrolment_code_ok(db: Session, operator_id: str, code: str, *, spend: bool) -> bool:
    from origin.models.key_custody import OperatorEnrolmentCode

    if not code:
        return False
    row = db.get(OperatorEnrolmentCode, hashlib.sha256(code.encode()).hexdigest())
    now = datetime.now(timezone.utc)
    exp = row.expires_at if row is not None and row.expires_at.tzinfo else (
        row.expires_at.replace(tzinfo=timezone.utc) if row is not None else None)
    if row is None or row.used_at is not None or exp <= now or row.operator_id != str(operator_id):
        return False
    if spend:
        row.used_at = now
        db.flush()
    return True


def require_operator_account_change(request: Request, db: Session, operator_id: str,
                                    body: bytes, *, enrolling: bool, final: bool) -> None:
    """Passkey management on the operator's own account: a console step-up with an existing
    operator passkey, bound to this request, or, to enrol the first one, the one-time enrolment
    code (spent when the enrolment completes, `final`). Otherwise 403."""
    from origin.db import passkey_credentials as db_passkeys

    console = request.headers.get(CONSOLE_HEADER, "").strip()
    if console:
        console_subject(console, operator_id)
        query = f"?{request.url.query}" if request.url.query else ""
        verify_step_up(db, operator_id, request.headers.get(STEP_UP_HEADER, ""),
                       request.method, request.url.path + query, body)
        return
    code = request.headers.get(ENROLMENT_HEADER, "").strip()
    if enrolling and not db_passkeys.list_for_person(db, operator_id) and _enrolment_code_ok(
            db, operator_id, code, spend=final):
        return
    raise HTTPException(status_code=403, detail="the operator's passkeys change only through the "
                        "operator console with a passkey step-up, or, for the first, with an "
                        "enrolment code from Origin's host")


def step_up_options(db: Session, operator_id: str, method: str, path: str,
                    body_sha256: str) -> dict:
    """A step-up challenge for one request: its digest, then random bytes."""
    body_hash = (body_sha256 or "").lower()
    if len(body_hash) != 64 or any(ch not in "0123456789abcdef" for ch in body_hash):
        raise HTTPException(status_code=400, detail="body_sha256 is the hex SHA-256 of the body")
    digest = hashlib.sha256(f"{method.upper()}\n{path}\n{body_hash}".encode("utf-8")).digest()
    return _options(db, operator_id, _STEP_UP_PURPOSE, digest + secrets.token_bytes(32))


def verify_step_up(db: Session, operator_id: str, header: str, method: str, path: str,
                   body: bytes) -> None:
    """The step-up on this request is a fresh passkey assertion by the operator, over a challenge
    bound to this very request. Otherwise 403."""
    try:
        step = json.loads(_unb64(header or ""))
        challenge, credential = str(step["challenge"]), step["credential"]
        bound = _unb64(challenge)[:32]
    except (ValueError, KeyError, TypeError, binascii.Error):
        raise HTTPException(status_code=403, detail="a passkey step-up is required for this "
                                                    f"action ({STEP_UP_HEADER})")
    if not hmac.compare_digest(bound, request_digest(method, path, body)):
        raise HTTPException(status_code=403, detail="the passkey step-up was for another request")
    try:
        who = passkey_service.verify_authentication(db, credential, challenge,
                                                    purpose=_STEP_UP_PURPOSE,
                                                    require_user_verification=True)
    except Exception as exc:                    # a malformed credential is a failed step-up
        logger.warning("operator step-up rejected: %s", exc)
        who = None
    db.commit()
    if who is None or str(who) != str(operator_id):
        raise HTTPException(status_code=403, detail="the passkey step-up failed")

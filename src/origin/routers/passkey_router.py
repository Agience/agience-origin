"""Origin passkey router — WebAuthn registration + authentication.

Backed by `origin.services.passkey_service`.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from origin import config
from origin.db import persons as db_persons
from origin.db.session import get_db
from origin.services import passkey_service
from origin.services.auth_service import create_jwt_token
from origin.services.dependencies import AuthContext, get_auth

logger = logging.getLogger(__name__)
passkey_router = APIRouter(prefix="/auth/passkey", tags=["Authentication"])


class RegisterOptionsResponse(BaseModel):
    options: dict


class RegisterCompleteRequest(BaseModel):
    credential: dict
    device_name: Optional[str] = None
    challenge: str


class RegisterCompleteResponse(BaseModel):
    credential_id: str
    device_name: Optional[str] = None


class LoginOptionsRequest(BaseModel):
    email: str


class LoginOptionsResponse(BaseModel):
    options: Optional[dict] = None
    has_passkeys: bool = False


class LoginCompleteRequest(BaseModel):
    credential: dict
    # `challenge` is a lookup key into the server's issued-challenge table, not the value the
    # server trusts. The expected challenge and the expected user both come from the stored row.
    # `user_id` is deliberately absent: accepting it from the caller would let the caller name
    # both sides of the check instead of just presenting a credential for the server to verify.
    challenge: str


class LoginCompleteResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class CredentialListResponse(BaseModel):
    credentials: list[dict]


def _require_interactive_user(auth: AuthContext) -> str:
    """The caller must be a real, directly-authenticated user — not a machine acting as one.

    `auth.user_id` alone is not enough to gate on: `resolve_auth` populates `user_id` from `sub`
    for an `mcp_client` token, and normalizes a delegation to `principal_type="user"` with
    `actor=act.sub`. Gating on `user_id` alone would let any third-party MCP app the user
    authorized — or any server holding a delegation for them — call:
      • `DELETE /auth/passkey/credentials/{id}` — remove the victim's passkeys, and
      • `POST register-options` + `register-complete` — enrol its own authenticator on the
        victim's account, a permanent backdoor that survives the OAuth grant being revoked, since
        revocation cannot undo a credential that now belongs to the attacker.
    Registering an authentication factor is the last thing that should be reachable by a delegated
    machine token: it is precisely the operation that outlives the delegation.

    Same guard, same two conditions, as `system_router._platform_admin_user_id`:
      • `principal_type == "user"` rejects mcp_client / service / server.
      • `actor is None` rejects delegation, which presents as `principal_type="user"`, so the
        first condition alone does not catch it.
    """
    if auth.principal_type != "user" or auth.actor is not None or not auth.user_id:
        raise HTTPException(
            status_code=403,
            detail="passkey management requires a directly-authenticated user session",
        )
    return auth.user_id


# ---------------------------------------------------------------------------
# Registration (requires auth)
# ---------------------------------------------------------------------------
@passkey_router.post("/register-options", response_model=RegisterOptionsResponse)
async def get_register_options(
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
):
    _require_interactive_user(auth)
    person = db_persons.get_by_id(db, auth.user_id)
    if person is None:
        raise HTTPException(status_code=404, detail="User not found")
    options = passkey_service.get_registration_options(db, str(person.id), person.email or "")
    return RegisterOptionsResponse(options=options)


@passkey_router.post("/register-complete", response_model=RegisterCompleteResponse)
async def complete_registration(
    body: RegisterCompleteRequest,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
):
    _require_interactive_user(auth)
    try:
        result = passkey_service.verify_registration(
            db=db,
            user_id=auth.user_id,
            credential=body.credential,
            challenge=body.challenge,
            device_name=body.device_name,
        )
    except ValueError as exc:
        db.commit()  # keep the challenge consumed
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    return RegisterCompleteResponse(**result)


# ---------------------------------------------------------------------------
# Authentication (no auth required)
# ---------------------------------------------------------------------------
@passkey_router.post("/login-options", response_model=LoginOptionsResponse)
async def get_login_options(
    body: LoginOptionsRequest,
    db: Session = Depends(get_db),
):
    """Issue a WebAuthn login challenge — for an address with passkeys, and for one without.

    This route answers the same shape for every email. A `{"has_passkeys": false}` for an address
    with no credentials and no account would make an unauthenticated POST a yes/no membership test
    against the whole user table, and two siblings settle that policy the same way as this one —
    `otp_router.request_otp` returns `{"sent": true}` for an unknown address and logs rather than
    tells, and `/auth/email/verify-request` always answers `{"sent": true}`.

    Those two return a constant, which costs nothing. The honest response here carries
    `allowCredentials`, the account's real credential ids, so matching them requires
    `get_decoy_authentication_options` to fabricate that list — stable per email, unpredictable
    without the server key — rather than to omit it. `has_passkeys` stays in the response and is
    always `true`: removing the field breaks the shape for a client reading it, and a field that is
    always true tells a caller nothing.

    A client cannot tell the two paths apart from the response, and the ceremony fails the same way
    for both — see `get_decoy_authentication_options` for what remains distinguishable.
    """
    options = (
        passkey_service.get_authentication_options(db, body.email)
        if passkey_service.has_passkeys(db, body.email)
        else passkey_service.get_decoy_authentication_options(body.email)
    )
    if options is None:
        # Only reachable with no server key to derive decoys from — a node that cannot answer
        # uniformly. Refuse rather than fall back to the shape that leaked.
        raise HTTPException(status_code=503, detail="Passkey login is unavailable")
    # The real branch wrote a challenge row; nothing above commits.
    db.commit()
    return LoginOptionsResponse(options=options, has_passkeys=True)


@passkey_router.post("/login-complete", response_model=LoginCompleteResponse)
async def complete_login(
    body: LoginCompleteRequest,
    db: Session = Depends(get_db),
):
    person_id = passkey_service.verify_authentication(
        db=db,
        credential=body.credential,
        challenge=body.challenge,
    )
    if not person_id:
        # The challenge is consumed even on failure (consume() marks it used
        # before crypto runs), so a failed attempt cannot be retried either.
        db.commit()
        raise HTTPException(status_code=401, detail="Passkey authentication failed")

    person = db_persons.get_by_id(db, person_id)
    if person is None:
        raise HTTPException(status_code=401, detail="User not found")

    user_data = {
        "sub": str(person.id),
        "email": person.email or "",
        "name": person.name or "",
        "picture": person.picture or "",
        "client_id": getattr(config, "PLATFORM_CLIENT_ID", "platform"),
        "aud": config.AUTHORITY_ISSUER,
    }
    access_token = create_jwt_token(user_data)
    refresh_token = create_jwt_token({**user_data, "token_type": "refresh"}, expires_hours=24 * 30)
    db.commit()
    return LoginCompleteResponse(access_token=access_token, refresh_token=refresh_token)


# ---------------------------------------------------------------------------
# Management (requires auth)
# ---------------------------------------------------------------------------
@passkey_router.get("/credentials", response_model=CredentialListResponse)
async def list_passkeys(
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
):
    _require_interactive_user(auth)
    creds = passkey_service.list_credentials(db, auth.user_id)
    return CredentialListResponse(credentials=creds)


@passkey_router.delete("/credentials/{credential_id}")
async def delete_passkey(
    credential_id: str,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
):
    _require_interactive_user(auth)
    deleted = passkey_service.delete_credential(db, auth.user_id, credential_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Credential not found")
    db.commit()
    return {"deleted": True}

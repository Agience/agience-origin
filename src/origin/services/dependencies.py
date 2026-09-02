"""Origin's auth dependency layer — identity only.

Origin is the identity authority: it resolves who a caller is (user, platform
service, delegation, mcp_client, server) from a signed JWT. It performs no
authorization, so it neither verifies API keys nor resolves grants. `AuthContext`
carries grant and key fields for the resource servers that consume the same shape;
in Origin nothing populates them.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import OAuth2AuthorizationCodeBearer
from sqlalchemy.orm import Session

from origin import config
from origin.db.session import get_db
from origin.models.person import Person as PersonModel
from origin.services import person_service
from origin.services.auth_verifier import verify_token

logger = logging.getLogger(__name__)


@dataclass
class AuthContext:
    """Unified auth context.

    The grant and key fields (`grants`, `api_key_id`, `api_key_entity`,
    `bearer_grant`) are part of the shape resource servers share, and are never
    populated in Origin — Origin does no authorization."""

    principal_id: str = ""
    principal_type: str = "user"            # user | service | mcp_client | delegation | server
    user_id: Optional[str] = None
    grants: List = field(default_factory=list)
    api_key_id: Optional[str] = None
    api_key_entity: Optional[object] = None
    server_id: Optional[str] = None
    actor: Optional[str] = None
    authority: Optional[str] = None
    host_id: Optional[str] = None
    bearer_grant: Optional[object] = None
    target_artifact_id: Optional[str] = None


oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="/auth/authorize",
    tokenUrl="/auth/token",
)


def _is_api_key_jwt(payload: Optional[dict]) -> bool:
    return bool(payload and payload.get("api_key_id"))


def _validate_aud_for_principal(payload: dict) -> None:
    principal_type = payload.get("principal_type", "user")
    aud = payload.get("aud")
    if principal_type == "service":
        # Platform mutual JWT: platform callers sign their own tokens with `aud="origin"`
        # when calling into Origin.
        if aud != "origin":
            raise HTTPException(status_code=401, detail="Invalid token audience for platform service")
    elif principal_type == "server":
        if aud != "agience":
            raise HTTPException(status_code=401, detail="Invalid token audience for server credential")
    elif principal_type == "mcp_client":
        if not aud:
            raise HTTPException(status_code=401, detail="Missing aud in mcp_client token")
    elif principal_type == "delegation":
        if not aud:
            raise HTTPException(status_code=401, detail="Missing aud in delegation token")
    else:
        if aud != config.AUTHORITY_ISSUER:
            raise HTTPException(status_code=401, detail="Invalid token audience")


def resolve_auth(token: str, db: Session, request: Optional[Request] = None) -> AuthContext:
    """Origin's token dispatch — SQLite-backed.

    Resolves against Origin's own tables.
    """
    if not token:
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    raw_token = token.strip()

    # Origin authenticates by signed JWT only. API keys (`agc_`) and bearer grant
    # keys are the resource server's concern — Origin neither verifies
    # nor resolves them. Such a token simply fails identity resolution below → 401.

    payload = verify_token(raw_token)
    if payload and "sub" in payload:
        # A token carrying `token_type` is not an access token. `token_type` is stamped at mint
        # time on every special-purpose token Origin issues, and never on an access token:
        # `create_jwt_token(user_data)` mints one with no `token_type` claim, while
        # refresh/email_verify/pwd_reset each add one. (`"token_type": "bearer"` elsewhere is an
        # OAuth *response* field sitting beside `access_token`, not a claim.)
        #
        # Each special-purpose token would be a dangerous Bearer session if accepted here:
        #
        #   * `email_verify` (24h) is lifted straight out of the `?token=` link in a verification
        #     email — accepting it would authenticate the user as themselves for a day before they
        #     had proven control of the mailbox, inverting the token's purpose.
        #   * `pwd_reset` (1h) — accepting it would make the reset link equivalent to a password.
        #   * `refresh` (30 days) carries identical claims to the access token plus this field, so
        #     accepting it would turn the long-lived refresh credential into a long-lived access
        #     credential — and, with no rotation and no revocation list, leave a compromised
        #     account unreachable by a password reset.
        #
        # The legitimate consumers of these tokens — `_grant_refresh_token` and the email-verify
        # endpoint — decode and check `token_type` themselves and never route through this
        # dependency.
        _tt = payload.get("token_type")
        if _tt:
            raise HTTPException(
                status_code=401,
                detail=f"a {_tt!r} token is not an access token; exchange it at its own endpoint")
        _validate_aud_for_principal(payload)
        if _is_api_key_jwt(payload):
            raise HTTPException(status_code=403, detail="API-key JWT not accepted; use direct API key")

        jwt_principal_type = payload.get("principal_type", "user")
        if jwt_principal_type == "service":
            # Platform mutual JWT — a peer service identifying itself to Origin.
            # `iss` carries the signer, the container holding the key (verified by
            # `verify_token`). Several personas can share one service key, so `iss`
            # alone cannot tell them apart — the acting persona rides in the
            # `client_id` claim. Surface it as `actor` so authz and audit can see
            # which one called; the principal stays the signing service, so
            # `_require_platform_server` is unaffected.
            return AuthContext(
                principal_id=str(payload.get("iss", "")),
                principal_type="service",
                actor=str(payload.get("client_id") or "") or None,
                authority=str(payload.get("iss", "")) or None,
            )
        if jwt_principal_type == "server":
            client_id = payload.get("client_id")
            return AuthContext(
                principal_id=str(client_id) if client_id else str(payload.get("sub", "")),
                principal_type="server",
                server_id=str(payload.get("server_id")) if payload.get("server_id") else None,
                authority=str(payload.get("authority", "")) or None,
                host_id=str(payload.get("host_id", "")) or None,
            )
        if jwt_principal_type == "mcp_client":
            return AuthContext(
                principal_id=str(payload.get("aud", "")),
                principal_type="mcp_client",
                user_id=str(payload.get("sub")) if payload.get("sub") else None,
            )
        if jwt_principal_type == "delegation":
            d_sub = payload.get("sub")
            d_act = (payload.get("act") or {}).get("sub")
            if not d_sub:
                raise HTTPException(status_code=401, detail="Delegation token missing sub")
            if not d_act:
                raise HTTPException(status_code=401, detail="Delegation token missing act.sub")
            return AuthContext(
                principal_id=str(d_sub),
                principal_type="user",
                user_id=str(d_sub),
                actor=str(d_act),
                authority=str(payload.get("iss", "")) or None,
                host_id=str(payload.get("host_id", "")) or None,
            )

        # Default: user JWT
        user_id = str(payload.get("sub")) if payload.get("sub") else None
        return AuthContext(
            principal_id=user_id or "",
            principal_type="user",
            user_id=user_id,
        )

    raise HTTPException(status_code=401, detail="Invalid token")


async def get_auth(
    token: str = Security(oauth2_scheme),
    db: Session = Depends(get_db),
    request: Request = None,
) -> AuthContext:
    auth = resolve_auth(token=token or "", db=db, request=request)
    if request is not None and auth.user_id:
        request.state.user_id = auth.user_id
    return auth


async def get_person(
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
) -> PersonModel:
    """Resolve the caller's own Person row — full end users only.

    Every route behind this dependency reads or writes the account itself: `/auth/userinfo` and
    `/auth/me/link-provider` return `_person_to_dict` (email, name, username, picture, preferences,
    linked external identities), and `/auth/me/preferences` + `link-provider` mutate it. So this is
    the choke point where "may this principal act as the account holder?" is answered, once, rather
    than five times in five handlers.

    A scoped `mcp_client` token carries a `user_id`. `resolve_auth` populates it from `sub`,
    because `sub` is what makes the token delegable at all — so the `user_id` check below admits a
    third-party client, and admitting it hands over exactly the PII the scoped token exists to
    withhold. The token is minted with no email, no name, no picture and no roles; letting its
    bearer read them back from `/auth/userinfo` would make that omission cosmetic. Hence the
    `principal_type` check, matching the guards in `system_router`, `oracle_router`,
    `passkey_router` and `server_credentials_router`.

    The token's `scopes` claim cannot stand in for this. It records what the client *asked for* at
    `/authorize` and nothing has vouched for the client — there is no consent step anywhere in this
    authority, so a client that registers itself and asks for `scope=openid email profile` would be
    licensing its own access to the mailbox. Gating on a value the caller chooses is not a gate.

    The OIDC-correct alternative — return the claims the granted scopes license, `sub` for `openid`,
    `email` for `email` — becomes available once a scope is something the *user* approves and the
    grant is recorded per client. At that point this refusal is what should relax, by consulting the
    recorded grant rather than the claim.

    Order matters: `user_id` is checked first so a `service` or `server` token, which carries none,
    keeps its existing 401 instead of being reclassified. A delegation is unaffected —
    `resolve_auth` normalizes it to `principal_type="user"`.
    """
    if not auth.user_id:
        raise HTTPException(status_code=401, detail="User identification required")
    if auth.principal_type != "user":
        raise HTTPException(
            status_code=403,
            detail=f"a {auth.principal_type!r} token may not read or modify the account it names; "
                   "this endpoint serves the authenticated end user only",
        )
    person = person_service.get_user_by_id(db, auth.user_id)
    if person is None:
        raise HTTPException(status_code=404, detail="User not found")
    return person

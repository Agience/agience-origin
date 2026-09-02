"""Origin's auth router — OAuth, password, refresh, client_credentials, /me.

First-party OAuth clients are named in config (`PLATFORM_CLIENT_ID` + `PLATFORM_CLIENT_IDS`);
every other `client_id` is third-party and receives a scoped, PII-free `mcp_client` token. No
cross-service call takes part in that decision.

Passkey and OTP sign-in live in their own routers (`passkey_router`, `otp_router`), not here.
"""

from __future__ import annotations

import base64
import hashlib
import html as _html
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode, urlparse

import bcrypt
from authlib.common.security import generate_token
from fastapi import (
    APIRouter, BackgroundTasks, Depends, Form, Header, HTTPException, Request, status,
)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from origin import config
from origin.db import oauth_clients as db_oauth_clients
from origin.db import person_identities as db_person_identities
from origin.db import persons as db_persons
from origin.db import server_credentials as db_server_credentials
from origin.db.session import get_db
from origin.models.oauth_client import OAuthClient
from origin.models.person import Person as PersonModel
from origin.services import email_service
from origin.services import guess_budget
from origin.services import otp_service
from origin.services import person_service
from origin.services import auth_service as origin_auth_service
from origin.services.auth_service import (
    access_token_expires_in_seconds,
    create_jwt_token,
    dummy_verify_password,
    email_verification_required,
    hash_password,
    is_client_redirect_allowed,
    verify_password,
)
from origin.services.auth_verifier import verify_token
from origin.services.dependencies import AuthContext, get_auth, get_person
from origin.services.oidc_providers import REGISTERED_PROVIDERS, oauth
from origin.services.platform_settings_service import settings as platform_settings

logger = logging.getLogger(__name__)
auth_router = APIRouter(prefix="/auth", tags=["Authentication"])
root_router = APIRouter(tags=["Authentication"])
internal_router = APIRouter(prefix="/internal", tags=["Internal"], include_in_schema=False)


# ---------------------------------------------------------------------------
# Internal endpoints (platform-server auth — used by Mantle/Chorus for cross-DB lookups)
# ---------------------------------------------------------------------------
#: The services whose tokens may reach the `/internal` routes. Verbatim the tuple
#: `auth_verifier.verify_token` dispatches on, and it has to stay that way: a name here that is
#: absent there never reaches this check (the token fails signature verification against Origin's
#: own key and 401s), and a name there that is absent here authenticates and is then refused. Both
#: directions fail closed, so drift costs a confusing error rather than access — but only one of
#: the two lists is the trust decision, and this is it.
#:
#: Not derived from `manifest.trust_anchors`, though the manifest is the obvious source. An anchor
#: answers "can I verify this signature", and the manifest also carries `origin` itself and is
#: merged additively by the installer on upgrade. Deriving from it would silently promote every
#: future anchor to a reader of every person's PII — authentication standing in for authorization,
#: which is the substitution this whole function exists to refuse.
_PLATFORM_SERVICES = frozenset({"mantle", "chorus", "crystal", "lumen"})


def _require_platform_server(auth: AuthContext) -> None:
    """The caller must be a service, and a service this authority named.

    Platform callers authenticate with mutual JWTs signed by their own service identity
    (`principal_type=service`). Both conditions below are load-bearing and the second is the one
    that matters: `principal_type` says only *that* the caller is a machine, never *which* machine,
    so on its own it would admit any principal this authority resolves as a service.

    `auth.principal_id` for a service IS the `iss` claim — `resolve_auth` populates it from
    `payload["iss"]` and from nothing else. That makes the check below an issuer check, and a
    signature-bound one rather than a caller-asserted one: `verify_token` routes a platform `iss`
    to `authority_trust.verify_jwt` with `expected_issuer_service=iss` AND
    `expected_issuer_claim=iss`, so the token must be signed by the private key whose public half
    is enrolled under that exact name in the authority manifest. Claiming someone else's name does
    not survive verification.

    The service token is unscoped, and this function answers only "is the caller a platform
    service". For `/internal/persons/{id}` the question that matters is "may this caller read
    person X", and the token cannot answer it: a platform service token carries `iss=sub=<service>`
    and no subject — it says which service is calling, and it can
    say nothing else"), so any enrolled platform service can read any person's email, name and
    identity records, with nothing in the request recording on whose behalf it asked.

    Narrowing the token is what scopes that read, and `/internal/delegation-token` below holds the
    shape: it refuses a bare `user_id` and requires the caller to present the user's own verified
    `subject_token`, so a service acts only for a user whose token it holds. `internal_get_person`
    takes the same credential, which reduces this function to proving the caller is a platform
    service at all while the subject token answers which person.

    A presented subject token is always honoured; its absence is refused only under
    `config.PERSON_LOOKUP_SUBJECT_TOKEN_REQUIRED`, off by default because a live caller has none to
    present. While it is off, this function is the whole of the decision for a caller that sends no
    subject token, and every such call is logged so an operator can see who is left.
    """
    if auth.principal_type != "service":
        raise HTTPException(status_code=403, detail="Platform service token required")
    if auth.principal_id not in _PLATFORM_SERVICES:
        raise HTTPException(status_code=403, detail="Caller is not a recognized platform service")


#: Token `principal_type`s that are not user identities. Two routes refuse them, for one reason:
#: "on behalf of a service" is not a statement about a person. `/internal/delegation-token` refuses
#: to exchange one (delegating for a non-person is meaningless and would reopen impersonation), and
#: `_verified_subject_id` refuses to read a person out of one — a service token presented as a
#: subject token would otherwise let a caller re-assert its own unscoped identity as authority over
#: whoever the path names, which is the exact substitution both routes exist to refuse.
_NON_USER_PRINCIPALS = {"service", "server", "delegation"}

#: Where a caller carries the subject's own token on `GET /internal/persons/{id}`.
#:
#: `/internal/delegation-token` carries the same credential as the `subject_token` field of a JSON
#: body; a GET has no body, so it travels as a header of that name instead. A header rather than a
#: query parameter, because this is a live user credential and query strings are written to access
#: logs, proxy history and browser referrers in a way headers are not.
_SUBJECT_TOKEN_HEADER = "X-Subject-Token"


def _verified_subject_id(subject_token: Optional[str]) -> Optional[str]:
    """The person a presented subject token names, or `None` if the caller presented none.

    The three refusals are `/internal/delegation-token`'s, in its order and with its statuses and
    wording — one credential verified one way, whichever route it arrives at. A caller that has
    learned to satisfy one has learned to satisfy the other, and a 403 it already handles does not
    change meaning depending on which endpoint returned it.

    Absence is not a refusal *here*: the caller decides whether a missing token is fatal, because
    that is the part configuration governs. Everything this function does do is unconditional.
    """
    if not subject_token:
        return None
    claims = verify_token(subject_token)
    if not claims:
        raise HTTPException(status_code=401, detail="Invalid or expired subject token")
    if claims.get("principal_type") in _NON_USER_PRINCIPALS:
        raise HTTPException(
            status_code=403,
            detail="subject_token must be a user token, not a service/delegation token",
        )
    subject_id = claims.get("sub")
    if not subject_id:
        raise HTTPException(status_code=400, detail="subject_token has no subject")
    return str(subject_id)


def _names_the_same_person(subject_id: str, person_id: str) -> bool:
    """Do these two ids resolve to one person row?

    `db.persons.get_by_id` looks up through `uuid.UUID(...)`, so `A1B2…` and `a1b2…` are the same
    row and a raw string comparison would refuse a caller whose token spells the id in the other
    case. Compare the way the lookup compares. When either side does not parse as a UUID the
    fallback is exact text: an id the lookup itself cannot resolve is not one to widen here.
    """
    a, b = subject_id.strip(), person_id.strip()
    try:
        return uuid.UUID(a) == uuid.UUID(b)
    except ValueError:
        return a == b


@internal_router.get("/persons/{person_id}")
def internal_get_person(
    person_id: str,
    subject_token: Optional[str] = Header(default=None, alias=_SUBJECT_TOKEN_HEADER),
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
):
    """Server-to-server person lookup — the call a peer's own person service makes, and the
    `_resolve_person_email` on the webhook mail path.

    Two credentials, two questions. The service JWT in `Authorization` says which platform service
    is asking, and `_require_platform_server` is the whole of that check — it is not weakened here.
    `X-Subject-Token` carries the subject's own Origin token and says on whose behalf; Origin
    verifies it and requires it to name the person in the path.

    The path id is checked against the token's `sub`, which is what the header buys. Holding a
    user's token is not authority over every user — Chorus is a gateway and holds user tokens as a
    matter of course — so a service presenting user A's token to read user B's record would be the
    unscoped read with an extra step.
    `/internal/delegation-token` needs no equivalent check because it has no second, caller-asserted
    subject to disagree with the verified one: it derives `sub` from the token and mints for that.
    This route does have one, in the path, so the same rule — the subject comes from the verified
    token — has to be spelled as an equality. A mismatch is 403, never a redirect to the token's own
    person: answering a different question than the one asked is how a caller ends up mailing A's
    address to B.

    `PERSON_LOOKUP_SUBJECT_TOKEN_REQUIRED` governs one thing: whether an ABSENT subject token is
    refused. Off (the default) the lookup proceeds on the service token alone, exactly as before,
    and logs. On, it is a 403. Nothing above depends on the flag — a presented token is verified,
    refused if it is not a live user token, and matched against the path on both settings — so a
    caller that starts sending one is held to the tighter rule the moment it ships, without waiting
    for the flip, and cannot weaken itself by sending one.
    """
    _require_platform_server(auth)

    subject_id = _verified_subject_id(subject_token)
    if subject_id is None:
        if config.PERSON_LOOKUP_SUBJECT_TOKEN_REQUIRED:
            raise HTTPException(
                status_code=403,
                detail=(
                    "Subject token required: present the subject's own token in the "
                    f"{_SUBJECT_TOKEN_HEADER} header"
                ),
            )
        # The audit line the flip is scheduled off. Logged on every such call rather than once per
        # caller per process: the question an operator asks before flipping is "is anyone STILL
        # calling this way", and a one-shot answers "did anyone ever", which stays true forever
        # after the caller is fixed. The volume is the cost of the gap being open and falls to zero
        # when the callers carry a token — which is the same event that makes the flip safe.
        logger.warning(
            "unscoped person lookup: caller=%s actor=%s person_id=%s (no %s presented; "
            "this call is unauthorized for the subject and will be refused once "
            "PERSON_LOOKUP_SUBJECT_TOKEN_REQUIRED is on)",
            auth.principal_id, auth.actor or "-", person_id, _SUBJECT_TOKEN_HEADER,
        )
    elif not _names_the_same_person(subject_id, person_id):
        # Before the lookup, so the refusal cannot double as an existence oracle for a person the
        # caller holds no token for.
        raise HTTPException(
            status_code=403, detail="subject_token does not name the requested person"
        )

    person = person_service.get_user_by_id(db, person_id)
    if person is None:
        raise HTTPException(status_code=404, detail="Person not found")
    return _person_to_dict(person)


class _DelegationTokenRequest(BaseModel):
    """Body for POST /internal/delegation-token.

    The requester supplies the user's own verified token (`subject_token`), not a bare `user_id`.
    Origin derives the subject from the verified token, so a platform service can only obtain a
    delegation for a user whose token it actually holds — it can never mint an arbitrary-user
    impersonation. The service authenticates separately (mutual JWT) so the chain records who
    exchanged, but the subject is never caller-asserted.
    """
    model_config = ConfigDict(extra="forbid")
    server_client_id: str
    subject_token: str
    ttl_seconds: int = 300


# `_NON_USER_PRINCIPALS` is defined above, beside `_verified_subject_id` — the two routes that
# refuse a non-user subject share one list.


@internal_router.post("/delegation-token")
def internal_issue_delegation_token(
    body: _DelegationTokenRequest,
    auth: AuthContext = Depends(get_auth),
):
    """Exchange a verified user token for a short-lived RFC 8693 delegation JWT.

    The gateway (Chorus persona) forwards the user's Origin-signed token; Origin verifies it,
    derives `sub` from the verified token, and mints the delegation (sub=user,
    aud=server_client_id, act.sub=server_client_id, principal_type=delegation, exp=300s). Origin
    owns the RSA signing key, so the service cannot issue these itself, and Origin never trusts a
    caller-supplied subject: a compromised service can only exchange tokens it already possesses,
    never fabricate a delegation for a user it has not authenticated.
    """
    _require_platform_server(auth)
    claims = verify_token(body.subject_token)
    if not claims:
        raise HTTPException(status_code=401, detail="Invalid or expired subject token")
    if claims.get("principal_type") in _NON_USER_PRINCIPALS:
        raise HTTPException(
            status_code=403,
            detail="subject_token must be a user token, not a service/delegation token",
        )
    user_id = claims.get("sub")
    if not user_id:
        raise HTTPException(status_code=400, detail="subject_token has no subject")
    token = origin_auth_service.issue_delegation_token(
        body.server_client_id, str(user_id), body.ttl_seconds
    )
    return {"token": token}


class _DescribeDelegationRequest(BaseModel):
    """Body for POST /internal/describe-delegation.

    The autonomous, event-driven describer (Crystal) has no forwarded user token — it reacts to a
    change-feed event. Rather than impersonate the artifact's owner, it acts as the operator-rooted
    `platform-system` principal under a bounded `platform.describe` scope, addressed to the persona
    that will run the describe. The requester names the persona and the resource; it cannot name a
    user subject.
    """
    model_config = ConfigDict(extra="forbid")
    persona_client_id: str
    resource_id: str
    ttl_seconds: int = 300


@internal_router.post("/describe-delegation")
def internal_issue_describe_delegation(
    body: _DescribeDelegationRequest,
    auth: AuthContext = Depends(get_auth),
):
    """Mint an operator-rooted system-describe delegation for the event-driven
    describer.

    No user impersonation: the subject is fixed to the system principal (rooted
    to the operator), the scope is `platform.describe`, and the audience/actor is
    the persona that will perform the enrichment. Mantle authorizes it exactly
    like any system-principal call — it only reaches artifacts the system
    principal has been granted, and safely 404s (describer no-ops) otherwise.
    """
    _require_platform_server(auth)

    if not platform_settings.get("platform.operator_id"):
        raise HTTPException(status_code=409, detail="Platform operator not configured")

    from origin.service_identity import get_system_principal_id

    subject_id = get_system_principal_id()
    if not subject_id:
        raise HTTPException(
            status_code=409,
            detail="Instance namespace unavailable; cannot derive system principal",
        )

    token = origin_auth_service.issue_system_delegation_token(
        subject_id,
        actor=body.persona_client_id,
        scope="platform.describe",
        audience=body.persona_client_id,
        ttl_seconds=body.ttl_seconds,
    )
    logger.info(
        "describe-delegation issued: persona=%s resource=%s sub=%s",
        body.persona_client_id, body.resource_id, subject_id,
    )
    return {"token": token, "subject_id": subject_id}


# Named system-delegation purposes. The requester picks a purpose, not an arbitrary subject, and
# Origin maps it to a bounded scope — so a platform caller can obtain a delegation for the
# operator-rooted `platform-system` principal scoped to exactly one capability, never a delegation
# for an arbitrary user.
_SYSTEM_DELEGATION_PURPOSES: dict[str, dict[str, str]] = {
    # Webhook/background email sends (receipts, usage warnings, etc.).
    "platform-mail": {"scope": "platform.email.send", "audience": "mantle"},
    # Resolves the Stripe credential (sandbox or live) for the payment tekton, on behalf of the
    # platform. Scoped to one capability, like every entry here, so it cannot be widened into a
    # general secret-reader.
    "platform-stripe": {"scope": "platform.stripe.resolve", "audience": "mantle"},
}


class _SystemDelegationRequest(BaseModel):
    """Body for POST /internal/system-delegation."""
    model_config = ConfigDict(extra="forbid")
    purpose: str
    ttl_seconds: int = 300


@internal_router.post("/system-delegation")
def internal_issue_system_delegation(
    body: _SystemDelegationRequest,
    auth: AuthContext = Depends(get_auth),
):
    """Mint a delegation for the operator-rooted `platform-system` principal.

    For platform automation (e.g. Ophan's Stripe webhook) that has no user delegation but must
    still act under the full identity chain. The requester names a purpose, never a subject, so it
    cannot impersonate a user — Origin fixes the subject to the system principal and stamps a
    bounded scope. Platform callers only.
    """
    _require_platform_server(auth)

    cfg = _SYSTEM_DELEGATION_PURPOSES.get(body.purpose)
    if cfg is None:
        raise HTTPException(status_code=403, detail=f"Unknown system delegation purpose: {body.purpose}")

    # The system principal's authority roots to the operator: with none designated there is
    # nothing to root to, so no delegation can be minted yet.
    if not platform_settings.get("platform.operator_id"):
        raise HTTPException(status_code=409, detail="Platform operator not configured")

    from origin.service_identity import get_system_principal_id

    subject_id = get_system_principal_id()
    if not subject_id:
        raise HTTPException(status_code=409, detail="Instance namespace unavailable; cannot derive system principal")

    actor = auth.actor or auth.principal_id  # the requesting persona, else the service
    token = origin_auth_service.issue_system_delegation_token(
        subject_id, actor=actor, scope=cfg["scope"], audience=cfg["audience"], ttl_seconds=body.ttl_seconds,
    )
    logger.info(
        "system-delegation issued: purpose=%s actor=%s sub=%s scope=%s",
        body.purpose, actor, subject_id, cfg["scope"],
    )
    return {"token": token, "subject_id": subject_id, "scope": cfg["scope"]}


# Secret-artifact material custody belongs to the service that owns the encrypted store.
# Origin has no secret-vault endpoints.


@internal_router.get("/operator-id")
def internal_get_operator_id(
    auth: AuthContext = Depends(get_auth),
):
    """Return the platform operator UUID from Origin's settings.

    A peer calls this when its own platform settings do not carry
    ``platform.operator_id`` — after a reset that cleared the peer's store but
    left Origin's intact, or during first-login provisioning before the operator
    bootstrap ran.
    """
    _require_platform_server(auth)
    return {"operator_id": platform_settings.get("platform.operator_id") or ""}


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------
class PasswordLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    identifier: str
    password: str


class PasswordRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str
    password: str
    name: str = ""
    email: str = ""


class PasswordResetRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str


class PasswordResetConfirmBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str
    new_password: str


class EmailVerifyRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str


class EmailVerifyConfirmBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str


class LinkProviderRequest(BaseModel):
    code: str
    code_verifier: str
    redirect_uri: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _extract_email(user_info: dict) -> str:
    email = (
        (user_info.get("email") or "").strip()
        or (user_info.get("preferred_username") or "").strip()
        or (user_info.get("upn") or "").strip()
    )
    if not email:
        emails = user_info.get("emails")
        if isinstance(emails, list) and emails:
            email = str(emails[0]).strip()
    return email


def _extract_email_verified(user_info: dict) -> bool:
    """Whether the upstream provider vouched for this address, in its own words.

    `email_verified` is an OpenID Connect standard claim, but it is optional: a provider that never
    sends it is not saying "verified", it is saying nothing, so an absent claim reads as false
    rather than true. Treating a missing claim as true would let any IdP that omits it authenticate
    whatever address a user types.

    The claim is also not always a boolean — some providers send the string "true", and
    `bool("false")` is `True`, so a naive cast turns an explicit denial into an approval. Only
    values that unambiguously say yes are accepted.
    """
    claim = user_info.get("email_verified")
    if isinstance(claim, bool):
        return claim
    if isinstance(claim, str):
        return claim.strip().lower() in ("true", "1", "yes")
    return False


def _extract_name(user_info: dict) -> str:
    name = (user_info.get("name") or "").strip()
    if name:
        return name
    given = (user_info.get("given_name") or "").strip()
    family = (user_info.get("family_name") or "").strip()
    if given or family:
        return (given + " " + family).strip()
    return (user_info.get("preferred_username") or "").strip() or "User"


def _person_to_dict(person: PersonModel, db: Session | None = None) -> dict:
    """Serialize a Person row to the same shape Mantle emits.

    `google_id` / `oidc_provider` / `oidc_subject` are not part of this payload: they describe a
    single external identity, and a person may hold several, so a scalar field cannot answer
    "which provider?" without silently picking one. `identities` carries the full list instead
    (migration 0005). `db` is optional so callers that only need the account fields, and hold no
    session, are not forced to open one — without it the list is simply absent rather than wrong.
    """
    out = {
        "id": str(person.id),
        "email": person.email or "",
        "name": person.name or "",
        "username": person.username or "",
        "picture": person.picture,
        "preferences": person.preferences or {},
        "has_password": bool(person.password_hash),
        "created_time": person.created_time.isoformat() if person.created_time else None,
        "modified_time": person.modified_time.isoformat() if person.modified_time else None,
    }
    if db is not None:
        out["identities"] = [
            {"method": i.method, "provider": i.provider, "subject": i.subject,
             "verified": i.verified_at is not None}
            for i in person_service.list_identities(db, str(person.id))
        ]
    return out


def _compute_roles(user_id: str) -> list[str]:
    """Roles for inclusion in JWTs.

    The only role Origin computes is `platform:admin` for the bootstrap operator
    (`platform.operator_id`). There is no grant-based admin lookup here.
    """
    operator_id = platform_settings.get("platform.operator_id")
    if operator_id and user_id == operator_id:
        return ["platform:admin"]
    return []


# In-memory PKCE / authorization-code storage. Per-process, which is why `main.py` refuses to
# boot multi-worker; a shared store is what a multi-replica deployment would need.
authorization_codes: dict[str, dict] = {}
pkce_challenges: dict[str, dict] = {}

_AUTH_CACHE_TTL = timedelta(minutes=10)
_AUTH_CACHE_MAX_ITEMS = 5000


def _prune_auth_cache(now: datetime) -> None:
    cutoff = now - _AUTH_CACHE_TTL
    for cache in (pkce_challenges, authorization_codes):
        expired = [
            k
            for k, v in cache.items()
            if isinstance(v, dict) and v.get("timestamp") and v["timestamp"] < cutoff
        ]
        for k in expired:
            cache.pop(k, None)
        while len(cache) > _AUTH_CACHE_MAX_ITEMS:
            try:
                oldest = next(iter(cache))
            except StopIteration:
                break
            cache.pop(oldest, None)


# ---------------------------------------------------------------------------
# Local (non-federated) sign-in inside the OAuth code flow
# ---------------------------------------------------------------------------
#: Names Origin authenticating the person itself, so it is not shaped as a registered OIDC
#: provider. Held distinct from the `REGISTERED_PROVIDERS` keyspace, which keeps an upstream IdP
#: from being called "local" and taking this path.
_LOCAL_PROVIDER = "local"

#: Google's mark, inline — the sign-in page makes no external request for it. A `<img>` pointed at
#: a Google CDN would tell that CDN who is looking at the login screen before anyone has chosen to
#: use it, and would leave a blank square in any network where the CDN is blocked.
_GOOGLE_MARK = (
    '<svg viewBox="0 0 48 48" aria-hidden="true">'
    '<path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>'
    '<path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>'
    '<path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>'
    '<path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>'
    "</svg>"
)

#: The same document shell as `web/index.html`, loading the same two files: `/web/app.css` and
#: `/web/bg.js` are what `/login`, `/account`, `/reset-password` and `/verify-email` already use —
#: the branded card over the animated conic gradient and drifting blobs. A second copy of that
#: styling here would drift from the account page it hands the person to.
#:
#: Loads `bg.js`, not `app.js`. `app.js` carries `saveToken` and `finishLogin`, which put an access
#: token in `localStorage` and return it through a URL fragment — the implicit flow this endpoint
#: replaces. A page that cannot save a token cannot leak one, so the split in `web/bg.js` is what
#: lets this share the background without that flow.
_LOCAL_LOGIN_PAGE = """<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in · Agience</title><link rel="icon" href="/web/favicon.png">
<link rel="stylesheet" href="/web/app.css">
</head><body>
<div class="bg"></div>
<div class="card">
  <img class="logo" src="/web/logo_v.png" alt="Agience">
  <h1>Welcome, let's get you signed in</h1>
__PROVIDERS__
__PASSWORD__
__OTP__
  <div class="msg" id="msg"></div>
  <div class="foot"><a href="/terms">Terms</a> · <a href="/privacy">Privacy</a></div>
</div>
<script src="/web/bg.js"></script>
<script>
const S = "__STATE__";
const msg = document.getElementById("msg");
const say = (t, cls) => { msg.className = "msg " + (cls || "muted"); msg.textContent = t || ""; };
async function post(url, body){
  const r = await fetch(url, {method:"POST", headers:{"content-type":"application/json"},
                             body: JSON.stringify(body)});
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.detail || ("request failed (" + r.status + ")"));
  return d;
}
const $ = (s) => document.querySelector(s);
/* Every method ends the same way: the server hands back the redirect it already computed from the
   pending request. The page never assembles a redirect itself and never sees a token. */
const finish = (d) => location.assign(d.redirect);

const pwForm = $("#pwForm");
if (pwForm) pwForm.onsubmit = async (e) => {
  e.preventDefault();
  const btn = $("#pwBtn"); btn.disabled = true; say("");
  try {
    finish(await post("/auth/authorize/password", {oauth_state: S,
      identifier: $("#identifier").value.trim(), password: $("#password").value}));
  } catch (err) { say(err.message, "err"); btn.disabled = false; }
};

const otpToggle = $("#otpToggle");
if (otpToggle) otpToggle.onclick = () => {
  $("#local").classList.add("hidden");
  $("#otp").classList.remove("hidden");
  $("#email").focus(); say("");
};
const otpBack = $("#otpBack");
if (otpBack) otpBack.onclick = () => {
  $("#otp").classList.add("hidden");
  $("#local").classList.remove("hidden"); say("");
};
const sendForm = $("#sendForm");
if (sendForm) sendForm.onsubmit = async (e) => {
  e.preventDefault();
  const btn = $("#send"); btn.disabled = true;
  try {
    await post("/auth/authorize/otp/request", {oauth_state: S, email: $("#email").value.trim()});
    $("#step1").classList.add("hidden");
    $("#step2").classList.remove("hidden");
    $("#code").focus();
    /* Said the same way whether or not the account exists — the server does not disclose it and
       neither may this text, keeping the page as free of account-enumeration as the API. */
    say("If that address has an account, a code is on its way.");
  } catch (err) { say(err.message, "err"); btn.disabled = false; }
};
const codeForm = $("#codeForm");
if (codeForm) codeForm.onsubmit = async (e) => {
  e.preventDefault();
  const btn = $("#verify"); btn.disabled = true; say("");
  try {
    finish(await post("/auth/authorize/otp/verify", {oauth_state: S,
      email: $("#email").value.trim(), code: $("#code").value.trim()}));
  } catch (err) { say(err.message, "err"); btn.disabled = false; }
};
</script></body></html>"""

_PASSWORD_BLOCK = """  <div id="local">
    <form id="pwForm">
      <label for="identifier">Email or username</label>
      <input id="identifier" type="text" autocomplete="username" required>
      <label for="password">Password</label>
      <input id="password" type="password" autocomplete="current-password" required>
      <div class="between" style="margin-top:8px">
        <a class="link" href="/reset-password">Forgot your password?</a>
      </div>
      <button class="primary" type="submit" id="pwBtn">Sign in</button>
    </form>
__OTPTOGGLE__
  </div>
"""

_OTP_TOGGLE = """    <div class="row"><button class="link" type="button" id="otpToggle">Email me a code instead</button></div>
"""

_OTP_BLOCK = """  <div id="otp"__OTPHIDDEN__>
    <div id="step1">
      <form id="sendForm">
        <label for="email">Email</label>
        <input id="email" type="email" autocomplete="email" required>
        <button class="primary" type="submit" id="send">Send code</button>
      </form>
    </div>
    <div id="step2" class="hidden">
      <form id="codeForm">
        <label for="code">Code</label>
        <input id="code" inputmode="numeric" autocomplete="one-time-code" required>
        <button class="primary" type="submit" id="verify">Sign in</button>
      </form>
    </div>
__OTPBACK__
  </div>
"""

_OTP_BACK = """    <div class="row"><button class="link" type="button" id="otpBack">Use a password instead</button></div>
"""


def _render_local_login(
    oauth_state: str,
    *,
    providers: list[tuple[str, str]],
    password: bool,
    otp: bool,
) -> str:
    """The account chooser: whichever of password, OTP and federated sign-in this node actually has.

    Disabled methods are omitted, not hidden. A form for a disabled method is a button that fails,
    and a provider button for an unregistered provider is a 400 generator — both read to a person as
    "the login is broken" rather than as "this node does not offer that". What is rendered is what
    was measured to work; `/authorize` answers with a 400 rather than an empty page when the method
    list comes back empty.

    `oauth_state` is server-generated (`generate_token(32)`), never user input, which is why
    substituting it into the document is safe. Provider names come from `REGISTERED_PROVIDERS`, but
    their labels come from operator configuration (`CUSTOM_OIDC_NAME`) and are escaped — configured
    today, one settings endpoint away from being someone's input.
    """
    buttons = "".join(
        '  <button class="provider" type="button" '
        f'onclick="location.assign(\'/auth/authorize/federate?oauth_state={oauth_state}'
        f'&amp;provider={_html.escape(name, quote=True)}\')">'
        f"{_GOOGLE_MARK if name == 'google' else ''}"
        f"Continue with {_html.escape(label)}</button>\n"
        for name, label in providers
    )
    # The divider only earns its place when there is something on both sides of it.
    if buttons and (password or otp):
        buttons += '  <div class="sep">or</div>\n'

    if password:
        block = _PASSWORD_BLOCK.replace("__OTPTOGGLE__", _OTP_TOGGLE if otp else "")
        otp_block = _OTP_BLOCK.replace("__OTPHIDDEN__", ' class="hidden"').replace(
            "__OTPBACK__", _OTP_BACK
        ) if otp else ""
    else:
        block = ""
        # No password to fall back to, so OTP is the only local method: shown, with no way back.
        otp_block = _OTP_BLOCK.replace("__OTPHIDDEN__", "").replace("__OTPBACK__", "") if otp else ""

    return (
        _LOCAL_LOGIN_PAGE.replace("__PROVIDERS__", buttons)
        .replace("__PASSWORD__", block)
        .replace("__OTP__", otp_block)
        .replace("__STATE__", oauth_state)
    )


def _local_methods() -> tuple[bool, bool]:
    """(password, otp) — what this node can actually complete a local sign-in with, measured once.

    Measured here and passed down, never re-derived inside the template: two readings of "is OTP
    available?" is how a page comes to render a form the endpoint behind it does not accept.
    """
    return (
        platform_settings.get_bool("auth.password.enabled", True),
        email_service.is_configured(),
    )


def _pop_local_auth_request(oauth_state: str) -> dict:
    """The pending request for a local sign-in, or a 400. Read (not popped) on `request` because the
    person may need a second code; the caller pops only once a code has actually verified."""
    auth_request = pkce_challenges.get(oauth_state)
    if not auth_request or auth_request.get("provider") != _LOCAL_PROVIDER:
        raise HTTPException(status_code=400, detail="This sign-in has expired. Start again.")
    return auth_request


class _LocalOTPRequest(BaseModel):
    oauth_state: str
    email: str


class _LocalOTPVerify(BaseModel):
    oauth_state: str
    email: str
    code: str


@auth_router.post("/authorize/otp/request", dependencies=None)
async def authorize_local_otp_request(body: _LocalOTPRequest, db: Session = Depends(get_db)):
    """Send a one-time code for a sign-in already in flight.

    The response is identical for a known and an unknown address, matching `/auth/otp/request`:
    reporting "no such account" would make this endpoint an account-enumeration oracle, reachable
    without authentication since a sign-in in flight is not yet a session.
    """
    _pop_local_auth_request(body.oauth_state)
    if not email_service.is_configured():
        raise HTTPException(status_code=503, detail="Email delivery is not configured.")

    person = db_persons.get_by_email(db, body.email)
    if person is None:
        logger.info("local-authorize OTP requested for unknown email")
        return {"sent": True}
    if not await otp_service.request_otp(db, body.email):
        raise HTTPException(status_code=429, detail="Too many attempts. Please try again later.")
    return {"sent": True}


@auth_router.post("/authorize/otp/verify", dependencies=None)
async def authorize_local_otp_verify(body: _LocalOTPVerify, db: Session = Depends(get_db)):
    """Verify the code and mint the authorization code, completing the flow locally.

    The payload is the same shape the federated callback writes: `/token`, `_grant_authorization_code`
    and every consumer downstream cannot tell which path produced it. One shape for both paths is
    what keeps them from drifting apart.
    """
    auth_request = _pop_local_auth_request(body.oauth_state)

    person_id = await otp_service.verify_otp(db, body.email, body.code)
    if not person_id:
        raise HTTPException(status_code=401, detail="Invalid or expired code")
    person = db_persons.get_by_id(db, person_id)
    if person is None:
        raise HTTPException(status_code=401, detail="User not found")

    from origin.services.auth_service import is_person_allowed

    # The same gate the federated path applies. Holding a valid OTP proves control of the mailbox,
    # which is not the same question as being permitted to sign in here — skipping it would make the
    # local path a way around an admission rule the Google path enforces.
    if not is_person_allowed(None, person.email or ""):
        raise HTTPException(status_code=403, detail="User not allowed")

    # An OTP delivered to this address proves ownership — mirrors `/auth/otp/verify`, so an
    # account whose address is unverified is not left blocked by the path it signed in through.
    if not person.email_verified:
        person.email_verified = True

    # The identity row must exist before `/token` looks for it.
    # `person_service.get_or_create_user_by_oidc_identity` resolves only by (provider, subject) and
    # does not fall back to email. With no `(local, <person-id>)` row it takes the `create` branch
    # and mints a second person carrying this same address, leaving the OTP-verified one orphaned
    # and the grants attached to whichever the flow happened to produce.
    #
    # Writing it here is the natural place: a verified OTP is Origin establishing a local identity
    # for this person. Idempotent — a second sign-in finds the row and adds nothing.
    return _complete_local_signin(db, body.oauth_state, auth_request, person)


def _complete_local_signin(
    db: Session, oauth_state: str, auth_request: dict, person: PersonModel
) -> dict:
    """Write the local identity row and mint the authorization code. Both local legs end here.

    One implementation, because the OTP and password legs differ only in how they proved who this
    is. Everything after that proof — the identity row, the commit, the code payload, the redirect
    — is identical, so there is one payload shape for `/token` to read rather than two.

    The identity row must exist before `/token` looks for it:
    `person_service.get_or_create_user_by_oidc_identity` resolves by `(provider, subject)` first,
    and with no `(local, <person-id>)` row a local sign-in falls through to the email-linking
    branch instead — correct but strictly weaker, and it raises `IdentityLinkRefused` on an
    unverified address. Writing the row is what makes a local sign-in resolve by its durable key
    like every other method.
    """
    if db_person_identities.get_by_identity(
        db, method="oidc", provider=_LOCAL_PROVIDER, subject=str(person.id)
    ) is None:
        db_person_identities.add(
            db, person_id=person.id, method="oidc",
            provider=_LOCAL_PROVIDER, subject=str(person.id), verified=True,
        )
    db.commit()

    pkce_challenges.pop(oauth_state, None)
    _prune_auth_cache(datetime.now(timezone.utc))
    auth_code = generate_token(32)
    authorization_codes[auth_code] = {
        "user_info": {
            "provider": _LOCAL_PROVIDER,
            "sub": str(person.id),
            "email": (person.email or "").lower(),
            "name": person.name or "",
            "picture": person.picture or "",
            # What Origin itself knows about this address, passed on rather than assumed
            # downstream. `person_service` will not link a second provider onto this account
            # without it, and it must be the stored fact — reaching this line proves the person
            # holds the credential, which is not the same as having proved the mailbox.
            "email_verified": bool(person.email_verified),
        },
        "client_id": auth_request["client_id"],
        "redirect_uri": auth_request["redirect_uri"],
        "scope": auth_request["scope"],
        "code_challenge": auth_request.get("code_challenge"),
        "code_challenge_method": auth_request.get("code_challenge_method"),
        "timestamp": datetime.now(timezone.utc),
    }
    if auth_request.get("setup_operator_token"):
        authorization_codes[auth_code]["setup_operator_token"] = auth_request["setup_operator_token"]

    params = {"code": auth_code}
    if auth_request.get("state"):
        params["state"] = auth_request["state"]
    return {"redirect": f"{auth_request['redirect_uri']}?{urlencode(params)}"}


# ---------------------------------------------------------------------------
# Password gates shared by both password endpoints
#
# `/authorize/password` and `/auth/password/login` prove the same credential by two routes. Any
# gate written into one and not the other is a way around it, so the three below are functions
# rather than repeated blocks: a gate that exists once cannot be added to one path and forgotten on
# the other.
# ---------------------------------------------------------------------------
def _reject_if_password_budget_spent(identifier: str) -> None:
    """Refuse before the key derivation runs when this identifier's window budget is spent.

    The 429 and its wording are `otp_router`'s: a password guesser and an OTP guesser learn the
    same thing from a refusal, which is that they are being counted.
    """
    if guess_budget.password_attempts_exhausted(identifier):
        logger.warning(
            "password attempt throttled for %r — %d failures inside the window",
            identifier,
            guess_budget.password_window_cap(),
        )
        raise HTTPException(
            status_code=429, detail="Too many attempts. Please try again later."
        )


def _charge_password_failure(identifier: str, reason: str) -> None:
    """Spend one draw, and say so in the log.

    The log line is half the control. OTP and passkey failures were already recorded at WARNING
    (`otp_service.verify_otp`, `passkey_service`); a password failure was the one authentication
    failure Origin did not write down, so a credential-stuffing run against it left no trace at any
    level and a limiter firing on it would have been equally invisible.

    `reason` distinguishes the two failure paths for whoever reads the log, and appears nowhere in
    the response — the caller gets one indistinguishable 401 either way.
    """
    guess_budget.record_password_failure(identifier)
    logger.warning("password authentication failed for %r (%s)", identifier, reason)


def _upgrade_password_hash_if_stale(db: Session, person: PersonModel, password: str) -> None:
    """Re-hash at the current cost, on the one occasion the plaintext is in hand.

    `verify_password` reads the iteration count out of the stored hash, so raising the configured
    count leaves every existing hash verifying at the count it was written with — correct, and also
    permanent: without this, an account created before a raise keeps its old cost until its owner
    resets their password, which most never do. Successful sign-in is the only moment Origin holds
    a password it can re-derive from.

    Best-effort: a failed re-hash must not fail a sign-in that has already succeeded.
    """
    try:
        if origin_auth_service.password_hash_is_current(person.password_hash):
            return
        person.password_hash = hash_password(password)
        db.commit()
        logger.info("upgraded stored password hash to the current cost for person %s", person.id)
    except Exception:  # pragma: no cover — never let a rehash cost someone their session
        db.rollback()
        logger.warning("password hash upgrade failed for person %s", person.id, exc_info=True)


class _LocalPasswordVerify(BaseModel):
    oauth_state: str
    identifier: str
    password: str


@auth_router.post("/authorize/password", dependencies=None)
async def authorize_local_password(body: _LocalPasswordVerify, db: Session = Depends(get_db)):
    """Sign in with a password inside the authorization-code flow.

    Distinct from `/auth/password/login`, which mints an access + refresh token directly — a
    different grant that cannot complete PKCE, which is why the browser cannot use it here. This
    endpoint proves the same credential and hands back an authorization code instead, useless
    without the verifier the caller kept.

    Every gate `/auth/password/login` applies is applied here too, each named at its call site: a
    gate present on one password path and missing on the other would be a way around it, not a
    smaller version of it.
    """
    auth_request = _pop_local_auth_request(body.oauth_state)

    # The same 404 `/auth/password/login` gives, needed here too: a disabled method reachable
    # through a second URL is not disabled.
    if not platform_settings.get_bool("auth.password.enabled", True):
        raise HTTPException(status_code=404, detail="Password auth is disabled")

    identifier = (body.identifier or "").strip()
    password = body.password or ""
    if not identifier or not password:
        raise HTTPException(status_code=400, detail="Username and password are required")

    # The same guess budget `/auth/password/login` spends from, and the same 429. Two password
    # endpoints counting into two budgets would be one budget an attacker gets twice.
    _reject_if_password_budget_spent(identifier)

    if "@" in identifier:
        person = person_service.get_user_by_email(db, identifier.lower())
    else:
        person = person_service.get_user_by_username(db, identifier)

    # The dummy verify is the answer to a timing oracle: returning early for an unknown account
    # makes "no such user" measurably faster than "wrong password", which turns this endpoint into
    # an account-enumerator that no message needs to leak. Same reason, same call, as
    # `/auth/password/login`.
    if not person or not person.password_hash:
        dummy_verify_password(password)
        _charge_password_failure(identifier, "no such account or no password set")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not verify_password(password, person.password_hash):
        _charge_password_failure(identifier, "wrong password")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    guess_budget.clear_password_failures(identifier)
    _upgrade_password_hash_if_stale(db, person, password)

    # This gate is why the account-linking rule holds. An unverified password account signing in
    # here would still carry `email_verified=False`, but as a live session on an address nobody
    # proved — and `person_service` does not link an unproven address to an existing Google
    # identity. Skipping this gate would leave that check as the only thing standing between an
    # unproven address and someone else's account.
    if not person.email_verified and email_verification_required(person.email):
        await _send_verification_email(person)
        raise HTTPException(
            status_code=403,
            detail="Please verify your email to sign in. We've sent you a new verification link.",
        )

    from origin.services.auth_service import is_person_allowed

    # The same admission gate the federated and OTP paths apply: holding the password proves who
    # you are, not that you are permitted here.
    if not is_person_allowed(None, person.email or ""):
        raise HTTPException(status_code=403, detail="User not allowed")

    return _complete_local_signin(db, body.oauth_state, auth_request, person)


@auth_router.get("/authorize/federate", dependencies=None)
async def authorize_federate(request: Request, oauth_state: str, provider: str):
    """Hand a sign-in already in flight to an upstream provider — the chooser's provider buttons.

    The pending request is updated in place, so `/callback` reads `provider` straight out of
    `pkce_challenges[oauth_state]`; this call sets it, along with the `expected_iss` the RFC 9207
    check compares against. The authorization code minted downstream comes from the same pending
    request, so the client_id, redirect_uri, scope, state and PKCE challenge are the ones the caller
    originally sent.

    The button therefore carries `oauth_state` and nothing else, which keeps the property the local
    page is built around: the browser holds an opaque handle rather than the request. A handle that
    can only be redeemed server-side cannot be edited by whoever is looking at the page.
    """
    auth_request = _pop_local_auth_request(oauth_state)

    # An unregistered name is refused here as a 400. Reaching `oauth.create_client` it would fail
    # as a 500 — a server fault for a request that names something that does not exist.
    if provider == _LOCAL_PROVIDER or provider not in REGISTERED_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown or unconfigured provider: {provider}")

    oauth_client = oauth.create_client(provider)
    if not oauth_client:
        raise HTTPException(status_code=500, detail=f"Provider not available: {provider}")

    auth_request["provider"] = provider
    auth_request["expected_iss"] = REGISTERED_PROVIDERS[provider].get("issuer")

    extra_kwargs: dict = {}
    try:
        server_metadata = await oauth_client.load_server_metadata()
        if "offline_access" in (server_metadata.get("scopes_supported") or []):
            extra_kwargs["scope"] = (
                REGISTERED_PROVIDERS[provider].get("scope", "openid email profile") + " offline_access"
            )
    except Exception:
        pass

    return await oauth_client.authorize_redirect(
        request,
        redirect_uri=REGISTERED_PROVIDERS[provider]["redirect_uri"],
        state=oauth_state,
        **extra_kwargs,
    )


# ---------------------------------------------------------------------------
# OAuth /authorize
# ---------------------------------------------------------------------------
_FIRST_PARTY_HINT = (
    "If this is one of this node's own first-party clients, enrol its id in PLATFORM_CLIENT_IDS."
)

#: What an operator has to do, said where they will meet it. `/authorize` admits two populations
#: and no third: a client id an operator configured, and a client id this authority issued.
_UNKNOWN_CLIENT_HINT = (
    "This authority admits two kinds of client_id and no third: one an operator configured "
    "(PLATFORM_CLIENT_ID, or any entry in the comma-separated PLATFORM_CLIENT_IDS), and one it "
    "issued itself through POST /auth/register. Mantle's browser sign-in identifies as "
    "MANTLE_OIDC_CLIENT_ID, which has no default and is set on Mantle rather than here — enrol that "
    "exact value in PLATFORM_CLIENT_IDS, which is also what makes it receive a full user token "
    "instead of a scoped one."
)


def _is_first_party_client(client_id: str) -> bool:
    """Is this one of the platform's own first-party clients?

    Named, not inferred, and not looked up anywhere. `PLATFORM_CLIENT_ID` is the same value the
    direct-mint sign-in paths (password, OTP, passkey, setup) already stamp into the `client_id`
    claim; `PLATFORM_CLIENT_IDS` carries the node's other first-party surfaces, each of which
    reads its own client id and need not equal Origin's.

    Membership here is the whole of the test, and the answer for everything else is "third
    party": a client id nobody enrolled gets the scoped `mcp_client` token, never the full user
    JWT. A client that enrolled itself through `POST /auth/register` is third party too — this
    predicate does not read `oauth_clients`, and a client vouching for itself is not the operator
    naming it.

    This is a trust test, and `/authorize` runs a separate admission test. Admission is "configured
    here or registered in `oauth_clients`"; this predicate is "configured here" alone. The two
    answers differ on purpose: a registered client is admitted to the flow and still receives the
    scoped token, because being allowed in is not being vouched for.
    """
    if client_id == getattr(config, "PLATFORM_CLIENT_ID", "platform"):
        return True
    # An operator setting the env var by hand can hand us one string rather than the list the
    # CSV settings path produces; iterating that string would admit its individual characters.
    configured = getattr(config, "PLATFORM_CLIENT_IDS", None) or []
    if isinstance(configured, str):
        configured = [c.strip() for c in configured.split(",") if c.strip()]
    return client_id in configured


def _authorize_refusal(error: str, description: str) -> JSONResponse:
    """An RFC 6749 §4.1.2.1 refusal — returned to the browser, never sent to `redirect_uri`.

    This is the one OAuth error that stays off the redirect. §4.1.2.1: "If the request fails due to
    a missing, invalid, or mismatching redirection URI, or if the client identifier is missing or
    invalid, the authorization server SHOULD inform the resource owner of the error and MUST NOT
    automatically redirect the user-agent to the invalid redirection URI." An unknown client and an
    unbound redirect are the two states in which the redirect target has nothing standing behind it,
    so sending the error there would hand whoever guessed a client id a delivery to an address this
    authority has just declined to trust. The refusal is the response body, returned up the request
    that made it and nowhere else.

    Shaped as RFC 6749 §5.2's `error` / `error_description` pair rather than FastAPI's `detail`,
    because both readers act on it — an MCP client branches on `error`, and an operator reads
    `error_description` in a browser tab. `no-store` for the same reason the sign-in page sets it.
    """
    return JSONResponse(
        status_code=400,
        content={"error": error, "error_description": description},
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


@auth_router.get("/authorize", dependencies=None)
async def authorize(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    provider: Optional[str] = None,
    scope: Optional[str] = None,
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = "S256",
    setup_operator_token: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """OAuth2 authorization endpoint. Redirects to the upstream OIDC provider.

    Three populations of client reach this endpoint and exactly two are admitted:

    · Configured — `PLATFORM_CLIENT_ID` and every entry in `PLATFORM_CLIENT_IDS`. An operator named
      them, so there is no registration to read and nothing to look up. Admitted.
    · Registered — a row in `oauth_clients`, issued by `POST /auth/register`. Admitted, and bound to
      the redirect URIs it registered.
    · Everything else — refused, with `_UNKNOWN_CLIENT_HINT` naming the two ways into the first two.

    A peer service's browser sign-in belongs in the first population. It identifies as its own OIDC
    client id, a value with no default that is configured on that service, so it must be enrolled in
    `PLATFORM_CLIENT_IDS` to receive a user token at all. Unenrolled but admitted, it would get the
    scoped `mcp_client` token from `_grant_authorization_code` — no email, no name, no roles — and
    the facet would show an anonymous session with `platform:admin` never granted. Refusing at the
    login page with a message naming the setting is the answer a sign-in that half-works is not.

    ## Where a client's code may be delivered

    A registered client is held to the authority-wide allow-list AND its own `redirect_uris`.
    `is_client_redirect_allowed` is client-blind — it admits this node's facets, the well-known tool
    callbacks and loopback for every caller alike — so on its own it would let any client name any
    admitted callback, including another client's. The per-client set is what pins a client to its
    own address.

    Both, rather than its own set alone. Registration already refuses any URI `/authorize` would
    refuse (`_validated_redirect_uris`), so a registered set is a subset of the allow-list and the
    conjunction equals it — until an operator edits `FACET_URIS`. Then a facet withdrawn from
    configuration is withdrawn from every registered client holding it, in that one edit, with no
    rows to hunt through. Configuration stays the outer bound, and that bound can only narrow.

    A configured first-party client has no registration, so the allow-list is the whole of its
    binding. Both halves — which ids are first-party, which bases are admitted — are the same
    operator's configuration in the same file, so binding one to the other would mean a third
    configuration shape (client id → URIs) that every node would have to grow before it could sign
    anyone in, to separate two surfaces the operator already trusts equally.

    An id that is both configured and registered is treated as configured, and keeps the allow-list
    rather than the registration binding. Naming an id in `PLATFORM_CLIENT_IDS` is the operator's
    stronger statement, and it keeps a first-party sign-in from depending on a database row.
    """
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type. Only 'code' is supported.")

    # Configured first, and only then the registry — so a first-party sign-in reads no table. The
    # ordering is what makes this node's own door independent of `oauth_clients` existing, being
    # migrated, or being reachable, and it is also the ordering that decides the both-case above.
    registration: Optional[OAuthClient] = None
    if not _is_first_party_client(client_id):
        registration = db_oauth_clients.get_by_client_id(db, client_id)
        if registration is None:
            detail = f"Unknown client_id {client_id!r}. " + _UNKNOWN_CLIENT_HINT
            if client_id.startswith(_DCR_CLIENT_ID_PREFIX):
                # Shaped like an id this authority minted, with no row behind it. The client cannot
                # act on "unknown" — it holds what looks like a valid registration — but it can act
                # on "register again", and that is the true instruction: the row is gone (a rebuilt
                # database, a different node behind the same name), not merely unrecognised.
                detail += (
                    " This id carries this authority's registration prefix but has no registration "
                    "behind it — the record is gone rather than unrecognised. Register again at "
                    "POST /auth/register and use the client_id that call returns."
                )
            logger.warning(
                "Refused /authorize: client_id=%s is neither configured nor registered", client_id
            )
            return _authorize_refusal("invalid_client", detail)

    if not is_client_redirect_allowed(redirect_uri):
        # Named settings, because the two ways to be here are an operator's and an attacker's and
        # only the operator reads this: either the redirect base belongs to a facet this authority
        # has not been told about, or the caller is a first-party client nobody enrolled.
        raise HTTPException(
            status_code=403,
            detail="Invalid redirect_uri — its base is not among FACET_URI/FACET_URIS/ORIGIN_URI. "
                   + _FIRST_PARTY_HINT,
        )

    if registration is not None and not origin_auth_service.redirect_uri_matches_registered(
        redirect_uri, registration.redirect_uris
    ):
        # The finding this change exists to close. Passing the allow-list means only that some
        # client on this node may be delivered a code here; it says nothing about THIS one.
        #
        # The registered URIs are not listed back. The caller either registered them and has them,
        # or did not and is asking this authority to describe a client that is not theirs.
        logger.warning(
            "Refused /authorize: registered client_id=%s asked for an unregistered redirect_uri",
            client_id,
        )
        return _authorize_refusal(
            "invalid_request",
            f"redirect_uri {redirect_uri!r} is not one this client registered. A registered client "
            "receives its code only at a redirect_uri from its own registration — this authority's "
            "allow-list bounds which URIs may be registered at all, and entitles no client to "
            "another's. Register the URI you intend to use, or start the flow at one you did.",
        )

    if code_challenge:
        if code_challenge_method not in ("S256", "plain"):
            raise HTTPException(status_code=400, detail="code_challenge_method must be 'S256' or 'plain'.")
        if len(code_challenge) < 43 or len(code_challenge) > 128:
            raise HTTPException(
                status_code=400, detail="code_challenge must be between 43 and 128 characters"
            )

    # No `provider` means "show me the choices," not "pick one for me": the local page renders
    # every method this node actually has (password, OTP, and any registered federated provider),
    # so configuring an upstream IdP adds a sign-in door rather than replacing the others. A caller
    # that wants one specific provider still passes `?provider=google` and federates immediately.
    is_local = provider is None or provider == _LOCAL_PROVIDER
    if not is_local and provider not in REGISTERED_PROVIDERS:
        raise HTTPException(
            status_code=400, detail=f"Unknown or unconfigured provider: {provider}"
        )
    if is_local:
        provider = _LOCAL_PROVIDER
        password_ok, otp_ok = _local_methods()
        # A 400 only when there is genuinely nothing to render — a node with passwords and no mail
        # server has a working sign-in even though OTP is unavailable, so the check is "no method at
        # all," not "no email."
        if not (password_ok or otp_ok or REGISTERED_PROVIDERS):
            raise HTTPException(
                status_code=400,
                detail="This server has no way to sign anyone in — configure an upstream identity "
                       "provider, enable password sign-in, or configure email delivery for one-time "
                       "codes.",
            )

    _prune_auth_cache(datetime.now(timezone.utc))
    oauth_state = generate_token(32)
    auth_request = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "provider": provider,
        "scope": scope or "read",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        # No upstream issuer to compare against on the local path — nothing federates, so RFC 9207's
        # `iss` check has no counterparty. The callback only reads this for federated requests.
        "expected_iss": None if is_local else REGISTERED_PROVIDERS[provider].get("issuer"),
        "timestamp": datetime.now(timezone.utc),
    }
    if setup_operator_token:
        auth_request["setup_operator_token"] = setup_operator_token
    pkce_challenges[oauth_state] = auth_request

    if is_local:
        # The PKCE challenge, redirect_uri and client_id all stay server-side under `oauth_state`;
        # the page below only ever holds that opaque handle.
        return HTMLResponse(
            content=_render_local_login(
                oauth_state,
                providers=[
                    (name, meta.get("label", name))
                    for name, meta in sorted(REGISTERED_PROVIDERS.items())
                ],
                password=password_ok,
                otp=otp_ok,
            ),
            status_code=200,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )

    oauth_client = oauth.create_client(provider)
    if not oauth_client:
        raise HTTPException(status_code=500, detail=f"Provider not available: {provider}")

    extra_kwargs: dict = {}
    try:
        server_metadata = await oauth_client.load_server_metadata()
        if "offline_access" in (server_metadata.get("scopes_supported") or []):
            extra_kwargs["scope"] = (
                REGISTERED_PROVIDERS[provider].get("scope", "openid email profile") + " offline_access"
            )
    except Exception:
        pass

    return await oauth_client.authorize_redirect(
        request,
        redirect_uri=REGISTERED_PROVIDERS[provider]["redirect_uri"],
        state=oauth_state,
        **extra_kwargs,
    )


# ---------------------------------------------------------------------------
# OAuth /callback
# ---------------------------------------------------------------------------
@auth_router.get("/callback")
async def auth_callback(request: Request):
    try:
        oauth_state = request.query_params.get("state")
        if not oauth_state or oauth_state not in pkce_challenges:
            raise HTTPException(status_code=400, detail="Invalid or expired state parameter")
        auth_request = pkce_challenges[oauth_state]
        provider = auth_request.get("provider") or "google"

        callback_iss = request.query_params.get("iss")
        expected_iss = auth_request.get("expected_iss")
        if expected_iss and callback_iss and callback_iss != expected_iss:
            logger.warning(
                "RFC 9207 iss mismatch for %s: expected %r got %r", provider, expected_iss, callback_iss
            )
            raise HTTPException(status_code=400, detail="Authorization server mismatch (iss parameter)")

        oauth_client = oauth.create_client(provider)
        if not oauth_client:
            raise HTTPException(status_code=500, detail=f"Provider not available: {provider}")

        token = await oauth_client.authorize_access_token(request)
        user_info = token.get("userinfo")
        if not user_info:
            try:
                user_info = await oauth_client.userinfo(token=token)
            except Exception:
                user_info = None
        if not user_info:
            raise HTTPException(status_code=400, detail="Failed to fetch user info")

        email = _extract_email(user_info)
        name = _extract_name(user_info)
        if not email:
            raise HTTPException(status_code=400, detail="Provider did not return an email address")

        google_id = user_info.get("sub") if provider == "google" else None
        from origin.services.auth_service import is_person_allowed

        if not is_person_allowed(google_id, email):
            error_params = {"error": "access_denied", "error_description": "User not allowed"}
            if auth_request.get("state"):
                error_params["state"] = auth_request["state"]
            return RedirectResponse(
                url=f"{auth_request['redirect_uri']}?{urlencode(error_params)}",
                status_code=status.HTTP_302_FOUND,
            )

        _prune_auth_cache(datetime.now(timezone.utc))
        auth_code = generate_token(32)
        authorization_codes[auth_code] = {
            "user_info": {
                "provider": provider,
                "sub": user_info["sub"],
                "email": email.lower(),
                "name": name,
                "picture": user_info.get("picture"),
                # The provider's own claim, which decides whether this identity may join an
                # account that already exists at this address. See `_extract_email_verified` for
                # why an absent claim reads as false.
                "email_verified": _extract_email_verified(user_info),
            },
            "client_id": auth_request["client_id"],
            "redirect_uri": auth_request["redirect_uri"],
            "scope": auth_request["scope"],
            "code_challenge": auth_request.get("code_challenge"),
            "code_challenge_method": auth_request.get("code_challenge_method"),
            "timestamp": datetime.now(timezone.utc),
        }
        if auth_request.get("setup_operator_token"):
            authorization_codes[auth_code]["setup_operator_token"] = auth_request["setup_operator_token"]
        _prune_auth_cache(datetime.now(timezone.utc))

        params = {"code": auth_code}
        if auth_request["state"]:
            params["state"] = auth_request["state"]
        return RedirectResponse(
            url=f"{auth_request['redirect_uri']}?{urlencode(params)}",
            status_code=status.HTTP_302_FOUND,
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Authentication error: %s", exc)
        oauth_state = request.query_params.get("state")
        if oauth_state and oauth_state in pkce_challenges:
            auth_request = pkce_challenges[oauth_state]
            error_params = {"error": "server_error", "error_description": "Authentication failed"}
            if auth_request["state"]:
                error_params["state"] = auth_request["state"]
            return RedirectResponse(
                url=f"{auth_request['redirect_uri']}?{urlencode(error_params)}",
                status_code=status.HTTP_302_FOUND,
            )
        return JSONResponse(
            status_code=400,
            content={"error": "server_error", "error_description": "Authentication failed"},
        )


# ---------------------------------------------------------------------------
# OAuth /token
# ---------------------------------------------------------------------------
@auth_router.post("/token")
async def token_endpoint(
    background_tasks: BackgroundTasks,
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    if grant_type == "authorization_code":
        if not all([code, redirect_uri, client_id, code_verifier]):
            raise HTTPException(
                status_code=400,
                detail="Missing one or more required parameters: code, redirect_uri, client_id, code_verifier",
            )
        return await _grant_authorization_code(
            db=db,
            background_tasks=background_tasks,
            code=code,           # type: ignore[arg-type]
            redirect_uri=redirect_uri,  # type: ignore[arg-type]
            client_id=client_id,        # type: ignore[arg-type]
            code_verifier=code_verifier,
        )
    if grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(status_code=400, detail="Missing required parameter: refresh_token")
        return await _grant_refresh_token(background_tasks=background_tasks, refresh_token=refresh_token)
    if grant_type == "client_credentials":
        if not client_id or not client_secret:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "client_id and client_secret are required"},
            )
        return await _grant_client_credentials(db=db, client_id=client_id, client_secret=client_secret)

    raise HTTPException(
        status_code=400,
        detail="Unsupported grant_type. Only 'authorization_code', 'refresh_token', and 'client_credentials' are supported.",
    )


async def _grant_authorization_code(
    *,
    db: Session,
    background_tasks: BackgroundTasks,
    code: str,
    redirect_uri: str,
    client_id: str,
    code_verifier: Optional[str],
):
    if code not in authorization_codes:
        raise HTTPException(status_code=400, detail="Invalid or expired authorization code")
    auth_data = authorization_codes[code]
    _prune_auth_cache(datetime.now(timezone.utc))

    if client_id != auth_data["client_id"]:
        raise HTTPException(status_code=400, detail="Invalid client_id")
    if redirect_uri != auth_data["redirect_uri"]:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    if datetime.now(timezone.utc) - auth_data["timestamp"] > _AUTH_CACHE_TTL:
        del authorization_codes[code]
        raise HTTPException(status_code=400, detail="Authorization code expired")

    if auth_data.get("code_challenge"):
        if not code_verifier:
            raise HTTPException(status_code=400, detail="Missing code_verifier for PKCE")
        if auth_data["code_challenge_method"] == "S256":
            digest = hashlib.sha256(code_verifier.encode()).digest()
            verifier_challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        else:
            verifier_challenge = code_verifier
        if not secrets.compare_digest(verifier_challenge, auth_data["code_challenge"]):
            raise HTTPException(status_code=400, detail="Invalid code_verifier")

    del authorization_codes[code]

    info = auth_data["user_info"]
    try:
        user = person_service.get_or_create_user_by_oidc_identity(
            db,
            oidc_provider=info.get("provider") or "google",
            oidc_subject=info["sub"],
            email=info.get("email", ""),
            name=info.get("name", ""),
            picture=info.get("picture"),
            # The one place all three sign-in methods converge, which is why the linking rule lives
            # behind this call rather than in any of the three legs — Google's callback, the OTP leg
            # and the password leg all arrive here with the same payload shape.
            email_verified=bool(info.get("email_verified")),
        )
        db.commit()
    except PermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc))
    except person_service.IdentityLinkRefused as exc:
        # A 409, not a 401 or 403: the credential was good and the person is permitted, but this
        # identity cannot be joined to an account that already holds this address without proof
        # nobody has supplied. A 401 would send them to retry a sign-in that fails identically
        # forever; the message names the way out instead.
        db.rollback()
        logger.warning("Identity link refused for %r: %s", info.get("email"), exc)
        raise HTTPException(status_code=409, detail=str(exc))

    if not user:
        raise HTTPException(status_code=500, detail="Failed to create or retrieve user")
    logger.info("User authenticated: %s (%s)", user.email, user.id)

    # Setup-operator one-shot promotion: when the wizard hands off via OAuth.
    setup_op_token = auth_data.get("setup_operator_token")
    if setup_op_token:
        # `get_secret`, not `get`: this key is written with `is_secret=True`, so it lives in the
        # cache's `_secrets` map. `get()` reads only `_values` and defaults, which would silently
        # find nothing here — and with no operator, `_compute_roles` never grants `platform:admin`,
        # so `/system/*` would stay unreachable.
        stored = platform_settings.get_secret("platform.setup_operator_token")
        if (
            stored
            and not platform_settings.get("platform.operator_id")
            and platform_settings.get("platform.setup_complete") == "true"
            and secrets.compare_digest(stored, setup_op_token)
        ):
            platform_settings.set_many(
                db,
                [
                    {"key": "platform.operator_id", "value": str(user.id), "category": "platform", "is_secret": False},
                    {"key": "platform.setup_operator_token", "value": "", "category": "platform", "is_secret": True},
                ],
                updated_by=str(user.id),
            )
            logger.info("Setup token validated: promoted %s (%s) to platform operator", user.email, user.id)

    issuing_client_id = auth_data["client_id"]

    if _is_first_party_client(issuing_client_id):
        # First-party client → full user JWT
        user_data = {
            "sub": str(user.id),
            "email": user.email,
            "name": user.name,
            "picture": user.picture,
            "roles": _compute_roles(str(user.id)),
            "client_id": issuing_client_id,
            "aud": config.AUTHORITY_ISSUER,
        }
    else:
        # Third-party MCP OAuth client → scoped token: no email, no name, no picture, no roles,
        # and `aud` is the client rather than this authority. The user is present only as `sub`,
        # which is what makes the token delegable at all.
        #
        # `scopes` records what the client asked for. Nothing has vouched for this client, so
        # this is a record of the request and not a per-client entitlement — the resource server
        # authorizes an `mcp_client` principal on its own terms.
        granted_scopes = sorted(set((auth_data.get("scope") or "read").split())) or ["read"]
        user_data = {
            "sub": str(user.id),
            "aud": issuing_client_id,
            "principal_type": "mcp_client",
            "scopes": granted_scopes,
        }
        # A first-party client the operator forgot to enrol lands here and silently receives a
        # token its own backend will reject. Say so by name, once per grant, rather than leaving
        # the operator to discover it as a sign-in that fails downstream for no stated reason.
        logger.warning(
            "Minting a scoped mcp_client token for client_id=%s — not a configured first-party "
            "client. %s",
            issuing_client_id,
            _FIRST_PARTY_HINT,
        )

    access_token = create_jwt_token(user_data)
    refresh_token = create_jwt_token({**user_data, "token_type": "refresh"}, expires_hours=24 * 30)

    background_tasks.add_task(person_service.record_person_event, user_data, "auth_grant")
    return JSONResponse(
        content={
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": access_token_expires_in_seconds(),
            "refresh_token": refresh_token,
            "scope": auth_data["scope"],
        }
    )


async def _grant_refresh_token(*, background_tasks: BackgroundTasks, refresh_token: str):
    """Exchange a refresh token for a fresh access token. Not rotated, and not revocable.

    Refresh tokens are stateless JWTs: nothing is written at mint time, so there is nothing to
    consult here and nothing a password reset could mark. `password_reset_confirm` invalidates the
    reset *link*, via `_pw_fingerprint`, and evicts nobody. A stolen refresh token is therefore live
    for its full 30 days.

    Making one revocable means giving it state — a `jti` stored at mint and consumed here, so that a
    second presentation of the same `jti` is proof of theft and revokes the chain. Revoking every
    token for one person at once instead wants a `password_changed_at` column on `persons`, stamped
    into the token and compared here.

    Neither reaches a peer. Peers verify Origin's tokens offline against the inline JWKS in their
    authority manifest and never call back, so anything decided here binds at Origin only. The
    platform-wide revocation lag is the access token lifetime, which
    `auth_service.access_token_ttl_hours` brackets.
    """
    payload = verify_token(refresh_token)
    if not payload or payload.get("token_type") != "refresh":
        raise HTTPException(status_code=400, detail="Invalid refresh token")
    if not payload.get("aud"):
        raise HTTPException(status_code=400, detail="Refresh token has no audience — please log in again")

    user_data = {k: v for k, v in payload.items() if k not in ("exp", "token_type", "iat")}

    # Re-derived from current platform state rather than replayed from what the refresh token was
    # minted with. Refresh tokens live 30 days: copying `roles` through would let a demoted operator
    # keep `platform:admin` for up to a month after losing it — there is no revocation list and no
    # rotation, so the refresh token itself cannot be invalidated.
    subject = payload.get("sub")
    if subject and not payload.get("principal_type"):
        user_data["roles"] = _compute_roles(str(subject))
    else:
        # A scoped `mcp_client` refresh token carries a `sub` too, and deriving roles from it
        # would hand a third-party client the operator's `platform:admin` on the first refresh —
        # the PII-free token growing authority it was minted without.
        user_data.pop("roles", None)

    access_token = create_jwt_token(user_data)
    background_tasks.add_task(person_service.record_person_event, user_data, "refresh_grant")
    return JSONResponse(
        content={
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": access_token_expires_in_seconds(),
            "scope": " ".join(user_data.get("scopes", [])) or "read write",
        }
    )


async def _grant_client_credentials(*, db: Session, client_id: str, client_secret: str):
    """OAuth client_credentials grant — exchanges a registered client secret for a 1-hour JWT.

    Despite the OAuth-client naming, this does not mint an `mcp_client` token. It mints
    `principal_type: "server"` with `aud: "agience"` from a `server_credentials` row. The
    `mcp_client` principal is minted only by the authorization_code path above. Credentials are
    created operator-only through `/auth/clients` (`server_credentials_router`), and no client
    *artifact* is involved.

    `POST /auth/register` does not feed this grant. Dynamic registration writes `oauth_clients`, a
    separate table of public clients with no secret; nothing it produces can authenticate here,
    which is why it is a separate table rather than a row in `server_credentials` with a fabricated
    secret and a fabricated host id.

    Platform services do not request tokens from Origin: they sign their own with their service
    key, and peers verify via the inline JWKS in the platform authority manifest.

    A `principal_type: "server"` token addresses no endpoint on this platform. Every authenticated
    Origin route requires either `principal_type == "user"` (`/system`, `/oracle`, `/auth/clients`,
    passkey, and the `get_person` routes, which need a `user_id` this context never carries) or
    `principal_type == "service"` (`/internal/*`), and peers reject the type outright.
    """
    credential = db_server_credentials.get_by_client_id(db, client_id)
    if not credential or not credential.is_active:
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_client", "error_description": "Unknown or inactive client_id"},
        )
    if not bcrypt.checkpw(client_secret.encode(), credential.secret_hash.encode()):
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_client", "error_description": "Invalid client_secret"},
        )
    db_server_credentials.update_last_used(db, credential.id)
    db.commit()

    server_claims = {
        "sub": f"server/{credential.client_id}",
        "aud": "agience",
        "principal_type": "server",
        "authority": credential.authority,
        "host_id": str(credential.host_id),
        "server_id": str(credential.server_id),
        "client_id": credential.client_id,
        "scopes": list(credential.scopes or []),
        "resource_filters": dict(credential.resource_filters or {}),
    }
    return JSONResponse(
        content={
            "access_token": create_jwt_token(server_claims, expires_hours=1),
            "token_type": "bearer",
            "expires_in": 3600,
        }
    )


# ---------------------------------------------------------------------------
# RFC 7591 dynamic client registration
# ---------------------------------------------------------------------------
# A client with no `client_id` cannot reach `/authorize` at all. This endpoint is how an MCP
# client that registers itself gets one, instead of an operator hand-minting a token into a static
# header and re-minting it when it expires.
#
# What is registered here is enforced at `/authorize`, in both directions. A `client_id` must be
# configured or registered to start a flow at all, and a registered client is held to the
# `redirect_uris` in its row — so `redirect_uris` below is not a description, it is the address list
# this authority will deliver that client's codes to and the only one.
#
# Two consequences worth stating where they are created rather than discovered later:
#
# · A registration is not revoked by turning this endpoint off. `CLIENT_REGISTRATION_ENABLED`
#   governs whether new rows can be written; `/authorize` reads the table either way. Disabling
#   registration stops enrolment, it does not evict the clients already enrolled — evicting one
#   means deleting its row.
# · A registration is not a vouching. `_is_first_party_client` still does not read this table, so a
#   client that enrolled itself is admitted to the flow and still receives the scoped `mcp_client`
#   token. Being allowed in and being trusted are different questions with different answers.

#: Marks a `client_id` as one this endpoint minted. It appears in the `aud` of every token issued to
#: that client, so an operator reading a token, a log line or the table can tell a self-registered
#: client from a configured first-party id without a lookup — and `_is_first_party_client` answers
#: "third party" for it, which is the correct and visible answer.
_DCR_CLIENT_ID_PREFIX = "dcr_"

#: RFC 7591 §3.2.1 — registration responses carry a credential-shaped identifier, so they are not
#: cacheable. Same headers the local sign-in page sets.
_DCR_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}

#: What a registration may name. Not RFC 7591's full vocabulary — what `/token` above actually
#: implements for a client with no secret. `client_credentials` is the third grant this authority
#: supports and is absent by construction: it authenticates with a `client_secret` that this
#: endpoint does not issue and `server_credentials` is the table that holds.
_REGISTRABLE_GRANT_TYPES = ("authorization_code", "refresh_token")
#: `/authorize` refuses every `response_type` but `code`, so registering another would record a
#: capability this authority answers 400 to.
_REGISTRABLE_RESPONSE_TYPES = ("code",)
#: The only client authentication a public PKCE client has, and the only one this table can record
#: honestly — there is no secret column. RFC 7591 §2 defaults this field to `client_secret_basic`
#: when omitted; that default cannot apply here, so an omission is registered as `none` and returned
#: as `none`, which §3.2.1 provides for ("the value the authorization server registered").
_PUBLIC_CLIENT_AUTH_METHOD = "none"


class _RegistrationRefused(Exception):
    """An RFC 7591 §3.2.2 error, carrying the code an MCP client reads to decide what to say."""

    def __init__(self, error: str, description: str):
        super().__init__(description)
        self.error = error
        self.description = description


def _registration_error(status_code: int, error: str, description: str, **extra_headers) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "error_description": description},
        headers={**_DCR_NO_STORE, **extra_headers},
    )


def _client_registration_enabled() -> bool:
    return bool(getattr(config, "CLIENT_REGISTRATION_ENABLED", False))


def _client_registration_gate_token() -> str:
    """The RFC 7591 §3 initial access token, or empty for open registration."""
    return (getattr(config, "CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN", "") or "").strip()


def _presented_bearer(request: Request) -> str:
    header = request.headers.get("authorization") or ""
    scheme, _, value = header.partition(" ")
    return value.strip() if scheme.lower() == "bearer" else ""


def _validated_redirect_uris(raw) -> list[str]:
    """Every registered redirect must be one `/authorize` would honour.

    THE AGREEMENT IS THE POINT. `is_client_redirect_allowed` is the gate `/authorize` applies to
    every client, registered or not; it is what admits loopback, which is where an MCP client's
    callback lands. Registering a URI that gate would refuse promises delivery to an address this
    authority will never deliver to — a lie told at registration time, discovered by the client one
    whole browser round-trip later, as a 403 on a flow that had already worked twice.

    So the check here IS that function, called on each entry, plus two syntactic rules it does not
    apply because `/authorize` has no need of them: the URI must be absolute, and it must carry no
    fragment (RFC 6749 §3.1.2). Both narrow this endpoint relative to `/authorize`, which is the
    safe direction to differ in — a URI refused here is one that would have been honoured, never
    the reverse, so nothing registered is ever refused later.
    """
    if raw is None:
        raise _RegistrationRefused(
            "invalid_redirect_uri",
            "redirect_uris is required — a public client with no redirect target cannot complete "
            "an authorization code flow.",
        )
    if not isinstance(raw, list) or not raw:
        raise _RegistrationRefused(
            "invalid_redirect_uri", "redirect_uris must be a non-empty array of strings."
        )

    validated: list[str] = []
    for entry in raw:
        if not isinstance(entry, str) or not entry.strip():
            raise _RegistrationRefused(
                "invalid_redirect_uri", "every redirect_uris entry must be a non-empty string."
            )
        uri = entry.strip()
        parsed = urlparse(uri)
        if not parsed.scheme or not parsed.netloc:
            raise _RegistrationRefused(
                "invalid_redirect_uri", f"redirect_uri is not an absolute URI: {uri!r}"
            )
        if parsed.fragment:
            # RFC 6749 §3.1.2: the redirection endpoint URI MUST NOT include a fragment component.
            raise _RegistrationRefused(
                "invalid_redirect_uri", f"redirect_uri must not contain a fragment: {uri!r}"
            )
        if not is_client_redirect_allowed(uri):
            # Named settings, for the same reason `/authorize` names them: the operator is the only
            # reader who can act on this, and the two ways to be here are a facet this authority has
            # not been told about and a caller asking for somewhere it may not go.
            raise _RegistrationRefused(
                "invalid_redirect_uri",
                f"redirect_uri {uri!r} is not one this authority will deliver a code to — its base "
                "is not among FACET_URI/FACET_URIS/ORIGIN_URI and it is not loopback. Registering "
                "it would promise a delivery /authorize refuses.",
            )
        validated.append(uri)
    return validated


def _validated_string_list(raw, field: str, permitted: tuple[str, ...], default: tuple[str, ...]) -> list[str]:
    """`grant_types` / `response_types` — omitted takes RFC 7591 §2's default, present is checked."""
    if raw is None:
        return list(default)
    if not isinstance(raw, list) or not raw or not all(isinstance(v, str) for v in raw):
        raise _RegistrationRefused(
            "invalid_client_metadata", f"{field} must be a non-empty array of strings."
        )
    unsupported = [v for v in raw if v not in permitted]
    if unsupported:
        raise _RegistrationRefused(
            "invalid_client_metadata",
            f"{field} contains values this authority does not issue to a public client: "
            f"{', '.join(sorted(unsupported))}. Supported: {', '.join(permitted)}.",
        )
    # Order is not meaningful in either field; de-duplicated so the stored row and the response say
    # the same thing once.
    return sorted(set(raw))


def _validated_client_name(raw) -> Optional[str]:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise _RegistrationRefused("invalid_client_metadata", "client_name must be a string.")
    name = raw.strip()
    if not name:
        return None
    # The bound is the column's own width rather than a number chosen here, so the value that fits
    # the response is exactly the value that fits the table — a longer name is refused at the door
    # instead of being truncated into a row that no longer matches what was returned.
    limit = OAuthClient.client_name.type.length
    if len(name) > limit:
        raise _RegistrationRefused(
            "invalid_client_metadata", f"client_name is longer than {limit} characters."
        )
    return name


@auth_router.post("/register", dependencies=None, status_code=status.HTTP_201_CREATED)
async def register_client(request: Request, db: Session = Depends(get_db)):
    """RFC 7591 §3.1 — a client describes itself, this authority mints it a `client_id`.

    Off unless an operator turns it on (`CLIENT_REGISTRATION_ENABLED`), and gated by an initial
    access token when one is configured (`CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN`). Open
    registration writes rows to `oauth_clients` for any caller who can reach this path, which is
    what a home node wants and what a public identity service must not have; the setting is the
    whole of that difference, and off is the default because open is the half that cannot be undone
    by configuration after the fact.

    No rate limit. In open mode an anonymous caller can register without bound, and the answer
    offered here is the gate rather than a counter: a limiter tuned to a number invented in this
    file would slow an attacker and still fill the table, while making a legitimate node's first-run
    registration fail intermittently for a reason no operator could see. The password limiter exists
    because there is a secret to guess; there is nothing to guess here.

    Fields outside the set below — `client_uri`, `logo_uri`, `contacts`, `scope`, `software_id`,
    `software_statement` and the rest of RFC 7591 §2 — are ignored rather than refused: a client
    that sends them must still be able to register, and §3.2.1 makes the response the record of what
    was in fact registered, so an ignored field is one the client can see was not stored.

    RFC 7592 (read/update/delete a registration) is not implemented, so no `registration_access_token`
    and no `registration_client_uri` are returned. Both are optional in §3.2.1, and returning them
    without the endpoint behind them would be the same lie in a different field.
    """
    if not _client_registration_enabled():
        return _registration_error(
            403,
            "access_denied",
            "Dynamic client registration is not enabled on this authority. An operator enables it "
            "with CLIENT_REGISTRATION_ENABLED=true, and may gate it with "
            "CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN.",
        )

    gate_token = _client_registration_gate_token()
    if gate_token:
        presented = _presented_bearer(request)
        # Compared as bytes, not as strings: `compare_digest` on `str` raises TypeError unless both
        # sides are ASCII-only, and the presented side is whatever an anonymous caller put in a
        # header — a 500 on a header nobody validated is a worse answer than a 401.
        if not presented or not secrets.compare_digest(
            presented.encode("utf-8"), gate_token.encode("utf-8")
        ):
            # RFC 7591 §3: the initial access token is an OAuth 2.0 access token, so a bad one is
            # answered the way RFC 6750 §3.1 answers any bad bearer token.
            return _registration_error(
                401,
                "invalid_token",
                "This authority requires an initial access token to register a client. Present the "
                "operator's CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN as a bearer token.",
                **{"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

    try:
        payload = await request.json()
    except Exception:
        return _registration_error(
            400, "invalid_client_metadata", "The request body is not valid JSON."
        )
    if not isinstance(payload, dict):
        return _registration_error(
            400, "invalid_client_metadata", "The request body must be a JSON object."
        )

    try:
        redirect_uris = _validated_redirect_uris(payload.get("redirect_uris"))
        grant_types = _validated_string_list(
            payload.get("grant_types"), "grant_types",
            _REGISTRABLE_GRANT_TYPES, ("authorization_code",),
        )
        response_types = _validated_string_list(
            payload.get("response_types"), "response_types",
            _REGISTRABLE_RESPONSE_TYPES, ("code",),
        )
        # RFC 7591 §2 ties the two together: a client using the `authorization_code` grant uses the
        # `code` response type. Registering one without the other records a client that cannot
        # complete a flow.
        if ("authorization_code" in grant_types) != ("code" in response_types):
            raise _RegistrationRefused(
                "invalid_client_metadata",
                "grant_types and response_types disagree — the authorization_code grant and the "
                "code response type are registered together or not at all.",
            )
        auth_method = payload.get("token_endpoint_auth_method")
        if auth_method is not None and auth_method != _PUBLIC_CLIENT_AUTH_METHOD:
            raise _RegistrationRefused(
                "invalid_client_metadata",
                f"token_endpoint_auth_method must be {_PUBLIC_CLIENT_AUTH_METHOD!r}: this endpoint "
                "registers public clients that prove themselves with PKCE and issues no "
                "client_secret.",
            )
        client_name = _validated_client_name(payload.get("client_name"))
    except _RegistrationRefused as refused:
        return _registration_error(400, refused.error, refused.description)

    # The same generator and length `/authorize` uses for `oauth_state`, which lives in the same
    # request path and must be equally unguessable — a `client_id` an attacker can predict is one
    # they can register over or impersonate in a log. Not a number chosen here.
    client_id = f"{_DCR_CLIENT_ID_PREFIX}{generate_token(32)}"
    issued_at = datetime.now(timezone.utc)

    db_oauth_clients.create(db, {
        "client_id": client_id,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "token_endpoint_auth_method": _PUBLIC_CLIENT_AUTH_METHOD,
        "client_id_issued_at": issued_at,
    })
    db.commit()

    logger.info(
        "Registered OAuth client %s (%s) for %d redirect uri(s): %s",
        client_id, client_name or "unnamed", len(redirect_uris), ", ".join(redirect_uris),
    )

    # §3.2.1: the response states what was registered, and nothing else. `client_id_issued_at` is
    # seconds since the epoch, as the RFC defines it. No `client_secret`, so no
    # `client_secret_expires_at` — that field is required only alongside a secret.
    body = {
        "client_id": client_id,
        "client_id_issued_at": int(issued_at.timestamp()),
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "token_endpoint_auth_method": _PUBLIC_CLIENT_AUTH_METHOD,
    }
    if client_name:
        body["client_name"] = client_name
    return JSONResponse(status_code=201, content=body, headers=_DCR_NO_STORE)


# ---------------------------------------------------------------------------
# /providers
# ---------------------------------------------------------------------------
@auth_router.get("/providers", dependencies=None)
async def list_providers():
    providers = sorted(
        (
            {"name": name, "label": meta.get("label", name), "type": meta.get("type", "oidc")}
            for name, meta in REGISTERED_PROVIDERS.items()
        ),
        key=lambda p: p["label"],
    )
    email_configured = False
    try:
        from origin.services.email_service import is_configured as _email_configured

        email_configured = _email_configured()
    except Exception:
        email_configured = False
    return {
        "providers": providers,
        "password": platform_settings.get_bool("auth.password.enabled", True),
        "otp": email_configured,
    }


# ---------------------------------------------------------------------------
# Password login + register
# ---------------------------------------------------------------------------
@auth_router.post("/password/login")
async def password_login(
    background_tasks: BackgroundTasks,
    payload: PasswordLoginRequest,
    db: Session = Depends(get_db),
):
    if not platform_settings.get_bool("auth.password.enabled", True):
        raise HTTPException(status_code=404, detail="Password auth is disabled")

    identifier = (payload.identifier or "").strip()
    password = payload.password or ""
    if not identifier or not password:
        raise HTTPException(status_code=400, detail="Username and password are required")

    _reject_if_password_budget_spent(identifier)

    if "@" in identifier:
        user = person_service.get_user_by_email(db, identifier.lower())
    else:
        user = person_service.get_user_by_username(db, identifier)

    if not user or not user.password_hash:
        dummy_verify_password(password)
        _charge_password_failure(identifier, "no such account or no password set")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not verify_password(password, user.password_hash):
        _charge_password_failure(identifier, "wrong password")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    guess_budget.clear_password_failures(identifier)
    _upgrade_password_hash_if_stale(db, user, password)

    # Block sign-in until the email is verified (when verification is required for
    # this email). Resend the link inline (await) so the user recovers in one step
    # — the handler raises, so a background task wouldn't run.
    if not user.email_verified and email_verification_required(user.email):
        await _send_verification_email(user)
        raise HTTPException(
            status_code=403,
            detail="Please verify your email to sign in. We've sent you a new verification link.",
        )

    user_data = {
        "sub": str(user.id),
        "email": user.email,
        "name": user.name,
        "picture": user.picture,
        "roles": _compute_roles(str(user.id)),
        "client_id": getattr(config, "PLATFORM_CLIENT_ID", "platform"),
        "aud": config.AUTHORITY_ISSUER,
    }
    access_token = create_jwt_token(user_data)
    refresh_token = create_jwt_token({**user_data, "token_type": "refresh"}, expires_hours=24 * 30)
    background_tasks.add_task(person_service.record_person_event, user_data, "password_login")

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": access_token_expires_in_seconds(),
        "refresh_token": refresh_token,
        "scope": "read write",
    }


@auth_router.post("/password/register")
async def password_register(
    background_tasks: BackgroundTasks,
    payload: PasswordRegisterRequest,
    db: Session = Depends(get_db),
):
    if not platform_settings.get_bool("auth.password.enabled", True):
        raise HTTPException(status_code=404, detail="Password auth is disabled")

    username = (payload.username or "").strip()
    email = (payload.email or "").strip().lower()
    password = payload.password or ""
    name = (payload.name or "").strip()

    if not username:
        raise HTTPException(status_code=400, detail="Username is required")
    if email and "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email address")
    min_len = platform_settings.get_int("auth.password.min_length", 12)
    if len(password) < min_len:
        raise HTTPException(status_code=400, detail=f"Password must be at least {min_len} characters")

    verify_required = email_verification_required(email)
    try:
        user = person_service.create_user_with_password(
            db,
            username=username,
            name=name,
            password_hash=hash_password(password),
            email=email,
            email_verified=not verify_required,
        )
        db.commit()
    except PermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        db.rollback()
        logger.info("Password registration failed for username=%r (%s)", username, exc)
        raise HTTPException(status_code=400, detail="Registration failed")

    # Verification required: don't auto-login — send the link and tell the client
    # to prompt for confirmation. The user signs in after verifying.
    if verify_required:
        _queue_verification_email(background_tasks, user)
        return {"verification_required": True, "email": user.email}

    user_data = {
        "sub": str(user.id),
        "email": user.email,
        "name": user.name,
        "picture": user.picture,
        "roles": _compute_roles(str(user.id)),
        "client_id": getattr(config, "PLATFORM_CLIENT_ID", "platform"),
        "aud": config.AUTHORITY_ISSUER,
    }
    access_token = create_jwt_token(user_data)
    refresh_token = create_jwt_token({**user_data, "token_type": "refresh"}, expires_hours=24 * 30)
    background_tasks.add_task(person_service.record_person_event, user_data, "password_register")

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": access_token_expires_in_seconds(),
        "refresh_token": refresh_token,
        "scope": "read write",
    }


# ---------------------------------------------------------------------------
# Email verification
# ---------------------------------------------------------------------------
@auth_router.post("/email/verify-request")
async def email_verify_request(
    background_tasks: BackgroundTasks,
    payload: EmailVerifyRequestBody,
    db: Session = Depends(get_db),
):
    """Resend an email-verification link. Always returns 200 (never reveals
    whether the email exists); no-op if already verified. Email must be
    configured."""
    if not email_service.is_configured():
        raise HTTPException(status_code=503, detail="Email service not configured.")
    email = (payload.email or "").strip().lower()
    user = person_service.get_user_by_email(db, email) if email else None
    if user and user.email and not user.email_verified:
        _queue_verification_email(background_tasks, user)
        logger.info("Verification email re-queued for %s", email)
    return {"sent": True}


@auth_router.post("/email/verify-confirm")
async def email_verify_confirm(
    background_tasks: BackgroundTasks,
    payload: EmailVerifyConfirmBody,
    db: Session = Depends(get_db),
):
    """Confirm an email-verification token, mark the email verified, and sign the
    user in (magic-link UX)."""
    claims = verify_token(payload.token)
    if not claims or claims.get("token_type") != "email_verify" or not claims.get("sub"):
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")

    user = person_service.get_user_by_id(db, str(claims["sub"]))
    if user is None:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")

    # Single-use, by the same mechanism the reset tokens use — see `_email_fingerprint`. Without it
    # this endpoint is replayable for the token's full 24 hours, and each replay re-mints a 30-day
    # refresh token. That is not a theoretical replay: `web/verify-email.html` POSTs here on page
    # load with no interaction, so a link scanner, a mail-security crawler or a revisit from
    # history redeems the link again by itself.
    if _email_fingerprint(user) != claims.get("evf"):
        logger.warning("email verification token replayed or stale for person %s", user.id)
        raise HTTPException(
            status_code=400,
            detail="This verification link is no longer valid. Request a new one.",
        )

    person_service.set_email_verified(db, str(user.id), True)
    db.commit()

    user_data = {
        "sub": str(user.id),
        "email": user.email,
        "name": user.name,
        "picture": user.picture,
        "roles": _compute_roles(str(user.id)),
        "client_id": getattr(config, "PLATFORM_CLIENT_ID", "platform"),
        "aud": config.AUTHORITY_ISSUER,
    }
    access_token = create_jwt_token(user_data)
    refresh_token = create_jwt_token({**user_data, "token_type": "refresh"}, expires_hours=24 * 30)
    background_tasks.add_task(person_service.record_person_event, user_data, "email_verified")

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": access_token_expires_in_seconds(),
        "refresh_token": refresh_token,
        "scope": "read write",
    }


# ---------------------------------------------------------------------------
# Password reset (forgot-password)
# ---------------------------------------------------------------------------
def _pw_fingerprint(password_hash: str | None) -> str:
    """A short, non-reversible fingerprint of the current password hash. Embedded
    in the reset token so the token becomes single-use: once the password changes
    (this reset, or any other), the fingerprint no longer matches and a reused or
    stale token is rejected."""
    return hashlib.sha256((password_hash or "").encode()).hexdigest()[:16]


def _email_fingerprint(user) -> str:
    """A short, non-reversible fingerprint of the state redeeming the link necessarily changes.

    The same trick as `_pw_fingerprint`, over the two fields that matter here. `email_verified`
    flips False → True at redemption, so a redeemed token's fingerprint no longer matches anything
    and the link stops working the moment it works — single-use with no token store, no `jti` and
    no revocation list, exactly as the reset path gets it.

    The address is in the fingerprint for the second case: a link minted for one address must not
    still verify the account after its owner changes to another. One bit of state would also be a
    guessable fingerprint; hashed together with the address it is not.
    """
    email = (getattr(user, "email", "") or "").lower()
    verified = bool(getattr(user, "email_verified", False))
    return hashlib.sha256(f"{email}|{verified}".encode()).hexdigest()[:16]


def _verification_url(user) -> str:
    """Mint a 24h email-verification token and return the Facet verify link.

    Takes the person rather than an id because the token binds a fingerprint of their current
    state; both callers already hold one.
    """
    token = create_jwt_token(
        {
            "sub": str(user.id),
            "token_type": "email_verify",
            "evf": _email_fingerprint(user),
            "aud": config.AUTHORITY_ISSUER,
        },
        expires_hours=24,
    )
    return f"{config.FACET_URI.rstrip('/')}/verify-email?token={token}"


def _queue_verification_email(background_tasks: BackgroundTasks, user) -> None:
    """Queue the verification email as a background task (for 2xx responses, where
    background tasks actually run). No-op for accounts without an email."""
    if not getattr(user, "email", None):
        return
    background_tasks.add_task(email_service.send_email_verification, user.email, _verification_url(user))


async def _send_verification_email(user) -> None:
    """Send the verification email inline (await). Used on the login-block path,
    where the handler raises and FastAPI would discard background tasks.
    Best-effort: a send failure must not change the 403 the user sees."""
    if not getattr(user, "email", None):
        return
    try:
        await email_service.send_email_verification(user.email, _verification_url(user))
    except Exception:
        logger.warning("Failed to send verification email to %s", user.email, exc_info=True)


@auth_router.post("/password/reset-request")
async def password_reset_request(
    background_tasks: BackgroundTasks,
    payload: PasswordResetRequestBody,
    db: Session = Depends(get_db),
):
    """Begin a password reset. Always returns 200 (never reveals whether the
    email exists). When the email maps to a person who already has a password,
    emails a short-lived reset link. Email must be configured (same dependency
    as OTP)."""
    if not platform_settings.get_bool("auth.password.enabled", True):
        raise HTTPException(status_code=404, detail="Password auth is disabled")
    if not email_service.is_configured():
        raise HTTPException(
            status_code=503,
            detail="Email service not configured — cannot send a reset link.",
        )

    email = (payload.email or "").strip().lower()
    user = person_service.get_user_by_email(db, email) if email else None
    # Only send when the account exists AND already has a password (OAuth/OTP-only
    # accounts have nothing to reset). Don't reveal either way to the caller.
    if user and user.password_hash:
        reset_token = create_jwt_token(
            {
                "sub": str(user.id),
                "token_type": "pwd_reset",
                "pwf": _pw_fingerprint(user.password_hash),
                "aud": config.AUTHORITY_ISSUER,
            },
            expires_hours=1,
        )
        reset_url = f"{config.FACET_URI.rstrip('/')}/reset-password?token={reset_token}"
        background_tasks.add_task(email_service.send_password_reset, user.email, reset_url)
        logger.info("Password reset email queued for %s", email)
    else:
        logger.info("Password reset requested for unknown/passwordless email: %s", email)
    return {"sent": True}


@auth_router.post("/password/reset-confirm")
async def password_reset_confirm(
    payload: PasswordResetConfirmBody,
    db: Session = Depends(get_db),
):
    """Complete a password reset: verify the reset token, enforce the password
    policy, and set the new password. The token expires in 1 hour; there is no
    revocation list, so single-use is enforced by the fingerprint check in
    `_pw_fingerprint`, not by consuming the token."""
    if not platform_settings.get_bool("auth.password.enabled", True):
        raise HTTPException(status_code=404, detail="Password auth is disabled")

    claims = verify_token(payload.token)
    if not claims or claims.get("token_type") != "pwd_reset" or not claims.get("sub"):
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    min_len = platform_settings.get_int("auth.password.min_length", 12)
    if len(payload.new_password or "") < min_len:
        raise HTTPException(status_code=400, detail=f"Password must be at least {min_len} characters")

    # Single-use check: the token's fingerprint must still match the current hash.
    user = person_service.get_user_by_id(db, str(claims["sub"]))
    if not user or not user.password_hash or _pw_fingerprint(user.password_hash) != claims.get("pwf"):
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    person_service.set_password(db, str(user.id), hash_password(payload.new_password))
    db.commit()
    return {"reset": True}


# ---------------------------------------------------------------------------
# /auth/bootstrap/claim — first-operator bootstrap
# ---------------------------------------------------------------------------

class BootstrapClaimRequest(BaseModel):
    """Body for `POST /auth/bootstrap/claim`. The token comes from init's stdout."""
    model_config = ConfigDict(extra="forbid")
    token: str
    email: Optional[str] = None
    name: Optional[str] = None
    password: Optional[str] = None


class BootstrapClaimResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    person_id: str


@auth_router.post("/bootstrap/claim", response_model=BootstrapClaimResponse)
async def bootstrap_claim(body: BootstrapClaimRequest, db: Session = Depends(get_db)):
    """Claim the platform's bootstrap token to create the first operator.

    On first boot the key initialisation step generates a random token, prints
    it to stdout, and stores its sha256 in the platform authority manifest. The
    operator presents the cleartext token here exactly once; in exchange they
    get a person record, a `can_admin` grant on the authority artifact, and
    an access token. After this call, `platform.setup_complete=true` blocks
    any further claim attempts.

    Single-use. Consumes the bootstrap regardless of email/password — if
    those fields are absent, the operator is created passwordless and can
    later link an OAuth provider, set a password, or register a passkey.
    """
    from origin import authority_trust

    if (platform_settings.get("platform.setup_complete") or "").lower() == "true":
        raise HTTPException(status_code=410, detail="Bootstrap already completed")

    try:
        manifest = authority_trust.get_authority_manifest()
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="Authority manifest not found — re-run key initialisation",
        )

    if not manifest.bootstrap_token_hash:
        raise HTTPException(status_code=410, detail="Bootstrap token already consumed")

    presented_hash = hashlib.sha256(body.token.strip().encode("utf-8")).hexdigest()
    if not secrets.compare_digest(presented_hash, manifest.bootstrap_token_hash):
        raise HTTPException(status_code=401, detail="Invalid bootstrap token")

    if body.password and len(body.password) < 12:
        raise HTTPException(status_code=422, detail="Password must be at least 12 characters")

    op_email = (body.email or "").strip().lower()
    person_name = (body.name or "").strip() or (op_email.split("@")[0] if op_email else "operator")
    password_hash = hash_password(body.password) if body.password else None

    person = person_service.create_user_with_password(
        db,
        username=person_name,
        name=person_name,
        password_hash=password_hash or "",
        email=op_email,
    ) if password_hash else _create_passwordless_operator(
        db, email=op_email, name=person_name
    )

    operator_uuid = person.id  # native UUID for DB writes
    operator_id = str(person.id)  # str for JWT claims

    # The operator's authority is recorded by `platform.operator_id` (set below) — the root
    # signal every service honours. Data-plane authorization, the operator's admin grant on the
    # authority collection, lives in the peer that owns the store; Origin issues no grant.

    # Mark the bootstrap as consumed in platform_settings. This is the
    # canonical "claim happened" gate — checked at the top of this handler.
    # The artifact's bootstrap_token_hash field stays as-is (it's a hash,
    # informational only after this point).
    platform_settings.set_many(
        db,
        [
            {"key": "platform.setup_complete", "value": "true",
             "category": "platform", "is_secret": False},
            {"key": "platform.operator_id", "value": operator_id,
             "category": "platform", "is_secret": False},
        ],
        updated_by=operator_uuid,
    )
    db.commit()

    user_data = {
        "sub": operator_id,
        "email": op_email,
        "name": person_name,
        "picture": "",
        "roles": ["platform:admin"],
        "client_id": getattr(config, "PLATFORM_CLIENT_ID", "platform"),
        "aud": config.AUTHORITY_ISSUER,
    }
    access_token = create_jwt_token(user_data)
    refresh_token = create_jwt_token(
        {**user_data, "token_type": "refresh"}, expires_hours=24 * 30
    )

    logger.info(
        "Bootstrap claim consumed: operator=%s (%s)", person_name, operator_id
    )
    return BootstrapClaimResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        person_id=operator_id,
    )


def _create_passwordless_operator(db: Session, *, email: str, name: str) -> PersonModel:
    """Create the first operator without a password — they'll add one later
    via OAuth link, password reset, or passkey."""
    from origin.db import persons as db_persons

    if email and person_service.get_user_by_email(db, email):
        raise HTTPException(status_code=409, detail="Operator email already registered")
    return db_persons.create(
        db,
        {
            "email": email or None,
            "name": name,
            "username": name,
            "password_hash": None,
        },
    )


# ---------------------------------------------------------------------------
# /userinfo + /me/*
# ---------------------------------------------------------------------------
@auth_router.get("/userinfo")
async def user_info_endpoint(
    auth: AuthContext = Depends(get_auth),
    person: PersonModel = Depends(get_person),
):
    data = _person_to_dict(person)
    data["roles"] = _compute_roles(str(person.id))
    data["platform_user_id"] = config.AGIENCE_PLATFORM_USER_ID
    return data


@auth_router.get("/me/preferences")
async def get_preferences(
    auth: AuthContext = Depends(get_auth),
    person: PersonModel = Depends(get_person),
):
    return person.preferences or {}


@auth_router.patch("/me/preferences")
async def update_preferences(
    preferences: dict,
    auth: AuthContext = Depends(get_auth),
    person: PersonModel = Depends(get_person),
    db: Session = Depends(get_db),
):
    updated = person_service.update_preferences(db, str(person.id), preferences)
    db.commit()
    return updated.preferences or {}


# There is deliberately no `GET /auth/nonce` route, and `test_router_auth` pins its absence.
# Origin authenticates by signed JWT only, so the `principal_type == "api_key"` such a route would
# gate on is a value `resolve_auth` cannot produce. `auth_service.issue_nonce` stays: it is the
# minting half of the inbound-nonce pair whose verifying half lives in the resource server.


# ---------------------------------------------------------------------------
# /me/link-provider
# ---------------------------------------------------------------------------
@auth_router.post("/me/link-provider")
async def link_provider(
    body: LinkProviderRequest,
    auth: AuthContext = Depends(get_auth),
    person: PersonModel = Depends(get_person),
    db: Session = Depends(get_db),
):
    if body.code not in authorization_codes:
        raise HTTPException(status_code=400, detail="Invalid or expired authorization code")
    auth_data = authorization_codes[body.code]
    if body.redirect_uri != auth_data["redirect_uri"]:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    if datetime.now(timezone.utc) - auth_data["timestamp"] > _AUTH_CACHE_TTL:
        authorization_codes.pop(body.code, None)
        raise HTTPException(status_code=400, detail="Authorization code expired")

    if auth_data.get("code_challenge"):
        if not body.code_verifier:
            raise HTTPException(status_code=400, detail="Missing code_verifier")
        if auth_data["code_challenge_method"] == "S256":
            digest = hashlib.sha256(body.code_verifier.encode()).digest()
            computed = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        else:
            computed = body.code_verifier
        if not secrets.compare_digest(computed, auth_data["code_challenge"]):
            raise HTTPException(status_code=400, detail="Invalid code_verifier")

    authorization_codes.pop(body.code, None)
    info = auth_data["user_info"]
    try:
        updated = person_service.link_oidc_identity(
            db,
            user_id=str(person.id),
            oidc_provider=info.get("provider") or "google",
            oidc_subject=info["sub"],
        )
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))

    logger.info("Linked %s identity to user %s", info.get("provider"), person.id)
    return _person_to_dict(updated)


@auth_router.delete("/me/link-provider/{provider}")
async def unlink_provider(
    provider: str,
    subject: str | None = None,
    auth: AuthContext = Depends(get_auth),
    person: PersonModel = Depends(get_person),
    db: Session = Depends(get_db),
):
    """Unlink one external identity.

    `subject` is optional only while a provider has a single identity on the account — with one
    slot the route cannot be ambiguous. When the account holds more than one identity from
    `provider`, the endpoint returns 409 rather than guessing which one to drop.
    """
    matches = [i for i in person_service.list_identities(db, str(person.id))
               if i.method == "oidc" and i.provider == provider
               and (subject is None or i.subject == subject)]
    if not matches:
        raise HTTPException(status_code=404, detail=f"No {provider} identity is linked")
    if len(matches) > 1:
        raise HTTPException(
            status_code=409,
            detail=f"{len(matches)} {provider} identities are linked — pass ?subject= to say which")
    try:
        updated = person_service.unlink_oidc_identity(
            db, str(person.id), provider, matches[0].subject)
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))
    logger.info("Unlinked %s identity from user %s", provider, person.id)
    return _person_to_dict(updated)


# ---------------------------------------------------------------------------
# OIDC discovery (root_router — mounted at /)
# ---------------------------------------------------------------------------
def _discovery_document() -> dict:
    """The discovery document — built from this authority's configured identity, not the request.

    `request.base_url` is unusable here: behind a TLS-terminating proxy the last hop to uvicorn is
    plaintext, so a value derived from the request reads `http://` even when the public URI is
    `https://`. That breaks two things at once — a browser following `authorization_endpoint` is
    downgraded to a scheme nothing is listening on, and the `iss` claim stops matching: a relying
    party compares `iss` exactly, so a token minted saying `http://…` is rejected by a verifier
    configured with `https://…` as an unknown issuer.

    OIDC Discovery requires `issuer` to be a stable value that exactly matches the `iss` claim of
    the tokens this authority mints — a value that varies with the scheme, host header or port of
    whoever asked cannot satisfy that by construction. `AUTHORITY_ISSUER` is the identity this node
    signs as, so it is what the document states.
    """
    base_url = (getattr(config, "AUTHORITY_ISSUER", "") or config.ORIGIN_URI or "").rstrip("/")
    if not base_url:
        # An issuer derived from the caller is the defect above wearing a different hat: a wrong
        # issuer is worse than no document, so this raises rather than falls back to the request.
        raise HTTPException(
            status_code=500,
            detail="this authority has no configured issuer (AUTHORITY_ISSUER / ORIGIN_URI) — "
                   "refusing to publish a discovery document derived from the request",
        )
    document = {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/auth/authorize",
        "token_endpoint": f"{base_url}/auth/token",
        "userinfo_endpoint": f"{base_url}/auth/userinfo",
        "jwks_uri": f"{base_url}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "scopes_supported": ["read", "write", "openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    # Advertised only when it is there to be used. A client that reads `registration_endpoint` POSTs
    # to it and treats the answer as the flow's first step; publishing the field on a node with
    # registration switched off would turn a clean "this authority does not register clients" into a
    # 403 on a URL the document itself promised. The same reasoning as the redirect check above,
    # applied one level up: do not advertise what would be refused.
    if _client_registration_enabled():
        document["registration_endpoint"] = f"{base_url}/auth/register"
    return document


@root_router.get("/.well-known/openid-configuration")
async def openid_configuration(request: Request):
    """OIDC Discovery 1.0 §4."""
    return JSONResponse(content=_discovery_document())


@root_router.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server(request: Request):
    """RFC 8414 §3 — the same document, under the name an OAuth client looks for first.

    An MCP client probes this path *before* `/.well-known/openid-configuration` and only reaches the
    OIDC path as a fallback. A client that does not implement that fallback sees no authorization
    server here at all, and the endpoint it most needs to find — `registration_endpoint`, the way it
    obtains a `client_id` without an operator provisioning one — is unreachable. That is the whole
    reason this alias exists.

    The body is byte-identical to the OIDC document rather than a filtered subset. OIDC Discovery's
    metadata is a superset of RFC 8414's: every field published here is either registered by RFC 8414
    itself (`issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `registration_endpoint`,
    `scopes_supported`, `response_types_supported`, `grant_types_supported`,
    `token_endpoint_auth_methods_supported`, `code_challenge_methods_supported`) or an OIDC extra
    that RFC 8414 §3.2 requires an unrecognizing client to ignore (`userinfo_endpoint`,
    `subject_types_supported`, `id_token_signing_alg_values_supported`). Nothing in the set is
    sensitive, so filtering would buy no privacy — it would only introduce a second field list to
    keep in step with the first, and the failure mode of that drift is a field added for OIDC and
    silently missing for the OAuth client that actually reads this path.

    One builder serves both, so `issuer` and the endpoint URLs cannot disagree between the two
    documents, and the `base_url` reasoning in `_discovery_document` — a request-derived value reads
    `http://` behind a TLS-terminating proxy, which both downgrades a browser following
    `authorization_endpoint` and breaks exact-match `iss` comparison — holds here without being
    restated or recomputed.
    """
    return JSONResponse(content=_discovery_document())

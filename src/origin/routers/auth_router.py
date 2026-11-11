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
import ipaddress
import logging
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Annotated, Optional
from urllib.parse import urlencode, urlparse

import bcrypt
from authlib.common.security import generate_token
from fastapi import (
    APIRouter, BackgroundTasks, Body, Depends, Form, Header, HTTPException, Request, status,
)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from origin.services import refresh_tokens as _refresh_tokens
from origin import config
from origin.db import oauth_clients as db_oauth_clients
from origin.db import person_identities as db_person_identities
from origin.db import persons as db_persons
from origin.db import server_credentials as db_server_credentials
from origin.db.session import get_db
from origin.models.oauth_client import OAuthClient
from origin.models.password_reset import PasswordReset
from origin.models.person import Person as PersonModel
from origin.services import email_service
from origin.services import guess_budget
from origin.services import otp_service
from origin.services import person_service
from origin.services.email_address import require_canonical_email
from origin.services import auth_service as origin_auth_service
from origin.services.auth_service import (
    access_token_expires_in_seconds,
    create_jwt_token,
    dummy_verify_password,
    email_verification_required,
    hash_password,
    is_client_redirect_allowed,
    is_deactivated,
    is_registered_redirect_allowed,
    is_registration_redirect_allowed,
    person_token_claims,
    refuse_if_deactivated,
    run_kdf,
    verify_password,
)
from origin.services.auth_service import log_tag as _log_tag
from origin.services.auth_verifier import verify_token
from origin.services.dependencies import AuthContext, get_auth, get_person, kdf_admission
from origin.services.oidc_providers import REGISTERED_PROVIDERS, oauth
from origin.services.platform_settings_service import settings as platform_settings

logger = logging.getLogger(__name__)
auth_router = APIRouter(prefix="/auth", tags=["Authentication"])
root_router = APIRouter(tags=["Authentication"])
internal_router = APIRouter(prefix="/internal", tags=["Internal"], include_in_schema=False)

#: Admission for every route that spends a key derivation (`dependencies.kdf_admission`), released
#: when the endpoint returns rather than after the response and its background tasks.
_KDF_ADMISSION = [Depends(kdf_admission, scope="function")]


# ---------------------------------------------------------------------------
# Internal endpoints (platform-server auth — used by Mantle/Chorus for cross-DB lookups)
# ---------------------------------------------------------------------------
#: The services whose tokens may reach the person-record `/internal` routes: a subset of the
#: issuers `auth_verifier.verify_token` verifies. A name here that is absent there never reaches
#: this check (the token fails verification and 401s), and a name there that is absent here
#: authenticates and is then refused. Both directions fail closed, but only one of the two lists
#: is the trust decision, and this is it.
#:
#: Not derived from `manifest.trust_anchors`, though the manifest is the obvious source. An anchor
#: answers "can I verify this signature", and the manifest also carries `origin` itself and is
#: merged additively by the installer on upgrade. Deriving from it would silently promote every
#: future anchor to a reader of every person's PII — authentication standing in for authorization,
#: which is the substitution this whole function exists to refuse.
#: This is the trust decision, so a name here is a grant: `_require_platform_server` admits it to
#: the routes that read person records. Crystal authenticates (`auth_verifier.PLATFORM_ISSUERS`)
#: and is deliberately absent: it reaches its own delegation exchange and the describe delegation
#: only (review 21). An anchor without a name here authenticates and is refused, the safe direction.
_PLATFORM_SERVICES = frozenset({"mantle", "chorus"})
#: A chorus persona that signs as itself with its own enrolled key. It is admitted to the delegation
#: exchange for ITSELF only: the delegation's actor is then proven, and recorded as `act.iss`.
# The personas and Crystal: the services that hold a server delegation of their own (review 28).
from prism.trust.service_identity import SERVER_DELEGATION_SIGNERS as _PERSONAS  # noqa: E402


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
_NON_USER_PRINCIPALS = {"service", "server", "delegation", "mcp_client"}

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
    # Only what `/internal/delegation-token` exchanges (review 22, F6): no refresh, reset or other
    # single-purpose token, and one addressed to Origin itself.
    # The person's token addressed to Mantle (review 23) proves the same: Mantle's lookups
    # present the token the web app calls it on.
    if (claims.get("token_type") or claims.get("api_key_id")
            or claims.get("principal_type", "user") != "user"
            or claims.get("aud") not in (config.AUTHORITY_ISSUER, "mantle")):
        raise HTTPException(
            status_code=403,
            detail="subject_token must be a person's own access token for this authority",
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


# ---------------------------------------------------------------------------
# Billing recipients: Ophan's billing mail (review 21, F4)
# ---------------------------------------------------------------------------
#: Ophan, the persona that sends billing mail: the chorus host's token naming Ophan's client id,
#: or Ophan signing with its own enrolled key.
_BILLING_MAILER = "agience-server-ophan"


def _require_billing_mailer(auth: AuthContext) -> str:
    """Ophan, or 403. Returns how it is recorded."""
    if auth.principal_type == "service":
        if auth.principal_id == "chorus" and auth.actor == _BILLING_MAILER:
            return f"chorus/{_BILLING_MAILER}"
        if auth.principal_id == "ophan" and auth.actor is None:
            return "ophan"
    raise HTTPException(status_code=403, detail="billing recipients are Ophan's billing mail only")


class _BillingRecipientBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    active: bool
    plan: str = Field(default="", max_length=64)


@internal_router.put("/billing-recipients/{person_id}")
def internal_put_billing_recipient(person_id: str, body: _BillingRecipientBody,
                                   auth: AuthContext = Depends(get_auth),
                                   db: Session = Depends(get_db)):
    """Ophan records that a person's subscription is active, or ended, from the payment
    provider's verified event. Only an active record lets Ophan read their address."""
    from origin.models.billing_recipient import BillingRecipient

    caller = _require_billing_mailer(auth)
    if person_service.get_user_by_id(db, person_id) is None:
        raise HTTPException(status_code=404, detail="Person not found")
    row = db.get(BillingRecipient, person_id) or BillingRecipient(person_id=person_id)
    row.active, row.plan, row.recorded_by = body.active, body.plan, caller
    row.updated_at = datetime.now(timezone.utc)
    db.merge(row)
    db.commit()
    logger.warning("billing recipient %s: person=%s plan=%s by=%s",
                   "active" if body.active else "ended", person_id, body.plan, caller)
    return {"person_id": person_id, "active": body.active}


@internal_router.get("/billing-recipients/{person_id}")
def internal_get_billing_recipient(person_id: str, auth: AuthContext = Depends(get_auth),
                                   db: Session = Depends(get_db)):
    """A billed person's address, and nothing else, for Ophan's billing mail. 404 unless Ophan
    recorded an active billing record for them. Every read is recorded, found or not."""
    from origin.models.billing_recipient import BillingRecipient, BillingRecipientLookup

    caller = _require_billing_mailer(auth)
    row = db.get(BillingRecipient, person_id)
    person = person_service.get_user_by_id(db, person_id) if row is not None and row.active         else None
    email = (getattr(person, "email", None) or "") if person is not None         and not getattr(person, "deactivated_at", None) else ""
    db.add(BillingRecipientLookup(person_id=person_id, caller=caller, found=bool(email)))
    db.commit()
    logger.warning("billing recipient address read: person=%s by=%s found=%s", person_id, caller,
                   bool(email))
    if not email:
        raise HTTPException(status_code=404, detail="no active billing record with an address")
    return {"email": email}


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


from origin.services.auth_service import SERVER_DELEGATION_AUDIENCE as _SERVER_DELEGATION_AUDIENCE  # noqa: E402

#: The longest a person's delegation lives: ten minutes, and never past the token it came from.
MAX_DELEGATION_TTL = 600


# `_NON_USER_PRINCIPALS` is defined above, beside `_verified_subject_id` — the two routes that
# refuse a non-user subject share one list.


@internal_router.post("/delegation-token")
def internal_issue_delegation_token(
    body: _DelegationTokenRequest,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
):
    """Exchange a verified user token for a short-lived RFC 8693 delegation JWT.

    The gateway (Chorus persona) forwards the user's Origin-signed token; Origin verifies it,
    derives `sub` from the verified token, and mints the delegation (sub=user,
    aud=server_client_id, act.sub=server_client_id, principal_type=delegation, exp=300s). Origin
    owns the RSA signing key, so the service cannot issue these itself, and Origin never trusts a
    caller-supplied subject: a compromised service can only exchange tokens it already possesses,
    never fabricate a delegation for a user it has not authenticated.
    """
    # The actor is proven when a persona signs as itself: it may ask only for its own delegation,
    # and the delegation records that the signer was the persona (`act.iss`). The shared `chorus`
    # identity may still ask for any persona, as before, and its delegations say `act.iss=chorus` —
    # usable for everything except the release of a secret, which demands a proven actor.
    persona_signer = auth.principal_type == "service" and (
        auth.principal_id in _PERSONAS or auth.principal_id in config.PERSONA_AUDIENCES)
    if persona_signer:
        if body.server_client_id != f"agience-server-{auth.principal_id}":
            raise HTTPException(status_code=403,
                                detail="a persona may obtain a delegation for itself only")
        signer = auth.principal_id
    else:
        # The shared chorus identity, for a persona that holds no key of its own yet. Mantle calls
        # no exchange (review 21): it is refused here, though `_require_platform_server` admits it.
        _require_platform_server(auth)
        if auth.principal_id != "chorus":
            raise HTTPException(status_code=403, detail="the delegation exchange is a persona's, "
                                "or the chorus host's for a persona")
        signer = auth.principal_id
    claims = verify_token(body.subject_token)
    if not claims:
        raise HTTPException(status_code=401, detail="Invalid or expired subject token")
    from origin.services import not_before as _not_before
    from origin.services.dependencies import _is_narrowed
    if _not_before.ended(db, claims):
        raise HTTPException(status_code=401, detail="this sign-in has ended; sign in again")
    # A persona server holds the caller only as a delegation narrowed to itself (review 11, H3):
    # it exchanges that, and only that, for its own server delegation, which it signs for itself.
    narrowed_scope = None
    job: dict = {}
    # Only a delegation narrowed to the asking persona is exchanged (review 27): a person's own
    # access token never becomes a server delegation, so no server delegation carries a person's
    # unscoped reach, and the shared `chorus` identity, which nothing is narrowed to, exchanges
    # nothing.
    if not _is_narrowed(claims):
        raise HTTPException(status_code=403, detail="the exchange takes only a delegation "
                            "narrowed to the asking persona")
    if _is_narrowed(claims):
        if not persona_signer or claims.get("aud") != auth.principal_id:
            raise HTTPException(status_code=403, detail="a narrowed delegation is exchanged only "
                                "by the persona it was narrowed to, for itself")
        # The server delegation keeps the narrowing it came from (review 12, H5): its scope and
        # Origin's `narrowed` claim, so Mantle bounds it as it bounds the narrowed delegation.
        narrowed_scope = str(claims.get("scope") or "")
        # A timer's delegation keeps its reach on every exchange: never wider than its grant.
        job = origin_auth_service.job_reach_of(claims) or {}
        claims = {**claims, "principal_type": "user", "aud": config.AUTHORITY_ISSUER,
                  "act": None}
    if claims.get("principal_type") in _NON_USER_PRINCIPALS:
        raise HTTPException(
            status_code=403,
            detail="subject_token must be a user token, not a service/delegation token",
        )
    # Only a person's own access token for this authority is exchanged: not a refresh, reset or
    # other single-purpose token (`token_type`), not any principal type but a person, and not a
    # token addressed to anyone but Origin itself (an mcp_client's, a third party's).
    if (claims.get("token_type") or claims.get("api_key_id")
            or claims.get("principal_type", "user") != "user"
            or claims.get("aud") != config.AUTHORITY_ISSUER):
        raise HTTPException(
            status_code=403,
            detail="subject_token must be a person's own access token for this authority",
        )
    user_id = claims.get("sub")
    if not user_id:
        raise HTTPException(status_code=400, detail="subject_token has no subject")
    # Bounded twice: ten minutes at most, and never past the token it is exchanged for, so a
    # delegation cannot outlive the sign-in that proved the person. Recorded by `jti`
    # (`delegation_tokens`) so it can be checked and revoked.
    from origin.models.key_custody import DelegationRecord

    remaining = int(float(claims.get("exp") or 0) - datetime.now(timezone.utc).timestamp())
    ttl = min(int(body.ttl_seconds), MAX_DELEGATION_TTL, remaining)
    if ttl < 1:
        raise HTTPException(status_code=400, detail="ttl_seconds must be positive, and the "
                            "subject token must not be about to expire")
    jti = secrets.token_hex(16)
    token = origin_auth_service.issue_delegation_token(
        body.server_client_id, str(user_id), ttl, signer=signer, jti=jti,
        **({"narrowed_scope": narrowed_scope} if narrowed_scope is not None else {}),
        **job,
    )
    db.add(DelegationRecord(jti=jti, subject=str(user_id),
                            audience=_SERVER_DELEGATION_AUDIENCE,
                            signer=signer or "",
                            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl)))
    db.commit()
    return {"token": token, "expires_in": ttl}


class _NarrowHopRequest(BaseModel):
    """Body for POST /internal/narrow-hop."""
    model_config = ConfigDict(extra="forbid")
    subject_token: str
    audience: str
    scope: Optional[str] = None


def _narrow_hop(db: Session, caller: str, subject_token: str, audience: str,
                scope: Optional[str]) -> JSONResponse:
    """One hop of cross-persona work (review 12, decision 2), for the persona `caller` whose own
    signature the route has already proven.

    The subject must be a delegation Origin narrowed to `caller` itself (not a hop's result, which
    is not exchanged again). The result is narrowed to `audience`: the same person, scope
    `persona:<audience>` only, five minutes and never past the subject, no refresh token, never
    `platform:admin`, and only along the pairs Origin lists (`config.NARROW_HOPS`: Crystal to each
    persona, Lumen to Sage). Each hop is recorded (`narrow_hops`)."""
    from jose import jwt as _jose_jwt

    from origin.models.narrow_hop import NarrowHop
    from origin.services import not_before as _not_before
    from origin.services.dependencies import _is_narrowed

    claims = verify_token(subject_token)
    if not claims:
        raise HTTPException(status_code=401, detail="Invalid or expired subject token")
    if (not _is_narrowed(claims) or claims.get("aud") != caller
            or (claims.get("act") or {}).get("sub") != caller or claims.get("hop")):
        raise HTTPException(status_code=403, detail="a hop starts from a delegation narrowed to "
                            "the asking persona itself")
    if audience not in (config.NARROW_HOPS.get(caller) or []):
        raise HTTPException(status_code=403, detail=f"no hop from {caller} to {audience}")
    scopes = origin_auth_service.narrow_audiences().get(audience)
    if not scopes:
        raise HTTPException(status_code=403, detail=f"{audience} is not a narrow audience")
    wanted = (scope or "").split() or list(scopes)
    if not set(wanted) <= set(scopes):
        raise HTTPException(status_code=400, detail=f"scope outside {audience}'s")
    if _not_before.ended(db, claims):
        raise HTTPException(status_code=401, detail="this sign-in has ended; sign in again")
    person = db_persons.get_by_id(db, str(claims.get("sub") or ""))
    if person is None:
        raise HTTPException(status_code=401, detail="Invalid subject")
    refuse_if_deactivated(person)
    ends = datetime.fromtimestamp(float(claims.get("exp") or 0), timezone.utc)
    token = origin_auth_service.issue_narrow_delegation(
        str(person.id), audience, wanted, expires_at=ends,
        hop={"from": caller, "jti": str(claims.get("jti") or "")},
        **(origin_auth_service.job_reach_of(claims) or {}))
    issued = _jose_jwt.get_unverified_claims(token)
    db.add(NarrowHop(jti=str(issued["jti"]), sub=str(person.id),
                     subject_jti=str(claims.get("jti") or ""), from_aud=caller, to_aud=audience))
    db.commit()
    logger.info("narrow hop %s -> %s for %s", caller, audience, person.id)
    return JSONResponse(content={
        "access_token": token, "issued_token_type": _ACCESS_TOKEN_TYPE, "token_type": "bearer",
        "expires_in": max(0, int(issued["exp"] - datetime.now(timezone.utc).timestamp())),
        "scope": " ".join(wanted)})


@internal_router.post("/narrow-hop")
def internal_narrow_hop(body: _NarrowHopRequest, auth: AuthContext = Depends(get_auth),
                        db: Session = Depends(get_db)):
    """A hop (`_narrow_hop`) asked on the persona's own signed service token."""
    caller = str(auth.principal_id or "")
    if auth.principal_type != "service" or (caller not in config.NARROW_HOPS
                                            and caller not in config.PERSONA_AUDIENCES):
        raise HTTPException(status_code=403, detail="a hop is a persona's own exchange")
    return _narrow_hop(db, caller, body.subject_token, body.audience, body.scope)


class _JobDelegationRequest(BaseModel):
    """Body for POST /internal/job-delegation."""
    model_config = ConfigDict(extra="forbid")
    principal: str
    job: str
    audience: str
    #: The grant the timer was armed on: the one minted under, and no other.
    job_grant: str


#: Whom a timer's delegation is narrowed to: Lumen, which keeps the timer and records its runs, and
#: Crystal, which runs its target and hops on to the persona that serves it.
TIMER_AUDIENCES = ("lumen", "crystal")


@internal_router.post("/job-delegation")
def internal_job_delegation(body: _JobDelegationRequest, auth: AuthContext = Depends(get_auth),
                            db: Session = Depends(get_db)):
    """A delegation for a timer's firing (John, 2026-11-10: timers run on an Origin job grant),
    asked by Lumen on its own key. Minted only under the person's live grant for that timer's job
    (`lumen.timer.<id>`, made at Origin's page with a step-up), narrowed to Lumen or Crystal with
    that audience's own scope, five minutes and never past the grant, carrying the grant's reach
    (`job_reach`), which every exchange from it keeps and Mantle holds it to. Each one is recorded
    under its grant and rate-limited with it; a revoked or expired grant mints nothing."""
    import json as _json

    from origin.models.key_custody import KeyCustodyDelegation
    from origin.services import authority_ledger as _ledger, share_credentials

    if (auth.principal_type != "service" or auth.principal_id != "lumen"
            or auth.actor not in (None, "agience-server-lumen")):
        raise HTTPException(status_code=403, detail="a timer's delegation is Lumen's own to ask, "
                            "on its own key")
    run = body.job.startswith(_ledger.RUN_JOB_PREFIX)
    if not _ledger.is_reach_job(body.job) or body.audience not in TIMER_AUDIENCES \
            or (run and body.audience != "crystal"):
        raise HTTPException(status_code=400, detail="a timer's job, for lumen or crystal, or a "
                            "run's, for crystal")
    # The grant the timer was armed on, by its id: an older grant for the same timer, perhaps
    # wider, is never drawn on in its place.
    grant = share_credentials._live_grant_row(db, body.job_grant, job=body.job)
    reach = _json.loads(getattr(grant, "reach", None) or "[]") if grant is not None else []
    if grant is None or grant.principal != body.principal or not reach:
        raise HTTPException(status_code=403, detail=f"no live job grant for {body.job} by this "
                            f"person; arm the timer again")
    person = db_persons.get_by_id(db, body.principal)
    if person is None:
        raise HTTPException(status_code=403, detail="no such person")
    refuse_if_deactivated(person)
    scopes = origin_auth_service.narrow_audiences().get(body.audience)
    if not scopes:
        raise HTTPException(status_code=403, detail=f"{body.audience} is not a narrow audience")
    now = datetime.now(timezone.utc)
    if run:
        # A run's grant is used once (John, 2026-11-10): one delegation, to Crystal, then none.
        # Claimed by a row keyed on the grant, so two requests at once cannot both pass: the second
        # fails on the primary key, not on a count it read before the first wrote.
        from sqlalchemy.exc import IntegrityError
        db.add(KeyCustodyDelegation(jti=("run:" + grant.grant_id)[:64], subject=str(person.id),
                                    issued_by=grant.created_by or "", job_grant_id=grant.grant_id,
                                    job=body.job, collections="[]",
                                    expires_at=_ledger.parse_time(grant.expires_at)))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(status_code=403, detail=f"job grant {grant.grant_id} has had its "
                                f"one run; run it again to approve another")
    recent = db.query(KeyCustodyDelegation).filter(
        KeyCustodyDelegation.job_grant_id == grant.grant_id,
        KeyCustodyDelegation.created_time > now - timedelta(seconds=60)).count()
    if recent >= share_credentials.JOB_ISSUANCE_PER_MINUTE:
        raise HTTPException(status_code=429, detail=f"job grant {grant.grant_id} has had its "
                            f"delegations for the minute")
    ends = min(_ledger.parse_time(grant.expires_at),
               now + timedelta(seconds=origin_auth_service.NARROW_TTL_SECONDS))
    token = origin_auth_service.issue_narrow_delegation(
        str(person.id), body.audience, list(scopes), expires_at=ends, job_reach=reach,
        job_grant=grant.grant_id)
    from jose import jwt as _jose_jwt
    issued = _jose_jwt.get_unverified_claims(token)
    db.add(KeyCustodyDelegation(jti=str(issued["jti"]), subject=str(person.id),
                                issued_by=grant.created_by or "", job_grant_id=grant.grant_id,
                                job=body.job, collections="[]", expires_at=ends))
    db.commit()
    logger.info("timer delegation for %s: job=%s grant=%s audience=%s", person.id, body.job,
                grant.grant_id, body.audience)
    return {"access_token": token, "expires_in": max(0, int(issued["exp"] - now.timestamp())),
            "job_grant": grant.grant_id}


_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
from origin.services.auth_service import SYSTEM_DELEGATION_MAX_TTL as _SYSTEM_DELEGATION_MAX_TTL  # noqa: E402
#: The longest a hop's client assertion may live.
HOP_ASSERTION_MAX_TTL = 300


#: The clock skew allowed on a hop assertion's `iat`.
HOP_ASSERTION_SKEW = 30


def _hop_caller(db: Session, subject_token: str, assertion_type: Optional[str],
                assertion: Optional[str]) -> str:
    """The persona proven by an RFC 7523 client assertion for a hop at the token endpoint: a JWT
    signed with the key the authority manifest anchors for the persona the subject was narrowed to
    (`iss` = `sub` = that persona), addressed to this token endpoint, issued now (no `iat` ahead of
    the clock beyond the skew) and expiring within `HOP_ASSERTION_MAX_TTL` of now, bound to this
    subject token (`subject_digest` = the SHA-256 of it), and used once (its `jti` is spent here,
    so a captured assertion cannot be replayed with the same subject)."""
    import hashlib

    from jose import jwt as _jose_jwt

    from origin.services import key_shares as _key_shares

    from origin.authority_trust import verify_jwt as _verify_via_authority

    try:
        caller = str(_jose_jwt.get_unverified_claims(subject_token).get("aud") or "")
    except Exception:  # noqa: BLE001
        caller = ""
    if assertion_type != _JWT_BEARER or not assertion or not caller:
        raise HTTPException(status_code=401, detail="a hop needs the persona's own client "
                            "assertion")
    endpoints = {f"{(config.ORIGIN_URI or '').rstrip('/')}/auth/token",
                 f"{(config.AUTHORITY_ISSUER or '').rstrip('/')}/auth/token"}
    try:
        claims = _verify_via_authority(assertion, expected_issuer_service=caller,
                                       expected_issuer_claim=caller)
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=401, detail="the client assertion does not verify")
    now = datetime.now(timezone.utc).timestamp()
    iat, exp = claims.get("iat"), claims.get("exp")
    if (claims.get("sub") != caller or claims.get("aud") not in endpoints
            or not isinstance(iat, (int, float)) or not isinstance(exp, (int, float))
            or exp <= now or exp - iat > HOP_ASSERTION_MAX_TTL
            or iat > now + HOP_ASSERTION_SKEW or exp > now + HOP_ASSERTION_MAX_TTL):
        raise HTTPException(status_code=401, detail="the client assertion is not the persona's "
                            "own, for this endpoint, short-lived")
    if claims.get("subject_digest") != hashlib.sha256(subject_token.encode()).hexdigest():
        raise HTTPException(status_code=401, detail="the client assertion is not bound to this "
                            "subject token")
    jti = claims.get("jti")
    if (not isinstance(jti, str) or not jti
            or not _key_shares.spend_token(db, f"hop:{caller}:{jti}",
                                           datetime.fromtimestamp(exp, timezone.utc))):
        raise HTTPException(status_code=401, detail="the client assertion has no jti or was "
                            "already used")
    return caller


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

    The caller is Crystal, signing as itself, whose event-driven describer this serves, and no
    other service (review 21): Crystal is not among the services `_require_platform_server`
    admits for the person reads, and a platform service it does admit (Mantle, Chorus) is refused
    here. A describe delegation names no person and carries no proven actor (`act.iss`), so it
    never decides the use of a secret (`services.use_verdict`).
    """
    if not (auth.principal_type == "service" and auth.principal_id == "crystal"
            and auth.actor is None):
        raise HTTPException(status_code=403, detail="a describe delegation is Crystal's to ask")

    # The persona that runs the describe is one Origin knows (review 15): its actor and audience
    # are that persona's own client id, `agience-server-<persona>`, and nothing else.
    persona = body.persona_client_id
    if not (persona.startswith("agience-server-")
            and persona[len("agience-server-"):] in config.PERSONA_AUDIENCES):
        raise HTTPException(status_code=403, detail="a describe delegation names a known persona")

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
        actor=persona,
        scope="platform.describe",
        audience=persona,
        ttl_seconds=min(body.ttl_seconds, _SYSTEM_DELEGATION_MAX_TTL),
        jti=secrets.token_hex(16),
    )
    logger.info(
        "describe-delegation issued: persona=%s resource=%s sub=%s",
        body.persona_client_id, body.resource_id, subject_id,
    )
    return {"token": token, "subject_id": subject_id}


class _DescribeForMantleRequest(BaseModel):
    """Body for POST /internal/describe-delegation/for-mantle."""
    model_config = ConfigDict(extra="forbid")
    subject_token: str


@internal_router.post("/describe-delegation/for-mantle")
def internal_describe_for_mantle(body: _DescribeForMantleRequest,
                                 auth: AuthContext = Depends(get_auth),
                                 db: Session = Depends(get_db)):
    """The persona's own copy, addressed to Mantle, of the describe delegation Crystal had sent it
    (review 23, L1). The persona signs as itself and presents the delegation addressed to it; the
    copy keeps its subject and scope, names the persona as the proven actor (`act.iss`), never
    outlives it, and is recorded by `jti`. No persona takes a delegation it asked for itself, so
    Mantle, which holds the copy, cannot hand it back."""
    from origin.models.key_custody import DelegationRecord

    caller = str(auth.principal_id or "")
    if (auth.principal_type != "service" or auth.actor is not None
            or (caller not in _PERSONAS and caller not in config.PERSONA_AUDIENCES)):
        raise HTTPException(status_code=403, detail="a describe delegation is exchanged by the "
                            "persona it was sent to, signing as itself")
    me = f"agience-server-{caller}"
    claims = verify_token(body.subject_token)
    act = (claims or {}).get("act") if isinstance((claims or {}).get("act"), dict) else {}
    if (not claims or claims.get("principal_type") != "delegation"
            or claims.get("scope") != "platform.describe" or claims.get("aud") != me
            or act.get("sub") != me or act.get("iss")):
        raise HTTPException(status_code=403, detail="only a describe delegation sent to this "
                            "persona is exchanged")
    remaining = int(float(claims.get("exp") or 0) - datetime.now(timezone.utc).timestamp())
    if remaining < 1:
        raise HTTPException(status_code=401, detail="the describe delegation has expired")
    jti = secrets.token_hex(16)
    token = origin_auth_service.issue_system_delegation_token(
        str(claims.get("sub") or ""), actor=me, signer=caller, scope="platform.describe",
        audience="mantle", ttl_seconds=remaining, jti=jti)
    db.add(DelegationRecord(jti=jti, subject=str(claims.get("sub") or ""), audience="mantle",
                            signer=caller,
                            expires_at=datetime.now(timezone.utc) + timedelta(seconds=remaining)))
    db.commit()
    return {"token": token, "expires_in": remaining}


# Named system-delegation purposes. The requester picks a purpose, not an arbitrary subject, and
# Origin maps it to a bounded scope — so a platform caller can obtain a delegation for the
# operator-rooted `platform-system` principal scoped to exactly one capability, never a delegation
# for an arbitrary user.
#
# `actors` lists the only actors a purpose is minted for (review 15): the persona that carries it
# out, and the personas that ask it of that one.
_SYSTEM_DELEGATION_PURPOSES: dict[str, dict] = {
    # Webhook/background email sends (receipts, usage warnings, etc.).
    "platform-mail": {"scope": "platform.email.send", "audience": "mantle", "persona": "iris",
                      "actors": ("agience-server-iris", "agience-server-ophan")},
    # Resolves the Stripe credential (sandbox or live) for the payment tekton, on behalf of the
    # platform. Scoped to one capability, like every entry here, so it cannot be widened into a
    # general secret-reader.
    "platform-stripe": {"scope": "platform.stripe.resolve", "audience": "mantle",
                        "actors": ("agience-server-ophan",)},
}


#: The personas a platform service may carry a system delegation for, besides itself (review 16):
#: Chorus hosts Ophan, and asks for Ophan's purposes as Ophan.
_SYSTEM_DELEGATION_CALLERS: dict[str, tuple] = {"chorus": ("agience-server-ophan",)}


class _SystemDelegationRequest(BaseModel):
    """Body for POST /internal/system-delegation."""
    model_config = ConfigDict(extra="forbid")
    purpose: str
    ttl_seconds: int = 300


@internal_router.post("/system-delegation")
def internal_issue_system_delegation(
    body: _SystemDelegationRequest,
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
):
    """Mint a delegation for the operator-rooted `platform-system` principal.

    For platform automation (e.g. Ophan's Stripe webhook) that has no user delegation but must
    still act under the full identity chain. The requester names a purpose, never a subject, so it
    cannot impersonate a user — Origin fixes the subject to the system principal and stamps a
    bounded scope. Platform callers only — and the persona a purpose names, signing as itself.
    """
    # A purpose may name the persona that carries it out (`persona`): that persona, signing with
    # its own enrolled key, may ask for it, and the delegation is recorded as proven (`act.iss`).
    # 2026-10-19: platform mail is Iris's own operation; the secrets it uses are released only to
    # a persona that proved who it is.
    cfg_for_persona = _SYSTEM_DELEGATION_PURPOSES.get(body.purpose) or {}
    persona = cfg_for_persona.get("persona")
    if auth.principal_type == "service" and persona and auth.principal_id == persona:
        actor, signer = f"agience-server-{persona}", persona
    else:
        _require_platform_server(auth)
        signer = auth.principal_id
        # The actor is bound to the caller who signed (review 16, I1): a service acts as itself,
        # or as a persona it is listed as carrying out, never as one it merely names.
        claimed = auth.actor or ""
        if claimed and claimed != f"agience-server-{signer}" and                 claimed not in _SYSTEM_DELEGATION_CALLERS.get(signer, ()):
            raise HTTPException(status_code=403, detail=f"{signer} does not act as {claimed}")
        actor = claimed or signer

    cfg = _SYSTEM_DELEGATION_PURPOSES.get(body.purpose)
    if cfg is None:
        raise HTTPException(status_code=403, detail=f"Unknown system delegation purpose: {body.purpose}")
    if actor not in cfg["actors"]:
        raise HTTPException(status_code=403, detail=f"the purpose {body.purpose} is minted only "
                            f"for {', '.join(cfg['actors'])}")

    # The system principal's authority roots to the operator: with none designated there is
    # nothing to root to, so no delegation can be minted yet.
    if not platform_settings.get("platform.operator_id"):
        raise HTTPException(status_code=409, detail="Platform operator not configured")

    from origin.service_identity import get_system_principal_id

    subject_id = get_system_principal_id()
    if not subject_id:
        raise HTTPException(status_code=409, detail="Instance namespace unavailable; cannot derive system principal")

    # Recorded by `jti` with the signer that asked (review 21): a secret is used on a platform
    # purpose's delegation only when Origin holds this record of it (`services.use_verdict`).
    from origin.models.key_custody import DelegationRecord

    ttl = max(1, min(int(body.ttl_seconds or 0), _SYSTEM_DELEGATION_MAX_TTL))
    jti = secrets.token_hex(16)
    token = origin_auth_service.issue_system_delegation_token(
        subject_id, actor=actor, scope=cfg["scope"], audience=cfg["audience"],
        ttl_seconds=ttl, signer=signer, jti=jti,
    )
    db.add(DelegationRecord(jti=jti, subject=str(subject_id), audience=cfg["audience"],
                            signer=signer or "",
                            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl)))
    db.commit()
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
#: A verification nonce: random, generated by the browser that starts a verification, kept in that
#: browser, and bound into the mailed link as a hash. See `_verification_nonce_matches`.
_VerifyNonce = Annotated[str, Field(max_length=128)]

#: An email address or username; see `guess_budget.Identifier` for the bound and why.
_Identifier = guess_budget.Identifier


class PasswordLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    identifier: _Identifier
    password: str
    verify_nonce: _VerifyNonce = ""


class PasswordRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: _Identifier
    password: str
    name: str = ""
    email: _Identifier = ""
    verify_nonce: _VerifyNonce = ""


class PasswordResetRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: _Identifier


class PasswordResetConfirmBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str
    new_password: str


class EmailVerifyRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: _Identifier
    verify_nonce: _VerifyNonce = ""


class EmailVerifyConfirmBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str
    verify_nonce: _VerifyNonce = ""
    password: str = ""
    disown: bool = False


class LinkProviderRequest(BaseModel):
    code: str
    code_verifier: str
    redirect_uri: str
    #: The link attempt's random state (`POST /auth/me/link-attempts`), begun in the Origin session.
    state: Optional[str] = None


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

#: How long a started sign-in (`pkce_challenges`) waits for the person: long enough to type a
#: password or fetch a mailed code.
_AUTH_CACHE_TTL = timedelta(minutes=10)
#: How long a minted authorization code lives. A code is redeemed by the page it is delivered to,
#: at once; RFC 6749 §4.1.2 asks for a short life, and RFC 9700 §2.1.1 for single use.
_CODE_TTL = timedelta(seconds=60)
_AUTH_CACHE_MAX_ITEMS = 5000
#: A PKCE S256 challenge: the unpadded base64url of a SHA-256 digest, 43 characters.
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]{43}")


def _prune_auth_cache(now: datetime) -> None:
    for cache, ttl in ((pkce_challenges, _AUTH_CACHE_TTL), (authorization_codes, _CODE_TTL)):
        cutoff = now - ttl
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
</head><body data-state="__STATE__">
<div class="bg"></div>
<div class="card">
  <img class="logo" src="/web/logo_v.png" alt="Agience">
  <h1>Welcome, let's get you signed in</h1>
  <div class="beta"><strong>This is beta.</strong> Expect bugs and things not to work. We welcome
    any feedback to <a href="mailto:connect@agience.ai">connect@agience.ai</a> &mdash; and you are
    encouraged to contribute as a dev at
    <a href="https://github.com/Agience" target="_blank" rel="noopener noreferrer">github.com/Agience</a>.</div>
__PROVIDERS__
__PASSWORD__
__OTP__
__REGISTER__
  <div class="msg" id="msg"></div>
  <div class="foot"><a href="https://agience.ai/terms">Terms</a> · <a href="https://agience.ai/privacy">Privacy</a></div>
</div>
<script src="/web/bg.js"></script>
<script src="/web/authorize.js"></script></body></html>"""

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
__REGTOGGLE__
  </div>
"""

_REGISTER_TOGGLE = """    <div class="row"><button class="link" type="button" id="regToggle">No account yet? Create one</button></div>
"""

#: Registration, inside the flow rather than beside it.
#:
#: `/login` has carried a registration form all along, and the chooser did not link to it. A
#: person arriving from a service provider was therefore offered password and OTP, both of which
#: require an account to already exist — and OTP says "if that address has an account, a code is
#: on its way" to an address with none, so the dead end did not even announce itself.
#:
#: A link to `/login` would not have fixed it: `/login` mints a token directly, which cannot
#: complete PKCE, so registering there drops the pending authorization request and strands the
#: person on `/account` instead of back at the service provider they came from. This block posts
#: to `/auth/authorize/register`, which ends at `_complete_local_signin` like the other two legs
#: and returns them to the flow they started.
_REGISTER_BLOCK = """  <div id="reg" class="hidden">
    <form id="regForm">
      <label for="remail">Email</label>
      <input id="remail" type="email" autocomplete="email" required placeholder="you@example.com">
      <label for="rpassword">Password</label>
      <input id="rpassword" type="password" autocomplete="new-password" required
             placeholder="At least __MINLEN__ characters">
      <button class="primary" type="submit" id="regBtn">Create account</button>
    </form>
    <div class="row"><button class="link" type="button" id="regBack">Already have an account? Sign in</button></div>
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
    login_hint: str = "",
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
        f'data-href="/auth/authorize/federate?oauth_state={oauth_state}'
        f'&amp;provider={_html.escape(name, quote=True)}">'
        f"{_GOOGLE_MARK if name == 'google' else ''}"
        f"Continue with {_html.escape(label)}</button>\n"
        for name, label in providers
    )
    # The divider only earns its place when there is something on both sides of it.
    if buttons and (password or otp):
        buttons += '  <div class="sep">or</div>\n'

    if password:
        block = _PASSWORD_BLOCK.replace("__OTPTOGGLE__", _OTP_TOGGLE if otp else "").replace(
            "__REGTOGGLE__", _REGISTER_TOGGLE
        )
        if login_hint:
            # The account is known (a step-up names it): filled in, and the password asked for.
            block = block.replace(
                '<input id="identifier" type="text" autocomplete="username" required>',
                '<input id="identifier" type="text" autocomplete="username" required value="'
                + _html.escape(login_hint, quote=True) + '">').replace(
                '<input id="password" type="password" autocomplete="current-password" required>',
                '<input id="password" type="password" autocomplete="current-password" required autofocus>')
        otp_block = _OTP_BLOCK.replace("__OTPHIDDEN__", ' class="hidden"').replace(
            "__OTPBACK__", _OTP_BACK
        ) if otp else ""
        # Registration is a password method: it sets one. With password auth disabled there is
        # nothing for this form to create, which is why it is rendered on this branch only —
        # the same rule the rest of this function follows, that a disabled method is omitted
        # rather than shown and then refused.
        reg_block = _REGISTER_BLOCK.replace(
            "__MINLEN__", str(platform_settings.get_int("auth.password.min_length", 12))
        )
    else:
        block = ""
        # No password to fall back to, so OTP is the only local method: shown, with no way back.
        otp_block = _OTP_BLOCK.replace("__OTPHIDDEN__", "").replace("__OTPBACK__", "") if otp else ""
        reg_block = ""

    return (
        _LOCAL_LOGIN_PAGE.replace("__PROVIDERS__", buttons)
        .replace("__PASSWORD__", block)
        .replace("__OTP__", otp_block)
        .replace("__REGISTER__", reg_block)
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
    email: _Identifier


class _LocalOTPVerify(BaseModel):
    oauth_state: str
    email: _Identifier
    code: str


@auth_router.post("/authorize/otp/request", dependencies=_KDF_ADMISSION)
async def authorize_local_otp_request(
    request: Request,
    body: _LocalOTPRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Send a one-time code for a sign-in already in flight.

    The response is identical for a known address, an unknown one, and one whose limits refuse
    another code, matching `/auth/otp/request`: each spends one code hash and answers
    `{"sent": true}`, with the mail sent after the response. A difference in status or timing
    would make this endpoint an account-enumeration oracle, reachable without authentication since
    a sign-in in flight is not yet a session.
    """
    _pop_local_auth_request(body.oauth_state)
    if not email_service.is_configured():
        raise HTTPException(status_code=503, detail="Email delivery is not configured.")

    await _mail_sign_in_code(request, background_tasks, db, otp_service.normalize_email(body.email))
    return {"sent": True}


async def _mail_sign_in_code(
    request: Request, background_tasks: BackgroundTasks, db: Session, email: str
) -> None:
    """Mail a sign-in code to `email`: the body of both code-request routes, `/auth/otp/request`
    and `/auth/authorize/otp/request`, which answer `{"sent": true}` whatever happens here.

    The request is charged to the unauthenticated mail budget first (`_mail_send_admitted`), for
    every well-formed address, and past it nothing is mailed. An unknown address gets nothing. An
    account whose address is unconfirmed gets its confirmation link and not a code: entering a code
    confirms the address, so a code mailed there would confirm it outside the sign-up gate. Every
    outcome spends one code hash, so none is told apart by timing.
    """
    tag = _mail_send_admitted(request, email, "sign-in code request")
    if tag is None:
        _release_db(db)
        await otp_service.spend_code_hash()
        return
    person = db_persons.get_by_email(db, email)
    if person is None or is_deactivated(person):
        _release_db(db)
        logger.info("sign-in code requested for %s address %s",
                    "a deactivated" if person is not None else "an unknown", tag)
        await otp_service.spend_code_hash()
        return
    if not person.email_verified and email_verification_required(person.email):
        # Already charged above; the helper must not charge it twice.
        _queue_verification_email(background_tasks, person, db=db)
        logger.info("sign-in code requested for unconfirmed address %s; confirmation link queued", tag)
        await otp_service.spend_code_hash()
        return
    code = await otp_service.issue_otp(db, email)
    if code is not None:
        background_tasks.add_task(otp_service.deliver_otp, email, code, _mail_context(request))


@auth_router.post("/authorize/otp/verify", dependencies=_KDF_ADMISSION)
async def authorize_local_otp_verify(body: _LocalOTPVerify, db: Session = Depends(get_db)):
    """Verify the code and mint the authorization code, completing the flow locally.

    The payload is the same shape the federated callback writes: `/token`, `_grant_authorization_code`
    and every consumer downstream cannot tell which path produced it. One shape for both paths is
    what keeps them from drifting apart.
    """
    auth_request = _pop_local_auth_request(body.oauth_state)

    email = otp_service.normalize_email(body.email)
    person_id = await otp_service.verify_otp(db, email, body.code)
    if not person_id:
        raise HTTPException(status_code=401, detail="Invalid or expired code")
    person = db_persons.get_by_id(db, person_id)
    if person is None:
        raise HTTPException(status_code=401, detail="User not found")
    refuse_if_deactivated(person)

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
        # Origin's own method: the person signed in just now, on this form.
        "auth_time": int(datetime.now(timezone.utc).timestamp()),
    }
    if auth_request.get("setup_operator_token"):
        authorization_codes[auth_code]["setup_operator_token"] = auth_request["setup_operator_token"]

    params = {"code": auth_code}
    if auth_request.get("state"):
        params["state"] = auth_request["state"]
    from origin.services import origin_session
    response = JSONResponse({"redirect": _with_query(auth_request['redirect_uri'], params)})
    if _starts_origin_session(auth_request, db):
        origin_session.start(db, response, str(person.id))
    return response


# ---------------------------------------------------------------------------
# Password gates shared by both password endpoints
#
# `/authorize/password` and `/auth/password/login` prove the same credential by two routes. Any
# gate written into one and not the other is a way around it, so the three below are functions
# rather than repeated blocks: a gate that exists once cannot be added to one path and forgotten on
# the other.
# ---------------------------------------------------------------------------
def _spend_password_attempt(identifier: str) -> None:
    """Charge this attempt to the identifier's window budget, or refuse it with 429.

    Called before the account lookup and before any await, on every path alike, so what a caller
    can observe does not depend on whether the account exists, and so guesses sent at the same
    moment are each counted before any of them reaches its key derivation. A correct password
    takes the charge back (`guess_budget.clear_password_failures`).

    Only the identifier as typed is charged, never the other names of the account it resolves to.
    Charging an account's username on a failure through its email (or the reverse) would let
    anyone test whether two names belong to one account by spending one and watching the other
    throttle. An account whose username differs from its email therefore has two budgets; that is
    the price of the counter saying nothing about which names go together.

    The 429 and its wording are `otp_router`'s: a password guesser and an OTP guesser learn the
    same thing from a refusal, which is that they are being counted.
    """
    if not guess_budget.spend_password_attempt(identifier):
        logger.warning(
            "password attempt throttled for identifier %s — %d attempts inside the window",
            _log_tag(identifier.lower()),
            guess_budget.password_window_cap(),
        )
        raise HTTPException(
            status_code=429, detail="Too many attempts. Please try again later."
        )


def _log_password_failure(identifier: str, reason: str) -> None:
    """Record a failed password at WARNING, as OTP (`otp_service.verify_otp`) and passkey
    (`passkey_service`) failures are, so a credential-stuffing run leaves a trace and a limiter
    firing on it is visible. The attempt was already charged by `_spend_password_attempt`.

    `reason` distinguishes the two failure paths for whoever reads the log, and appears nowhere in
    the response — the caller gets one indistinguishable 401 either way.
    """
    logger.warning("password authentication failed for identifier %s (%s)",
                   _log_tag(identifier.lower()), reason)


async def _upgrade_password_hash_if_stale(
    db: Session, person_id, verified_hash: str, password: str
) -> None:
    """Re-hash at the current cost, on the one occasion the plaintext is in hand.

    `verify_password` reads the iteration count out of the stored hash, so raising the configured
    count leaves every existing hash verifying at the count it was written with — correct, and also
    permanent: without this, an account created before a raise keeps its old cost until its owner
    resets their password, which most never do. Successful sign-in is the only moment Origin holds
    a password it can re-derive from.

    `verified_hash` is the hash the password was just checked against. The new hash replaces it
    only if it is still the stored one (`persons.replace_password_hash`): the derivation is awaited,
    and a password reset committed meanwhile must win over a re-hash of the password it replaced.

    Best-effort: a failed re-hash must not fail a sign-in that has already succeeded. Nothing is
    read from the database before the derivation, so no connection is held across it.
    """
    try:
        if origin_auth_service.password_hash_is_current(verified_hash):
            return
        new_hash = await run_kdf(hash_password, password)
        if db_persons.replace_password_hash(db, str(person_id), verified_hash, new_hash):
            db.commit()
            logger.info("upgraded stored password hash to the current cost for person %s",
                        person_id)
        else:
            db.rollback()
            logger.info("stored password hash for person %s changed during the upgrade; left as "
                        "it is", person_id)
    except Exception:  # pragma: no cover — never let a rehash cost someone their session
        db.rollback()
        logger.warning("password hash upgrade failed for person %s", person_id, exc_info=True)


def _release_db(db: Session) -> None:
    """End the session's read-only transaction so its pooled connection goes back to the pool.

    Called before every wait that can take a while: a key derivation, which may also wait in the
    derivation queue, and a mail send, whether awaited inline (`_send_verification_email`) or queued
    as a background task that runs after the response (`_queue_verification_email`, the reset
    link). A request holding a connection across such a wait takes one of the pool's few
    connections (5, plus 10 overflow) for all of it, and once they are all held, the next checkout
    blocks the event loop until the pool's timeout. Loaded objects are expired, so reading one
    afterwards takes a connection again, briefly, for the reload. It is called only where every
    write so far has been committed, so the rollback discards nothing.
    """
    db.rollback()


class _LocalPasswordVerify(BaseModel):
    oauth_state: str
    identifier: _Identifier
    password: str


@auth_router.post("/authorize/password", dependencies=_KDF_ADMISSION)
async def authorize_local_password(
    request: Request, body: _LocalPasswordVerify, db: Session = Depends(get_db)
):
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
    # endpoints counting into two budgets would be one budget an attacker gets twice. Charged here,
    # before anything is awaited (see `_spend_password_attempt`).
    _spend_password_attempt(identifier)

    if "@" in identifier:
        person = person_service.get_user_by_email(db, identifier.lower())
    else:
        person = person_service.get_user_by_username(db, identifier)
    stored_hash = person.password_hash if person else None
    person_id = person.id if person else None
    _release_db(db)

    # The dummy verify is the answer to a timing oracle: returning early for an unknown account
    # makes "no such user" measurably faster than "wrong password", which turns this endpoint into
    # an account-enumerator that no message needs to leak. Same reason, same call, as
    # `/auth/password/login`.
    # The key derivation runs off the event loop, on its own limiter (`run_kdf`): it is
    # deliberately slow, and on the loop it would stall every other request Origin is serving.
    if not stored_hash:
        await run_kdf(dummy_verify_password, password)
        _log_password_failure(identifier, "no such account or no password set")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not await run_kdf(verify_password, password, stored_hash):
        _log_password_failure(identifier, "wrong password")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    guess_budget.clear_password_failures(identifier)
    await _upgrade_password_hash_if_stale(db, person_id, stored_hash, password)
    # After the password, so only its holder learns the account is deactivated; before the
    # confirmation link below, so a deactivated account is mailed nothing.
    refuse_if_deactivated(person)

    # This gate is why the account-linking rule holds. An unverified password account signing in
    # here would still carry `email_verified=False`, but as a live session on an address nobody
    # proved — and `person_service` does not link an unproven address to an existing Google
    # identity. Skipping this gate would leave that check as the only thing standing between an
    # unproven address and someone else's account.
    if not person.email_verified and email_verification_required(person.email):
        # Mailed without a verification nonce, so the link verifies the address and signs nobody
        # in. That is this flow's intended shape: the chooser page holds no session and has no
        # storage the verify page reads, and the sign-in it was completing is still pending here
        # (`_pop_local_auth_request` does not consume it), so after verifying, the person finishes
        # on this same page with the password they just used.
        await _send_verification_email(person, db=db, request=request)
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


class _LocalRegister(BaseModel):
    model_config = ConfigDict(extra="forbid")
    oauth_state: str
    email: _Identifier
    password: str


#: What both registration endpoints answer when account creation is refused.
#:
#: Registration does reveal whether an address or username is taken: a well-formed one that is
#: already registered gets this 400, where a free one is created. That is the price of telling a
#: person at once that they already have an account, and this sentence names the two ways forward
#: for exactly that person. What it keeps back is anything more: one sentence for every refusal
#: `person_service` raises, so it does not say whether the username or the email matched.
_REGISTRATION_REFUSED = (
    "Couldn't create that account. If you already have one, sign in or reset your password."
)


@auth_router.post("/authorize/register", dependencies=_KDF_ADMISSION)
async def authorize_local_register(
    request: Request,
    body: _LocalRegister,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Create an account for a sign-in already in flight, and continue that sign-in.

    Distinct from `/auth/password/register`, which mints an access + refresh token directly. That
    grant cannot complete PKCE, so a person who registered there would have their pending
    authorization request dropped and land on `/account` rather than back at the service provider
    that sent them. This endpoint creates the same account and ends at `_complete_local_signin`,
    the same tail the password and OTP legs use, so the caller receives an authorization code for
    the request they originally made.

    Every gate `/auth/password/register` applies is applied here too, each named at its call site:
    a gate present on one registration path and missing on the other is a way around it.

    The email IS the username, matching the form on `/login`. Two registration surfaces that
    disagreed about what identifies an account would produce accounts that only one of them could
    later find.
    """
    _refuse_if_registration_paused()
    auth_request = _pop_local_auth_request(body.oauth_state)

    # The same 404 `/auth/password/register` gives. A disabled method reachable through a second
    # URL is not disabled.
    if not platform_settings.get_bool("auth.password.enabled", True):
        raise HTTPException(status_code=404, detail="Password auth is disabled")

    email = (body.email or "").strip().lower()
    password = body.password or ""
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Enter a valid email address")
    min_len = platform_settings.get_int("auth.password.min_length", 12)
    if len(password) < min_len:
        raise HTTPException(
            status_code=400, detail=f"Password must be at least {min_len} characters"
        )

    verify_required = email_verification_required(email)
    password_hash = await run_kdf(hash_password, password)
    try:
        person = person_service.create_user_with_password(
            db,
            username=email,
            name="",            # the person names themselves; never their address's local part
            password_hash=password_hash,
            email=email,
            # Recorded verified only once proven (the link, or an OTP sign-in), whatever the plane
            # asks: a targeted invite, and every peer, read this flag as proof of the address.
            email_verified=False,
        )
        db.commit()
    except PermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        db.rollback()
        # One sentence for every refusal; see `_REGISTRATION_REFUSED` for what a refusal still
        # reveals (that the address is taken) and what it does not.
        logger.info("local-authorize registration failed (%s)", exc)
        raise HTTPException(status_code=400, detail=_REGISTRATION_REFUSED)

    # Verification required: the account exists but the mailbox is not proved, so the flow stops
    # here rather than minting a code. `_pop_local_auth_request` reads without popping, so the
    # pending request survives and the person can sign in on this same page after confirming.
    if verify_required:
        queued = _queue_verification_email(background_tasks, person, db=db, request=request)
        return {"verification_required": True, "email": queued}

    from origin.services.auth_service import is_person_allowed

    # The same admission gate the password, OTP and federated legs apply. Creating an account
    # proves an address, not that this authority admits its holder.
    if not is_person_allowed(None, person.email or ""):
        raise HTTPException(status_code=403, detail="User not allowed")

    background_tasks.add_task(
        person_service.record_person_event,
        {"sub": str(person.id), "email": person.email, "name": person.name},
        "password_register",
    )
    return _complete_local_signin(db, body.oauth_state, auth_request, person)


def federation_kwargs(auth_request: dict) -> dict:
    """What a pending sign-in asks of the upstream provider: a fresh sign-in (`prompt=login`,
    `max_age=0`) when it is a re-authentication."""
    out: dict = {}
    if auth_request.get("prompt") == "login":
        out["prompt"] = "login"
    if auth_request.get("max_age") is not None:
        out["max_age"] = int(auth_request["max_age"])
    return out


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

    extra_kwargs.update(federation_kwargs(auth_request))
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


def _with_query(uri: str, params: dict) -> str:
    """`uri` with `params` appended to its query (RFC 6749 §4.1.2): a listed URI may carry one."""
    return f"{uri}{'&' if '?' in uri else '?'}{urlencode(params)}"


def _require_s256_verifier(auth_data: dict, code_verifier: Optional[str]) -> None:
    """The code's PKCE proof: an S256 challenge was recorded (every flow records one), and
    `code_verifier` hashes to it. 400 otherwise."""
    if auth_data.get("code_challenge_method") != "S256" or not auth_data.get("code_challenge"):
        raise HTTPException(status_code=400, detail="This code carries no PKCE challenge (S256).")
    if not code_verifier:
        raise HTTPException(status_code=400, detail="Missing code_verifier for PKCE")
    digest = hashlib.sha256(code_verifier.encode()).digest()
    computed = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    if not secrets.compare_digest(computed, str(auth_data["code_challenge"])):
        raise HTTPException(status_code=400, detail="Invalid code_verifier")


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
    prompt: Optional[str] = None,
    max_age: Optional[int] = None,
    login_hint: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """OAuth2 authorization endpoint. Redirects to the upstream OIDC provider.

    `prompt=login` and `max_age=0` ask for a fresh sign-in (a re-authentication): they are passed
    to a federated provider, and Origin's own methods never read a session anyway.

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

    Only to a URI configured for that client, compared whole (RFC 6749 §3.1.2.2,
    `auth_service.redirect_uri_matches_registered`). A first-party client's URIs are its entry in
    `CLIENT_REDIRECT_URIS`; a registered client's are its own registration, which
    `CLIENT_REGISTRATION_REDIRECT_URIS` bounded when it was made. No URI is admitted by code: no
    tool page, no loopback default, no base taken from `FACET_URI`/`FACET_URIS`/`ORIGIN_URI`. The
    one variation is RFC 8252 §7.3's: a listed http loopback URI admits any port. Every refusal is
    a 403 naming the setting to change.

    An id that is both configured and registered is treated as configured, and is held to
    `CLIENT_REDIRECT_URIS` rather than its registration: naming an id in `PLATFORM_CLIENT_IDS` is
    the operator's stronger statement, and it keeps a first-party sign-in from depending on a row.

    PKCE with S256 is required of every flow (RFC 9700 §2.1.1); `plain` and a missing challenge
    are refused before anything starts.
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

    # Where the code may go: only to a URI configured for this client, compared whole. A
    # first-party client's URIs are `CLIENT_REDIRECT_URIS[client_id]`; a registered client's are
    # its registration's. No URI is admitted by code, and none is refused by name. The listed URIs
    # are not echoed back: the operator has them, and anyone else is asking to be told.
    if registration is None:
        if not is_client_redirect_allowed(redirect_uri, client_id=client_id):
            logger.warning("Refused /authorize: redirect_uri not configured for client_id=%s",
                           client_id)
            raise HTTPException(
                status_code=403,
                detail=f"redirect_uri is not configured for client_id {client_id!r}. A first-party "
                       "client receives its code only at a URI listed for it, exactly, in "
                       "CLIENT_REDIRECT_URIS; add the URI there to use it.",
            )
    elif not is_registered_redirect_allowed(redirect_uri, registration.redirect_uris):
        logger.warning(
            "Refused /authorize: registered client_id=%s asked for an unregistered redirect_uri",
            client_id,
        )
        raise HTTPException(
            status_code=403,
            detail=f"redirect_uri is not in client_id {client_id!r}'s registration. A registered "
                   "client receives its code only at a URI it registered, exactly; register the "
                   "URI to use it (POST /auth/register, bounded by "
                   "CLIENT_REGISTRATION_REDIRECT_URIS).",
        )

    # PKCE, S256 only, on every authorization-code flow (RFC 9700 §2.1.1). A request without a
    # challenge, or with `plain`, starts nothing: the code it would mint could be redeemed by
    # whoever intercepted it.
    if not code_challenge:
        raise HTTPException(status_code=400, detail="code_challenge is required (PKCE, S256).")
    if code_challenge_method != "S256":
        raise HTTPException(status_code=400, detail="code_challenge_method must be 'S256'.")
    if len(code_challenge) != 43 or not _B64URL_RE.fullmatch(code_challenge):
        raise HTTPException(
            status_code=400,
            detail="code_challenge must be the 43-character base64url SHA-256 of the verifier.",
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
        "prompt": "login" if prompt == "login" else None,
        "max_age": max_age if isinstance(max_age, int) and max_age >= 0 else None,
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
                # OIDC `login_hint`: the account the client already knows, filled in. Only a hint;
                # the sign-in proves whoever signs in.
                login_hint=(login_hint or "").strip()[:254],
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

    extra_kwargs.update(federation_kwargs(auth_request))
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
                url=_with_query(auth_request['redirect_uri'], error_params),
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
            # When the provider says the person signed in (OIDC `auth_time`), for a
            # re-authentication's freshness check; absent when it does not say.
            "auth_time": (user_info.get("auth_time") if isinstance(user_info.get("auth_time"),
                                                                   (int, float)) else None),
        }
        if auth_request.get("setup_operator_token"):
            authorization_codes[auth_code]["setup_operator_token"] = auth_request["setup_operator_token"]
        _prune_auth_cache(datetime.now(timezone.utc))

        params = {"code": auth_code}
        if auth_request["state"]:
            params["state"] = auth_request["state"]
        # The sign-in this state began is spent: the code now carries it.
        pkce_challenges.pop(oauth_state, None)
        response = RedirectResponse(
            url=_with_query(auth_request['redirect_uri'], params),
            status_code=status.HTTP_302_FOUND,
        )
        # Origin's own session, for a person Origin already knows by this identity.
        from origin.db.session import SessionLocal
        from origin.services import origin_session
        with SessionLocal() as sdb:
            known = person_service.get_user_by_oidc_identity(sdb, provider, str(user_info["sub"]))
            if _starts_origin_session(auth_request, sdb):
                origin_session.start(sdb, response,
                                     str(known.id) if known is not None else None)
        return response

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
                url=_with_query(auth_request['redirect_uri'], error_params),
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
    request: Request,
    background_tasks: BackgroundTasks,
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    subject_token: Optional[str] = Form(None),
    subject_token_type: Optional[str] = Form(None),
    audience: Optional[str] = Form(None),
    scope: Optional[str] = Form(None),
    client_assertion_type: Optional[str] = Form(None),
    client_assertion: Optional[str] = Form(None),
    actor_token: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    if grant_type == _TOKEN_EXCHANGE:
        # A delegation narrowed to a persona, exchanged for one narrowed to the next persona, is a
        # hop (review 12, decision 2): proven by that persona's own client assertion (RFC 7523).
        from jose import jwt as _jose_jwt

        from origin.services.dependencies import _is_narrowed
        try:
            unverified = _jose_jwt.get_unverified_claims(subject_token or "")
            narrowed_subject = _is_narrowed(unverified)
        except Exception:  # noqa: BLE001
            unverified, narrowed_subject = {}, False
        if (narrowed_subject and subject_token_type == _ACCESS_TOKEN_TYPE
                and audience == _EMBER_TO and unverified.get("aud") == _EMBER):
            return _ember_for_mantle(db, subject_token or "", actor_token)
        if narrowed_subject and subject_token_type == _ACCESS_TOKEN_TYPE:
            caller = _hop_caller(db, subject_token or "", client_assertion_type, client_assertion)
            return _narrow_hop(db, caller, subject_token or "", audience or "", scope)
        return _grant_token_exchange(db, subject_token, subject_token_type, audience, scope)
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
        return await _grant_refresh_token(background_tasks=background_tasks, refresh_token=refresh_token,
                                          client_id=client_id, client_secret=client_secret,
                                          db=db)
    if grant_type == "client_credentials":
        if not client_id or not client_secret:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "client_id and client_secret are required"},
            )
        # The one grant here that spends a key derivation (bcrypt on the secret), so the one that
        # takes the same admission the sign-in routes do (`dependencies.kdf_admission`).
        try:
            kdf_key = origin_auth_service.kdf_admit(request.client.host if request.client else None)
        except origin_auth_service.KdfRefused as refused:
            return JSONResponse(
                status_code=refused.status_code,
                content={"error": "temporarily_unavailable", "error_description": refused.detail},
                headers={"Retry-After": str(refused.retry_after)},
            )
        try:
            return await _grant_client_credentials(
                db=db, client_id=client_id, client_secret=client_secret
            )
        finally:
            origin_auth_service.kdf_release(kdf_key)

    raise HTTPException(
        status_code=400,
        detail="Unsupported grant_type. Only 'authorization_code', 'refresh_token', "
               "'client_credentials' and token exchange are supported.",
    )


_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
_ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


def _narrow_response(person_id: str, audience: str, scopes: list) -> JSONResponse:
    token = origin_auth_service.issue_narrow_delegation(person_id, audience, scopes)
    return JSONResponse(content={
        "access_token": token, "issued_token_type": _ACCESS_TOKEN_TYPE, "token_type": "bearer",
        "expires_in": origin_auth_service.NARROW_TTL_SECONDS, "scope": " ".join(scopes)})


_EMBER, _EMBER_TO = "ember", "mantle"


def _ember_for_mantle(db: Session, subject_token: str, actor_token: Optional[str]) -> JSONResponse:
    """Ember's delegation for a person, exchanged by Ember for the same person's delegation
    addressed to Mantle (review 21, F6), so Ember never hands Mantle a token Ember itself takes.

    The subject is a delegation Origin narrowed to Ember (`aud` = `act.sub` = `ember`), not a hop's
    result. The actor (`actor_token`) is Ember's own account's access token: Origin's delegation
    narrowed to Ember for a service account whose audience is Ember. The result: `aud` `mantle`,
    actor `ember`, the subject's scopes, never past the subject, no refresh token, recorded as a
    hop (`narrow_hops`), and never exchanged again."""
    from jose import jwt as _jose_jwt

    from origin.models.narrow_hop import NarrowHop
    from origin.services import not_before as _not_before
    from origin.services import service_accounts
    from origin.services.dependencies import _is_narrowed

    def _ember_own(claims) -> bool:
        return bool(claims) and _is_narrowed(claims) and claims.get("aud") == _EMBER             and (claims.get("act") or {}).get("sub") == _EMBER and not claims.get("hop")

    claims = verify_token(subject_token)
    if not _ember_own(claims):
        raise HTTPException(status_code=403, detail="only Ember's own delegation for a person is "
                            "exchanged for Mantle")
    actor = verify_token(actor_token or "") if actor_token else None
    if (not _ember_own(actor)
            or service_accounts.audience_of(str(actor.get("sub") or "")) != _EMBER):
        raise HTTPException(status_code=401, detail="the exchange is Ember's own, on its own "
                            "account's token (actor_token)")
    if _not_before.ended(db, claims) or _not_before.ended(db, actor):
        raise HTTPException(status_code=401, detail="this sign-in has ended; sign in again")
    person = db_persons.get_by_id(db, str(claims.get("sub") or ""))
    if person is None:
        raise HTTPException(status_code=401, detail="Invalid subject")
    refuse_if_deactivated(person)
    scopes = str(claims.get("scope") or "").split()
    ends = datetime.fromtimestamp(float(claims.get("exp") or 0), timezone.utc)
    token = origin_auth_service.issue_narrow_delegation(
        str(person.id), _EMBER_TO, scopes, expires_at=ends, actor=_EMBER,
        hop={"from": _EMBER, "jti": str(claims.get("jti") or "")})
    issued = _jose_jwt.get_unverified_claims(token)
    db.add(NarrowHop(jti=str(issued["jti"]), sub=str(person.id),
                     subject_jti=str(claims.get("jti") or ""), from_aud=_EMBER, to_aud=_EMBER_TO))
    db.commit()
    return JSONResponse(content={
        "access_token": token, "issued_token_type": _ACCESS_TOKEN_TYPE, "token_type": "bearer",
        "expires_in": max(0, int(issued["exp"] - datetime.now(timezone.utc).timestamp())),
        "scope": " ".join(scopes)})


def _grant_token_exchange(db: Session, subject_token: Optional[str],
                          subject_token_type: Optional[str], audience: Optional[str],
                          scope: Optional[str]) -> JSONResponse:
    """RFC 8693 for a person's own access token: refused (review 23, H1). A bearer alone never
    narrows: Mantle holds the person's token on every call and would mint a delegation narrowed to
    any persona. A person's narrowed delegation is made in their Origin session
    (`POST /auth/me/authority/narrow`, `narrow_for_person`)."""
    raise HTTPException(status_code=400, detail="a person's delegation is narrowed only in their "
                        "Origin session: POST /auth/me/authority/narrow")


def narrow_for_person(db: Session, person_id: str, audience: Optional[str],
                      scope: Optional[str]) -> JSONResponse:
    """A delegation for the person narrowed to one audience (Ember, a persona's facet, the relay)
    and to that audience's scopes, five minutes long, never `platform:admin`, with no refresh token
    (review 8, R3), for a person signed in to their Origin session (the caller checks that)."""
    allowed = origin_auth_service.narrow_audiences()
    if not audience or audience not in allowed:
        raise HTTPException(status_code=400, detail="audience is not a narrow audience")
    person = db_persons.get_by_id(db, str(person_id or ""))
    if person is None:
        raise HTTPException(status_code=401, detail="Invalid subject")
    refuse_if_deactivated(person)
    asked = (scope or "").split() or [s for s in allowed[audience]
                                      if s not in origin_auth_service.OPT_IN_SCOPES]
    if not set(asked) <= set(allowed[audience]):
        raise HTTPException(status_code=400, detail=f"scope outside {audience}'s")
    return _narrow_response(str(person.id), audience, asked)


async def _grant_authorization_code(
    *,
    db: Session,
    background_tasks: BackgroundTasks,
    code: str,
    redirect_uri: str,
    client_id: str,
    code_verifier: Optional[str],
):
    # Single use (RFC 9700 §2.1.1): the code is taken out of the store before anything is checked,
    # so a failed attempt (wrong client, redirect_uri or verifier) spends it as a success would.
    auth_data = authorization_codes.pop(code, None)
    _prune_auth_cache(datetime.now(timezone.utc))
    if auth_data is None:
        raise HTTPException(status_code=400, detail="Invalid or expired authorization code")

    if client_id != auth_data["client_id"]:
        raise HTTPException(status_code=400, detail="Invalid client_id")
    # The exact URI the code was issued for (RFC 6749 §4.1.3), compared whole.
    if redirect_uri != auth_data["redirect_uri"]:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    if datetime.now(timezone.utc) - auth_data["timestamp"] > _CODE_TTL:
        raise HTTPException(status_code=400, detail="Authorization code expired")
    _require_s256_verifier(auth_data, code_verifier)

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
    # Both branches below, the scoped third-party token included.
    refuse_if_deactivated(user)

    if _is_first_party_client(issuing_client_id):
        # First-party client → full user JWT
        user_data = person_token_claims(
            user, client_id=issuing_client_id, roles=_compute_roles(str(user.id)),
        )
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

    # A sign-in delivered to a persona's facet (`NARROW_FACETS`) gets a delegation narrowed to that
    # facet, never the platform token or a refresh token. Delivered anywhere but the web app
    # (`APP_URI`), Origin's own pages or such a facet, it gets no token at all (review 12): a
    # redirect URL never picks the audience.
    if _is_first_party_client(issuing_client_id):
        persona = origin_auth_service.facet_narrowing(auth_data.get("redirect_uri") or "")
        if persona is False:
            raise HTTPException(status_code=400, detail="this facet is not one Origin narrows a "
                                "sign-in to (NARROW_FACETS)")
        if persona:
            background_tasks.add_task(person_service.record_person_event, user_data,
                                      "auth_grant")
            return _narrow_response(str(user.id), persona,
                                    origin_auth_service.narrow_audiences()[persona])

    access_token = create_jwt_token(user_data)
    refresh_token = _refresh_tokens.issue(db, user_data)

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


async def _grant_refresh_token(*, background_tasks: BackgroundTasks, refresh_token: str,
                               db: Optional[Session] = None, client_id: Optional[str] = None,
                               client_secret: Optional[str] = None):
    """Exchange a refresh token for a fresh access token and the next refresh token.

    Refresh tokens rotate on use and are revocable (`services.refresh_tokens`): each is recorded by
    `jti` in its sign-in's family, taken here once, and replaced by the next in the family. A used
    one presented again is theft and revokes the whole family. A deactivated person's are revoked.

    None of this reaches a peer. Peers verify Origin's tokens offline against the inline JWKS in their
    authority manifest and never call back, so anything decided here binds at Origin only. The
    platform-wide revocation lag is the access token lifetime, which
    `auth_service.access_token_ttl_hours` brackets.
    """
    payload = verify_token(refresh_token)
    if not payload or payload.get("token_type") != "refresh":
        raise HTTPException(status_code=400, detail="Invalid refresh token")
    if not payload.get("aud"):
        raise HTTPException(status_code=400, detail="Refresh token has no audience — please log in again")
    # The client authenticates itself (review 11, M1): it names itself, and it must be the client
    # the family was issued to. A confidential client must prove its secret, which Origin holds
    # for no refresh-token client, so a registration that is not public refreshes nothing.
    if not client_id:
        raise HTTPException(status_code=400, detail="client_id is required")
    if db is not None:
        from origin.models.oauth_client import OAuthClient
        reg = db.get(OAuthClient, client_id)
        if reg is not None and (reg.token_endpoint_auth_method or "none") != "none":
            raise HTTPException(status_code=401, detail="a confidential client authenticates "
                                "with a secret Origin does not hold for refresh tokens")

    # The access token is its own: never the refresh token's `jti` or family.
    user_data = {k: v for k, v in payload.items()
                 if k not in ("exp", "token_type", "iat", "jti", "fam")}

    # A deactivated person's refresh tokens stop here, whichever client they were minted for.
    if db is not None and payload.get("sub"):
        try:
            holder = person_service.get_user_by_id(db, str(payload["sub"]))
        except (ValueError, TypeError):
            holder = None
        if holder is not None and getattr(holder, "deactivated_at", None) is not None:
            _refresh_tokens.revoke_person(db, str(payload["sub"]))
            db.commit()
        if holder is not None:
            refuse_if_deactivated(holder)

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

    if db is None:
        raise HTTPException(status_code=500, detail="the refresh grant needs the database")
    try:
        next_refresh = _refresh_tokens.rotate(db, refresh_token, payload, user_data,
                                              client_id=client_id)
    except _refresh_tokens.RefreshRefused as exc:
        logger.warning("refresh grant refused: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid refresh token")
    access_token = create_jwt_token({**user_data, "jti": secrets.token_hex(16)})
    background_tasks.add_task(person_service.record_person_event, user_data, "refresh_grant")
    return JSONResponse(
        content={
            "access_token": access_token,
            "refresh_token": next_refresh,
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
    secret_hash = credential.secret_hash.encode()
    _release_db(db)
    if not await run_kdf(bcrypt.checkpw, client_secret.encode(), secret_hash):
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
    """Every registered redirect must be one the operator configured for registration.

    Registration is how a URI comes to be configured for a client, so what it may record is itself
    configuration: each entry must appear in `CLIENT_REGISTRATION_REDIRECT_URIS`, compared whole
    (`auth_service.is_registration_redirect_allowed`; a listed http loopback URI admits any port,
    RFC 8252 §7.3). Nothing registers an arbitrary third-party address, and an empty list refuses
    every one. Two syntactic rules come first: the URI must be absolute, and it must carry no
    fragment (RFC 6749 §3.1.2).
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
        if not is_registration_redirect_allowed(uri):
            # Named setting: the operator is the only reader who can act on this.
            raise _RegistrationRefused(
                "invalid_redirect_uri",
                f"redirect_uri {uri!r} is not one a registration may name: it is not listed, "
                "exactly, in CLIENT_REGISTRATION_REDIRECT_URIS.",
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
        "app_uri": _app_uri(),
        "sso_return_uris": _sso_return_uris(),
    }


def _origin_parts(uri: str) -> Optional[tuple[str, str, int]]:
    """`(scheme, host, port)` of an http(s) URL, normalised the way two spellings of one origin
    compare equal: host lower-cased and without a trailing dot, the default port made explicit.
    None for anything else, a malformed port included."""
    p = urlparse(uri or "")
    if p.scheme not in ("http", "https") or not p.hostname:
        return None
    try:
        port = p.port
    except ValueError:
        return None
    host = p.hostname.lower().rstrip(".")
    if not host:
        return None
    return p.scheme, host, port or (443 if p.scheme == "https" else 80)


def _render_origin(parts: tuple[str, str, int], path: str = "/") -> str:
    scheme, host, port = parts
    netloc = f"[{host}]" if ":" in host else host
    if port != (443 if scheme == "https" else 80):
        netloc += f":{port}"
    return f"{scheme}://{netloc}{path}"


def _is_loopback_host(host: str) -> bool:
    """Every spelling of the visitor's own machine: `localhost` and its subdomains, 127.0.0.0/8,
    `::1`, an IPv4-mapped loopback, and the unspecified addresses."""
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_unspecified


def _own_origins() -> set:
    own = {_origin_parts(config.ORIGIN_URI), _origin_parts(getattr(config, "AUTHORITY_ISSUER", ""))}
    own.discard(None)
    return own


def _is_mantle(parts) -> bool:
    """Is this origin Mantle's? Mantle serves pages, so it is never the app nor an SSO return,
    whatever a setting says (`config.without_mantle` drops it from the environment's values; this
    holds for a value from the settings store too)."""
    mantle = _origin_parts(getattr(config, "MANTLE_URI", "") or "")
    return mantle is not None and parts == mantle


def _app_uri() -> Optional[str]:
    """The front end a signed-in person continues to from the account page, or None.

    `config.APP_URI` (env `APP_URI`, else the `branding.app_uri` setting) is an origin, and only an
    origin: a value carrying a path, query, fragment or credentials is refused and logged, not
    trimmed, so a misconfiguration is seen rather than half-applied. Also None when it is unset,
    not http(s), a loopback host, or Origin's own origin: a "continue" that led back here would be
    a loop, and one to loopback names the visitor's own machine.
    """
    raw = getattr(config, "APP_URI", "") or ""
    if not raw:
        return None
    parts = _origin_parts(raw)
    p = urlparse(raw)
    beyond_origin = (
        p.username or p.password or p.path not in ("", "/") or p.query or p.fragment or p.params
    )
    if parts is None or beyond_origin:
        logger.warning("APP_URI %r is not a bare http(s) origin; no app link is published", raw)
        return None
    if _is_loopback_host(parts[1]) or parts in _own_origins() or _is_mantle(parts):
        return None
    return _render_origin(parts)


def _sso_return_uris() -> list[str]:
    """The exact return URIs the sign-in pages hand an existing session to without a click.

    `SSO_RETURN_URIS` (env, else the `branding.sso_return_uris` setting), plus the app's root when
    `APP_URI` is set. Each is an https URL with no credentials, query or fragment, compared by the
    pages on origin and path exactly: a silent hand-off to any `*.agience.ai` page would turn an
    open redirect or user-authored page on any subdomain into a zero-click token leak. Entries that
    do not qualify are logged and left out.
    """
    extra = getattr(config, "SSO_RETURN_URIS", None) or []
    if isinstance(extra, str):
        extra = [u.strip() for u in extra.split(",") if u.strip()]
    app = _app_uri()
    out: list[str] = [app] if app and app.startswith("https://") else []
    for raw in extra:
        parts = _origin_parts(raw)
        p = urlparse(raw)
        qualifies = (
            parts is not None
            and parts[0] == "https"
            and not (p.username or p.password or p.query or p.fragment or p.params)
            and not _is_loopback_host(parts[1])
            and parts not in _own_origins()
            and not _is_mantle(parts)
        )
        if not qualifies:
            logger.warning("SSO return URI %r is not an https URL of another origin with no "
                           "query or fragment; it is not published", raw)
            continue
        uri = _render_origin(parts, p.path or "/")
        if uri not in out:
            out.append(uri)
    return out


# ---------------------------------------------------------------------------
# Password login + register
# ---------------------------------------------------------------------------
@auth_router.post("/password/login", dependencies=_KDF_ADMISSION)
async def password_login(
    request: Request,
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

    # Charged before anything is awaited (see `_spend_password_attempt`).
    _spend_password_attempt(identifier)

    if "@" in identifier:
        user = person_service.get_user_by_email(db, identifier.lower())
    else:
        user = person_service.get_user_by_username(db, identifier)
    stored_hash = user.password_hash if user else None
    user_id = user.id if user else None
    _release_db(db)

    # Off the event loop, as in `authorize_local_password`.
    if not stored_hash:
        await run_kdf(dummy_verify_password, password)
        _log_password_failure(identifier, "no such account or no password set")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not await run_kdf(verify_password, password, stored_hash):
        _log_password_failure(identifier, "wrong password")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    guess_budget.clear_password_failures(identifier)
    await _upgrade_password_hash_if_stale(db, user_id, stored_hash, password)
    # After the password, so only its holder learns the account is deactivated; before the
    # confirmation link below, so a deactivated account is mailed nothing.
    refuse_if_deactivated(user)

    # Block sign-in until the email is verified (when verification is required for
    # this email). Resend the link inline (await) so the user recovers in one step.
    # `error: email_unverified` tells the page this 403 mailed a link, unlike the
    # other 403s sign-in can give.
    if not user.email_verified and email_verification_required(user.email):
        await _send_verification_email(user, payload.verify_nonce, db=db, request=request)
        return JSONResponse(
            status_code=403,
            content={
                "detail": "Please verify your email to sign in. We've sent you a new verification link.",
                "error": "email_unverified",
            },
        )

    user_data = person_token_claims(
        user, client_id=getattr(config, "PLATFORM_CLIENT_ID", "platform"),
        roles=_compute_roles(str(user.id)),
    )
    access_token = create_jwt_token(user_data)
    refresh_token = _refresh_tokens.issue(db, user_data)
    background_tasks.add_task(person_service.record_person_event, user_data, "password_login")

    return _signed_in_on_page(request, db, str(user_id), {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": access_token_expires_in_seconds(),
        "refresh_token": refresh_token,
        "scope": "read write",
    })


@auth_router.post("/password/register", dependencies=_KDF_ADMISSION)
async def password_register(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: PasswordRegisterRequest,
    db: Session = Depends(get_db),
):
    _refuse_if_registration_paused()
    if not platform_settings.get_bool("auth.password.enabled", True):
        raise HTTPException(status_code=404, detail="Password auth is disabled")

    username = (payload.username or "").strip()
    email = (payload.email or "").strip().lower()
    password = payload.password or ""
    name = (payload.name or "").strip()

    if not username:
        raise HTTPException(status_code=400, detail="Username is required")
    # Required: confirmation is the only proof that an account's owner is reachable, and an
    # account with no address has nothing to confirm, so it would be live the moment it exists.
    if not email:
        raise HTTPException(status_code=400, detail="An email address is required")
    if "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email address")
    min_len = platform_settings.get_int("auth.password.min_length", 12)
    if len(password) < min_len:
        raise HTTPException(status_code=400, detail=f"Password must be at least {min_len} characters")

    verify_required = email_verification_required(email)
    password_hash = await run_kdf(hash_password, password)
    try:
        user = person_service.create_user_with_password(
            db,
            username=username,
            name=name,
            password_hash=password_hash,
            email=email,
            # Recorded verified only once proven (the link, or an OTP sign-in), whatever the plane
            # asks: a targeted invite, and every peer, read this flag as proof of the address.
            email_verified=False,
        )
        db.commit()
    except PermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        db.rollback()
        logger.info("Password registration failed for username %s (%s)",
                    _log_tag(username.lower()), exc)
        raise HTTPException(status_code=400, detail=_REGISTRATION_REFUSED)

    # Verification required: don't auto-login — send the link and tell the client
    # to prompt for confirmation. The user signs in after verifying.
    if verify_required:
        queued = _queue_verification_email(
            background_tasks, user, payload.verify_nonce, db=db, request=request
        )
        return {"verification_required": True, "email": queued}

    user_data = person_token_claims(
        user, client_id=getattr(config, "PLATFORM_CLIENT_ID", "platform"),
        roles=_compute_roles(str(user.id)),
    )
    access_token = create_jwt_token(user_data)
    refresh_token = _refresh_tokens.issue(db, user_data)
    background_tasks.add_task(person_service.record_person_event, user_data, "password_register")

    return _signed_in_on_page(request, db, str(user.id), {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": access_token_expires_in_seconds(),
        "refresh_token": refresh_token,
        "scope": "read write",
    })


# ---------------------------------------------------------------------------
# Email verification
# ---------------------------------------------------------------------------
@auth_router.post("/email/verify-request")
async def email_verify_request(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: EmailVerifyRequestBody,
    db: Session = Depends(get_db),
):
    """Resend an email-verification link. Always returns 200 (never reveals
    whether the email exists); no-op if already verified. Email must be
    configured.

    Throttled by the mail-send budget `_mail_send_admitted` applies, the one
    `/auth/password/reset-request` shares; see there for what a flooded address keeps."""
    if not email_service.is_configured():
        raise HTTPException(status_code=503, detail="Email service not configured.")
    email = otp_service.normalize_email(payload.email)
    tag = _mail_send_admitted(request, email, "verification resend")
    if tag is None:
        return {"sent": True}
    user = person_service.get_user_by_email(db, email)
    if user and user.email and not user.email_verified and not is_deactivated(user):
        _queue_verification_email(background_tasks, user, payload.verify_nonce, db=db)
        logger.info("Verification email re-queued for address %s", tag)
    return {"sent": True}


def _mail_context(request: Optional[Request]) -> str:
    """The "requested on ... from ..." line a sign-in mail carries (`email_service.request_context`)."""
    if request is None:
        return ""
    return email_service.request_context(request.headers.get("user-agent"))


def _mail_send_admitted(request: Request, email: str, what: str) -> Optional[str]:
    """Charge one unauthenticated mail send to `guess_budget`'s shared send budget. Returns the
    address's log tag when the send may go ahead, None when it must be dropped.

    The budget is per (address, client), and more loosely per address and per client. Past any cap
    the send is dropped silently and the caller answers with its usual 200: every well-formed
    address is charged whether or not an account answers to it, so the response never depends on
    one existing. Something that cannot be an address matches no account and is not charged. A
    domain without a dot (`localhost`, an intranet name) is an address: accounts live there.

    The per-address cap is deliberately a cap on flooding one inbox, and it holds against the
    address's owner too: four or more clients (`guess_budget._MAIL_SEND_CLIENTS`) each spending
    their per-(address, client) budget use it up, and neither a resend nor a reset link reaches
    that address until the window passes. An emailed code is no fallback here: the code-request
    routes are charged to this same budget. What the owner keeps is sign-in that sends no mail: the
    password of a confirmed account, or a passkey, where they have one.

    Every unauthenticated route that mails is charged here: the resend and reset routes directly,
    the code-request routes through `_mail_sign_in_code`, and the confirmation link sent on
    registration and on a password sign-in to an unconfirmed account through the `request` those
    callers hand the two send helpers. An address its registrant chose is otherwise one they can
    have mailed again on every sign-in attempt.

    The client is `request.client.host`. That is the connecting peer unless the connection comes
    from uvicorn's `FORWARDED_ALLOW_IPS` (default 127.0.0.1), in which case uvicorn takes it from
    `X-Forwarded-For`. The deployment this assumes: the reverse proxy in front of Origin runs on the
    same host and sets `X-Forwarded-For` from its own peer, not from the header it received. A
    proxy that forwards a caller's header verbatim lets the caller choose its own key.
    """
    local, _, domain = email.partition("@")
    if not local or not domain or "@" in domain:
        return None
    client = (request.client.host if request.client else "") or "unknown"
    tag = _log_tag(email)
    if guess_budget.mail_sends_exhausted(email, client):
        logger.warning("%s throttled for address %s from %s", what, tag, client)
        return None
    guess_budget.record_mail_send(email, client)
    return tag


@auth_router.post("/email/verify-confirm", dependencies=_KDF_ADMISSION)
async def email_verify_confirm(
    background_tasks: BackgroundTasks,
    payload: EmailVerifyConfirmBody,
    db: Session = Depends(get_db),
):
    """Confirm an email-verification token and mark the email verified. Signs the person in
    only when the redeeming browser presents the nonce the link was minted for (see
    `_verification_nonce_matches`); otherwise answers `{"verified": true}` with no token.

    An account with a password is confirmed only with that password. The link proves who holds the
    mailbox, not who chose the password, and registration takes no proof of the address: anyone can
    register a stranger's address with a password of their own, and were the stranger's click
    enough, that password would open the stranger's confirmed account (and a Google sign-in on it
    later would land there too). Without `password` the answer is `{"password_required": true}` and
    nothing changes, so a mail scanner redeeming the link by itself consumes nothing. The mailbox's
    holder who did not register the account sends `disown` instead: the address is confirmed as
    theirs and the password someone else set is dropped (`password_cleared`), and they sign in with
    an emailed code. An account with no password (federated, or made by a code) confirms as before.
    """
    claims = verify_token(payload.token)
    if not claims or claims.get("token_type") != "email_verify" or not claims.get("sub"):
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")

    user = person_service.get_user_by_id(db, str(claims["sub"]))
    if user is None:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")
    # Before anything below changes the account (verifying it, or disowning its password).
    refuse_if_deactivated(user)

    # Single-use, by the same mechanism the reset tokens use — see `_email_fingerprint`. Without it
    # this endpoint is replayable for the token's full 24 hours, and each replay re-mints a 30-day
    # refresh token. That is not a theoretical replay: `web/verify-email.html` POSTs here on page
    # load with no interaction, so a link scanner, a mail-security crawler or a revisit from
    # history redeems the link again by itself.
    if _email_fingerprint(user) != claims.get("evf"):
        # One refusal is worded differently: the link was minted for this account's CURRENT address
        # and the only field that moved is `email_verified`. That is the fingerprint of the same
        # person with the flag still False, so it is told apart by recomputing it, not by trusting
        # anything the token says. It is still refused and still mints nothing — single use is
        # untouched — and only someone holding a validly signed link for this account can see it.
        if user.email_verified and _email_fingerprint(
            SimpleNamespace(email=user.email, email_verified=False)
        ) == claims.get("evf"):
            return JSONResponse(
                status_code=400,
                content={"detail": "This email is already verified — sign in.",
                         "error": "already_verified"},
            )
        logger.warning("email verification token replayed or stale for person %s", user.id)
        raise HTTPException(
            status_code=400,
            detail="This verification link is no longer valid. Request a new one.",
        )

    password_cleared = False
    if user.password_hash and payload.disown:
        user.password_hash = None
        password_cleared = True
    elif user.password_hash:
        if not payload.password:
            return {"password_required": True}
        # Its own budget, per account in a ledger of its own (`guess_budget.
        # spend_confirmation_attempt`), not the sign-in budget keyed by the address: anyone can
        # spend that one by trying to sign in as the address, and a registrant refused here is
        # steered to disowning their own account. Only holders of a link for this account reach
        # it, and they hold the mailbox and can disown anyway, so guessing here gains nothing
        # sign-in does not already allow.
        stored_hash, user_id = user.password_hash, str(user.id)
        # Charged before anything is awaited, as `_spend_password_attempt` is.
        if not guess_budget.spend_confirmation_attempt(user_id):
            logger.warning("email confirmation throttled for person %s — %d attempts inside the "
                           "window", user_id, guess_budget.password_window_cap())
            raise HTTPException(status_code=429, detail="Too many attempts. Please try again later.")
        _release_db(db)
        if not await run_kdf(verify_password, payload.password, stored_hash):
            logger.warning("wrong password confirming the address of person %s", user_id)
            raise HTTPException(status_code=401, detail="That password doesn't match this account.")
        guess_budget.clear_confirmation_failures(user_id)
        # Read again after the wait: a confirmation that finished meanwhile has moved the
        # fingerprint, and this one must then be refused as used.
        user = person_service.get_user_by_id(db, user_id)
        if user is None or _email_fingerprint(user) != claims.get("evf"):
            raise HTTPException(
                status_code=400,
                detail="This verification link is no longer valid. Request a new one.",
            )

    person_service.set_email_verified(db, str(user.id), True)
    db.commit()
    if password_cleared:
        logger.info("address confirmed by its mailbox's holder for person %s, who disowned the "
                    "registration; its password was dropped", user.id)

    user_data = person_token_claims(
        user, client_id=getattr(config, "PLATFORM_CLIENT_ID", "platform"),
        roles=_compute_roles(str(user.id)),
    )
    # Every verification is recorded, signed in or not.
    background_tasks.add_task(person_service.record_person_event, user_data, "email_verified")

    if password_cleared:
        # The holder disowned the registration: whichever browser this is, it signed nothing up.
        return {"verified": True, "password_cleared": True}
    if not _verification_nonce_matches(claims, payload.verify_nonce):
        logger.info("email verified for person %s without the starting browser's nonce; "
                    "no session minted", user.id)
        return {"verified": True}

    access_token = create_jwt_token(user_data)
    refresh_token = _refresh_tokens.issue(db, user_data)

    # `email` lets a tab of this browser waiting on the same registration tell that it was this
    # address that was verified. Only the browser that started the verification is told.
    return {
        "verified": True,
        "email": user.email,
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


def _nonce_hash(nonce: str) -> str:
    return hashlib.sha256(nonce.encode()).hexdigest()


def _verification_nonce_matches(claims: dict, presented: str) -> bool:
    """Does the redeeming browser hold the nonce the link was minted for?

    A verification link is a bearer credential for the account it names, and anyone can forward
    theirs: register `attacker@x`, mail the victim the link, and a redemption that signs in would
    sign the victim's browser in as the attacker (login CSRF), after which the sign-in page's silent
    SSO would keep handing that session to the app. So the link only proves the mailbox. Signing in
    additionally needs the random nonce the starting browser generated, kept in its own storage and
    sent with the request that mailed the link, whose hash the token carries as `vnh`. A link
    opened on another device or browser still verifies the address; it just does not sign anyone in.
    """
    expected = claims.get("vnh")
    if not expected or not presented:
        return False
    return secrets.compare_digest(_nonce_hash(presented), str(expected))


def _verification_url(user, nonce: str = "") -> str:
    """Mint a 24h email-verification token and return the Facet verify link.

    Takes the person rather than an id because the token binds a fingerprint of their current
    state; every caller already holds one. `nonce` is the starting browser's verification nonce,
    bound as its hash; without one the link verifies but never signs in.
    """
    claims = {
        "sub": str(user.id),
        "token_type": "email_verify",
        "evf": _email_fingerprint(user),
        "aud": config.AUTHORITY_ISSUER,
    }
    if nonce:
        claims["vnh"] = _nonce_hash(nonce)
    token = create_jwt_token(claims, expires_hours=24)
    return f"{config.FACET_URI.rstrip('/')}/verify-email?token={token}"


def _queue_verification_email(
    background_tasks: BackgroundTasks, user, nonce: str = "", db: Optional[Session] = None,
    request: Optional[Request] = None,
) -> Optional[str]:
    """Queue the verification email as a background task (for 2xx responses, where
    background tasks actually run). No-op for accounts without an email. Returns the address
    queued to, read before any release, whether or not the budget let it go.

    With `request`, the send is charged to the unauthenticated mail budget (`_mail_send_admitted`)
    and dropped silently past it; a caller that has charged it already passes none.

    With `db`, the session's connection is released (`_release_db`) once the address and link are
    read: the send runs after the response, and the session is closed only after it."""
    email = getattr(user, "email", None)
    if not email:
        return None
    if request is not None and _mail_send_admitted(
        request, email.strip().lower(), "verification email"
    ) is None:
        if db is not None:
            _release_db(db)
        return email
    url = _verification_url(user, nonce)
    if db is not None:
        _release_db(db)
    background_tasks.add_task(email_service.send_email_verification, email, url,
                              _mail_context(request))
    return email


async def _send_verification_email(
    user, nonce: str = "", db: Optional[Session] = None, request: Optional[Request] = None
) -> None:
    """Send the verification email inline (await). Used on the login-block path,
    where the handler raises and FastAPI would discard background tasks.
    Best-effort: a send failure must not change the 403 the user sees.

    With `request`, the send is charged to the unauthenticated mail budget (`_mail_send_admitted`)
    and dropped silently past it.

    With `db`, the session's connection is released (`_release_db`) once the address and link are
    read, before the send is awaited."""
    email = getattr(user, "email", None)
    if not email:
        return
    if request is not None and _mail_send_admitted(
        request, email.strip().lower(), "verification email"
    ) is None:
        if db is not None:
            _release_db(db)
        return
    url = _verification_url(user, nonce)
    if db is not None:
        _release_db(db)
    try:
        await email_service.send_email_verification(email, url, _mail_context(request))
    except Exception:
        logger.warning("Failed to send verification email to address %s", _log_tag(email.lower()),
                       exc_info=True)


@auth_router.post("/password/reset-request")
async def password_reset_request(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: PasswordResetRequestBody,
    db: Session = Depends(get_db),
):
    """Begin a password reset. Always returns 200 (never reveals whether the
    email exists). When the email maps to a person who has a password, or whose address is
    confirmed, emails a short-lived link that sets one. Email must be configured (same dependency
    as OTP). Throttled by the mail-send budget verification resends share (see
    `_mail_send_admitted`), so neither endpoint is the cheaper way to fill an inbox.

    A confirmed account with no password — federated, made by a code, or disowned at confirmation
    (`email_verify_confirm`) — sets its first password here: the link reaches only the mailbox the
    account was confirmed for. An unconfirmed account with no password gets nothing; confirming
    comes first."""
    if not platform_settings.get_bool("auth.password.enabled", True):
        raise HTTPException(status_code=404, detail="Password auth is disabled")
    if not email_service.is_configured():
        raise HTTPException(
            status_code=503,
            detail="Email service not configured — cannot send a reset link.",
        )

    email = otp_service.normalize_email(payload.email)
    tag = _mail_send_admitted(request, email, "password reset request")
    if tag is None:
        return {"sent": True}
    user = person_service.get_user_by_email(db, email)
    # Don't reveal either way to the caller. A deactivated account is mailed nothing.
    if user and (user.password_hash or user.email_verified) and not is_deactivated(user):
        reset_token = _issue_reset_token(db, user)
        # The link names no account: the page asks `reset-check`, which reads it from the token.
        reset_url = f"{config.FACET_URI.rstrip('/')}/reset-password?token={reset_token}"
        to = user.email
        _release_db(db)  # the send runs after the response; see `_queue_verification_email`
        background_tasks.add_task(email_service.send_password_reset, to, reset_url,
                                  _mail_context(request))
        logger.info("Password reset email queued for address %s", tag)
    else:
        logger.info("Password reset requested for an unknown or unconfirmed passwordless "
                    "address %s", tag)
    return {"sent": True}


#: How long a mailed reset link works.
_RESET_TTL = timedelta(hours=1)


def _reset_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _issue_reset_token(db: Session, user) -> str:
    """A reset link's token: 32 random URL-safe characters, stored only as their hash. Short on
    purpose: a mail carrying a long signed token is filed as junk by Outlook where the same mail
    with a short link is not. Expired rows are removed here."""
    now = datetime.now(timezone.utc)
    db.query(PasswordReset).filter(PasswordReset.expires_at < now).delete(synchronize_session=False)
    token = secrets.token_urlsafe(24)
    db.add(PasswordReset(token_hash=_reset_hash(token), person_id=user.id,
                         password_fingerprint=_pw_fingerprint(user.password_hash),
                         expires_at=now + _RESET_TTL))
    db.commit()
    return token


def _reset_claims(db: Session, token: str) -> dict | None:
    """`{"sub", "pwf"}` for a reset token that is stored and unexpired, else None."""
    if not token or len(token) > 128:
        return None
    row = db.get(PasswordReset, _reset_hash(token))
    if row is None:
        return None
    expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
    if expires <= datetime.now(timezone.utc):
        return None
    return {"sub": str(row.person_id), "pwf": row.password_fingerprint}


def _reset_token_still_applies(user, claims: dict) -> bool:
    """The account exists, may have a password set by mail (it has one, or its address is
    confirmed), and has not changed password since the link was minted."""
    if not user or not (user.password_hash or user.email_verified) or is_deactivated(user):
        return False
    return _pw_fingerprint(user.password_hash) == claims.get("pwf")


class PasswordResetCheckBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str


@auth_router.post("/password/reset-check")
async def password_reset_check(payload: PasswordResetCheckBody, db: Session = Depends(get_db)):
    """Which account a reset link resets, for the page to name it to a password manager. The token
    decides, never the URL: the link carries no address, and an altered one names nothing. Answers
    only while the link would still be accepted by `reset-confirm` (same checks, no derivation), and
    only to its holder, who read it in that account's own mailbox."""
    claims = _reset_claims(db, payload.token)
    if not claims:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    user = person_service.get_user_by_id(db, str(claims["sub"]))
    if not _reset_token_still_applies(user, claims):
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    return {"email": user.email or user.username or ""}


@auth_router.post("/password/reset-confirm", dependencies=_KDF_ADMISSION)
async def password_reset_confirm(
    payload: PasswordResetConfirmBody,
    db: Session = Depends(get_db),
):
    """Complete a password reset: look the token up, enforce the password policy, and set the new
    password. The token expires in 1 hour and works once: setting the password deletes every reset
    row for the account, and a link also stops working once the password changes any other way
    (`_pw_fingerprint`). A confirmed account with no password sets its first one this way; its
    fingerprint is that of no password, which setting one moves."""
    if not platform_settings.get_bool("auth.password.enabled", True):
        raise HTTPException(status_code=404, detail="Password auth is disabled")

    claims = _reset_claims(db, payload.token)
    if not claims:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    min_len = platform_settings.get_int("auth.password.min_length", 12)
    if len(payload.new_password or "") < min_len:
        raise HTTPException(status_code=400, detail=f"Password must be at least {min_len} characters")

    # Single-use check: the token's fingerprint must still match the current hash.
    user = person_service.get_user_by_id(db, str(claims["sub"]))
    if not _reset_token_still_applies(user, claims):
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    user_id = str(user.id)
    _release_db(db)
    new_hash = await run_kdf(hash_password, payload.new_password)

    # Checked again once the derivation is done, with nothing awaited between this and the commit:
    # a second use of the same link that raced this one has changed the hash by now, and must lose.
    user = person_service.get_user_by_id(db, user_id)
    if not _reset_token_still_applies(user, claims):
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    person_service.set_password(db, user_id, new_hash)
    db.query(PasswordReset).filter(PasswordReset.person_id == user.id).delete(synchronize_session=False)
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


@auth_router.post("/bootstrap/claim", response_model=BootstrapClaimResponse,
                   dependencies=_KDF_ADMISSION)
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

    try:
        op_email = require_canonical_email(body.email) if (body.email or "").strip() else ""
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    person_name = (body.name or "").strip() or (op_email.split("@")[0] if op_email else "operator")
    password_hash = await run_kdf(hash_password, body.password) if body.password else None

    person = person_service.create_user_with_password(
        db,
        username=person_name,
        name=person_name,
        password_hash=password_hash or "",
        email=op_email,
        email_verified=True,              # the operator's own address, on the bootstrap token
        allow_paused=True,                # the operator's own bootstrap claim
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

    user_data = person_token_claims(
        person, client_id=getattr(config, "PLATFORM_CLIENT_ID", "platform"),
        roles=["platform:admin"],
    )
    access_token = create_jwt_token(user_data)
    refresh_token = _refresh_tokens.issue(db, user_data)

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
            "email_verified": True,          # the operator's own address, on the bootstrap token
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
# A person's step-up for a change to how they sign in (`services.person_step_up`)
# ---------------------------------------------------------------------------
def _refuse_if_registration_paused() -> None:
    """403 while new accounts are paused (`REGISTRATION_PAUSED`, or the platform setting
    `auth.registration.paused`): enforced here, by Origin, not only by the proxy in front of it."""
    if person_service.registration_paused():
        raise HTTPException(status_code=403, detail="New accounts are temporarily paused. Sign "
                            "in with an existing account.")


def on_origin_s_own_page(request: Request) -> bool:
    """Was this request sent by one of Origin's own pages? Its `Origin` (or, without one, its
    `Referer`) is Origin's own origin: scheme, host and port. A browser sets both, and no page
    elsewhere can claim Origin's."""
    source = request.headers.get("origin") or request.headers.get("referer") or ""
    parts = _origin_parts(source)
    return parts is not None and parts in _own_origins()


def _signed_in_on_page(request: Request, db: Session, person_id: str, body: dict) -> JSONResponse:
    """A sign-in's answer, which on Origin's own page also starts the person's Origin session, as
    `/auth/authorize`'s local form does (`_complete_local_signin`). A sign-in posted from any other
    page, the web app's included, starts none: credentials are typed only on Origin's page, and the
    session is what every authority change and the web app's token for Mantle are made in."""
    from origin.services import origin_session

    response = JSONResponse(body)
    if on_origin_s_own_page(request):
        origin_session.start(db, response, person_id)
    return response


def _starts_origin_session(auth_request: dict, db: Optional[Session] = None) -> bool:
    """Does a sign-in for this request start Origin's own session in the browser? Not one on its
    way to a re-authentication (`/auth/reauth/complete`), nor one through the method to be
    linked (back to `/passkey` carrying a link attempt's state): the person proving themselves
    again, or signing in through the method to add, must never replace the session the change
    was begun in, nor give another browser one (review 11). An ordinary sign-in at `/passkey`
    does start one."""
    from origin.services import link_attempts, person_step_up
    req = auth_request or {}
    target = str(req.get("redirect_uri") or "")
    if target == person_step_up.complete_uri():
        return False
    if target == person_step_up.link_uri() and db is not None and link_attempts.is_attempt(
            db, req.get("state")):
        return False
    return True


def _interactive(auth: AuthContext) -> str:
    """A person's own session, not a machine acting as them (a delegation or an mcp_client)."""
    if auth.principal_type != "user" or auth.actor is not None or not auth.user_id:
        raise HTTPException(status_code=403, detail="a sign-in method changes only in the "
                            "person's own session")
    return str(auth.user_id)


@auth_router.post("/me/link-attempts")
async def begin_link_attempt(request: Request, body: dict = Body(...),
                             auth: AuthContext = Depends(get_auth),
                             db: Session = Depends(get_db)):
    """Begin linking another sign-in method, in the person's Origin session: a random state for
    this attempt, bound to the PKCE challenge (`code_challenge`, S256) the sign-in will carry."""
    from origin.services import link_attempts, origin_session

    who = _interactive(auth)
    origin_session.require(request, db, who)
    return {"state": link_attempts.begin(db, who, str(body.get("code_challenge") or ""))}


@auth_router.post("/me/step-up-options")
async def person_step_up_options(
    request: Request,
    body: dict = Body(...),
    auth: AuthContext = Depends(get_auth),
    db: Session = Depends(get_db),
):
    """The step-up for one request that changes how this person signs in
    (`{method, path, body | body_sha256}`): a passkey challenge, or a link to re-authenticate at
    Origin. A re-authentication is started only in the person's own Origin session (the cookie
    Origin's own sign-in sets), never on a token alone; for a link, `body` (the link's own request)
    is sent so the start page can show which identity it joins."""
    from origin.services import origin_session, person_step_up

    who = _interactive(auth)
    raw = body.get("body")
    return person_step_up.options(db, who, str(body.get("method") or ""),
                                  str(body.get("path") or ""), str(body.get("body_sha256") or ""),
                                  body=raw if isinstance(raw, str) else None,
                                  session_person=origin_session.person_of(request, db),
                                  session_sha256=origin_session.digest_of(request))


@auth_router.get("/not-before", dependencies=None)
async def published_not_before(after: int = 0, db: Session = Depends(get_db)):
    """The not-before times peers enforce (review 11, M2), served by sequence (review 12, M8): a JWT
    signed by Origin's current key,
    `{"iss", "iat", "token_type": "not_before", "after", "seq", "entries": [{"sub", "not_before",
    "seq"}], "all_before"}`.

    Every change to a person's bound takes the next number in one sequence; `entries` lists the
    people whose bound changed after `after` (a peer's cursor), each with its number, and `seq` is
    the highest number there is, the peer's next cursor. Numbers, not times, so a change committed
    late with an earlier time is never skipped. An entry's `not_before` (unix seconds) is the time
    before which that person's access tokens no longer count; `all_before` is the time before which
    every token Origin issued ends (a signing-key rollover), or 0, sent every time. Peers (Mantle,
    prism, Ember, Chorus) refuse a token whose `iat` is earlier.

    Public, as the JWKS is: it names person ids and times, never anyone's email or name."""
    from sqlalchemy import func

    from origin.models.sign_in_bounds import PersonNotBefore
    from origin.services import not_before as _nb

    def _ts(t):
        t = _nb._aware(t)
        return t.timestamp() if t is not None else 0.0

    after = max(0, int(after))
    top = int(db.query(func.max(PersonNotBefore.seq)).scalar() or 0)
    entries, all_before = [], 0.0
    for row in db.query(PersonNotBefore).order_by(PersonNotBefore.seq):
        when = max(_ts(row.access_before), _ts(row.refresh_before))
        if row.person_id == _nb.EVERYONE:
            all_before = when
        elif int(row.seq or 0) > after:
            entries.append({"sub": row.person_id, "not_before": int(when) + 1,
                            "seq": int(row.seq or 0)})
    now = datetime.now(timezone.utc).timestamp()
    token = create_jwt_token({"iss": config.AUTHORITY_ISSUER, "token_type": "not_before",
                              "after": after, "seq": top, "entries": entries,
                              "all_before": int(all_before) + 1 if all_before else 0,
                              "iat": now}, expires_hours=1 / 12)
    return {"token": token}


@auth_router.post("/sign-out", dependencies=None)
async def sign_out(request: Request, refresh_token: str = Form(...),
                   db: Session = Depends(get_db)):
    """End one sign-in: the presented refresh token's whole family is revoked, the person's
    access tokens issued before now end at Origin (their other sign-ins refresh into new ones), and
    the Origin session this browser carries ends with its cookie."""
    from origin.services import not_before, origin_session

    payload = verify_token(refresh_token)
    if not payload or payload.get("token_type") != "refresh":
        raise HTTPException(status_code=400, detail="Invalid refresh token")
    n = _refresh_tokens.revoke_token_family(db, payload)
    if payload.get("sub"):
        not_before.end_access(db, str(payload["sub"]))
    response = JSONResponse({"signed_out": True, "revoked": n})
    origin_session.end(request, db, response)
    db.commit()
    return response


@auth_router.post("/sign-out-everywhere")
async def sign_out_everywhere(auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)):
    """End every sign-in of the caller's: all their refresh-token families and Origin sessions."""
    from origin.services import origin_session

    from origin.services import authority_ledger as _ledger

    from origin.services import not_before

    who = _interactive(auth)
    n = _refresh_tokens.revoke_person(db, who)
    origin_session.revoke_person(db, who)
    not_before.end_all(db, who)              # every token issued before now, legacy ones too
    db.commit()
    jobs = _ledger.revoke_person_job_grants(db, who)
    return {"signed_out": True, "revoked": n, "job_grants_revoked": jobs}


# -- the person's own job grants, at Origin's own page (review 9, H2) -----------------------------

@auth_router.get("/me/job-grants")
async def my_job_grants(request: Request, auth: AuthContext = Depends(get_auth),
                        db: Session = Depends(get_db)):
    """The job grants the person made, or that name their own key: in their Origin session."""
    from origin.services import authority_ledger as _ledger, origin_session

    who = _interactive(auth)
    origin_session.require(request, db, who)
    return {"job_grants": _ledger.person_job_grants(db, who)}


@auth_router.post("/me/job-grants")
async def make_my_job_grant(request: Request, body: dict = Body(...),
                            auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)):
    """Grant a named background job narrow authority over the person's own key, or over
    collections they administer (`{job, expires_at, principal?, collections?}`): only in their
    Origin session with a fresh step-up bound to this very request. A bearer token or a
    delegation alone makes no job grant. Every one made raises an operator alert."""
    from origin.services import authority_ledger as _ledger, person_step_up

    who = _interactive(auth)
    await person_step_up.require(request, db, who)
    job, until = body.get("job"), body.get("expires_at")
    cols = body.get("collections") or []
    reach = body.get("reach") or []
    if (not isinstance(job, str) or not job or not isinstance(until, str)
            or not isinstance(cols, list) or not all(isinstance(c, str) for c in cols)
            or not isinstance(reach, list) or not all(isinstance(r, str) for r in reach)):
        raise HTTPException(status_code=400, detail="job and expires_at are required; "
                            "collections and reach are lists of ids")
    try:
        receipt = _ledger.page_job_grant(db, who, job=job, expires_at=until,
                                         principal=body.get("principal"), collections=cols,
                                         reach=reach)
    except _ledger.EntryRefused as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    row = db.query(__import__("origin.models.authority_ledger", fromlist=["x"])
                   .AuthorityJobGrant).filter_by(seq=receipt.get("seq")).first()
    return {"grant_id": row.grant_id if row else None, "receipt": receipt}


@auth_router.post("/me/job-grants/{grant_id}/revoke")
async def revoke_my_job_grant(grant_id: str, request: Request,
                              auth: AuthContext = Depends(get_auth),
                              db: Session = Depends(get_db)):
    """Revoke one of the person's own job grants, in their Origin session with a fresh step-up
    bound to this request: a click stolen in a framed page does nothing (review 11, M7)."""
    from origin.services import authority_ledger as _ledger, person_step_up

    who = _interactive(auth)
    await person_step_up.require(request, db, who)
    try:
        out = _ledger.page_revoke_job_grant(db, who, grant_id)
    except _ledger.EntryRefused as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    if out is None:
        raise HTTPException(status_code=404, detail="no such job grant of yours")
    return {"grant_id": grant_id, "revoked": True}


@auth_router.get("/reauth/start", dependencies=None)
async def person_reauth_start(ticket: str, db: Session = Depends(get_db)):
    """Origin's own page for a re-authentication: the exact action, and a confirm. Nothing goes
    to a sign-in until the person confirms."""
    from origin.services import person_step_up

    return HTMLResponse(person_step_up.start_page(db, ticket),
                        headers={"Content-Security-Policy": "default-src 'none'; "
                                 "form-action 'self'; frame-ancestors 'none'",
                                 "Cache-Control": "no-store"})


@auth_router.post("/reauth/start", dependencies=None)
async def person_reauth_confirm(ticket: str = Form(...), csrf: str = Form(...),
                                db: Session = Depends(get_db)):
    """The person confirmed the action: on to Origin's own sign-in, a fresh one."""
    from origin.services import person_step_up

    return RedirectResponse(url=person_step_up.confirm(db, ticket, csrf),
                            status_code=status.HTTP_303_SEE_OTHER)


@auth_router.get("/reauth/complete", dependencies=None)
async def person_reauth_complete(request: Request, code: str, state: str,
                                 db: Session = Depends(get_db)):
    """The sign-in's code, consumed here: the ticket is proven if the identity that signed in is
    already this person's, and only in the browser whose Origin session started the ticket. No
    token is minted, and no session is started or replaced: the one it began in stays."""
    from origin.services import origin_session, person_step_up

    row = person_step_up.complete(db, state, code, authorization_codes, _CODE_TTL,
                                  session_sha256=origin_session.digest_of(request))
    # Back to the Origin page that asked, in this tab, where the request is sent with the proven
    # ticket (`web/reauth-complete.js`, BUG-037).
    from origin.main import PASSKEY_PAGE_CSP
    return HTMLResponse(
        "<!doctype html><meta charset=utf-8><title>Confirmed</title>"
        f"<p>Confirmed: you may now {_html.escape(row.describe)}.</p>"
        '<p><a id="back" href="/passkey" hidden>Back to finish it</a></p>'
        '<script src="/web/reauth-complete.js"></script>',
        headers={"Content-Security-Policy": PASSKEY_PAGE_CSP, "Cache-Control": "no-store"})


# ---------------------------------------------------------------------------
# /me/link-provider
# ---------------------------------------------------------------------------
@auth_router.post("/me/link-provider")
async def link_provider(
    request: Request,
    body: LinkProviderRequest,
    auth: AuthContext = Depends(get_auth),
    person: PersonModel = Depends(get_person),
    db: Session = Depends(get_db),
):
    """Join another sign-in identity to this account: the code of a sign-in through it, and a
    fresh step-up by a method the person already has (`services.person_step_up`). An access
    token alone joins nothing."""
    from origin.services import link_attempts, person_step_up

    _interactive(auth)
    # The attempt first (review 10, R10): its state was begun in this person's Origin session, and
    # the sign-in's code carries the PKCE challenge it recorded, so a code obtained anywhere else
    # links nothing, whatever step-up comes with it.
    attempt = link_attempts.live(db, body.state, str(person.id))
    pending = authorization_codes.get(body.code) or {}
    if not pending.get("code_challenge") or pending.get("code_challenge_method") != "S256":
        raise HTTPException(status_code=403, detail="the sign-in to be linked carries no PKCE "
                            "challenge (S256)")
    if not secrets.compare_digest(str(pending["code_challenge"]), attempt.code_challenge):
        raise HTTPException(status_code=403, detail="the sign-in to be linked was not made for "
                            "this link attempt")
    await person_step_up.require(request, db, str(person.id))
    # Single use from here: the step-up above may ask the person to confirm and come back, so the
    # code survives it; past it, every outcome spends the code.
    auth_data = authorization_codes.pop(body.code, None)
    if auth_data is None:
        raise HTTPException(status_code=400, detail="Invalid or expired authorization code")
    if body.redirect_uri != auth_data["redirect_uri"]:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    # Made by Origin's own page for this: its own platform client, back to `/passkey` (review 11).
    if (not _is_first_party_client(str(auth_data.get("client_id") or ""))
            or auth_data.get("redirect_uri") != person_step_up.link_uri()):
        raise HTTPException(status_code=403, detail="the sign-in to be linked was not made by "
                            "Origin's own page for this link")
    if datetime.now(timezone.utc) - auth_data["timestamp"] > _CODE_TTL:
        raise HTTPException(status_code=400, detail="Authorization code expired")
    _require_s256_verifier(auth_data, body.code_verifier)

    link_attempts.spend(db, attempt)
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
    request: Request,
    provider: str,
    subject: str | None = None,
    auth: AuthContext = Depends(get_auth),
    person: PersonModel = Depends(get_person),
    db: Session = Depends(get_db),
):
    """Unlink one external identity, with a fresh step-up by a method the person already has
    (`services.person_step_up`).

    `subject` is optional only while a provider has a single identity on the account — with one
    slot the route cannot be ambiguous. When the account holds more than one identity from
    `provider`, the endpoint returns 409 rather than guessing which one to drop.
    """
    from origin.services import person_step_up

    _interactive(auth)
    await person_step_up.require(request, db, str(person.id))
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
        "code_challenge_methods_supported": ["S256"],
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

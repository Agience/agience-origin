"""The acting caller's credential, which Origin requires before it releases a key share or
co-signs a change to reach.

Mantle's bound service token proves only that Mantle is calling. Were it enough, Mantle alone could
open every key or write any grant, so each such call also carries the credential of whoever Mantle
is acting for, verified here by Origin itself. Three kinds are accepted, each only as Origin issued
it:

  access       a person's access token: no `token_type`, `aud` = this authority, a person who
               exists and is not deactivated
  delegation   an RFC 8693 delegation Origin issued for a person (`principal_type=delegation`,
               `act.sub`, no `scope`), addressed to Mantle (a persona's server delegation
               is too), the person active,
               ten minutes at most, with a `jti` Origin recorded at issue and has not revoked
  seed         a credential the operator minted for one seed pass (`scope=authority.seed`, the
               platform system principal, ten minutes at most, recorded and not revoked). Unlike
               a background delegation it may widen reach: a seed grants, and minting it is the
               operator's deliberate act (`/oracle/seed-credential`).
  background   a delegation Origin minted for one principal for background work
               (`scope=custody.share.release`, `aud=origin`, at most `MAX_BACKGROUND_TTL` seconds),
               present in `key_custody_delegations`, not revoked, under a background authority
               the operator granted and has not withdrawn. It opens that principal and no other.
  job          a persona's server delegation carrying a timer's job grant (`job_grant`,
               `job_reach`), accepted at a key share release only (`verify_job_credential`). It
               opens the person's key for the artifacts its live grant lists, by id, and no other
               (John, 2026-11-10).

Everything else is refused: no credential, a token another key signed, a platform service's token,
a refresh or single-purpose token, an mcp_client token, a system delegation issued for another
purpose.

Verifying a credential says who it is; it does not say what they reach. Origin decides that over
its own replica of the authority ledger (`authority_reach.Reach.may_release`, and the rules in
`authority_ledger`).

Background work runs only on a job grant (John, 2026-11-02): a person grants a named job over
their own key, an Admin over a collection's, as a `job_grant` entry in the ledger. Under a live
one, and only for its job, principal and collections, Mantle may ask Origin to mint a delegation
(`POST /internal/custody-delegations/{principal_id}`, the job bound in its service token), minutes
long, recorded by `jti` with the grant it was minted under, rate-limited per grant. Mantle's
service token alone mints nothing, and nothing long-lived sits on Mantle's disk.

A credential is recorded by its `jti`, or a SHA-256 prefix of the token when it has none; the
token itself is never stored or logged.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from origin import config
from origin.models.key_custody import KeyCustodyDelegation, KeyCustodyRelease
from origin.models.person import Person

#: The scope and audience of a background delegation.
SHARE_RELEASE_SCOPE = "custody.share.release"
PLATFORM_AUDIENCE = "origin"

#: How long a minted background delegation lives, and the most it may.
DEFAULT_BACKGROUND_TTL = 300
MAX_BACKGROUND_TTL = 600

#: The scope of a seed credential, and its longest life.
SEED_SCOPE = "authority.seed"
MAX_SEED_TTL = 600

#: The longest a person's delegation may live and still act at a release or on the ledger.
MAX_PERSON_DELEGATION_TTL = 600

#: How many background delegations one job grant may have minted in a minute.
JOB_ISSUANCE_PER_MINUTE = 30


def _delegation_audiences() -> frozenset:
    """The services a person's delegation may be addressed to and still act: Mantle. A persona's
    server delegation is addressed to Mantle too (review 22), so nothing addressed to a persona
    acts here."""
    return frozenset({"mantle"})


class CredentialRefused(Exception):
    """The credential does not act here. The message names why and carries no token."""


@dataclass(frozen=True)
class VerifiedCredential:
    subject: str
    kind: str              # access | delegation | background
    ref: str               # jti, or a SHA-256 prefix of the token
    #: For a background delegation, the one principal it opens; None for a person's credential.
    principal: Optional[str] = None
    #: For a background delegation, the collections its job grant covers: it releases nothing
    #: for any other collection.
    collections: tuple = ()
    #: For a narrowed delegation (kind `narrowed`), the scopes it carries.
    scopes: tuple = ()
    #: For a job's delegation (kind `job`), the artifact ids its job grant lists: the only ones
    #: whose key it opens.
    reach: tuple = ()


#: Ember's narrowed delegation acts, as an acting credential, for these scopes only (John,
#: 2026-11-02): what each may do is the ledger's (`authority_ledger._decide_narrowed`), the reach
#: verdict's (`authority_router.reach_for_action`) and the first-share rule's to say, and none of
#: them ever releases a content key.
NARROWED_AUDIENCE = "ember"
NARROWED_SCOPES = frozenset({"ember:memory", "ember:read"})
#: A narrowed delegation's life, with a few seconds for clocks.
MAX_NARROWED_TTL = 300 + 5


def _ref(token: str, payload: dict) -> str:
    jti = payload.get("jti")
    if isinstance(jti, str) and 0 < len(jti) <= 64:
        return jti
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:40]


def _live_person(db: Session, subject: str) -> None:
    try:
        pid = uuid.UUID(subject)
    except (ValueError, TypeError):
        raise CredentialRefused("the credential names no person") from None
    person = db.get(Person, pid)
    if person is None:
        raise CredentialRefused("the credential names a person Origin does not know")
    if getattr(person, "deactivated_at", None):
        raise CredentialRefused("the credential names a deactivated person")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(t: Optional[datetime]) -> Optional[datetime]:
    if t is not None and t.tzinfo is None:
        return t.replace(tzinfo=timezone.utc)
    return t


def verify_share_credential(db: Session, token: str) -> VerifiedCredential:
    """Verify `token` as the acting caller's credential, or raise `CredentialRefused`."""
    from origin.services.auth_verifier import verify_token

    if not token:
        raise CredentialRefused("no acting credential")
    payload = verify_token(token)
    if not payload or payload.get("iss") != config.AUTHORITY_ISSUER:
        raise CredentialRefused("not a live credential Origin issued")
    subject = str(payload.get("sub") or "")
    if not subject:
        raise CredentialRefused("the credential names no acting principal")
    if payload.get("token_type") or payload.get("api_key_id"):
        raise CredentialRefused("a single-purpose token is not an access credential")
    ptype = payload.get("principal_type", "user")
    aud = payload.get("aud")
    from origin.services import not_before
    if not_before.ended(db, payload):
        raise CredentialRefused("a credential issued before its person signed out")

    if ptype == "user":
        # The person's own access token, or the one the web app calls Mantle on (review 23).
        if aud not in (config.AUTHORITY_ISSUER, "mantle"):
            raise CredentialRefused("an access token for another audience")
        _live_person(db, subject)
        return VerifiedCredential(subject, "access", _ref(token, payload))

    if ptype == "delegation":
        actor = str((payload.get("act") or {}).get("sub") or "")
        if not actor:
            raise CredentialRefused("a delegation with no actor")
        # A persona's server delegation releases no key and is no person's credential on the
        # ledger (review 27), whoever signed its exchange: a persona-signed one is the persona's
        # (`use_verdict.verify_persona_credential`, which the use verdict, `/reach` and the
        # ledger's persona path take first), and anything else naming a persona server is refused.
        from prism.trust.use_verdict import SERVER_PREFIX
        if actor.startswith(SERVER_PREFIX):
            raise CredentialRefused("a persona's server delegation is not an acting credential")
        scope = payload.get("scope")
        # Ember's narrowed delegation, addressed to Ember, or Origin's exchange of it addressed to
        # Mantle (review 21, F6), which is what Ember now calls Mantle on.
        if (payload.get("act") or {}).get("sub") == NARROWED_AUDIENCE and (
                aud == NARROWED_AUDIENCE
                or (aud == "mantle" and payload.get("narrowed") is True)):
            return _verify_narrowed(db, token, payload, subject)
        if scope is None:
            if aud not in _delegation_audiences():
                raise CredentialRefused("a delegation addressed to another service")
            _bounded_delegation(db, payload, subject)
            _live_person(db, subject)
            return VerifiedCredential(subject, "delegation", _ref(token, payload))
        if scope == SEED_SCOPE and aud == PLATFORM_AUDIENCE:
            return _verify_seed(db, payload, subject)
        if scope != SHARE_RELEASE_SCOPE or aud != PLATFORM_AUDIENCE:
            raise CredentialRefused("a delegation issued for another purpose")
        iat, exp = payload.get("iat"), payload.get("exp")
        if not isinstance(iat, (int, float)) or not isinstance(exp, (int, float)) \
                or exp - iat > MAX_BACKGROUND_TTL:
            raise CredentialRefused(f"a background delegation living over {MAX_BACKGROUND_TTL}s")
        row = db.get(KeyCustodyDelegation, str(payload.get("jti") or ""))
        if row is None or row.subject != subject:
            raise CredentialRefused("a background delegation Origin did not mint")
        if row.revoked_at is not None:
            raise CredentialRefused("a revoked background delegation")
        grant = _live_grant_row(db, row.job_grant_id, job=row.job)
        if grant is None:
            raise CredentialRefused("the job grant this background delegation was minted under "
                                    "is revoked or over")
        import json as _json
        return VerifiedCredential(subject, "background", row.jti, principal=subject,
                                  collections=tuple(_json.loads(row.collections or "[]")))

    raise CredentialRefused(f"a {ptype} token is not an acting credential")


def _verify_narrowed(db: Session, token: str, payload: dict, subject: str) -> VerifiedCredential:
    """Ember's narrowed delegation for a person: its own scopes, minutes long, for a live person.
    It never opens a key: the share routes refuse kind `narrowed` outright."""
    scopes = tuple(sorted(set(str(payload.get("scope") or "").split())))
    if not scopes or not set(scopes) <= NARROWED_SCOPES:
        raise CredentialRefused("a narrowed delegation carrying scopes Ember's acts do not name")
    iat, exp = payload.get("iat"), payload.get("exp")
    if not isinstance(iat, (int, float)) or not isinstance(exp, (int, float))             or exp - iat > MAX_NARROWED_TTL:
        raise CredentialRefused(f"a narrowed delegation living over {MAX_NARROWED_TTL}s")
    if not payload.get("jti"):
        raise CredentialRefused("a narrowed delegation with no jti")
    _live_person(db, subject)
    return VerifiedCredential(subject, "narrowed", _ref(token, payload), scopes=scopes)


def _verify_seed(db: Session, payload: dict, subject: str) -> VerifiedCredential:
    """A seed credential: the system principal's, minted by the operator for one seed pass,
    minutes long, recorded and not revoked. It may widen reach (a seed grants), unlike a
    background delegation."""
    from origin import service_identity
    from origin.models.key_custody import SeedCredential

    iat, exp = payload.get("iat"), payload.get("exp")
    if not isinstance(iat, (int, float)) or not isinstance(exp, (int, float)) \
            or exp - iat > MAX_SEED_TTL:
        raise CredentialRefused(f"a seed credential living over {MAX_SEED_TTL}s")
    row = db.get(SeedCredential, str(payload.get("jti") or ""))
    if row is None or row.subject != subject:
        raise CredentialRefused("a seed credential the operator did not mint")
    if row.revoked_at is not None:
        raise CredentialRefused("a revoked seed credential")
    system_id = service_identity.get_system_principal_id()
    if not system_id or subject != system_id:
        raise CredentialRefused("a seed credential for another principal")
    return VerifiedCredential(subject, "seed", row.jti)


def mint_seed_credential(db: Session, operator_id: str, minutes: int = 10,
                         rekey_shares: Optional[list] = None,
                         plan: Optional[list] = None) -> dict:
    """The operator's deliberate act: a credential for one seed pass that grants as the
    platform system principal. Returns `{"token", "jti", "expires_at"}`; the token is not kept."""
    from origin import service_identity
    from origin.models.key_custody import SeedCredential
    from origin.services.auth_service import issue_system_delegation_token

    system_id = service_identity.get_system_principal_id()
    if not system_id:
        raise CredentialRefused("instance namespace unavailable; no system principal")
    ttl = max(60, min(int(minutes) * 60, MAX_SEED_TTL))
    jti = secrets.token_hex(16)
    expires = _now() + timedelta(seconds=ttl)
    token = issue_system_delegation_token(system_id, actor=operator_id, scope=SEED_SCOPE,
                                          audience=PLATFORM_AUDIENCE, ttl_seconds=ttl, jti=jti)
    import json as _json
    db.add(SeedCredential(jti=jti, subject=system_id, issued_by=operator_id, expires_at=expires,
                          plan=_json.dumps(sorted(set(plan))) if plan else None,
                          rekey_shares=_json.dumps(sorted(set(rekey_shares)))
                          if rekey_shares else None))
    db.commit()
    return {"token": token, "jti": jti, "expires_at": expires.isoformat(timespec="seconds")}


def seed_marks(db: Session, jti: str, principal_id: str) -> bool:
    """May the seed credential `jti` mark `principal_id`'s share for re-key? Only a share the
    operator listed when minting it."""
    import json as _json
    from origin.models.key_custody import SeedCredential

    row = db.get(SeedCredential, jti)
    if row is None or not row.rekey_shares:
        return False
    try:
        return principal_id in set(_json.loads(row.rekey_shares))
    except (TypeError, ValueError):
        return False


def revoke_seed_credential(db: Session, jti: str) -> bool:
    from origin.models.key_custody import SeedCredential

    row = db.get(SeedCredential, jti)
    if row is None:
        return False
    if row.revoked_at is None:
        row.revoked_at = _now()
        db.commit()
    return True


def _bounded_delegation(db: Session, payload: dict, subject: str) -> None:
    """A person's delegation acts at a key release or on the authority ledger only if it is
    short (ten minutes at most), carries a `jti` Origin recorded when it issued it, and has not
    been revoked."""
    from origin.models.key_custody import DelegationRecord

    iat, exp = payload.get("iat"), payload.get("exp")
    if not isinstance(iat, (int, float)) or not isinstance(exp, (int, float)) \
            or exp - iat > MAX_PERSON_DELEGATION_TTL:
        raise CredentialRefused(f"a delegation living over {MAX_PERSON_DELEGATION_TTL}s")
    jti = payload.get("jti")
    row = db.get(DelegationRecord, str(jti)) if isinstance(jti, str) and jti else None
    if row is None or row.subject != subject:
        raise CredentialRefused("a delegation Origin holds no record of")
    if row.revoked_at is not None:
        raise CredentialRefused("a revoked delegation")


def revoke_delegation(db: Session, jti: str) -> bool:
    from origin.models.key_custody import DelegationRecord

    row = db.get(DelegationRecord, jti)
    if row is None:
        return False
    if row.revoked_at is None:
        row.revoked_at = _now()
        db.commit()
    return True


def bind_to_principal(cred: VerifiedCredential, principal_id: str) -> None:
    """A background delegation opens its own principal and no other."""
    if cred.principal is not None and cred.principal != principal_id:
        raise CredentialRefused("a background delegation minted for another principal")


def bind_to_collection(cred: VerifiedCredential, principal_id: str,
                       collection_id: Optional[str]) -> None:
    """A background delegation releases nothing for a collection its job grant does not cover:
    a collection key's own collection, or one the grant lists."""
    if cred.kind != "background" or not collection_id:
        return
    from origin.services.authority_reach import collection_key_collection
    allowed = set(cred.collections) | {collection_key_collection(principal_id)}
    if collection_id not in allowed:
        raise CredentialRefused("a background delegation for a collection its job grant does not "
                                "cover")


def record_release(db: Session, principal_id: str, cred: VerifiedCredential, *,
                   collection_id: Optional[str] = None) -> None:
    db.add(KeyCustodyRelease(principal_id=principal_id, subject=cred.subject,
                             credential_kind=cred.kind, credential_ref=cred.ref,
                             collection_id=collection_id))
    db.commit()


# -- background work ------------------------------------------------------------------------------

def _live_grant_row(db: Session, grant_id: Optional[str], *, job: Optional[str] = None):
    """The job grant `grant_id`, if it is live, names `job` (the delegation's own), and its
    grantor still holds what it was granted under; None otherwise (and for a delegation minted
    under the console's retired standing authority, which names none)."""
    from origin.models.authority_ledger import AuthorityJobGrant
    from origin.services.authority_ledger import grant_still_held, parse_time

    row = db.get(AuthorityJobGrant, grant_id) if grant_id else None
    if row is None or row.state != "active" or (job is not None and row.job != job):
        return None
    try:
        if parse_time(row.expires_at) <= _now():
            return None
    except ValueError:
        return None
    return row if grant_still_held(db, row) else None


def carries_job_grant(token: str) -> bool:
    """Does `token` name a job grant (unverified: only which verifier to try)?"""
    from jose import jwt as _jose_jwt

    try:
        claims = _jose_jwt.get_unverified_claims(token)
    except Exception:  # noqa: BLE001 — not a JWT: the ordinary verifier refuses it
        return False
    return isinstance(claims, dict) and bool(claims.get("job_grant")) and "job_reach" in claims


def verify_job_credential(db: Session, token: str) -> VerifiedCredential:
    """A timer's job delegation, as a persona exchanged it to call Mantle: a key share release's
    acting credential for the artifacts its grant lists and nothing else (John, 2026-11-10: a job
    or persona opens a person's content key only under a live job grant the person approved at
    Origin, only for the artifacts in its reach, for its lifetime). Refuses with
    `CredentialRefused`.

    Accepted only by the release route: every other route verifies with
    `verify_share_credential`, which refuses a persona's server delegation outright, so a job's
    delegation never writes the ledger, stores a share or answers a reach verdict."""
    import json as _json

    from origin.services import authority_ledger
    from origin.services.auth_verifier import verify_token
    from origin.services.use_verdict import UseRefused, verify_persona_credential

    try:
        persona = verify_persona_credential(db, token)
    except UseRefused as exc:
        raise CredentialRefused(str(exc)) from None
    if persona.kind != "person":
        raise CredentialRefused("a platform purpose's delegation carries no job grant")
    claims = verify_token(token) or {}
    iat, exp = claims.get("iat"), claims.get("exp")
    if not isinstance(iat, (int, float)) or not isinstance(exp, (int, float)) \
            or exp - iat > MAX_PERSON_DELEGATION_TTL + 5:
        raise CredentialRefused(f"a job's delegation living over {MAX_PERSON_DELEGATION_TTL}s")
    reach = claims.get("job_reach")
    if not isinstance(reach, list) or not reach:
        raise CredentialRefused("a job's delegation with no reach")
    grant = _live_grant_row(db, str(claims.get("job_grant") or ""))
    if grant is None or not authority_ledger.is_reach_job(str(grant.job)):
        raise CredentialRefused("the job grant this delegation names is revoked, over, or not a "
                                "timer's")
    if grant.principal != persona.subject:
        raise CredentialRefused("a job grant another person made")
    granted = _json.loads(getattr(grant, "reach", None) or "[]")
    if sorted({str(r) for r in reach}) != sorted({str(r) for r in granted}):
        raise CredentialRefused("a job's delegation whose reach is not its grant's")
    # No `principal`: the key it opens is the one the listed artifact is keyed under, a
    # collection's (`ck:<collection>`) or the person's own, which `bind_to_job_reach` and the
    # release's own walk decide.
    return VerifiedCredential(persona.subject, "job", persona.jti,
                              reach=tuple(sorted({str(r) for r in granted})))


def bind_to_job_reach(cred: VerifiedCredential, principal_id: str, artifact_id: Optional[str],
                      rc=None) -> None:
    """A job's delegation opens a key only for an artifact its grant lists, named by id, and only
    the key that artifact is keyed under: its own collection's, by its creation edge, or the
    person's own master key."""
    if cred.kind != "job":
        return
    if not artifact_id or artifact_id not in cred.reach:
        raise CredentialRefused("a job's delegation opens a key only for an artifact its job "
                                "grant lists")
    from origin.services.authority_reach import collection_key_collection
    collection = collection_key_collection(principal_id)
    if collection is None:
        # The person's own master key, or the key of the root the listed artifact sits under.
        node, seen = str(artifact_id), set()
        while principal_id != cred.subject and node != principal_id and node not in seen \
                and rc is not None and len(seen) < 64:
            seen.add(node)
            up = rc.origin_parent(node)
            if not up:
                break
            node = str(up[0])
        if principal_id != cred.subject and node != principal_id:
            raise CredentialRefused("a job's delegation opens only the key its listed artifact "
                                    "is keyed under")
        return
    if collection == str(artifact_id):
        return                       # a top-level artifact is keyed under its own id
    parent = rc.origin_parent(artifact_id) if rc is not None else None
    if not parent or parent[0] != collection:
        raise CredentialRefused("a job's delegation opens only the key its listed artifact is "
                                "keyed under")


class IssuanceLimited(CredentialRefused):
    """This job grant has had its delegations for the minute."""


def mint_background_delegation(db: Session, principal_id: str, job: str,
                               ttl_seconds: int = DEFAULT_BACKGROUND_TTL) -> dict:
    """A delegation for one principal, for one named job, minted only under a live job grant
    naming that job and covering that principal (John, 2026-11-02). Rate-limited per grant, each
    one recorded, and the operator alerted once per grant per hour. Returns
    `{"token", "jti", "expires_at", "job_grant"}`; the token is not kept."""
    import json as _json

    from origin.services import authority_ledger, custody_plane
    from origin.services.auth_service import issue_system_delegation_token

    why_not = custody_plane.custody_refusal()
    if why_not:
        raise CredentialRefused(why_not)
    if authority_ledger.is_reach_job(job):
        # A timer's grant opens content within its reach, as the person, through Lumen; it never
        # releases a key share, whoever asks.
        raise CredentialRefused(f"job {job!r} is a timer's, and releases no key share")
    grant = authority_ledger.live_job_grant(db, job=job, principal=principal_id)
    if grant is None:
        raise CredentialRefused(f"no live job grant names job {job!r} for {principal_id!r}; "
                                f"background key use is shut until the person, or an Admin of "
                                f"the collection, grants it")
    minute_ago = _now() - timedelta(seconds=60)
    recent = (db.query(KeyCustodyDelegation)
              .filter(KeyCustodyDelegation.job_grant_id == grant.grant_id).all())
    if sum(1 for r in recent if _aware(r.created_time) > minute_ago) >= JOB_ISSUANCE_PER_MINUTE:
        raise IssuanceLimited(f"job grant {grant.grant_id} has had {JOB_ISSUANCE_PER_MINUTE} "
                              f"delegations this minute")
    ttl = max(30, min(int(ttl_seconds), MAX_BACKGROUND_TTL))
    jti = secrets.token_hex(16)
    expires = _now() + timedelta(seconds=ttl)
    token = issue_system_delegation_token(
        principal_id, actor=grant.created_by or "job", scope=SHARE_RELEASE_SCOPE,
        audience=PLATFORM_AUDIENCE, ttl_seconds=ttl, jti=jti)
    db.add(KeyCustodyDelegation(jti=jti, subject=principal_id, issued_by=grant.created_by or "",
                                job_grant_id=grant.grant_id, job=job,
                                collections=grant.collections, expires_at=expires))
    db.commit()
    _alert_issuance(db, grant, principal_id, job, len(recent) + 1)
    return {"token": token, "jti": jti, "expires_at": expires.isoformat(timespec="seconds"),
            "job_grant": grant.grant_id, "collections": _json.loads(grant.collections or "[]")}


def _alert_issuance(db: Session, grant, principal_id: str, job: str, total: int) -> None:
    """One operator alert per job grant per hour, its count kept current: every issuance is in
    `key_custody_delegations`, and the alert says that a job is drawing on its grant."""
    from origin.models.authority_ledger import OperatorAlert

    hour_ago = _now() - timedelta(hours=1)
    row = (db.query(OperatorAlert).filter(OperatorAlert.kind == "background_issuance",
                                          OperatorAlert.resource_id == grant.grant_id)
           .order_by(OperatorAlert.id.desc()).first())
    detail = (f"job {job} drew {total} background delegation(s) under job grant "
              f"{grant.grant_id} (last for {principal_id})")
    if row is not None and _aware(row.created_time) > hour_ago:
        row.detail = detail
    else:
        db.add(OperatorAlert(kind="background_issuance", seq=grant.seq or 0,
                             resource_id=grant.grant_id, subject=principal_id, actor="mantle",
                             detail=detail))
    db.commit()

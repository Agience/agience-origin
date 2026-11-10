"""/internal/key-shares — Origin's share of each Mantle master key, for Mantle alone.

Mantle splits each principal's master key 2-of-3 and keeps share 2 here (`services.key_shares`
says how it is stored and when a write may replace one). Mantle combines its own share with this
one to use a key, so these routes are the whole of Origin's part in key custody:

    PUT /internal/key-shares/{principal_id}   {"x", "y", "kcv", "supersedes"?}
    GET /internal/key-shares/{principal_id}?collection_id=&artifact_id=
                                              -> {"x", "y", "kcv"}
                                              |  404 {"absent": true}  (no share stored)
                                              |  403                   (the caller does not reach it)
                                              |  503                   (a share that will not open)
        X-Acting-Credential: <the acting caller's own credential>     (required on GET)
    POST /internal/custody-delegations/{principal_id}   {"job"}
                                              -> {"token", "jti", "expires_at", "job_grant"}
                                              |  403 (no live job grant names this job and key)
                                              |  429 (the grant's delegations for the minute)

The caller must be Mantle's enrolled service identity: a service JWT addressed to Origin
(`aud=origin`), signed by the key the authority manifest anchors for `mantle`, which `get_auth`
verifies as it does for every peer call. No other service, no person and no delegation reaches a
share. Chorus is a platform service too, and is refused here: it has no part in key custody.

Each token is also bound to the one call it was signed for, so a token taken from a log or a proxy
opens nothing else and nothing twice: it lives at most `MAX_TOKEN_TTL` seconds, carries a `jti`
that is accepted once (`key_custody_nonces`), and names the method (`htm`), the route path (`htu`),
the principal (`principal_id`) and, on a release, the scope (`collection_id`, `artifact_id`), each
of which must match the request.

A release also needs the credential of whoever Mantle is acting for, in `X-Acting-Credential`,
which Origin verifies itself (`services.share_credentials`): a person's access token, a delegation
Origin issued for a person, or a background delegation Origin minted for this one principal. Origin
then decides, by its own walk over its replica of the authority ledger
(`authority_reach.Reach.may_release`), whether the credential's subject reaches this key for
`read`: the principal itself, or a collection (or artifact) keyed under it that the subject reaches.
Without such a credential Mantle alone cannot open a key. A store needs none: it releases nothing.

Background work has no person present. It runs on a job grant: Mantle asks for a delegation for
one principal and one named job at `/internal/custody-delegations/{principal_id}`, and Origin mints
one only under a live job grant naming both; it lives minutes and opens that principal, and the
collections its grant covers, alone. Custody is refused off isolated production
(`services.custody_plane`).

Every call is logged, refusals at WARNING. A release is recorded (`key_custody_releases`) with the
principal, the collection, the credential's subject, kind and reference (its `jti` or a hash), and
logged with the first eight characters of the key-check value; never the share and never the
credential.
"""
from __future__ import annotations

import logging

from origin.services.platform_settings_service import settings as platform_settings
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from jose import jwt as jose_jwt
from sqlalchemy.orm import Session

from origin.db.session import get_db
from origin.models.key_custody import KeyCustodyShare
from origin.services import authority_ledger, key_shares, share_credentials
from origin.services.dependencies import AuthContext, get_auth

logger = logging.getLogger(__name__)
_PREFIX = "/internal/key-shares"
key_share_router = APIRouter(prefix=_PREFIX, tags=["Internal"], include_in_schema=False)

#: The one service that holds the other share. A set of one, named, so a test can read it.
CUSTODIAN_PEERS = frozenset({"mantle"})

#: Where the acting caller's own credential travels on a release or a ledger submission.
ACTING_CREDENTIAL_HEADER = "X-Acting-Credential"

#: The longest lifetime (`exp - iat`) a custody token may have.
MAX_TOKEN_TTL = 60


def _require_mantle(auth: AuthContext = Depends(get_auth)) -> AuthContext:
    """Mantle's own service token, or 403.

    `principal_id` is the verified `iss`; `actor` is set only when a service token carries a
    `client_id` (a persona riding a shared key), which Mantle's never does.
    """
    if (auth.principal_type != "service" or auth.principal_id not in CUSTODIAN_PEERS
            or auth.actor is not None):
        logger.warning(
            "key share access refused: principal_type=%s principal=%s actor=%s",
            auth.principal_type, auth.principal_id, auth.actor,
        )
        raise HTTPException(status_code=403, detail="key custody peer only")
    return auth


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    return header[7:].strip() if header[:7].lower() == "bearer " else ""


def bound_call(request: Request, db: Session, *, path: str, claims_must: dict) -> str:
    """Refuse (401) a token not bound to this method, path and these claims, or already spent.
    Returns the token.

    Runs after `_require_mantle`, so the signature is already verified; the claims are read from
    the same token. A claim whose required value is None must be absent or null."""
    token = _bearer(request)
    claims = jose_jwt.get_unverified_claims(token)
    why = ""
    iat, exp, jti = claims.get("iat"), claims.get("exp"), claims.get("jti")
    if not isinstance(iat, int) or not isinstance(exp, int) or exp - iat > MAX_TOKEN_TTL:
        why = f"lifetime over {MAX_TOKEN_TTL}s"
    elif not isinstance(jti, str) or not 8 <= len(jti) <= 128:
        why = "no jti"
    elif claims.get("htm") != request.method:
        why = "method"
    elif claims.get("htu") != path:
        why = "path"
    else:
        for name, want in claims_must.items():
            if claims.get(name) != want:
                why = name
                break
    if not why and not key_shares.spend_token(db, jti, datetime.fromtimestamp(exp, timezone.utc)):
        why = "replayed"
    if why:
        logger.warning("custody call refused: %s %s token not bound to this call (%s)",
                       request.method, path, why)
        raise HTTPException(status_code=401, detail="token not bound to this call")
    return token


def _bound(request: Request, principal_id: str, db: Session, **extra) -> str:
    if not key_shares.valid_principal(principal_id):
        raise HTTPException(status_code=400, detail="malformed principal id")
    return bound_call(request, db, path=f"{_PREFIX}/{principal_id}",
                      claims_must={"principal_id": principal_id, **extra})


def acting_credential(request: Request, db: Session, what: str, *, job: bool = False):
    """The verified acting credential on this request, or 401/403 naming why. `job`: the release
    route alone also takes a timer's job delegation (`share_credentials.verify_job_credential`)."""
    credential = request.headers.get(ACTING_CREDENTIAL_HEADER, "").strip()
    if not credential:
        logger.warning("%s refused: no acting credential", what)
        raise HTTPException(status_code=401, detail="the acting caller's credential is required")
    try:
        if job and share_credentials.carries_job_grant(credential):
            return share_credentials.verify_job_credential(db, credential)
        return share_credentials.verify_share_credential(db, credential)
    except share_credentials.CredentialRefused as exc:
        logger.warning("%s refused: acting credential refused (%s)", what, exc)
        raise HTTPException(status_code=403, detail=f"acting credential refused: {exc}")


def _known(rc, key_id: str) -> bool:
    """Does Origin's replica know this key: a master key's root, or a collection key's
    collection?"""
    from origin.services.authority_reach import collection_key_collection

    coll = collection_key_collection(key_id)
    if coll is not None:
        return rc.r.node(coll) is not None
    return rc.r.root_entry(key_id) is not None


def _scope_id(value: Optional[str]) -> Optional[str]:
    if value is None or value == "":
        return None
    if not key_shares.valid_principal(value):
        raise HTTPException(status_code=400, detail="malformed collection or artifact id")
    return value


def _custody_here() -> None:
    """Custody only on isolated production (`services.custody_plane`), else 403."""
    from origin.services import custody_plane
    why = custody_plane.custody_refusal()
    if why:
        logger.warning("custody refused on this node: %s", why)
        raise HTTPException(status_code=403, detail=why)


def _charged_store(db: Session, principal_id: str, body: dict) -> bool:
    """A charged root's share is stored only for the key step 21 rotated it onto, as the operator
    recorded it, and only while that split is open under its grant (reviews 31 and 32); otherwise
    403. True for a charged root."""
    if not authority_ledger.charged_root(authority_ledger.reach(db), principal_id):
        return False
    kcv = authority_ledger.rotation_kcv(db, principal_id)
    rot = authority_ledger._rotation(db, principal_id)
    if kcv is None or rot is None or rot.grant_id is None or \
            not authority_ledger.charged_split_open(db, principal_id) or \
            (body or {}).get("kcv") != kcv:
        logger.warning("key share store refused: principal=%s is a charged root, and this is not "
                       "its recorded rotated key's open split", principal_id)
        raise HTTPException(status_code=403, detail="not stored: a charged root's share is "
                            "stored only for its recorded rotated key, while its split is open")
    return True


@key_share_router.put("/{principal_id}")
def put_share(principal_id: str, request: Request, body: dict = Body(...),
              db: Session = Depends(get_db), auth: AuthContext = Depends(_require_mantle)):
    _custody_here()
    _bound(request, principal_id, db)
    charged = _charged_store(db, principal_id, body)
    # A first share is stored only for a key Origin's replica knows (a master key's root, a
    # collection key's collection), on the credential of its principal or of whoever brought it
    # into being. No share can exist for an id Origin has not seen.
    first = db.get(KeyCustodyShare, principal_id) is None
    if first:
        rc = authority_ledger.reach(db)
        if not _known(rc, principal_id):
            raise HTTPException(status_code=403, detail="not stored: Origin's replica does not "
                                "know this key; its root or collection comes first")
        acting = acting_credential(request, db, f"key share store: principal={principal_id}")
        if acting.kind == "narrowed":
            # The memory collection is made, and its key stored, by the person's own token at
            # sign-in; a narrowed delegation stores no key share (review 11).
            raise HTTPException(status_code=403, detail="not stored: a narrowed delegation "
                                "stores no key share")
        # Its principal, a subject that may open it, or one holding admin on what it keys (the
        # creation grant): explicit grants, never created_by.
        may, _why = rc.may_release(subject=acting.subject, principal_id=principal_id,
                                   collection_id=None)
        from origin.services.authority_reach import collection_key_collection
        node = collection_key_collection(principal_id) or principal_id
        if acting.subject != principal_id and not may and not rc.has_any_action(
                acting.subject, node, "admin"):
            logger.warning("key share store refused: principal=%s for=%s", principal_id,
                           acting.subject)
            raise HTTPException(status_code=403, detail="not stored: a first share is stored "
                                "by the key's principal or its creator")
    # Any write to a share Origin holds changes what opens everything under it, whatever key
    # check it claims: the key check is Mantle's claim, never proof. Restating the very share
    # Origin holds changes nothing and needs only a credential that reaches it. Anything else is
    # accepted only for a share marked replaceable (a first share Mantle has not activated yet,
    # or one the operator's seed or bootstrap credential marked for re-key), and only from the
    # key's principal or Admin on what it keys.
    else:
        acting = acting_credential(request, db, f"key share replace: principal={principal_id}")
        if acting.kind == "narrowed":
            raise HTTPException(status_code=403, detail="not replaced: a narrowed delegation "
                                "replaces no share")
        try:
            share_credentials.bind_to_principal(acting, principal_id)
        except share_credentials.CredentialRefused as exc:
            raise HTTPException(status_code=403, detail=f"acting credential refused: {exc}")
        rc = authority_ledger.reach(db)
        row = db.get(KeyCustodyShare, principal_id)
        if key_shares.same_share(row, body):
            allowed, why = rc.may_release(subject=acting.subject, principal_id=principal_id,
                                          collection_id=None)
            if not allowed and acting.subject != principal_id:
                raise HTTPException(status_code=403, detail=f"not restated: {why}")
        else:
            from origin.services.authority_reach import collection_key_collection
            node = collection_key_collection(principal_id) or principal_id
            if not row.rekey_pending:
                raise HTTPException(status_code=403, detail="not replaced: this share is not "
                                    "marked for re-key")
            # Whoever stored a first share may replace it while it is still pending (review 27):
            # their own split, interrupted before it was activated.
            storer = bool(row.stored_by) and row.stored_by == acting.subject
            if acting.subject != principal_id and not storer and not rc.has_any_action(
                    acting.subject, node, "admin"):
                logger.warning("key share replace refused: principal=%s for=%s", principal_id,
                               acting.subject)
                raise HTTPException(status_code=403, detail="not replaced: a share is replaced "
                                    "by the key's principal or Admin on what it keys")
    supersedes = body.get("supersedes")
    if charged and not first:
        # The record of a fresh kcv is what lets the pending share of an earlier key be replaced
        # (review 32): the split of the rotated key goes through over it, as a re-split does.
        held = db.get(KeyCustodyShare, principal_id)
        if held is not None and held.rekey_pending:
            supersedes = held.kcv
    try:
        outcome = key_shares.store_share(
            db, principal_id, {k: body.get(k) for k in ("x", "y", "kcv")},
            supersedes=supersedes if isinstance(supersedes, str) else None,
        )
    except key_shares.ShareRejected as exc:
        logger.warning("key share store refused: principal=%s caller=%s (%s)",
                       principal_id, auth.principal_id, exc)
        raise HTTPException(status_code=400, detail=str(exc))
    except key_shares.ShareConflict:
        logger.warning(
            "key share store refused: principal=%s caller=%s a share of another key is stored",
            principal_id, auth.principal_id,
        )
        raise HTTPException(status_code=409, detail="a share of another key is stored")
    if first and outcome == "stored":
        # Whoever stored a first share may activate it (review 26, L3), until it is activated.
        row = db.get(KeyCustodyShare, principal_id)
        if row is not None:
            row.stored_by = acting.subject
            db.commit()
    if charged:
        authority_ledger.note_charged_share_written(db, principal_id)
    logger.info("key share %s: principal=%s caller=%s kcv=%s", outcome, principal_id,
                auth.principal_id, str(body.get("kcv"))[:8])
    return {"principal_id": principal_id, "outcome": outcome}


@key_share_router.post("/{principal_id}/activate")
def activate_share(principal_id: str, request: Request, db: Session = Depends(get_db),
                   auth: AuthContext = Depends(_require_mantle)):
    """Mantle activated the key this share belongs to: it is no longer replaceable. On the acting
    credential of the key's principal, of one holding Admin on what it keys, as a replacement is
    (review 25), or of whoever stored this first share, until it is first activated (review 26,
    L3): activation decides whether a later re-key can take. Custody only on isolated production
    (review 26, I3)."""
    _custody_here()
    if not key_shares.valid_principal(principal_id):
        raise HTTPException(status_code=400, detail="malformed principal id")
    bound_call(request, db, path=f"{_PREFIX}/{principal_id}/activate",
               claims_must={"principal_id": principal_id})
    row = db.get(KeyCustodyShare, principal_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no share")
    acting = acting_credential(request, db, f"key share activate: principal={principal_id}")
    if acting.kind == "narrowed":
        raise HTTPException(status_code=403, detail="not activated: a narrowed delegation "
                            "activates no share")
    try:
        share_credentials.bind_to_principal(acting, principal_id)
    except share_credentials.CredentialRefused as exc:
        raise HTTPException(status_code=403, detail=f"acting credential refused: {exc}")
    from origin.services.authority_reach import collection_key_collection
    node = collection_key_collection(principal_id) or principal_id
    storer = bool(row.stored_by) and row.stored_by == acting.subject
    if acting.subject != principal_id and not storer and not authority_ledger.reach(
            db).has_any_action(acting.subject, node, "admin"):
        logger.warning("key share activate refused: principal=%s for=%s", principal_id,
                       acting.subject)
        raise HTTPException(status_code=403, detail="not activated: a share is activated by the "
                            "key's principal, Admin on what it keys, or whoever stored its first "
                            "copy")
    if authority_ledger.charged_root(authority_ledger.reach(db), principal_id):
        # Over a charged root, only the recorded rotated key's share, written under the record
        # (review 33, F6): the same share its release reads back.
        rot = authority_ledger._rotation(db, principal_id)
        if rot is None or row.kcv != rot.kcv or not rot.share_written:
            logger.warning("key share activate refused: principal=%s is a charged root, and this "
                           "is not its recorded rotated key's share", principal_id)
            raise HTTPException(status_code=403, detail="not activated: a charged root's share is "
                                "activated only for its recorded rotated key, written under the "
                                "record")
        # Activated, the record is spent (review 34): its kcv is never recorded again, even
        # after a seed's re-mark, so a new record needs a fresh kcv.
        rot.share_written = False
    row.rekey_pending = False
    row.stored_by = None                  # the storer's say ends at the first activation
    db.commit()
    if authority_ledger.charged_root(authority_ledger.reach(db), principal_id):
        # The split of a charged root's rotated key has read back (review 31): the operator's
        # custody grant over it ends here.
        ended = authority_ledger.end_charged_custody(db, principal_id)
        logger.warning("charged root %s split and activated: %d custody grant(s) revoked",
                       principal_id, ended)
    return {"principal_id": principal_id, "rekey_pending": False}


@key_share_router.post("/{principal_id}/rekey-pending")
def mark_rekey_pending(principal_id: str, request: Request, db: Session = Depends(get_db),
                       auth: AuthContext = Depends(_require_mantle)):
    """Mark a share for re-key, on the operator's seed or bootstrap credential only (the split
    or the rekey pass). Custody only on isolated production (review 27)."""
    _custody_here()
    if not key_shares.valid_principal(principal_id):
        raise HTTPException(status_code=400, detail="malformed principal id")
    bound_call(request, db, path=f"{_PREFIX}/{principal_id}/rekey-pending",
               claims_must={"principal_id": principal_id})
    credential = request.headers.get(ACTING_CREDENTIAL_HEADER, "").strip()
    kind = None
    try:
        from origin.services import share_credentials as _sc
        verified = _sc.verify_share_credential(db, credential)
        kind = verified.kind
    except Exception:  # noqa: BLE001 — not a share credential: try the bootstrap one
        kind = None
    if kind == "seed" and not _sc.seed_marks(db, verified.ref, principal_id):
        raise HTTPException(status_code=403, detail="this seed credential does not list this "
                            "share for re-key")
    if kind != "seed":
        try:
            authority_ledger.verify_bootstrap_credential(
                db, credential, platform_settings.get("platform.operator_id"))
            kind = "bootstrap"
        except authority_ledger.EntryRefused:
            raise HTTPException(status_code=403, detail="the operator's seed or bootstrap "
                                "credential marks a share for re-key")
        # Scoped like the seed's: only a share whose key the window lists (a master key's
        # principal, or a collection key's collection); a window with no list marks nothing.
        import json as _json
        from origin.services.authority_reach import collection_key_collection
        window = authority_ledger.bootstrap_window(db, credential)
        listed = set(_json.loads(window.ids)) if window is not None and window.ids else set()
        if principal_id not in listed and collection_key_collection(principal_id) not in listed:
            raise HTTPException(status_code=403, detail="this bootstrap credential's window does "
                                "not list this share for re-key")
    row = db.get(KeyCustodyShare, principal_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no share")
    row.rekey_pending = True
    db.commit()
    logger.warning("key share %s marked for re-key on a %s credential", principal_id, kind)
    return {"principal_id": principal_id, "rekey_pending": True}


@key_share_router.get("/{principal_id}")
def get_share(principal_id: str, request: Request,
              collection_id: Optional[str] = Query(default=None),
              artifact_id: Optional[str] = Query(default=None),
              db: Session = Depends(get_db), auth: AuthContext = Depends(_require_mantle)):
    _custody_here()
    collection_id, artifact_id = _scope_id(collection_id), _scope_id(artifact_id)
    _bound(request, principal_id, db, collection_id=collection_id, artifact_id=artifact_id)
    acting = acting_credential(request, db, f"key share release: principal={principal_id}",
                               job=True)
    if acting.kind == "narrowed":
        # Ember acts for a person without ever opening their content (John, 2026-11-02).
        logger.warning("key share release refused: principal=%s for=%s (a narrowed delegation)",
                       principal_id, acting.subject)
        raise HTTPException(status_code=403, detail="acting credential refused: a narrowed "
                            "delegation never releases a key")
    try:
        share_credentials.bind_to_principal(acting, principal_id)
        share_credentials.bind_to_collection(acting, principal_id, collection_id)
        share_credentials.bind_to_job_reach(acting, principal_id, artifact_id,
                                            authority_ledger.reach(db))
    except share_credentials.CredentialRefused as exc:
        logger.warning("key share release refused: principal=%s for=%s (%s)", principal_id,
                       acting.subject, exc)
        raise HTTPException(status_code=403, detail=f"acting credential refused: {exc}")
    # Reach before absence, for any key Origin knows: whether a known key has a share here is
    # told only to someone who reaches it. An id the replica has no root for and no share for is
    # one Origin knows nothing about (Mantle asks before it mints a first key), and "absent"
    # says only that.
    rc = authority_ledger.reach(db)
    held = db.get(KeyCustodyShare, principal_id) is not None
    if not _known(rc, principal_id) and not held:
        logger.info("key share release: principal=%s caller=%s NOT FOUND (unknown key)",
                    principal_id, auth.principal_id)
        return JSONResponse(status_code=404,
                            content={"absent": True, "principal_id": principal_id})
    allowed, why = rc.may_release(
        subject=acting.subject, principal_id=principal_id, collection_id=collection_id,
        artifact_id=artifact_id)
    if not allowed:
        logger.warning("key share release refused: principal=%s collection=%s for=%s (%s %s): %s",
                       principal_id, collection_id, acting.subject, acting.kind, acting.ref, why)
        raise HTTPException(status_code=403, detail=f"not released: {why}")
    if authority_ledger.charged_root(rc, principal_id) and not \
            authority_ledger.charged_release_open(db, principal_id):
        # A charged root's key opens for its own principal alone, and no one acts as a root on a
        # credential of its own: only the split of the key step 21 rotated reads its share back
        # (review 31), and nothing after that split is activated.
        logger.warning("key share release refused: principal=%s for=%s (a charged root, and not "
                       "its rotated key's split reading back)", principal_id, acting.subject)
        raise HTTPException(status_code=403, detail="not released: a charged root's share is "
                            "released only while the split of its recorded rotated key reads "
                            "back")
    if not held:
        return JSONResponse(status_code=404,
                            content={"absent": True, "principal_id": principal_id})
    try:
        share = key_shares.release_share(db, principal_id)
    except key_shares.ShareUnreadable:
        logger.error("key share release refused: principal=%s the stored share does not decrypt",
                     principal_id)
        raise HTTPException(status_code=503, detail="the stored share could not be decrypted")
    if share is None:
        return JSONResponse(status_code=404,
                            content={"absent": True, "principal_id": principal_id})
    share_credentials.record_release(db, principal_id, acting, collection_id=collection_id)
    # Whether the share is still replaceable (review 28, L4): Mantle completes an activated
    # share's split, and draws a fresh one over a pending share, which its storer may replace.
    pending = bool(db.get(KeyCustodyShare, principal_id).rekey_pending)
    logger.warning("key share released: principal=%s collection=%s caller=%s for=%s (%s %s: %s) "
                   "kcv=%s", principal_id, collection_id, auth.principal_id, acting.subject,
                   acting.kind, acting.ref, why, str(share.get("kcv"))[:8])
    return {"principal_id": principal_id, **share, "pending": pending}


# -- background work: a delegation for one principal, minutes long ------------------------------

delegation_router = APIRouter(prefix="/internal/custody-delegations", tags=["Internal"],
                              include_in_schema=False)


@delegation_router.post("/{principal_id}")
def mint_delegation(principal_id: str, request: Request, body: dict = Body(default={}),
                    db: Session = Depends(get_db), auth: AuthContext = Depends(_require_mantle)):
    """A background delegation for one principal and one named job (`{"job"}`, bound in the
    service token), minted only under a live job grant for both. Mantle's token alone mints
    nothing."""
    _custody_here()
    if not key_shares.valid_principal(principal_id):
        raise HTTPException(status_code=400, detail="malformed principal id")
    job = body.get("job") if isinstance(body, dict) else None
    if not isinstance(job, str) or not job:
        raise HTTPException(status_code=400, detail="body.job names the background job")
    bound_call(request, db, path=f"/internal/custody-delegations/{principal_id}",
               claims_must={"principal_id": principal_id, "job": job})
    # Only for a key Origin's replica knows, or the platform system principal (which acts on the
    # ledger for background work): never for an arbitrary id.
    from origin import service_identity
    if (not _known(authority_ledger.reach(db), principal_id)
            and principal_id != (service_identity.get_system_principal_id() or None)):
        logger.warning("background delegation refused: principal=%s is no key Origin knows",
                       principal_id)
        raise HTTPException(status_code=403, detail="no key principal Origin's replica knows")
    try:
        minted = share_credentials.mint_background_delegation(db, principal_id, job)
    except share_credentials.IssuanceLimited as exc:
        logger.warning("background delegation refused: principal=%s job=%s (%s)", principal_id,
                       job, exc)
        raise HTTPException(status_code=429, detail=str(exc))
    except share_credentials.CredentialRefused as exc:
        logger.warning("background delegation refused: principal=%s job=%s (%s)", principal_id,
                       job, exc)
        raise HTTPException(status_code=403, detail=str(exc))
    logger.warning("background delegation minted: principal=%s job=%s grant=%s jti=%s expires=%s",
                   principal_id, job, minted["job_grant"], minted["jti"], minted["expires_at"])
    return minted

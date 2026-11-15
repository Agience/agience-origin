"""/internal/authority — Mantle submits each change to reach; Origin checks it, co-signs, appends.

    POST /internal/authority/entries
         {"entry": {...}, "bootstrap": false, "proof"?: {...}, "compensates"?: <seq>}
        X-Acting-Credential: <the acting person's own credential, or the bootstrap credential>
        -> {"outcome": "appended" | "unchanged", "seq", "entry_hash", "prev_hash", "signature",
            "kid"}
        |  400 malformed entry   401 token or credential missing   403 not permitted   409 conflict
    GET  /internal/authority/head      -> {"seq", "entry_hash"}

The caller is Mantle's service identity, on a token bound to this call like every custody call
(`key_share_router.bound_call`), which also names the SHA-256 of the entry body (`body_sha256`),
of the proof when there is one (`proof_sha256`), whether it is a bootstrap entry, and the entry a
compensating entry withdraws: Mantle's signature on the submission. Origin keeps the token's `jti`
and the body digest, not the token.

The acting credential is verified by Origin itself and the entry judged against Origin's own
replica (`services.authority_ledger`). A bootstrap entry is accepted only on the operator's
dedicated bootstrap credential (`/oracle/authority-ledger/bootstrap`), which is good for nothing
else. A background delegation acts on the ledger only as the platform system principal, and makes
no change of its own: no grant, edge or root, no narrowing or retirement (review 16).
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from jose import jwt as jose_jwt
from sqlalchemy.orm import Session

from origin.db.session import get_db
from origin.routers.key_share_router import (
    ACTING_CREDENTIAL_HEADER, _require_mantle, acting_credential, bound_call,
)
from origin.services import authority_ledger
from origin.services.dependencies import AuthContext
from origin.services.platform_settings_service import settings as platform_settings

logger = logging.getLogger(__name__)
_PREFIX = "/internal/authority"
authority_router = APIRouter(prefix=_PREFIX, tags=["Internal"], include_in_schema=False)


@authority_router.post("/entries")
def submit_entry(request: Request, body: dict = Body(...), db: Session = Depends(get_db),
                 auth: AuthContext = Depends(_require_mantle)):
    entry = body.get("entry")
    bootstrap = body.get("bootstrap", False)
    proof = body.get("proof")
    compensates = body.get("compensates")
    batch = body.get("batch")
    if batch is not None and (not isinstance(batch, str) or not 0 < len(batch) <= 64):
        raise HTTPException(status_code=400, detail="batch is a short string")
    if not isinstance(bootstrap, bool):
        raise HTTPException(status_code=400, detail="bootstrap is a boolean")
    if proof is not None and not isinstance(proof, dict):
        raise HTTPException(status_code=400, detail="proof is an object")
    if compensates is not None and (not isinstance(compensates, int)
                                    or isinstance(compensates, bool)):
        raise HTTPException(status_code=400, detail="compensates is an entry number")
    try:
        digest = authority_ledger.body_digest(entry)
    except authority_ledger.EntryRefused as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    token = bound_call(request, db, path=f"{_PREFIX}/entries", claims_must={
        "body_sha256": digest, "bootstrap": bootstrap or None,
        "proof_sha256": authority_ledger.proof_digest(proof), "compensates": compensates,
        "batch": batch})
    jti = str(jose_jwt.get_unverified_claims(token).get("jti") or "")

    if bootstrap:
        credential = request.headers.get(ACTING_CREDENTIAL_HEADER, "").strip()
        try:
            operator = authority_ledger.verify_bootstrap_credential(
                db, credential, platform_settings.get("platform.operator_id"))
        except authority_ledger.EntryRefused as exc:
            logger.warning("authority bootstrap refused: %s", exc)
            raise HTTPException(status_code=403, detail=str(exc))
        actor = authority_ledger.Actor(operator, "bootstrap",
                                       str(jose_jwt.get_unverified_claims(credential)["jti"]))
        window = authority_ledger.bootstrap_window(db, credential)
        window_ids = json.loads(window.ids) if window is not None and window.ids else None
    elif (persona := _persona_entry_actor(request, db)) is not None:
        actor = persona
    else:
        acting = acting_credential(request, db, f"authority entry {entry.get('kind')}")
        if acting.kind == "background":
            from origin import service_identity
            system_id = service_identity.get_system_principal_id()
            if not system_id or acting.subject != system_id:
                logger.warning("authority entry refused: a background delegation for %s acts on "
                               "the ledger only as the system principal", acting.subject)
                raise HTTPException(status_code=403, detail="a background delegation changes "
                                    "reach only as the platform system principal")
        actor = authority_ledger.Actor(acting.subject, acting.kind, acting.ref,
                                       scopes=tuple(getattr(acting, "scopes", ()) or ()),
                                       collections=tuple(getattr(acting, "collections", ())
                                                         or ()))
    try:
        receipt = authority_ledger.append(db, entry, actor=actor, submitted_jti=jti,
                                          bootstrap=bootstrap, proof=proof,
                                          compensates=compensates, batch=batch,
                                          submitted_by=str(jose_jwt.get_unverified_claims(
                                              token).get("iss") or ""),
                                          window_ids=window_ids if bootstrap else None)
    except authority_ledger.EntryRefused as exc:
        logger.warning("authority entry refused: %s by %s (%s): %s", entry.get("kind"),
                       actor.subject, actor.kind, exc)
        raise HTTPException(status_code=exc.status, detail=str(exc))
    return receipt


def _persona_entry_actor(request: Request, db: Session):
    """The actor of a ledger entry made on a persona's own delegation (review 26, L5), by the one
    definition the use verdict and `/reach` take; None when the acting credential is not one.
    What it may make is `authority_ledger._decide_persona`'s. Iris's platform mail delegation
    makes no entry."""
    from origin.services import use_verdict as _uv

    token = request.headers.get(ACTING_CREDENTIAL_HEADER, "").strip()
    try:
        cred = _uv.verify_persona_credential(db, token)
    except _uv.UseRefused:
        return None
    if cred.kind != "person":
        raise HTTPException(status_code=403, detail="a platform purpose's delegation makes no "
                            "change to reach")
    return authority_ledger.Actor(cred.subject, authority_ledger.PERSONA, cred.jti,
                                  scopes=(f"persona:{cred.persona}",))


@authority_router.post("/bootstrap-done")
def bootstrap_done(request: Request, db: Session = Depends(get_db),
                   auth: AuthContext = Depends(_require_mantle)):
    """The bootstrap batch is done: its credential is good for nothing more."""
    bound_call(request, db, path=f"{_PREFIX}/bootstrap-done", claims_must={})
    credential = request.headers.get(ACTING_CREDENTIAL_HEADER, "").strip()
    try:
        authority_ledger.verify_bootstrap_credential(
            db, credential, platform_settings.get("platform.operator_id"))
    except authority_ledger.EntryRefused as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    authority_ledger.finish_bootstrap(db, credential)
    return {"done": True}


@authority_router.post("/confirm")
def confirm_entries(request: Request, body: dict = Body(...), db: Session = Depends(get_db),
                    auth: AuthContext = Depends(_require_mantle)):
    """Mantle committed the writes these entries were made for (`{"seqs": [...]}`); they can no
    longer be withdrawn by compensation."""
    seqs = body.get("seqs")
    if not isinstance(seqs, list) or not all(isinstance(s, int) and not isinstance(s, bool)
                                             for s in seqs):
        raise HTTPException(status_code=400, detail="seqs is a list of entry numbers")
    # Body-bound: the token names the digest of exactly these seqs.
    token = bound_call(request, db, path=f"{_PREFIX}/confirm", claims_must={
        "body_sha256": authority_ledger.confirm_digest(seqs)})
    try:
        n = authority_ledger.confirm(db, seqs, str(jose_jwt.get_unverified_claims(token)
                                                   .get("iss") or ""))
    except authority_ledger.EntryRefused as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    return {"confirmed": n}




#: How many entries one answer of the feed carries; a reader pages on with `after` up to `head`.
FEED_PAGE = 500


@authority_router.get("/feed")
def ledger_feed(request: Request, after: int = 0, db: Session = Depends(get_db),
                auth: AuthContext = Depends(_require_mantle)):
    """Entries after `after`, oldest first, each with everything needed to verify it: its body,
    actor and credential, its place in the chain and Origin's co-signature, and the public key of
    every kid on the page (`keys`). Mantle applies what it did not submit itself from here: the
    operator's revocations and withdrawals, and every authority change made in a person's Origin
    session (review 12)."""
    from origin.models.authority_ledger import AuthorityEntry

    bound_call(request, db, path=f"{_PREFIX}/feed", claims_must={})
    rows = (db.query(AuthorityEntry).filter(AuthorityEntry.seq > int(after))
            .order_by(AuthorityEntry.seq).limit(FEED_PAGE).all())
    keys = authority_ledger._signing_keys(db)
    return {"entries": [{"seq": r.seq, "kind": r.kind, "body": json.loads(r.body),
                         "actor": r.actor, "credential_kind": r.credential_kind,
                         "credential_ref": r.credential_ref, "bootstrap": bool(r.bootstrap),
                         "compensates": r.compensates, "claimed_from": r.claimed_from,
                         "submitted_by": r.submitted_by, "prev_hash": r.prev_hash,
                         "entry_hash": r.entry_hash, "signature": r.signature, "kid": r.kid}
                        for r in rows],
            "keys": {r.kid: keys[r.kid] for r in rows if r.kid in keys},
            "head": authority_ledger.head(db)[0]}


@authority_router.post("/seed-done")
def seed_done(request: Request, db: Session = Depends(get_db),
              auth: AuthContext = Depends(_require_mantle)):
    """The seed pass is done: its seed credential is revoked, so it serves one pass."""
    from origin.services import share_credentials

    bound_call(request, db, path=f"{_PREFIX}/seed-done", claims_must={})
    acting = acting_credential(request, db, "seed done")
    if acting.kind != "seed":
        raise HTTPException(status_code=403, detail="not a seed credential")
    share_credentials.revoke_seed_credential(db, acting.ref)
    return {"done": True}


@authority_router.get("/head")
def ledger_head(db: Session = Depends(get_db), auth: AuthContext = Depends(_require_mantle)):
    seq, digest = authority_ledger.head(db)
    return {"seq": seq, "entry_hash": digest}


#: Origin's own record of the platform's Authorities collection, set only through the console.
AUTHORITY_COLLECTION_SETTING = "platform.authority_collection_id"
_PAGE_MAX = 1000


def _platform_admin(db: Session, subject: str) -> bool:
    """Mantle's rule (`dependencies.is_platform_admin`), decided on Origin's replica: an active
    allow grant carrying Admin on the Authorities collection Origin has pinned, or the operator
    while no one holds one (the first admin has to be appointed by someone)."""
    authority_id = platform_settings.get(AUTHORITY_COLLECTION_SETTING)
    operator = platform_settings.get("platform.operator_id")
    rc = authority_ledger.reach(db)
    # Only a grant to a person counts: Origin's walk reads every grantee type but invites, so a
    # grant typed `service` (or anything else) naming someone's id must appoint no one.
    if (authority_id and _is_person(db, subject)
            and rc.has_any_action(subject, str(authority_id), "admin")
            and _person_admins(db, str(authority_id)) & {subject}):
        return True
    if not operator or str(operator) != subject:
        return False
    if not authority_id:
        return True
    # An appointment is a live grant to a person: an expired one, an invite (no one's until
    # claimed) or any other grantee appoints no one.
    return not _person_admins(db, str(authority_id))


def _is_person(db: Session, subject: str) -> bool:
    from origin.services.authority_ledger import SqlReplica
    return SqlReplica(db).is_person(subject)


def _person_admins(db: Session, authority_id: str) -> set:
    """The people holding a live, unexpired allow grant carrying Admin on `authority_id`."""
    from origin.models.authority_ledger import AuthorityGrant
    from origin.services.authority_reach import unexpired

    return {g.grantee_id for g in db.query(AuthorityGrant).filter(
        AuthorityGrant.resource_id == authority_id, AuthorityGrant.state == "active",
        AuthorityGrant.effect == "allow", AuthorityGrant.grantee_type == "user")
        if "admin" in (g.actions or "").split(",") and unexpired(g.expires_at)
        and _is_person(db, g.grantee_id)}


@authority_router.get("/platform-users")
def platform_users(request: Request, limit: int = 100, offset: int = 0,
                   db: Session = Depends(get_db), auth: AuthContext = Depends(_require_mantle)):
    """Origin's person records, one page, for a platform admin (`_platform_admin`), on Mantle's
    service token bound to this page and the caller's own person credential."""
    if not 1 <= limit <= _PAGE_MAX or offset < 0:
        raise HTTPException(status_code=400, detail=f"limit is 1..{_PAGE_MAX}, offset >= 0")
    bound_call(request, db, path=f"{_PREFIX}/platform-users",
               claims_must={"limit": limit, "offset": offset})
    acting = acting_credential(request, db, "platform user list")
    if acting.kind not in ("access", "delegation"):
        raise HTTPException(status_code=403, detail="a person's own credential lists users")
    if not _platform_admin(db, acting.subject):
        logger.warning("platform user list refused for %s", acting.subject)
        raise HTTPException(status_code=403, detail="Platform admin access required")
    from origin.models.person import Person

    q = db.query(Person).order_by(Person.created_time, Person.id)
    total = q.count()
    users = [{"id": str(p.id), "email": p.email or "", "name": p.name or "",
              "picture": p.picture, "created_time": p.created_time.isoformat()
              if p.created_time else None,
              "deactivated": p.deactivated_at is not None}
             for p in q.offset(offset).limit(limit)]
    return {"users": users, "total": total, "limit": limit, "offset": offset}


# -- Mantle's questions of the replica: reach for an action, and its store's digest (M3) ---------

#: The verdicts a narrowed delegation may ask, by action, for the scopes that make the act: a
#: verdict is not a key (John, 2026-11-02).
_NARROWED_VERDICTS = {"read": ("ember:read",), "create": ("ember:memory",),
                      "add": ("ember:memory",)}


@authority_router.get("/reach")
def reach_for_action(request: Request, resource_id: str = "", action: str = "",
                     db: Session = Depends(get_db), auth: AuthContext = Depends(_require_mantle)):
    """Does the acting credential's subject reach `resource_id` for `action`, by Origin's own
    walk of its replica? Mantle asks before any action under threshold custody, on its service
    token bound to this resource and action and the caller's own credential."""
    from origin.services.authority_reach import ACTIONS

    if action not in ACTIONS or not resource_id or len(resource_id) > 128:
        raise HTTPException(status_code=400, detail="a resource id and one CRUDEASIO action")
    bound_call(request, db, path=f"{_PREFIX}/reach",
               claims_must={"resource_id": resource_id, "action": action})
    subject = _persona_reach_subject(request, db, action)
    if subject is None:
        acting = acting_credential(request, db, f"reach {action} on {resource_id}")
        if acting.kind == "narrowed" and not (set(_NARROWED_VERDICTS.get(action, ())) & set(
                acting.scopes)):
            raise HTTPException(status_code=403, detail=f"a narrowed delegation asks no {action} "
                                "verdict outside its scopes")
        subject = acting.subject
    rc = authority_ledger.reach(db)
    return {"allowed": bool(rc.reaches(subject, resource_id, action))}


#: The most principals one `principal-kinds` question names.
MAX_KINDS = 1000


@authority_router.post("/principal-kinds")
def principal_kinds(request: Request, body: dict = Body(...), db: Session = Depends(get_db),
                    auth: AuthContext = Depends(_require_mantle)):
    """What each key principal is, by Origin's replica (review 27): `person`, `collection_key`,
    `platform`, `root` or `unknown` (`authority_ledger.principal_kind`). Mantle's operator counts
    and the split pass's gate read this, never the shape of an id. Structure only: it says nothing
    a key or a grant would."""
    import hashlib

    ids = body.get("ids") if isinstance(body, dict) else None
    if (not isinstance(ids, list) or len(ids) > MAX_KINDS
            or not all(isinstance(i, str) and 0 < len(i) <= 128 for i in ids)):
        raise HTTPException(status_code=400, detail=f"body.ids is a list of at most {MAX_KINDS} "
                            "principal ids")
    bound_call(request, db, path=f"{_PREFIX}/principal-kinds",
               claims_must={"body_sha256": hashlib.sha256(
                   authority_ledger.canonical(body).encode("utf-8")).hexdigest()})
    rc = authority_ledger.reach(db)
    kinds = {i: authority_ledger.principal_kind(rc, i) for i in ids}
    # The roots a part of which was removed (review 30, F4): step 21 rotates each one's master key
    # and step 23 splits the new key under the operator's `platform.custody` grant.
    charged = sorted(i for i, k in kinds.items() if k == "root" and rc.part_removed(i))
    return {"kinds": kinds, "charged": charged}


#: The verdicts a persona's delegation may ask, by its kind (review 25, M1): what a persona does
#: for a person (`person`), and what Iris's platform mail does (`platform`). A verdict is not a
#: key: a persona's delegation never releases one.
_PERSONA_VERDICTS = {"person": frozenset({"read", "invoke", "create", "update", "add"}),
                     "platform": frozenset({"read", "invoke"})}

#: A server delegation's verdicts narrowed further for one signer, to the actions its Mantle
#: routes take (review 28, L3): Crystal reads, invokes operators and creates
#: (`mantle.services.dependencies.NARROWED_SERVER_ROUTES["crystal"]`).
_SIGNER_VERDICTS = {"crystal": frozenset({"read", "invoke", "create"})}
_ALL_ACTIONS = frozenset({"create", "read", "update", "delete", "evict", "invoke", "add", "share",
                          "admin"})


def _persona_reach_subject(request: Request, db: Session, action: str):
    """The subject of the acting credential when it is a persona's own delegation (the server
    delegation narrowed to the persona, or the platform mail delegation), by the one definition
    the use verdict takes (`use_verdict.verify_persona_credential`); None when it is not one, for
    the ordinary acting-credential check. 403 for an action outside the persona's."""
    from origin.services import use_verdict as _uv

    token = request.headers.get(ACTING_CREDENTIAL_HEADER, "").strip()
    try:
        cred = _uv.verify_persona_credential(db, token)
    except _uv.UseRefused:
        return None
    if action not in _PERSONA_VERDICTS.get(cred.kind, frozenset()) or action not in \
            _SIGNER_VERDICTS.get(cred.persona, _ALL_ACTIONS):
        raise HTTPException(status_code=403, detail=f"a persona's delegation asks no {action} "
                            "verdict")
    return cred.subject


@authority_router.post("/use-verdict")
def use_verdict(request: Request, body: dict = Body(...), db: Session = Depends(get_db),
                auth: AuthContext = Depends(_require_mantle)):
    """Origin's signed verdict that a persona may use a credential's sealed secret for a card
    (`{"credential_id", "card_id"}`), decided by its own walk on the persona's delegation in
    `X-Acting-Credential` (`services.use_verdict`, review 21). Mantle returns it beside the sealed
    copy, and the persona opens nothing without it."""
    import hashlib

    from origin.services import use_verdict as _uv

    credential_id, card_id, nonce = body.get("credential_id"), body.get("card_id"), \
        body.get("nonce")
    if (set(body) != {"credential_id", "card_id", "nonce"}
            or not all(isinstance(v, str) and 0 < len(v) <= 128 for v in (credential_id, card_id))
            or not isinstance(nonce, str) or not 16 <= len(nonce) <= 128):
        raise HTTPException(status_code=400, detail="a credential id, a card id and the "
                            "persona's nonce for this use")
    bound_call(request, db, path=f"{_PREFIX}/use-verdict", claims_must={
        "body_sha256": hashlib.sha256(authority_ledger.canonical(body).encode("utf-8"))
        .hexdigest()})
    token = request.headers.get(ACTING_CREDENTIAL_HEADER, "").strip()
    if not token:
        raise HTTPException(status_code=401, detail="the persona's delegation is required")
    try:
        return {"verdict": _uv.issue(db, token, credential_id, card_id, nonce)}
    except _uv.UseRefused as exc:
        logger.warning("secret use refused: credential=%s card=%s: %s", credential_id, card_id,
                       exc)
        raise HTTPException(status_code=403, detail=f"no verdict: {exc}")


@authority_router.post("/credential-seals")
def credential_seals(request: Request, body: dict = Body(...), db: Session = Depends(get_db),
                     auth: AuthContext = Depends(_require_mantle)):
    """Keep the digests of a credential's sealed copies (`{"credential_id", "sealed_sha256":
    {persona: hex}, "endpoints_sha256"}`), on its writer's own credential in
    `X-Acting-Credential` (review 22): every use verdict carries the persona's."""
    import hashlib

    from origin.services import use_verdict as _uv

    credential_id = body.get("credential_id")
    if (set(body) != {"credential_id", "sealed_sha256", "endpoints_sha256"}
            or not isinstance(credential_id, str) or not 0 < len(credential_id) <= 128):
        raise HTTPException(status_code=400, detail="a credential id and its seals' digests")
    bound_call(request, db, path=f"{_PREFIX}/credential-seals", claims_must={
        "body_sha256": hashlib.sha256(authority_ledger.canonical(body).encode("utf-8"))
        .hexdigest()})
    acting = acting_credential(request, db, f"credential seals for {credential_id}")
    if acting.kind not in ("access", "delegation", "seed"):
        raise HTTPException(status_code=403, detail="a credential's seals are its writer's own")
    try:
        _uv.record_seals(db, acting, authority_ledger.reach(db), credential_id,
                         body.get("sealed_sha256"), body.get("endpoints_sha256"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except _uv.UseRefused as exc:
        logger.warning("credential seals refused: credential=%s for=%s: %s", credential_id,
                       acting.subject, exc)
        raise HTTPException(status_code=403, detail=str(exc))
    return {"credential_id": credential_id, "recorded": True}


@authority_router.post("/verify")
def verify_reach(request: Request, body: dict = Body(...), db: Session = Depends(get_db),
                 auth: AuthContext = Depends(_require_mantle)):
    """Compare Mantle's digest of its active grants and containment edges with the replica's
    (`services.authority_digest`). A mismatch is Mantle's alarm to raise; the replica's counts
    are returned so it can say how far apart they are."""
    import hashlib

    from origin.services import authority_digest

    digest = body.get("digest")
    if not isinstance(digest, str) or len(digest) != 64:
        raise HTTPException(status_code=400, detail="digest is a SHA-256 hex string")
    bound_call(request, db, path=f"{_PREFIX}/verify", claims_must={
        "body_sha256": hashlib.sha256(authority_ledger.canonical(body).encode("utf-8"))
        .hexdigest()})
    mine = authority_digest.replica_digest(db)
    match = mine["digest"] == digest
    if not match:
        logger.error("Mantle's store diverges from the replica: Mantle %s grants, %s edges; "
                     "replica %s grants, %s edges", body.get("grants"), body.get("edges"),
                     mine["grants"], mine["edges"])
    return {"match": match, "replica": mine}

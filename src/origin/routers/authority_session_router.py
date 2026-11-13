"""Authority changes made in the person's own Origin session (review 12, John 2026-11-03).

Mantle holds every person's access token, so no change to authority is taken on one: the web app
calls Origin directly, carrying the person's Origin session cookie (HttpOnly, SameSite=Strict on
Origin's host would not travel cross-site, so the web app's session for this route is the same
cookie sent with `credentials: "include"`; see below), and Origin decides the entry by the same
ledger rules as any of the person's, appended as theirs (`authority_ledger.session_entry`).

    POST /auth/me/authority/entries          {"entry": <edge entry>}  -> the receipt
    GET  /auth/me/authority/grants?resource_id=<id>                  -> {"grants": [...]}
    POST /auth/me/authority/preview          {resource_id}  -> {resource_detail, parents[], parent_details[], grantees[], preview}
    POST /auth/me/authority/grants           {resource_id, grantee_id, actions[], preview, effect?, expires_at?}
    POST /auth/me/authority/grants/{id}/change   {actions[], expires_at?}
    POST /auth/me/authority/grants/{id}/revoke
    POST /auth/me/authority/invites          {resource_id, actions[], email, preview, resource_name?, expires_at?}
    POST /auth/me/authority/invite-context   {token}
    POST /auth/me/authority/claim            {token}
    POST /auth/me/authority/narrow           {audience, scope?}  -> a delegation narrowed to it
    POST /auth/me/authority/mantle-token     -> the person's token addressed to Mantle
        401 no live Origin session   403 refused (CSRF, the ledger's rule, or an invite
        from an account whose address is not verified)   400 malformed
        404 a grant or invite Origin does not hold

Grants are Origin's own record (review 13, H2). The person's view of a resource's grants, and the
prior state of every change, are read from Origin's replica in the session; a grant is made with
an id Origin mints, and changed or revoked by an id Origin holds, the entry built from Origin's
row. Nothing a caller restates from Mantle's listing reaches the ledger: the generic route makes
edge changes only.

Invites are Origin's to make and to mail (review 13, H1; John, 2026-11-03). Origin mints the
claim token, targets the invite at the address the owner gives (claimable once, by the person whose
verified address it is), and mails the link there, as it mails sign-in codes. The token is in that
mail alone: no answer carries it, Mantle never sees the address or the link, and a claim by anyone
else refuses and spends nothing.

Cross-site request forgery: a request is taken only with the custom header `X-Origin-Session`
(which no form or simple cross-site request can set, and which a browser sends cross-origin only
after a preflight Origin answers for the web app alone) and an `Origin` (or, without one, a
`Referer`) that is the web app (`APP_URI`) or Origin itself. Plain grants need no step-up; a job
grant is not made here (`POST /auth/me/job-grants`, with its step-up).

The preflight for this route is answered here (`SessionCORS`), with credentials, for the web app
and Origin only; Origin's general CORS policy stays without credentials.
"""
from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from origin.db.session import get_db

logger = logging.getLogger(__name__)

PREFIX = "/auth/me/authority"
HEADER = "X-Origin-Session"

authority_session_router = APIRouter(prefix=PREFIX, tags=["Authority"])


def _origin_of(url: str) -> Optional[str]:
    try:
        p = urlparse(url or "")
    except ValueError:
        return None
    if not p.scheme or not p.netloc:
        return None
    return f"{p.scheme}://{p.netloc}".lower()


def trusted_origins() -> set:
    """The web app and Origin itself: the only pages that may make an authority change."""
    from origin import config
    out = set()
    for u in (config.APP_URI, config.ORIGIN_URI, getattr(config, "AUTHORITY_ISSUER", "")):
        o = _origin_of(u)
        if o:
            out.add(o)
    return out


def _check_csrf(request: Request) -> None:
    if request.headers.get(HEADER) is None:
        raise HTTPException(status_code=403, detail=f"the {HEADER} header is required")
    origin = request.headers.get("origin")
    source = _origin_of(origin) if origin else _origin_of(request.headers.get("referer", ""))
    if source is None or source not in trusted_origins():
        raise HTTPException(status_code=403, detail="an authority change comes from the web app "
                            "or Origin's own pages")


def _person(request: Request, db: Session) -> str:
    from origin.db import persons as db_persons
    from origin.services import origin_session
    from origin.services.auth_service import refuse_if_deactivated

    _check_csrf(request)
    person = origin_session.person_of(request, db)
    if not person:
        raise HTTPException(status_code=401, detail="sign in at Origin: an authority change is "
                            "made in your Origin session")
    row = db_persons.get_by_id(db, str(person))
    if row is None:
        raise HTTPException(status_code=401, detail="sign in at Origin: an authority change is "
                            "made in your Origin session")
    refuse_if_deactivated(row)
    return str(person)


@authority_session_router.post("/narrow")
def narrow(request: Request, body: dict = Body(default={}), db: Session = Depends(get_db)):
    """A delegation for the signed-in person narrowed to one audience and its scopes (review 23,
    H1): made only here, in the person's Origin session, never on a bearer Mantle could hold."""
    from origin.routers.auth_router import narrow_for_person

    person = _person(request, db)
    audience, scope = body.get("audience"), body.get("scope")
    if not isinstance(audience, str) or (scope is not None and not isinstance(scope, str)):
        raise HTTPException(status_code=400, detail="an audience, and optionally a scope")
    return narrow_for_person(db, person, audience, scope)


@authority_session_router.post("/mantle-token")
def mantle_token(request: Request, body: dict = Body(default={}),
                 db: Session = Depends(get_db)):
    """The signed-in person's token addressed to Mantle (review 23, H1): what the web app calls
    Mantle on. Origin takes it as no session and exchanges it for nothing.

    `expect_sub` names the person the web app has signed in. The browser's Origin session may be
    someone else's (another tab signed in at Origin), and the web app must never call Mantle as
    them: a session for another person answers 409 and issues nothing."""
    from origin import config
    from origin.db import persons as db_persons
    from origin.services import auth_service

    person_id = _person(request, db)
    expected = (body or {}).get("expect_sub") if isinstance(body, dict) else None
    if expected is not None and str(expected) != str(person_id):
        raise HTTPException(status_code=409, detail="this browser's Origin session is another "
                            "person's: sign in again")
    person = db_persons.get_by_id(db, person_id)
    if person is None:
        raise HTTPException(status_code=401, detail="Invalid subject")
    token = auth_service.issue_mantle_token(
        person, client_id=getattr(config, "PLATFORM_CLIENT_ID", "") or "agience-client")
    return {"access_token": token, "token_type": "bearer",
            "expires_in": auth_service.MANTLE_TOKEN_TTL_SECONDS}


def _append(db: Session, person: str, entry: dict, proof: Optional[dict] = None) -> dict:
    from origin.services import authority_ledger
    try:
        return authority_ledger.session_entry(db, person, entry, proof)
    except authority_ledger.EntryRefused as exc:
        logger.warning("session authority entry refused for %s: %s", person, exc)
        raise HTTPException(status_code=exc.status, detail=str(exc))


@authority_session_router.post("/entries")
def session_entry(request: Request, body: dict = Body(...), db: Session = Depends(get_db)):
    """An edge change the person makes in their Origin session. Grants, denies and invites have
    their own routes, built from Origin's own record (review 13, H2)."""
    person = _person(request, db)
    entry = body.get("entry")
    if not isinstance(entry, dict):
        raise HTTPException(status_code=400, detail="body.entry is a ledger entry")
    if entry.get("kind") not in ("edge.add", "edge.remove"):
        raise HTTPException(status_code=400, detail="this route makes edge changes; a grant, deny "
                            "or invite is made at /auth/me/authority/grants or /invites")
    return _append(db, person, entry)


def _grant_view(g) -> dict:
    return {"grant_id": g.grant_id, "grantee_id": g.grantee_id, "grantee_type": g.grantee_type,
            "resource_id": g.resource_id,
            "actions": [a for a in (g.actions or "").split(",") if a], "effect": g.effect,
            "state": g.state, "expires_at": g.expires_at, "target_kind": g.target_kind}


def _display_name(db: Session, person_id: str) -> str:
    """A person's display name at Origin (`Person.name`), the same record the preview's creators
    are named from; "" for anyone Origin holds no name for. Never their address."""
    import uuid as _uuid

    from origin.models.person import Person
    try:
        who = db.get(Person, _uuid.UUID(str(person_id)))
    except (ValueError, TypeError):
        return ""
    return (getattr(who, "name", "") or "") if who is not None else ""


def _listed(db: Session, g) -> dict:
    """A grant as the owner's sharing dialog lists it: a person grantee named, and an invite with
    how many times it was claimed, so a spent one is shown as spent."""
    v = _grant_view(g)
    if g.grantee_type == "user":
        v["grantee_name"] = _display_name(db, g.grantee_id)
    if g.grantee_type == "invite":
        from origin.models.authority_ledger import AuthorityGrant
        v["max_claims"] = g.max_claims
        v["claims"] = (db.query(AuthorityGrant)
                       .filter(AuthorityGrant.claimed_from == g.grant_id).count())
    return v


def _may_share(db: Session, person: str, resource_id: str) -> bool:
    from origin.services import authority_ledger
    return authority_ledger.reach(db).has_any_action(person, resource_id, "share", "admin")


def _actions(value) -> list:
    if not isinstance(value, list) or not value or not all(isinstance(a, str) for a in value):
        raise HTTPException(status_code=400, detail="actions is a list of CRUDEASIO names")
    return value


def _held(db: Session, grant_id: str):
    from origin.models.authority_ledger import AuthorityGrant
    row = db.get(AuthorityGrant, grant_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Origin holds no grant with this id")
    return row


def _entry_from(row, **changes) -> dict:
    v = _grant_view(row)
    entry = {"kind": "grant", "grant_id": v["grant_id"], "grantee_id": v["grantee_id"],
             "grantee_type": v["grantee_type"], "resource_id": v["resource_id"],
             "actions": v["actions"], "effect": v["effect"], "state": v["state"],
             "expires_at": v["expires_at"],
             "target": ({"kind": row.target_kind, "digest": row.target_digest}
                        if row.target_kind else None),
             "max_claims": row.max_claims}
    entry.update(changes)
    return entry


def _preview_of(db: Session, resource_id: str) -> dict:
    """What Origin holds about a resource, for the owner to confirm before an invite or grant is
    made on it (review 15, L4): the resource itself (its creator, creation date, and how many
    members and grantees it has, review 17), its creation chain up to its root (ids, each with its
    creator and date), and the active grants on it and on each of those parents, which reach it. `preview` is the digest of exactly this; a
    make names it, and is refused if Origin holds something else by then."""
    import hashlib
    import json as _json

    from origin.models.authority_ledger import AuthorityGrant
    from origin.services import authority_ledger
    rc = authority_ledger.reach(db)
    parents, cur, seen = [], resource_id, {resource_id}
    while True:
        p = rc.origin_parent(cur)
        if not p or not p[0] or p[0] in seen:
            break
        cur = str(p[0])
        seen.add(cur)
        parents.append(cur)
    rows = (db.query(AuthorityGrant)
            .filter(AuthorityGrant.resource_id.in_([resource_id, *parents]),
                    AuthorityGrant.state == "active")
            .order_by(AuthorityGrant.resource_id, AuthorityGrant.grant_id).all())
    grantees = [{"resource_id": g.resource_id, "grantee_id": g.grantee_id,
                 "grantee_type": g.grantee_type, "effect": g.effect,
                 # Named only on the item itself: a grantee up the chain is reached through it,
                 # and naming them would let an owner of a child read names off a parent.
                 **({"grantee_name": _display_name(db, g.grantee_id)}
                    if g.grantee_type == "user" and g.resource_id == resource_id else {}),
                 "actions": [a for a in (g.actions or "").split(",") if a],
                 "target_kind": g.target_kind} for g in rows]
    from origin.models.authority_ledger import AuthorityEdge
    me = _node_detail(db, resource_id)
    me["members"] = db.query(AuthorityEdge).filter(AuthorityEdge.src == resource_id).count()
    me["grantees"] = sum(1 for g in grantees if g["resource_id"] == resource_id)
    held = {"resource_id": resource_id, "resource_detail": me, "parents": parents,
            "parent_details": [_node_detail(db, n) for n in parents], "grantees": grantees}
    digest = hashlib.sha256(_json.dumps(held, sort_keys=True,
                                        separators=(",", ":")).encode()).hexdigest()
    return {**held, "preview": digest}


def _node_detail(db: Session, node_id: str) -> dict:
    """What Origin holds about a node that a person recognizes (review 16, L3), since it holds no
    item names: who brought it into being (their display name at Origin) and when."""
    import uuid as _uuid

    from origin.models.authority_ledger import AuthorityEntry, AuthorityNode
    from origin.models.person import Person

    node = db.get(AuthorityNode, node_id)
    creator, when = "", None
    if node is not None:
        try:
            who = db.get(Person, _uuid.UUID(str(node.created_by))) if node.created_by else None
        except (ValueError, TypeError):
            who = None
        creator = (getattr(who, "name", "") or "") if who is not None else ""
        entry = db.get(AuthorityEntry, node.seq) if node.seq else None
        if entry is not None and entry.created_time is not None:
            when = entry.created_time.isoformat()
    return {"id": node_id, "creator": creator or ("the platform" if node is not None
                                                   and not node.created_by else "someone"),
            "created_at": when}


def _confirmed_preview(db: Session, resource_id: str, body: dict) -> None:
    """The make names the preview the owner confirmed, and Origin still holds what it showed."""
    if body.get("preview") != _preview_of(db, resource_id)["preview"]:
        raise HTTPException(status_code=409, detail="confirm Origin's preview of this item first "
                            "(POST /auth/me/authority/preview); what Origin holds changed or was "
                            "not previewed")


@authority_session_router.post("/preview")
def preview(request: Request, body: dict = Body(...), db: Session = Depends(get_db)):
    """What Origin holds about a resource (its parent chain and grantees), for a person who may
    share it, shown before an invite or grant is made on it (review 15)."""
    person = _person(request, db)
    resource_id = body.get("resource_id")
    if not isinstance(resource_id, str) or not resource_id:
        raise HTTPException(status_code=400, detail="resource_id is required")
    if not _may_share(db, person, resource_id):
        raise HTTPException(status_code=403, detail="you hold neither Share nor Admin on this")
    return _preview_of(db, resource_id)


@authority_session_router.get("/grants")
def list_grants(request: Request, resource_id: str, db: Session = Depends(get_db)):
    """Origin's own record of the grants on a resource, for a person who may share it."""
    from origin.models.authority_ledger import AuthorityGrant

    person = _person(request, db)
    if not _may_share(db, person, resource_id):
        raise HTTPException(status_code=403, detail="you hold neither Share nor Admin on this")
    rows = db.query(AuthorityGrant).filter(AuthorityGrant.resource_id == resource_id)
    return {"resource_id": resource_id, "grants": [_listed(db, g) for g in rows]}


@authority_session_router.post("/grants")
def make_grant(request: Request, body: dict = Body(...), db: Session = Depends(get_db)):
    """A grant (or a deny) the person makes; Origin mints its id."""
    import uuid as _uuid

    person = _person(request, db)
    resource_id, grantee_id = body.get("resource_id"), body.get("grantee_id")
    if not isinstance(resource_id, str) or not isinstance(grantee_id, str):
        raise HTTPException(status_code=400, detail="resource_id and grantee_id are required")
    effect = body.get("effect") or "allow"
    if effect not in ("allow", "deny"):
        raise HTTPException(status_code=400, detail="effect is allow or deny")
    if _may_share(db, person, resource_id):
        # One who may not share is refused by the ledger's own rule, previewed or not.
        _confirmed_preview(db, resource_id, body)
    entry = {"kind": "grant", "grant_id": f"g-{_uuid.uuid4()}", "grantee_id": grantee_id,
             "grantee_type": "user", "resource_id": resource_id,
             "actions": _actions(body.get("actions")), "effect": effect, "state": "active",
             "expires_at": body.get("expires_at"), "target": None, "max_claims": None}
    return {**_append(db, person, entry), "grant_id": entry["grant_id"]}


@authority_session_router.post("/grants/{grant_id}/change")
def change_grant(grant_id: str, request: Request, body: dict = Body(...),
                 db: Session = Depends(get_db)):
    """A change to a grant Origin holds, built from Origin's own row."""
    person = _person(request, db)
    row = _held(db, grant_id)
    if row.grantee_type != "user":
        raise HTTPException(status_code=400, detail="an invite is revoked, not changed")
    changes = {"actions": _actions(body.get("actions")), "state": "active"}
    if "expires_at" in body:
        changes["expires_at"] = body.get("expires_at")
    return _append(db, person, _entry_from(row, **changes))


@authority_session_router.post("/grants/{grant_id}/revoke")
def revoke_grant(grant_id: str, request: Request, db: Session = Depends(get_db)):
    """A grant or invite Origin holds, revoked, built from Origin's own row."""
    person = _person(request, db)
    return _append(db, person, _entry_from(_held(db, grant_id), state="revoked"))


def _invite_by_token(db: Session, token):
    import hashlib

    from origin.models.authority_ledger import AuthorityGrant

    if not isinstance(token, str) or not token:
        raise HTTPException(status_code=400, detail="body.token is the invite's token")
    digest = hashlib.sha256(token.encode()).hexdigest()
    inv = (db.query(AuthorityGrant)
           .filter(AuthorityGrant.grantee_type == "invite", AuthorityGrant.grantee_id == digest)
           .first())
    if inv is None:
        raise HTTPException(status_code=404, detail="no invite for this token")
    return inv


def _for(db: Session, person: str, inv) -> bool:
    """Does the invite name this person (their verified address, or their id)?"""
    from origin.services import authority_ledger
    if not inv.target_kind:
        return False
    if inv.target_kind == "user_id":
        return authority_ledger.target_digest("user_id", person) == inv.target_digest
    ident = authority_ledger.reach(db).r.identity(person)
    email, verified = ident or ("", False)
    if not verified or "@" not in email:
        return False
    value = email if inv.target_kind == "email" else email.split("@", 1)[1]
    return authority_ledger.target_digest(inv.target_kind, value) == inv.target_digest


@authority_session_router.post("/invites")
async def make_invite(request: Request, body: dict = Body(...), db: Session = Depends(get_db)):
    """An invite Origin makes and mails (John, 2026-11-03): targeted at the address the owner
    gives, claimable once, its link in that mail alone."""
    import hashlib
    import secrets as _secrets
    import uuid as _uuid

    from origin import config
    from origin.db import persons as db_persons
    from origin.models.person import Person
    from origin.services import authority_ledger, email_service
    from origin.services.person_service import registration_paused

    from origin.services.email_address import canonical_email

    person = _person(request, db)
    # The mail names its sender by their verified address, so the invitee can tell who sent it: an
    # account whose address is not verified sends no invite.
    owner = db.get(Person, _uuid.UUID(person)) if _is_uuid(person) else None
    if owner is None or not owner.email_verified or "@" not in (owner.email or ""):
        raise HTTPException(status_code=403, detail="verify your email address first: an invite "
                            "names its sender by their verified address")
    resource_id, email = body.get("resource_id"), str(body.get("email") or "").strip()
    if not isinstance(resource_id, str) or not resource_id:
        raise HTTPException(status_code=400, detail="resource_id is required")
    # The target is the canonical form: a claimant's stored address is canonical, so an invite to
    # `x@d.com.` or `x@BÜCHER.de` would otherwise name a digest no account could ever match.
    try:
        email = canonical_email(email)
    except ValueError:
        raise HTTPException(status_code=400, detail="email is the invitee's address")
    if len(email) > 254:
        raise HTTPException(status_code=400, detail="email is the invitee's address")
    actions = _actions(body.get("actions"))
    # The name the owner typed or confirmed for what they share (review 14): echoed in the answer
    # and named in the mail, so the owner sees what Origin will invite to, not what Mantle said.
    name = " ".join(str(body.get("resource_name") or "").split())[:120] or "a shared item"
    if not _may_share(db, person, resource_id):
        raise HTTPException(status_code=403, detail="you hold neither Share nor Admin on this")
    _confirmed_preview(db, resource_id, body)
    if registration_paused() and db_persons.get_by_email(db, email) is None:
        raise HTTPException(status_code=409, detail="new accounts are paused, and this address "
                            "has none: the invite could not be claimed")
    if not email_service.is_configured():
        raise HTTPException(status_code=503, detail="Origin has no mail configured to send it")
    token = _secrets.token_urlsafe(32)
    entry = {"kind": "grant", "grant_id": f"inv-{_uuid.uuid4()}",
             "grantee_id": hashlib.sha256(token.encode()).hexdigest(), "grantee_type": "invite",
             "resource_id": resource_id, "actions": actions, "effect": "allow",
             "state": "active", "expires_at": body.get("expires_at"),
             "target": {"kind": "email",
                        "digest": authority_ledger.target_digest("email", email)},
             "max_claims": 1}
    _append(db, person, entry)
    link = f"{(config.APP_URI or config.ORIGIN_URI).rstrip('/')}/invite/{token}"
    sent = await email_service.send_invite(email, owner.name or "Someone", name, link,
                                           from_email=owner.email)
    if not sent:
        # Never left live unmailed: the owner sees the failure and the invite is withdrawn.
        _append(db, person, {**entry, "state": "revoked"})
        raise HTTPException(status_code=502, detail="the invite could not be mailed")
    return {"invite_id": entry["grant_id"], "resource_id": resource_id, "resource_name": name,
            "actions": actions, "expires_at": entry["expires_at"], "email": email}


def _is_uuid(value: str) -> bool:
    import uuid as _uuid
    try:
        _uuid.UUID(str(value))
        return True
    except ValueError:
        return False


@authority_session_router.post("/invite-context")
def invite_context(request: Request, body: dict = Body(...), db: Session = Depends(get_db)):
    """What an invite is, for the person opening its link: shown only in a session, and carrying
    nothing that claims it."""
    person = _person(request, db)
    inv = _invite_by_token(db, body.get("token"))
    v = _grant_view(inv)
    return {"invite_id": v["grant_id"], "resource_id": v["resource_id"],
            "actions": v["actions"], "expires_at": v["expires_at"], "state": v["state"],
            "for_you": _for(db, person, inv), "address_verified": _verified(db, person)}


def _verified(db: Session, person: str) -> bool:
    """Is the signed-in person's own address verified? An invite is matched to a verified address
    alone, so the claim page asks for verification first when it is not."""
    from origin.services import authority_ledger
    ident = authority_ledger.reach(db).r.identity(person)
    return bool(ident and ident[1])


def _for_me(db: Session, person: str, inv) -> bool:
    """Can the person accept this invite in the app (FR-004)? It names their id or their verified
    address exactly. A domain invite still needs its mailed token."""
    return inv.target_kind in ("user_id", "email") and _for(db, person, inv)


def _live_invite(db: Session, invite_id: str):
    from origin.services.authority_ledger import unexpired
    inv = _held(db, invite_id)
    if (inv.grantee_type != "invite" or inv.state != "active" or inv.effect != "allow"
            or not unexpired(inv.expires_at)):
        raise HTTPException(status_code=404, detail="no live invite with this id")
    return inv


def _inviter(db: Session, person_id: str) -> str:
    """Who sent an invite, for its recipient: their display name, else their verified address, as
    the invite mail names them (an invite is sent only from a verified address); "" if neither."""
    from origin.services import authority_ledger
    name = _display_name(db, person_id)
    if name:
        return name
    email, verified = authority_ledger.reach(db).r.identity(str(person_id)) or ("", False)
    return email if verified and "@" in email else ""


@authority_session_router.get("/invites/incoming")
def incoming_invites(request: Request, db: Session = Depends(get_db)):
    """The live invites that name the signed-in person (their id, or their verified address), so
    the app shows them in their Inbox with Accept and Decline, and no email is needed (FR-004).
    Each says who sent it and with which actions. Origin keeps no name for what is shared (the
    name is only in the mail), so none is given here."""
    from origin.models.authority_ledger import AuthorityGrant
    from origin.services import authority_ledger
    from origin.services.authority_ledger import target_digest, unexpired
    person = _person(request, db)
    targets = [("user_id", target_digest("user_id", person))]
    email, verified = authority_ledger.reach(db).r.identity(person) or ("", False)
    if verified and "@" in email:
        targets.append(("email", target_digest("email", email)))
    out = []
    for kind, digest in targets:
        rows = (db.query(AuthorityGrant)
                .filter(AuthorityGrant.grantee_type == "invite", AuthorityGrant.state == "active",
                        AuthorityGrant.effect == "allow", AuthorityGrant.target_kind == kind,
                        AuthorityGrant.target_digest == digest).all())
        for inv in rows:
            if not unexpired(inv.expires_at):
                continue
            if inv.max_claims is not None and (db.query(AuthorityGrant).filter(
                    AuthorityGrant.claimed_from == inv.grant_id).count() >= inv.max_claims):
                continue
            v = _grant_view(inv)
            out.append({"invite_id": inv.grant_id, "resource_id": inv.resource_id,
                        "actions": v["actions"], "expires_at": v["expires_at"],
                        "from": _inviter(db, inv.created_by)})
    return {"invites": out}


@authority_session_router.post("/invites/{invite_id}/accept")
def accept_invite(invite_id: str, request: Request, db: Session = Depends(get_db)):
    """The invite's target accepts it in the app (FR-004). It is the same claim as `/claim` (their
    own grant, no more than the invite carries, keeping its expiry), proven by their Origin
    session and the invite naming them rather than by the mailed token. It takes the same ledger
    path, so Mantle's feed applies it like any claim."""
    import uuid as _uuid

    from origin.services import authority_ledger
    person = _person(request, db)
    inv = _live_invite(db, invite_id)
    if not _for_me(db, person, inv):
        raise HTTPException(status_code=403, detail="this invite does not name you; an invite to "
                            "a domain is accepted from the link in its email")
    entry = {"kind": "grant", "grant_id": f"claim-{_uuid.uuid4()}", "grantee_id": str(person),
             "grantee_type": "user", "resource_id": inv.resource_id,
             "actions": [a for a in (inv.actions or "").split(",") if a], "effect": "allow",
             "state": "active", "expires_at": inv.expires_at, "target": None, "max_claims": None}
    receipt = _append(db, str(person), entry,
                      {"invite_id": inv.grant_id, "session": authority_ledger.SESSION_TARGETED})
    return {**receipt, "resource_id": inv.resource_id, "grant_id": entry["grant_id"]}


@authority_session_router.post("/invites/{invite_id}/decline")
def decline_invite(invite_id: str, request: Request, db: Session = Depends(get_db)):
    """The invite's target declines it (FR-004). The invite is retired, so no one can claim it, and
    its sender's sharing dialog shows it as declined."""
    person = _person(request, db)
    inv = _live_invite(db, invite_id)
    if not _for_me(db, person, inv):
        raise HTTPException(status_code=403, detail="this invite does not name you")
    return _append(db, str(person), _entry_from(inv, state="retired"))


@authority_session_router.post("/claim")
def session_claim(request: Request, body: dict = Body(...), db: Session = Depends(get_db)):
    """An invite claimed in the claimant's own Origin session from its token alone, as the web
    app's claim page holds it: Origin finds the live invite by the token's digest and makes the
    claim (the claimant's own grant, no more than the invite carries, keeping its expiry) by the
    ledger's claim rule. A token Origin does not know claims nothing (404)."""
    import uuid as _uuid

    from origin.services import authority_ledger

    person = _person(request, db)
    token = body.get("token")
    inv = _invite_by_token(db, token)
    if inv.state != "active" or inv.effect != "allow":
        raise HTTPException(status_code=404, detail="no live invite for this token")
    if not inv.target_kind:
        # An invite that names no one proves nothing about who holds its token (it may have
        # passed through Mantle): the session claims none (review 13, H1).
        raise HTTPException(status_code=403, detail="this invite names no one, so it is not "
                            "claimed here; ask its owner for an invite to your address")
    entry = {"kind": "grant", "grant_id": f"claim-{_uuid.uuid4()}", "grantee_id": str(person),
             "grantee_type": "user", "resource_id": inv.resource_id,
             "actions": [a for a in (inv.actions or "").split(",") if a], "effect": "allow",
             "state": "active", "expires_at": inv.expires_at, "target": None, "max_claims": None}
    try:
        receipt = authority_ledger.session_entry(db, str(person), entry,
                                                 {"invite_id": inv.grant_id, "token": token})
        return {**receipt, "resource_id": inv.resource_id, "grant_id": entry["grant_id"]}
    except authority_ledger.EntryRefused as exc:
        logger.warning("invite claim refused for %s: %s", person, exc)
        raise HTTPException(status_code=exc.status, detail=str(exc))


class SessionCORS(BaseHTTPMiddleware):
    """Answers the web app's preflight for the session route with credentials, and adds the
    credentialed CORS headers to its answers; any other origin gets no CORS headers here."""

    async def dispatch(self, request, call_next):
        if not request.url.path.startswith(PREFIX + "/"):
            return await call_next(request)
        origin = _origin_of(request.headers.get("origin", ""))
        allowed = origin is not None and origin in trusted_origins()
        if request.method == "OPTIONS" and request.headers.get("access-control-request-method"):
            if not allowed:
                return Response(status_code=403)
            return Response(status_code=204, headers=self._headers(origin, preflight=True))
        response = await call_next(request)
        if allowed:
            for k, v in self._headers(origin, preflight=False).items():
                response.headers[k] = v
        return response

    @staticmethod
    def _headers(origin: str, *, preflight: bool) -> dict:
        h = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true",
             "Vary": "Origin"}
        if preflight:
            h.update({"Access-Control-Allow-Methods": "GET, POST",
                      "Access-Control-Allow-Headers": f"content-type, {HEADER.lower()}",
                      "Access-Control-Max-Age": "600"})
        return h

"""The authority ledger: Origin co-signs each change to reach, after checking it itself.

Mantle owns and serves grants. A change that affects who reaches what counts at Origin (for key
release) only once Origin has

  1. verified the acting person's own credential (`share_credentials.verify_share_credential`);
  2. checked, against its own replica, that this person may make the change (the rules below,
     Mantle's own, ported in `authority_reach`); and
  3. appended the entry, hash-chained to the one before, and co-signed it with Origin's key.

The replica (`authority_nodes`, `authority_grants`, `authority_edges`, `authority_roots`) is
written only here, by applying an appended entry, so it holds only co-signed entries.

The entry kinds and their bodies (structure only; any other field is refused):

    grant        {grant_id, grantee_id, grantee_type, resource_id, actions[], effect, state,
                  expires_at, target, max_claims}   the state after a change; `target` is an
                                                    invite's {kind, digest} or null
    edge.add     {src, dst, origin, propagate}      a containment edge; propagate null = all
    edge.remove  {src, dst}
    root         {principal_id, root_id}            a key principal and its origin root

Ids Origin has seen. Every id the replica knows is a node, recorded with who brought it into
being. An id Origin has not seen comes into being only by its own creation: a `root` entry (a new
key principal) or a creation edge (`edge.add` with `origin`), submitted by its creator. A person's
id comes into being only by that person's own `root`, and a creation edge never names one. A grant
naming an unseen resource, and an edge naming an unseen collection or (for secondary containment)
an unseen member, is refused.

Who may make each change (the actor is the credential's subject):

  * grant, created or widened: admin held directly on the resource for a direct grant or any
    change to one, share or admin for an invite (`grants_router`, `grant_service.can_share` /
    `can_admin`), and no wider than the actor holds there (`clamp_grant_to_issuer`, allow grants
    only). Or the creator's base case: the actor brought the resource into being and every grant
    on it is the actor's. Or an invite claim, below.
  * grant, narrowed: the grantee may give up their own grant; a grant on a resource being deleted
    is retired (`deleted`) by anyone who may delete the resource, its issuer or an admin; an
    invite is closed by its issuer or an admin, or by anyone once Origin's own count shows it
    spent (its claimant's write, which records what Origin already enforces).
  * An invite's target and claim limit never change after it is made.
  * An invite claim: a user grant for the actor, whose submission carries the claim token as
    proof. Origin checks `sha256(token)` against the invite's grantee (the token hash), the
    invite's target against the actor's own identity (their id, or their verified email or its
    domain), its live state and expiry, and its claim limit counted in the replica; the grant
    takes no more than the invite's actions and keeps its expiry. The token is not stored.
  * edge.add: create or add reaching the collection (`check_access` walks up the origin chain).
    An existing edge is narrowed on the same right; widening one (more actions conducted) needs
    admin held on the collection. A member has one creation edge, ever: a move is secondary
    containment.
  * edge.remove: a secondary edge by evict (or admin) on the collection, or delete reaching the
    member; a creation edge, which deletes the member at Origin, only by delete reaching the
    member or admin on the collection (review 15).
  * root: the principal's own creator, or the person themselves; Origin's walk must give the
    same root.
  * A background delegation makes no change of its own (review 16): no grant, edge or root,
    no narrowing or retirement. It restates what Origin holds, or re-submits Mantle's withdrawal
    of a secondary edge within the collections its job grant lists.
  * A compensating entry (`compensates=N`) withdraws entry N, made by the same actor, while it is
    still the latest change to that row: an added edge is removed, a put grant retired. Mantle
    sends one when the write the entry was for did not commit.

A bootstrap entry (`bootstrap=True`) is accepted only on the operator's dedicated bootstrap
credential (`verify_bootstrap_credential`), skips the authority rules, and records no creator, so
the base case never opens on what it co-signs.

An entry that would not change the replica is answered `unchanged`, with the co-signature of the
entry that last set that state, and nothing is appended: resubmitting is safe.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from origin.models.authority_ledger import (
    AuthorityBatch,
    AuthorityBootstrapWindow, AuthorityEdge, AuthorityEntry, AuthorityGrant, AuthorityNode,
    AuthorityRoot, AuthoritySigningKey,
)
from origin.services.authority_reach import ACTIONS, Grant, Mask, MemoryReplica, Reach, unexpired

logger = logging.getLogger(__name__)

from prism.trust.ledger import GENESIS  # noqa: E402  (one name both repos read, review 17)

#: How long after an entry its actor may withdraw it as a write that did not commit.
COMPENSATION_WINDOW_SECONDS = 60
#: How fresh a new key principal's recorded creation must be.
ROOT_FRESHNESS_MINUTES = 10
from prism.trust.ledger import LEDGER_VERSION  # noqa: E402
_MAX_ID = 128

#: The scope of the operator's bootstrap credential, and its longest life.
BOOTSTRAP_SCOPE = "authority.bootstrap"
MAX_BOOTSTRAP_MINUTES = 60

#: States that mean a grant confers nothing.
_ACTIVE = "active"


class EntryRefused(Exception):
    """The entry is not appended. `status` is the HTTP answer: 400 malformed, 403 not permitted,
    409 conflicts with the replica."""

    def __init__(self, message: str, status: int = 403) -> None:
        super().__init__(message)
        self.status = status


# -- the body ------------------------------------------------------------------------------------

_FIELDS = {
    "grant": {"grant_id", "grantee_id", "grantee_type", "resource_id", "actions", "effect",
              "state", "expires_at", "target", "max_claims"},
    "edge.add": {"src", "dst", "origin", "propagate"},
    "edge.remove": {"src", "dst"},
    "root": {"principal_id", "root_id"},
    # Retired (John, 2026-11-03: "It's not a drop key. It's a grant with Add rights and nothing
    # else."): no new one is taken; one already in the chain still verifies, and applies nothing.
    "drop_key": {"collection_id", "public"},
    # The operator's: a root or node someone planted, cleared so its id can be created again.
    "root.retire": {"principal_id"},
    # A named background job's own narrow authority (John, 2026-11-02): see `_decide_job_grant`.
    "job_grant": {"grant_id", "job", "principal", "collections", "expires_at", "state"},
    # Retired (John, 2026-11-08: rotate a charged root's key, do not confirm it): no new one is
    # taken; one already in the chain still verifies and replays, and opens nothing.
    "root.confirm_empty": {"principal_id"},
}
KINDS = frozenset(_FIELDS)
TARGET_KINDS = frozenset({"user_id", "email", "domain"})


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _id(body: dict, key: str) -> str:
    v = body.get(key)
    if not isinstance(v, str) or not v or len(v) > _MAX_ID:
        raise EntryRefused(f"{key} must be a non-empty string of at most {_MAX_ID}", 400)
    return v


def _actions(value: Any, key: str) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(a, str) for a in value):
        raise EntryRefused(f"{key} must be a list of action names", 400)
    unknown = sorted(set(value) - set(ACTIONS))
    if unknown:
        raise EntryRefused(f"{key} names actions outside CRUDEASIO: {unknown}", 400)
    return [a for a in ACTIONS if a in set(value)]          # CRUDEASIO order, no repeats


def _canonical_time(value: str) -> str:
    """An expiry in its one stored form (review 18): UTC, ISO-8601."""
    return parse_time(value).astimezone(timezone.utc).isoformat()


def normalise(body: Any, *, canonical_times: bool = True) -> dict:
    """The entry body in its one canonical shape, or `EntryRefused` (400). Each expiry is stored
    as UTC ISO-8601 (review 18), so Origin and Mantle read one value one way. With
    `canonical_times=False` an expiry is kept as given (still checked): the shape a submission's
    body digest is taken over, and the one an entry stored before review 18 was stored in."""
    if not isinstance(body, dict):
        raise EntryRefused("an entry is an object", 400)
    kind = body.get("kind")
    if kind not in _FIELDS:
        raise EntryRefused(f"unknown entry kind {kind!r}", 400)
    extra = sorted(set(body) - _FIELDS[kind] - {"kind"})
    missing = sorted(_FIELDS[kind] - set(body))
    if extra or missing:
        raise EntryRefused(f"a {kind} entry has exactly {sorted(_FIELDS[kind])}; extra {extra}, "
                           f"missing {missing}", 400)
    out: Dict[str, Any] = {"kind": kind}
    if kind == "grant":
        for k in ("grant_id", "grantee_id", "grantee_type", "resource_id"):
            out[k] = _id(body, k)
        out["actions"] = _actions(body["actions"], "actions")
        effect = str(body["effect"] or "").strip().lower()
        if effect not in ("allow", "deny"):
            raise EntryRefused("effect is allow or deny", 400)
        out["effect"] = effect
        state = body["state"]
        if not isinstance(state, str) or not state or len(state) > 32:
            raise EntryRefused("state must be a short string", 400)
        out["state"] = state
        exp = body["expires_at"]
        if exp is not None and (not isinstance(exp, str) or len(exp) > 64):
            raise EntryRefused("expires_at is an ISO time or null", 400)
        if exp:
            try:
                parse_time(exp)
            except ValueError:
                raise EntryRefused("expires_at is not an ISO-8601 time", 400) from None
        out["expires_at"] = (_canonical_time(exp) if canonical_times else exp) if exp else None
        target = body["target"]
        if target is not None:
            if (not isinstance(target, dict) or set(target) != {"kind", "digest"}
                    or target["kind"] not in TARGET_KINDS
                    or not isinstance(target["digest"], str) or len(target["digest"]) != 64):
                raise EntryRefused("target is {kind: user_id|email|domain, digest} or null", 400)
            if out["grantee_type"] != "invite":
                raise EntryRefused("only an invite has a target", 400)
            target = {"kind": target["kind"], "digest": target["digest"]}
        out["target"] = target
        mc = body["max_claims"]
        if mc is not None and (not isinstance(mc, int) or isinstance(mc, bool) or mc < 0):
            raise EntryRefused("max_claims is a non-negative integer or null", 400)
        if mc is not None and out["grantee_type"] != "invite":
            raise EntryRefused("only an invite has a claim limit", 400)
        out["max_claims"] = mc
    elif kind in ("edge.add", "edge.remove"):
        out["src"], out["dst"] = _id(body, "src"), _id(body, "dst")
        if out["src"] == out["dst"]:
            raise EntryRefused("an edge joins two different nodes", 400)
        if kind == "edge.add":
            if not isinstance(body["origin"], bool):
                raise EntryRefused("origin is a boolean", 400)
            out["origin"] = body["origin"]
            prop = body["propagate"]
            out["propagate"] = None if prop is None else _actions(prop, "propagate")
    elif kind == "drop_key":
        out["collection_id"] = _id(body, "collection_id")
        pub = body["public"]
        try:
            raw = base64.b64decode(pub, validate=True) if isinstance(pub, str) else b""
        except (ValueError, TypeError):
            raw = b""
        if len(raw) != 32:
            raise EntryRefused("public is a base64 X25519 public key", 400)
        out["public"] = base64.b64encode(raw).decode("ascii")
    elif kind in ("root.retire", "root.confirm_empty"):
        out["principal_id"] = _id(body, "principal_id")
    elif kind == "job_grant":
        out["grant_id"], out["principal"] = _id(body, "grant_id"), _id(body, "principal")
        job = body["job"]
        if not isinstance(job, str) or not _JOB_NAME.fullmatch(job):
            raise EntryRefused("job is a dotted name of letters, digits, '-' and '_'", 400)
        out["job"] = job
        cols = body["collections"]
        if not isinstance(cols, list) or not all(isinstance(c, str) and c and len(c) <= _MAX_ID
                                                 for c in cols) or len(cols) > 64:
            raise EntryRefused("collections is a list of at most 64 ids", 400)
        out["collections"] = sorted(set(cols))
        exp = body["expires_at"]
        try:
            parse_time(exp) if isinstance(exp, str) else (_ for _ in ()).throw(ValueError())
        except ValueError:
            raise EntryRefused("expires_at is an ISO-8601 time", 400) from None
        out["expires_at"] = _canonical_time(exp) if canonical_times else exp
        if body["state"] not in (_ACTIVE, "revoked"):
            raise EntryRefused("a job grant's state is active or revoked", 400)
        out["state"] = body["state"]
    else:
        out["principal_id"], out["root_id"] = _id(body, "principal_id"), _id(body, "root_id")
    return out


#: A job's name: `platform.reindex`, `ledger.retry`.
_JOB_NAME = re.compile(r"[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+){0,7}")
#: How long a job grant may run before it is granted again.
JOB_GRANT_MAX_DAYS = 30


def body_digest(body: dict) -> str:
    """SHA-256 of the canonical body: what Mantle's service token for a submission names."""
    return hashlib.sha256(canonical(normalise(body, canonical_times=False)).encode("utf-8")
                          ).hexdigest()


def proof_digest(proof: Optional[dict]) -> Optional[str]:
    if not proof:
        return None
    return hashlib.sha256(canonical(proof).encode("utf-8")).hexdigest()


from prism.trust.ledger import target_digest  # noqa: E402,F401  (shared, review 17)


# -- the replica over Origin's tables -----------------------------------------------------------

def _grant_of(row: AuthorityGrant) -> Grant:
    return Grant(id=row.grant_id, grantee_id=row.grantee_id, grantee_type=row.grantee_type,
                 resource_id=row.resource_id,
                 actions=frozenset(a for a in (row.actions or "").split(",") if a),
                 effect=row.effect, state=row.state, expires_at=row.expires_at,
                 created_by=row.created_by or "", target_kind=row.target_kind,
                 target_digest=row.target_digest, max_claims=row.max_claims,
                 claimed_from=row.claimed_from)


def _prop_load(text: Optional[str]):
    return None if text is None else json.loads(text)


class SqlReplica:
    def __init__(self, db: Session) -> None:
        self.db = db

    def grants_held_by(self, grantee_id):
        return [_grant_of(r) for r in
                self.db.query(AuthorityGrant).filter(AuthorityGrant.grantee_id == grantee_id)]

    def grants_on(self, resource_id):
        return [_grant_of(r) for r in
                self.db.query(AuthorityGrant).filter(AuthorityGrant.resource_id == resource_id)]

    def grant(self, grant_id):
        row = self.db.get(AuthorityGrant, grant_id)
        return _grant_of(row) if row else None

    def origin_parents(self, node_id):
        rows = (self.db.query(AuthorityEdge)
                .filter(AuthorityEdge.dst == node_id, AuthorityEdge.origin.is_(True))
                .order_by(AuthorityEdge.src).all())
        return [(r.src, _prop_load(r.propagate)) for r in rows]

    def origin_children(self, node_id):
        rows = (self.db.query(AuthorityEdge.dst)
                .filter(AuthorityEdge.src == node_id, AuthorityEdge.origin.is_(True))
                .order_by(AuthorityEdge.dst).all())
        return [r[0] for r in rows]

    def origin_added_by(self, node_id):
        row = (self.db.query(AuthorityEdge)
               .filter(AuthorityEdge.dst == node_id, AuthorityEdge.origin.is_(True))
               .order_by(AuthorityEdge.src).first())
        return row.added_by if row is not None else None

    def edge(self, src, dst):
        row = self.db.get(AuthorityEdge, (src, dst))
        if row is None:
            return None
        return {"origin": bool(row.origin), "propagate": _prop_load(row.propagate)}

    def has_edges(self, node_id):
        q = self.db.query(AuthorityEdge)
        return (q.filter(AuthorityEdge.src == node_id).first() is not None
                or q.filter(AuthorityEdge.dst == node_id).first() is not None)

    def has_members(self, node_id):
        return self.db.query(AuthorityEdge).filter(AuthorityEdge.src == node_id).first() \
            is not None

    def root_entry(self, principal_id):
        row = self.db.get(AuthorityRoot, principal_id)
        if row is None:
            return None
        return {"root_id": row.root_id, "registered_by": row.registered_by}

    def node(self, node_id):
        row = self.db.get(AuthorityNode, node_id)
        if row is None:
            return None
        return _node_view(row.created_by, row.member, row.part_removed_seq,
                          row.confirmed_empty_seq)

    def _person(self, node_id):
        from origin.models.person import Person
        try:
            pid = uuid.UUID(str(node_id))
        except (ValueError, TypeError):
            return None
        return self.db.get(Person, pid)

    def is_person(self, node_id):
        return self._person(node_id) is not None

    def identity(self, subject):
        p = self._person(subject)
        if p is None:
            return None
        return (str(p.email or ""), bool(getattr(p, "email_verified", False)))

    def job_grant(self, grant_id):
        from origin.models.authority_ledger import AuthorityJobGrant
        row = self.db.get(AuthorityJobGrant, grant_id)
        return None if row is None else job_grant_view(row)

    def claims_of(self, invite_id):
        return (self.db.query(AuthorityGrant)
                .filter(AuthorityGrant.claimed_from == invite_id).count())


def _node_view(created_by, member, part_removed_seq=None, confirmed_empty_seq=None) -> dict:
    """A node as both replicas give it. A root is charged once a node under it has gone (review
    29), for good (review 30, F4): the confirmation an older Origin recorded is carried, and
    opens nothing."""
    out = {"created_by": created_by, "member": bool(member)}
    if part_removed_seq is not None:
        out["part_removed_seq"] = int(part_removed_seq)
        out["part_removed"] = True
    if confirmed_empty_seq is not None:
        out["confirmed_empty_seq"] = int(confirmed_empty_seq)
    return out


def reach(db: Session) -> Reach:
    rc = Reach(SqlReplica(db))
    rc.head = head(db)[0]                  # what a memoized answer is keyed by (review 29, L2)
    return rc


# -- the rules ------------------------------------------------------------------------------------

@dataclass
class Context:
    """Who is asking and how: the actor (credential subject), the credential kind, and what the
    submission carries besides the body."""

    actor: str
    kind: str = "access"
    ref: str = ""
    bootstrap: bool = False
    proof: Optional[dict] = None
    compensates: Optional[int] = None
    #: The submission batch (one Mantle operation), and the database, for the creation rule.
    batch: Optional[str] = None
    db: Optional[object] = field(default=None, repr=False)
    #: Filled by the claim rule: the invite this grant spends.
    claimed_from: Optional[str] = field(default=None)
    #: Filled by the compensation rule: the withdrawn entry's row as it was before (`prior_state`).
    restored: Optional[dict] = field(default=None)
    #: The operator settling an unconfirmed entry (`resolve_unconfirmed`), which may lift a deny.
    settle: bool = False
    #: The operator retiring a planted root (`retire_root`): its own denies go with it.
    retiring: Optional[str] = None
    #: A narrowed delegation's scopes (kind `narrowed`): what Ember may do for its person.
    scopes: tuple = ()
    #: A background delegation's collections, as its job grant lists them (review 16).
    collections: tuple = ()


def _grant_from_body(b: dict, created_by: str = "") -> Grant:
    t = b.get("target") or {}
    return Grant(id=b["grant_id"], grantee_id=b["grantee_id"], grantee_type=b["grantee_type"],
                 resource_id=b["resource_id"], actions=frozenset(b["actions"]),
                 effect=b["effect"], state=b["state"], expires_at=b["expires_at"],
                 created_by=created_by, target_kind=t.get("kind"),
                 target_digest=t.get("digest"), max_claims=b.get("max_claims"))


def _structure(g: Grant) -> tuple:
    return (g.grantee_id, g.grantee_type, g.resource_id, g.actions, g.effect, g.state,
            g.expires_at, g.target_kind, g.target_digest, g.max_claims)


def _confers(g: Optional[Grant]) -> frozenset:
    """What a grant authorizes: its actions if it is a live allow, else nothing."""
    if g is None or g.state != _ACTIVE or g.effect != "allow":
        return frozenset()
    return g.actions


def parse_time(value: Optional[str]) -> Optional[datetime]:
    """An ISO-8601 time as an aware datetime (a naive one is UTC), or None; `ValueError` for one
    that does not parse. Every expiry is compared as a time, never as text."""
    if value is None:
        return None
    t = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _later(a: Optional[str], b: Optional[str]) -> bool:
    """Is expiry `a` later than `b` (None is never)?"""
    if a == b:
        return False
    if a is None:
        return True
    if b is None:
        return False
    return parse_time(a) > parse_time(b)


def _widens(prior: Optional[Grant], new: Grant) -> bool:
    """Does `new` authorize anything `prior` did not, or for longer? A deny or a non-live grant
    authorizes nothing; dropping a deny widens."""
    if prior is not None and prior.effect == "deny" and prior.state == _ACTIVE and (
            new.effect != "deny" or new.state != _ACTIVE or not prior.actions <= new.actions):
        return True
    if prior is not None and prior.effect == "deny" and prior.state == _ACTIVE and (
            _later(prior.expires_at, new.expires_at)):
        return True                          # a deny that ends sooner lifts it sooner
    added = _confers(new) - _confers(prior)
    if added:
        return True
    return bool(_confers(new)) and prior is not None and _later(new.expires_at, prior.expires_at)


def _seen(rc: Reach, node: str) -> bool:
    return rc.r.node(node) is not None


def _created_in_batch(ctx: "Context", node: str) -> Optional[str]:
    """How `node` came into being in this submission batch, by this actor: "root" or "edge"
    (its creation edge), or None. `created_by` grants nothing (architecture §51); a creator's
    rights are the creation grant co-signed in the same batch as the creation."""
    if not ctx.batch or ctx.db is None:
        return None
    made = ctx.db.get(AuthorityNode, node)
    if made is None:
        return None
    # The entry that brought the node into being, and nothing that merely restates it.
    row = ctx.db.get(AuthorityEntry, made.seq)
    if (row is None or row.batch != ctx.batch or row.actor != ctx.actor or row.bootstrap
            or row.compensates is not None):
        return None
    b = json.loads(row.body)
    if row.kind == "root" and b.get("principal_id") == node:
        return "root"
    if row.kind == "edge.add" and b.get("dst") == node and b.get("origin"):
        return "edge"
    return None


def _same_mask(a, b) -> bool:
    from origin.services.authority_reach import Mask

    return Mask.from_propagate(a).actions == Mask.from_propagate(b).actions


def _creation_grant(rc: Reach, ctx: "Context", new: Grant) -> Optional[str]:
    """The creator's own grant on what they created in this batch: on a self-rooted id (its
    root), any actions; on a member (its creation edge, already checked for create or add on the
    collection), no more than the creator's own walk reaches on it."""
    if new.grantee_id != ctx.actor or new.grantee_type != "user" or new.effect != "allow":
        return None
    # The creation grant is the first live grant, and only that. A grant left revoked on an id
    # the operator retired (`retire_root`) belongs to its earlier life.
    if any(g.id != new.id and g.state == _ACTIVE for g in rc.r.grants_on(new.resource_id)):
        return None
    how = _created_in_batch(ctx, new.resource_id)
    if how == "root":
        return "the creation grant on a root created in this batch"
    if how == "edge" and new.actions <= _reached_actions(rc, ctx.actor, new.resource_id):
        return "the creation grant on a member created in this batch, within its reach"
    return None


def _reached_actions(rc: Reach, actor: str, node: str) -> frozenset:
    """Every action `actor`'s own grants reach on `node`, on it or up its origin chain (the
    light-cone walk; an invite is no one's grant until claimed)."""
    return frozenset(a for a in ACTIONS if rc.reaches(actor, node, a))


def _claim(rc: Reach, ctx: Context, new: Grant) -> Optional[str]:
    """The invite-claim rule, or None when this is not a claim it accepts."""
    proof = ctx.proof or {}
    invite_id, token = proof.get("invite_id"), proof.get("token")
    if not isinstance(invite_id, str) or not isinstance(token, str) or not token:
        return None
    inv = rc.r.grant(invite_id)
    if (inv is None or inv.grantee_type != "invite" or inv.resource_id != new.resource_id
            or inv.state != _ACTIVE or inv.effect != "allow" or not unexpired(inv.expires_at)):
        raise EntryRefused("the invite is not a live invite on this resource")
    if hashlib.sha256(token.encode()).hexdigest() != inv.grantee_id:
        raise EntryRefused("the claim token does not match the invite")
    if inv.target_kind:
        ident = rc.r.identity(ctx.actor)
        if inv.target_kind == "user_id":
            ok = target_digest("user_id", ctx.actor) == inv.target_digest
        else:
            email, verified = ident or ("", False)
            if not verified or "@" not in email:
                raise EntryRefused("an email or domain invite needs the claimant's verified "
                                   "address")
            value = email if inv.target_kind == "email" else email.split("@", 1)[1]
            ok = target_digest(inv.target_kind, value) == inv.target_digest
        if not ok:
            raise EntryRefused("the claimant is not the invite's target")
    if inv.max_claims is not None and rc.r.claims_of(inv.id) >= inv.max_claims:
        raise EntryRefused("the invite has reached its claim limit")
    if not new.actions <= inv.actions or new.expires_at != inv.expires_at:
        raise EntryRefused("a claim takes no more than the invite's actions and keeps its expiry")
    ctx.claimed_from = inv.id
    return "an invite claim, proven"


def _was_creation_edge(db: Session, src: str, dst: str, before_seq: int) -> bool:
    """Was the edge (`src`, `dst`) that entry `before_seq` removed the member's own creation
    edge: the last co-signed `edge.add` for that very pair before it carried `origin`?"""
    for row in (db.query(AuthorityEntry)
                .filter(AuthorityEntry.seq < before_seq,
                        AuthorityEntry.kind.in_(("edge.add", "edge.remove")))
                .order_by(AuthorityEntry.seq.desc())):
        body = json.loads(row.body)
        if (body.get("src"), body.get("dst")) != (src, dst):
            continue
        return row.kind == "edge.add" and bool(body.get("origin"))
    return False


def _retires_unchanged(prior: Optional[Grant], new: Grant) -> bool:
    """A grant taken from active to retired or deleted, and nothing else about it changed."""
    return (prior is not None and new.state != _ACTIVE and prior.state == _ACTIVE
            and _structure(prior)[:5] == _structure(new)[:5])


#: Credentials Mantle holds or could hold: a person's access token and a delegation made for
#: them (review 12). On these Origin takes no change to authority.
MANTLE_HELD = ("access", "delegation")
#: The actor kind of an entry the person makes in their own Origin session
#: (`POST /auth/me/authority/entries`), called by the web app directly (review 12).
ORIGIN_SESSION = "origin_session"
SESSION_ONLY = ("is made in the person's Origin session (POST /auth/me/authority/entries), never "
                "on a token Mantle holds")


def _session_only(what: str) -> "EntryRefused":
    return EntryRefused(f"{what} {SESSION_ONLY}")


def _held_grant_allowed(rc: Reach, ctx: Context, prior: Optional[Grant], new: Grant) -> bool:
    """What a token Mantle holds may still do to a grant: the creator's own creation grant on
    what they created in this batch, and an allow grant retired on a resource already deleted at
    Origin (review 15), which is bookkeeping: the resource opens nothing for anyone. Neither gives
    anyone anything. A deny is never lifted on a token Mantle holds."""
    if prior is None and new.grantee_id == ctx.actor and _creation_grant(rc, ctx, new):
        return True
    return (_retires_unchanged(prior, new) and prior.effect != "deny"
            and rc.gone(new.resource_id))


#: Names the authority manifest anchors as the platform's own services, never as a grantee.
_PLATFORM_SERVICES = frozenset({"origin", "mantle", "chorus"})


def _known_server(name: str) -> bool:
    """A persona or platform server Origin knows: one of its personas, or a name its authority
    manifest anchors (review 14). `agience-server-<anything>` names no one."""
    from origin import config
    if name in getattr(config, "PERSONA_AUDIENCES", ()):
        return True
    try:
        from origin.authority_trust import get_authority_manifest
        anchors = getattr(get_authority_manifest(), "trust_anchors", {}) or {}
    except Exception:  # noqa: BLE001 — no manifest loaded: only the configured personas
        return False
    # The platform's own services are anchored too, and are no one's grantee (review 15).
    return bool(name) and name not in _PLATFORM_SERVICES and name in anchors


def _grantee_exists(rc: Reach, new: Grant) -> bool:
    """A grant names someone Origin knows (n1b): a person, the platform system principal, a
    persona server, or the commons for Read. An invite names a claim token's hash and is
    exempt; so is a deny on a principal no longer here."""
    if new.grantee_type != "user":
        return True
    gid = str(new.grantee_id)
    if rc.r.is_person(gid):
        return True
    from origin import service_identity
    if gid == (service_identity.get_system_principal_id() or ""):
        return True
    if gid.startswith("agience-server-") and _known_server(gid[len("agience-server-"):]):
        return True
    if gid == "public" and new.actions <= frozenset({"read"}):
        return True
    return False


def _decide_grant(rc: Reach, ctx: Context, b: dict) -> Optional[str]:
    actor = ctx.actor
    new = _grant_from_body(b)
    prior = rc.r.grant(new.id)
    if not ctx.bootstrap and _seen(rc, new.resource_id) and rc.gone(new.resource_id):
        # Deleted at Origin (review 15): nothing is granted on it again. A grant on it may be
        # retired as bookkeeping, except a deny on a token Mantle holds: that is answered as
        # unchanged and stays, holding nothing open since the resource opens for no one.
        if not _retires_unchanged(prior, new):
            raise EntryRefused("the resource was deleted at Origin; nothing is granted on it", 409)
        if prior.effect == "deny" and ctx.kind in MANTLE_HELD:
            return None
    # A withdrawal undoes Mantle's own failed write, bound to that entry's actor, credential and
    # window and decided again against what the actor holds now; an entry made in the session is
    # confirmed when appended and is never withdrawn.
    if ctx.kind in MANTLE_HELD and not ctx.bootstrap and ctx.compensates is None and not (
            prior is not None and _structure(prior) == _structure(new)):
        if not _seen(rc, new.resource_id) or not _held_grant_allowed(rc, ctx, prior, new):
            what = "an invite" if new.grantee_type == "invite" else (
                "a deny" if new.effect == "deny" or (prior and prior.effect == "deny")
                else "a grant")
            raise _session_only(what)
    if (prior is None and not ctx.bootstrap and new.state == _ACTIVE
            and not _grantee_exists(rc, new)):
        raise EntryRefused(f"the grantee {new.grantee_id!r} does not exist")
    if prior is not None:
        if (prior.resource_id, prior.grantee_id, prior.grantee_type) != (
                new.resource_id, new.grantee_id, new.grantee_type):
            raise EntryRefused("a grant's resource and grantee do not change", 409)
        if (prior.target_kind, prior.target_digest, prior.max_claims) != (
                new.target_kind, new.target_digest, new.max_claims):
            raise EntryRefused("an invite's target and claim limit do not change", 409)
        if _structure(prior) == _structure(new):
            return None
    resource = new.resource_id
    if not _seen(rc, resource):
        if ctx.bootstrap:
            return "bootstrap"
        raise EntryRefused("the resource is unknown to Origin's replica; it comes into being "
                           "only by its own root or creation edge")
    if ctx.bootstrap:
        return "bootstrap"
    widening = _widens(prior, new)
    # A deny is changed only by Admin on the resource, whoever issued it (architecture §51:
    # created_by grants nothing), and never on a token Mantle holds (review 15); a background
    # delegation changes none. One on a resource deleted at Origin is retired in the session.
    if prior is not None and (prior.effect == "deny" or new.effect == "deny"):
        if ctx.kind == ORIGIN_SESSION and _retires_unchanged(prior, new) and rc.gone(resource):
            return "a deny retired on a resource deleted at Origin"
        if ctx.kind != "background" and rc.has_any_action(actor, resource, "admin"):
            return "admin on the resource changes a deny"
        raise EntryRefused("a deny is changed only by Admin on the resource")
    if ctx.kind == "background":
        # The system principal's revocations (a peer's, an erasure's) must land under
        # enforcement. A narrowing never widens reach, so it is safe for confidentiality.
        if widening or (prior is None and new.effect == "deny"):
            raise EntryRefused("a background delegation does not issue or widen a grant")
        return "a narrowing by the system principal"

    if not widening:
        if prior is not None and new.state != _ACTIVE and prior.state == _ACTIVE:
            if actor == prior.grantee_id:
                return "the grantee gives up their own grant"
            if rc.gone(resource):
                return "retired on a resource deleted at Origin"
            if prior.grantee_type == "invite":
                if rc.has_any_action(actor, resource, "share", "admin"):
                    return "share or admin on the resource closes an invite"
                if prior.max_claims is not None and rc.r.claims_of(prior.id) >= prior.max_claims:
                    return "records that the invite is spent, as Origin counted"
                raise EntryRefused("an invite is closed by share or admin on the resource")
    created = _creation_grant(rc, ctx, new)
    if created:
        return created
    # `grants_router`: an invite needs share or admin; a direct grant, or any change to one,
    # needs admin.
    needs = ("share", "admin") if new.grantee_type == "invite" else ("admin",)
    if new.effect == "deny" and (prior is None or prior.effect != "deny"):
        needs = ("admin",)                   # a deny is an admin's, whoever issued the grant
    named = " or ".join(needs)
    refusal = EntryRefused(f"the actor holds no {named} on the resource")
    if rc.has_any_action(actor, resource, *needs):
        # The clamp bounds what a grant hands out (`clamp_grant_to_issuer`), so it applies to a
        # change that widens; a narrowing (a revocation) carries what it already carried.
        wider = sorted(new.actions - rc.effective_actions(actor, resource))
        if not (widening and new.effect == "allow" and wider):
            return f"{named} on the resource"
        refusal = EntryRefused(f"the grant carries {wider}, which the actor does not hold on "
                               f"the resource")
    # A claim is open to anyone the invite names, whatever else they hold.
    if (prior is None and new.grantee_type == "user" and new.grantee_id == actor
            and new.state == _ACTIVE and new.effect == "allow"):
        why = _claim(rc, ctx, new)
        if why:
            return why
    raise refusal


def _wider_mask(prior: Optional[list], new: Optional[list]) -> bool:
    p = Mask.from_propagate(prior).actions
    n = Mask.from_propagate(new).actions
    return not n <= p


def _decide_edge_add(rc: Reach, ctx: Context, b: dict) -> Optional[str]:
    actor = ctx.actor
    src, dst = b["src"], b["dst"]
    prior = rc.r.edge(src, dst)
    want = {"origin": b["origin"], "propagate": b["propagate"]}
    if prior is not None and bool(prior["origin"]) == bool(want["origin"]) and _same_mask(
            prior["propagate"], want["propagate"]):
        return None                  # a restatement: compared as masks, not encodings
    if not ctx.bootstrap and any(_seen(rc, n) and rc.gone(n) for n in (src, dst)):
        raise EntryRefused("a node deleted at Origin takes no edge, in or out", 409)
    if prior is not None and prior["origin"] and not want["origin"]:
        # A demotion would delete the member at Origin without charging its root (review 30,
        # F1): a creation edge is removed, never demoted, by bootstrap too.
        raise EntryRefused("a creation edge is removed, never demoted", 403)
    if ctx.bootstrap and b["origin"] and _seen(rc, dst) and rc.gone(dst):
        raise EntryRefused("a node deleted at Origin takes no creation edge, by bootstrap "
                           "either", 409)
    if prior is not None and ctx.kind in MANTLE_HELD and not ctx.bootstrap:
        raise _session_only("a change to what an edge conducts")
    if b["origin"]:
        parent = rc.origin_parent(dst)
        if parent is not None and parent[0] != src:
            raise EntryRefused("the member already has its creation edge; a move is secondary "
                               "containment", 409)
    if ctx.bootstrap:
        if b["origin"] and prior is None and rc.r.is_person(dst):
            raise EntryRefused("a creation edge cannot claim a person's id, by bootstrap either")
        return "bootstrap"
    if ctx.kind == "background":
        if (prior is not None and not (want["origin"] and not prior["origin"])
                and not _wider_mask(prior["propagate"], want["propagate"])):
            return "a narrowing by the system principal"
        raise EntryRefused("a background delegation does not add or widen an edge")
    if not _seen(rc, src):
        raise EntryRefused("the collection is unknown to Origin's replica")
    may_add = rc.reaches(actor, src, "create") or rc.reaches(actor, src, "add")
    if prior is None:
        if b["origin"]:
            if _seen(rc, dst):
                raise EntryRefused("an existing id has its creation once; a creation edge "
                                   "cannot claim it")
            if rc.r.is_person(dst):
                raise EntryRefused("a creation edge cannot claim a person's id")
            if _derived_for_another(ctx, dst):
                raise EntryRefused("this id is derived from another person's id; only that "
                                   "person creates it")
        elif not _seen(rc, dst):
            raise EntryRefused("the member is unknown to Origin's replica")
        if may_add:
            return "create or add reaching the collection"
        raise EntryRefused("the actor reaches the collection for neither create nor add")
    if want["origin"] and not prior["origin"]:
        raise EntryRefused("secondary containment does not become a creation edge")
    # What an existing edge conducts decides who reaches everything below it: changing it,
    # wider or narrower, is Admin's on the collection (architecture §51: Add is intake, Evict
    # removes the edge; neither rewrites another member's mask).
    if rc.has_any_action(actor, src, "admin"):
        return "admin on the collection changes what the edge conducts"
    raise EntryRefused("changing what an edge conducts needs admin on the collection")


def _decide_edge_remove(rc: Reach, ctx: Context, b: dict) -> Optional[str]:
    actor = ctx.actor
    src, dst = b["src"], b["dst"]
    if rc.r.edge(src, dst) is None:
        return None
    if ctx.bootstrap:
        return "bootstrap"
    if ctx.kind == "background":
        return "a removal by the system principal"
    if rc.gone(src) or rc.gone(dst):
        return "what is left of a node deleted at Origin goes with it"
    if rc.r.edge(src, dst).get("origin"):
        # Removing a creation edge deletes the member at Origin (review 15), so it is Delete's,
        # or Admin's on the collection; Evict alone removes a secondary edge (architecture §51).
        if rc.reaches(actor, dst, "delete") or rc.has_any_action(actor, src, "admin"):
            return "delete reaching the member (or admin on the collection) deletes it"
        raise EntryRefused("removing a creation edge deletes the member: it needs delete "
                           "reaching the member, or admin on the collection; evict removes only a "
                           "secondary edge")
    if (rc.reaches(actor, src, "evict") or rc.has_any_action(actor, src, "admin")
            or rc.reaches(actor, dst, "delete")):
        return "evict (or admin) on the collection, or delete on the member"
    raise EntryRefused("the actor may neither evict from the collection nor delete the member")


#: The ids Mantle derives from a person's id for what first sign-in makes (`user_provisioning`,
#: `events.observation`): their card, their own card beside an old one, their Inbox, and their
#: observations container. Registered, or created by an edge, only by that person.
#: Every id Mantle derives from a person, in one place (cross-checked against Mantle's own
#: functions by `test_f11_origin_s_forms_are_mantle_s`):
#:   * URL forms (`uuid5(NAMESPACE_URL, …)`): the person card, their own card beside an old one,
#:     their Inbox, their observations container;
#:   * their local collection (`shard.local_collection`), by person id or by email;
#:   * identity-member ids (`services.artifact_identity`, `uuid5(NS, principal\nkey)`) for the
#:     natural keys the platform itself uses: a caller-chosen key cannot be enumerated, so only
#:     these well-known ones are protected (an id squatted on a private key is cleared with the
#:     operator's `retire-root`);
#:   * seeded slugs templated per person (`{{user.id}}`, `{{user.email}}`), under the instance
#:     namespace, for the seed namespaces below.
DERIVED_URL_FORMS = ("agience://person/{p}", "agience://person/{p}/own",
                     "agience://workspace/inbox/{p}", "agience://observations/{p}")
_EMBER_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "ember.agience.ai")
_IDENTITY_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "artifact-identity.mantle.agience.ai")
WELL_KNOWN_IDENTITY_KEYS = ("ember:memory",)
SEED_NAMESPACES = ("user", "agience", "platform")
_derived_cache: Dict[str, str] = {}
_derived_people: set = set()


def memory_collection_id(person: str) -> str:
    """The person's Ember memory collection: Mantle's identity id for (person, `ember:memory`)
    (`services.artifact_identity`)."""
    return str(uuid.uuid5(_IDENTITY_NS, f"{person}\nember:memory"))


def derived_ids(person: str, *, email: Optional[str] = None) -> List[str]:
    """Every id Mantle derives from `person` (and their address, where Mantle uses it)."""
    out = [str(uuid.uuid5(uuid.NAMESPACE_URL, f.format(p=person))) for f in DERIVED_URL_FORMS]
    names = [person] + ([email] if email else [])
    out += [str(uuid.uuid5(_EMBER_NS, f"local-collection:{n}")) for n in names]
    out += [str(uuid.uuid5(_IDENTITY_NS, f"{person}\n{k}")) for k in WELL_KNOWN_IDENTITY_KEYS]
    try:
        from origin import service_identity
        ns = service_identity.get_instance_namespace()
    except Exception:  # noqa: BLE001 — no instance namespace: those forms cannot exist here
        ns = None
    if ns is not None:
        out += [str(uuid.uuid5(ns, f"{sn}/{n}")) for sn in SEED_NAMESPACES for n in names]
    return out


def derived_owner(db: Optional[Session], node_id: str) -> Optional[str]:
    """The person `node_id` is derived from, or None. Computed over Origin's own person rows, so
    whoever submits an id cannot say whose it is."""
    if db is None:
        return None
    from origin.models.person import Person

    rows = {str(i): (e or "").lower() for (i, e) in db.query(Person.id, Person.email)}
    # Keyed by (person, address): a changed address derives its own ids, and the old ones stay the
    # person's (they may hold rows Mantle made under them).
    fresh = {(p, e) for p, e in rows.items()} - _derived_people
    for person, email in fresh:
        for node in derived_ids(person, email=email or None):
            _derived_cache[node] = person
            _squat_alert(db, node, person)
    _derived_people.update(fresh)
    owner = _derived_cache.get(str(node_id))
    return owner if owner in rows else None


def _squat_alert(db: Session, node: str, person: str) -> None:
    """An id derived from `person` that someone else already registered (before the person
    signed up, or under an address they took later) raises an operator alert; the operator
    clears it with `retire_root`."""
    try:
        root = db.get(AuthorityRoot, node)
    except Exception:  # noqa: BLE001 — no replica tables: nothing to compare
        return
    if root is None or not root.registered_by or root.registered_by == person:
        return
    from origin.models.authority_ledger import OperatorAlert
    if db.query(OperatorAlert).filter(OperatorAlert.kind == "derived_id_squatted",
                                      OperatorAlert.resource_id == node).first():
        return
    db.add(OperatorAlert(kind="derived_id_squatted", seq=int(root.seq or 0), resource_id=node,
                         subject=person, actor=root.registered_by,
                         detail=f"{node} is derived from {person} and was registered by "
                                f"{root.registered_by}; retire it with retire-root"))
    db.commit()


def _derived_for_another(ctx: "Context", node_id: str) -> Optional[str]:
    owner = derived_owner(getattr(ctx, "db", None), node_id)
    return owner if owner is not None and owner != ctx.actor else None


def _decide_root(rc: Reach, ctx: Context, b: dict) -> Optional[str]:
    actor = ctx.actor
    principal, root = b["principal_id"], b["root_id"]
    prior = rc.r.root_entry(principal)
    if prior is not None:
        if prior["root_id"] == root:
            return None
        raise EntryRefused("this key principal is registered under another root", 409)
    if rc.r.node(principal) is not None and rc.gone(principal):
        # Deleted at Origin (review 16): registering it as a root would not bring it back, and
        # it is no one's to register.
        raise EntryRefused("this node was deleted at Origin; it is not registered as a root", 409)
    walked = rc.root_of(principal)
    if walked != root:
        raise EntryRefused(f"Origin's replica walks {principal!r} to another root", 409)
    if ctx.bootstrap:
        if rc.r.is_person(principal) and root != principal:
            raise EntryRefused("a person's key roots to that person, by bootstrap either")
        return "bootstrap"
    if rc.r.is_person(principal) and actor != principal:
        raise EntryRefused("a person's own key is registered only by that person")
    if _derived_for_another(ctx, principal):
        raise EntryRefused("this id is derived from another person's id; only that person "
                           "registers it")
    node = rc.r.node(principal)
    if node is None:
        # The creation the store recorded for this id: made by this actor, just now.
        made = (ctx.proof or {}) if isinstance(ctx.proof, dict) else {}
        if not rc.r.is_person(principal):
            try:
                when = parse_time(made.get("created_at"))
            except (ValueError, TypeError):
                when = None
            now = datetime.now(timezone.utc)
            if (made.get("created_by") != actor or when is None
                    or not now - timedelta(minutes=ROOT_FRESHNESS_MINUTES) <= when
                    <= now + timedelta(minutes=1)):
                raise EntryRefused("a new key principal is registered with its creation: by its "
                                   "creator, freshly minted")
        return "a new key principal, by its creator"
    if rc.has_any_action(actor, principal, "admin") or _created_in_batch(ctx, principal):
        return "admin on it, or its creation in this batch, registers its root"
    raise EntryRefused("this id was brought into being by someone else")


def _decide_retired_drop_key(rc: Reach, ctx: Context, b: dict) -> Optional[str]:
    """A drop key is not part of the authority model (John, 2026-11-03): writing without reading
    is a grant with Add and nothing else, and sealing what is added to the collection's readers is
    Mantle's key material, which Origin never stores or co-signs."""
    raise EntryRefused("a drop key is not an authority entry: write-without-read is a grant with "
                       "Add and nothing else", 400)


def _decide_root_retire(rc: Reach, ctx: Context, b: dict) -> Optional[str]:
    raise EntryRefused("a root or node is retired only by the operator, through the console")


def _job_scope(rc: Reach, actor: str, principal: str, collections: list) -> bool:
    """May `actor` grant (or revoke) a job over `principal` and `collections`? The person whose
    key it is, for their own master key; Admin on a collection, for that collection's key and for
    each collection listed. Never by `created_by` (architecture §51)."""
    from origin.services.authority_reach import collection_key_collection

    own = collection_key_collection(principal)
    if own is not None:
        needs = {own, *collections}
    elif principal == actor and rc.r.is_person(actor):
        needs = set(collections)
    elif _a_root(rc, principal):
        # A root's own master key, which keys its legacy content: granted over by a full
        # reader-Admin of the root only (review 28, L1), the same rule that releases the key, so a
        # job never opens a key wider than its grantor's Read.
        return (rc.full_reader_admin(actor, principal)[0]
                and all(_admin_and_read(rc, actor, c) for c in collections))
    else:
        return False
    return all(_admin_and_read(rc, actor, c) for c in needs)


def _admin_and_read(rc: Reach, who: str, collection: str) -> bool:
    """Admin on `collection`, and Read on it (review 10, R4): a job opens the collection's key,
    and a key is a Read."""
    return (_seen(rc, collection) and rc.has_any_action(who, collection, "admin")
            and rc.reaches(who, collection, "read"))


#: The actor kind of an entry Origin appends for a person at its own page, in their Origin session
#: with a fresh step-up (`/auth/me/job-grants`): the only way a job grant is made (review 9, H2).
ORIGIN_PAGE = "origin_page"


def _decide_job_grant(rc: Reach, ctx: Context, b: dict) -> Optional[str]:
    """A job grant: made by the person whose key it is or an Admin of each collection, on their
    own credential (never a background, seed or bootstrap one), live at most
    `JOB_GRANT_MAX_DAYS`; only revoked after, by the same rights or the operator."""
    from origin.services import custody_plane

    why_not = custody_plane.custody_refusal()
    if why_not:
        raise EntryRefused(why_not)
    if ctx.kind in MANTLE_HELD:
        raise EntryRefused("a job grant is made and revoked at Origin's own page, in the "
                           "person's Origin session (POST /auth/me/job-grants), never on a token "
                           "Mantle holds")
    if ctx.kind == ORIGIN_SESSION and b["kind"] == "job_grant":
        raise EntryRefused("a job grant is made with a step-up at POST /auth/me/job-grants")
    if ctx.bootstrap or ctx.kind not in (ORIGIN_PAGE,):
        raise EntryRefused("a job grant is made on a person's own credential")
    prior = getattr(rc.r, "job_grant", lambda _g: None)(b["grant_id"])
    if prior is None and ctx.kind != ORIGIN_PAGE:
        # Mantle holds every person's access token, and a delegation is Mantle's too: neither
        # alone may hand a background job weeks of the person's key.
        raise EntryRefused("a job grant is made at Origin's own page, in the person's Origin "
                           "session with a fresh step-up (POST /auth/me/job-grants)")
    if prior is not None:
        same = {k: prior[k] for k in ("job", "principal", "collections", "expires_at")}
        if same != {k: b[k] for k in same}:
            raise EntryRefused("a job grant does not change; grant a new one", 409)
        if prior["state"] == b["state"]:
            return None
        if b["state"] != "revoked":
            raise EntryRefused("a revoked job grant stays revoked", 409)
        if not _job_scope(rc, ctx.actor, b["principal"], b["collections"]):
            raise EntryRefused("a job grant is revoked by the person whose key it is or an Admin "
                               "of its collections")
        return "the job grant is revoked"
    if b["state"] != _ACTIVE:
        raise EntryRefused("a new job grant is active", 400)
    until = parse_time(b["expires_at"])
    now = datetime.now(timezone.utc)
    if until <= now or until > now + timedelta(days=JOB_GRANT_MAX_DAYS):
        raise EntryRefused(f"a job grant ends in the future, within {JOB_GRANT_MAX_DAYS} days",
                           400)
    if not _job_scope(rc, ctx.actor, b["principal"], b["collections"]):
        raise EntryRefused("a job grant is made by the person whose key it is, or an Admin of "
                           "each collection it names")
    return "a job grant within the actor's own authority"


_DECIDE = {"grant": _decide_grant, "edge.add": _decide_edge_add,
           "edge.remove": _decide_edge_remove, "root": _decide_root,
           "root.confirm_empty": lambda rc, ctx, b: _operator_only(),
           "drop_key": _decide_retired_drop_key, "root.retire": _decide_root_retire,
           "job_grant": _decide_job_grant}


def _decide_compensation(db: Session, ctx: Context, b: dict) -> str:
    """A compensating entry withdraws entry `ctx.compensates`, made by the same actor, while it is
    still the latest change to that row."""
    row = db.get(AuthorityEntry, int(ctx.compensates))
    # A withdrawal retried later (Mantle's outstanding one) comes as the system principal's
    # narrowing: any actor's entry, past the window, and still only while it is the latest change.
    retried = ctx.kind in ("background", "operator")
    if row is not None and row.resolved_by:
        raise EntryRefused(f"the operator resolved entry {row.seq}; nothing is left to withdraw",
                           410)
    if row is not None and row.confirmed:
        raise EntryRefused("Mantle confirmed the write this entry was made for; it is not "
                           "withdrawn by compensation")
    if row is None or (row.actor != ctx.actor and not retried):
        raise EntryRefused("a compensating entry withdraws an entry the same actor made")
    if row.credential_ref != ctx.ref and not retried:
        raise EntryRefused("a compensating entry comes on the credential the entry was made on")
    made = row.created_time if row.created_time.tzinfo else row.created_time.replace(
        tzinfo=timezone.utc)
    if not retried and datetime.now(timezone.utc) - made > timedelta(
            seconds=COMPENSATION_WINDOW_SECONDS):
        raise EntryRefused(f"a compensating entry comes within {COMPENSATION_WINDOW_SECONDS}s "
                           f"of the entry it withdraws")
    orig = json.loads(row.body)
    # A deny whose write did not commit was never in force in Mantle's store: its own actor
    # withdraws it, within the window. Nobody else does, the system principal's retry included;
    # an unconfirmed deny past that is settled only by the operator's resolve.
    if row.kind == "grant" and orig.get("effect") == "deny" and ctx.kind == "background":
        raise EntryRefused("a retried withdrawal never lifts a deny; the operator resolves it")
    if row.kind == "edge.add" and b["kind"] == "edge.remove" and (
            orig["src"], orig["dst"]) == (b["src"], b["dst"]):
        cur = db.get(AuthorityEdge, (b["src"], b["dst"]))
    elif row.kind == "grant" and b["kind"] == "grant" and orig["grant_id"] == b["grant_id"] \
            and b["state"] == "retired":
        cur = db.get(AuthorityGrant, b["grant_id"])
    else:
        raise EntryRefused("a compensating entry is the narrowing inverse of the entry it "
                           "withdraws", 400)
    if cur is None or cur.seq != row.seq:
        latest = db.get(AuthorityEntry, cur.seq) if cur is not None else None
        raise EntryRefused(
            "the row has changed since; it is not withdrawn (latest entry "
            f"{cur.seq if cur is not None else 'none'}"
            f"{', a withdrawal' if latest is not None and latest.compensates is not None else ''}"
            ")", 409)
    ctx.restored = prior_state(db, row)
    # The entry's own actor, on its own credential, within its window, undoes its own failed
    # write whatever that restores. Anyone else's withdrawal (the system principal's retry, the
    # operator's) only narrows: it never makes a grant more live, or an edge conduct more, than it
    # does now. The operator lifts an unconfirmed deny by settling it (`resolve_unconfirmed`).
    if retried and not getattr(ctx, "settle", False) and _restores_wider(db, row, ctx.restored):
        raise EntryRefused("a withdrawal on a background or operator credential only narrows; "
                           "this one would widen reach, so it is the entry's own actor's, or the "
                           "operator's to settle")
    if not retried and _restores_wider(db, row, ctx.restored):
        # The entry's own actor undoes their write only while they still hold what it was made
        # under: a widening restoration is decided as that change, now.
        rc = reach(db)
        restored = ctx.restored
        orig = json.loads(row.body)
        if restored["kind"] == "grant" and orig.get("state") == "deleted":
            # A grant retired with its resource deleted (the one grant change a token Mantle holds
            # makes, review 12): undone only while the actor still holds the Delete it was made
            # under, on the collection the resource was removed from.
            parents = [json.loads(e.body).get("src") for e in db.query(AuthorityEntry).filter(
                AuthorityEntry.batch == row.batch, AuthorityEntry.kind == "edge.remove",
                AuthorityEntry.actor == row.actor) if json.loads(e.body).get("dst")
                == restored["resource_id"] and _was_creation_edge(
                    db, json.loads(e.body).get("src") or "", restored["resource_id"], e.seq)]
            if not any(p and rc.reaches(ctx.actor, p, "delete") for p in parents):
                raise EntryRefused("the actor no longer holds the Delete this deletion was made "
                                   "under; it is not undone")
        elif restored["kind"] == "grant":
            again = Context(actor=ctx.actor, kind=ctx.kind, ref=ctx.ref, batch=None,
                            compensates=ctx.compensates)
            again.db = db
            _decide_grant(rc, again, restored)
        elif not rc.has_any_action(ctx.actor, restored["src"], "admin"):
            raise EntryRefused("the actor no longer holds Admin on the collection; the "
                               "withdrawal would widen what its edge conducts")
    return f"withdraws entry {row.seq}"


def _restores_wider(db: Session, row: AuthorityEntry, restored: dict) -> bool:
    if restored["kind"] == "grant":
        cur = db.get(AuthorityGrant, restored["grant_id"])
        return _widens(_grant_of(cur) if cur is not None else None, _grant_from_body(restored))
    if restored["kind"] == "edge.add":
        cur = db.get(AuthorityEdge, (restored["src"], restored["dst"]))
        if cur is None:
            return True
        return (bool(restored["origin"]) and not bool(cur.origin)) or _wider_mask(
            _prop_load(cur.propagate), restored["propagate"])
    return False


def _row_key(kind: str, b: dict) -> tuple:
    if kind == "grant":
        return ("grant", b["grant_id"])
    return ("edge", b["src"], b["dst"])


def prior_state(db: Session, row: AuthorityEntry) -> dict:
    """What withdrawing entry `row` restores: its row as the entry before it on that row left it
    (every entry's body is the row's whole state, a withdrawal's included), or, when `row` brought
    the row into being, its absence: a grant retired, an edge removed."""
    b = json.loads(row.body)
    key = _row_key(row.kind, b)
    kinds = ("grant",) if key[0] == "grant" else ("edge.add", "edge.remove")
    for prev in (db.query(AuthorityEntry).filter(AuthorityEntry.seq < row.seq,
                                                 AuthorityEntry.kind.in_(kinds))
                 .order_by(AuthorityEntry.seq.desc())):
        pb = json.loads(prev.body)
        if _row_key(prev.kind, pb) == key:
            return normalise(pb)
    if key[0] == "grant":
        return normalise({**b, "state": "retired"})
    return {"kind": "edge.remove", "src": b["src"], "dst": b["dst"]}


#: How long a batch Origin issued stays open: one operation's submissions, seconds apart.
BATCH_WINDOW_SECONDS = 60


def open_batch(db: Session, batch: Optional[str], credential_ref: str) -> str:
    """The batch this submission belongs to. Without one, Origin issues a new batch; with one,
    it must be a batch Origin issued, to this same credential, within its window. One
    operation, one credential, one batch: a batch name chosen by the caller means nothing."""
    import secrets

    now = datetime.now(timezone.utc)
    if batch is None:
        bid = secrets.token_hex(16)
        db.add(AuthorityBatch(batch_id=bid, credential_ref=credential_ref, created_time=now))
        db.commit()
        return bid
    row = db.get(AuthorityBatch, batch)
    if (row is None or row.credential_ref != credential_ref
            or now - _aware(row.created_time) > timedelta(seconds=BATCH_WINDOW_SECONDS)):
        raise EntryRefused("not a batch Origin issued to this credential, or it has closed", 403)
    return batch


def confirm_digest(seqs: list) -> str:
    return hashlib.sha256(canonical({"seqs": [int(s) for s in seqs]}).encode("utf-8")).hexdigest()


def confirm(db: Session, seqs: list, submitted_by: str) -> int:
    """`submitted_by` committed the writes these entries were made for. Only entries it submitted
    and that are still pending are confirmed; any other seq refuses the whole call."""
    rows = [db.get(AuthorityEntry, int(s)) for s in seqs]
    for s, row in zip(seqs, rows):
        if row is None or row.submitted_by != submitted_by or row.confirmed or row.resolved_by:
            raise EntryRefused(f"entry {s} is not one this service submitted and holds pending",
                               403)
    for row in rows:
        row.confirmed = True
    db.commit()
    return len(rows)


def unconfirmed(db: Session) -> list:
    """Entries submitted and neither confirmed nor resolved: a write that may not have committed,
    or a withdrawal still due at Mantle."""
    q = (db.query(AuthorityEntry).filter(AuthorityEntry.confirmed.is_(False),
                                          AuthorityEntry.resolved_by.is_(None))
         .order_by(AuthorityEntry.seq))
    return [_entry_view(r) for r in q]


def _entry_view(r) -> dict:
    return {"seq": r.seq, "kind": r.kind, "body": json.loads(r.body), "actor": r.actor,
            "credential_kind": r.credential_kind, "credential_ref": r.credential_ref,
            "batch": r.batch, "confirmed": bool(r.confirmed), "resolved_by": r.resolved_by,
            "created_time": _aware(r.created_time).isoformat()}


def entries_by_credential(db: Session, credential_ref: Optional[str], since, until) -> list:
    q = db.query(AuthorityEntry)
    if credential_ref:
        q = q.filter(AuthorityEntry.credential_ref == credential_ref)
    if since is not None:
        q = q.filter(AuthorityEntry.created_time >= since)
    if until is not None:
        q = q.filter(AuthorityEntry.created_time <= until)
    return [_entry_view(r) for r in q.order_by(AuthorityEntry.seq)]


def revoke_entry(db: Session, seq: int, operator_id: str, ref: str) -> Optional[dict]:
    """The operator's narrowing undoing entry `seq`: a grant it made is revoked, an edge it
    added is removed. Appended to the ledger as the operator's entry. None if nothing is left
    to undo."""
    row = db.get(AuthorityEntry, int(seq))
    if row is None:
        raise EntryRefused(f"no entry {seq}", 404)
    b = json.loads(row.body)
    if row.kind == "grant" and b.get("effect") == "allow" and b.get("state") == "active":
        cur = db.get(AuthorityGrant, b["grant_id"])
        if cur is None or cur.state != "active":
            return None
        inverse = {**b, "state": "revoked"}
        current = _grant_of(cur)
        inverse = {**inverse, "actions": sorted(current.actions), "effect": current.effect,
                   "expires_at": current.expires_at}
    elif row.kind == "edge.add":
        if db.get(AuthorityEdge, (b["src"], b["dst"])) is None:
            return None
        inverse = {"kind": "edge.remove", "src": b["src"], "dst": b["dst"]}
    else:
        raise EntryRefused("only a grant or an added edge is revoked here", 400)
    return append(db, inverse, actor=Actor(operator_id, "operator", ref),
                  submitted_jti=f"console:{ref}")


def job_grant_view(row) -> dict:
    return {"grant_id": row.grant_id, "job": row.job, "principal": row.principal,
            "collections": json.loads(row.collections or "[]"), "expires_at": row.expires_at,
            "state": row.state, "created_by": row.created_by, "seq": row.seq}


def _held_for_tests(grant_id: str) -> bool:
    """A test-only seam (review 18): the job grants a test states as held without a grantor
    (`origin.tests.authority_fixtures.HELD_FOR_TESTS`). Honoured only while pytest is loaded and
    that test module is imported; production holds no such list."""
    import sys
    from pathlib import Path
    if "pytest" not in sys.modules:
        return False
    fixtures = sys.modules.get("origin.tests.authority_fixtures")
    # This source tree's own `tests` folder, beside this package, and no other: a wheel carries
    # no tests (`exclude = ["origin.tests*"]`), so a module planted under that name elsewhere is
    # not this seam (review 19).
    here = Path(__file__).resolve().parents[1] / "tests" / "authority_fixtures.py"
    try:
        theirs = Path(getattr(fixtures, "__file__", "") or "").resolve()
    except (OSError, ValueError):
        return False
    if fixtures is None or theirs != here:
        return False
    return grant_id in (getattr(fixtures, "HELD_FOR_TESTS", None) or ())


def grant_still_held(db: Session, row) -> bool:
    """Does the job grant's grantor still hold what it was granted under? The platform's own
    grant: the platform principal holds Admin on every collection it names. A person's: the grantor
    is an active person and still the key's own person, or Admin on each collection (review 9,
    M5). Checked when a delegation is minted and when one is used."""
    from origin import service_identity
    from origin.models.person import Person

    if _held_for_tests(row.grant_id):
        return True
    rc = reach(db)
    cols = json.loads(row.collections or "[]")
    system = service_identity.get_system_principal_id()
    if system and row.principal == system:
        return all(_admin_and_read(rc, system, c) for c in cols)
    if row.job == NON_PERSON_CUSTODY_JOB and not cols and not rc.r.is_person(row.principal):
        # The operator's split of a non-person principal's key (review 26, H1): held while its
        # grantor is still the operator and the principal is still no person's.
        from origin.services.platform_settings_service import settings as _ps
        try:
            operator = str(_ps.get("platform.operator_id") or "")
        except Exception:  # noqa: BLE001 — no settings: no operator
            operator = ""
        if operator and str(row.created_by) == operator:
            try:
                non_person_principal(db, str(row.principal))
            except EntryRefused:
                return False
            # Over a charged root (review 31): held only for its recorded rotated key, and only
            # while that key's split is reading back. Once the share is activated, it has ended.
            if charged_root(rc, str(row.principal)):
                rot = _rotation(db, str(row.principal))
                return (rot is not None and rot.grant_id == row.grant_id
                        and charged_split_open(db, str(row.principal)))
            return True
    try:
        person = db.get(Person, uuid.UUID(str(row.created_by)))
    except (ValueError, TypeError):
        person = None
    if person is None or person.deactivated_at is not None:
        return False
    return _job_scope(rc, str(row.created_by), row.principal, cols)


def live_job_grant(db: Session, *, job: str, principal: str):
    """The live job grant naming `job` that covers `principal` (its own key, or a listed
    collection's key), or None."""
    from origin.models.authority_ledger import AuthorityJobGrant
    from origin.services.authority_reach import collection_key_collection

    coll = collection_key_collection(principal)
    now = datetime.now(timezone.utc)
    for row in db.query(AuthorityJobGrant).filter(AuthorityJobGrant.job == job,
                                                  AuthorityJobGrant.state == _ACTIVE):
        try:
            if parse_time(row.expires_at) <= now:
                continue
        except ValueError:
            continue
        cols = set(json.loads(row.collections or "[]"))
        if (row.principal == principal or (coll is not None and coll in cols)) and \
                grant_still_held(db, row):
            return row
    return None


def job_grants(db: Session) -> list:
    from origin.models.authority_ledger import AuthorityJobGrant
    return [job_grant_view(r) for r in
            db.query(AuthorityJobGrant).order_by(AuthorityJobGrant.seq)]


def person_job_grants(db: Session, person_id: str) -> list:
    """The job grants a person made, or that name their own key."""
    from origin.models.authority_ledger import AuthorityJobGrant
    return [job_grant_view(r) for r in db.query(AuthorityJobGrant).filter(
        (AuthorityJobGrant.created_by == person_id) | (AuthorityJobGrant.principal == person_id))
        .order_by(AuthorityJobGrant.seq)]


def page_job_grant(db: Session, person_id: str, *, job: str, expires_at: str,
                   principal: Optional[str] = None, collections: Optional[list] = None) -> dict:
    """A job grant the person makes at Origin's own page (their session and a step-up, checked by
    the route), appended as theirs."""
    entry = {"kind": "job_grant", "grant_id": "jg-" + secrets.token_hex(8), "job": job,
             "principal": principal or person_id, "collections": list(collections or []),
             "expires_at": expires_at, "state": _ACTIVE}
    return append(db, entry, actor=Actor(person_id, ORIGIN_PAGE, f"page:{person_id}"))


def session_entry(db: Session, person_id: str, entry: dict,
                  proof: Optional[dict] = None) -> dict:
    """An authority change the person makes in their own Origin session (review 12), decided by
    the same rules as any of theirs, appended as theirs. A job grant is not made here. `proof`
    carries an invite claim's token (`{"invite_id", "token"}`)."""
    b = normalise(entry)
    if b["kind"] == "job_grant":
        raise EntryRefused("a job grant is made with a step-up at POST /auth/me/job-grants")
    if b["kind"] not in ("grant", "edge.add", "edge.remove"):
        raise EntryRefused("the session makes grants, invites, denies and edge changes", 400)
    return append(db, b, actor=Actor(person_id, ORIGIN_SESSION, f"session:{person_id}"),
                  submitted_jti=f"session:{secrets.token_hex(8)}", proof=proof)


def page_revoke_job_grant(db: Session, person_id: str, grant_id: str) -> Optional[dict]:
    """The person revokes a job grant they made or that names their key: None if it is not one
    of theirs."""
    from origin.models.authority_ledger import AuthorityJobGrant
    row = db.get(AuthorityJobGrant, grant_id)
    if row is None or person_id not in (row.created_by, row.principal):
        return None
    v = job_grant_view(row)
    if v["state"] != _ACTIVE:
        return {"grant_id": grant_id, "state": v["state"]}
    return append(db, {"kind": "job_grant", "grant_id": grant_id, "job": v["job"],
                       "principal": v["principal"], "collections": v["collections"],
                       "expires_at": v["expires_at"], "state": "revoked"},
                  actor=Actor(person_id, ORIGIN_PAGE, f"page:{person_id}"))


def revoke_person_job_grants(db: Session, person_id: str) -> int:
    """Every live job grant the person made, revoked as the operator's narrowing (sign-out
    everywhere): their own right to revoke may already be gone with their Admin."""
    from origin.models.authority_ledger import AuthorityJobGrant
    n = 0
    for row in db.query(AuthorityJobGrant).filter(AuthorityJobGrant.created_by == person_id,
                                                  AuthorityJobGrant.state == _ACTIVE).all():
        v = job_grant_view(row)
        append(db, {"kind": "job_grant", "grant_id": row.grant_id, "job": v["job"],
                    "principal": v["principal"], "collections": v["collections"],
                    "expires_at": v["expires_at"], "state": "revoked"},
               actor=Actor(person_id, "operator", f"sign-out:{person_id}"),
               submitted_jti=f"sign-out:{person_id}")
        n += 1
    return n


#: The one job the operator grants over a principal other than the platform system principal: the
#: split of a non-person principal's whole master key (review 26, H1). No person ever acts as the
#: platform user, the system principal or a persona's principal on their own credential, so no
#: call splits their keys; the split pass does, under this grant.
NON_PERSON_CUSTODY_JOB = "platform.custody"


def platform_principals() -> frozenset:
    """The platform's own key principals, which no one acts as on their own credential: the
    platform user, the platform system principal, and each persona's server principal
    (`agience-server-<persona>`)."""
    from prism.trust.service_identity import SERVER_DELEGATION_SIGNERS
    from prism.trust.use_verdict import SERVER_PREFIX

    from origin import config, service_identity

    # Every service that holds a server delegation of its own, Crystal included (review 30, I1).
    out = {config.AGIENCE_PLATFORM_USER_ID,
           *(SERVER_PREFIX + p for p in SERVER_DELEGATION_SIGNERS)}
    system = service_identity.get_system_principal_id()
    if system:
        out.add(system)
    return frozenset(out)


def non_person_principal(db: Session, principal: str) -> str:
    """`principal`, when it is a key principal the operator may grant `platform.custody` over:
    one of the platform's own (`platform_principals`, review 27) that Origin's replica knows a
    root for. A person's key is theirs to grant, a collection's or a root's its Admins'.
    Otherwise `EntryRefused`."""
    if not isinstance(principal, str) or not principal or len(principal) > 128:
        raise EntryRefused("principal is a key principal's id", 400)
    rc = reach(db)
    if principal not in platform_principals() and not (_a_root(rc, principal)
                                                       and rc.part_removed(principal)):
        raise EntryRefused("the operator grants this over the platform user, the system "
                           "principal, a persona's server principal or a charged root only; a "
                           "person's key is theirs to grant, a collection's or a root's its "
                           "Admins'", 403)
    if rc.r.is_person(principal):
        raise EntryRefused("a person's key is theirs to grant, never the operator's", 403)
    if rc.r.root_entry(principal) is None:
        raise EntryRefused("Origin's replica knows no root for this principal", 404)
    return principal


#: The longest the operator's `platform.custody` grant over a charged root lives (review 31): the
#: split and its read-back, no more.
CHARGED_CUSTODY_MAX_HOURS = 2

_KCV_RE = re.compile(r"^[0-9a-f]{32}$")


def charged_root(rc: "Reach", principal: str) -> bool:
    """Is `principal` a charged root: a root (`_a_root`) a part of which was removed?"""
    return _a_root(rc, principal) and rc.part_removed(principal)


def rotation_kcv(db: Session, principal: str) -> Optional[str]:
    """The key-check value of the key step 21 rotated this charged root onto, as the operator
    recorded it, or None."""
    from origin.models.key_custody import ChargedRootRotation
    row = db.get(ChargedRootRotation, str(principal))
    return row.kcv if row is not None else None


def record_rotation(db: Session, principal: str, kcv: str, operator_id: str) -> dict:
    """The operator records step 21's rotation of a charged root's key (review 31): the rotated
    key's key-check value, read from the rotation's own report (`charged_roots`). A later
    rotation of the same root replaces it, and opens a split of its own: no grant is bound to it
    yet, and no share written under it (review 32). Refused for anything but a charged root, once
    Origin holds an activated share for it (a split key is not rotated; a seed's re-mark makes it
    pending again), and for a kcv Origin already holds or held a share of (the current share's,
    or any in its share history): such a kcv is no freshly rotated key's."""
    from origin.models.key_custody import (
        ChargedRootRotation, KeyCustodyShare, KeyCustodyShareHistory)

    if not isinstance(kcv, str) or not _KCV_RE.match(kcv):
        raise EntryRefused("kcv is 32 lowercase hex characters", 400)
    if not isinstance(principal, str) or not principal or len(principal) > 128:
        raise EntryRefused("principal is a key principal's id", 400)
    if not charged_root(reach(db), principal):
        raise EntryRefused("a rotation is recorded only for a charged root", 409)
    share = db.get(KeyCustodyShare, principal)
    if share is not None and not share.rekey_pending:
        raise EntryRefused("Origin holds an activated share for this root: its key is split, "
                           "and a split key is not rotated", 409)
    held = {share.kcv} if share is not None else set()
    held |= {h.kcv for h in db.query(KeyCustodyShareHistory).filter(
        KeyCustodyShareHistory.principal_id == principal)}
    prior = db.get(ChargedRootRotation, principal)
    # The one kcv that may be recorded again (review 33, F2): this root's own pending share,
    # written under an earlier record of this very kcv, whose read-back at Mantle failed. The new
    # record still needs a fresh write before anything is released.
    resplit = (share is not None and share.rekey_pending and share.kcv == kcv
               and prior is not None and prior.kcv == kcv and bool(prior.share_written))
    if kcv in held and not resplit:
        raise EntryRefused("Origin holds or held a share of the key with this kcv: it is no "
                           "freshly rotated key's; run step 21 again and record the new kcv", 409)
    row = prior
    if row is None:
        row = ChargedRootRotation(principal_id=principal, kcv=kcv, recorded_by=str(operator_id))
        db.add(row)
    else:
        row.kcv, row.recorded_by = kcv, str(operator_id)
        row.recorded_time = datetime.now(timezone.utc)
    row.grant_id, row.share_written = None, False
    # The custody grant bound to the record before this one ends with it (review 34), revoked
    # before the new record is committed, in the same transaction (review 35): a grant that lands
    # after the record is bound to it and stays live, and none is bound to it and then revoked.
    end_charged_custody(db, principal)
    db.commit()
    logger.warning("rotation of charged root %s recorded by %s: kcv=%s", principal, operator_id,
                   kcv[:8])
    return {"principal_id": principal, "kcv": kcv}


def _rotation(db: Session, principal: str):
    from origin.models.key_custody import ChargedRootRotation
    return db.get(ChargedRootRotation, str(principal))


def _grant_live(db: Session, grant_id: Optional[str]) -> bool:
    from origin.models.authority_ledger import AuthorityJobGrant

    row = db.get(AuthorityJobGrant, grant_id) if grant_id else None
    if row is None or row.state != _ACTIVE:
        return False
    try:
        return parse_time(row.expires_at) > datetime.now(timezone.utc)
    except ValueError:
        return False


def charged_split_open(db: Session, principal: str) -> bool:
    """Is a charged root's split still open (reviews 31 and 32)? Only while step 21's rotation is
    recorded for it, Origin holds no share for it or only a pending one, and the record has not
    been spent: no grant is bound to it yet, or the one bound to it (the first custody grant made
    after the record, two hours at most) still lives. Once that grant ends, or the share is
    activated, the split is closed until a new record of a fresh kcv."""
    from origin.models.key_custody import KeyCustodyShare

    rot = _rotation(db, principal)
    if rot is None:
        return False
    share = db.get(KeyCustodyShare, principal)
    if share is not None and not share.rekey_pending:
        return False
    return rot.grant_id is None or _grant_live(db, rot.grant_id)


def charged_release_open(db: Session, principal: str) -> bool:
    """May a charged root's share be released now (reviews 31 and 32)? Only while its split is
    open under its live grant, and the pending share Origin holds is the recorded rotated key's
    and was written after the record: the split's read-back, never a share held before."""
    from origin.models.key_custody import KeyCustodyShare

    rot = _rotation(db, principal)
    share = db.get(KeyCustodyShare, principal)
    return (rot is not None and charged_split_open(db, principal) and rot.grant_id is not None
            and bool(rot.share_written) and share is not None and share.kcv == rot.kcv)


def charged_grant_allowed(db: Session, principal: str) -> Optional[str]:
    """Why the operator may not grant `platform.custody` over this charged root now, or None
    (review 32): one grant per record, while its split is open."""
    rot = _rotation(db, principal)
    if rot is None:
        return ("no rotation is recorded for this charged root: run step 21, then record its "
                "rotated key's kcv (POST /oracle/charged-roots/{principal}/rotation)")
    if rot.grant_id is not None:
        return ("this rotation record's split was already granted; once that grant ends, a new "
                "record of a fresh kcv is needed (run step 21 again)")
    if not charged_split_open(db, principal):
        return "Origin holds an activated share of this charged root: its split is done"
    return None


def bind_charged_grant(db: Session, principal: str, grant_id: str) -> bool:
    """Bind `grant_id` to this charged root's record, if no grant is bound yet: one conditional
    update, so of two grants racing past the check only one binds (review 35). True if it did."""
    from sqlalchemy import update

    from origin.models.key_custody import ChargedRootRotation

    result = db.execute(update(ChargedRootRotation)
                        .where(ChargedRootRotation.principal_id == str(principal),
                               ChargedRootRotation.grant_id.is_(None))
                        .values(grant_id=grant_id))
    db.commit()
    db.expire_all()
    return result.rowcount == 1


def note_charged_share_written(db: Session, principal: str) -> None:
    """A share of the recorded kcv was just written for this charged root, under its split."""
    rot = _rotation(db, principal)
    if rot is not None and not rot.share_written:
        rot.share_written = True
        db.commit()


def charged_root_shares(db: Session) -> dict:
    """Step 23's check (review 32): every charged root Origin knows and its share's state, as
    counts and ids. `activated` is done; `pending` is a split not activated (re-run step 21 and
    record a fresh kcv); `none` holds no share (not split: its key was removed, or the split has
    not run)."""
    from origin.models.authority_ledger import AuthorityNode
    from origin.models.key_custody import KeyCustodyShare

    rc = reach(db)
    out = {"activated": [], "pending": [], "none": []}
    for n in db.query(AuthorityNode).filter(AuthorityNode.part_removed_seq.isnot(None)):
        if not charged_root(rc, n.node_id):
            continue
        share = db.get(KeyCustodyShare, n.node_id)
        state = "none" if share is None else ("pending" if share.rekey_pending else "activated")
        out[state].append(n.node_id)
    # Each pending split's case (review 35): a share written under the record and never released
    # since is a read-back that failed (Mantle left the key whole: the same-kcv remedy); one
    # released since may also be an activation that failed (Mantle's log says "is split, but
    # Origin was not told it is active": `--combine` within the grant, never a re-record).
    from origin.models.key_custody import KeyCustodyRelease
    detail = {}
    for pid in out["pending"]:
        rot = _rotation(db, pid)
        released = rot is not None and db.query(KeyCustodyRelease).filter(
            KeyCustodyRelease.principal_id == pid,
            KeyCustodyRelease.released_at >= rot.recorded_time).first() is not None
        detail[pid] = {"share_written": bool(rot and rot.share_written),
                       "released_since_record": bool(released)}
    return {**{k: sorted(v) for k, v in out.items()},
            **{f"{k}_count": len(v) for k, v in out.items()},
            "pending_detail": detail}


def end_charged_custody(db: Session, principal: str) -> int:
    """The split of a charged root's key read back and was activated: every live
    `platform.custody` grant over it is revoked, as the operator's narrowing. Returns how many."""
    from origin.models.authority_ledger import AuthorityJobGrant
    from origin.services.platform_settings_service import settings as _ps

    try:
        operator = str(_ps.get("platform.operator_id") or "")
    except Exception:  # noqa: BLE001 — no settings: no operator to revoke as
        operator = ""
    if not operator:
        return 0
    n = 0
    for row in db.query(AuthorityJobGrant).filter(
            AuthorityJobGrant.job == NON_PERSON_CUSTODY_JOB,
            AuthorityJobGrant.principal == principal,
            AuthorityJobGrant.state == _ACTIVE).all():
        revoke_job_grant(db, row.grant_id, operator, f"split-activated:{principal}")
        n += 1
    return n


def principal_kind(rc: "Reach", principal: str) -> str:
    """What a key principal is, by Origin's replica (reviews 27 and 28): `person` (an Origin
    account), `collection_key` (`ck:<collection>`), `platform` (`platform_principals`), `root` (a
    node the replica knows with no creation parent: a top-level collection or artifact, whose
    master key keys its legacy content), `member` (a node with a creation parent), or
    `unknown`."""
    from origin.services.authority_reach import collection_key_collection

    if collection_key_collection(principal) is not None:
        return "collection_key"
    if rc.r.is_person(principal):
        return "person"
    if principal in platform_principals():
        return "platform"
    if rc.r.root_entry(principal) is not None or rc.r.node(principal) is not None:
        # A node with a creation parent is a member, whose content is keyed under its root's
        # key or its collection's, not under a master key of its own (review 28, I2).
        return "member" if rc.origin_parent(principal) is not None else "root"
    return "unknown"


def _a_root(rc: "Reach", principal: str) -> bool:
    """Is `principal` a root the replica knows (no creation parent), other than a person and the
    platform's own principals: a top-level collection or artifact."""
    if rc.r.is_person(principal) or principal in platform_principals():
        return False
    if rc.r.root_entry(principal) is None and rc.r.node(principal) is None:
        return False
    return rc.origin_parent(principal) is None


def operator_job_grant(db: Session, *, job: str, hours: int, collections: list,
                       operator_id: str, ref: str, principal: Optional[str] = None) -> dict:
    """The operator grants a job for the platform's own principal, or `platform.custody` over a
    non-person principal's key (`non_person_principal`)."""
    from origin import service_identity
    system = service_identity.get_system_principal_id()
    most = 24 * 30
    if principal is not None:
        if job != NON_PERSON_CUSTODY_JOB or collections:
            raise EntryRefused(f"over another principal the operator grants only "
                               f"{NON_PERSON_CUSTODY_JOB}, over its key alone", 400)
        system = non_person_principal(db, principal)
        if charged_root(reach(db), principal):
            # Review 31: only over the key step 21 rotated, recorded first, and only for the
            # split and its read-back.
            why = charged_grant_allowed(db, principal)
            if why:
                raise EntryRefused(why, 409)
            most = CHARGED_CUSTODY_MAX_HOURS
    if not system:
        raise EntryRefused("no platform system principal on this node", 409)
    until = datetime.now(timezone.utc) + timedelta(hours=max(1, min(int(hours), most)))
    gid = "jg-" + secrets.token_hex(8)
    receipt = append(db, {"kind": "job_grant", "grant_id": gid, "job": job, "principal": system,
                          "collections": list(collections), "expires_at": until.isoformat(),
                          "state": _ACTIVE}, actor=Actor(operator_id, "operator", ref),
                     submitted_jti=f"console:{ref}")
    if most == CHARGED_CUSTODY_MAX_HOURS and principal is not None:
        # The one grant this record's split runs under. A grant that lost the race to bind is
        # revoked at once and refused.
        if not bind_charged_grant(db, principal, gid):
            revoke_job_grant(db, gid, operator_id, f"unbound:{principal}")
            raise EntryRefused("another custody grant is already bound to this rotation record; "
                               "this one is revoked", 409)
    return receipt


def revoke_job_grant(db: Session, grant_id: str, operator_id: str, ref: str) -> Optional[dict]:
    from origin.models.authority_ledger import AuthorityJobGrant
    row = db.get(AuthorityJobGrant, grant_id)
    if row is None:
        raise EntryRefused("no such job grant", 404)
    v = job_grant_view(row)
    return append(db, {"kind": "job_grant", "grant_id": grant_id, "job": v["job"],
                       "principal": v["principal"], "collections": v["collections"],
                       "expires_at": v["expires_at"], "state": "revoked"},
                  actor=Actor(operator_id, "operator", ref), submitted_jti=f"console:{ref}")


def retire_root(db: Session, principal_id: str, operator_id: str, ref: str) -> list:
    """The operator clears a planted root or node so its id can be created again: every live
    allow grant on it revoked, every edge to or from it removed, then the root and node retired,
    each the operator's own entry. Returns the receipts (none when nothing is there)."""
    receipts = []
    actor = Actor(operator_id, "operator", ref)
    from origin.services.platform_settings_service import settings as _ps
    try:
        pinned = _ps.get("platform.authority_collection_id")
    except Exception:  # noqa: BLE001 — no settings: nothing pinned
        pinned = None
    if pinned and str(pinned) == principal_id:
        raise EntryRefused("this is the pinned Authorities collection; re-pin first", 409)
    # Its planted denies go first, by the operator's settling, then its live allow grants.
    for g in db.query(AuthorityGrant).filter(AuthorityGrant.resource_id == principal_id,
                                             AuthorityGrant.state == "active",
                                             AuthorityGrant.effect == "deny").all():
        cur = _grant_of(g)
        receipts.append(append(db, {
            "kind": "grant", "grant_id": cur.id, "grantee_id": cur.grantee_id,
            "grantee_type": cur.grantee_type, "resource_id": cur.resource_id,
            "actions": sorted(cur.actions), "effect": "deny", "state": "retired",
            "expires_at": cur.expires_at, "target": None, "max_claims": None},
            actor=actor, submitted_jti=f"console:{ref}", retiring=principal_id))
    for g in db.query(AuthorityGrant).filter(AuthorityGrant.resource_id == principal_id,
                                             AuthorityGrant.state == "active",
                                             AuthorityGrant.effect == "allow").all():
        cur = _grant_of(g)
        receipts.append(append(db, {
            "kind": "grant", "grant_id": cur.id, "grantee_id": cur.grantee_id,
            "grantee_type": cur.grantee_type, "resource_id": cur.resource_id,
            "actions": sorted(cur.actions), "effect": cur.effect, "state": "revoked",
            "expires_at": cur.expires_at,
            "target": ({"kind": cur.target_kind, "digest": cur.target_digest}
                       if cur.target_kind else None),
            "max_claims": cur.max_claims}, actor=actor, submitted_jti=f"console:{ref}"))
    edges = (db.query(AuthorityEdge).filter((AuthorityEdge.src == principal_id)
                                            | (AuthorityEdge.dst == principal_id)).all())
    for e in edges:
        receipts.append(append(db, {"kind": "edge.remove", "src": e.src, "dst": e.dst},
                               actor=actor, submitted_jti=f"console:{ref}"))
    r = append(db, {"kind": "root.retire", "principal_id": principal_id}, actor=actor,
               submitted_jti=f"console:{ref}")
    if r.get("seq") is not None and r.get("outcome") == "appended":
        receipts.append(r)
    _retire_key_shares(db, principal_id)
    return receipts


def _retire_key_shares(db: Session, principal_id: str) -> None:
    """What a retired id owns at Origin goes with it (review 16, I4): its live key shares, its own
    master key's and its collection key's (`ck:<id>`). An id created again after the retire starts
    with no share, so it inherits no key. The share history stays, as the record of what was."""
    from origin.models.key_custody import KeyCustodyShare
    for pid in (principal_id, f"ck:{principal_id}"):
        row = db.get(KeyCustodyShare, pid)
        if row is not None:
            db.delete(row)
            logger.warning("retired id %s: its key share %s is removed", principal_id, pid)
    db.commit()


def resolve_unconfirmed(db: Session, seq: int, decision: str, operator_id: str,
                        ref: str) -> dict:
    """The operator settles an unconfirmed entry: `withdraw` appends the narrowing inverse as the
    operator's entry; `keep` records that the write is to stand. Either way the entry is marked
    resolved, so Mantle's due withdrawal of it clears (410)."""
    row = db.get(AuthorityEntry, int(seq))
    if row is None or row.confirmed or row.resolved_by:
        raise EntryRefused(f"entry {seq} is not pending", 409)
    receipt = None
    if decision == "withdraw":
        b = json.loads(row.body)
        if row.kind == "grant":
            receipt = revoke_entry(db, seq, operator_id, ref) if b.get("state") == "active" \
                and b.get("effect") == "allow" else _withdraw_deny(db, row, b, operator_id, ref)
        elif row.kind == "edge.add":
            receipt = revoke_entry(db, seq, operator_id, ref)
    elif decision != "keep":
        raise EntryRefused("decision is withdraw or keep", 400)
    row = db.get(AuthorityEntry, int(seq))
    row.resolved_by, row.resolved_at = operator_id, datetime.now(timezone.utc)
    db.commit()
    return {"seq": int(seq), "decision": decision, "receipt": receipt}


def _withdraw_deny(db: Session, row, b: dict, operator_id: str, ref: str) -> Optional[dict]:
    """An unconfirmed deny (its write never committed at Mantle), withdrawn by the operator."""
    cur = db.get(AuthorityGrant, b["grant_id"])
    if cur is None or cur.seq != row.seq:
        return None
    return append(db, {**b, "state": "retired"}, actor=Actor(operator_id, "operator", ref),
                  submitted_jti=f"console:{ref}", compensates=row.seq, settle=True)


def decide(db: Session, ctx: Context, body: dict) -> Optional[str]:
    """Why `ctx.actor` may make this change (a short reason), None when it changes nothing, or
    `EntryRefused`."""
    b = normalise(body)
    ctx.db = db
    if ctx.kind == "background":
        return _decide_background(db, ctx, b)
    if ctx.compensates is not None:
        return _decide_compensation(db, ctx, b)
    if ctx.kind == "operator":
        return _decide_operator(reach(db), ctx, b)
    if ctx.kind == "narrowed":
        return _decide_narrowed(reach(db), ctx, b)
    if ctx.kind == PERSONA:
        return _decide_persona(reach(db), ctx, b)
    return _DECIDE[b["kind"]](reach(db), ctx, b)


def _decide_background(db: Session, ctx: Context, b: dict) -> Optional[str]:
    """A background delegation (the system principal's `ledger.retry` job) makes no change of its
    own (review 16). It restates what Origin already holds (answered unchanged), or re-submits
    Mantle's outstanding withdrawal of a secondary edge, within the collections its job grant
    lists. It never narrows a mask, demotes or removes a creation edge, or retires a grant: an
    unconfirmed entry like that is the operator's to resolve (`resolve_unconfirmed`)."""
    if ctx.compensates is None:
        why = _DECIDE[b["kind"]](reach(db), ctx, b)
        if why is None:
            return None
        raise EntryRefused("a background delegation makes no change of its own; it only "
                           "re-submits what was already decided")
    row = db.get(AuthorityEntry, int(ctx.compensates))
    orig = json.loads(row.body) if row is not None else {}
    if row is None or row.kind != "edge.add" or orig.get("origin"):
        raise EntryRefused("a background delegation re-submits only the withdrawal of a "
                           "secondary edge; anything else unconfirmed is the operator's to "
                           "resolve")
    if orig.get("src") not in ctx.collections:
        raise EntryRefused("a background delegation acts only within the collections its job "
                           "grant lists")
    return _decide_compensation(db, ctx, b)


def _decide_narrowed(rc: Reach, ctx: Context, b: dict) -> Optional[str]:
    """Ember's narrowed delegation acts for its person only in its scopes (John, 2026-11-02):
    `ember:memory` creates a member in the person's own memory collection (the creation edge and
    the member's creation grant, in the same batch). Ember never makes the memory collection (the
    person's own token does, at sign-in), never makes
    or changes any other grant (sharing is the person's own act, in their own session), and never
    opens a key."""
    actor, kind = ctx.actor, b["kind"]
    mid = memory_collection_id(actor)
    memory = "ember:memory" in ctx.scopes
    if memory and kind == "edge.add" and b["src"] == mid and b["origin"] \
            and rc.r.edge(b["src"], b["dst"]) is None and not _seen(rc, b["dst"]) \
            and _seen(rc, mid):
        return _decide_edge_add(rc, ctx, b)
    if memory and kind == "grant":
        new = _grant_from_body(b)
        prior = rc.r.grant(new.id)
        parent = rc.origin_parent(new.resource_id)
        if prior is None and new.grantee_id == actor and new.grantee_type == "user" \
                and parent is not None and parent[0] == mid and new.resource_id != mid:
            why = _creation_grant(rc, ctx, new)
            if why:
                return why
    raise EntryRefused(f"a narrowed delegation does not make this {kind} change: it acts only "
                       f"for its scopes {list(ctx.scopes)}, and never makes the memory "
                       f"collection or a share")


#: The actor kind of a persona's own delegation (`use_verdict.verify_persona_credential`, kind
#: `person`): the server delegation a persona calls Mantle on for its person (review 26, L5).
PERSONA = "persona"


def _decide_persona(rc: Reach, ctx: Context, b: dict) -> Optional[str]:
    """A persona acts for its person on the one path a persona's routes need (review 26, L5): it
    creates a member (a memory, a note) by its creation edge in a collection its person reaches for
    Create or Add (`_decide_edge_add`, as for the person), and gives its person the creation grant
    on that member in the same batch, no wider than the person's own reach (`_creation_grant`).
    It makes no root, no share, no deny, no edge removal and no change to what an edge conducts,
    and it never opens a key."""
    kind = b["kind"]
    if kind == "edge.add" and b["origin"] and rc.r.edge(b["src"], b["dst"]) is None             and not _seen(rc, b["dst"]):
        return _decide_edge_add(rc, ctx, b)
    if kind == "grant":
        new = _grant_from_body(b)
        if rc.r.grant(new.id) is None:
            why = _creation_grant(rc, ctx, new)
            if why:
                return why
    raise EntryRefused(f"a persona's delegation does not make this {kind} change: it makes only "
                       f"a new member for its person, by its creation edge, and its person's "
                       f"creation grant on it")


def _operator_only():
    raise EntryRefused("no one confirms a root empty any more; a charged root's key is rotated "
                       "at step 21", 403)


def _decide_operator(rc: Reach, ctx: "Context", b: dict) -> Optional[str]:
    """The operator, through the console, revokes or removes; they never widen reach. They also
    retire a planted root or node (its grants revoked and its edges removed first, as their own
    entries)."""
    if b["kind"] == "root.confirm_empty":
        raise EntryRefused("a charged root is no longer confirmed: its key is rotated at step 21 "
                           "and opens for its own principal alone", 409)
    if b["kind"] == "root.retire":
        pid = b["principal_id"]
        if rc.r.root_entry(pid) is None and rc.r.node(pid) is None:
            return None
        if rc.r.has_edges(pid) or any(g.state == _ACTIVE and g.effect == "allow"
                                      for g in rc.r.grants_on(pid)):
            raise EntryRefused("revoke its grants and remove its edges first", 409)
        return "the operator retires a root"
    if b["kind"] == "job_grant":
        from origin import service_identity
        prior = rc.r.job_grant(b["grant_id"])
        if prior is not None:
            if prior["state"] == b["state"]:
                return None
            if b["state"] == "revoked":
                return "the operator revokes a job grant"
            raise EntryRefused("a revoked job grant stays revoked", 409)
        system = service_identity.get_system_principal_id()
        if (system and b["principal"] != system and b["job"] == NON_PERSON_CUSTODY_JOB
                and not b["collections"] and ctx.db is not None):
            # The split of a non-person principal's key (review 26, H1): never a person's or a
            # collection's.
            non_person_principal(ctx.db, b["principal"])
            return "the operator grants the split of a non-person principal's key"
        if not system or b["principal"] != system:
            raise EntryRefused("the operator grants jobs for the platform's own principal only; "
                               "a person or an Admin grants them over their own keys", 403)
        missing = [c for c in b["collections"] if not _admin_and_read(rc, system, c)]
        if missing:
            raise EntryRefused(f"the platform principal holds no Admin and Read on {missing}: the "
                               "operator's job grants cover only the platform's own collections",
                               403)
        return "the operator grants a job for the platform's own principal"
    if b["kind"] == "edge.remove":
        return None if rc.r.edge(b["src"], b["dst"]) is None else "the operator removes an edge"
    if b["kind"] == "grant":
        prior = rc.r.grant(b["grant_id"])
        new = _grant_from_body(b)
        if (prior is not None and ctx.retiring and prior.resource_id == ctx.retiring
                and prior.effect == "deny" and new.state != _ACTIVE
                and _structure_key(prior) == _structure_key(new)):
            return "a planted deny goes with the root the operator retires"
        if prior is None or _widens(prior, new) or _structure_key(prior) != _structure_key(new):
            raise EntryRefused("the operator only revokes a grant here", 403)
        return "the operator revokes a grant"
    raise EntryRefused("the operator only revokes grants and removes edges here", 403)


def _structure_key(g) -> tuple:
    return (g.resource_id, g.grantee_id, g.grantee_type)


# -- applying an entry to the replica ------------------------------------------------------------

def _node(db: Session, node_id: str, created_by: str, seq: int) -> None:
    if db.get(AuthorityNode, node_id) is None:
        db.add(AuthorityNode(node_id=node_id, created_by=created_by, seq=seq, member=False))
        db.flush()


def _alert_job_grant(db: Session, b: dict, seq: int, actor: str, why: str) -> None:
    """Every job grant made raises an operator alert (review 9, H2): a job may now open the key it
    names while the person is away."""
    if b.get("state") != _ACTIVE:
        return
    from origin.models.authority_ledger import OperatorAlert
    detail = (f"job {b['job']} granted over {b['principal']} "
              f"(collections {','.join(b['collections']) or 'none'}) until {b['expires_at']} "
              f"by {actor} (entry {seq}, {why})")
    db.add(OperatorAlert(kind="job_grant", seq=seq, resource_id=b["grant_id"],
                         subject=b["principal"], actor=actor, detail=detail))
    logger.warning("operator alert job_grant: %s", detail)
    db.commit()


def _one_seed_batch(db: Session, jti: str, batch: Optional[str]) -> None:
    """A seed credential writes one batch: the first it opened (review 11)."""
    from origin.models.key_custody import SeedCredential

    row = db.get(SeedCredential, jti)
    if row is None:
        return
    if row.first_batch is None:
        row.first_batch = batch
        db.commit()
    elif row.first_batch != batch:
        raise EntryRefused("a seed credential writes one batch; mint another for another pass")


def _in_seed_plan(db: Session, jti: str, body: dict) -> None:
    """A seed credential makes only the entries its pass planned when it was minted (review 25,
    M4), each named by `body_digest`; a seed minted with no plan makes none."""
    import json as _json

    from origin.models.key_custody import SeedCredential

    row = db.get(SeedCredential, jti)
    plan = set(_json.loads(row.plan or "[]")) if row is not None else set()
    if body_digest(body) not in plan:
        raise EntryRefused("this entry is outside the seed's plan: a seed makes only the entries "
                           "its pass planned when it was minted")


def _alert_seed_grant(db: Session, b: dict, seq: int, ref: str) -> None:
    """Every grant made on a seed credential raises an operator alert (review 25, M4)."""
    from origin.models.authority_ledger import OperatorAlert

    detail = (f"seed {ref}: {b['grantee_type']} {b['grantee_id']} granted "
              f"{','.join(b.get('actions', ()))} ({b.get('effect')}) on {b['resource_id']} "
              f"(entry {seq})")
    db.add(OperatorAlert(kind="seed_grant", seq=seq, resource_id=b["grant_id"],
                         subject=b["grantee_id"], actor=ref, detail=detail))
    db.commit()
    logger.warning("operator alert seed_grant: %s", detail)


def _alert(db: Session, b: dict, seq: int, actor: str, why: str, *, bootstrap: bool = False,
           ref: str = "") -> None:
    """Raise the operator alerts this appended entry calls for (John, 2026-11-02): a live allow
    grant carrying Admin, and any live allow grant on the Authorities collection Origin has
    pinned (a platform-admin appointment, or a grant on its way to one). Recorded in
    `operator_alerts`, which the console lists, and logged. An alert never refuses the entry."""
    if b.get("kind") == "job_grant":
        _alert_job_grant(db, b, seq, actor, why)
        return
    if b.get("kind") != "grant" or b.get("effect") != "allow" or b.get("state") != _ACTIVE:
        return
    from origin.models.authority_ledger import OperatorAlert
    from origin.services.platform_settings_service import settings as platform_settings

    try:
        authorities = platform_settings.get("platform.authority_collection_id")
    except Exception:  # noqa: BLE001 — no settings loaded: no appointment to name
        authorities = None
    if str(why or "").startswith("the creation grant") and not (
            authorities and b["resource_id"] == str(authorities)):
        return                           # a creator's own grant, in the batch that created it
    kinds = []
    platform = bool(authorities) and b["resource_id"] == str(authorities)
    if "admin" in b.get("actions", ()):
        if bootstrap and not platform:
            # A bootstrap states hundreds of grants: one summary per bootstrap credential, its
            # count kept current, and the platform-relevant ones raised on their own below.
            _bootstrap_summary(db, b, seq, actor, ref)
        else:
            kinds.append("admin_grant")
    if platform:
        kinds.append("platform_admin")
    for kind in kinds:
        detail = (f"{b['grantee_type']} {b['grantee_id']} holds {','.join(b['actions'])} on "
                  f"{b['resource_id']} (entry {seq}, {why})")
        db.add(OperatorAlert(kind=kind, seq=seq, resource_id=b["resource_id"],
                             subject=b["grantee_id"], actor=actor, detail=detail))
        logger.warning("operator alert %s: %s", kind, detail)
    if kinds:
        db.commit()


def _bootstrap_summary(db: Session, b: dict, seq: int, actor: str, ref: str) -> None:
    from origin.models.authority_ledger import OperatorAlert

    key = f"bootstrap:{ref}"
    row = (db.query(OperatorAlert).filter(OperatorAlert.kind == "bootstrap_admin_summary",
                                          OperatorAlert.resource_id == key).first())
    if row is None:
        row = OperatorAlert(kind="bootstrap_admin_summary", seq=seq, resource_id=key,
                            subject="", actor=actor, detail="")
        db.add(row)
        count = 0
    else:
        count = int((row.detail or "0").split(" ", 1)[0] or 0)
    count += 1
    row.detail = (f"{count} grant(s) carrying Admin stated by bootstrap credential {ref} "
                  f"(last: {b['grantee_id']} on {b['resource_id']}, entry {seq})")
    db.commit()


def pinned_admin_alerts(db: Session, collection_id: str, operator_id: str) -> int:
    """Pinning `collection_id` as the Authorities collection appoints every person holding live
    Admin on it: one platform_admin alert each. Returns how many."""
    from origin.models.authority_ledger import OperatorAlert

    admins = collection_admins(db, collection_id)
    for person in admins:
        db.add(OperatorAlert(kind="platform_admin", seq=0, resource_id=collection_id,
                             subject=person, actor=operator_id,
                             detail=f"{person} is a platform admin: {collection_id} was pinned as "
                                    f"the Authorities collection"))
        logger.warning("operator alert platform_admin: %s on pinned %s", person, collection_id)
    db.commit()
    return len(admins)


def collection_admins(db: Session, collection_id: str) -> list:
    """Every person holding a live, unexpired allow grant carrying Admin on the collection."""
    from origin.services.authority_reach import unexpired

    rc = reach(db)
    out = []
    for g in db.query(AuthorityGrant).filter(AuthorityGrant.resource_id == collection_id,
                                             AuthorityGrant.state == _ACTIVE,
                                             AuthorityGrant.effect == "allow",
                                             AuthorityGrant.grantee_type == "user"):
        if "admin" in (g.actions or "").split(",") and unexpired(g.expires_at) \
                and rc.r.is_person(g.grantee_id) and g.grantee_id not in out:
            out.append(g.grantee_id)
    return sorted(out)


def collection_view(db: Session, collection_id: str) -> Optional[dict]:
    """Origin's own view of a collection: its root and node as the replica holds them, and who
    holds Admin. None when the replica does not know it."""
    rc = reach(db)
    node = rc.r.node(collection_id)
    if node is None:
        return None
    return {"collection_id": collection_id, "root": rc.r.root_entry(collection_id),
            "created_by": node.get("created_by"), "admins": collection_admins(db, collection_id)}


def alerts(db: Session, *, include_acknowledged: bool = False) -> list:
    from origin.models.authority_ledger import OperatorAlert

    q = db.query(OperatorAlert)
    if not include_acknowledged:
        q = q.filter(OperatorAlert.acknowledged_at.is_(None))
    return [{"id": a.id, "kind": a.kind, "seq": a.seq, "resource_id": a.resource_id,
             "subject": a.subject, "actor": a.actor, "detail": a.detail,
             "created_time": _aware(a.created_time).isoformat(),
             "acknowledged_by": a.acknowledged_by}
            for a in q.order_by(OperatorAlert.id)]


def acknowledge_alert(db: Session, alert_id: int, operator_id: str) -> bool:
    from origin.models.authority_ledger import OperatorAlert

    a = db.get(OperatorAlert, int(alert_id))
    if a is None:
        return False
    if a.acknowledged_at is None:
        a.acknowledged_by, a.acknowledged_at = operator_id, datetime.now(timezone.utc)
        db.commit()
    return True


def _apply(db: Session, b: dict, seq: int, ctx: Context) -> None:
    kind = b["kind"]
    creator = "" if ctx.bootstrap else ctx.actor
    if kind == "grant":
        if ctx.bootstrap:
            _node(db, b["resource_id"], "", seq)
        row = db.get(AuthorityGrant, b["grant_id"])
        if row is None:
            row = AuthorityGrant(grant_id=b["grant_id"], created_by=creator,
                                 claimed_from=ctx.claimed_from)
            db.add(row)
        row.grantee_id, row.grantee_type = b["grantee_id"], b["grantee_type"]
        row.resource_id, row.actions = b["resource_id"], ",".join(b["actions"])
        row.effect, row.state, row.expires_at = b["effect"], b["state"], b["expires_at"]
        t = b.get("target") or {}
        row.target_kind, row.target_digest = t.get("kind"), t.get("digest")
        row.max_claims = b.get("max_claims")
        row.seq = seq
    elif kind == "edge.add":
        if ctx.bootstrap:
            _node(db, b["src"], "", seq)
            _node(db, b["dst"], "", seq)
        elif b["origin"]:
            _node(db, b["dst"], creator, seq)            # its creation
        if b["origin"]:
            db.get(AuthorityNode, b["dst"]).member = True
        row = db.get(AuthorityEdge, (b["src"], b["dst"]))
        if row is not None and row.origin and not b["origin"] and ctx.compensates is None:
            # A demotion (an older Origin took one; this one refuses it, review 30) deleted its
            # member as a removal does: charged the same way, as `replay` and 0029 charge it.
            _charge(db, b["src"], seq)
        if row is None:
            row = AuthorityEdge(src=b["src"], dst=b["dst"], added_by=creator)
            db.add(row)
        row.origin = b["origin"]
        row.propagate = None if b["propagate"] is None else json.dumps(b["propagate"])
        row.seq = seq
    elif kind == "edge.remove":
        row = db.get(AuthorityEdge, (b["src"], b["dst"]))
        if row is not None:
            if row.origin and ctx.compensates is None:
                # A node under a root goes (review 29, M1): its root's master key opens for its own
                # principal alone, for good. The withdrawal of a creation whose write never
                # committed removes nothing of the root, and charges nothing (review 31).
                _charge(db, b["src"], seq)
            db.delete(row)
    elif kind == "root.confirm_empty":
        node = db.get(AuthorityNode, b["principal_id"])
        if node is not None:
            node.confirmed_empty_seq = seq
    elif kind == "drop_key":
        return                              # retired: an old entry applies nothing
    elif kind == "job_grant":
        from origin.models.authority_ledger import AuthorityJobGrant
        row = db.get(AuthorityJobGrant, b["grant_id"])
        if row is None:
            row = AuthorityJobGrant(grant_id=b["grant_id"], created_by=creator)
            db.add(row)
        row.job, row.principal = b["job"], b["principal"]
        row.collections, row.expires_at = json.dumps(b["collections"]), b["expires_at"]
        row.state, row.seq = b["state"], seq
    elif kind == "root.retire":
        for model in (AuthorityRoot, AuthorityNode):
            row = db.get(model, b["principal_id"])
            if row is not None:
                db.delete(row)
        db.flush()
    else:
        _node(db, b["principal_id"], creator, seq)
        db.add(AuthorityRoot(principal_id=b["principal_id"], root_id=b["root_id"],
                             registered_by=creator, seq=seq))


def _charge(db: Session, src: str, seq: int) -> None:
    """Charge the root `src` sits under now with entry `seq`'s removal of a part of it."""
    node = db.get(AuthorityNode, Reach(SqlReplica(db)).root_of(src))
    if node is not None:
        node.part_removed_seq = seq


def _last_seq_for(db: Session, b: dict) -> Optional[int]:
    kind = b["kind"]
    if kind == "grant":
        row = db.get(AuthorityGrant, b["grant_id"])
    elif kind == "edge.add":
        row = db.get(AuthorityEdge, (b["src"], b["dst"]))
    elif kind == "root":
        row = db.get(AuthorityRoot, b["principal_id"])
    elif kind == "job_grant":
        from origin.models.authority_ledger import AuthorityJobGrant
        row = db.get(AuthorityJobGrant, b["grant_id"])
    else:
        row = None
    return row.seq if row is not None else None


# -- hashing and co-signing -----------------------------------------------------------------------

def entry_hash(*, seq: int, prev_hash: str, body: dict, actor: str, credential_kind: str,
               credential_ref: str, bootstrap: bool, compensates: Optional[int], kid: str,
               claimed_from: Optional[str] = None) -> str:
    envelope = {"v": LEDGER_VERSION, "seq": seq, "prev": prev_hash, "body": body,
                "actor": actor, "credential_kind": credential_kind,
                "credential_ref": credential_ref, "bootstrap": bool(bootstrap),
                "compensates": compensates, "kid": kid, "claimed_from": claimed_from}
    return hashlib.sha256(canonical(envelope).encode("utf-8")).hexdigest()


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def current_kid() -> str:
    from origin.key_manager import get_key_id
    return get_key_id()


def cosign(db: Session, digest: str) -> str:
    """Origin's RS256 signature over the entry hash, and the public key recorded by kid so the
    entry still verifies after the key is rotated."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    from origin.key_manager import get_private_key_pem, get_public_key_pem

    kid = current_kid()
    if db.get(AuthoritySigningKey, kid) is None:
        db.add(AuthoritySigningKey(kid=kid, public_pem=get_public_key_pem()))
    key = serialization.load_pem_private_key(get_private_key_pem().encode(), password=None)
    return _b64u(key.sign(digest.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()))


def verify_cosignature(digest: str, signature: str, public_pem: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    key = serialization.load_pem_public_key(public_pem.encode())
    try:
        key.verify(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)),
                   digest.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


def head(db: Session) -> Tuple[int, str]:
    row = db.query(AuthorityEntry).order_by(AuthorityEntry.seq.desc()).first()
    return (row.seq, row.entry_hash) if row else (0, GENESIS)


def _receipt(row: AuthorityEntry, outcome: str) -> dict:
    """The receipt, with the ledger's head at answer time (`head_seq`), which Mantle records
    and checks never goes backwards."""
    from sqlalchemy.orm import object_session
    db = object_session(row)
    head_seq = head(db)[0] if db is not None else row.seq
    return {"outcome": outcome, "seq": row.seq, "entry_hash": row.entry_hash,
            "prev_hash": row.prev_hash, "signature": row.signature, "kid": row.kid,
            "head_seq": head_seq}


@dataclass(frozen=True)
class Actor:
    subject: str
    kind: str
    ref: str
    scopes: tuple = ()
    #: A background delegation's collections, as its job grant lists them (review 16).
    collections: tuple = ()


def append(db: Session, body: dict, *, actor: Actor, submitted_jti: str = "",
           bootstrap: bool = False, proof: Optional[dict] = None,
           compensates: Optional[int] = None, window_ids: Optional[list] = None,
           batch: Optional[str] = None, submitted_by: Optional[str] = None,
           settle: bool = False, retiring: Optional[str] = None) -> dict:
    """Decide, append, co-sign and apply one entry. Returns its receipt
    (`{"outcome": "appended" | "unchanged", "seq", "entry_hash", "prev_hash", "signature",
    "kid"}`; an unchanged edge removal has no seq)."""
    b = normalise(body)
    if not bootstrap and compensates is None and actor.kind not in ("operator",):
        batch = open_batch(db, batch, actor.ref)
    if actor.kind == "seed" and compensates is None:
        _one_seed_batch(db, actor.ref, batch)
        _in_seed_plan(db, actor.ref, body)
    for _ in range(3):
        ctx = Context(actor=actor.subject, kind=actor.kind, ref=actor.ref, bootstrap=bootstrap,
                      proof=proof, compensates=compensates, batch=batch, settle=settle,
                      retiring=retiring,
                      scopes=tuple(getattr(actor, "scopes", ()) or ()),
                      collections=tuple(getattr(actor, "collections", ()) or ()))
        if bootstrap:
            _bootstrap_allowed(db, b, window_ids)
        why = decide(db, ctx, b)
        if compensates is not None and ctx.restored is not None:
            b = ctx.restored                  # what is appended is the row's prior state
        if why is None:
            seq = _last_seq_for(db, b)
            row = db.get(AuthorityEntry, seq) if seq else None
            if row is None:
                return {"outcome": "unchanged", "seq": None, "batch": batch}
            return {**_receipt(row, "unchanged"), "batch": batch}
        last, prev = head(db)
        seq = last + 1
        kid = current_kid()
        digest = entry_hash(seq=seq, prev_hash=prev, body=b, actor=actor.subject,
                            credential_kind=actor.kind, credential_ref=actor.ref,
                            bootstrap=bootstrap, compensates=compensates, kid=kid,
                            claimed_from=ctx.claimed_from)
        signature = cosign(db, digest)
        row = AuthorityEntry(seq=seq, kind=b["kind"], body=canonical(b), actor=actor.subject,
                             credential_kind=actor.kind, credential_ref=actor.ref,
                             bootstrap=bool(bootstrap), compensates=compensates,
                             claimed_from=ctx.claimed_from, submitted_jti=submitted_jti or "", body_sha256=body_digest(b),
                             prev_hash=prev, entry_hash=digest, signature=signature, kid=kid,
                             # A bootstrap restates what is written; a withdrawal is final.
                             confirmed=(bool(bootstrap) or compensates is not None
                                        or actor.kind in ("operator", ORIGIN_PAGE,
                                                          ORIGIN_SESSION)),
                             batch=batch, submitted_by=submitted_by)
        db.add(row)
        _apply(db, b, seq, ctx)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()                     # another append took this seq; decide again
            continue
        logger.info("authority entry %d appended: %s by %s (%s)", seq, b["kind"],
                    actor.subject, why)
        _alert(db, b, seq, actor.subject, why, bootstrap=bool(bootstrap), ref=actor.ref)
        if actor.kind == "seed" and b.get("kind") == "grant":
            _alert_seed_grant(db, b, seq, actor.ref)
        return {**_receipt(row, "appended"), "batch": batch}
    raise EntryRefused("the ledger head moved three times; try again", 409)


# -- the bootstrap credential ----------------------------------------------------------------------

def _entry_ids(b: dict) -> list:
    if b["kind"] == "grant":
        return [b["grant_id"], b["resource_id"]]
    if b["kind"] in ("edge.add", "edge.remove"):
        return [b["src"], b["dst"]]
    if b["kind"] == "drop_key":
        return [b["collection_id"]]
    if b["kind"] == "job_grant":
        return [b["grant_id"], b["principal"]]
    return [b["principal_id"]]


def _bootstrap_allowed(db: Session, b: dict, window_ids: Optional[list]) -> None:
    """A bootstrap entry states what Mantle held before the ledger, for ids no ordinary entry
    has touched. Once the ledger has ordinary entries, only the ids the operator listed when
    re-opening it are accepted."""
    for nid in _entry_ids(b):
        node = db.get(AuthorityNode, nid)
        if node is not None and node.created_by:
            raise EntryRefused(f"{nid!r} is an id the ledger already holds; a bootstrap states "
                               f"only what it has not seen")
    grant = db.get(AuthorityGrant, b["grant_id"]) if b["kind"] == "grant" else None
    if grant is not None and grant.created_by:
        raise EntryRefused("a grant the ledger already holds is not restated by a bootstrap")
    if b["kind"] in ("edge.add", "edge.remove"):
        edge = db.get(AuthorityEdge, (b["src"], b["dst"]))
        if edge is not None and edge.added_by:
            raise EntryRefused("an edge the ledger already holds is not restated by a bootstrap")
    listed = set(window_ids or ())
    if listed and not set(_entry_ids(b)) <= listed:
        raise EntryRefused("a bootstrap window that lists ids states those ids only")
    ordinary = db.query(AuthorityEntry).filter(AuthorityEntry.bootstrap.is_(False)).first()
    if ordinary is not None:
        if not listed:
            raise EntryRefused("the ledger has ordinary entries; a bootstrap is accepted only "
                               "for the ids the operator listed when re-opening it")

def _aware(t):
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def issue_bootstrap_credential(db: Session, operator_id: str, minutes: int = 60,
                               ids: Optional[list] = None) -> dict:
    """A credential for bootstrap entries and nothing else: `scope=authority.bootstrap`,
    `aud=origin`, an hour at most, recorded by `jti`, withdrawn by `close_bootstrap`.
    `verify_share_credential` refuses it as an acting credential."""
    import secrets

    from origin.services.auth_service import issue_system_delegation_token

    minutes = max(1, min(int(minutes), MAX_BOOTSTRAP_MINUTES))
    jti = secrets.token_hex(16)
    expires = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    token = issue_system_delegation_token(operator_id, actor=operator_id, scope=BOOTSTRAP_SCOPE,
                                          audience="origin", ttl_seconds=minutes * 60, jti=jti)
    db.add(AuthorityBootstrapWindow(id=jti, opened_by=operator_id, expires_at=expires,
                                    ids=json.dumps(sorted(set(ids))) if ids else None))
    db.commit()
    return {"token": token, "id": jti, "expires_at": expires.isoformat(timespec="seconds")}


def verify_bootstrap_credential(db: Session, token: str, operator_id: Optional[str]) -> str:
    """The operator id the bootstrap credential speaks for, or `EntryRefused`. See
    `bootstrap_window` for the ids it is good for."""
    from origin import config
    from origin.services.auth_verifier import verify_token

    payload = verify_token(token or "") or {}
    if (payload.get("iss") != config.AUTHORITY_ISSUER or payload.get("scope") != BOOTSTRAP_SCOPE
            or payload.get("aud") != "origin"):
        raise EntryRefused("a bootstrap entry needs the operator's bootstrap credential")
    row = db.get(AuthorityBootstrapWindow, str(payload.get("jti") or ""))
    if row is None or row.closed_at is not None or _aware(row.expires_at) <= datetime.now(
            timezone.utc):
        raise EntryRefused("the bootstrap credential is withdrawn or expired")
    if not operator_id or payload.get("sub") != str(operator_id) or row.opened_by != str(
            operator_id):
        raise EntryRefused("the bootstrap credential is not the current operator's")
    return str(operator_id)


def bootstrap_window(db: Session, token: str) -> AuthorityBootstrapWindow:
    from jose import jwt as jose_jwt
    return db.get(AuthorityBootstrapWindow, str(jose_jwt.get_unverified_claims(token).get("jti")))


def finish_bootstrap(db: Session, token: str) -> None:
    """The batch the credential was issued for is done: it is good for nothing more."""
    w = bootstrap_window(db, token)
    if w is not None and w.closed_at is None:
        w.closed_at = datetime.now(timezone.utc)
        db.commit()


def close_bootstrap(db: Session) -> int:
    rows = (db.query(AuthorityBootstrapWindow)
            .filter(AuthorityBootstrapWindow.closed_at.is_(None)).all())
    for r in rows:
        r.closed_at = datetime.now(timezone.utc)
    db.commit()
    return len(rows)


# -- verification ----------------------------------------------------------------------------------

def _signing_keys(db: Session) -> Dict[str, str]:
    keys = {r.kid: r.public_pem for r in db.query(AuthoritySigningKey)}
    try:
        from origin.key_manager import get_public_key_pem
        keys.setdefault(current_kid(), get_public_key_pem())
    except Exception:  # noqa: BLE001 — no key loaded: only recorded keys verify
        pass
    return keys


def _replay_charge(rep: MemoryReplica, src: str, seq: int) -> None:
    root = Reach(rep).root_of(src)
    if root in rep.nodes:
        rep.nodes[root] = {**rep.nodes[root], "part_removed_seq": seq, "part_removed": True}


def replay(db: Session) -> MemoryReplica:
    """The replica the ledger alone produces, applied entry by entry."""
    rep = MemoryReplica()
    for row in db.query(AuthorityEntry).order_by(AuthorityEntry.seq):
        b = json.loads(row.body)
        creator = "" if row.bootstrap else row.actor
        if b["kind"] == "grant":
            prior = rep.grants.get(b["grant_id"])
            g = _grant_from_body(b, prior.created_by if prior else creator)
            g = Grant(**{**g.__dict__, "claimed_from": (prior.claimed_from if prior
                                                         else row.claimed_from)})
            rep.grants[b["grant_id"]] = g
            if row.bootstrap:
                rep.nodes.setdefault(b["resource_id"], {"created_by": "", "member": False})
        elif b["kind"] == "edge.add":
            prior = rep.edges.get((b["src"], b["dst"]))
            if prior is not None and prior.get("origin") and not b["origin"] \
                    and row.compensates is None:
                _replay_charge(rep, b["src"], row.seq)      # a past demotion, as `_apply` does
            rep.edges[(b["src"], b["dst"])] = {
                "origin": b["origin"], "propagate": b["propagate"],
                "added_by": prior["added_by"] if prior else creator}
            if row.bootstrap:
                rep.nodes.setdefault(b["src"], {"created_by": "", "member": False})
                rep.nodes.setdefault(b["dst"], {"created_by": "", "member": False})
            elif b["origin"]:
                rep.nodes.setdefault(b["dst"], {"created_by": creator, "member": False})
            if b["origin"]:
                rep.nodes[b["dst"]]["member"] = True
        elif b["kind"] == "edge.remove":
            gone = rep.edges.pop((b["src"], b["dst"]), None)
            if gone is not None and gone.get("origin") and row.compensates is None:
                _replay_charge(rep, b["src"], row.seq)      # charged, as `_apply` charges it
        elif b["kind"] == "root.confirm_empty":
            if b["principal_id"] in rep.nodes:
                rep.nodes[b["principal_id"]] = {**rep.nodes[b["principal_id"]],
                                                "confirmed_empty_seq": row.seq}
        elif b["kind"] in ("drop_key", "job_grant"):
            continue                         # no reach: the replica holds them beside it
        elif b["kind"] == "root.retire":
            rep.roots.pop(b["principal_id"], None)
            rep.nodes.pop(b["principal_id"], None)
        else:
            rep.nodes.setdefault(b["principal_id"], {"created_by": creator, "member": False})
            rep.roots[b["principal_id"]] = {"root_id": b["root_id"], "registered_by": creator}
    return rep


def _tables(db: Session) -> MemoryReplica:
    rep = MemoryReplica()
    for r in db.query(AuthorityGrant):
        rep.grants[r.grant_id] = _grant_of(r)
    for r in db.query(AuthorityEdge):
        rep.edges[(r.src, r.dst)] = {"origin": bool(r.origin),
                                     "propagate": _prop_load(r.propagate), "added_by": r.added_by}
    for r in db.query(AuthorityNode):
        rep.nodes[r.node_id] = _node_view(r.created_by, r.member, r.part_removed_seq,
                                          r.confirmed_empty_seq)
    for r in db.query(AuthorityRoot):
        rep.roots[r.principal_id] = {"root_id": r.root_id, "registered_by": r.registered_by}
    return rep


def verify_chain(db: Session) -> Tuple[bool, str]:
    """Walk the whole ledger: every hash recomputed from its body (kid and credential kind
    included), every link to the one before, every co-signature against the key that made it
    (every key that has co-signed is kept, so rotation does not break this), and the replay of the
    whole chain compared with the replica tables. `(True, "<n> entries")` or `(False, <the first
    fault>)`."""
    keys = _signing_keys(db)
    prev, n = GENESIS, 0
    for row in db.query(AuthorityEntry).order_by(AuthorityEntry.seq):
        n += 1
        if row.seq != n:
            return False, f"a gap before entry {row.seq}"
        if row.prev_hash != prev:
            return False, f"entry {row.seq} does not link to the one before"
        body = json.loads(row.body)
        if canonical(normalise(body, canonical_times=False)) != row.body:
            return False, f"entry {row.seq} is not in canonical form"
        digest = entry_hash(seq=row.seq, prev_hash=row.prev_hash, body=body, actor=row.actor,
                            credential_kind=row.credential_kind,
                            credential_ref=row.credential_ref, bootstrap=bool(row.bootstrap),
                            compensates=row.compensates, kid=row.kid,
                            claimed_from=row.claimed_from)
        if digest != row.entry_hash:
            return False, f"entry {row.seq} does not hash to its recorded hash"
        pem = keys.get(row.kid)
        if pem is None or not verify_cosignature(digest, row.signature, pem):
            return False, f"entry {row.seq} carries a co-signature no recorded key made"
        prev = row.entry_hash
    replayed, held = replay(db), _tables(db)
    for name in ("grants", "edges", "roots", "nodes"):
        a, b = getattr(replayed, name), getattr(held, name)
        if name == "grants":
            a = {k: _structure(v) + (v.created_by, v.claimed_from) for k, v in a.items()}
            b = {k: _structure(v) + (v.created_by, v.claimed_from) for k, v in b.items()}
        if a != b:
            diff = sorted(set(a) ^ set(b)) or sorted(k for k in a if a[k] != b.get(k))
            return False, f"the replica's {name} differ from the ledger's replay at {diff[:3]}"
    return True, f"{n} entries"

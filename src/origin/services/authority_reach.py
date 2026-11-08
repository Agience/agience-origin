"""Who reaches what, decided by Origin over its own replica of the authority ledger.

A port of Mantle's reach rules, kept line for line so the two answer the same question the same
way. Mantle's tests (`tests/test_origin_reach_matches_mantle.py`) run both on shared fixtures and
compare every answer; a rule changed on one side and not the other fails there.

    Mantle                                          here
    attenuation.Mask / propagates                   Mask / propagates
    entities.grant.mask_of, grant_is_allow          mask_of
    lattice_api.get_origin_parent / _root           Reach.origin_parent / root_of
    lattice_api.origin_chain                        Reach.chain
    oracle.LightConeGrantVerifier._reaches          Reach.reaches
    oracle.LightConeGrantVerifier._granted_roots    Reach.granted_roots
    oracle.LightConeGrantVerifier.authorized        Reach.authorized
    grant_service.user_has_any_action               Reach.has_any_action
    grant_service.effective_flags                   Reach.effective_actions

One difference, stated: Mantle's `origin_chain` steps from a version id to its root id by reading
the artifact. The replica holds no artifacts, so Mantle names the root it means (it sends root
ids), and the chain here starts at that id.

The replica is read through a small interface (`ReplicaView`), so the same rules run over Origin's
tables (`SqlReplica`) and over an in-memory fixture (`MemoryReplica`).

On top of the port, `may_release` adds what Origin needs that Mantle's verifier does not: the key
asked for must be the one the reached collection is keyed under (its origin root), so reaching one
collection cannot be spent on another principal's key.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Protocol, Tuple

# -- the attenuation algebra (Mantle `attenuation.py`) -------------------------------------------

ACTIONS: Tuple[str, ...] = (
    "create", "read", "update", "delete", "evict", "invoke", "add", "share", "admin",
)
_INDEX = {a: i for i, a in enumerate(ACTIONS)}
_ACTION_BITS = (1 << len(ACTIONS)) - 1
_ALLOW_BIT = 1 << len(ACTIONS)


@dataclass(frozen=True)
class Mask:
    code: int

    @classmethod
    def of(cls, actions: Iterable[str] = (), *, allow: bool = True) -> "Mask":
        code = _ALLOW_BIT if allow else 0
        for name in actions:
            bit = _INDEX.get(str(name))
            if bit is not None:
                code |= 1 << bit
        return cls(code)

    @classmethod
    def from_propagate(cls, value: Any) -> "Mask":
        """The `edge.propagate` decoder: None is unrestricted, a list names actions, a JSON-array
        string is decoded, any other string carries the actions whose names it contains."""
        if isinstance(value, Mask):
            return value
        if value is None:
            return TOP
        if isinstance(value, Mapping):
            return cls.of(value.keys())
        if isinstance(value, (list, tuple, set, frozenset)):
            return cls.of(str(v) for v in value)
        text = value if isinstance(value, str) else str(value)
        if text.startswith("["):
            try:
                decoded = json.loads(text)
            except ValueError:
                decoded = None
            if isinstance(decoded, list):
                return cls.of(str(v) for v in decoded)
        return cls.of(a for a in ACTIONS if a in text)

    @property
    def is_allow(self) -> bool:
        return bool(self.code & _ALLOW_BIT)

    @property
    def is_deny(self) -> bool:
        return not self.is_allow

    @property
    def actions(self) -> frozenset:
        return frozenset(a for i, a in enumerate(ACTIONS) if self.code & (1 << i))

    def carries(self, action: str) -> bool:
        bit = _INDEX.get(action)
        return bit is not None and bool(self.code & (1 << bit))

    def allows(self, action: str) -> bool:
        return self.is_allow and self.carries(action)

    def __and__(self, other: "Mask") -> "Mask":
        return Mask(self.code & other.code)


TOP = Mask(_ACTION_BITS | _ALLOW_BIT)


def propagates(column_value: Any, action: str) -> bool:
    return Mask.from_propagate(column_value).allows(action)


# -- grants (Mantle `entities/grant.py`) ---------------------------------------------------------

@dataclass(frozen=True)
class Grant:
    """A grant as the ledger carries it: structure only."""

    id: str
    grantee_id: str
    grantee_type: str
    resource_id: str
    actions: frozenset            # the CRUDEASIO actions whose `can_*` flag is set
    effect: str = "allow"
    state: str = "active"
    expires_at: Optional[str] = None
    #: Who made the entry that created it (the co-signed actor); not part of the structure Mantle
    #: holds, used only by the creator's base case.
    created_by: str = ""
    #: An invite's target (a kind and a digest of the address) and claim limit, and, for a grant
    #: taken by claiming an invite, which one.
    target_kind: Optional[str] = None
    target_digest: Optional[str] = None
    max_claims: Optional[int] = None
    claimed_from: Optional[str] = None


def mask_of(grant: Grant) -> Mask:
    """`Mask.from_flags(grant, allow=grant_is_allow(grant))`: an effect that is not exactly
    `allow` (normalized) confers nothing."""
    allow = str(grant.effect or "").strip().lower() == "allow"
    return Mask.of(grant.actions, allow=allow)


def unexpired(expires_at: Optional[str], now: Optional[datetime] = None) -> bool:
    """`lattice_api._unexpired`, on the value alone."""
    if not expires_at:
        return True
    now = now or datetime.now(timezone.utc)
    try:
        e = datetime.fromisoformat(str(expires_at).strip().replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return False            # an expiry that does not parse is past: it confers nothing
    if e.tzinfo is None:
        e = e.replace(tzinfo=timezone.utc)
    return e > now


def _active(g: Grant) -> bool:
    return g.state == "active" and unexpired(g.expires_at)


# -- the replica, read --------------------------------------------------------------------------

class ReplicaView(Protocol):
    def grants_held_by(self, grantee_id: str) -> List[Grant]: ...

    def grants_on(self, resource_id: str) -> List[Grant]: ...

    def grant(self, grant_id: str) -> Optional[Grant]: ...

    def origin_parents(self, node_id: str) -> List[Tuple[str, Any]]: ...

    def origin_children(self, node_id: str) -> List[str]: ...

    def origin_added_by(self, node_id: str) -> Optional[str]: ...

    def edge(self, src: str, dst: str) -> Optional[dict]: ...

    def has_edges(self, node_id: str) -> bool: ...

    def has_members(self, node_id: str) -> bool: ...

    def root_entry(self, principal_id: str) -> Optional[dict]: ...

    def node(self, node_id: str) -> Optional[dict]: ...

    def is_person(self, node_id: str) -> bool: ...

    def identity(self, subject: str) -> Optional[tuple]: ...

    def claims_of(self, invite_id: str) -> int: ...


@dataclass
class MemoryReplica:
    """A replica held in memory: the fixture form, and what a test describes a lattice with."""

    grants: Dict[str, Grant] = field(default_factory=dict)
    #: (src, dst) -> {"origin": bool, "propagate": None | list}
    edges: Dict[Tuple[str, str], dict] = field(default_factory=dict)
    roots: Dict[str, dict] = field(default_factory=dict)
    #: node_id -> {"created_by"}
    nodes: Dict[str, dict] = field(default_factory=dict)
    #: person id -> (email, email_verified)
    persons: Dict[str, tuple] = field(default_factory=dict)
    def grants_held_by(self, grantee_id):
        return [g for g in self.grants.values() if g.grantee_id == grantee_id]

    def grants_on(self, resource_id):
        return [g for g in self.grants.values() if g.resource_id == resource_id]

    def grant(self, grant_id):
        return self.grants.get(grant_id)

    def origin_parents(self, node_id):
        return [(s, e.get("propagate")) for (s, d), e in sorted(self.edges.items())
                if d == node_id and e.get("origin")]

    def origin_children(self, node_id):
        return [d for (s, d), e in sorted(self.edges.items()) if s == node_id and e.get("origin")]

    def origin_added_by(self, node_id):
        for (s, d), e in sorted(self.edges.items()):
            if d == node_id and e.get("origin"):
                return e.get("added_by", "")
        return None

    def edge(self, src, dst):
        e = self.edges.get((src, dst))
        return None if e is None else {"origin": e.get("origin"), "propagate": e.get("propagate")}

    def has_edges(self, node_id):
        return any(node_id in k for k in self.edges)

    def has_members(self, node_id):
        return any(k[0] == node_id for k in self.edges)

    def root_entry(self, principal_id):
        return self.roots.get(principal_id)

    def node(self, node_id):
        return self.nodes.get(node_id)

    def is_person(self, node_id):
        return node_id in self.persons

    def identity(self, subject):
        return self.persons.get(subject)

    def claims_of(self, invite_id):
        return sum(1 for g in self.grants.values() if g.claimed_from == invite_id)


#: `lattice_api.ORIGIN_WALK_CEILING`.
ORIGIN_WALK_CEILING = 10_000


class OriginChainUnterminated(RuntimeError):
    pass


class Reach:
    """Mantle's reach rules over one replica."""

    def __init__(self, replica: ReplicaView) -> None:
        self.r = replica

    # `lattice_api.get_origin_parent`: the creation edge into this node, or None (a root).
    def origin_parent(self, node_id: str) -> Optional[Tuple[str, Any]]:
        parents = self.r.origin_parents(str(node_id))
        return parents[0] if parents else None

    def gone(self, node_id: str) -> bool:
        """Is `node_id` deleted at Origin (review 15)? A node is gone once its creation edge is
        removed: it has had a creation parent and has none now. Its members go with it, since
        each has one creation edge and walking those edges up reaches the gone node. A root that
        never had a creation edge is never gone this way. A creation chain that loops is treated
        as gone, so it opens nothing."""
        cur, seen = str(node_id), set()
        while cur and cur not in seen:
            seen.add(cur)
            parent = self.origin_parent(cur)
            if parent is None:
                n = self.r.node(cur)
                return bool(n and n.get("member"))
            cur = str(parent[0] or "")
        return True

    # `lattice_api.get_origin_root`.
    def root_of(self, node_id: str) -> str:
        current = str(node_id)
        visited = {current}
        while True:
            parent = self.origin_parent(current)
            if not parent:
                return current
            parent_id = parent[0]
            if not parent_id or parent_id in visited:
                return current
            visited.add(parent_id)
            current = parent_id

    # `lattice_api.origin_chain`, starting at a root id (see the module note).
    def chain(self, node_id: str, action: str, *, ceiling: int = ORIGIN_WALK_CEILING
              ) -> Iterator[str]:
        first = str(node_id)
        seen = {first}
        yield first
        cursor = first
        while True:
            if len(seen) > ceiling:
                raise OriginChainUnterminated(
                    f"origin chain from {node_id!r} did not terminate within {ceiling} hops")
            parent = self.origin_parent(cursor)
            if parent is None:
                return
            parent_id, mask = parent
            if not parent_id or str(parent_id) in seen:
                return
            if not propagates(mask, action):
                return
            parent_id = str(parent_id)
            yield parent_id
            seen.add(parent_id)
            cursor = parent_id

    # `LightConeResolver._grants_for` for a person: active, unexpired, held as `user`.
    def grants(self, subject: str, *, not_issued_by: Optional[str] = None) -> List[Grant]:
        return [g for g in self.r.grants_held_by(str(subject))
                if g.grantee_type == "user" and _active(g)
                and not (not_issued_by and g.created_by == not_issued_by)]

    # `LightConeGrantVerifier._reaches`.
    def reaches(self, subject: str, node_id: str, action: str, *,
                not_issued_by: Optional[str] = None) -> bool:
        return self.reach_grant(subject, node_id, action, not_issued_by=not_issued_by) is not None

    def reach_grant(self, subject: str, node_id: str, action: str, *,
                    not_issued_by: Optional[str] = None) -> Optional[str]:
        """The id of the grant by which `subject` reaches `node_id` for `action` (the first allow
        met walking up from the node), or None when it does not reach it. `reaches` is this,
        read as a yes or no."""
        if self.gone(str(node_id)):
            return None                                   # deleted at Origin: no one reaches it
        allow, deny = {}, set()
        for g in self.grants(subject, not_issued_by=not_issued_by):
            if not g.resource_id:
                continue
            m = mask_of(g)
            if m.is_deny and m.carries(action):
                deny.add(str(g.resource_id))
            elif m.allows(action):
                allow.setdefault(str(g.resource_id), str(g.id))
        if not allow:
            return None
        try:
            for resource in self.chain(str(node_id), action):
                if resource in deny:
                    return None
                if resource in allow:
                    return allow[resource]
        except Exception:  # noqa: BLE001 — a malformed chain authorizes nothing
            return None
        return None

    def creation_chain(self, node_id: str, *, ceiling: int = ORIGIN_WALK_CEILING
                       ) -> Iterator[str]:
        """`node_id` and every node up its creation edges to its root, whatever each edge
        conducts (review 16). A loop ends the walk; one past the ceiling raises."""
        cur, seen = str(node_id), set()
        while cur and cur not in seen:
            if len(seen) > ceiling:
                raise OriginChainUnterminated(
                    f"origin chain from {node_id!r} did not terminate within {ceiling} hops")
            seen.add(cur)
            yield cur
            parent = self.origin_parent(cur)
            cur = str(parent[0] or "") if parent else ""

    def denies(self, subject: str, node_id: str, action: str) -> bool:
        """Does a live deny `subject` holds, on `node_id` or anywhere up its creation chain,
        carry `action`? A deny on a collection holds against every path to its key (review 11,
        M3), and against every edge below it whatever that edge conducts (review 16): narrowing an
        edge, by anyone, never lifts an ancestor's deny."""
        deny = set()
        for g in self.grants(subject):
            if g.resource_id and mask_of(g).is_deny and mask_of(g).carries(action):
                deny.add(str(g.resource_id))
        if not deny:
            return False
        try:
            return any(r in deny for r in self.creation_chain(str(node_id)))
        except Exception:  # noqa: BLE001 — a malformed chain: refuse
            return True

    # `LightConeGrantVerifier._granted_roots`.
    def granted_roots(self, subject: str, action: str) -> frozenset:
        allow, deny = [], set()
        for g in self.grants(subject):
            if not g.resource_id:
                continue
            m = mask_of(g)
            if m.is_deny and m.carries(action):
                deny.add(str(g.resource_id))
            elif m.allows(action):
                allow.append(str(g.resource_id))
        roots = set()
        for resource in allow:
            if resource in deny or self.gone(resource):
                continue
            try:
                roots.add(str(self.root_of(resource)))
            except Exception:  # noqa: BLE001
                continue
        return frozenset(roots)

    # `LightConeGrantVerifier.authorized`, for a person.
    def authorized(self, *, subject: str, principal_id: str, collection_id: Optional[str],
                   action: str, artifact_id: Optional[str] = None) -> bool:
        if subject == principal_id:
            return True
        if collection_id:
            if self.reaches(subject, collection_id, action):
                return True
            return bool(artifact_id) and self.reaches(subject, artifact_id, action)
        return str(principal_id) in self.granted_roots(subject, action)

    # `grant_service.user_has_any_action`: direct grants on the resource, any grantee type.
    def _direct(self, subject: str, resource_id: str) -> List[Mask]:
        # An invite is no principal's grant until claimed (`lattice_api` reads it the same way).
        return [mask_of(g) for g in self.r.grants_held_by(str(subject))
                if g.resource_id == resource_id and _active(g) and g.grantee_type != "invite"]

    def has_any_action(self, subject: str, resource_id: str, *actions: str) -> bool:
        if not subject or self.gone(str(resource_id)):
            return False
        masks = self._direct(subject, resource_id)
        if any(m.is_deny and m.carries(a) for m in masks for a in actions):
            return False
        return any(m.allows(a) for m in masks for a in actions)

    # `grant_service.effective_flags`, as action names.
    def effective_actions(self, subject: str, resource_id: str) -> frozenset:
        if not subject or self.gone(str(resource_id)):
            return frozenset()
        masks = self._direct(subject, resource_id)
        held = set()
        for m in masks:
            if m.is_allow:
                held |= m.actions
        for m in masks:
            if m.is_deny:
                held -= m.actions
        return frozenset(held)

    # -- Origin's own, on top of the port -----------------------------------------------------

    def may_release(self, *, subject: str, principal_id: str, collection_id: Optional[str],
                    artifact_id: Optional[str] = None) -> Tuple[bool, str]:
        """May `subject`'s credential open this key's share?

        Two kinds of key (John, 2026-10-31):

          * a collection key, `ck:<collection>`: every collection's content is keyed under its
            own. Released to a subject whose walk reaches that collection for `read`, or reaches
            an artifact whose creation edge is from that collection (its content is keyed there),
            and to a background delegation minted for that key. The collection must be an id
            Origin's replica knows.
          * a master key, any other id: released to the principal itself and to no one else.
            Reach to a collection under a principal opens that collection's key, never the
            principal's.
        """
        collection = collection_key_collection(principal_id)
        if collection is not None:
            if self.r.node(collection) is None:
                return False, "Origin's replica does not know this collection"
            if self.gone(collection) or (artifact_id and self.gone(str(artifact_id))):
                return False, "the collection was deleted at Origin; its key opens for no one"
            if subject == principal_id:
                return True, "a background delegation for this collection key"
            if subject == collection:
                return True, "the principal's own id as a collection"
            if self.denies(subject, collection, "read"):
                return False, "a deny on the collection holds against every path to its key"
            if self.reaches(subject, collection, "read"):
                return True, "reaches the collection"
            if artifact_id:
                parent = self.origin_parent(artifact_id)
                # By a grant someone else issued: a member's own record of what they reached on
                # their artifact (the owner grant) does not outlast their reach on the collection.
                if parent and parent[0] == collection and self.reaches(
                        subject, artifact_id, "read", not_issued_by=subject):
                    return True, "reaches an artifact keyed under the collection"
            return False, "the credential's subject does not reach this collection"
        if self.r.root_entry(principal_id) is None:
            return False, "Origin's replica holds no root for this key"
        if subject == principal_id:
            return True, "the principal's own key"
        ok, why = self.full_reader_admin(subject, principal_id)
        if ok:
            return True, why
        return False, ("a master key is released only to its own principal, or a root's to a "
                       f"full reader-Admin of it ({why})")

    #: Answers of `full_reader_admin`, by (subject, root, ledger head); a new entry is a new head,
    #: so no answer outlives the replica it was made on (review 29, L2).
    _FULL_READER: dict = {}

    @classmethod
    def verdict_memo_size(cls) -> int:
        return len(cls._FULL_READER)

    def part_removed(self, root: str) -> bool:
        """Has a node under `root` ever gone (reviews 29 and 30)? Then the root is charged for
        good: its master key opens for its own principal alone."""
        n = self.r.node(root)
        return bool(n and (n.get("part_removed") or n.get("part_removed_seq")))

    def full_reader_admin(self, subject: str, root: str) -> Tuple[bool, str]:
        """Is `subject` a full reader-Admin of `root` (John, 2026-11-08): Admin on the root, and
        Read reaching every node whose root is that root, with no deny on Read on any of them?
        A root's own master key keys its legacy content, all of it, so it opens for no one who
        may not read all of it. `root` is a root with no creation parent, and no person. The one
        rule for releasing a root's master key (`may_release`) and for granting a job over it
        (`authority_ledger._job_scope`)."""
        from origin.services.authority_ledger import _a_root

        if not _a_root(self, root):          # a person, a platform principal, a member (I1)
            return False, "not a root"
        if self.part_removed(root):
            # A node under it went (review 29, M1): its legacy content may still be under this
            # key, and whoever reads the rest may not have read that part. Its own principal
            # alone opens it until the operator confirms nothing is left under it.
            return False, ("a part of the root was removed; its master key opens for its own "
                           "principal alone")
        head = getattr(self, "head", None)
        key = (subject, root, head)
        if head is not None and key in Reach._FULL_READER:
            answer, until = Reach._FULL_READER[key]
            # An expiry appends nothing, so the head does not move when a grant lapses (review
            # 30, F3): the answer holds only until the earliest expiry it rested on.
            if until is None or _now_iso() < until:
                return answer
        answer = self._walk_full_reader(subject, root)
        if head is not None:
            if len(Reach._FULL_READER) >= ORIGIN_WALK_CEILING:
                Reach._FULL_READER.clear()
            Reach._FULL_READER[key] = (answer, self._earliest_expiry(subject))
        return answer

    def _earliest_expiry(self, subject: str):
        """The earliest expiry among the subject's live grants, as an aware time, or None when
        none of them expires."""
        times = []
        for g in self.r.grants_held_by(subject):
            if g.expires_at and g.state == "active":
                times.append(_iso(g.expires_at))
        return min(times) if times else None

    def _walk_full_reader(self, subject: str, root: str) -> Tuple[bool, str]:
        # The subject's grants are read once for the walk (review 29, L2), and the walk counts
        # its nodes: past the ceiling it fails closed rather than walking on.
        rc = Reach(_OneSubject(self.r, subject))
        if not rc.has_any_action(subject, root, "admin"):
            return False, "no Admin on the root"
        seen, todo = {root}, [root]
        while todo:
            if len(seen) > ORIGIN_WALK_CEILING:
                return False, "the root is too large to walk; refused"
            node = todo.pop()
            if rc.gone(node):
                continue
            if rc.denies(subject, node, "read") or not rc.reaches(subject, node, "read"):
                return False, f"does not read {node} under the root"
            for child in rc.r.origin_children(node):
                if child not in seen:
                    seen.add(child)
                    todo.append(child)
        return True, "a full reader-Admin of the root"


def _iso(value: str):
    """An expiry as an aware UTC time (compared as times, never as strings)."""
    from datetime import datetime, timezone
    t = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t.astimezone(timezone.utc)


def _now_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


class _OneSubject:
    """A replica view that reads one subject's grants once (`full_reader_admin`'s walk)."""

    def __init__(self, replica, subject: str) -> None:
        self._r, self._subject, self._held = replica, subject, None

    def grants_held_by(self, grantee_id):
        if grantee_id != self._subject:
            return self._r.grants_held_by(grantee_id)
        if self._held is None:
            self._held = list(self._r.grants_held_by(grantee_id))
        return self._held

    def __getattr__(self, name):
        return getattr(self._r, name)


#: A collection key's id: `ck:<collection id>`.
from prism.trust.ledger import COLLECTION_KEY_PREFIX  # noqa: E402  (shared, review 17)


def collection_key_collection(key_id: str) -> Optional[str]:
    """The collection a collection key belongs to, or None for a master key."""
    if isinstance(key_id, str) and key_id.startswith(COLLECTION_KEY_PREFIX):
        return key_id[len(COLLECTION_KEY_PREFIX):] or None
    return None

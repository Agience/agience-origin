"""Origin's replica of reach, digested in the one canonical form Mantle digests its store in
(`prism.trust.ledger.canonical_reach`), so the two can be compared without either sending the
other its rows. Every field of a grant or an edge that could widen reach is in it (review 19); the
form's own docstring says what is left out and why.
"""
from __future__ import annotations

import hashlib
from sqlalchemy.orm import Session

def canonical(grants: list, edges: list) -> str:
    """`prism.trust.ledger.canonical_reach`, the one form both sides digest (review 19). A grant
    here is a tuple `(grant_id, grantee_id, grantee_type, resource_id, actions, effect, state,
    expires_at, target_kind, target_digest, max_claims)`; the first seven alone are taken too."""
    from prism.trust.ledger import canonical_reach
    keys = ("grant_id", "grantee_id", "grantee_type", "resource_id", "actions", "effect", "state",
            "expires_at", "target_kind", "target_digest", "max_claims")
    return canonical_reach([dict(zip(keys, g)) for g in grants], edges)


def replica_digest(db: Session) -> dict:
    """`{"digest", "grants", "edges"}` over the replica's active grants and its edges.

    A deny on a node deleted at Origin is left out (review 15): no token Mantle holds lifts a deny,
    so the deletion's retirement of it is answered `unchanged` and it stays here, while Mantle's
    store drops it with the node. It holds nothing open, since the node opens for no one."""
    from origin.models.authority_ledger import AuthorityEdge, AuthorityGrant
    from origin.services.authority_ledger import reach

    rc = reach(db)
    grants = [(r.grant_id, r.grantee_id, r.grantee_type, r.resource_id,
               [a for a in (r.actions or "").split(",") if a], r.effect, r.state,
               r.expires_at, r.target_kind, r.target_digest, r.max_claims)
              for r in db.query(AuthorityGrant).filter(AuthorityGrant.state == "active")
              if not (r.effect == "deny" and rc.gone(r.resource_id))]
    edges = [(r.src, r.dst, r.origin, r.propagate) for r in db.query(AuthorityEdge)]
    text = canonical(grants, edges)
    return {"digest": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "grants": len(grants), "edges": len(edges)}

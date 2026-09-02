"""The Origin — the governing entity, distinct from the Authority it owns.

## The distinction

An **Authority** answers one technical question: is this principal who they claim? — an `iss` + a
JWKS. It is a governable artifact in its own right (`vnd.agience.issuer+json`), plural and federated.

An **Origin** is the governing entity: it owns an Authority (its issuer) and carries what an Authority
does not — policy, economy parameters, and the peering identity (which other origins it has an
exchange agreement with). One Origin owns one Authority.

    peering is an origin-level act (economy, policy, exchange agreements);
    validation is an authority-level act (iss / JWKS).

Resolution is Origin → Authority → JWKS: a row's `_origin` references an Origin; the Origin resolves to
its Authority for token validation. This names the entity and gives it a resolvable link to the issuer;
it does not rewire the live token path.

## Governance carries the constants

An Origin's `economy` block holds its coupling constants — the α's of its economy (the facilitation
fee, the demurrage rate). Different origins may run different physics; within one, the constants are
fixed, public, and measured rather than legislated. `constants_of` exposes them as the seam for
per-origin physics.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

ORIGIN_CONTENT_TYPE = "application/vnd.agience.origin+json"
ISSUER_CONTENT_TYPE = "application/vnd.agience.issuer+json"      # the Authority primitive

# The leaf's self-origin when it belongs to no external authority — consistent with
# `delegate.LOCAL_ORIGIN`. A local origin owns a local issuer (`urn:agience:issuer:local`).
LOCAL_ORIGIN = "urn:agience:origin:local"
LOCAL_ISSUER = "urn:agience:issuer:local"

# The economy's coupling constants — the α's an Origin governs. These are what an origin inherits
# when it governs none of its own; an Origin artifact may override any of them, and may govern one
# this dict does not ship at all.
def _default_constants() -> Dict[str, float]:
    """The α's an Origin inherits when it governs none of its own — currently none.

    An origin that has not declared a fee has not declared a fee: `constants_of` returns what the
    Origin governs and nothing else, so a settlement path reads an absence and must decide what to
    do about it — a state an operator can see, unlike a 10% cut nobody chose
    ([[absence-is-not-an-affirmative-claim]]). Absence is not set to 0.0, precisely so the two
    cannot be confused.

    Empty by design: there is no quantity this codebase currently derives that an Origin inherits
    without governing it itself. An α that does not exist must not be inherited as one."""
    return {}


DEFAULT_CONSTANTS: Dict[str, float] = _default_constants()

#: The α's an Origin may govern — a different set from the ones it inherits, and the distinction is
#: load-bearing (see `constants_of`). A name is here because it is an economy term whose value is a
#: matter of governance; a name is absent because it is not governable at all, a stronger statement
#: than "we ship no default for it".
GOVERNABLE: frozenset = frozenset({
    "facilitation_fee",     # the Origin's flat cut of a settlement — no inherited value, see above
    "demurrage_tau",        # the 2nd-law clock; unset means measured off the node's screen, not defaulted
})


def _slug(s: str) -> str:
    ok = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    out = "".join(c if c in ok else "-" for c in str(s).strip().lower())
    return "-".join(p for p in out.split("-") if p)[:64] or "unnamed"


def origin_id(name: str) -> str:
    """A stable Origin id from a name. A URL (an external origin's domain) is used as-is; anything
    else becomes a `urn:agience:origin:<slug>`."""
    n = str(name or "").strip()
    if n.startswith(("http://", "https://", "urn:")):
        return n
    return "urn:agience:origin:%s" % _slug(n)


def origin_artifact(name: str, *, issuer: str, policy: Optional[dict] = None,
                    economy: Optional[dict] = None, peers: Optional[List[str]] = None,
                    owner: str = "") -> Dict[str, Any]:
    """A `vnd.agience.origin+json` — a governing entity that OWNS an Authority (`issuer`).

    `issuer` is the id (or `iss`) of the `vnd.agience.issuer+json` this Origin validates against.
    `policy` is the membrane (what may flow / consent rules); `economy` overrides `DEFAULT_CONSTANTS`;
    `peers` are exchange-agreement refs to other origins (P7). A person made this container on
    purpose, so its own provenance is human-authored — the *contents it governs* are weighed on their
    own rungs."""
    from prism.grounding import CITE_GENESIS, P_HUMAN, _now
    oid = origin_id(name)
    econ = dict(DEFAULT_CONSTANTS)
    econ.update(economy or {})
    return {
        "id": oid,
        "content_type": ORIGIN_CONTENT_TYPE,
        "state": "committed",
        "name": name or oid,
        "issuer": issuer,                       # ← the Authority this Origin owns
        "policy": policy or {},                 # the membrane: what this origin permits
        "economy": econ,                        # the coupling constants it governs (§10b)
        "peers": list(peers or []),             # exchange agreements (P7)
        "context": "origin %s (authority: %s)" % (name or oid, issuer),
        "content": "",
        "provenance": P_HUMAN,
        "cited_from": CITE_GENESIS,
        "created_by": owner or oid,
        "created_time": _now(),
    }


def local_origin_artifact() -> Dict[str, Any]:
    """The self-origin for a leaf that belongs to no external authority — owns the local issuer."""
    return origin_artifact("local", issuer=LOCAL_ISSUER)


def register_origin(store, name: str, *, issuer: str, **kw) -> Dict[str, Any]:
    """Write an Origin artifact. Returns it (with `published`)."""
    doc = origin_artifact(name, issuer=issuer, **kw)
    try:
        (getattr(store, "artifacts", None) or store).put_artifact(doc)
        doc["published"] = True
    except Exception as e:
        doc["published"] = False
        doc["publish_error"] = "%s: %s" % (type(e).__name__, str(e)[:160])
    return doc


# ── resolution: Origin → Authority → JWKS (validation is an authority act) ─────────────────────────
def _get(store, oid: str) -> Optional[dict]:
    try:
        return (getattr(store, "artifacts", None) or store).get_artifact(oid)
    except Exception:
        return None


def authority_ref(store, origin_ref: str) -> Optional[str]:
    """The Authority (issuer id / `iss`) an Origin validates against, or None if it cannot be
    resolved — an absence here is safer than a validation gap that silently opens (a row validated
    against the wrong issuer)."""
    o = _get(store, origin_ref)
    if not o or o.get("content_type") != ORIGIN_CONTENT_TYPE:
        return None
    return o.get("issuer") or None


def resolve_authority(store, origin_ref: str) -> Optional[dict]:
    """The Authority ARTIFACT (`vnd.agience.issuer+json`) an Origin owns, for token validation —
    Origin → Authority → its JWKS. None if the origin, its issuer ref, or the issuer artifact is
    absent (fail closed: cannot validate ⇒ do not pretend to)."""
    iss = authority_ref(store, origin_ref)
    if not iss:
        return None
    return _get(store, iss)


def constants_of(store, origin_ref: str) -> Dict[str, float]:
    """The economy's coupling constants an Origin governs — the seam for per-origin physics (§10b).

    Starts from `DEFAULT_CONSTANTS` and overrides with whatever this Origin's `economy` block sets,
    limited to `GOVERNABLE` keys; an origin with no economy block governs nothing of its own."""
    o = _get(store, origin_ref)
    out = dict(DEFAULT_CONSTANTS)
    if o and o.get("content_type") == ORIGIN_CONTENT_TYPE:
        econ = o.get("economy")
        if isinstance(econ, dict):
            for k, v in econ.items():
                if k in GOVERNABLE and isinstance(v, (int, float)) and not isinstance(v, bool):
                    out[str(k)] = float(v)
    return out


def peers_of(store, origin_ref: str) -> List[str]:
    """The exchange-agreement refs an Origin has with other origins (P7). Empty by default —
    isolation is the default; peering is a deliberate, signed exception."""
    o = _get(store, origin_ref)
    if o and isinstance(o.get("peers"), list):
        return [str(p) for p in o["peers"] if p]
    return []


__all__ = ["ORIGIN_CONTENT_TYPE", "ISSUER_CONTENT_TYPE", "LOCAL_ORIGIN", "LOCAL_ISSUER",
           "DEFAULT_CONSTANTS", "GOVERNABLE", "origin_id", "origin_artifact", "local_origin_artifact",
           "register_origin", "authority_ref", "resolve_authority", "constants_of", "peers_of"]

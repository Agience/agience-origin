"""Two Mantle-only questions Origin answers from its own replica (sixth review, M3).

* `GET /internal/authority/reach?resource_id=&action=`: does the acting credential's subject reach
  this resource for this action, by Origin's own walk? Mantle asks it before it lets any action
  through under threshold custody, so a store that drifted from what Origin co-signed decides
  nothing on its own.
* `POST /internal/authority/verify {"digest", "grants", "edges"}`: does Mantle's digest of its
  active grants and containment edges match the replica's (`services.authority_digest`)?

Both take Mantle's service token bound to the call (and to the query or the body), single-use.
"""
from __future__ import annotations

import hashlib
import json

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client

ALL = ["create", "read", "update", "delete", "evict", "invoke", "add", "share", "admin"]
REACH = "/internal/authority/reach"
VERIFY = "/internal/authority/verify"


def _reach(c, credential, resource, action, token=None):
    tok = token or _shares._token("GET", "-", htu=REACH, resource_id=resource, action=action)
    headers = {"Authorization": f"Bearer {tok}"}
    if credential:
        headers["X-Acting-Credential"] = credential
    return c.get(REACH, params={"resource_id": resource, "action": action}, headers=headers)


def _verify(c, body, token=None):
    from origin.services.authority_ledger import canonical

    digest = hashlib.sha256(canonical(body).encode()).hexdigest()
    tok = token or _shares._token("POST", "-", htu=VERIFY, body_sha256=digest)
    return c.post(VERIFY, json=body, headers={"Authorization": f"Bearer {tok}"})


def _world(c):
    alice, bob = af.person("Alice"), af.person("Bob")
    af.ok(af.submit(c, alice[1], af.root("K"), batch="k"))
    af.ok(af.submit(c, alice[1], af.grant("g-a", alice[0], "K", ALL), batch="k"))
    af.ok(af.submit(c, alice[1], af.grant("g-b", bob[0], "K", ["read", "invoke"]), batch="k2"))
    af.ok(af.submit(c, alice[1], af.edge("K", "m-1"), batch="k3"))
    return alice, bob


def test_reach_is_answered_per_action_by_origin_s_walk(custody_client):
    c = custody_client
    alice, bob = _world(c)
    assert _reach(c, bob[1], "K", "invoke").json() == {"allowed": True}
    assert _reach(c, bob[1], "K", "update").json() == {"allowed": False}
    assert _reach(c, bob[1], "m-1", "read").json() == {"allowed": True}     # down the edge
    assert _reach(c, alice[1], "m-1", "admin").json() == {"allowed": True}


def test_reach_needs_a_bound_token_and_the_caller_s_credential(custody_client):
    c = custody_client
    _alice, bob = _world(c)
    assert _reach(c, None, "K", "read").status_code == 401
    other = _shares._token("GET", "-", htu=REACH, resource_id="K", action="admin")
    assert _reach(c, bob[1], "K", "read", token=other).status_code == 401    # bound to another
    tok = _shares._token("GET", "-", htu=REACH, resource_id="K", action="read")
    assert _reach(c, bob[1], "K", "read", token=tok).status_code == 200
    assert _reach(c, bob[1], "K", "read", token=tok).status_code == 401      # single-use
    assert _reach(c, bob[1], "K", "fly").status_code == 400


def _expected(alice, bob):
    # Each grant with its expiry, invite target (kind, digest) and claim limit (review 19).
    grants = sorted([
        ["g-a", alice, "user", "K", sorted(ALL), "allow", "active", None, None, None, None],
        ["g-b", bob, "user", "K", ["invoke", "read"], "allow", "active", None, None, None,
         None]])
    text = json.dumps({"edges": [["K", "m-1", True, None]], "grants": grants},
                      separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(text.encode()).hexdigest()


def test_the_replica_digest_is_the_canonical_form(custody_client):
    from origin.db.session import SessionLocal
    from origin.services import authority_digest

    alice, bob = _world(custody_client)
    with SessionLocal() as db:
        got = authority_digest.replica_digest(db)
    assert got == {"digest": _expected(alice[0], bob[0]), "grants": 2, "edges": 1}


def test_verify_says_whether_mantle_s_store_matches_the_replica(custody_client):
    c = custody_client
    alice, bob = _world(c)
    same = {"digest": _expected(alice[0], bob[0]), "grants": 2, "edges": 1}
    r = _verify(c, same)
    assert r.status_code == 200 and r.json()["match"] is True
    r = _verify(c, {**same, "digest": "0" * 64})
    assert r.status_code == 200 and r.json()["match"] is False
    assert r.json()["replica"]["grants"] == 2


def test_verify_needs_a_token_bound_to_its_body(custody_client):
    c = custody_client
    _world(c)
    tok = _shares._token("POST", "-", htu=VERIFY, body_sha256="0" * 64)
    assert _verify(c, {"digest": "a" * 64, "grants": 0, "edges": 0}, token=tok).status_code == 401

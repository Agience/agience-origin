"""Review 12 (John, 2026-11-03): authority changes happen at Origin.

Mantle holds every person's access token and every delegation made for them, so no entry that
changes authority (a grant, an invite, a deny, a change to what an edge conducts, a job grant) is
taken on such a token at `/internal/authority/entries`. Two acts stay there, because they are the
content ops Mantle performs: the creator's own creation grant on what they created in that batch
(never a grant to anyone else), and the retirement of grants with the resource they name being
deleted in the same batch. New edges and edge removals are membership, a content op, and stay too.

The person makes every other change in their Origin session (`POST /auth/me/authority/entries`),
which the web app calls directly, with the custom header `X-Origin-Session: 1` and an `Origin` of
the web app or Origin itself. Mantle applies those entries from Origin's feed, which carries what
it needs to verify them. Origin co-signs no grant to a grantee that does not exist (n1b).
"""
from __future__ import annotations

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client
ALL = ["create", "read", "update", "delete", "evict", "add", "share", "admin"]
ROUTE = "/auth/me/authority/entries"
REFUSAL = "made in the person's Origin session"


@pytest.fixture
def people(custody_client):
    return {n: af.person(n, email=f"{n}@team.test") for n in ("alice", "bob", "mal")}


def _direct(c, credential, entry, **kw):
    """The credential path itself, with no fallback to the session."""
    return af.submit(c, credential, entry, via_session=False, **kw)


def _own(c, person, cid="W", batch="own"):
    af.ok(_direct(c, person[1], af.root(cid), batch=batch))
    af.ok(_direct(c, person[1], af.grant(f"g-{cid}-own", person[0], cid, ALL), batch=batch))


GRANTS = "/auth/me/authority/grants"


def _session(c, person_id, entry, *, origin=None, header=True):
    """The person makes `entry` in their Origin session: a grant or deny through the grants route
    (Origin mints its id, review 13), anything else through the generic route."""
    from origin import config
    oc.origin_page_session(c, person_id)
    headers = {"Origin": origin or config.APP_URI or config.ORIGIN_URI}
    if header:
        headers["X-Origin-Session"] = "1"
    if entry.get("kind") == "grant" and entry.get("grantee_type") == "user":
        # The preview the owner confirmed, which a make names (review 15).
        seen = c.post("/auth/me/authority/preview", json={"resource_id": entry["resource_id"]},
                      headers=headers)
        return c.post(GRANTS, json={"resource_id": entry["resource_id"],
                                    "grantee_id": entry["grantee_id"],
                                    "actions": entry["actions"], "effect": entry["effect"],
                                    "expires_at": entry["expires_at"],
                                    "preview": seen.json().get("preview")
                                    if seen.status_code == 200 else None}, headers=headers)
    return c.post(ROUTE, json={"entry": entry}, headers=headers)


# -- the credential path -----------------------------------------------------------------------

def test_n1_a_person_s_token_gives_no_one_a_grant(custody_client, people):
    c = custody_client
    alice, mal = people["alice"], people["mal"]
    _own(c, alice)
    r = _direct(c, alice[1], af.grant("g-mal", mal[0], "W", ["read"]), batch=None)
    assert r.status_code == 403 and REFUSAL in r.text, r.text


def test_the_creator_s_own_creation_grant_stays_on_the_token(custody_client, people):
    c = custody_client
    alice = people["alice"]
    _own(c, alice)                                       # root + her own grant, one batch
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant
    with SessionLocal() as db:
        assert db.get(AuthorityGrant, "g-W-own").state == "active"


def test_a_creation_batch_grants_no_one_else(custody_client, people):
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    af.ok(_direct(c, alice[1], af.root("X"), batch="x"))
    r = _direct(c, alice[1], af.grant("g-bx", bob[0], "X", ALL), batch="x")
    assert r.status_code == 403 and REFUSAL in r.text, r.text


@pytest.mark.parametrize("entry", [
    lambda bob: af.invite("inv-1", "tok-1", "W", ["read"]),
    lambda bob: af.grant("g-deny", bob, "W", ["read"], effect="deny"),
    lambda bob: af.grant("g-W-own", "SELF", "W", ALL, state="revoked"),
])
def test_invites_denies_and_revocations_are_refused_on_the_token(custody_client, people, entry):
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    _own(c, alice)
    e = entry(bob[0])
    if e["grantee_id"] == "SELF":
        e["grantee_id"] = alice[0]
    r = _direct(c, alice[1], e, batch=None)
    assert r.status_code == 403 and REFUSAL in r.text, r.text


def test_what_an_edge_conducts_is_changed_only_in_the_session(custody_client, people):
    c = custody_client
    alice = people["alice"]
    _own(c, alice)
    af.ok(_direct(c, alice[1], af.edge("W", "M1"), batch="m"))          # a new member: content
    r = _direct(c, alice[1], af.edge("W", "M1", propagate=["read"]), batch=None)
    assert r.status_code == 403 and REFUSAL in r.text, r.text
    af.ok(_direct(c, alice[1], af.unedge("W", "M1"), batch=None))       # membership: content


def test_a_delegation_makes_no_grant_either(custody_client, people):
    from origin.services.auth_service import issue_delegation_token
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    _own(c, alice)
    tok = issue_delegation_token("agience-server-crystal", alice[0])
    r = _direct(c, tok, af.grant("g-bw", bob[0], "W", ["read"]), batch=None)
    assert r.status_code in (401, 403) and "g-bw" not in _rows(), r.text


def _rows():
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant
    with SessionLocal() as db:
        return {g.grant_id for g in db.query(AuthorityGrant)}


# -- the session path --------------------------------------------------------------------------

def test_the_person_grants_in_their_origin_session(custody_client, people):
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    _own(c, alice)
    r = _session(c, alice[0], af.grant("g-bw", bob[0], "W", ["read"]))
    assert r.status_code == 200, r.text
    assert r.json()["outcome"] == "appended" and r.json()["grant_id"] in _rows()


def test_the_session_route_keeps_the_ledger_s_rules(custody_client, people):
    c = custody_client
    alice, bob, mal = people["alice"], people["bob"], people["mal"]
    _own(c, alice)
    r = _session(c, bob[0], af.grant("g-mw", mal[0], "W", ["read"]))       # Bob holds nothing
    assert r.status_code == 403, r.text


def test_the_session_route_needs_its_header_and_the_web_app_s_origin(custody_client, people):
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    _own(c, alice)
    before = _rows()
    assert _session(c, alice[0], af.grant("g-1", bob[0], "W", ["read"]),
                    header=False).status_code == 403
    assert _session(c, alice[0], af.grant("g-2", bob[0], "W", ["read"]),
                    origin="https://evil.test").status_code == 403
    c.cookies.clear()
    from origin import config
    r = c.post(GRANTS, json={"resource_id": "W", "grantee_id": bob[0], "actions": ["read"]},
               headers={"X-Origin-Session": "1", "Origin": config.APP_URI or config.ORIGIN_URI})
    assert r.status_code == 401
    assert _rows() == before


def test_the_session_route_makes_no_job_grant(custody_client, people):
    c = custody_client
    alice = people["alice"]
    _own(c, alice)
    entry = {"kind": "job_grant", "grant_id": "jg-1", "job": "platform.rekey",
             "principal": alice[0], "collections": [], "expires_at": "2099-01-01T00:00:00+00:00",
             "state": "active"}
    r = _session(c, alice[0], entry)
    assert r.status_code == 400 and "edge changes" in r.text, r.text


def test_the_web_app_may_call_the_session_route_with_its_cookie(custody_client, monkeypatch):
    from origin import config
    app = "https://my.agience.ai"
    monkeypatch.setattr(config, "APP_URI", app)
    r = custody_client.options(ROUTE, headers={
        "Origin": app, "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,x-origin-session"})
    assert r.headers.get("access-control-allow-origin") == app, r.headers
    assert r.headers.get("access-control-allow-credentials") == "true"


# -- n1b: no grant to someone who does not exist ------------------------------------------------

def test_n1b_no_grant_to_a_grantee_that_does_not_exist(custody_client, people):
    c = custody_client
    alice = people["alice"]
    _own(c, alice)
    r = _session(c, alice[0], af.grant("g-x", "someone", "W", ["read"]))
    assert r.status_code == 403 and "does not exist" in r.text, r.text
    r = _session(c, alice[0], af.grant("g-y", "00000000-0000-0000-0000-00000000dead", "W",
                                       ["read"]))
    assert r.status_code == 403 and "does not exist" in r.text, r.text


# -- the feed carries what Mantle needs to apply and verify -------------------------------------

def test_the_feed_carries_each_entry_s_signature_and_its_key(custody_client, people):
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    _own(c, alice)
    gid = af.ok(_session(c, alice[0], af.grant("g-bw", bob[0], "W", ["read"])))["grant_id"]
    tok = _shares._token("GET", "-", htu="/internal/authority/feed")
    r = c.get("/internal/authority/feed", params={"after": 0},
              headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200, r.text
    body = r.json()
    e = next(x for x in body["entries"] if x["body"].get("grant_id") == gid)
    for k in ("seq", "kind", "body", "actor", "credential_kind", "credential_ref", "bootstrap",
              "compensates", "claimed_from", "prev_hash", "entry_hash", "signature", "kid"):
        assert k in e, k
    assert e["kid"] in body["keys"] and "BEGIN PUBLIC KEY" in body["keys"][e["kid"]]
    from origin.services import authority_ledger as al
    assert al.entry_hash(seq=e["seq"], prev_hash=e["prev_hash"], body=e["body"],
                         actor=e["actor"], credential_kind=e["credential_kind"],
                         credential_ref=e["credential_ref"], bootstrap=e["bootstrap"],
                         compensates=e["compensates"], kid=e["kid"],
                         claimed_from=e["claimed_from"]) == e["entry_hash"]
    assert al.verify_cosignature(e["entry_hash"], e["signature"], body["keys"][e["kid"]])


# -- what the reviewer could not finish --------------------------------------------------------

def test_retire_root_clears_a_planted_deny_end_to_end(custody_client, people, monkeypatch):
    """Mal plants a node with a deny on Alice; the operator retires it; Alice then makes the id
    her own and its key opens for her."""
    c = custody_client
    alice, mal = people["alice"], people["mal"]
    af.operator(monkeypatch)
    af.ok(_direct(c, mal[1], af.root("SQ"), batch="m"))
    af.ok(_direct(c, mal[1], af.grant("g-mal-sq", mal[0], "SQ", ALL), batch="m"))
    af.ok(_session(c, mal[0], af.grant("g-sq-deny", alice[0], "SQ", ["read"], effect="deny")))
    r = oc.call(c, "POST", "/oracle/authority-ledger/retire-root",
                json={"principal_id": "SQ", "reason": "planted"})
    assert r.status_code == 200, r.text
    _own(c, alice, cid="SQ", batch="a")
    assert af.store_share(c, "ck:SQ", alice[1]).status_code == 200
    assert af.release(c, "ck:SQ", alice[1], collection="SQ").status_code == 200


def test_a_seed_credential_writes_one_batch_end_to_end(custody_client, people, monkeypatch):
    from origin import service_identity
    c = custody_client
    alice = people["alice"]
    af.operator(monkeypatch)
    system = "00000000-0000-0000-0000-00000000005e"
    monkeypatch.setattr(service_identity, "get_system_principal_id", lambda: system)
    _own(c, alice)
    from origin.services.authority_ledger import body_digest
    seed = oc.call(c, "POST", "/oracle/seed-credential", json={
        "minutes": 10, "plan": [body_digest(af.root("SEEDED")), body_digest(af.root("SEEDED2"))]})
    assert seed.status_code == 200, seed.text
    tok = seed.json()["token"]
    af.ok(_direct(c, tok, af.root("SEEDED"), batch="s1"))
    r = _direct(c, tok, af.root("SEEDED2"), batch="s2")
    assert r.status_code == 403, r.text


def test_an_invite_is_claimed_by_its_token_alone_in_the_origin_session(custody_client, people):
    """The web app's claim page holds only the invite's token (review 12): Origin finds the invite
    by the token's digest and makes the claim in the claimant's own session, taking no more than
    the invite carries. A token Origin does not know claims nothing."""
    from origin import config
    from origin.tests import operator_console_fixtures as oc

    c = custody_client
    alice, bob = people["alice"], people["bob"]
    af.ok(af.submit(c, alice[1], af.root("K"), batch="k"))
    af.ok(af.submit(c, alice[1], af.grant("g-ak", alice[0], "K", ALL), batch="k"))
    # An invite the person makes is targeted (review 13); this one at Bob's verified address.
    af.ok(af.session_submit(c, alice[0], af.invite("inv-k", "tok-k", "K", ["read"],
                                                   target=("email", "bob@team.test"))))
    oc.origin_page_session(c, bob[0])
    headers = {"X-Origin-Session": "1", "Origin": config.APP_URI or config.ORIGIN_URI}
    assert c.post("/auth/me/authority/claim", json={"token": "nope"},
                  headers=headers).status_code == 404
    r = c.post("/auth/me/authority/claim", json={"token": "tok-k"}, headers=headers)
    assert r.status_code == 200, r.text
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant
    with SessionLocal() as db:
        mine = [g for g in db.query(AuthorityGrant).filter(AuthorityGrant.grantee_id == bob[0],
                                                           AuthorityGrant.resource_id == "K")]
        assert [(g.actions, g.claimed_from) for g in mine] == [("read", "inv-k")]
    assert c.post("/auth/me/authority/claim", json={"token": "tok-k"},
                  headers={"Origin": config.APP_URI}).status_code == 403     # no custom header

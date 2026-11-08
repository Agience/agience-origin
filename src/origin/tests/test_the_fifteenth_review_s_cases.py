"""Review 15.

H1: a deny is never lifted on a token Mantle holds, and "deleted" means gone at Origin. Removing a
node's creation edge deletes it there: nothing names it or reaches it afterwards, on any path, and
its members go with it (each has its one creation edge, and that edge's parent is gone). Its keys
are released to no one, its drop key is not changed, and no edge or grant is added on it. Removing
its remaining edges, and retiring an allow grant on it, still land: they narrow nothing that is
left. A deny on it is never retired on a token Mantle holds.

L1: removing a creation edge is a deletion, so it needs Delete (or Admin on the collection), never
Evict alone. Evict removes a secondary edge (architecture §51).
"""
# ruff: noqa: F811
from __future__ import annotations

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_origin_co_signs_only_changes_the_actor_may_make import (  # noqa: F401
    ALL, _grant_row, world)

custody_client = _shares.custody_client


def _s_with_m_and_a_deny(c, world):
    """Alice (Admin on W) makes S in W and M in S, gives Bob Read on M, denies Bob Read on all of
    S, and gives Dave Delete on W alone."""
    alice_id, alice = world["alice"]
    bob_id, _bob = world["bob"]
    dave_id, dave = af.person("dave", email="dave@team.test")
    af.ok(af.submit(c, alice, af.edge("W", "S"), batch="mk", via_session=False))
    af.ok(af.submit(c, alice, af.grant("g-as", alice_id, "S", ALL), batch="mk",
                    via_session=False))
    af.ok(af.submit(c, alice, af.edge("S", "M"), batch="mk", via_session=False))
    af.ok(af.submit(c, alice, af.grant("g-am", alice_id, "M", ALL), batch="mk",
                    via_session=False))
    af.ok(af.session_submit(c, alice_id, af.grant("g-bm", bob_id, "M", ["read"])))
    af.ok(af.session_submit(c, alice_id, af.grant("g-deny-bs", bob_id, "S", ["read"],
                                                  effect="deny")))
    af.ok(af.session_submit(c, alice_id, af.grant("g-dw", dave_id, "W", ["delete"])))
    af.store_share(c, "ck:S")
    af.store_share(c, "ck:M")
    return dave_id, dave


def test_a_delete_only_token_lifts_no_deny_and_the_deleted_node_opens_no_key(custody_client,
                                                                             world):
    c = custody_client
    _alice_id, alice = world["alice"]
    bob_id, bob = world["bob"]
    _dave_id, dave = _s_with_m_and_a_deny(c, world)
    assert af.release(c, "ck:S", bob, collection="S", artifact="M").status_code == 403

    # Dave deletes S (Delete reaching it, architecture §51) and asks to retire Bob's deny with it.
    af.ok(af.submit(c, dave, af.unedge("W", "S"), batch="del", via_session=False))
    r = af.submit(c, dave, af.grant("g-deny-bs", bob_id, "S", ["read"], effect="deny",
                                    state="deleted"), batch="del", via_session=False)
    assert r.status_code == 200 and r.json().get("outcome") == "unchanged", r.text
    assert _grant_row("g-deny-bs").state == "active"          # the deny was not lifted

    # S is gone at Origin, and M with it: no key of either is released, on any path.
    for principal, art in (("ck:S", "M"), ("ck:S", None), ("ck:M", None)):
        assert af.release(c, principal, bob, collection=principal[3:],
                          artifact=art).status_code == 403
        assert af.release(c, principal, alice, collection=principal[3:]).status_code == 403
    # Nothing is added on it again: no edge into or out of it, no grant on it or on M.
    for entry in (af.edge("W", "S", origin=False), af.edge("S", "X"),
                  af.edge("W", "M", origin=False),
                  af.grant("g-new-s", bob_id, "S", ["read"]),
                  af.grant("g-new-m", bob_id, "M", ["read"])):
        r = af.submit(c, alice, entry, batch="back", via_session=False)
        assert r.status_code in (403, 409), (entry, r.text)
    for entry in (af.edge("W", "S", origin=False), af.grant("g-new-s2", bob_id, "S", ["read"])):
        r = af.session_submit(c, world["alice"][0], entry)
        assert r.status_code in (403, 409), (entry, r.text)


def test_what_is_left_of_a_deleted_node_is_still_taken_down(custody_client, world):
    c = custody_client
    bob_id, _bob = world["bob"]
    _dave_id, dave = _s_with_m_and_a_deny(c, world)
    af.ok(af.submit(c, dave, af.unedge("W", "S"), batch="del", via_session=False))
    # Its member's edge goes, and an allow grant on it is retired as bookkeeping.
    af.ok(af.submit(c, dave, af.unedge("S", "M"), batch="del", via_session=False))
    r = af.submit(c, dave, af.grant("g-bm", bob_id, "M", ["read"], state="deleted"),
                  batch="del", via_session=False)
    assert r.status_code == 200, r.text
    assert _grant_row("g-bm").state == "deleted"


def test_a_deny_on_a_resource_that_stays_is_not_lifted_on_a_held_token(custody_client, world):
    """The control: no deletion, and Admin-held Mantle tokens still change no deny."""
    c = custody_client
    alice_id, alice = world["alice"]
    bob_id, _bob = world["bob"]
    _s_with_m_and_a_deny(c, world)
    r = af.submit(c, alice, af.grant("g-deny-bs", bob_id, "S", ["read"], effect="deny",
                                     state="deleted"), batch="x", via_session=False)
    assert r.status_code == 403, r.text
    assert _grant_row("g-deny-bs").state == "active"
    # In the owner's Origin session it is retired.
    af.ok(af.session_submit(c, alice_id, af.grant("g-deny-bs", bob_id, "S", ["read"],
                                                  effect="deny", state="retired")))
    assert _grant_row("g-deny-bs").state == "retired"


def test_removing_a_creation_edge_needs_delete_never_evict_alone(custody_client, world):
    c = custody_client
    alice_id, alice = world["alice"]
    eve_id, eve = af.person("eve", email="eve@team.test")
    af.ok(af.submit(c, alice, af.edge("W", "S"), batch="mk", via_session=False))
    af.ok(af.submit(c, alice, af.grant("g-as", alice_id, "S", ALL), batch="mk",
                    via_session=False))
    af.ok(af.submit(c, alice, af.root("Y")))
    af.ok(af.submit(c, alice, af.grant("g-ay", alice_id, "Y", ALL)))
    af.ok(af.submit(c, alice, af.edge("W", "Y", origin=False), batch="mk2", via_session=False))
    af.ok(af.session_submit(c, alice_id, af.grant("g-ew", eve_id, "W", ["evict"])))
    r = af.submit(c, eve, af.unedge("W", "S"), batch="ev", via_session=False)
    assert r.status_code == 403 and "delete" in r.text.lower(), r.text
    af.ok(af.submit(c, eve, af.unedge("W", "Y"), batch="ev", via_session=False))   # secondary


# -- L4: Origin previews what an invite or grant is for, and the owner confirms that --------------

from origin.tests.test_the_thirteenth_review_s_session_cases import (  # noqa: E402,F401
    BASE, _as, _hdr, _token_of, mail, people)


def _preview(c, owner_id, resource_id):
    _as(c, owner_id)
    return c.post(f"{BASE}/preview", json={"resource_id": resource_id}, headers=_hdr())


def test_origin_previews_the_parent_chain_and_the_grantees(custody_client, world):
    c = custody_client
    alice_id, alice = world["alice"]
    bob_id = world["bob"][0]
    af.ok(af.submit(c, alice, af.edge("W", "S"), batch="mk", via_session=False))
    af.ok(af.submit(c, alice, af.grant("g-as", alice_id, "S", ALL), batch="mk",
                    via_session=False))
    r = _preview(c, alice_id, "S")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["resource_id"] == "S" and body["parents"] == ["W"]
    held = {(g["resource_id"], g["grantee_id"]) for g in body["grantees"]}
    assert ("S", alice_id) in held and ("W", bob_id) in held
    assert isinstance(body["preview"], str) and len(body["preview"]) == 64
    _as(c, world["carol"][0])
    assert c.post(f"{BASE}/preview", json={"resource_id": "S"},
                  headers=_hdr()).status_code == 403


def test_an_invite_or_grant_is_made_only_on_the_preview_the_owner_confirmed(custody_client, world,
                                                                             mail):
    c = custody_client
    alice_id, _alice = world["alice"]
    carol_id = world["carol"][0]
    body = {"resource_id": "W", "actions": ["read"], "email": "carol@team.test"}
    _as(c, alice_id)
    assert c.post(f"{BASE}/invites", json=body, headers=_hdr()).status_code == 409   # unpreviewed
    assert c.post(f"{BASE}/grants", json={"resource_id": "W", "grantee_id": carol_id,
                                          "actions": ["read"]}, headers=_hdr()).status_code == 409
    seen = _preview(c, alice_id, "W").json()["preview"]
    # What Origin holds changes after the preview: the owner confirms again.
    af.ok(c.post(f"{BASE}/grants", json={"resource_id": "W", "grantee_id": carol_id,
                                         "actions": ["read"], "preview": seen}, headers=_hdr()))
    r = c.post(f"{BASE}/invites", json={**body, "preview": seen}, headers=_hdr())
    assert r.status_code == 409 and "preview" in r.text, r.text
    again = _preview(c, alice_id, "W").json()["preview"]
    r = c.post(f"{BASE}/invites", json={**body, "preview": again}, headers=_hdr())
    assert r.status_code == 200, r.text
    assert len(mail) == 1


# -- info: the session cookie's scheme is decided as the sign-in cookie's is -----------------------

def test_the_session_cookie_scheme_follows_authority_issuer(monkeypatch):
    """`main._session_cookie_is_https_only` keys on `AUTHORITY_ISSUER`; Origin's own session
    cookie does the same, so the two cookies never disagree about being `__Host-`."""
    from origin import config
    from origin.services import origin_session
    monkeypatch.setattr(config, "AUTHORITY_ISSUER", "https://origin.agience.ai", raising=False)
    monkeypatch.setattr(config, "ORIGIN_URI", "http://origin.internal:8080", raising=False)
    assert origin_session.cookie_name() == origin_session.HOST_COOKIE
    monkeypatch.setattr(config, "AUTHORITY_ISSUER", "http://localhost:8080", raising=False)
    monkeypatch.setattr(config, "ORIGIN_URI", "https://origin.agience.ai", raising=False)
    assert origin_session.cookie_name() == origin_session.COOKIE


# -- info: the platform's own anchors are no one's grantee -----------------------------------------

def test_mantle_and_chorus_are_not_grantees(custody_client, world, monkeypatch):
    """The manifest anchors Mantle and Chorus as platform services, not personas: a grant to
    `agience-server-mantle` or `agience-server-chorus` names no one."""
    from origin.services import authority_ledger

    class _Manifest:
        trust_anchors = {"origin": {}, "mantle": {}, "chorus": {}, "ophan": {}}

    import origin.authority_trust as at
    monkeypatch.setattr(at, "get_authority_manifest", lambda: _Manifest())
    assert authority_ledger._known_server("ophan")
    c = custody_client
    alice_id, _alice = world["alice"]
    for name in ("mantle", "chorus", "origin"):
        r = af.session_submit(c, alice_id, af.grant(f"g-{name}", f"agience-server-{name}", "W",
                                                    ["read"]))
        assert r.status_code == 403 and "does not exist" in r.text, (name, r.text)


# -- info: an address is unverified unless something proved it ------------------------------------

def test_a_person_row_is_unverified_unless_a_path_says_proven(custody_client):
    from origin.db import persons as db_persons
    from origin.db.session import SessionLocal
    from origin.models.person import Person
    assert str(Person.__table__.c.email_verified.server_default.arg.text) == "0"
    with SessionLocal() as db:
        p = db_persons.create(db, {"email": "new@team.test", "name": "New"})
        db.commit()
        assert p.email_verified is False


def test_migration_0022_makes_the_column_default_unverified():
    """Rows already stored keep their value; a row inserted without one is unverified."""
    import importlib.util
    import pathlib

    import sqlalchemy as sa
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    path = (pathlib.Path(__file__).resolve().parents[1] / "alembic" / "versions"
            / "0022_email_verified_default_off.py")
    spec = importlib.util.spec_from_file_location("m0022", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.down_revision == "0021_tokens_review12"
    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE persons (id TEXT PRIMARY KEY, "
                             "email_verified BOOLEAN NOT NULL DEFAULT 1)"))
        conn.execute(sa.text("INSERT INTO persons (id) VALUES ('old')"))
        ops = Operations(MigrationContext.configure(conn))
        mod.op = ops
        mod.upgrade()
        conn.execute(sa.text("INSERT INTO persons (id) VALUES ('new')"))
        rows = dict(conn.execute(sa.text("SELECT id, email_verified FROM persons")).all())
    assert rows == {"old": 1, "new": 0}


# -- parity: Mantle's digest of reach agrees after a deletion whose deny Origin kept --------------

def test_the_reach_digest_leaves_out_what_a_deleted_node_holds(custody_client, world):
    """Mantle drops a deleted node's deny with it, and Origin keeps the deny it answered
    `unchanged` to: it holds nothing open on a node deleted at Origin. So Origin's digest leaves out
    a deny on a deleted node, and the store's digest and the replica's still agree. Allow grants
    are retired on both sides alike and need nothing."""
    from origin.db.session import SessionLocal
    from origin.services import authority_digest
    c = custody_client
    bob_id, _bob = world["bob"]
    _dave_id, dave = _s_with_m_and_a_deny(c, world)
    with SessionLocal() as db:
        before = authority_digest.replica_digest(db)["grants"]
    af.ok(af.submit(c, dave, af.unedge("W", "S"), batch="del", via_session=False))
    af.ok(af.submit(c, dave, af.grant("g-deny-bs", bob_id, "S", ["read"], effect="deny",
                                      state="deleted"), batch="del", via_session=False))
    assert _grant_row("g-deny-bs").state == "active"
    with SessionLocal() as db:
        after = authority_digest.replica_digest(db)
    assert after["grants"] == before - 1                       # g-deny-bs, and only it

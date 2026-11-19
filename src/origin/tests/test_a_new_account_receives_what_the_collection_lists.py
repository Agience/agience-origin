"""A new account receives what the operator's "New accounts receive" collection lists (BUG-091).

The collection's edges are the list: on each member, the person receives what the edge into it
conducts, within the ceiling (the mask on the edge from the operator's "New account ceiling" into
the list) and within what the operator reaches. Origin makes the grants as
the operator's own entries; Mantle names only the person.
"""
from __future__ import annotations

import uuid

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_background_work_runs_on_a_job_grant import ALL

custody_client = _shares.custody_client

#: Every CRUDEASIO action, as a creator holds on what it makes.
EVERY = [*ALL, "invoke"]


def _root(c, who, rid, actions=EVERY):
    af.ok(af.submit(c, who[1], af.root(rid), batch=f"r-{rid}"))
    af.ok(af.submit(c, who[1], af.grant(f"g-{rid}", who[0], rid, actions), batch=f"r-{rid}"))


def _ceiling(c, op_token, n, mask=("read", "invoke"), maker=af.OPERATOR):
    """Make the operator's "New account ceiling" and its edge into `n` with `mask`."""
    import origin.services.authority_ledger as L
    ceiling = L.new_account_ceiling_id(af.OPERATOR)
    af.ok(af.submit(c, op_token, af.edge(maker, ceiling), batch="ceil"))
    af.ok(af.submit(c, op_token, af.edge(ceiling, n, origin=False, propagate=list(mask)),
                    batch="ceil"))
    return ceiling


@pytest.fixture()
def platform(custody_client, monkeypatch):
    """The operator makes "New accounts receive" (N), the operators' collection C with op-1 and
    op-2, a seed collection S, and a collection D it does not list. N links C for read and invoke
    and S for read."""
    import origin.services.authority_ledger as L
    c = custody_client
    op_token = af.operator(monkeypatch)
    op = (af.OPERATOR, op_token)
    _root(c, op, af.OPERATOR)
    n = L.new_accounts_receive_id(af.OPERATOR)
    for parent, node in ((af.OPERATOR, n), (af.OPERATOR, "C-ops"), (af.OPERATOR, "S-seed"),
                         (af.OPERATOR, "D-other"), ("C-ops", "op-1"), ("C-ops", "op-2"),
                         ("D-other", "d-1")):
        af.ok(af.submit(c, op_token, af.edge(parent, node), batch="mk"))
    af.ok(af.submit(c, op_token, af.edge(n, "C-ops", origin=False, propagate=["read", "invoke"]),
                    batch="ln"))
    af.ok(af.submit(c, op_token, af.edge(n, "S-seed", origin=False, propagate=["read"]),
                    batch="ln"))
    _ceiling(c, op_token, n)
    return c, n, op_token


def _grants(person):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant
    with SessionLocal() as db:
        return sorted((g.resource_id, ",".join(sorted(g.actions.split(","))))
                      for g in db.query(AuthorityGrant)
                      .filter(AuthorityGrant.grantee_id == person, AuthorityGrant.state == "active"))


def _reaches(person, node, action):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    with SessionLocal() as db:
        return L.reach(db).reaches(person, node, action)


def test_a_new_account_receives_what_each_edge_conducts(platform):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    alice, _ = af.person("alice")
    with SessionLocal() as db:
        assert len(L.grant_new_account(db, alice, "t1")) == 2
    assert _grants(alice) == [("C-ops", "invoke,read"), ("S-seed", "read")]
    assert _reaches(alice, "op-1", "invoke") and _reaches(alice, "op-2", "read")
    assert not _reaches(alice, "S-seed", "invoke") and not _reaches(alice, "d-1", "read")
    with SessionLocal() as db:
        assert L.grant_new_account(db, alice, "t2") == [], "asking again grants nothing more"


def test_an_edge_conducting_more_gives_read_and_invoke_at_most(platform):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    _c, n, op_token = platform
    af.ok(af.submit(platform[0], op_token, af.edge(n, "D-other", origin=False), batch="all"))
    alice, _ = af.person("alice")
    with SessionLocal() as db:
        L.grant_new_account(db, alice, "t1")
    assert ("D-other", "invoke,read") in _grants(alice)


def test_nothing_beyond_what_the_operator_itself_reaches(custody_client, monkeypatch):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    c = custody_client
    op_token = af.operator(monkeypatch)
    _root(c, (af.OPERATOR, op_token), af.OPERATOR, ALL)
    n = L.new_accounts_receive_id(af.OPERATOR)
    for node in (n, "C-ops"):
        af.ok(af.submit(c, op_token, af.edge(af.OPERATOR, node), batch="mk"))
    af.ok(af.submit(c, op_token, af.edge(n, "C-ops", origin=False, propagate=["read", "invoke"]),
                    batch="ln"))
    _ceiling(c, op_token, n)
    alice, _ = af.person("alice")
    with SessionLocal() as db:
        L.grant_new_account(db, alice, "t1")
    assert _grants(alice) == [("C-ops", "read")]


def test_the_ceiling_edge_sets_the_most_a_member_gives(platform):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    c, n, op_token = platform
    ceiling = L.new_account_ceiling_id(af.OPERATOR)
    af.ok(af.submit(c, op_token, af.unedge(ceiling, n), batch="lower"))
    af.ok(af.submit(c, op_token, af.edge(ceiling, n, origin=False, propagate=["read"]),
                    batch="lower2"))
    alice, _ = af.person("alice")
    with SessionLocal() as db:
        L.grant_new_account(db, alice, "t1")
    assert _grants(alice) == [("C-ops", "read"), ("S-seed", "read")]


def test_no_ceiling_edge_gives_nothing(custody_client, monkeypatch):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    c = custody_client
    op_token = af.operator(monkeypatch)
    _root(c, (af.OPERATOR, op_token), af.OPERATOR)
    n = L.new_accounts_receive_id(af.OPERATOR)
    for node in (n, "C-ops"):
        af.ok(af.submit(c, op_token, af.edge(af.OPERATOR, node), batch="mk"))
    af.ok(af.submit(c, op_token, af.edge(n, "C-ops", origin=False, propagate=["read", "invoke"]),
                    batch="ln"))
    alice, _ = af.person("alice")
    with SessionLocal() as db:
        assert L.grant_new_account(db, alice, "t1") == []
    assert _grants(alice) == []


def _operator_grant(db, body):
    import origin.services.authority_ledger as L
    return L.append(db, body, actor=L.Actor(af.OPERATOR, "operator", "t"),
                    submitted_jti="console:t")


def _body(grantee, resource, actions=("invoke", "read"), **over):
    return {"kind": "grant", "grant_id": str(uuid.uuid4()), "grantee_id": grantee,
            "grantee_type": "user", "resource_id": resource, "actions": list(actions),
            "effect": "allow", "state": "active", "expires_at": None, "target": None,
            "max_claims": None, **over}


@pytest.mark.parametrize("why, make", [
    ("a collection the list does not name", lambda p: _body(p, "D-other")),
    ("a member below a listed collection", lambda p: _body(p, "op-1")),
    ("more than the edge conducts", lambda p: _body(p, "S-seed", ("read", "invoke"))),
    ("more than the ceiling", lambda p: _body(p, "C-ops", ("read", "admin"))),
    ("an expiry", lambda p: _body(p, "C-ops", expires_at="2099-01-01T00:00:00+00:00")),
    ("a deny", lambda p: _body(p, "C-ops", effect="deny")),
    ("not a person", lambda p: _body("nobody-at-all", "C-ops")),
])
def test_the_operator_grants_nothing_else(platform, why, make):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    alice, _ = af.person("alice")
    with SessionLocal() as db:
        with pytest.raises(L.EntryRefused):
            _operator_grant(db, make(alice))
    assert _grants(alice) == [], why


def test_a_collection_someone_else_made_at_that_id_gives_nothing(custody_client, monkeypatch):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    c = custody_client
    af.operator(monkeypatch)
    bob = af.person("bob")
    _root(c, bob, bob[0])
    n = L.new_accounts_receive_id(af.OPERATOR)
    af.ok(af.submit(c, bob[1], af.edge(bob[0], n), batch="b"))
    af.ok(af.submit(c, bob[1], af.edge(n, "b-1"), batch="b"))
    alice, _ = af.person("alice")
    with SessionLocal() as db:
        assert L.grant_new_account(db, alice, "t1") == []
    assert _grants(alice) == []


def test_no_collection_grants_nothing(custody_client, monkeypatch):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    af.operator(monkeypatch)
    alice, _ = af.person("alice")
    with SessionLocal() as db:
        assert L.grant_new_account(db, alice, "t1") == []


def test_the_route_answers_only_mantle(platform):
    c = platform[0]
    alice, token = af.person("alice")
    r = c.post("/internal/authority/new-person-grants", json={"person_id": alice},
               headers={"Authorization": f"Bearer {token}"})
    assert r.status_code in (401, 403)
    assert _grants(alice) == []

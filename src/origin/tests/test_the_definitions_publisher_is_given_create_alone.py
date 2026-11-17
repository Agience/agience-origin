"""The platform's system principal publishes the operator definitions the services carry into the
platform operators' collection, on one grant: create, made by Origin as the operator's own entry.

Origin derives the collection from the instance namespace, as Mantle seeds it, and makes the grant
only when the operator made that collection and reaches it for create. The operator may make no
other grant to the system principal through this path: not read, not a second resource, not an
expiry.
"""
from __future__ import annotations

import uuid

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_background_work_runs_on_a_job_grant import ALL

custody_client = _shares.custody_client

EVERY = [*ALL, "invoke"]
NS = uuid.UUID("6f1c3a52-9b1e-4d8e-a1b2-0c0ffee00045")
SYSTEM = "00000000-0000-0000-0000-0000000000bb"
COLL = str(uuid.uuid5(NS, "platform/platform-operators"))


def _identity(monkeypatch, system=SYSTEM, ns=NS):
    from origin import service_identity
    monkeypatch.setattr(service_identity, "get_instance_namespace", lambda: ns)
    monkeypatch.setattr(service_identity, "get_system_principal_id", lambda: system)


def _root(c, who, rid, actions=EVERY):
    af.ok(af.submit(c, who[1], af.root(rid), batch=f"r-{rid}"))
    af.ok(af.submit(c, who[1], af.grant(f"g-{rid}", who[0], rid, actions), batch=f"r-{rid}"))


@pytest.fixture()
def platform(custody_client, monkeypatch):
    """The operator makes the platform operators' collection with one operator in it."""
    c = custody_client
    op_token = af.operator(monkeypatch)
    _identity(monkeypatch)
    _root(c, (af.OPERATOR, op_token), af.OPERATOR)
    for parent, node in ((af.OPERATOR, COLL), (COLL, "op-1")):
        af.ok(af.submit(c, op_token, af.edge(parent, node), batch="mk"))
    return c, op_token


def _grants(who=SYSTEM):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant
    with SessionLocal() as db:
        return sorted((g.resource_id, ",".join(sorted(g.actions.split(","))))
                      for g in db.query(AuthorityGrant)
                      .filter(AuthorityGrant.grantee_id == who, AuthorityGrant.state == "active"))


def _reaches(node, action, who=SYSTEM):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    with SessionLocal() as db:
        return L.reach(db).reaches(who, node, action)


def test_the_collection_id_is_the_one_mantle_seeds(monkeypatch):
    import origin.services.authority_ledger as L
    _identity(monkeypatch)
    assert L.platform_operators_id() == COLL


def test_the_system_principal_is_given_create_and_nothing_more(platform):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    with SessionLocal() as db:
        assert len(L.grant_definitions_publisher(db, "t1")) == 1
    assert _grants() == [(COLL, "create")]
    assert _reaches(COLL, "create")
    assert not _reaches(COLL, "read") and not _reaches("op-1", "read")
    with SessionLocal() as db:
        assert L.grant_definitions_publisher(db, "t2") == [], "asking again grants nothing more"


def test_no_system_principal_grants_nothing(platform, monkeypatch):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    _identity(monkeypatch, system="")
    with SessionLocal() as db:
        assert L.grant_definitions_publisher(db, "t1") == []


def test_a_collection_someone_else_made_at_that_id_gives_nothing(custody_client, monkeypatch):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    c = custody_client
    af.operator(monkeypatch)
    _identity(monkeypatch)
    bob = af.person("bob")
    _root(c, bob, bob[0])
    af.ok(af.submit(c, bob[1], af.edge(bob[0], COLL), batch="b"))
    with SessionLocal() as db:
        assert L.grant_definitions_publisher(db, "t1") == []
    assert _grants() == []


def _body(resource=COLL, actions=("create",), grantee=SYSTEM, **over):
    return {"kind": "grant", "grant_id": str(uuid.uuid4()), "grantee_id": grantee,
            "grantee_type": "user", "resource_id": resource, "actions": list(actions),
            "effect": "allow", "state": "active", "expires_at": None, "target": None,
            "max_claims": None, **over}


@pytest.mark.parametrize("why, body", [
    ("read beside create", _body(actions=("create", "read"))),
    ("read alone", _body(actions=("read",))),
    ("another resource", _body(resource="op-1")),
    ("an expiry", _body(expires_at="2099-01-01T00:00:00+00:00")),
    ("a deny", _body(effect="deny")),
])
def test_the_operator_grants_the_system_principal_nothing_else(platform, why, body):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    with SessionLocal() as db:
        with pytest.raises(L.EntryRefused):
            L.append(db, body, actor=L.Actor(af.OPERATOR, "operator", "t"),
                     submitted_jti="console:t")
    assert _grants() == [], why


def test_the_route_answers_only_mantle(platform):
    c = platform[0]
    _alice, token = af.person("alice")
    r = c.post("/internal/authority/definitions-grant", json={},
               headers={"Authorization": f"Bearer {token}"})
    assert r.status_code in (401, 403)
    assert _grants() == []

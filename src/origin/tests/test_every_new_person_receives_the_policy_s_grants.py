"""Every new person receives the grants `platform.new_person_grants` names, made by Origin as the
operator's own entries (2026-11-15): read and invoke on each member made in a policy collection the
operator made, and nothing else. Mantle asks only for a person; what they get is decided here.
"""
from __future__ import annotations

import json

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_background_work_runs_on_a_job_grant import _root

custody_client = _shares.custody_client


@pytest.fixture()
def platform(custody_client, monkeypatch):
    """The operator makes the operators' collection C with members op-1 and op-2, and another
    collection D with member d-1; the policy names C with read and invoke."""
    c = custody_client
    op_token = af.operator(monkeypatch)
    op = (af.OPERATOR, op_token)
    _root(c, op, af.OPERATOR)
    coll, other = "C-ops", "D-other"
    for parent, node in ((af.OPERATOR, coll), (af.OPERATOR, other), (coll, "op-1"), (coll, "op-2"),
                         (other, "d-1")):
        af.ok(af.submit(c, op_token, af.edge(parent, node), batch="mk"))
    policy = {"value": json.dumps([{"collection_id": coll, "actions": ["read", "invoke"]}])}
    from origin.services.platform_settings_service import settings as ps
    real_get = ps.get
    monkeypatch.setattr(ps, "get", lambda k, *a, **kw:
                        policy["value"] if k == "platform.new_person_grants" else real_get(k, *a, **kw))
    return c, coll, other, policy


def _grants(person):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant
    with SessionLocal() as db:
        return sorted((g.resource_id, ",".join(sorted(g.actions.split(",")))) for g in db.query(AuthorityGrant)
                      .filter(AuthorityGrant.grantee_id == person, AuthorityGrant.state == "active"))


def test_a_new_person_receives_read_and_invoke_on_each_member_of_the_policy_collection(platform):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    alice, _ = af.person("alice")
    with SessionLocal() as db:
        receipts = L.grant_new_person(db, alice, "t1")
    assert len(receipts) == 2
    assert _grants(alice) == [("op-1", "invoke,read"), ("op-2", "invoke,read")]
    with SessionLocal() as db:
        assert L.grant_new_person(db, alice, "t2") == [], "asking again grants nothing more"


def test_the_ceiling_holds_whatever_the_policy_names(platform):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    _c, coll, _other, policy = platform
    policy["value"] = json.dumps([{"collection_id": coll, "actions": ["read", "invoke", "admin", "share"]}])
    alice, _ = af.person("alice")
    with SessionLocal() as db:
        L.grant_new_person(db, alice, "t1")
    assert {a for _r, a in _grants(alice)} == {"invoke,read"}


def _operator_grant(db, body):
    import origin.services.authority_ledger as L
    return L.append(db, body, actor=L.Actor(af.OPERATOR, "operator", "t"), submitted_jti="console:t")


def _body(grantee, resource, actions=("invoke", "read"), **over):
    import uuid
    return {"kind": "grant", "grant_id": str(uuid.uuid4()), "grantee_id": grantee, "grantee_type": "user",
            "resource_id": resource, "actions": list(actions), "effect": "allow", "state": "active",
            "expires_at": None, "target": None, "max_claims": None, **over}


@pytest.mark.parametrize("why, make", [
    ("a member of a collection the policy does not name", lambda p: _body(p, "d-1")),
    ("more than the policy and the ceiling allow", lambda p: _body(p, "op-1", ("read", "admin"))),
    ("an expiry", lambda p: _body(p, "op-1", expires_at="2099-01-01T00:00:00+00:00")),
    ("a deny", lambda p: _body(p, "op-1", effect="deny")),
    ("not a person", lambda p: _body("nobody-at-all", "op-1")),
    ("the collection itself, not a member", lambda p: _body(p, "C-ops")),
])
def test_the_operator_grants_nothing_else(platform, why, make):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    alice, _ = af.person("alice")
    with SessionLocal() as db:
        with pytest.raises(L.EntryRefused):
            _operator_grant(db, make(alice))
    assert _grants(alice) == [], why


def test_a_collection_someone_else_made_gives_nothing(platform):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    c, _coll, _other, policy = platform
    bob = af.person("bob")
    _root(c, bob, bob[0])
    af.ok(af.submit(c, bob[1], af.edge(bob[0], "B-coll"), batch="b"))
    af.ok(af.submit(c, bob[1], af.edge("B-coll", "b-1"), batch="b"))
    policy["value"] = json.dumps([{"collection_id": "B-coll", "actions": ["read"]}])
    alice, _ = af.person("alice")
    with SessionLocal() as db:
        with pytest.raises(L.EntryRefused):
            L.grant_new_person(db, alice, "t1")
    assert _grants(alice) == []


def test_no_policy_grants_nothing(platform):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    _c, _coll, _other, policy = platform
    policy["value"] = ""
    alice, _ = af.person("alice")
    with SessionLocal() as db:
        assert L.grant_new_person(db, alice, "t1") == []


def test_the_route_answers_only_mantle(platform):
    c = platform[0]
    alice, token = af.person("alice")
    r = c.post("/internal/authority/new-person-grants", json={"person_id": alice},
               headers={"Authorization": f"Bearer {token}"})
    assert r.status_code in (401, 403)
    assert _grants(alice) == []


def _put_policy(c, rows):
    from origin.tests import operator_console_fixtures as oc
    return oc.call(c, "PUT", "/oracle/settings/platform.new_person_grants",
                   json={"value": json.dumps(rows)})


def test_the_operator_sets_the_policy_on_a_collection_they_made(platform):
    c, coll, _other, _policy = platform
    r = _put_policy(c, [{"collection_id": coll, "actions": ["read", "invoke"]}])
    assert r.status_code == 200, r.text


@pytest.mark.parametrize("rows, status", [
    ([{"collection_id": "C-ops", "actions": ["read", "admin"]}], 400),   # beyond the ceiling
    ([{"collection_id": "not-known-here", "actions": ["read"]}], 409),   # not in Origin's replica
    ([], 400),
])
def test_the_policy_is_refused_beyond_what_the_rules_allow(platform, rows, status):
    assert _put_policy(platform[0], rows).status_code == status


def test_a_seeded_collection_is_granted_itself_and_not_its_members(platform):
    """`on: "itself"`: a seeded collection such as Start Here, read, on the collection alone."""
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    _c, _coll, other, policy = platform
    policy["value"] = json.dumps([{"collection_id": other, "actions": ["read"], "on": "itself"}])
    alice, _ = af.person("alice")
    with SessionLocal() as db:
        L.grant_new_person(db, alice, "t1")
    assert _grants(alice) == [(other, "read")]
    with SessionLocal() as db:
        with pytest.raises(L.EntryRefused):
            _operator_grant(db, _body(alice, "d-1", ("read",)))      # its member is not named


def test_both_forms_together(platform):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    _c, coll, other, policy = platform
    policy["value"] = json.dumps([{"collection_id": coll, "actions": ["read", "invoke"]},
                                  {"collection_id": other, "actions": ["read"], "on": "itself"}])
    alice, _ = af.person("alice")
    with SessionLocal() as db:
        L.grant_new_person(db, alice, "t1")
    assert _grants(alice) == [(other, "read"), ("op-1", "invoke,read"), ("op-2", "invoke,read")]

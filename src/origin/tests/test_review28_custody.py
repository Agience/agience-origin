"""Review 28 at Origin.

M1 (John, 2026-11-08): a top-level collection's (a root's) master key is released to a full
reader-Admin of the root: a subject holding Admin on the root who reaches every node whose root
is that root for Read, with no deny on the way (`Reach.full_reader_admin`). The same rule decides
who may grant a job over the root's key (L1), so a job grant never opens a key wider than its
grantor's Read.

L3. Crystal's own server delegation is a persona's delegation at Origin, by the one definition of
the services that hold one (`prism.trust.service_identity.SERVER_DELEGATION_SIGNERS`), with its
verdicts bounded to the actions its Mantle routes take; it still releases no key.

L4. A release says whether the share is still pending, so Mantle replaces a pending share with a
fresh split and completes only an activated one.

I2. `principal_kind` says `root` only for a node with no creation parent; a member is `member`.
"""
from __future__ import annotations

import secrets
import uuid

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_review21_a_secret_is_used_only_on_origin_s_verdict as r21
from origin.tests import test_review25_a_persona_s_delegation_gets_a_bounded_reach_verdict as r25
from origin.tests import test_review27_custody as r27
from origin.tests.test_background_work_runs_on_a_job_grant import _later, _mint

custody_client = r21.custody_client
unsealed_world = r21.unsealed_world
world = r21.world
ALL = r21.ALL


def _tree(c):
    """Alice's root `root` (all of it hers), holding `mid`, holding `deep`, which conducts only
    Update from `mid`."""
    alice = af.person("Alice")
    root, mid, deep = (str(uuid.uuid4()), "c-mid-" + uuid.uuid4().hex[:6],
                       "a-deep-" + uuid.uuid4().hex[:6])
    af.ok(af.submit(c, alice[1], af.root(root), batch="r"))
    af.ok(af.submit(c, alice[1], af.grant("g-r", alice[0], root, ALL), batch="r"))
    af.ok(af.submit(c, alice[1], af.edge(root, mid), batch="r2"))
    af.ok(af.submit(c, alice[1], af.edge(mid, deep, propagate=["update"]), batch="r3"))
    return alice, root, mid, deep


def _job(principal, job="platform.rekey"):
    return {"kind": "job_grant", "grant_id": "jg-" + uuid.uuid4().hex[:8], "job": job,
            "principal": principal, "collections": [], "expires_at": _later(), "state": "active"}


# -- M1 -------------------------------------------------------------------------------------------

def test_a_full_reader_admin_of_a_root_gets_its_master_key(custody_client):
    c = custody_client
    alice = af.person("Alice")
    team, coll = str(uuid.uuid4()), "c-" + uuid.uuid4().hex[:8]
    af.ok(af.submit(c, alice[1], af.root(team), batch="t"))
    af.ok(af.submit(c, alice[1], af.grant("g-t", alice[0], team, ALL), batch="t"))
    af.ok(af.submit(c, alice[1], af.edge(team, coll), batch="t2"))
    assert af.store_share(c, team, credential=alice[1]).status_code == 200
    for scope in ({}, {"collection": team}, {"collection": coll}):
        r = af.release(c, team, alice[1], **scope)
        assert r.status_code == 200, (scope, r.text)


def test_an_admin_who_does_not_read_every_node_of_the_root_gets_nothing(custody_client):
    c = custody_client
    alice, root, mid, deep = _tree(c)
    bob = af.person("Bob")
    af.ok(af.submit(c, alice[1], af.grant("g-rb", bob[0], root, ["read", "admin"]), batch="b"))
    af.store_share(c, root, credential=alice[1])
    assert af.release(c, root, bob[1]).status_code == 403
    assert af.page(bob[0], _job(root)).status_code == 403            # L1: nor a job over it


def test_a_reader_without_admin_gets_nothing(custody_client):
    c = custody_client
    alice = af.person("Alice")
    team = str(uuid.uuid4())
    af.ok(af.submit(c, alice[1], af.root(team), batch="t"))
    af.ok(af.submit(c, alice[1], af.grant("g-t", alice[0], team, ALL), batch="t"))
    bob = af.person("Bob")
    af.ok(af.submit(c, alice[1], af.grant("g-tb", bob[0], team, ["read"]), batch="b"))
    af.store_share(c, team, credential=alice[1])
    assert af.release(c, team, bob[1]).status_code == 403


def test_a_deny_anywhere_under_the_root_refuses(custody_client):
    c = custody_client
    alice = af.person("Alice")
    team, coll = str(uuid.uuid4()), "c-" + uuid.uuid4().hex[:8]
    bob = af.person("Bob")
    af.ok(af.submit(c, alice[1], af.root(team), batch="t"))
    af.ok(af.submit(c, alice[1], af.grant("g-t", alice[0], team, ALL), batch="t"))
    af.ok(af.submit(c, alice[1], af.edge(team, coll), batch="t2"))
    af.ok(af.submit(c, alice[1], af.grant("g-c", alice[0], coll, ALL), batch="t2"))  # creation
    af.ok(af.submit(c, alice[1], af.grant("g-tb", bob[0], team, ["read", "admin"]), batch="b"))
    af.store_share(c, team, credential=alice[1])
    assert af.release(c, team, bob[1]).status_code == 200
    af.ok(af.submit(c, alice[1], af.grant("g-deny", bob[0], coll, ["read"], effect="deny"),
                    batch="d"))
    assert af.release(c, team, bob[1]).status_code == 403


def test_a_full_reader_admin_s_job_grant_opens_the_root_s_key(custody_client):
    c = custody_client
    alice = af.person("Alice")
    team = str(uuid.uuid4())
    af.ok(af.submit(c, alice[1], af.root(team), batch="t"))
    af.ok(af.submit(c, alice[1], af.grant("g-t", alice[0], team, ALL), batch="t"))
    af.store_share(c, team, credential=alice[1])
    assert af.page(alice[0], _job(team)).status_code == 200
    m = _mint(c, team, "platform.rekey")
    assert m.status_code == 200, m.text
    assert af.release(c, team, m.json()["token"]).status_code == 200


# -- L3 -------------------------------------------------------------------------------------------

def _crystal(sub):
    from origin.services.auth_service import issue_delegation_token
    jti = secrets.token_hex(16)
    tok = issue_delegation_token("agience-server-crystal", sub, 300, signer="crystal", jti=jti,
                                 narrowed_scope="persona:crystal")
    r25._record(jti, sub, signer="crystal")
    return tok


@pytest.mark.parametrize("action, allowed", [("read", False), ("invoke", True)])
def test_crystal_s_server_delegation_gets_a_bounded_verdict(world, action, allowed):
    c, _alice, bob = world
    r = r25._reach(c, _crystal(bob[0]), r21.CARD, action)
    assert r.status_code == 200, r.text
    assert r.json()["allowed"] is allowed                          # Bob holds Invoke only


@pytest.mark.parametrize("action", ["admin", "share", "delete", "update", "add"])
def test_crystal_asks_no_verdict_outside_its_routes(world, action):
    c, _alice, bob = world
    assert r25._reach(c, _crystal(bob[0]), r21.CARD, action).status_code == 403


def test_crystal_s_server_delegation_releases_no_key(custody_client):
    from origin.db.session import SessionLocal
    from origin.services import share_credentials

    alice = af.person("Alice")
    with SessionLocal() as db, pytest.raises(share_credentials.CredentialRefused):
        share_credentials.verify_share_credential(db, _crystal(alice[0]))


# -- L4 -------------------------------------------------------------------------------------------

def test_a_release_says_whether_the_share_is_pending(custody_client):
    c = custody_client
    alice = af.person("Alice")
    af.ok(af.submit(c, alice[1], af.root(alice[0]), batch="a"))
    assert af.store_share(c, alice[0], alice[1]).status_code == 200
    assert af.release(c, alice[0], alice[1]).json()["pending"] is True
    assert r27.r26._activate(c, alice[0], alice[1]).status_code == 200
    assert af.release(c, alice[0], alice[1]).json()["pending"] is False


# -- I2 -------------------------------------------------------------------------------------------

def test_a_member_is_no_root(custody_client):
    c = custody_client
    alice, root, mid, _deep = _tree(c)
    r = r27._kinds(c, [root, mid])
    assert r.json()["kinds"] == {root: "root", mid: "member"}

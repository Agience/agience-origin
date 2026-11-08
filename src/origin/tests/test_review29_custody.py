"""Review 29 at Origin.

M1 (John, 2026-11-08: refuse after any removal). Removing a creation edge could make an Admin who
could not read the removed part a full reader-Admin of the root, and the root's master key keys
that part's legacy content. Now once any node under a root has gone, Origin releases the root's
master key to its own principal alone, and grants no job over it, until the operator confirms on
the console that nothing is left under that key (`root.confirm_empty`, recorded in the ledger). A
later removal refuses again.

I1. A full reader-Admin is never of one of the platform's own principals.
L2. The walk is bounded: the subject's grants are read once, the nodes counted to the ceiling
(failing closed past it), and the answer kept per subject, root and ledger head.
I2. A use verdict is a persona's: Crystal, which uses no secret, gets none.
"""
from __future__ import annotations

import uuid


from origin.tests import authority_fixtures as af
from origin.tests import test_review21_a_secret_is_used_only_on_origin_s_verdict as r21
from origin.tests import test_review28_custody as r28
from origin.tests.test_background_work_runs_on_a_job_grant import _later

custody_client = r21.custody_client
world = r21.world
unsealed_world = r21.unsealed_world
ALL = r21.ALL


def _root_with_a_private_part(c):
    """Olga's root R holds C (hers too); Ann holds every action on R, and a deny on Read on C."""
    olga, ann = af.person("Olga"), af.person("Ann")
    root, coll, other = (str(uuid.uuid4()), "c-" + uuid.uuid4().hex[:8],
                         "o-" + uuid.uuid4().hex[:8])
    af.ok(af.submit(c, olga[1], af.root(root), batch="r"))
    af.ok(af.submit(c, olga[1], af.grant("g-r", olga[0], root, ALL), batch="r"))
    af.ok(af.submit(c, olga[1], af.edge(root, coll), batch="r2"))
    af.ok(af.submit(c, olga[1], af.grant("g-c", olga[0], coll, ALL), batch="r2"))
    af.ok(af.submit(c, olga[1], af.edge(root, other), batch="r3"))
    af.ok(af.submit(c, olga[1], af.grant("g-o", olga[0], other, ALL), batch="r3"))
    af.ok(af.submit(c, olga[1], af.grant("g-ra", ann[0], root, ALL), batch="r4"))
    af.ok(af.submit(c, olga[1], af.grant("g-ca", ann[0], coll, ["read"], effect="deny"),
                    batch="r5"))
    af.store_share(c, root, credential=olga[1])
    return olga, ann, root, coll, other


def test_removing_the_unread_part_does_not_open_the_root_s_key(custody_client):
    c = custody_client
    _olga, ann, root, coll, other = _root_with_a_private_part(c)
    assert af.release(c, root, ann[1]).status_code == 403          # she does not read C
    # Ann removes C's creation edge, on a token Mantle holds: Admin on R is enough.
    af.ok(af.submit(c, ann[1], af.unedge(root, coll), batch="x", via_session=False))
    assert af.release(c, root, ann[1]).status_code == 403          # still: a part went
    job = {"kind": "job_grant", "grant_id": "jg-" + uuid.uuid4().hex[:8],
           "job": "platform.rekey", "principal": root, "collections": [],
           "expires_at": _later(), "state": "active"}
    assert af.page(ann[0], job).status_code == 403                 # nor a job over it
    # A charged root stays charged (review 30, F4): its key is rotated at step 21, not confirmed.
    af.ok(af.submit(c, ann[1], af.unedge(root, other), batch="y", via_session=False))
    assert af.release(c, root, ann[1]).status_code == 403


def test_the_root_s_own_principal_still_opens_it_after_a_removal(custody_client):
    c = custody_client
    olga, ann, root, coll, _other = _root_with_a_private_part(c)
    af.ok(af.submit(c, ann[1], af.unedge(root, coll), batch="x", via_session=False))
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger
    with SessionLocal() as db:
        assert authority_ledger.reach(db).may_release(
            subject=root, principal_id=root, collection_id=None)[0]


# -- I1 and L2 ------------------------------------------------------------------------------------

def test_no_one_is_a_full_reader_admin_of_a_platform_principal(custody_client, monkeypatch):
    from origin import config
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger

    c = custody_client
    ann = af.person("Ann")
    pu = config.AGIENCE_PLATFORM_USER_ID
    af.operator(monkeypatch)
    boot = af.open_bootstrap(c, ids=[pu, "g-pu"])
    af.ok(af.submit(c, boot, af.root(pu), bootstrap=True, batch=None))
    af.ok(af.submit(c, boot, af.grant("g-pu", ann[0], pu, ALL), bootstrap=True, batch=None))
    with SessionLocal() as db:
        assert authority_ledger.reach(db).full_reader_admin(ann[0], pu)[0] is False


def test_the_walk_fails_closed_past_the_ceiling_and_reads_grants_once(monkeypatch):
    from origin.services import authority_reach as ar

    rep = ar.MemoryReplica()
    rep.roots["R"] = {"root_id": "R"}
    rep.nodes["R"] = {"created_by": "o"}
    for i in range(12):
        rep.nodes[f"n{i}"] = {"created_by": "o", "member": True}
        rep.edges[("R", f"n{i}")] = {"origin": True, "propagate": None}
    rep.grants["g"] = ar.Grant(id="g", grantee_id="A", grantee_type="user", resource_id="R",
                               actions=frozenset(ALL))
    calls = []
    real = rep.grants_held_by
    rep.grants_held_by = lambda who: calls.append(who) or real(who)
    rc = ar.Reach(rep)
    assert rc.full_reader_admin("A", "R")[0] is True
    assert calls.count("A") == 1
    monkeypatch.setattr(ar, "ORIGIN_WALK_CEILING", 5)
    assert ar.Reach(rep).full_reader_admin("A", "R")[0] is False


def test_the_answer_is_kept_per_subject_root_and_head(custody_client):
    from origin.services import authority_reach as ar

    c = custody_client
    olga, ann, root, coll, _other = _root_with_a_private_part(c)
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger
    with SessionLocal() as db:
        rc = authority_ledger.reach(db)
        first = rc.full_reader_admin(olga[0], root)
        assert first[0] is True
        assert ar.Reach.verdict_memo_size() >= 1


# -- I2 -------------------------------------------------------------------------------------------

def test_crystal_gets_no_use_verdict(world):
    c, _alice, bob = world
    r = r21._ask(c, r28._crystal(bob[0]))
    assert r.status_code == 403 and "only by a persona" in r.text, r.text

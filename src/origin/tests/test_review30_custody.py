"""Review 30 at Origin.

F1. A creation edge is removed, never demoted: a demotion (origin true to false) would delete the
member at Origin without charging its root. Bootstrap may not demote either, nor give a gone node
a creation edge; migration 0029 charges past demotions.

F2. `verify_chain` replays the removal charges (`part_removed_seq`, `confirmed_empty_seq`) and an
old ledger's `root.confirm_empty` entry, and compares them with the tables.

F3. A memoized full reader-Admin answer lapses when the earliest of the subject's grants it rested
on expires.

F4 (John, 2026-11-08: rotate, do not confirm). A charged root's master key opens for its own
principal alone, permanently: there is no confirmation. `root.confirm_empty` is kept only so an
old ledger replays; no new one is taken. The operator may grant `platform.custody` over a charged
root's key, the new key step 21 rotates it to, so step 23 can split it; Origin names the charged
roots to Mantle (`principal-kinds`).

I1. The platform's own principals include Crystal's server principal.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_review21_a_secret_is_used_only_on_origin_s_verdict as r21
from origin.tests import test_review27_custody as r27
from origin.tests import test_review29_custody as r29

custody_client = r21.custody_client
ALL = r21.ALL


# -- F1 -------------------------------------------------------------------------------------------

def test_a_creation_edge_is_never_demoted(custody_client):
    c = custody_client
    olga, ann, root, coll, _other = r29._root_with_a_private_part(c)
    r = af.session_submit(c, olga[0], af.edge(root, coll, origin=False))
    assert r.status_code == 403 and "never demoted" in r.text, r.text
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger
    with SessionLocal() as db:
        rc = authority_ledger.reach(db)
        assert not rc.gone(coll) and not rc.part_removed(root)
    assert af.release(c, root, ann[1]).status_code == 403


def test_bootstrap_neither_demotes_nor_re_creates_a_gone_node(custody_client, monkeypatch):
    c = custody_client
    _olga, ann, root, coll, other = r29._root_with_a_private_part(c)
    af.ok(af.submit(c, ann[1], af.unedge(root, coll), batch="x", via_session=False))
    af.operator(monkeypatch)
    boot = af.open_bootstrap(c, ids=[root, coll, other])
    # The route refuses (a bootstrap states only ids the ledger has not seen) ...
    for entry in (af.edge(root, other, origin=False), af.edge(root, coll)):
        assert af.submit(c, boot, entry, bootstrap=True, batch=None).status_code in (403, 409)


def test_the_edge_rule_refuses_a_bootstrap_demotion_or_revival():
    """... and the edge rule itself refuses both, whatever else a bootstrap passes."""
    from origin.services.authority_ledger import Context, EntryRefused, _decide_edge_add
    from origin.services.authority_reach import MemoryReplica, Reach

    rep = MemoryReplica()
    rep.nodes.update({"R": {"created_by": ""}, "C": {"created_by": "", "member": True},
                      "G": {"created_by": "", "member": True}})
    rep.roots["R"] = {"root_id": "R"}
    rep.edges[("R", "C")] = {"origin": True, "propagate": None}
    boot = Context(actor="op", kind="bootstrap", bootstrap=True)
    with pytest.raises(EntryRefused, match="never demoted"):
        _decide_edge_add(Reach(rep), boot, {"kind": "edge.add", "src": "R", "dst": "C",
                                             "origin": False, "propagate": None})
    with pytest.raises(EntryRefused, match="takes no creation edge"):
        _decide_edge_add(Reach(rep), boot, {"kind": "edge.add", "src": "R", "dst": "G",
                                             "origin": True, "propagate": None})


# -- F2 -------------------------------------------------------------------------------------------

def test_the_ledger_verifies_with_charges_and_an_old_confirmation(custody_client, monkeypatch):
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger as al

    c = custody_client
    _olga, ann, root, coll, _other = r29._root_with_a_private_part(c)
    af.ok(af.submit(c, ann[1], af.unedge(root, coll), batch="x", via_session=False))
    # A confirmation an older Origin took (review 29): written as it was then, to replay now.
    real = al._decide_operator
    monkeypatch.setattr(al, "_decide_operator", lambda rc, ctx, b: "an older Origin took it"
                        if b["kind"] == "root.confirm_empty" else real(rc, ctx, b))
    with SessionLocal() as db:
        al.append(db, {"kind": "root.confirm_empty", "principal_id": root},
                  actor=al.Actor("op", "operator", "old"), submitted_jti="console:old")
    monkeypatch.setattr(al, "_decide_operator", real)
    with SessionLocal() as db:
        ok, detail = al.verify_chain(db)
        assert ok, detail
        assert al.reach(db).part_removed(root)                 # charged for good, even so
        node = al._tables(db).nodes[root]
        assert node["part_removed_seq"] and node["confirmed_empty_seq"]


# -- F3 -------------------------------------------------------------------------------------------

def test_an_expired_grant_does_not_keep_a_cached_full_reader_yes(custody_client):
    c = custody_client
    olga, ann = af.person("Olga"), af.person("Ann")
    root, other = str(uuid.uuid4()), "o-" + uuid.uuid4().hex[:8]
    af.ok(af.submit(c, olga[1], af.root(root), batch="r"))
    af.ok(af.submit(c, olga[1], af.grant("g-r", olga[0], root, ALL), batch="r"))
    af.ok(af.submit(c, olga[1], af.edge(root, other), batch="r3"))
    af.ok(af.submit(c, olga[1], af.grant("g-o", olga[0], other, ALL), batch="r3"))
    soon = (datetime.now(timezone.utc) + timedelta(seconds=3)).isoformat()
    af.ok(af.submit(c, olga[1], af.grant("g-ra", ann[0], root, ALL, expires_at=soon),
                    batch="r4"))
    af.store_share(c, root, credential=olga[1])
    assert af.release(c, root, ann[1]).status_code == 200
    time.sleep(3.5)
    assert af.release(c, root, ann[1]).status_code == 403


# -- F4 -------------------------------------------------------------------------------------------

def test_a_charged_root_opens_for_its_own_principal_alone_for_good(custody_client, monkeypatch):
    c = custody_client
    _olga, ann, root, coll, _other = r29._root_with_a_private_part(c)
    af.ok(af.submit(c, ann[1], af.unedge(root, coll), batch="x", via_session=False))
    af.operator(monkeypatch)
    r = oc.call(c, "POST", "/oracle/authority-ledger/confirm-empty", json={"principal_id": root})
    assert r.status_code in (404, 405)                         # there is no confirmation
    assert af.release(c, root, ann[1]).status_code == 403


def test_the_operator_grants_custody_over_a_charged_root_only(custody_client, monkeypatch):
    from origin import service_identity
    from origin.tests.test_background_work_runs_on_a_job_grant import _mint

    c = custody_client
    _olga, ann, root, coll, _other = r29._root_with_a_private_part(c)
    af.operator(monkeypatch)
    monkeypatch.setattr(service_identity, "get_system_principal_id",
                        lambda: "00000000-0000-0000-0000-00000000005e")
    grant = {"job": "platform.custody", "hours": 2, "principal": root}
    assert oc.call(c, "POST", "/oracle/job-grants", json=grant).status_code == 403  # uncharged
    af.ok(af.submit(c, ann[1], af.unedge(root, coll), batch="x", via_session=False))
    # Charged: granted once step 21's rotation is recorded (review 31).
    assert oc.call(c, "POST", f"/oracle/charged-roots/{root}/rotation",
                   json={"kcv": "b" * 32}).status_code == 200
    r = oc.call(c, "POST", "/oracle/job-grants", json=grant)
    assert r.status_code == 200, r.text
    assert _mint(c, root, "platform.custody").status_code == 200


def test_origin_names_the_charged_roots(custody_client):
    c = custody_client
    _olga, ann, root, coll, other = r29._root_with_a_private_part(c)
    af.ok(af.submit(c, ann[1], af.unedge(root, coll), batch="x", via_session=False))
    r = r27._kinds(c, [root, other])
    assert r.json()["charged"] == [root]


# -- I1 -------------------------------------------------------------------------------------------

def test_crystal_s_server_principal_is_the_platform_s_own():
    from origin.services.authority_ledger import platform_principals
    assert "agience-server-crystal" in platform_principals()


@pytest.mark.parametrize("_", [0])
def test_the_migration_charges_a_past_demotion(_, monkeypatch):
    import json

    import sqlalchemy as sa

    from origin.tests.test_review29_migration_charges_past_removals import _Op, _migration

    engine = sa.create_engine("sqlite://")
    with engine.connect() as c:
        c.execute(sa.text("CREATE TABLE authority_nodes (node_id TEXT PRIMARY KEY)"))
        c.execute(sa.text("CREATE TABLE authority_edges (src TEXT, dst TEXT, origin BOOLEAN)"))
        c.execute(sa.text("CREATE TABLE authority_ledger (seq INTEGER, kind TEXT, body TEXT, "
                          "bootstrap BOOLEAN, compensates INTEGER)"))
        for n in ("R", "C"):
            c.execute(sa.text("INSERT INTO authority_nodes VALUES (:n)"), {"n": n})
        c.execute(sa.text("INSERT INTO authority_edges VALUES ('R', 'C', 0)"))
        for seq, body in ((1, {"kind": "root", "principal_id": "R", "root_id": "R"}),
                          (2, {"kind": "edge.add", "src": "R", "dst": "C", "origin": True}),
                          (3, {"kind": "edge.add", "src": "R", "dst": "C", "origin": False})):
            c.execute(sa.text("INSERT INTO authority_ledger VALUES (:s, :k, :b, 0, NULL)"),
                      {"s": seq, "k": body["kind"], "b": json.dumps(body)})   # 3: demoted
        mod = _migration()
        monkeypatch.setattr(mod, "op", _Op(c))
        mod.upgrade()
        got = dict(c.execute(sa.text(
            "SELECT node_id, part_removed_seq FROM authority_nodes")).fetchall())
    assert got == {"R": 3, "C": None}

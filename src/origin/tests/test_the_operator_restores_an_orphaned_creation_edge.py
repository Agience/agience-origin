"""The operator restores a creation edge a removal took from a member still held elsewhere
(2026-11-14: a drag-move removed it, and Origin read the member as deleted while another workspace
still listed it). The edge comes back as it was; nothing else is widened."""
from __future__ import annotations

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_background_work_runs_on_a_job_grant import _root

custody_client = _shares.custody_client


def _orphan(c):
    """Alice makes X in her workspace A, shows it in C too, then removes it from A."""
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityEntry
    alice = af.person("alice", email="alice@team.test")
    _root(c, alice, alice[0])
    a, cc, x = alice[0], "C-" + alice[0][:8], "X-" + alice[0][:8]
    for node in (cc, x):
        af.ok(af.submit(c, alice[1], af.edge(a, node), batch="mk"))
        af.ok(af.submit(c, alice[1], af.grant("g-" + node, a, node, ("read", "delete", "admin")),
                        batch="mk"))
    af.ok(af.submit(c, alice[1], af.edge(cc, x, origin=False), batch="ln"))
    af.ok(af.submit(c, alice[1], af.unedge(a, x), batch="rm"))
    with SessionLocal() as db:
        seq = max(r.seq for r in db.query(AuthorityEntry).filter(AuthorityEntry.kind == "edge.remove"))
    return alice, a, cc, x, seq


def test_the_removal_orphans_and_the_restore_brings_the_creation_edge_back(custody_client):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    c = custody_client
    alice, a, cc, x, seq = _orphan(c)
    with SessionLocal() as db:
        rc = L.reach(db)
        assert rc.gone(x), "the removal should have orphaned X"
        L.restore_creation_edge(db, seq, "operator-1", "repair-1")
    with SessionLocal() as db:
        rc = L.reach(db)
        assert not rc.gone(x)
        assert rc.origin_parent(x)[0] == a
        assert rc.r.edge(cc, x)["origin"] is False, "the other container's edge stays a link"


def test_the_operator_adds_no_other_edge(custody_client):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    c = custody_client
    alice, a, cc, x, seq = _orphan(c)
    with SessionLocal() as db:
        L.restore_creation_edge(db, seq, "operator-1", "repair-1")
        with pytest.raises(L.EntryRefused):
            L.restore_creation_edge(db, seq, "operator-1", "repair-2")      # already restored
        with pytest.raises(L.EntryRefused):
            L.append(db, af.edge(cc, x), actor=L.Actor("operator-1", "operator", "x"))

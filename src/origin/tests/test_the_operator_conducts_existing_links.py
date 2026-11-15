"""The operator's rewrite of existing links (John, 2026-11-15): a link stored with the empty mask
conducts once the person who added it holds Share on what it links; every other link, and every
other edge, keeps its mask. Running it again changes nothing."""
from __future__ import annotations

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_background_work_runs_on_a_job_grant import _root

custody_client = _shares.custody_client


def _store(c):
    """Alice's workspace A holds C and X; she links C -> X with the empty mask. Bob's workspace B
    holds Y, which Alice may only read; she links C -> Y with the empty mask too. A third item Z,
    Alice's, is linked into C with a mask that carries read only."""
    alice = af.person("alice", email="alice@team.test")
    bob = af.person("bob", email="bob@team.test")
    _root(c, alice, alice[0])
    _root(c, bob, bob[0])
    a, b = alice[0], bob[0]
    cc, x, z, y = "C-" + a[:8], "X-" + a[:8], "Z-" + a[:8], "Y-" + b[:8]
    for node in (cc, x, z):
        af.ok(af.submit(c, alice[1], af.edge(a, node), batch="mk"))
        af.ok(af.submit(c, alice[1], af.grant("g-" + node, a, node, ("read", "add", "admin")),
                        batch="mk"))
    af.ok(af.submit(c, bob[1], af.edge(b, y), batch="mk"))
    af.ok(af.submit(c, bob[1], af.grant("g-" + y, b, y, ("read", "admin")), batch="mk"))
    af.ok(af.submit(c, bob[1], af.grant("g-alice-" + y, a, y, ("read",)), batch="mk"))
    af.ok(af.submit(c, alice[1], af.edge(cc, x, origin=False, propagate=[]), batch="ln"))
    af.ok(af.submit(c, alice[1], af.edge(cc, y, origin=False, propagate=[]), batch="ln"))
    af.ok(af.submit(c, alice[1], af.edge(cc, z, origin=False, propagate=["read"]), batch="ln"))
    return alice, bob, cc, x, y, z


def _mask(src, dst):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    with SessionLocal() as db:
        e = L.reach(db).r.edge(src, dst)
        return None if e is None else (e["origin"], e["propagate"])


def _count():
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityEntry
    with SessionLocal() as db:
        return db.query(AuthorityEntry).count()


def test_the_plan_conducts_the_link_its_adder_shares_and_keeps_the_others(custody_client):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    alice, bob, cc, x, y, z = _store(custody_client)
    with SessionLocal() as db:
        conduct, kept = L.links_to_conduct(db)
    assert (cc, x) in conduct
    assert (cc, y, alice[0]) in [tuple(k) for k in kept], "Alice holds no Share on Bob's Y"
    assert all(p[:2] != (cc, z) for p in [*conduct, *kept]), "a non-empty mask is not a candidate"


def test_the_rewrite_conducts_only_the_shared_link(custody_client):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    alice, bob, cc, x, y, z = _store(custody_client)
    with SessionLocal() as db:
        receipts = L.conduct_existing_links(db, "operator-1", "links-1")
    assert len(receipts) == 1
    origin_x, mask_x = _mask(cc, x)
    assert origin_x is False and mask_x is None, "the link stays a link and conducts everything"
    assert L._same_mask(_mask(cc, y)[1], []), "the link to Bob's Y stays blocked"
    assert L._same_mask(_mask(cc, z)[1], ["read"]), "a non-empty mask is untouched"


def test_running_it_again_changes_nothing(custody_client):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    _store(custody_client)
    with SessionLocal() as db:
        L.conduct_existing_links(db, "operator-1", "links-1")
    before = _count()
    with SessionLocal() as db:
        assert L.conduct_existing_links(db, "operator-1", "links-2") == []
    assert _count() == before


def test_the_operator_cannot_conduct_a_link_whose_adder_lacks_share(custody_client):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    alice, bob, cc, x, y, z = _store(custody_client)
    before = _count()
    with SessionLocal() as db:
        with pytest.raises(L.EntryRefused) as refused:
            L.append(db, af.edge(cc, y, origin=False), actor=L.Actor("operator-1", "operator", "x"))
    assert refused.value.status == 403
    with SessionLocal() as db:
        with pytest.raises(L.EntryRefused):      # a non-empty mask is not the operator's to widen
            L.append(db, af.edge(cc, z, origin=False), actor=L.Actor("operator-1", "operator", "x"))
    assert _count() == before


def test_the_operator_cannot_make_a_link_that_does_not_exist(custody_client):
    import origin.services.authority_ledger as L
    from origin.db.session import SessionLocal
    alice, bob, cc, x, y, z = _store(custody_client)
    with SessionLocal() as db:
        with pytest.raises(L.EntryRefused):
            L.append(db, af.edge(x, z, origin=False), actor=L.Actor("operator-1", "operator", "x"))

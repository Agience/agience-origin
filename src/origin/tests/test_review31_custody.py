"""Review 31, at Origin, through Origin's real apply, routes and `verify_chain`.

H1. The operator's `platform.custody` over a charged root is for the split of the key step 21
    rotated, and its read-back, alone: the grant needs the rotation recorded first (the rotated
    key's kcv, on the operator's console), lives at most two hours, releases the root's share only
    while the share Origin holds is that key's and still pending, and ends when it is activated.
    A share of any other key is neither stored nor released.
L1. The withdrawal of a creation whose write never committed (a compensating `edge.remove`)
    removes nothing of the root, and charges nothing.
L2. Migration 0029's fill is what `replay` produces: a past demotion is charged by both, and each
    removal is charged to the root its source sat under at that entry, so `verify_chain` passes
    on a migrated ledger.
"""
from __future__ import annotations

import contextlib
import uuid
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests import test_review21_a_secret_is_used_only_on_origin_s_verdict as r21
from origin.tests import test_review29_custody as r29

custody_client = r21.custody_client
ALL = r21.ALL
SYSTEM = "00000000-0000-0000-0000-00000000005e"


def _activate(c, principal, credential):
    tok = _shares._token("POST", principal, htu=f"/internal/key-shares/{principal}/activate")
    return c.post(f"/internal/key-shares/{principal}/activate",
                  headers={"Authorization": f"Bearer {tok}", "X-Acting-Credential": credential})


def _charged(c, monkeypatch):
    from origin import service_identity

    _olga, ann, root, coll, _other = r29._root_with_a_private_part(c)
    af.ok(af.submit(c, ann[1], af.unedge(root, coll), batch="x", via_session=False))
    assert af.release(c, root, ann[1]).status_code == 403          # charged: Ann is refused
    af.operator(monkeypatch)
    monkeypatch.setattr(service_identity, "get_system_principal_id", lambda: SYSTEM)
    return root


def _grant(c, root, hours=24 * 30):
    return oc.call(c, "POST", "/oracle/job-grants",
                   json={"job": "platform.custody", "hours": hours, "principal": root})


def _record(c, root, kcv):
    return oc.call(c, "POST", f"/oracle/charged-roots/{root}/rotation", json={"kcv": kcv})


def test_the_operator_grants_custody_over_a_charged_root_only_after_its_rotation(
        custody_client, monkeypatch):
    c = custody_client
    root = _charged(c, monkeypatch)
    # No rotation recorded (step 21 skipped the root): no grant at all.
    r = _grant(c, root)
    assert r.status_code == 409, r.text
    assert "rotation" in r.text
    # Recorded for anything but a charged root: refused.
    plain = str(uuid.uuid4())
    olga = af.person("Olga")
    af.ok(af.submit(c, olga[1], af.root(plain), batch="p"))
    assert _record(c, plain, _shares.KCV_B).status_code == 409
    assert _record(c, root, "not-a-kcv").status_code == 400
    # Recorded: granted, and for two hours at most whatever is asked.
    assert _record(c, root, _shares.KCV_B).status_code == 200
    r = _grant(c, root)
    assert r.status_code == 200, r.text
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityJobGrant
    from origin.services.authority_ledger import parse_time
    with SessionLocal() as db:
        row = db.query(AuthorityJobGrant).filter(AuthorityJobGrant.principal == root,
                                                 AuthorityJobGrant.state == "active").one()
        assert parse_time(row.expires_at) <= datetime.now(timezone.utc) + timedelta(
            hours=2, minutes=1)


def test_a_charged_root_s_key_is_released_only_while_its_rotated_split_reads_back(
        custody_client, monkeypatch):
    from origin.tests.test_background_work_runs_on_a_job_grant import _mint

    c = custody_client
    root = _charged(c, monkeypatch)
    assert _record(c, root, _shares.KCV_B).status_code == 200
    assert _grant(c, root).status_code == 200
    token = _mint(c, root, "platform.custody").json()["token"]
    # The share Origin holds is the OLD key's (as when step 21 skipped the root, or the key was
    # split before it): never released, on the operator's custody job or any other.
    rel = af.release(c, root, token)
    assert rel.status_code == 403, rel.text
    # Nor is a share of any key but the recorded rotated one stored.
    other = af.store_share(c, root, credential=token, kcv=_shares.KCV_A,
                           y=_shares.SHARE_Y[:-4] + "AAA=")
    assert other.status_code == 403, other.text
    # The split of the rotated key: stored over the pending old share, then read back.
    put = af.store_share(c, root, credential=token, kcv=_shares.KCV_B,
                         supersedes=_shares.KCV_A)
    assert put.status_code == 200, put.text
    back = af.release(c, root, token)
    assert back.status_code == 200, back.text
    assert back.json()["kcv"] == _shares.KCV_B and back.json()["pending"] is True
    # Activated: the grant ends, nothing more is minted, and nothing more is released.
    assert _activate(c, root, token).status_code == 200
    assert af.release(c, root, token).status_code == 403
    assert _mint(c, root, "platform.custody").status_code == 403
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityJobGrant
    with SessionLocal() as db:
        assert db.query(AuthorityJobGrant).filter(AuthorityJobGrant.principal == root,
                                                  AuthorityJobGrant.state == "active").count() == 0
    # And no new grant, nor a new rotation, once the split is done.
    assert _grant(c, root).status_code == 409
    assert _record(c, root, _shares.KCV_A).status_code == 409


def test_a_withdrawn_creation_does_not_charge_its_root(custody_client):
    """A creation edge co-signed and then withdrawn (its write lost at Mantle) by an `edge.remove`
    compensation: nothing of the root was ever removed."""
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger as al

    c = custody_client
    olga = af.person("Olga")
    R, C = str(uuid.uuid4()), "c-" + uuid.uuid4().hex[:8]
    af.ok(af.submit(c, olga[1], af.root(R), batch="r"))
    af.ok(af.submit(c, olga[1], af.grant("g-r", olga[0], R, ALL), batch="r"))
    added = af.ok(af.submit(c, olga[1], af.edge(R, C), batch="r2"))
    seq = added.get("seq") or (added.get("receipt") or {}).get("seq")
    r = af.submit(c, olga[1], af.unedge(R, C), compensates=int(seq), batch="r2",
                  via_session=False)
    assert r.status_code == 200, r.text
    with SessionLocal() as db:
        assert not al.reach(db).part_removed(R)
        ok, detail = al.verify_chain(db)
        assert ok, detail
    # A real removal still charges it.
    D = "d-" + uuid.uuid4().hex[:8]
    af.ok(af.submit(c, olga[1], af.edge(R, D), batch="r3"))
    af.ok(af.submit(c, olga[1], af.unedge(R, D), batch="r4", via_session=False))
    with SessionLocal() as db:
        assert al.reach(db).part_removed(R)
        ok, detail = al.verify_chain(db)
        assert ok, detail


class _Fill:
    """Alembic's `op` for migration 0029's fill alone, over Origin's real tables (the columns are
    already there)."""

    def __init__(self, conn):
        self.conn = conn

    def get_bind(self):
        return self.conn

    @contextlib.contextmanager
    def batch_alter_table(self, name):
        class _B:
            def add_column(self, col):
                pass
        yield _B()


def _migrate_as_before_0029():
    """Clear the charges (the state before 0029) and run 0029's fill on the real tables."""
    from origin.db.session import SessionLocal
    from origin.tests.test_review29_migration_charges_past_removals import _migration

    mod = _migration()
    with SessionLocal() as db:
        conn = db.connection()
        conn.execute(sa.text("UPDATE authority_nodes SET part_removed_seq = NULL"))
        mod.op = _Fill(conn)
        mod.upgrade()
        db.commit()


def test_a_migrated_ledger_with_bottom_up_removals_verifies(custody_client):
    """R -> X -> A, each a creation edge. A is removed first (charged to R then), then X (charged
    to R). Apply, replay and 0029 all charge R alone."""
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger as al

    c = custody_client
    olga = af.person("Olga")
    R, X, A = str(uuid.uuid4()), "x-" + uuid.uuid4().hex[:8], "a-" + uuid.uuid4().hex[:8]
    af.ok(af.submit(c, olga[1], af.root(R), batch="r"))
    af.ok(af.submit(c, olga[1], af.grant("g-r", olga[0], R, ALL), batch="r"))
    af.ok(af.submit(c, olga[1], af.edge(R, X), batch="r2"))
    af.ok(af.submit(c, olga[1], af.grant("g-x", olga[0], X, ALL), batch="r2"))
    af.ok(af.submit(c, olga[1], af.edge(X, A), batch="r3"))
    af.ok(af.submit(c, olga[1], af.grant("g-a", olga[0], A, ALL), batch="r3"))
    af.ok(af.submit(c, olga[1], af.unedge(X, A), batch="d1", via_session=False))
    af.ok(af.submit(c, olga[1], af.unedge(R, X), batch="d2", via_session=False))
    with SessionLocal() as db:
        ok, detail = al.verify_chain(db)
        assert ok, detail
    _migrate_as_before_0029()
    with SessionLocal() as db:
        ok, detail = al.verify_chain(db)
        assert al.reach(db).part_removed(R)
        assert not al.reach(db).part_removed(X)
        assert ok, detail


def test_a_migrated_ledger_with_a_past_demotion_verifies(custody_client, monkeypatch):
    """A demotion an older Origin took (written as it was then), then 0029's fill: apply, replay
    and the fill all charge R."""
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger as al

    c = custody_client
    olga = af.person("Olga")
    R, C = str(uuid.uuid4()), "c-" + uuid.uuid4().hex[:8]
    af.ok(af.submit(c, olga[1], af.root(R), batch="r"))
    af.ok(af.submit(c, olga[1], af.grant("g-r", olga[0], R, ALL), batch="r"))
    af.ok(af.submit(c, olga[1], af.edge(R, C), batch="r2"))
    real = al._decide_edge_add
    monkeypatch.setattr(al, "_decide_edge_add",
                        lambda rc, ctx, b: "an older Origin took it" if not b["origin"]
                        else real(rc, ctx, b))
    monkeypatch.setitem(al._DECIDE, "edge.add", al._decide_edge_add)
    r = af.session_submit(c, olga[0], af.edge(R, C, origin=False))
    monkeypatch.setitem(al._DECIDE, "edge.add", real)
    monkeypatch.setattr(al, "_decide_edge_add", real)
    assert r.status_code == 200, r.text
    with SessionLocal() as db:
        assert al.reach(db).part_removed(R)
        ok, detail = al.verify_chain(db)
        assert ok, detail
    _migrate_as_before_0029()
    with SessionLocal() as db:
        assert al.reach(db).part_removed(R)
        ok, detail = al.verify_chain(db)
        assert ok, detail

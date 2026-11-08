"""Review 32, at Origin, through Origin's real routes.

F1. A recorded kcv is never one Origin already holds a share of (the current share's, or any in
    its share history), and a charged root's share is released only once a share was written
    after the rotation was recorded.
F2. A charged root's split is open only under the first custody grant made after the record, and
    only while that grant lives: once it ends (revoked, expired), no later grant reopens it
    without a new record of a fresh kcv. The operator lists the charged roots whose shares are not
    activated.
F5, F6. A seed's re-mark of a split charged root alone reopens nothing; with a new record of a
    fresh kcv, the split goes through over the activated share.
"""
from __future__ import annotations

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests import test_review31_custody as r31
from origin.tests.test_background_work_runs_on_a_job_grant import _mint

custody_client = r31.custody_client
KCV_C = "c" * 32
KCV_D = "d" * 32


def _live_grant(root):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityJobGrant
    with SessionLocal() as db:
        return db.query(AuthorityJobGrant).filter(AuthorityJobGrant.principal == root,
                                                  AuthorityJobGrant.state == "active").one().grant_id


def test_a_recorded_kcv_of_the_old_key_is_refused(custody_client, monkeypatch):
    c = custody_client
    root = r31._charged(c, monkeypatch)
    # The fixture's pending first share is the OLD key's (kcv A): its kcv is no rotated key's.
    r = r31._record(c, root, _shares.KCV_A)
    assert r.status_code == 409, r.text
    # A fresh kcv is recorded; a share Origin held before the record is never released.
    assert r31._record(c, root, _shares.KCV_B).status_code == 200
    assert r31._grant(c, root, hours=2).status_code == 200
    token = _mint(c, root, "platform.custody").json()["token"]
    assert af.release(c, root, token).status_code == 403
    # Written after the record, under the recorded kcv: read back.
    put = af.store_share(c, root, credential=token, kcv=_shares.KCV_B)
    assert put.status_code == 200, put.text
    assert af.release(c, root, token).status_code == 200
    # A kcv once held, now in the share history, is refused too.
    assert r31._record(c, root, _shares.KCV_A).status_code == 409
    # The current pending share's kcv is recorded again only as its own re-split (review 33).
    assert r31._record(c, root, _shares.KCV_B).status_code == 200
    assert af.release(c, root, token).status_code == 403            # the new record: no write


def test_an_unactivated_charged_split_closes_with_its_grant(custody_client, monkeypatch):
    c = custody_client
    root = r31._charged(c, monkeypatch)
    assert r31._record(c, root, _shares.KCV_B).status_code == 200
    assert r31._grant(c, root, hours=2).status_code == 200
    token = _mint(c, root, "platform.custody").json()["token"]
    assert af.store_share(c, root, credential=token, kcv=_shares.KCV_B).status_code == 200
    assert af.release(c, root, token).status_code == 200            # the read-back
    listed = oc.call(c, "GET", "/oracle/charged-roots/shares").json()
    assert root in listed["pending"] and listed["pending_count"] >= 1
    # Activation never reaches Origin, and the grant ends.
    assert oc.call(c, "POST", f"/oracle/job-grants/{_live_grant(root)}/revoke").status_code == 200
    assert _mint(c, root, "platform.custody").status_code == 403
    # No later grant reopens it: a new record is needed, and it needs a fresh kcv.
    again = r31._grant(c, root, hours=2)
    assert again.status_code == 409, again.text
    assert r31._record(c, root, KCV_C).status_code == 200
    assert r31._grant(c, root, hours=2).status_code == 200
    token2 = _mint(c, root, "platform.custody").json()["token"]
    assert af.release(c, root, token2).status_code == 403             # nothing written since
    # The new split replaces the pending share of the earlier kcv, then reads back.
    assert af.store_share(c, root, credential=token2, kcv=KCV_C).status_code == 200
    assert af.release(c, root, token2).status_code == 200
    assert r31._activate(c, root, token2).status_code == 200
    listed = oc.call(c, "GET", "/oracle/charged-roots/shares").json()
    assert root not in listed["pending"] and root in listed["activated"]


def _mark(c, principal, credential):
    tok = _shares._token("POST", principal, htu=f"/internal/key-shares/{principal}/rekey-pending")
    return c.post(f"/internal/key-shares/{principal}/rekey-pending",
                  headers={"Authorization": f"Bearer {tok}", "X-Acting-Credential": credential})


def test_a_re_mark_alone_reopens_nothing_and_a_fresh_record_resplits(custody_client,
                                                                   monkeypatch):
    c = custody_client
    root = r31._charged(c, monkeypatch)
    assert r31._record(c, root, _shares.KCV_B).status_code == 200
    assert r31._grant(c, root, hours=2).status_code == 200
    token = _mint(c, root, "platform.custody").json()["token"]
    assert af.store_share(c, root, credential=token, kcv=_shares.KCV_B).status_code == 200
    assert r31._activate(c, root, token).status_code == 200
    # The rollback (offline escrow combine) is followed by a seed's re-mark of the share.
    seed = oc.call(c, "POST", "/oracle/seed-credential", json={"minutes": 10,
                                                                "rekey_shares": [root]})
    assert seed.status_code == 200, seed.text
    assert _mark(c, root, seed.json()["token"]).status_code == 200
    # The re-mark alone: no grant, and nothing released.
    assert r31._grant(c, root, hours=2).status_code == 409
    # Step 21 rotates again: a fresh kcv is recorded, granted, and the split goes through.
    assert r31._record(c, root, KCV_D).status_code == 200
    assert r31._grant(c, root, hours=2).status_code == 200
    token2 = _mint(c, root, "platform.custody").json()["token"]
    assert af.release(c, root, token2).status_code == 403
    assert af.store_share(c, root, credential=token2, kcv=KCV_D).status_code == 200
    back = af.release(c, root, token2)
    assert back.status_code == 200 and back.json()["kcv"] == KCV_D

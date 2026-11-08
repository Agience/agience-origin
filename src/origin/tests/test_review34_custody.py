"""Review 34, at Origin, through Origin's real routes.

F1. Once a charged root's split is activated, its kcv is never recorded again, not even after a
    seed's re-mark: the same-kcv re-split (review 33) is for a pending split alone, and a new
    record needs a fresh kcv.
F3. A new record of a charged root revokes the custody grant bound to the record before it, so no
    two custody grants over the root live at once, and a delegation minted under the earlier one
    writes and releases nothing.
"""
from __future__ import annotations

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests import test_review31_custody as r31
from origin.tests import test_review32_custody as r32
from origin.tests.test_background_work_runs_on_a_job_grant import _mint

custody_client = r31.custody_client
KCV_E = "e" * 32


def _live(root):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityJobGrant
    with SessionLocal() as db:
        return sorted(g.grant_id for g in db.query(AuthorityJobGrant).filter(
            AuthorityJobGrant.principal == root, AuthorityJobGrant.state == "active"))


def test_an_activated_kcv_is_not_recorded_again_after_a_re_mark(custody_client, monkeypatch):
    c = custody_client
    root = r31._charged(c, monkeypatch)
    assert r31._record(c, root, _shares.KCV_B).status_code == 200
    assert r31._grant(c, root, hours=2).status_code == 200
    token = _mint(c, root, "platform.custody").json()["token"]
    assert af.store_share(c, root, credential=token, kcv=_shares.KCV_B).status_code == 200
    assert af.release(c, root, token).status_code == 200
    assert r31._activate(c, root, token).status_code == 200
    seed = oc.call(c, "POST", "/oracle/seed-credential", json={"minutes": 10,
                                                                "rekey_shares": [root]})
    assert seed.status_code == 200, seed.text
    assert r32._mark(c, root, seed.json()["token"]).status_code == 200
    again = r31._record(c, root, _shares.KCV_B)
    assert again.status_code == 409, again.text
    assert r31._grant(c, root, hours=2).status_code == 409
    # A fresh kcv is recorded, as the doc says.
    assert r31._record(c, root, KCV_E).status_code == 200


def test_a_re_record_revokes_the_earlier_grant(custody_client, monkeypatch):
    c = custody_client
    root = r31._charged(c, monkeypatch)
    assert r31._record(c, root, _shares.KCV_B).status_code == 200
    assert r31._grant(c, root, hours=2).status_code == 200
    first = _live(root)
    assert len(first) == 1
    token = _mint(c, root, "platform.custody").json()["token"]
    assert af.store_share(c, root, credential=token, kcv=_shares.KCV_B).status_code == 200
    # The read-back failed: the operator records the same kcv again (step 23).
    assert r31._record(c, root, _shares.KCV_B).status_code == 200
    assert _live(root) == []                          # the earlier grant is revoked
    assert r31._grant(c, root, hours=2).status_code == 200
    assert len(_live(root)) == 1 and _live(root) != first
    # The earlier grant's delegation neither writes nor reads back under the new record.
    assert af.store_share(c, root, credential=token, kcv=_shares.KCV_B).status_code == 403
    assert af.release(c, root, token).status_code == 403

"""Review 35, at Origin, through Origin's real routes.

LOW-2. `record_rotation` revokes the earlier record's custody grant before the new record is
       committed, in the same transaction: a grant that lands after the record is bound to it and
       stays live. Of two grants that both pass the check against one record, only one binds; the
       other is revoked and refused.
INFO-5. Step 23's check tells a pending split's cases apart: whether a share was written under
        the record, and whether it was released (read back) since.
"""
from __future__ import annotations

from origin.services import authority_ledger
from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests import test_review31_custody as r31
from origin.tests.test_background_work_runs_on_a_job_grant import _mint

custody_client = r31.custody_client
KCV_F = "f" * 32


def _live(root):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityJobGrant
    with SessionLocal() as db:
        return sorted(g.grant_id for g in db.query(AuthorityJobGrant).filter(
            AuthorityJobGrant.principal == root, AuthorityJobGrant.state == "active"))


def test_the_earlier_grant_is_revoked_before_the_new_record_commits(custody_client, monkeypatch):
    c = custody_client
    root = r31._charged(c, monkeypatch)
    assert r31._record(c, root, _shares.KCV_B).status_code == 200
    assert r31._grant(c, root, hours=2).status_code == 200
    real_end = authority_ledger.end_charged_custody
    seen = {}

    def watching(db, principal):
        from origin.db.session import SessionLocal
        from origin.models.key_custody import ChargedRootRotation
        with SessionLocal() as other:            # what a concurrent grant would read
            row = other.get(ChargedRootRotation, principal)
            seen["kcv"] = row.kcv if row else None
        return real_end(db, principal)

    monkeypatch.setattr(authority_ledger, "end_charged_custody", watching)
    assert r31._record(c, root, KCV_F).status_code == 200
    monkeypatch.setattr(authority_ledger, "end_charged_custody", real_end)
    assert seen["kcv"] == _shares.KCV_B               # revoked before the new record was visible
    assert _live(root) == []
    # A grant made after the record is bound to it and stays live.
    assert r31._grant(c, root, hours=2).status_code == 200
    from origin.db.session import SessionLocal
    with SessionLocal() as db:
        assert authority_ledger.charged_split_open(db, root)
    assert len(_live(root)) == 1


def test_only_one_of_two_grants_binds_to_a_record(custody_client, monkeypatch):
    c = custody_client
    root = r31._charged(c, monkeypatch)
    assert r31._record(c, root, _shares.KCV_B).status_code == 200
    # Both grants pass the check, as two requests racing past it would.
    monkeypatch.setattr(authority_ledger, "charged_grant_allowed", lambda db, p: None)
    assert r31._grant(c, root, hours=2).status_code == 200
    second = r31._grant(c, root, hours=2)
    assert second.status_code == 409, second.text
    assert len(_live(root)) == 1                     # the loser is revoked


def test_the_shares_check_tells_the_pending_cases_apart(custody_client, monkeypatch):
    c = custody_client
    root = r31._charged(c, monkeypatch)
    assert r31._record(c, root, _shares.KCV_B).status_code == 200
    assert r31._grant(c, root, hours=2).status_code == 200
    token = _mint(c, root, "platform.custody").json()["token"]
    assert af.store_share(c, root, credential=token, kcv=_shares.KCV_B).status_code == 200
    detail = oc.call(c, "GET", "/oracle/charged-roots/shares").json()["pending_detail"][root]
    assert detail == {"share_written": True, "released_since_record": False}   # read-back failed
    assert af.release(c, root, token).status_code == 200
    detail = oc.call(c, "GET", "/oracle/charged-roots/shares").json()["pending_detail"][root]
    assert detail == {"share_written": True, "released_since_record": True}

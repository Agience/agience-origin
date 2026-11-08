"""Review 33, at Origin, through Origin's real routes.

F2. A split that stored Origin's share of the rotated key and then failed its read-back is
    recorded again with the same kcv, when that pending share was written under an earlier record
    of that kcv for that root; the new record needs a fresh write before anything is released.
F6. Activation over a charged root takes only the recorded key's share, written under the record.
"""
from __future__ import annotations

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests import test_review31_custody as r31
from origin.tests import test_review32_custody as r32
from origin.tests.test_background_work_runs_on_a_job_grant import _mint

custody_client = r31.custody_client


def test_a_pending_split_of_the_recorded_kcv_is_recorded_again(custody_client, monkeypatch):
    c = custody_client
    root = r31._charged(c, monkeypatch)
    kprime = _shares.KCV_B
    assert r31._record(c, root, kprime).status_code == 200
    assert r31._grant(c, root, hours=2).status_code == 200
    token = _mint(c, root, "platform.custody").json()["token"]
    assert af.store_share(c, root, credential=token, kcv=kprime).status_code == 200
    # Mantle's read-back fails; its key stays whole, still marked for K'. The grant ends.
    assert oc.call(c, "POST",
                   f"/oracle/job-grants/{r32._live_grant(root)}/revoke").status_code == 200
    # Step 21 reports K' again (`already`): recorded again, for this root's own pending split.
    again = r31._record(c, root, kprime)
    assert again.status_code == 200, again.text
    assert r31._grant(c, root, hours=2).status_code == 200
    token2 = _mint(c, root, "platform.custody").json()["token"]
    assert af.release(c, root, token2).status_code == 403          # no write since the record
    assert af.store_share(c, root, credential=token2, kcv=kprime).status_code == 200
    assert af.release(c, root, token2).status_code == 200
    assert r31._activate(c, root, token2).status_code == 200
    # Activated: the same kcv is never recorded again.
    assert r31._record(c, root, kprime).status_code == 409


def test_a_kcv_held_before_any_record_is_still_refused(custody_client, monkeypatch):
    """The fixture's pending share (kcv A) was written before any record: it is no rotated key's,
    and the same-kcv re-record above does not reach it."""
    c = custody_client
    root = r31._charged(c, monkeypatch)
    assert r31._record(c, root, _shares.KCV_A).status_code == 409


def test_activation_takes_only_the_recorded_key_s_share(custody_client, monkeypatch):
    c = custody_client
    root = r31._charged(c, monkeypatch)
    assert r31._record(c, root, _shares.KCV_B).status_code == 200
    assert r31._grant(c, root, hours=2).status_code == 200
    token = _mint(c, root, "platform.custody").json()["token"]
    # The share Origin holds is the old key's pending one (kcv A): not activated.
    r = r31._activate(c, root, token)
    assert r.status_code == 403, r.text
    assert af.store_share(c, root, credential=token, kcv=_shares.KCV_B).status_code == 200
    assert r31._activate(c, root, token).status_code == 200

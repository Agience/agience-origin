"""The artifact that records an invite is read by the person the invite names (FR-004).

The inviter, in their own Origin session, asks Origin to let the invitee read the artifact recording
their invite (`POST /auth/me/authority/invites/{id}/record`). Origin finds the invitee from the
address the invite went to, and grants read alone, only when that address belongs to a verified
account; the answer is the same either way. The read ends once the invite is accepted, declined or
revoked, so the Inbox shows only invites still waiting.
"""
from __future__ import annotations

from origin.tests import authority_fixtures as af
from origin.tests import test_an_invite_is_accepted_in_the_app_without_its_email as _inv

custody_client = _inv.custody_client
mailed = _inv.mailed
_hdr, _as, _invite, ALL = _inv._hdr, _inv._as, _inv._invite, _inv.ALL
_TOKENS: dict = {}


def _owner(c):
    """Ann, who owns W and may share it."""
    pid, tok = af.person("Ann Lee", email="ann@team.test", verified=True)
    af.ok(af.submit(c, tok, af.root("W"), batch="own", via_session=False))
    af.ok(af.submit(c, tok, af.grant("g-W-own", pid, "W", ALL), batch="own", via_session=False))
    _TOKENS["ann"] = (pid, tok)
    return pid


def _record_artifact(c, rid="Rec"):
    """Ann's artifact `rid`, inside her W, recording an invite; as its creator she holds admin."""
    pid, tok = _TOKENS["ann"]
    af.ok(af.submit(c, tok, af.edge("W", rid), batch="own", via_session=False))
    af.ok(af.submit(c, tok, af.grant(f"g-{rid}-own", pid, rid, ALL), batch="own",
                    via_session=False))


def _reads(pid, rid="Rec", action="read") -> bool:
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger
    with SessionLocal() as db:
        return authority_ledger.reach(db).reaches(pid, rid, action)


def _read_state(inv):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant
    with SessionLocal() as db:
        row = db.get(AuthorityGrant, f"invread-{inv}")
        return row.state if row is not None else None


def _record(c, pid, inv, rid="Rec"):
    _as(c, pid)
    return c.post(f"/auth/me/authority/invites/{inv}/record", json={"artifact_id": rid},
                  headers=_hdr())


def _setup(c):
    ann = _owner(c)
    bob, _ = af.person("Bob", email="bob@team.test", verified=True)
    _record_artifact(c)
    return ann, bob, _invite(c, ann)


def test_the_invitee_reads_the_record_and_nothing_more(custody_client, mailed):
    c = custody_client
    ann, bob, inv = _setup(c)
    r = _record(c, ann, inv)
    assert r.status_code == 200 and r.json() == {"recorded": True}, r.text
    assert _reads(bob) and not _reads(bob, action="update") and not _reads(bob, "W")
    assert _record(c, ann, inv).status_code == 200


def test_accepting_ends_the_read_of_the_record(custody_client, mailed):
    c = custody_client
    ann, bob, inv = _setup(c)
    _record(c, ann, inv)
    _as(c, bob)
    assert c.post(f"/auth/me/authority/invites/{inv}/accept", headers=_hdr()).status_code == 200
    assert _read_state(inv) == "revoked" and _reads(bob, "W")


def test_declining_ends_the_read_of_the_record(custody_client, mailed):
    c = custody_client
    ann, bob, inv = _setup(c)
    _record(c, ann, inv)
    _as(c, bob)
    assert c.post(f"/auth/me/authority/invites/{inv}/decline", headers=_hdr()).status_code == 200
    assert not _reads(bob) and _read_state(inv) == "revoked"


def test_revoking_the_invite_ends_the_read_of_the_record(custody_client, mailed):
    c = custody_client
    ann, bob, inv = _setup(c)
    _record(c, ann, inv)
    _as(c, ann)
    assert c.post(f"/auth/me/authority/grants/{inv}/revoke", headers=_hdr()).status_code == 200
    assert not _reads(bob) and _read_state(inv) == "revoked"


def test_an_address_with_no_verified_account_gets_the_same_answer_and_no_grant(custody_client,
                                                                               mailed):
    c = custody_client
    ann = _owner(c)
    _record_artifact(c)
    inv = _invite(c, ann, email="nobody@team.test")
    r = _record(c, ann, inv)
    assert r.status_code == 200 and r.json() == {"recorded": True}
    assert _read_state(inv) is None


def test_only_the_inviter_records_their_invite(custody_client, mailed):
    c = custody_client
    ann, bob, inv = _setup(c)
    assert _record(c, bob, inv).status_code == 404
    assert not _reads(bob)


def test_a_record_the_inviter_may_not_share_is_refused(custody_client, mailed):
    c = custody_client
    ann, bob, inv = _setup(c)
    carol, ctok = af.person("Carol", email="carol@team.test", verified=True)
    af.ok(af.submit(c, ctok, af.root("C"), batch="c", via_session=False))
    af.ok(af.submit(c, ctok, af.grant("g-C-own", carol, "C", ALL), batch="c", via_session=False))
    af.ok(af.submit(c, ctok, af.edge("C", "Theirs"), batch="c", via_session=False))
    assert _record(c, ann, inv, "Theirs").status_code == 403
    assert not _reads(bob, "Theirs")


def test_a_record_origin_has_not_seen_is_retried(custody_client, mailed):
    c = custody_client
    ann, bob, inv = _setup(c)
    assert _record(c, ann, inv, "NotYet").status_code == 409


def test_an_invite_is_recorded_once(custody_client, mailed):
    c = custody_client
    ann, bob, inv = _setup(c)
    _record_artifact(c, "Rec2")
    assert _record(c, ann, inv).status_code == 200
    assert _record(c, ann, inv, "Rec2").status_code == 409
    assert not _reads(bob, "Rec2")

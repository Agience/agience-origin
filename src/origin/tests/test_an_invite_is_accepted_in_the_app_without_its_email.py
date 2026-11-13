"""An invite to someone with an account arrives in the app, and is accepted there with no email
(FR-004, John, 2026-11-10).

An invite to an account's id, or to its verified address, is listed for that person in their
Origin session (`GET /auth/me/authority/invites/incoming`). They accept it
(`POST …/invites/{id}/accept`), which makes the same claim the mailed link makes, through the
ledger's own claim rule, or they decline it (`…/decline`). The sender's sharing dialog then counts
the claim, or shows the invite retired. The proof is the person's own Origin session plus the
invite naming them, in place of the mailed token.

A domain invite names everyone at a domain, so it is never listed and never accepted without its
mailed token. An account whose address is not verified is offered no email invite. No other
credential (a person's access token, a delegation Mantle holds) can make the tokenless claim.
"""
from __future__ import annotations

import pytest

from origin.services import email_service as E
from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client
ALL = ["create", "read", "update", "delete", "evict", "add", "share", "admin"]


def _hdr():
    from origin import config
    return {"Origin": config.APP_URI or config.ORIGIN_URI, "X-Origin-Session": "1"}


@pytest.fixture
def mailed(monkeypatch):
    out = []

    async def send_invite(to_email, from_name, resource_name, claim_url, *, from_email):
        out.append(to_email)
        return True

    monkeypatch.setattr(E, "is_configured", lambda: True)
    monkeypatch.setattr(E, "send_invite", send_invite)
    return out


def _owner(c):
    """Ann, who owns W and may share it."""
    pid, tok = af.person("Ann Lee", email="ann@team.test", verified=True)
    af.ok(af.submit(c, tok, af.root("W"), batch="own", via_session=False))
    af.ok(af.submit(c, tok, af.grant("g-W-own", pid, "W", ALL), batch="own", via_session=False))
    return pid


def _as(c, pid):
    c.cookies.clear()
    oc.origin_page_session(c, pid)


def _invite(c, ann, email="bob@team.test", actions=("read",)):
    _as(c, ann)
    seen = c.post("/auth/me/authority/preview", json={"resource_id": "W"}, headers=_hdr())
    r = c.post("/auth/me/authority/invites",
               json={"resource_id": "W", "actions": list(actions), "email": email,
                     "preview": seen.json().get("preview")}, headers=_hdr())
    assert r.status_code == 200, r.text
    return r.json()["invite_id"]


def _incoming(c, pid):
    _as(c, pid)
    r = c.get("/auth/me/authority/invites/incoming", headers=_hdr())
    assert r.status_code == 200, r.text
    return r.json()["invites"]


def _reaches(pid, action="read") -> bool:
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger
    with SessionLocal() as db:
        return authority_ledger.reach(db).reaches(pid, "W", action)


def _listed(c, ann, invite_id):
    _as(c, ann)
    r = c.get("/auth/me/authority/grants", params={"resource_id": "W"}, headers=_hdr())
    assert r.status_code == 200, r.text
    return next(g for g in r.json()["grants"] if g["grant_id"] == invite_id)


def test_an_invite_to_an_account_is_listed_and_accepted_in_the_app(custody_client, mailed):
    c = custody_client
    ann = _owner(c)
    bob, _ = af.person("Bob", email="bob@team.test", verified=True)
    inv = _invite(c, ann)

    (row,) = _incoming(c, bob)
    assert row["invite_id"] == inv and row["resource_id"] == "W"
    assert row["actions"] == ["read"] and row["from"] == "Ann Lee"
    assert not _reaches(bob)

    _as(c, bob)
    r = c.post(f"/auth/me/authority/invites/{inv}/accept", headers=_hdr())
    assert r.status_code == 200, r.text
    assert _reaches(bob) and not _reaches(bob, "update")
    assert _incoming(c, bob) == []
    assert _listed(c, ann, inv)["claims"] == 1


def test_a_declined_invite_grants_nothing_and_shows_retired_to_its_sender(custody_client, mailed):
    c = custody_client
    ann = _owner(c)
    bob, _ = af.person("Bob", email="bob@team.test", verified=True)
    inv = _invite(c, ann)

    _as(c, bob)
    r = c.post(f"/auth/me/authority/invites/{inv}/decline", headers=_hdr())
    assert r.status_code == 200, r.text
    assert _incoming(c, bob) == []
    assert not _reaches(bob)
    seen = _listed(c, ann, inv)
    assert seen["state"] == "retired" and seen["claims"] == 0
    _as(c, bob)
    assert c.post(f"/auth/me/authority/invites/{inv}/accept", headers=_hdr()).status_code == 404


def test_someone_the_invite_does_not_name_can_neither_see_nor_take_it(custody_client, mailed):
    c = custody_client
    ann = _owner(c)
    carol, _ = af.person("Carol", email="carol@team.test", verified=True)
    inv = _invite(c, ann)
    assert _incoming(c, carol) == []
    _as(c, carol)
    assert c.post(f"/auth/me/authority/invites/{inv}/accept", headers=_hdr()).status_code == 403
    assert c.post(f"/auth/me/authority/invites/{inv}/decline", headers=_hdr()).status_code == 403
    assert not _reaches(carol)


def test_an_unverified_address_is_offered_no_email_invite(custody_client, mailed):
    c = custody_client
    ann = _owner(c)
    bob, _ = af.person("Bob", email="bob@team.test", verified=False)
    inv = _invite(c, ann)
    assert _incoming(c, bob) == []
    _as(c, bob)
    assert c.post(f"/auth/me/authority/invites/{inv}/accept", headers=_hdr()).status_code == 403
    assert not _reaches(bob)


def test_a_domain_invite_still_needs_its_mailed_token(custody_client):
    c = custody_client
    ann = _owner(c)
    bob, _ = af.person("Bob", email="bob@team.test", verified=True)
    af.ok(af.session_submit(c, ann, af.invite("inv-dom", "tok-dom", "W",
                                                target=("domain", "team.test"))))
    assert _incoming(c, bob) == []
    _as(c, bob)
    r = c.post("/auth/me/authority/invites/inv-dom/accept", headers=_hdr())
    assert r.status_code == 403, r.text
    # The ledger refuses the tokenless proof for a domain invite even when asked directly.
    claim = af.grant("claim-dom", bob, "W", ("read",))
    r = af.session_submit(c, bob, claim, {"invite_id": "inv-dom", "session": "targeted"})
    assert r.status_code == 403 and "mailed token" in r.json()["detail"]
    assert not _reaches(bob)


def test_the_tokenless_claim_is_taken_only_in_the_persons_own_origin_session(custody_client):
    c = custody_client
    ann = _owner(c)
    bob, bob_tok = af.person("Bob", email="bob@team.test", verified=True)
    af.ok(af.session_submit(c, ann, af.invite("inv-b", "tok-b", "W",
                                                target=("email", "bob@team.test"),
                                                max_claims=1)))
    claim = af.grant("claim-b", bob, "W", ("read",))
    r = af.submit(c, bob_tok, claim, proof={"invite_id": "inv-b", "session": "targeted"},
                  via_session=False)
    assert r.status_code in (403, 409), r.text
    assert not _reaches(bob)


def test_the_tokenless_claim_takes_no_more_than_the_invite(custody_client):
    c = custody_client
    ann = _owner(c)
    bob, _ = af.person("Bob", email="bob@team.test", verified=True)
    af.ok(af.session_submit(c, ann, af.invite("inv-r", "tok-r", "W",
                                                target=("email", "bob@team.test"),
                                                max_claims=1)))
    wider = af.grant("claim-w", bob, "W", ("read", "update"))
    r = af.session_submit(c, bob, wider, {"invite_id": "inv-r", "session": "targeted"})
    assert r.status_code == 403 and "no more than" in r.json()["detail"]
    assert not _reaches(bob)


def test_an_inviter_with_no_display_name_is_named_by_their_verified_address(custody_client, mailed):
    """2026-11-13, the Tester: the Accept toast and "… invited you" were blank for an inviter with
    no display name. The invite names them as its mail does, by their verified address."""
    c = custody_client
    pid, tok = af.person("", email="noname@team.test", verified=True)
    from origin.db.session import SessionLocal
    from origin.models.person import Person
    import uuid as _uuid
    with SessionLocal() as db:
        db.get(Person, _uuid.UUID(pid)).name = ""
        db.commit()
    af.ok(af.submit(c, tok, af.root("W"), batch="own", via_session=False))
    af.ok(af.submit(c, tok, af.grant("g-W-own", pid, "W", ALL), batch="own", via_session=False))
    bob, _ = af.person("Bob", email="bob@team.test", verified=True)
    _invite(c, pid)
    (row,) = _incoming(c, bob)
    assert row["from"] == "noname@team.test"

"""Review 13 (2026-11-03): invites, grants and the Origin session.

H1 The claim token never needs to reach Mantle, and Mantle could do nothing with it if it did:
   Origin makes every invite itself, targeted at the address the owner gives, mails the link there
   (John, 2026-11-03), and lets only the person whose verified address it names claim it. A claim by
   anyone else refuses and spends nothing. The invite's context is Origin's to show, to a session.
H2 The person's view of grants, and the prior state of every change to one, are Origin's own
   record: a grant is made, changed or revoked by its Origin id, built from what Origin holds, and
   Origin refuses an id it does not hold. The generic session route makes edge changes only.
M1 Cookie tossing: Origin's session cookie is `__Host-` prefixed on https, and a request carrying
   more than one session cookie is refused.
"""
from __future__ import annotations

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import operator_console_fixtures as oc
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client
ALL = ["create", "read", "update", "delete", "evict", "add", "share", "admin"]
BASE = "/auth/me/authority"


def _hdr():
    from origin import config
    return {"Origin": config.APP_URI or config.ORIGIN_URI, "X-Origin-Session": "1"}


def _as(c, person_id):
    c.cookies.clear()
    oc.origin_page_session(c, person_id)


def _row(gid):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant
    with SessionLocal() as db:
        g = db.get(AuthorityGrant, gid)
        return None if g is None else (g.grantee_id, g.resource_id, g.actions, g.state)


def _held_by(pid):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant
    with SessionLocal() as db:
        return [(g.resource_id, g.actions, g.state)
                for g in db.query(AuthorityGrant).filter(AuthorityGrant.grantee_id == pid)]


@pytest.fixture
def people(custody_client):
    return {n: af.person(n, email=f"{n}@team.test") for n in ("alice", "bob", "mal")}


@pytest.fixture
def mail(monkeypatch):
    """Origin's mail sender, captured: (to, link)."""
    from origin.services import email_service
    sent = []

    async def send_invite(to_email, from_name, resource_name, claim_url, message=None):
        sent.append((to_email, claim_url))
        return True

    monkeypatch.setattr(email_service, "is_configured", lambda: True)
    monkeypatch.setattr(email_service, "send_invite", send_invite)
    return sent


def _own(c, person, cid="W"):
    af.ok(af.submit(c, person[1], af.root(cid), batch="own", via_session=False))
    af.ok(af.submit(c, person[1], af.grant(f"g-{cid}-own", person[0], cid, ALL), batch="own",
                    via_session=False))


def _seen(c, cid):
    """Origin's preview of `cid`, which a make names (review 15)."""
    r = c.post(f"{BASE}/preview", json={"resource_id": cid}, headers=_hdr())
    return r.json().get("preview") if r.status_code == 200 else None


def _invite(c, owner, email, actions=("read",), cid="W"):
    _as(c, owner[0])
    return c.post(f"{BASE}/invites", json={"resource_id": cid, "actions": list(actions),
                                           "preview": _seen(c, cid),
                                           "email": email}, headers=_hdr())


def _token_of(link):
    return link.rsplit("/invite/", 1)[1]


# -- H1 -------------------------------------------------------------------------------------------

def test_an_untargeted_invite_is_never_made_in_the_session(custody_client, people):
    c = custody_client
    alice = people["alice"]
    _own(c, alice)
    _as(c, alice[0])
    r = c.post(f"{BASE}/entries", json={"entry": af.invite("inv-link", "tok", "W", ["read"])},
               headers=_hdr())
    assert r.status_code in (400, 403), r.text


def test_origin_mails_the_invite_and_answers_no_token(custody_client, people, mail):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant
    from origin.services.authority_ledger import target_digest

    c = custody_client
    alice = people["alice"]
    _own(c, alice)
    r = _invite(c, alice, "Bob@Team.test", ("read", "update"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"invite_id", "resource_id", "resource_name", "actions", "expires_at",
                         "email"}
    assert body["resource_id"] == "W" and body["actions"] == ["read", "update"]
    assert len(mail) == 1 and mail[0][0] == "bob@team.test" and "/invite/" in mail[0][1]
    assert _token_of(mail[0][1]) not in r.text
    with SessionLocal() as db:
        inv = db.get(AuthorityGrant, body["invite_id"])
        assert inv.grantee_type == "invite" and inv.max_claims == 1
        assert (inv.target_kind, inv.target_digest) == ("email",
                                                        target_digest("email", "bob@team.test"))


def test_only_a_person_who_may_share_invites(custody_client, people, mail):
    c = custody_client
    alice, mal = people["alice"], people["mal"]
    _own(c, alice)
    assert _invite(c, mal, "bob@team.test").status_code == 403
    assert mail == []


def test_the_invite_s_context_is_origin_s_to_show_and_says_whom_it_is_for(custody_client,
                                                                           people, mail):
    c = custody_client
    alice, bob, mal = people["alice"], people["bob"], people["mal"]
    _own(c, alice)
    af.ok(_invite(c, alice, "bob@team.test"))
    token = _token_of(mail[0][1])
    _as(c, bob[0])
    r = c.post(f"{BASE}/invite-context", json={"token": token}, headers=_hdr())
    assert r.status_code == 200, r.text
    assert r.json()["for_you"] is True and r.json()["resource_id"] == "W"
    assert token not in r.text
    _as(c, mal[0])
    assert c.post(f"{BASE}/invite-context", json={"token": token},
                  headers=_hdr()).json()["for_you"] is False
    c.cookies.clear()
    assert c.post(f"{BASE}/invite-context", json={"token": token},
                  headers=_hdr()).status_code == 401


def test_a_claim_by_another_person_refuses_and_spends_nothing(custody_client, people, mail):
    c = custody_client
    alice, bob, mal = people["alice"], people["bob"], people["mal"]
    _own(c, alice)
    af.ok(_invite(c, alice, "bob@team.test"))
    token = _token_of(mail[0][1])
    _as(c, mal[0])
    r = c.post(f"{BASE}/claim", json={"token": token}, headers=_hdr())
    assert r.status_code == 403, r.text
    assert not any(res == "W" for res, _a, _s in _held_by(mal[0]))
    _as(c, bob[0])
    r = c.post(f"{BASE}/claim", json={"token": token}, headers=_hdr())
    assert r.status_code == 200, r.text
    assert ("W", "read", "active") in _held_by(bob[0])
    assert c.post(f"{BASE}/claim", json={"token": token}, headers=_hdr()).status_code == 403


def test_an_untargeted_invite_is_not_claimable_in_the_session(custody_client, people):
    """An invite made before targets were required (on the bootstrap, or by an older web app)
    names no one, so its token proves nothing about who holds it: the session claims it not."""
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant
    import hashlib

    c = custody_client
    alice, mal = people["alice"], people["mal"]
    _own(c, alice)
    with SessionLocal() as db:
        db.add(AuthorityGrant(grant_id="inv-old", grantee_id=hashlib.sha256(b"old").hexdigest(),
                              grantee_type="invite", resource_id="W", actions="read",
                              effect="allow", state="active", created_by=alice[0], seq=0))
        db.commit()
    _as(c, mal[0])
    r = c.post(f"{BASE}/claim", json={"token": "old"}, headers=_hdr())
    assert r.status_code == 403 and "names no one" in r.text, r.text
    assert not any(res == "W" for res, _a, _s in _held_by(mal[0]))


def test_while_registration_is_paused_no_invite_goes_to_an_address_without_an_account(
        custody_client, people, mail, monkeypatch):
    c = custody_client
    alice = people["alice"]
    _own(c, alice)
    from origin import config
    monkeypatch.setattr(config, "REGISTRATION_PAUSED", True, raising=False)
    r = _invite(c, alice, "stranger@else.test")
    assert r.status_code == 409 and "paused" in r.text, r.text
    assert mail == []
    assert _invite(c, alice, "bob@team.test").status_code == 200        # an account exists


# -- H2 -------------------------------------------------------------------------------------------

def test_a_grant_is_made_changed_and_revoked_by_origin_s_own_record(custody_client, people):
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    _own(c, alice)
    _as(c, alice[0])
    r = c.post(f"{BASE}/grants", json={"resource_id": "W", "grantee_id": bob[0],
                                       "actions": ["read"], "preview": _seen(c, "W")},
               headers=_hdr())
    assert r.status_code == 200, r.text
    gid = r.json()["grant_id"]
    listed = c.get(f"{BASE}/grants", params={"resource_id": "W"}, headers=_hdr())
    assert listed.status_code == 200, listed.text
    mine = [g for g in listed.json()["grants"] if g["grant_id"] == gid]
    assert mine and mine[0]["grantee_id"] == bob[0] and mine[0]["actions"] == ["read"]
    r = c.post(f"{BASE}/grants/{gid}/change", json={"actions": ["read", "update"]},
               headers=_hdr())
    assert r.status_code == 200, r.text
    assert _row(gid) == (bob[0], "W", "read,update", "active")
    r = c.post(f"{BASE}/grants/{gid}/revoke", headers=_hdr())
    assert r.status_code == 200, r.text
    assert _row(gid)[3] == "revoked"


def test_origin_refuses_a_grant_id_it_does_not_hold(custody_client, people):
    c = custody_client
    alice = people["alice"]
    _own(c, alice)
    _as(c, alice[0])
    assert c.post(f"{BASE}/grants/g-decoy/revoke", headers=_hdr()).status_code == 404
    assert c.post(f"{BASE}/grants/g-made-up/change", json={"actions": ["read"]},
                  headers=_hdr()).status_code == 404
    assert _row("g-made-up") is None


def test_the_generic_session_route_makes_no_grant(custody_client, people):
    """Probes h2a and h2b: a grant entry restated from Mantle's listing never reaches the ledger,
    whether its id is a decoy (a revocation that would report success) or made up (an edit that
    would mint a grant to Mantle's choice of grantee)."""
    c = custody_client
    alice, mal = people["alice"], people["mal"]
    _own(c, alice)
    _as(c, alice[0])
    af.ok(c.post(f"{BASE}/grants", json={"resource_id": "W", "grantee_id": mal[0],
                                         "actions": ["read"], "preview": _seen(c, "W")},
                 headers=_hdr()))
    decoy = af.grant("g-decoy", mal[0], "W", ["read"], state="revoked")
    made_up = af.grant("g-made-up", mal[0], "W", ["read", "share", "admin"])
    for entry in (decoy, made_up):
        r = c.post(f"{BASE}/entries", json={"entry": entry}, headers=_hdr())
        assert r.status_code in (400, 403), r.text
    assert _row("g-made-up") is None


def test_only_a_sharer_sees_a_resource_s_grants(custody_client, people):
    c = custody_client
    alice, mal = people["alice"], people["mal"]
    _own(c, alice)
    _as(c, mal[0])
    assert c.get(f"{BASE}/grants", params={"resource_id": "W"},
                 headers=_hdr()).status_code in (403, 404)


# -- M1 -------------------------------------------------------------------------------------------

def test_a_request_with_two_session_cookies_is_refused(custody_client, people):
    """Probe m1: a cookie tossed by a sibling host, sent after the person's, decides nothing."""
    from origin.db.session import SessionLocal
    from origin.services import origin_session

    c = custody_client
    bob, mal = people["bob"], people["mal"]
    c.cookies.clear()
    with SessionLocal() as db:
        bob_raw = origin_session.issue(db, bob[0])
        mal_raw = origin_session.issue(db, mal[0])
        db.commit()
    name = origin_session.cookie_name()
    for cookie in (f"{name}={bob_raw}; {name}={mal_raw}",
                   f"{origin_session.COOKIE}={bob_raw}; {origin_session.HOST_COOKIE}={mal_raw}"):
        r = c.post(f"{BASE}/invite-context", json={"token": "x"},
                   headers={**_hdr(), "Cookie": cookie})
        assert r.status_code == 400 and "more than one" in r.text, r.text


def test_on_https_the_session_cookie_is_host_prefixed(monkeypatch):
    from starlette.responses import Response

    from origin import config
    from origin.services import origin_session

    monkeypatch.setattr(config, "ORIGIN_URI", "https://origin.agience.ai", raising=False)
    monkeypatch.setattr(config, "AUTHORITY_ISSUER", "https://origin.agience.ai", raising=False)
    resp = Response()
    origin_session.set_cookie(resp, "raw")
    header = resp.headers["set-cookie"]
    assert header.startswith("__Host-origin_session=raw")
    assert "Secure" in header and "Path=/" in header and "Domain" not in header

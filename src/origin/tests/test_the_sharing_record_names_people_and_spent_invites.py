"""What Origin's sharing record tells the owner and the invitee, in their Origin session.

* A person an owner shares with is named by their display name at Origin, from the same record the
  preview's `parent_details` creators come from (`Person.name`), in the grants listing and in the
  preview's grantees. Nothing else about them (no address) is added.
* An invite says how many times it was claimed (`claims`) beside `max_claims`, so the owner's
  dialog drops one that is spent.
* The invite's context says whether the signed-in person's own address is verified, so the claim
  page can say "verify your address first" rather than "addressed to a different account".
"""
from __future__ import annotations

from origin.tests import authority_fixtures as af
from origin.tests import test_the_thirteenth_review_s_session_cases as _thirteenth
from origin.tests.test_the_thirteenth_review_s_session_cases import (
    BASE, _as, _hdr, _invite, _own, _token_of)

custody_client = _thirteenth.custody_client
mail = _thirteenth.mail
people = _thirteenth.people


def _grants(c, cid="W"):
    r = c.get(f"{BASE}/grants", params={"resource_id": cid}, headers=_hdr())
    assert r.status_code == 200, r.text
    return r.json()["grants"]


def test_a_claimed_invite_says_it_is_spent_and_the_claimant_is_named(custody_client, people,
                                                                     mail):
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    _own(c, alice)
    af.ok(_invite(c, alice, "bob@team.test"))
    _as(c, alice[0])
    (inv,) = [g for g in _grants(c) if g["grantee_type"] == "invite"]
    assert inv["claims"] == 0 and inv["max_claims"] == 1
    _as(c, bob[0])
    assert c.post(f"{BASE}/claim", json={"token": _token_of(mail[0][1])},
                  headers=_hdr()).status_code == 200
    _as(c, alice[0])
    rows = _grants(c)
    (inv,) = [g for g in rows if g["grantee_type"] == "invite"]
    assert inv["claims"] == 1
    (claim,) = [g for g in rows if g["grantee_id"] == bob[0]]
    assert claim["grantee_name"] == "bob"
    assert "email" not in claim and "bob@team.test" not in str(rows)
    shown = c.post(f"{BASE}/preview", json={"resource_id": "W"}, headers=_hdr()).json()
    named = {g["grantee_id"]: g.get("grantee_name") for g in shown["grantees"]}
    assert named[bob[0]] == "bob" and named[alice[0]] == "alice"


def test_the_invite_context_says_whether_the_signed_in_address_is_verified(custody_client,
                                                                          people, mail):
    c = custody_client
    alice = people["alice"]
    unverified = af.person("una", email="una@team.test", verified=False)
    _own(c, alice)
    af.ok(_invite(c, alice, "una@team.test"))
    token = _token_of(mail[0][1])
    _as(c, unverified[0])
    r = c.post(f"{BASE}/invite-context", json={"token": token}, headers=_hdr())
    assert r.status_code == 200, r.text
    assert r.json()["for_you"] is False and r.json()["address_verified"] is False
    _as(c, people["bob"][0])
    r = c.post(f"{BASE}/invite-context", json={"token": token}, headers=_hdr())
    assert r.json()["address_verified"] is True

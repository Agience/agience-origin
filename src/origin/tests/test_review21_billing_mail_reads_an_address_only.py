"""Ophan's billing mail reads one address, for a person with an active billing record, audited
(review 21, F4).

`GET /internal/persons/{id}` answered a platform service for any person with no subject token.
Ophan's receipt and usage mail runs from a payment webhook, with no person's token to show, so it
gets its own narrow route instead:

* `PUT /internal/billing-recipients/{id}` `{"active", "plan"}`: Ophan records that a person's
  subscription is active (or no longer is), from the payment provider's verified event;
* `GET /internal/billing-recipients/{id}` answers `{"email"}` and nothing else, only while that
  record is active, and each read is recorded (`billing_recipient_lookups`).

Only Ophan reaches them: the chorus host's token carrying Ophan's client id, or Ophan's own key.
Mantle, Crystal and a person are refused.
"""
from __future__ import annotations

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client
PATH = "/internal/billing-recipients/"


def _chorus_as(client_id=None) -> dict:
    """The chorus host's own token, as `ServerAuth.sign_self_jwt` signs it (Ophan rides the shared
    chorus key and names itself in `client_id`)."""
    extra = {"client_id": client_id} if client_id else {}
    return {"Authorization": "Bearer " + _shares._token("GET", "-", iss="chorus", **extra)}


OPHAN = "agience-server-ophan"


def _mark(c, person, active=True, headers=None):
    return c.put(PATH + person, json={"active": active, "plan": "pro"},
                 headers=headers or _chorus_as(OPHAN))


def test_ophan_reads_the_address_of_a_person_it_bills(custody_client):
    c = custody_client
    alice = af.person("Alice", email="alice@x.test")
    assert _mark(c, alice[0]).status_code == 200
    r = c.get(PATH + alice[0], headers=_chorus_as(OPHAN))
    assert r.status_code == 200 and r.json() == {"email": "alice@x.test"}


def test_no_billing_record_no_address(custody_client):
    c = custody_client
    bob = af.person("Bob", email="bob@x.test")
    assert c.get(PATH + bob[0], headers=_chorus_as(OPHAN)).status_code == 404
    assert _mark(c, bob[0]).status_code == 200
    assert _mark(c, bob[0], active=False).status_code == 200
    assert c.get(PATH + bob[0], headers=_chorus_as(OPHAN)).status_code == 404


def test_each_read_is_recorded(custody_client):
    from origin.db.session import SessionLocal
    from origin.models.billing_recipient import BillingRecipientLookup

    c = custody_client
    alice = af.person("Alice", email="alice@x.test")
    _mark(c, alice[0])
    c.get(PATH + alice[0], headers=_chorus_as(OPHAN))
    with SessionLocal() as db:
        rows = db.query(BillingRecipientLookup).filter_by(person_id=alice[0]).all()
    assert [(r.caller, r.found) for r in rows] == [(f"chorus/{OPHAN}", True)]


@pytest.mark.parametrize("who", ["mantle", "chorus-bare", "chorus-as-iris", "person"])
def test_only_ophan_reaches_them(custody_client, who):
    c = custody_client
    alice = af.person("Alice", email="alice@x.test")
    _mark(c, alice[0])
    headers = {
        "mantle": {"Authorization": "Bearer " + _shares._token("GET", "-")},
        "chorus-bare": _chorus_as(),
        "chorus-as-iris": _chorus_as("agience-server-iris"),
        "person": {"Authorization": f"Bearer {alice[1]}"},
    }[who]
    assert c.get(PATH + alice[0], headers=headers).status_code in (401, 403)
    assert _mark(c, alice[0], headers=headers).status_code in (401, 403)

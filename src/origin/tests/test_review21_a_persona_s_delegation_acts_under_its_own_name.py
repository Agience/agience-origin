"""A persona's server delegation is addressed to Mantle, and is no acting credential (reviews 21,
22 and 27).

A persona carries a person's delegation to Mantle. Origin addresses that server delegation to
Mantle (review 22). It is the persona's, taken only by the use verdict, `/reach` and the ledger's
persona path; as an acting credential for a key or a person's ledger entry it is refused (review
27). Nothing addressed to a persona, by its client id or its bare name, acts here either.
"""
from __future__ import annotations

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_a_share_release_needs_the_callers_credential import _recorded_delegation

custody_client = _shares.custody_client


def _verify(token):
    from origin.db.session import SessionLocal
    from origin.services import share_credentials

    with SessionLocal() as db:
        return share_credentials.verify_share_credential(db, token)


def test_a_persona_server_delegation_is_addressed_to_mantle_and_acts_as_no_one(custody_client):
    from jose import jwt as jose_jwt

    from origin.services import share_credentials

    alice = af.person("Alice")
    tok = _recorded_delegation("agience-server-lumen", alice[0])
    assert jose_jwt.get_unverified_claims(tok)["aud"] == "mantle"
    with pytest.raises(share_credentials.CredentialRefused):
        _verify(tok)


@pytest.mark.parametrize("aud", ["lumen", "agience-server-lumen"])
def test_nothing_addressed_to_a_persona_acts(custody_client, aud):
    from origin.services import share_credentials

    assert aud not in share_credentials._delegation_audiences()

"""Review 22, F6: the subject token on a person lookup is a person's own access token for Origin.

`GET /internal/persons/{id}` took any token Origin signed for the person as `X-Subject-Token`: a
refresh token, a password-reset or email-verification token, one addressed to someone else. It now
takes only what `/internal/delegation-token` exchanges: no `token_type`, and `aud` Origin's own
issuer.
"""
from __future__ import annotations

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client


def _lookup(c, person_id, subject):
    tok = _shares._token("GET", "-")
    return c.get(f"/internal/persons/{person_id}",
                 headers={"Authorization": f"Bearer {tok}", "X-Subject-Token": subject})


def test_the_person_s_own_access_token_reads_their_record(custody_client):
    alice = af.person("Alice")
    assert _lookup(custody_client, alice[0], alice[1]).status_code == 200


@pytest.mark.parametrize("extra", [{"token_type": "refresh"}, {"token_type": "password_reset"},
                                   {"token_type": "email_verify"}, {"aud": "someone-else"}])
def test_a_token_with_a_purpose_or_another_audience_is_no_subject_token(custody_client, extra):
    from origin import config
    from origin.services.auth_service import create_jwt_token

    alice = af.person("Alice")
    claims = {"sub": alice[0], "email": "a@x.test", "client_id": "platform",
              "aud": config.AUTHORITY_ISSUER, **extra}
    r = _lookup(custody_client, alice[0], create_jwt_token(claims))
    assert r.status_code == 403, r.text

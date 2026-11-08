"""Review 25, I1: a token whose claims have the wrong type is no token at Origin, not a 500.

`verify_token` let python-jose's `TypeError` (a null `exp`) through, and a route answered 500. It
now reads such a token as unverifiable, like prism's `verify_jwt`, which also maps an
`ArithmeticError`. Tokens are Origin's own (`create_jwt_token`).
"""
from __future__ import annotations

import pytest


from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client


@pytest.mark.parametrize("exp", [None, "soon", [1]])
def test_an_odd_exp_verifies_as_nothing(custody_client, exp):
    from origin import config
    from origin.services.auth_service import create_jwt_token
    from origin.services.auth_verifier import verify_token

    tok = create_jwt_token({"sub": "p-1", "aud": config.AUTHORITY_ISSUER, "exp": exp})
    assert verify_token(tok) is None

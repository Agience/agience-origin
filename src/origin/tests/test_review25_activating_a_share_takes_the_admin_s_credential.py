"""Review 25, I2: activating a share takes an acting credential, checked as a replacement is.

Activation makes a share no longer replaceable, so it decides whether a later re-key can take. It
took Mantle's token alone. It now takes the acting credential of the key's principal, or of one
holding Admin on what the key keys, as a replacement does.
"""
from __future__ import annotations

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client
ALL = ["create", "read", "update", "delete", "evict", "invoke", "add", "share", "admin"]


def activate(c, principal, credential=None):
    tok = _shares._token("POST", principal, htu=f"/internal/key-shares/{principal}/activate")
    headers = {"Authorization": f"Bearer {tok}"}
    if credential:
        headers["X-Acting-Credential"] = credential
    return c.post(f"/internal/key-shares/{principal}/activate", headers=headers)


def test_activation_takes_the_admin_s_credential_and_no_one_else_s(custody_client):
    c = custody_client
    alice, bob = af.person("Alice"), af.person("Bob")
    af.ok(af.submit(c, alice[1], af.root("K"), batch="a"))
    af.ok(af.submit(c, alice[1], af.grant("g-k", alice[0], "K", ALL), batch="a"))
    af.ok(af.submit(c, alice[1], af.grant("g-bk", bob[0], "K", ["read"]), batch="b"))
    assert af.store_share(c, "ck:K", credential=alice[1]).status_code == 200
    assert activate(c, "ck:K").status_code == 401
    assert activate(c, "ck:K", bob[1]).status_code == 403
    assert activate(c, "ck:K", alice[1]).status_code == 200

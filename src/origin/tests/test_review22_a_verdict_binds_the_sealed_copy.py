"""Review 22, F2: Origin's verdict binds the sealed copy its writer made.

Mantle seals a credential when it is written, to each persona's key from the manifest, so a Mantle
taken over later could answer `/use` with a genuine verdict beside a copy it sealed itself. So when
a credential is written, Mantle sends Origin, on the writer's own credential, the SHA-256 of each
persona's sealed copy and of the credential's endpoint list
(`POST /internal/authority/credential-seals`). Origin keeps them only from the credential's
creator, or someone who may update it, and every verdict carries the persona's digests
(`sealed_sha256`, `endpoints_sha256`), which the persona compares with what Mantle served. No
record, no verdict.

Also review 22, F3: each verdict is bound to the persona's own fresh nonce for that one use.
"""
from __future__ import annotations

import hashlib

from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests import test_review21_a_secret_is_used_only_on_origin_s_verdict as r21

custody_client = r21.custody_client
unsealed_world = r21.unsealed_world
PATH = "/internal/authority/credential-seals"
SEALED, ENDPOINTS = "a" * 64, "b" * 64


def record(c, credential, *, cred=r21.CRED, sealed=None, endpoints=ENDPOINTS):
    from origin.services.authority_ledger import canonical

    body = {"credential_id": cred, "sealed_sha256": sealed or {"iris": SEALED},
            "endpoints_sha256": endpoints}
    digest = hashlib.sha256(canonical(body).encode()).hexdigest()
    tok = _shares._token("POST", "-", htu=PATH, body_sha256=digest)
    return c.post(PATH, json=body, headers={"Authorization": f"Bearer {tok}",
                                            "X-Acting-Credential": credential})


def test_the_verdict_carries_the_digests_the_writer_recorded(unsealed_world):
    from jose import jwt as jose_jwt

    c, alice, bob = unsealed_world
    assert record(c, alice[1]).status_code == 200
    claims = jose_jwt.get_unverified_claims(r21._ask(c, r21._delegation(bob[0])).json()["verdict"])
    assert (claims["sealed_sha256"], claims["endpoints_sha256"]) == (SEALED, ENDPOINTS)


def test_no_record_no_verdict(unsealed_world):
    c, _alice, bob = unsealed_world
    r = r21._ask(c, r21._delegation(bob[0]))
    assert r.status_code == 403 and "seal" in r.text


def test_no_record_for_the_persona_no_verdict(unsealed_world):
    c, alice, bob = unsealed_world
    assert record(c, alice[1], sealed={"lumen": SEALED}).status_code == 200
    assert r21._ask(c, r21._delegation(bob[0])).status_code == 403


def test_only_the_creator_or_an_updater_records_one(unsealed_world):
    c, _alice, bob = unsealed_world
    assert record(c, bob[1]).status_code == 403              # Bob holds Invoke only
    assert record(c, None or "").status_code in (401, 403)


def test_a_record_is_digests_only(unsealed_world):
    c, alice, _bob = unsealed_world
    assert record(c, alice[1], sealed={"iris": "not-a-digest"}).status_code == 400
    assert record(c, alice[1], endpoints="x").status_code == 400


world = r21.world


def test_a_nonce_buys_one_verdict_and_the_verdict_names_it(world):
    """Review 22, F3. Mantle holding the persona's delegation can still ask for verdicts under
    nonces of its own, but each names a nonce the persona never sent for a use it is making, so
    the persona opens nothing on it (`use_verdict.verify`). A nonce is good for one verdict."""
    from jose import jwt as jose_jwt

    c, _alice, bob = world
    dlg = r21._delegation(bob[0])
    first = r21._ask(c, dlg, nonce="n" * 32)
    assert first.status_code == 200
    assert jose_jwt.get_unverified_claims(first.json()["verdict"])["nonce"] == "n" * 32
    assert r21._ask(c, dlg, nonce="n" * 32).status_code == 403
    assert r21._ask(c, dlg, body={"credential_id": r21.CRED, "card_id": r21.CARD}).status_code \
        == 400


def test_a_use_nonce_is_spent_in_its_own_table(world):
    """Review 23, I2: the persona's use nonces are kept apart from the jtis of Mantle's custody
    tokens, so neither can be spent, or pre-spent, as the other."""
    from origin.db.session import SessionLocal
    from origin.models.key_custody import KeyCustodyNonce, UseNonce

    c, _alice, bob = world
    with SessionLocal() as db:
        before = db.query(KeyCustodyNonce).count()
    assert r21._ask(c, r21._delegation(bob[0]), nonce="u" * 32).status_code == 200
    with SessionLocal() as db:
        assert db.query(UseNonce).count() == 1
        # The one new custody-token jti is Mantle's token for this very call.
        assert db.query(KeyCustodyNonce).count() == before + 1

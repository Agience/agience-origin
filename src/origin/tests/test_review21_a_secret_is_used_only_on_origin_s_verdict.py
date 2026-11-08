"""A persona opens a sealed secret only on a verdict Origin signed (review 21, F1).

Mantle's `/use` hands a persona the copy of a credential sealed to the persona's key. Mantle's own
yes is not enough: a Mantle that is taken over would say yes to anything, and the persona would
open the copy and act as the person. So Mantle asks Origin
(`POST /internal/authority/use-verdict`), on the persona's own Origin-issued delegation as the
acting credential, and Origin decides by its own walk of its replica: the subject's Invoke on the
card and on the credential, and the persona's own Read on the credential. The verdict it signs
binds the persona, the subject, the delegation's `jti`, the credential, the card and the three
grants, and the persona checks it with `prism.trust.use_verdict.verify`.

Every token here is minted by Origin's own issuers and Mantle's service token by the custody
fixture; the verdict is checked by the same prism function a persona runs.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client

ALL = ["create", "read", "update", "delete", "evict", "invoke", "add", "share", "admin"]
PATH = "/internal/authority/use-verdict"
SHELF, CARD, CRED = "shelf-1", "card-1", "cred-1"
IRIS = "agience-server-iris"


#: The sealed copy and endpoint list the credential's writer made; their digests are what the
#: writer records at Origin (review 22).
SEALED_COPY = {"alg": "RSA-OAEP-256+A256GCM", "kid": "iris-1", "ek": "e", "iv": "i", "ct": "c"}
ENDPOINTS = ["https://oauth2.googleapis.com"]


@pytest.fixture
def unsealed_world(custody_client, monkeypatch):
    """Alice's shelf holds a card and a credential; Bob holds Invoke on the shelf; Iris's own
    principal holds Read on the shelf, and so on the credential in it. The manifest also anchors Origin's own key, as every
    deployed manifest does, so the persona's check can run."""
    from origin import authority_trust, config
    from origin.key_manager import get_jwk_public

    m = authority_trust._manifest
    anchors = {**m.trust_anchors, "origin": {"jwks": {"keys": [get_jwk_public()]}}}
    monkeypatch.setattr(authority_trust, "_manifest", authority_trust.AuthorityManifest(
        issuer=config.AUTHORITY_ISSUER, artifact_id=m.artifact_id, trust_anchors=anchors,
        bootstrap_token_hash=None, raw={}))
    c = custody_client
    alice, bob = af.person("Alice"), af.person("Bob")
    af.ok(af.submit(c, alice[1], af.root(SHELF), batch="w"))
    af.ok(af.submit(c, alice[1], af.grant("g-alice", alice[0], SHELF, ALL), batch="w"))
    af.ok(af.submit(c, alice[1], af.edge(SHELF, CARD), batch="w2"))
    af.ok(af.submit(c, alice[1], af.edge(SHELF, CRED), batch="w3"))
    af.ok(af.submit(c, alice[1], af.grant("g-bob", bob[0], SHELF, ["invoke"]), batch="w4"))
    af.ok(af.submit(c, alice[1], af.grant("g-iris", IRIS, SHELF, ["read"]), batch="w5"))
    return c, alice, bob


def record_seals(c, credential, personas=("iris",)):
    """The writer's record of the credential's sealed copies, as Mantle sends it (review 22)."""
    from origin.services.authority_ledger import canonical
    from prism.trust import use_verdict

    body = {"credential_id": CRED,
            "sealed_sha256": {p: use_verdict.sealed_digest(SEALED_COPY) for p in personas},
            "endpoints_sha256": use_verdict.endpoints_digest(ENDPOINTS)}
    digest = hashlib.sha256(canonical(body).encode()).hexdigest()
    tok = _shares._token("POST", "-", htu="/internal/authority/credential-seals",
                         body_sha256=digest)
    return c.post("/internal/authority/credential-seals", json=body,
                  headers={"Authorization": f"Bearer {tok}", "X-Acting-Credential": credential})


@pytest.fixture
def world(unsealed_world):
    """The world above, with the writer's seal record for Iris's copy."""
    c, alice, bob = unsealed_world
    af.ok(record_seals(c, alice[1]))
    return c, alice, bob


def _delegation(sub, *, persona="iris", signer="iris", record=True, ttl=300):
    """The persona's server delegation as `/internal/delegation-token` issues it: Origin's own
    issuer, its `jti` recorded with the signer that asked."""
    from origin.db.session import SessionLocal
    from origin.models.key_custody import DelegationRecord
    from origin.services.auth_service import issue_delegation_token

    jti = secrets.token_hex(16)
    client = f"agience-server-{persona}"
    tok = issue_delegation_token(client, sub, ttl, signer=signer, jti=jti)
    if record:
        with SessionLocal() as db:
            db.add(DelegationRecord(jti=jti, subject=sub, audience=client, signer=signer,
                                    expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl)))
            db.commit()
    return tok


def _ask(c, credential, body=None, token=None, nonce=None):
    """Mantle's request for a verdict, with the persona's fresh nonce for the use (`.nonce`)."""
    from origin.services.authority_ledger import canonical

    nonce = nonce or secrets.token_hex(16)
    body = body if body is not None else {"credential_id": CRED, "card_id": CARD, "nonce": nonce}
    digest = hashlib.sha256(canonical(body).encode()).hexdigest()
    tok = token or _shares._token("POST", "-", htu=PATH, body_sha256=digest)
    headers = {"Authorization": f"Bearer {tok}"}
    if credential:
        headers["X-Acting-Credential"] = credential
    resp = c.post(PATH, json=body, headers=headers)
    resp.nonce = nonce
    return resp


def _kept(r):
    """What the persona compares a verdict with: Mantle's copy, list and its own nonce."""
    return {"sealed": SEALED_COPY, "endpoints": ENDPOINTS, "nonce": r.nonce}


def test_origin_signs_a_verdict_the_persona_accepts(world):
    from jose import jwt as jose_jwt
    from prism.trust import use_verdict

    c, _alice, bob = world
    dlg = _delegation(bob[0])
    r = _ask(c, dlg)
    assert r.status_code == 200, r.text
    claims = use_verdict.verify(r.json()["verdict"], persona="iris", **_kept(r),
                                delegation=jose_jwt.get_unverified_claims(dlg),
                                credential_id=CRED, card_id=CARD)
    assert claims["sub"] == bob[0]
    assert claims["grants"] == {"invoke_card": "g-bob", "invoke_credential": "g-bob",
                                "read": "g-iris"}


def test_the_persona_refuses_a_verdict_for_another_use(world):
    from jose import jwt as jose_jwt
    from prism.trust import use_verdict

    c, _alice, bob = world
    dlg = _delegation(bob[0])
    r = _ask(c, dlg)
    verdict = r.json()["verdict"]
    mine = jose_jwt.get_unverified_claims(dlg)
    for kw in ({"credential_id": "cred-2", "card_id": CARD},
               {"credential_id": CRED, "card_id": "card-2"}):
        with pytest.raises(use_verdict.VerdictRefused):
            use_verdict.verify(verdict, persona="iris", delegation=mine, **_kept(r), **kw)
    other = jose_jwt.get_unverified_claims(_delegation(bob[0]))
    with pytest.raises(use_verdict.VerdictRefused):          # bound to the other delegation's jti
        use_verdict.verify(verdict, persona="iris", delegation=other, **_kept(r),
                           credential_id=CRED,
                           card_id=CARD)
    with pytest.raises(use_verdict.VerdictRefused):          # addressed to Iris, not Lumen
        use_verdict.verify(verdict, persona="lumen", delegation=mine, **_kept(r),
                           credential_id=CRED,
                           card_id=CARD)


def test_no_verdict_without_the_subject_s_invoke(world):
    c, alice, _bob = world
    carol = af.person("Carol")
    r = _ask(c, _delegation(carol[0]))
    assert r.status_code == 403 and "invoke" in r.text.lower()


def test_no_verdict_without_the_persona_s_own_read(world):
    c, _alice, bob = world
    r = _ask(c, _delegation(bob[0], persona="lumen", signer="lumen"))
    assert r.status_code == 403 and "read" in r.text.lower()


def test_a_delegation_the_shared_identity_asked_for_gets_no_verdict(world):
    c, _alice, bob = world
    assert _ask(c, _delegation(bob[0], signer="chorus")).status_code == 403


def test_an_unrecorded_delegation_gets_no_verdict(world):
    c, _alice, bob = world
    assert _ask(c, _delegation(bob[0], record=False)).status_code == 403


def test_a_describe_delegation_or_a_person_s_own_token_gets_no_verdict(world):
    """The system delegation the describe route mints is addressed to any persona and names no
    person; a person's own access token is not the persona's. Neither decides a use."""
    from origin.service_identity import get_system_principal_id
    from origin.services.auth_service import issue_system_delegation_token

    c, _alice, bob = world
    describe = issue_system_delegation_token(get_system_principal_id() or "sys", actor=IRIS,
                                             scope="platform.describe", audience=IRIS,
                                             jti=secrets.token_hex(16))
    assert _ask(c, describe).status_code == 403
    assert _ask(c, bob[1]).status_code == 403


def test_the_call_is_mantle_s_bound_token_only(world):
    c, _alice, bob = world
    dlg = _delegation(bob[0])
    assert _ask(c, None).status_code == 401
    other = _shares._token("POST", "-", htu=PATH, body_sha256="0" * 64)
    assert _ask(c, dlg, token=other).status_code == 401          # bound to another body
    chorus = _shares._token("POST", "-", iss="chorus", htu=PATH, body_sha256="0" * 64)
    assert _ask(c, dlg, token=chorus).status_code == 403


def test_a_verdict_is_no_bearer_at_origin(world):
    c, _alice, bob = world
    verdict = _ask(c, _delegation(bob[0])).json()["verdict"]
    assert c.get("/auth/userinfo", headers={"Authorization": f"Bearer {verdict}"}).status_code == 401


def test_mantle_mints_no_describe_delegation(world, monkeypatch):
    """`/internal/describe-delegation` takes Crystal's own token alone: Mantle's service token no
    longer reaches it through the platform-server fallback."""
    from origin.tests.authority_fixtures import operator

    c, _alice, _bob = world
    operator(monkeypatch)
    tok = _shares._token("POST", "-", htu="/internal/describe-delegation")
    r = c.post("/internal/describe-delegation",
               json={"persona_client_id": IRIS, "resource_id": CARD},
               headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403, r.text


SYSTEM = "sys-principal-1"


def _platform_delegation(c, monkeypatch, purpose):
    """The system delegation Iris obtains signing as itself, through the real route."""
    from origin.routers import auth_router
    from origin.services.dependencies import AuthContext, get_auth

    monkeypatch.setattr(auth_router.platform_settings, "get",
                        lambda k, *a, **kw: "operator-1" if k == "platform.operator_id" else None)
    c.app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="iris", principal_type="service", user_id=None)
    try:
        return c.post("/internal/system-delegation", json={"purpose": purpose})
    finally:
        c.app.dependency_overrides.pop(get_auth, None)


def test_iris_s_platform_mail_delegation_is_recorded_and_decides_a_verdict(world, monkeypatch):
    """Platform mail: the system principal's Invoke on the platform's card and credential, and
    Iris's Read, on the delegation Iris obtained as itself, which Origin now records by `jti`."""
    from jose import jwt as jose_jwt

    import origin.service_identity as ksi
    from prism.trust import use_verdict

    c, alice, _bob = world
    monkeypatch.setattr(ksi, "get_system_principal_id", lambda: SYSTEM)
    af.ok(af.submit(c, alice[1], af.grant("g-sys", SYSTEM, SHELF, ["invoke"]), batch="sys"))
    r = _platform_delegation(c, monkeypatch, "platform-mail")
    assert r.status_code == 200, r.text
    dlg = r.json()["token"]
    got = _ask(c, dlg)
    assert got.status_code == 200, got.text
    claims = use_verdict.verify(got.json()["verdict"], persona="iris", **_kept(got),
                                delegation=jose_jwt.get_unverified_claims(dlg),
                                credential_id=CRED, card_id=CARD)
    assert claims["sub"] == SYSTEM and claims["grants"]["invoke_card"] == "g-sys"


def test_no_other_system_delegation_decides_a_use(world, monkeypatch):
    """A system delegation for a purpose no secret use names, even one Origin recorded, for a
    persona proven by its key, decides nothing."""
    from origin.db.session import SessionLocal
    from origin.models.key_custody import DelegationRecord
    from origin.services.auth_service import issue_system_delegation_token

    import origin.service_identity as ksi

    c, alice, _bob = world
    monkeypatch.setattr(ksi, "get_system_principal_id", lambda: SYSTEM)
    af.ok(af.submit(c, alice[1], af.grant("g-sys", SYSTEM, SHELF, ["invoke"]), batch="sys"))
    jti = secrets.token_hex(16)
    tok = issue_system_delegation_token(SYSTEM, actor=IRIS, signer="iris",
                                        scope="platform.stripe.resolve", audience="mantle",
                                        jti=jti)
    with SessionLocal() as db:
        db.add(DelegationRecord(jti=jti, subject=SYSTEM, audience="mantle", signer="iris",
                                expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)))
        db.commit()
    assert _ask(c, tok).status_code == 403

"""Review 19, H1: a service token any service sends is useless at any other service.

Each service's outbound service token, with the audience it really uses, is replayed at every
other service's inbound check: Origin's and Mantle's audience rule for a platform service
(`_validate_aud_for_principal`), Crystal's gateway gate (`verify_service_token`) and its
registration check (`verify_token_of`, which also takes a token once). Each is accepted only at
the service it names.
"""
from __future__ import annotations

import time
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from jose import jwk as jose_jwk
from jose import jwt


def _anchor():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return pem, {"keys": [jose_jwk.construct(pub, algorithm="RS256").to_dict()]}


KEYS = {n: _anchor() for n in ("mantle", "crystal", "chorus", "lumen", "origin")}
ANCHORS = {n: k[1] for n, k in KEYS.items()}


def _token(signer, aud):
    now = int(time.time())
    return jwt.encode({"iss": signer, "sub": signer, "aud": aud, "principal_type": "service",
                       "iat": now, "exp": now + 300, "jti": uuid.uuid4().hex},
                      KEYS[signer][0], algorithm="RS256")


#: (who sends it, the audience it is sent to) for every service-to-service call in the tree:
#: Mantle and Crystal and the personas to Origin, Crystal to Mantle (its change feed and type
#: publish), Origin to Mantle, and a persona to Crystal (its own registration).
OUTBOUND = [("mantle", "origin"), ("crystal", "origin"), ("chorus", "origin"),
            ("crystal", "mantle"), ("origin", "mantle"), ("lumen", "crystal")]


def _origin_takes(token):
    from origin.services.dependencies import _validate_aud_for_principal
    try:
        _validate_aud_for_principal(jwt.get_unverified_claims(token))
        return True
    except HTTPException:
        return False


def _mantle_takes(token):
    from mantle.services.dependencies import _validate_aud_for_principal
    try:
        _validate_aud_for_principal(jwt.get_unverified_claims(token))
        return True
    except HTTPException:
        return False


def _crystal_gate_takes(token):
    from crystal.identity import verify_service_token
    return verify_service_token(token, ANCHORS)


def _crystal_register_takes(token):
    from crystal.identity import verify_token_of
    signer = jwt.get_unverified_claims(token)["iss"]
    return verify_token_of(token, ANCHORS, signer)


TAKES = {"origin": [_origin_takes], "mantle": [_mantle_takes],
         "crystal": [_crystal_gate_takes, _crystal_register_takes]}


@pytest.mark.parametrize("signer,aud", OUTBOUND)
def test_each_outbound_token_is_taken_only_where_it_is_addressed(signer, aud):
    for service, checks in TAKES.items():
        for check in checks:
            took = check(_token(signer, aud))
            assert took is (service == aud), (signer, aud, service, check.__name__)


def test_a_registration_token_is_taken_once():
    from crystal.identity import verify_token_of
    once = _token("lumen", "crystal")
    assert verify_token_of(once, ANCHORS, "lumen") is True
    assert verify_token_of(once, ANCHORS, "lumen") is False


def test_crystal_s_own_outbound_tokens_are_useless_at_its_own_gate():
    from crystal.identity import CrystalIdentity, verify_service_token
    ident = CrystalIdentity(KEYS["crystal"][0], "http://origin.test")
    for aud in ("mantle", "origin"):
        assert verify_service_token(ident.service_jwt(aud), ANCHORS) is False

"""Crystal's own service token is verified at Origin, and reaches only Crystal's routes (review 21,
F7).

Origin expected Crystal's token at three routes (its own delegation exchange, the describe
delegation and a hop) but never verified one: `crystal` was not among the issuers Origin checks
against the manifest, so Crystal's work for a person and its event-driven describer failed closed.
Crystal is now verified like every platform service, as a service token only (`principal_type`
`service`, `sub == iss`, review 20), and reaches:

* `/internal/delegation-token`, for its own server delegation, from a delegation narrowed to it;
* `/internal/describe-delegation`, which only Crystal may ask.

It reads no person (`/internal/persons/{id}`), mints no system delegation, and exchanges nothing
for another persona.

Crystal's token is signed by prism's `sign_service_jwt` with a Crystal identity, as Crystal signs.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

CRYSTAL_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def client(origin_app, monkeypatch):
    from origin import authority_trust, config

    anchors = {"mantle": {"jwks": _shares._jwks(_shares._KEYS["mantle"], "mantle-1")},
               "crystal": {"jwks": _shares._jwks(CRYSTAL_KEY, "crystal-1")}}
    monkeypatch.setattr(authority_trust, "_manifest", authority_trust.AuthorityManifest(
        issuer=config.AUTHORITY_ISSUER, artifact_id="manifest", trust_anchors=anchors,
        bootstrap_token_hash=None, raw={}))
    with TestClient(origin_app) as c:
        from origin.db.base import Base
        from origin.db.session import get_engine

        Base.metadata.create_all(get_engine())
        yield c


def _crystal(**claims) -> dict:
    from prism.trust.service_identity import ServiceIdentity, sign_service_jwt

    me = ServiceIdentity(name="crystal", kid="crystal-1", private_key=CRYSTAL_KEY)
    return {"Authorization": "Bearer " + sign_service_jwt(audience="origin", signer=me,
                                                          additional_claims=claims)}


def _narrowed_to_crystal(person_id: str) -> str:
    from origin.services.auth_service import issue_narrow_delegation
    return issue_narrow_delegation(person_id, "crystal", ["persona:crystal"])


def test_crystal_exchanges_its_own_narrowed_delegation(client):
    alice = af.person("Alice")
    r = client.post("/internal/delegation-token", headers=_crystal(),
                    json={"server_client_id": "agience-server-crystal",
                          "subject_token": _narrowed_to_crystal(alice[0])})
    assert r.status_code == 200, r.text


def test_crystal_exchanges_nothing_for_another_persona(client):
    alice = af.person("Alice")
    r = client.post("/internal/delegation-token", headers=_crystal(),
                    json={"server_client_id": "agience-server-iris",
                          "subject_token": _narrowed_to_crystal(alice[0])})
    assert r.status_code == 403


def test_crystal_asks_the_describe_delegation(client, monkeypatch):
    import origin.service_identity as ksi

    af.operator(monkeypatch)
    monkeypatch.setattr(ksi, "get_system_principal_id", lambda: "sys-principal-1")
    r = client.post("/internal/describe-delegation", headers=_crystal(),
                    json={"persona_client_id": "agience-server-iris", "resource_id": "a-1"})
    assert r.status_code == 200, r.text


def test_crystal_reads_no_person_and_mints_no_system_delegation(client, monkeypatch):
    alice = af.person("Alice")
    af.operator(monkeypatch)
    assert client.get(f"/internal/persons/{alice[0]}", headers=_crystal()).status_code == 403
    assert client.post("/internal/system-delegation", headers=_crystal(),
                       json={"purpose": "platform-mail"}).status_code == 403


def test_crystal_s_key_stands_for_no_person(client):
    """Review 20's rule holds for Crystal too: its key signs only its own service token."""
    alice = af.person("Alice")
    tok = _crystal(principal_type="delegation", sub=alice[0])   # defaults win: still a service
    assert client.get("/auth/userinfo", headers=tok).status_code in (401, 403)

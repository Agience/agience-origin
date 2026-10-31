"""Origin's share of a Mantle master key is stored and released for Mantle's service identity alone.

The tokens here are really signed and really verified: `get_auth` checks each against an authority
manifest that anchors `mantle` and `chorus` to keys made in this file, so "Mantle's enrolled service
identity" means the key the manifest names, not a stubbed `AuthContext`. Each token is also bound
to one call: a lifetime of at most 60 seconds, a `jti` used once, and claims naming the method, the
path and the principal.

Imports happen inside the tests, as in `test_oracle_router_auth.py`: the `origin_app` fixture
reloads the modules a module-level import would bind to.
"""
from __future__ import annotations

import base64
import logging
import threading
import time
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

KCV_A = "a" * 32
KCV_B = "b" * 32
SHARE_Y = base64.b64encode(bytes(range(32))).decode()
OTHER_Y = base64.b64encode(bytes(32)).decode()


def _pem(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def _jwks(key, kid):
    from jose import jwk

    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    d = jwk.construct(pub, "RS256").to_dict()
    d.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return {"keys": [d]}


_KEYS = {name: rsa.generate_private_key(public_exponent=65537, key_size=2048)
         for name in ("mantle", "chorus", "impostor")}


def _token(method: str, principal: str, *, iss: str = "mantle", key: str | None = None,
           aud: str = "origin", ttl: int = 60, drop: tuple = (), **extra) -> str:
    """A service token bound to `method /internal/key-shares/<principal>`, unless `extra` or
    `drop` spoils it."""
    from jose import jwt

    now = int(time.time())
    claims = {"iss": iss, "sub": iss, "aud": aud, "principal_type": "service",
              "iat": now, "exp": now + ttl, "jti": uuid.uuid4().hex, "htm": method,
              "htu": f"/internal/key-shares/{principal}", "principal_id": principal}
    claims.update(extra)
    for k in drop:
        claims.pop(k, None)
    return jwt.encode(claims, _pem(_KEYS[key or iss]), algorithm="RS256",
                      headers={"kid": f"{iss}-1"})


@pytest.fixture
def custody_client(origin_app, monkeypatch):
    """A client with real tables and a manifest anchoring `mantle` and `chorus`."""
    from origin import authority_trust

    manifest = authority_trust.AuthorityManifest(
        issuer="http://origin.test", artifact_id="manifest",
        trust_anchors={n: {"jwks": _jwks(_KEYS[n], f"{n}-1")} for n in ("mantle", "chorus")},
        bootstrap_token_hash=None, raw={})
    monkeypatch.setattr(authority_trust, "_manifest", manifest)
    with TestClient(origin_app) as c:
        from origin.db.base import Base
        from origin.db.session import get_engine

        Base.metadata.create_all(get_engine())
        yield c


def _put(c, principal, tok=None, **body):
    body = {"x": 2, "y": SHARE_Y, "kcv": KCV_A, **body}
    tok = tok or _token("PUT", principal)
    return c.put(f"/internal/key-shares/{principal}", json=body,
                 headers={"Authorization": f"Bearer {tok}"})


def _get(c, principal, tok=None):
    tok = tok or _token("GET", principal)
    return c.get(f"/internal/key-shares/{principal}", headers={"Authorization": f"Bearer {tok}"})


# -- the positive control and the storage --------------------------------------------------------

def test_mantle_stores_and_releases_a_share(custody_client, caplog):
    """The positive control for every refusal below."""
    with caplog.at_level(logging.INFO):
        assert _put(custody_client, "p-1").json()["outcome"] == "stored"
        r = _get(custody_client, "p-1")
    assert r.status_code == 200
    assert (r.json()["x"], r.json()["y"], r.json()["kcv"]) == (2, SHARE_Y, KCV_A)
    released = [rec for rec in caplog.records if "key share released" in rec.getMessage()]
    assert released and released[0].levelno == logging.WARNING
    assert all(SHARE_Y not in rec.getMessage() for rec in caplog.records), "a log held the share"


def test_an_absent_share_says_so_in_its_body(custody_client):
    r = _get(custody_client, "nobody")
    assert r.status_code == 404 and r.json() == {"absent": True, "principal_id": "nobody"}


def test_the_share_is_in_its_own_table_encrypted(custody_client):
    from origin.db.session import SessionLocal
    from origin.models.key_custody import KeyCustodyShare
    from origin.models.platform_setting import PlatformSetting

    _put(custody_client, "p-2")
    with SessionLocal() as db:
        row = db.get(KeyCustodyShare, "p-2")
        assert row is not None and SHARE_Y not in row.y_sealed
        assert db.get(PlatformSetting, "custody.mantle.p-2") is None


def test_a_share_that_cannot_be_decrypted_is_refused_not_absent(custody_client):
    from origin.db.session import SessionLocal
    from origin.models.key_custody import KeyCustodyShare

    _put(custody_client, "p-3")
    with SessionLocal() as db:
        db.get(KeyCustodyShare, "p-3").y_sealed = "gAAAA-not-a-fernet-token"
        db.commit()
    r = _get(custody_client, "p-3")
    assert r.status_code == 503 and "absent" not in r.json()


# -- the settings routes cannot reach a share ----------------------------------------------------

def _operator(monkeypatch):
    from origin import config
    from origin.services.auth_service import create_jwt_token
    from origin.services.platform_settings_service import settings as platform_settings

    real_get = platform_settings.get
    monkeypatch.setattr(platform_settings, "get", lambda k, *a, **kw:
                        "00000000-0000-0000-0000-0000000000aa" if k == "platform.operator_id"
                        else real_get(k, *a, **kw))
    return create_jwt_token({"sub": "00000000-0000-0000-0000-0000000000aa", "email": "op@x.test",
                             "name": "Op", "client_id": "platform",
                             "aud": config.AUTHORITY_ISSUER})


def test_the_settings_routes_cannot_write_or_list_a_custody_key(custody_client, monkeypatch):
    _put(custody_client, "p-4")
    op = {"Authorization": f"Bearer {_operator(monkeypatch)}"}
    r = custody_client.patch("/system/settings", headers=op, json={"settings": [
        {"key": "custody.mantle.p-4", "value": '{"x": 2, "y": "AA==", "kcv": "' + KCV_B + '"}'}]})
    assert r.status_code == 400
    listed = custody_client.get("/system/settings", headers=op).json()["categories"]
    assert "custody" not in listed
    assert _get(custody_client, "p-4").json()["kcv"] == KCV_A


def test_no_settings_writer_can_store_a_custody_key(custody_client):
    from origin.db.session import SessionLocal
    from origin.services.platform_settings_service import is_secret_key
    from origin.services.platform_settings_service import settings as platform_settings

    assert is_secret_key("custody.anything")
    with SessionLocal() as db, pytest.raises(ValueError):
        platform_settings.set_value(db, "custody.mantle.p-5", "plaintext")


# -- who may call --------------------------------------------------------------------------------

def test_another_platform_service_is_refused(custody_client):
    """Chorus holds an enrolled key and passes every other peer gate; it has no part in custody."""
    _put(custody_client, "p-6")
    assert _get(custody_client, "p-6", _token("GET", "p-6", iss="chorus")).status_code == 403
    assert _put(custody_client, "p-6", _token("PUT", "p-6", iss="chorus"),
                kcv=KCV_B).status_code == 403


def test_a_token_claiming_mantle_signed_by_another_key_is_refused(custody_client):
    assert _get(custody_client, "p-7", _token("GET", "p-7", key="impostor")).status_code == 401


def test_a_mantle_token_for_another_audience_is_refused(custody_client):
    assert _get(custody_client, "p-7", _token("GET", "p-7", aud="mantle")).status_code == 401


def test_a_persona_riding_mantle_s_key_is_refused(custody_client):
    tok = _token("GET", "p-7", client_id="agience-server-ophan")
    assert _get(custody_client, "p-7", tok).status_code == 403


def test_the_operator_is_refused(custody_client, monkeypatch):
    """An operator token opens `/oracle`; it does not open a key share."""
    _put(custody_client, "p-8")
    assert _get(custody_client, "p-8", _operator(monkeypatch)).status_code == 403


# -- each token is bound to one call --------------------------------------------------------------

def test_a_token_is_used_once(custody_client):
    _put(custody_client, "p-9")
    tok = _token("GET", "p-9")
    assert _get(custody_client, "p-9", tok).status_code == 200
    assert _get(custody_client, "p-9", tok).status_code == 401


@pytest.mark.parametrize("spoil", [
    {"htm": "PUT"},
    {"htu": "/internal/key-shares/someone-else"},
    {"principal_id": "someone-else"},
    {"ttl": 61},
    {"drop": ("jti",)},
    {"drop": ("htm",)},
    {"drop": ("principal_id",)},
])
def test_a_token_bound_to_another_call_is_refused(custody_client, spoil):
    _put(custody_client, "p-10")
    assert _get(custody_client, "p-10", _token("GET", "p-10", **spoil)).status_code == 401


def test_a_get_token_does_not_store(custody_client):
    assert _put(custody_client, "p-11", _token("GET", "p-11")).status_code == 401


# -- overwrite rules, atomically -----------------------------------------------------------------

def test_a_share_of_another_key_is_not_overwritten(custody_client):
    assert _put(custody_client, "p-12").json()["outcome"] == "stored"
    assert _put(custody_client, "p-12").json()["outcome"] == "unchanged"
    assert _put(custody_client, "p-12", y=OTHER_Y, kcv=KCV_B).status_code == 409
    assert _get(custody_client, "p-12").json()["kcv"] == KCV_A


def test_a_share_of_the_same_key_replaces_and_a_named_kcv_supersedes(custody_client):
    _put(custody_client, "p-13")
    assert _put(custody_client, "p-13", y=OTHER_Y).json()["outcome"] == "replaced"
    r = _put(custody_client, "p-13", kcv=KCV_B, supersedes=KCV_A)
    assert r.json()["outcome"] == "replaced"
    assert _get(custody_client, "p-13").json()["kcv"] == KCV_B


def test_two_stores_of_different_keys_cannot_both_win(custody_client):
    """Without a conditional write, both calls read 'nothing stored' and both answered stored."""
    from origin.db.session import SessionLocal
    from origin.services import key_shares

    barrier = threading.Barrier(2)
    real_read = key_shares._read

    def slow_read(db, principal_id):
        row = real_read(db, principal_id)
        try:
            barrier.wait(timeout=2)
        except threading.BrokenBarrierError:
            pass
        return row

    key_shares._read = slow_read
    results = []

    def store(kcv):
        with SessionLocal() as db:
            try:
                results.append(key_shares.store_share(db, "p-14", {"x": 2, "y": SHARE_Y,
                                                                   "kcv": kcv}))
            except key_shares.ShareConflict:
                results.append("conflict")

    try:
        threads = [threading.Thread(target=store, args=(k,)) for k in (KCV_A, KCV_B)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        key_shares._read = real_read
    assert sorted(results) == ["conflict", "stored"], results


@pytest.mark.parametrize("body", [{"x": 0}, {"x": "2"}, {"y": "not base64!"}, {"kcv": "XYZ"}])
def test_a_malformed_share_is_refused(custody_client, body):
    assert _put(custody_client, "p-15", **body).status_code == 400

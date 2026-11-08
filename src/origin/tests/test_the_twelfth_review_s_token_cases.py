"""Review 12's token cases at Origin (2026-11-03).

Decision 2  Cross-persona work: Origin exchanges per hop. A persona holding a delegation narrowed to
            itself exchanges it, on its own signed service token, at `/internal/narrow-hop` for one
            narrowed to the next persona: the same person, scope `persona:<next>` only, five
            minutes and never past the token it came from, only along the pairs Origin lists
            (`NARROW_HOPS`), each hop recorded.
H5          The server delegation a persona obtains from its narrowed delegation keeps the
            narrowing: the narrowed scope and Origin's `narrowed` claim.
M8          Not-before rows are served by a monotonic sequence (`after`), not by time.
L11         `REGISTRATION_PAUSED` also stops the account that OTP verification or a first federated
            sign-in would create.
Info        A missing `service_accounts` table refuses to issue a person token, rather than issue
            one for what may be a service account. A redirect URL never picks a narrow audience:
            only facets Origin lists (`NARROW_FACETS`) are narrowed to, and a first-party sign-in
            to any other facet is refused. Origin's issuer and key are per deployment: a staging
            Origin's tokens are not production's.
"""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt as jose_jwt

from origin.tests import authority_fixtures as af
from origin.tests import test_a_sign_in_method_changes_only_with_a_fresh_step_up as t
from origin.tests.test_the_eighth_review_s_sign_in_cases import _exchange

custody_client = t.custody_client


def _as_service(name):
    """The persona `name` calling Origin on its own signed service token."""
    from origin.main import app
    from origin.services.dependencies import AuthContext, get_auth
    app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id=name, principal_type="service", user_id=None)


def _clear():
    from origin.main import app
    from origin.services.dependencies import get_auth
    app.dependency_overrides.pop(get_auth, None)


def _hop(c, caller, subject, audience, **extra):
    _as_service(caller)
    try:
        return c.post("/internal/narrow-hop",
                      json={"subject_token": subject, "audience": audience, **extra})
    finally:
        _clear()


# -- H5 -------------------------------------------------------------------------------------------

def test_a_persona_s_server_delegation_keeps_its_narrowing(custody_client):
    c = custody_client
    p, tok = af.person("Ann")
    lumen = _exchange(c, tok, "lumen").json()["access_token"]
    _as_service("lumen")
    try:
        r = c.post("/internal/delegation-token",
                   json={"server_client_id": "agience-server-lumen", "subject_token": lumen,
                         "ttl_seconds": 600})
    finally:
        _clear()
    assert r.status_code == 200, r.text
    claims = jose_jwt.get_unverified_claims(r.json()["token"])
    assert claims["narrowed"] is True and claims["scope"] == "persona:lumen"
    assert claims["exp"] <= jose_jwt.get_unverified_claims(lumen)["exp"] + 1


def test_a_person_s_own_token_makes_no_server_delegation(custody_client):
    """Review 27: no one exchanges a person's own token for a server delegation, the chorus
    identity included; only a delegation narrowed to the asking persona is exchanged."""
    c = custody_client
    p, tok = af.person("Ann")
    _as_service("chorus")
    try:
        r = c.post("/internal/delegation-token",
                   json={"server_client_id": "agience-server-iris", "subject_token": tok})
    finally:
        _clear()
    assert r.status_code == 403, r.text


# -- decision 2: per-hop exchange -----------------------------------------------------------------

def test_crystal_hops_to_a_persona_for_the_same_person_and_the_hop_is_recorded(custody_client):
    from origin.db.session import SessionLocal
    from origin.models.narrow_hop import NarrowHop

    c = custody_client
    p, tok = af.person("Ann")
    crystal = _exchange(c, tok, "crystal").json()["access_token"]
    r = _hop(c, "crystal", crystal, "iris")
    assert r.status_code == 200, r.text
    claims = jose_jwt.get_unverified_claims(r.json()["access_token"])
    sub_claims = jose_jwt.get_unverified_claims(crystal)
    assert claims["sub"] == p and claims["aud"] == "iris" and claims["act"]["sub"] == "iris"
    assert claims["narrowed"] is True and claims["scope"] == "persona:iris"
    assert claims["exp"] <= sub_claims["exp"] and "refresh_token" not in r.json()
    assert claims["hop"] == {"from": "crystal", "jti": sub_claims["jti"]}
    with SessionLocal() as db:
        rows = db.query(NarrowHop).filter(NarrowHop.sub == p).all()
        assert [(h.from_aud, h.to_aud, h.subject_jti) for h in rows] == [
            ("crystal", "iris", sub_claims["jti"])]


def test_lumen_hops_to_sage_and_nowhere_else(custody_client):
    c = custody_client
    p, tok = af.person("Ann")
    lumen = _exchange(c, tok, "lumen").json()["access_token"]
    assert _hop(c, "lumen", lumen, "sage").status_code == 200
    r = _hop(c, "lumen", lumen, "iris")
    assert r.status_code == 403 and "hop" in r.text


def test_a_hop_needs_the_persona_its_token_was_narrowed_to(custody_client):
    c = custody_client
    p, tok = af.person("Ann")
    crystal = _exchange(c, tok, "crystal").json()["access_token"]
    assert _hop(c, "lumen", crystal, "sage").status_code == 403      # Lumen holding Crystal's
    from origin.main import app                                       # a person, not a persona
    from origin.services.dependencies import AuthContext, get_auth
    app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id=p, principal_type="user", user_id=p)
    try:
        r = c.post("/internal/narrow-hop", json={"subject_token": crystal, "audience": "iris"})
    finally:
        _clear()
    assert r.status_code == 403


def test_a_hop_widens_nothing(custody_client):
    c = custody_client
    p, tok = af.person("Ann")
    crystal = _exchange(c, tok, "crystal").json()["access_token"]
    assert _hop(c, "crystal", tok, "iris").status_code == 403          # a person's own token
    assert _hop(c, "crystal", crystal, "iris", scope="persona:iris platform:admin"
                ).status_code == 400
    assert _hop(c, "crystal", crystal, "ember").status_code == 403    # not a listed pair
    iris = _hop(c, "crystal", crystal, "iris").json()["access_token"]
    assert _hop(c, "iris", iris, "sage").status_code == 403           # a hop does not chain on


def test_a_hop_never_outlives_the_token_it_came_from(custody_client):
    from origin.services import auth_service

    c = custody_client
    p, tok = af.person("Ann")
    short = auth_service.issue_narrow_delegation(
        p, "crystal", ["persona:crystal"],
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=40))
    r = _hop(c, "crystal", short, "iris")
    assert r.status_code == 200, r.text
    assert jose_jwt.get_unverified_claims(r.json()["access_token"])["exp"] <= \
        jose_jwt.get_unverified_claims(short)["exp"]


def test_a_hop_after_sign_out_everywhere_is_refused(custody_client):
    from origin.db.session import SessionLocal
    from origin.services import not_before

    c = custody_client
    p, tok = af.person("Ann")
    crystal = _exchange(c, tok, "crystal").json()["access_token"]
    import time
    time.sleep(1.1)
    with SessionLocal() as db:
        not_before.end_all(db, p)
        db.commit()
    assert _hop(c, "crystal", crystal, "iris").status_code == 401


# -- M8: not-before by sequence -------------------------------------------------------------------

def _bounds(c, after=None):
    r = c.get("/auth/not-before", params={} if after is None else {"after": after})
    assert r.status_code == 200, r.text
    return jose_jwt.get_unverified_claims(r.json()["token"])


def test_not_before_is_served_by_sequence(custody_client):
    from origin.db.session import SessionLocal
    from origin.services import not_before

    c = custody_client
    a, _ = af.person("A")
    b, _ = af.person("B")
    with SessionLocal() as db:
        not_before.end_all(db, a)
        db.commit()
    first = _bounds(c)
    assert [e["sub"] for e in first["entries"]] == [a] and first["seq"] >= 1
    assert first["entries"][0]["seq"] == first["seq"]
    with SessionLocal() as db:
        not_before.end_access(db, b)
        db.commit()
    later = _bounds(c, after=first["seq"])
    assert [e["sub"] for e in later["entries"]] == [b] and later["seq"] > first["seq"]
    assert _bounds(c, after=later["seq"])["entries"] == []
    with SessionLocal() as db:                       # a row changed again moves to a new seq
        not_before.end_all(db, a)
        db.commit()
    again = _bounds(c, after=later["seq"])
    assert [e["sub"] for e in again["entries"]] == [a] and again["seq"] > later["seq"]


def test_a_bound_whose_time_is_older_than_the_cursor_is_never_skipped(custody_client):
    """A row committed late with an earlier wall time still has a later seq."""
    from origin.db.session import SessionLocal
    from origin.models.sign_in_bounds import PersonNotBefore
    from origin.services import not_before

    c = custody_client
    a, _ = af.person("A")
    b, _ = af.person("B")
    with SessionLocal() as db:
        not_before.end_all(db, a)
        db.commit()
    cursor = _bounds(c)["seq"]
    with SessionLocal() as db:
        not_before.end_all(db, b)
        row = db.get(PersonNotBefore, b)
        row.access_before = row.refresh_before = datetime.now(timezone.utc) - timedelta(hours=1)
        db.commit()
    assert [e["sub"] for e in _bounds(c, after=cursor)["entries"]] == [b]


# -- L11: the registration pause covers every path that makes an account --------------------------

@pytest.fixture
def paused(monkeypatch):
    from origin import config
    monkeypatch.setattr(config, "REGISTRATION_PAUSED", True, raising=False)


def test_a_paused_registration_stops_an_otp_account(custody_client, paused):
    from origin.db.session import SessionLocal
    from origin.services import person_service

    with SessionLocal() as db:
        with pytest.raises(PermissionError):
            person_service.get_or_create_user_by_email(db, "new@team.test")
        assert person_service.get_user_by_email(db, "new@team.test") is None


def test_a_paused_registration_stops_a_first_federated_sign_in(custody_client, paused):
    from origin.db.session import SessionLocal
    from origin.services import person_service

    with SessionLocal() as db:
        with pytest.raises(PermissionError):
            person_service.get_or_create_user_by_oidc_identity(
                db, oidc_provider="google", oidc_subject="nobody-yet", email="fresh@team.test",
                name="Fresh", email_verified=True)
        assert person_service.get_user_by_email(db, "fresh@team.test") is None


def test_a_paused_registration_still_signs_in_an_existing_person(custody_client, paused):
    from origin.db.session import SessionLocal
    from origin.services import person_service

    p, _ = af.person("Old", email="old@team.test")
    with SessionLocal() as db:
        assert str(person_service.get_or_create_user_by_email(db, "old@team.test").id) == p


# -- Info: service accounts fail closed -----------------------------------------------------------

def test_a_missing_service_accounts_table_issues_no_person_token(custody_client, monkeypatch):
    from sqlalchemy.exc import OperationalError

    from origin.db import session as sess
    from origin.services import auth_service

    class Broken:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, *a, **k):
            raise OperationalError("SELECT", {}, Exception("no such table: service_accounts"))

    monkeypatch.setattr(sess, "SessionLocal", lambda: Broken())
    with pytest.raises(RuntimeError, match="service_accounts"):
        auth_service.create_jwt_token({"sub": "someone", "aud": "x"})


# -- Info: no URL picks a narrow audience ---------------------------------------------------------

def _facet_code(c, redirect):
    from origin import config
    from origin.routers import auth_router
    alice, _tok = af.person("Alice", email="alice@team.test")
    t._identity(alice, "google", "alice-google")
    verifier = "v" * 48
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()) \
        .rstrip(b"=").decode()
    code = t._code("google", "alice-google", "alice@team.test", redirect=redirect)
    auth_router.authorization_codes[code].update(
        {"code_challenge": challenge, "code_challenge_method": "S256",
         "client_id": config.PLATFORM_CLIENT_ID})
    return c.post("/auth/token", data={"grant_type": "authorization_code", "code": code,
                                       "redirect_uri": redirect,
                                       "client_id": config.PLATFORM_CLIENT_ID,
                                       "code_verifier": verifier})


def test_a_facet_origin_is_no_narrow_audience_unless_origin_lists_it(custody_client,
                                                                     monkeypatch):
    from origin import config
    from origin.services import auth_service

    monkeypatch.setattr(config, "FACET_URIS", ["https://my.test", "https://aria.test",
                                               "https://other.test"], raising=False)
    monkeypatch.setattr(config, "APP_URI", "https://my.test", raising=False)
    monkeypatch.setattr(config, "NARROW_FACETS", ["https://aria.test"], raising=False)
    aud = auth_service.narrow_audiences()
    assert "https://aria.test" in aud and "https://other.test" not in aud


def test_a_sign_in_to_an_unlisted_facet_gets_no_token(custody_client, monkeypatch):
    from origin import config

    monkeypatch.setattr(config, "FACET_URIS", ["https://my.test", "https://other.test"],
                        raising=False)
    monkeypatch.setattr(config, "APP_URI", "https://my.test", raising=False)
    monkeypatch.setattr(config, "NARROW_FACETS", [], raising=False)
    r = _facet_code(custody_client, "https://other.test/cb")
    assert r.status_code == 400 and "facet" in r.text


def test_a_sign_in_to_a_listed_facet_gets_only_its_narrowed_delegation(custody_client,
                                                                        monkeypatch):
    from origin import config

    monkeypatch.setattr(config, "FACET_URIS", ["https://my.test", "https://aria.test"],
                        raising=False)
    monkeypatch.setattr(config, "APP_URI", "https://my.test", raising=False)
    monkeypatch.setattr(config, "NARROW_FACETS", ["https://aria.test"], raising=False)
    r = _facet_code(custody_client, "https://aria.test/cb")
    assert r.status_code == 200, r.text
    assert "refresh_token" not in r.json()
    assert jose_jwt.get_unverified_claims(r.json()["access_token"])["aud"] == "https://aria.test"


# -- H4: issuer and key are per deployment --------------------------------------------------------

def test_a_staging_origin_s_token_is_not_production_s(custody_client, monkeypatch, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from origin import config
    from origin.services import auth_service, auth_verifier

    staging_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = staging_key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode()
    now = int(datetime.now(timezone.utc).timestamp())
    claims = {"sub": "p", "aud": "https://rc.origin.test", "iss": "https://rc.origin.test",
              "iat": now, "exp": now + 600}
    staging = jose_jwt.encode(claims, pem, algorithm="RS256", headers={"kid": "origin-1"})
    assert auth_verifier.verify_token(staging) is None               # other key, other issuer
    # Production's key with staging's issuer is refused too: the issuer is checked, not assumed.
    prod_signed = jose_jwt.encode({**claims, "aud": config.AUTHORITY_ISSUER},
                                  auth_service.get_private_key_pem(), algorithm="RS256",
                                  headers={"kid": "origin-1"})
    assert auth_verifier.verify_token(prod_signed) is None
    # What this Origin issues names this Origin's own issuer, whatever it is configured to be.
    monkeypatch.setattr(config, "AUTHORITY_ISSUER", "https://rc.origin.test", raising=False)
    mine = auth_service.create_jwt_token({"sub": "p", "aud": "https://rc.origin.test",
                                          "token_type": "probe"})
    assert jose_jwt.get_unverified_claims(mine)["iss"] == "https://rc.origin.test"


# -- decision 2 at the token endpoint: RFC 8693 with the persona's RFC 7523 client assertion ------

@pytest.fixture
def crystal_key(custody_client, monkeypatch):
    """Crystal's own key, anchored in the authority manifest as Crystal's."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    from origin import authority_trust
    from origin.tests import test_a_key_share_is_released_only_to_mantle as shares

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    m = authority_trust._manifest
    anchors = {**m.trust_anchors, "crystal": {"jwks": shares._jwks(key, "crystal-1")}}
    monkeypatch.setattr(authority_trust, "_manifest", authority_trust.AuthorityManifest(
        issuer=m.issuer, artifact_id=m.artifact_id, trust_anchors=anchors,
        bootstrap_token_hash=m.bootstrap_token_hash, raw=m.raw))
    return key


def _assertion(key, *, subject="", iss="crystal", aud=None, ttl=60):
    import hashlib
    import time
    import uuid

    from origin import config
    from origin.tests import test_a_key_share_is_released_only_to_mantle as shares
    now = int(time.time())
    return jose_jwt.encode(
        {"iss": iss, "sub": iss, "aud": aud or f"{config.ORIGIN_URI.rstrip('/')}/auth/token",
         "principal_type": "service", "iat": now, "exp": now + ttl, "jti": uuid.uuid4().hex,
         "subject_digest": hashlib.sha256(subject.encode()).hexdigest()},
        shares._pem(key), algorithm="RS256", headers={"kid": f"{iss}-1"})


def _endpoint_hop(c, subject, audience, assertion):
    form = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": audience, "client_id": "agience-server-crystal"}
    if assertion:
        form.update({"client_assertion_type":
                     "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                     "client_assertion": assertion})
    return c.post("/auth/token", data=form)


def test_crystal_hops_at_the_token_endpoint_on_its_own_assertion(custody_client, crystal_key):
    c = custody_client
    p, tok = af.person("Ann")
    crystal = _exchange(c, tok, "crystal").json()["access_token"]
    r = _endpoint_hop(c, crystal, "sage", _assertion(crystal_key, subject=crystal))
    assert r.status_code == 200, r.text
    claims = jose_jwt.get_unverified_claims(r.json()["access_token"])
    assert claims["aud"] == "sage" and claims["sub"] == p and claims["scope"] == "persona:sage"


def test_a_hop_at_the_token_endpoint_needs_the_persona_s_own_valid_assertion(custody_client,
                                                                             crystal_key):
    from cryptography.hazmat.primitives.asymmetric import rsa

    c = custody_client
    p, tok = af.person("Ann")
    crystal = _exchange(c, tok, "crystal").json()["access_token"]
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert _endpoint_hop(c, crystal, "sage", None).status_code == 401
    assert _endpoint_hop(c, crystal, "sage", _assertion(other, subject=crystal)).status_code == 401
    assert _endpoint_hop(c, crystal, "sage",
                         _assertion(crystal_key, subject=crystal, aud="https://elsewhere.test/auth/token")
                         ).status_code == 401
    assert _endpoint_hop(c, crystal, "sage", _assertion(crystal_key, subject=crystal, ttl=3600)).status_code == 401
    assert _endpoint_hop(c, crystal, "ember", _assertion(crystal_key, subject=crystal)).status_code == 403

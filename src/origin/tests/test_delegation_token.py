"""Tests for the internal delegation-token endpoint.

`POST /internal/delegation-token` exchanges a VERIFIED user token
(`subject_token`) for a short-lived RFC 8693 delegation JWT (sub=user,
aud=server_client_id, act.sub=server_client_id, principal_type=delegation). A
platform gateway calls this with the user's forwarded token. Origin derives the
subject from the token it verifies — never from a caller-asserted `user_id` — so
a compromised service can only delegate for users whose tokens it holds.

`POST /internal/describe-delegation` mints an operator-rooted system-describe
delegation for the autonomous event-driven describer (no user impersonation).

Platform callers authenticate to Origin via a mutual JWT signed with their own service
identity. The auth guard checks `principal_type == "service"` and that `principal_id` names one
of the platform services Origin admits.

Covers:
  - Auth guard rejects non-service / non-platform callers
  - Happy-path verifies the subject_token, derives the subject, mints a JWT
  - An invalid or non-user subject_token is rejected (no impersonation)
  - Body validation rejects unknown fields
  - describe-delegation is operator-rooted + system-scoped
"""

from __future__ import annotations

import pytest
from unittest.mock import ANY, patch

from fastapi.testclient import TestClient


def _patch_platform_auth(service_name: str = "mantle"):
    """Make the request authenticate as a platform service (mantle or chorus)."""
    from origin.routers import auth_router
    from origin.services.dependencies import AuthContext

    return patch.object(
        auth_router,
        "get_auth",
        return_value=AuthContext(
            principal_id=service_name,
            principal_type="service",
            user_id=None,
        ),
    )


@pytest.fixture(autouse=True)
def _tables(request):
    """The exchange records each delegation it issues (`delegation_tokens`), so a test that
    reaches it needs the tables."""
    if "client" in request.fixturenames:
        request.getfixturevalue("client")
        from origin.db.base import Base
        from origin.db.session import get_engine
        Base.metadata.create_all(get_engine())
    yield


def test_delegation_token_happy_path(client: TestClient, origin_app):
    # Override auth via FastAPI dependency_overrides so the platform-service
    # guard accepts our synthetic context.
    from origin.routers import auth_router
    from origin.services.dependencies import AuthContext, get_auth

    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="sage",
        principal_type="service",
        user_id=None,
    )
    try:
        # Origin verifies the forwarded delegation, narrowed to the persona, and derives
        # sub=user-123 (review 27: only a narrowed delegation is exchanged).
        with patch.object(auth_router, "verify_token", return_value=_narrowed("sage")), \
             patch.object(auth_router, "origin_auth_service") as svc:
            svc.issue_delegation_token.return_value = "minted-jwt"
            resp = client.post(
                "/internal/delegation-token",
                json={
                    "server_client_id": "agience-server-sage",
                    "subject_token": "user.jwt.forwarded",
                },
            )
        assert resp.status_code == 200
        assert resp.json() == {"token": "minted-jwt", "expires_in": 300}
        # Subject came from the VERIFIED token, not the request body.
        svc.issue_delegation_token.assert_called_once_with(
            "agience-server-sage", "user-123", 300, signer="sage", jti=ANY,
            narrowed_scope="persona:sage")
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def _as_service(origin_app, name):
    from origin.services.dependencies import AuthContext, get_auth
    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id=name, principal_type="service", user_id=None)


def test_a_persona_signing_as_itself_gets_its_own_delegation_with_its_proof(client: TestClient, origin_app):
    """2026-10-19: every persona signed as `chorus` and named itself in the request, so the actor on
    a delegation was asserted. A persona that signs with its own enrolled key is recorded as the
    proven signer (`act.iss`)."""
    from origin.routers import auth_router
    from origin.services.dependencies import get_auth

    _as_service(origin_app, "lumen")
    try:
        with patch.object(auth_router, "verify_token", return_value=_narrowed("lumen")),              patch.object(auth_router, "origin_auth_service") as svc:
            svc.issue_delegation_token.return_value = "minted-jwt"
            ok = client.post("/internal/delegation-token", json={
                "server_client_id": "agience-server-lumen", "subject_token": "user.jwt"})
            other = client.post("/internal/delegation-token", json={
                "server_client_id": "agience-server-iris", "subject_token": "user.jwt"})
        assert ok.status_code == 200
        svc.issue_delegation_token.assert_called_once_with(
            "agience-server-lumen", "user-123", 300, signer="lumen", jti=ANY,
            narrowed_scope="persona:lumen")
        assert other.status_code == 403, "a persona may obtain a delegation for itself only"
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def test_a_persona_is_admitted_to_the_exchange_and_nothing_else(client: TestClient, origin_app):
    from origin.services.dependencies import get_auth

    _as_service(origin_app, "lumen")
    try:
        resp = client.post("/internal/system-delegation", json={"purpose": "platform-mail"})
        assert resp.status_code == 403
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def test_the_minted_delegation_records_who_signed_for_it(monkeypatch):
    from jose import jwt as jose_jwt

    from origin.services import auth_service

    monkeypatch.setattr("origin.service_identity.get_host_id", lambda: "host-1")
    token = auth_service.issue_delegation_token("agience-server-lumen", "user-123", signer="lumen")
    assert jose_jwt.get_unverified_claims(token)["act"] == {"sub": "agience-server-lumen", "iss": "lumen"}


def test_delegation_token_rejects_invalid_subject_token(client: TestClient, origin_app):
    """A subject_token that fails verification gets 401 — no delegation minted."""
    from origin.routers import auth_router
    from origin.services.dependencies import AuthContext, get_auth

    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="chorus", principal_type="service", user_id=None,
    )
    try:
        with patch.object(auth_router, "verify_token", return_value=None):
            resp = client.post(
                "/internal/delegation-token",
                json={"server_client_id": "agience-server-sage", "subject_token": "garbage"},
            )
        assert resp.status_code == 401
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def test_delegation_token_rejects_service_subject_token(client: TestClient, origin_app):
    """A service/delegation token is not a user identity → 403. This is the core
    anti-impersonation guard: a caller cannot escalate a service token into a
    user delegation."""
    from origin.routers import auth_router
    from origin.services.dependencies import AuthContext, get_auth

    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="chorus", principal_type="service", user_id=None,
    )
    try:
        with patch.object(
            auth_router, "verify_token",
            return_value={"sub": "chorus", "principal_type": "service"},
        ):
            resp = client.post(
                "/internal/delegation-token",
                json={"server_client_id": "agience-server-sage", "subject_token": "svc.jwt"},
            )
        assert resp.status_code == 403
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def test_delegation_token_rejects_non_platform_caller(client: TestClient, origin_app):
    """Non-platform service tokens get 403."""
    from origin.services.dependencies import AuthContext, get_auth

    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="some-third-party-service",
        principal_type="service",
        user_id=None,
    )
    try:
        resp = client.post(
            "/internal/delegation-token",
            json={
                "server_client_id": "agience-server-sage",
                "subject_token": "user.jwt",
            },
        )
        assert resp.status_code == 403
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def test_delegation_token_rejects_user_principal(client: TestClient, origin_app):
    """User JWTs are not allowed to mint delegation tokens (caller must be a
    platform service)."""
    from origin.services.dependencies import AuthContext, get_auth

    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="user-123",
        principal_type="user",
        user_id="user-123",
    )
    try:
        resp = client.post(
            "/internal/delegation-token",
            json={
                "server_client_id": "agience-server-sage",
                "subject_token": "user.jwt",
            },
        )
        assert resp.status_code == 403
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def test_delegation_token_rejects_extra_fields(client: TestClient, origin_app):
    """The request schema forbids unknown fields (extra='forbid')."""
    from origin.services.dependencies import AuthContext, get_auth

    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="chorus",
        principal_type="service",
        user_id=None,
    )
    try:
        resp = client.post(
            "/internal/delegation-token",
            json={
                "server_client_id": "x",
                "subject_token": "y",
                "rogue_field": "z",
            },
        )
        assert resp.status_code == 422
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


# ---------------------------------------------------------------------------
# POST /internal/describe-delegation — operator-rooted system-describe
# ---------------------------------------------------------------------------

def test_describe_delegation_happy_path(client: TestClient, origin_app):
    """No subject in the request — Origin fixes sub to the system principal and
    scope to platform.describe, addressed to the persona."""
    from origin.routers import auth_router
    from origin.services.dependencies import AuthContext, get_auth
    import origin.service_identity as ksi

    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="crystal", principal_type="service", user_id=None,
    )
    try:
        with patch.object(auth_router.platform_settings, "get", return_value="operator-1"), \
             patch.object(ksi, "get_system_principal_id", return_value="sys-principal-1"), \
             patch.object(auth_router, "origin_auth_service") as svc:
            svc.issue_system_delegation_token.return_value = "minted-describe-jwt"
            resp = client.post(
                "/internal/describe-delegation",
                json={"persona_client_id": "agience-server-sage", "resource_id": "art-9"},
            )
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"token": "minted-describe-jwt", "subject_id": "sys-principal-1"}
        _, kwargs = svc.issue_system_delegation_token.call_args
        assert kwargs["actor"] == "agience-server-sage"
        assert kwargs["scope"] == "platform.describe"
        assert kwargs["audience"] == "agience-server-sage"
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def test_describe_delegation_rejects_non_platform_caller(client: TestClient, origin_app):
    from origin.services.dependencies import AuthContext, get_auth

    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="user-1", principal_type="user", user_id="user-1",
    )
    try:
        resp = client.post(
            "/internal/describe-delegation",
            json={"persona_client_id": "agience-server-sage", "resource_id": "art-9"},
        )
        assert resp.status_code == 403
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def test_describe_delegation_409_without_operator(client: TestClient, origin_app):
    from origin.routers import auth_router
    from origin.services.dependencies import AuthContext, get_auth

    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="crystal", principal_type="service", user_id=None,
    )
    try:
        with patch.object(auth_router.platform_settings, "get", return_value=None):
            resp = client.post(
                "/internal/describe-delegation",
                json={"persona_client_id": "agience-server-sage", "resource_id": "art-9"},
            )
        assert resp.status_code == 409
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


# ---------------------------------------------------------------------------
# POST /internal/system-delegation — operator-rooted, purpose-scoped
# ---------------------------------------------------------------------------

def test_system_delegation_happy_path(client: TestClient, origin_app):
    """A platform caller names a PURPOSE (not a subject); Origin fixes the subject
    to the system principal, stamps the purpose's scope, and threads the
    requesting persona through as the actor."""
    from origin.routers import auth_router
    from origin.services.dependencies import AuthContext, get_auth
    import origin.service_identity as ksi

    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="chorus", principal_type="service",
        actor="agience-server-ophan", user_id=None,
    )
    try:
        with patch.object(auth_router.platform_settings, "get", return_value="operator-1"), \
             patch.object(ksi, "get_system_principal_id", return_value="sys-principal-1"), \
             patch.object(auth_router, "origin_auth_service") as svc:
            svc.issue_system_delegation_token.return_value = "minted-sys-jwt"
            resp = client.post("/internal/system-delegation", json={"purpose": "platform-mail"})

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body == {"token": "minted-sys-jwt", "subject_id": "sys-principal-1", "scope": "platform.email.send"}
        _, kwargs = svc.issue_system_delegation_token.call_args
        assert kwargs["actor"] == "agience-server-ophan"   # requesting persona
        assert kwargs["scope"] == "platform.email.send"
        assert kwargs["audience"] == "mantle"
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def test_iris_signing_as_itself_gets_the_platform_mail_delegation_proven(client: TestClient, origin_app):
    """2026-10-19: platform mail is Iris's operation, and the mail secrets are released only to a
    persona that proved who it is. Iris, signing with its own key, may ask for the platform-mail
    delegation; it is recorded as the signer. It may ask for no other purpose."""
    from origin.routers import auth_router
    from origin.services.dependencies import get_auth
    import origin.service_identity as ksi

    _as_service(origin_app, "iris")
    try:
        with patch.object(auth_router.platform_settings, "get", return_value="operator-1"),              patch.object(ksi, "get_system_principal_id", return_value="sys-principal-1"),              patch.object(auth_router, "origin_auth_service") as svc:
            svc.issue_system_delegation_token.return_value = "minted-sys-jwt"
            mail = client.post("/internal/system-delegation", json={"purpose": "platform-mail"})
            stripe = client.post("/internal/system-delegation", json={"purpose": "platform-stripe"})
        assert mail.status_code == 200, mail.text
        _, kwargs = svc.issue_system_delegation_token.call_args
        assert kwargs["actor"] == "agience-server-iris" and kwargs["signer"] == "iris"
        assert stripe.status_code == 403, "Iris carries platform mail and nothing else"
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def test_a_minted_system_delegation_records_its_signer(monkeypatch):
    from jose import jwt as jose_jwt

    from origin.services import auth_service

    monkeypatch.setattr("origin.service_identity.get_host_id", lambda: "host-1")
    token = auth_service.issue_system_delegation_token(
        "sys-1", actor="agience-server-iris", signer="iris", scope="platform.email.send", audience="mantle")
    assert jose_jwt.get_unverified_claims(token)["act"] == {"sub": "agience-server-iris", "iss": "iris"}


def test_system_delegation_rejects_unknown_purpose(client: TestClient, origin_app):
    from origin.services.dependencies import AuthContext, get_auth

    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="chorus", principal_type="service", user_id=None,
    )
    try:
        resp = client.post("/internal/system-delegation", json={"purpose": "exfiltrate"})
        assert resp.status_code == 403
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def test_system_delegation_rejects_non_platform_caller(client: TestClient, origin_app):
    from origin.services.dependencies import AuthContext, get_auth

    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="user-123", principal_type="user", user_id="user-123",
    )
    try:
        resp = client.post("/internal/system-delegation", json={"purpose": "platform-mail"})
        assert resp.status_code == 403
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def test_system_delegation_409_without_operator(client: TestClient, origin_app):
    """No subject can be minted before the operator (the human root) exists."""
    from origin.routers import auth_router
    from origin.services.dependencies import AuthContext, get_auth

    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="chorus", principal_type="service", actor="agience-server-ophan",
        user_id=None,
    )
    try:
        with patch.object(auth_router.platform_settings, "get", return_value=None):
            resp = client.post("/internal/system-delegation", json={"purpose": "platform-mail"})
        assert resp.status_code == 409
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


# Origin has no secret-vault endpoints: material custody belongs to the service that owns the
# encrypted store.



def test_describe_delegation_admits_crystal_whose_describer_it_serves(client: TestClient, origin_app):
    """2026-10-18: Crystal, the only caller of this route, was refused by the platform-service
    guard, so no event-driven describe could run."""
    from origin.routers import auth_router
    from origin.services.dependencies import AuthContext, get_auth
    import origin.service_identity as ksi

    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="crystal", principal_type="service", user_id=None,
    )
    try:
        with patch.object(auth_router.platform_settings, "get", return_value="operator-1"), \
             patch.object(ksi, "get_system_principal_id", return_value="sys-principal-1"), \
             patch.object(auth_router, "origin_auth_service") as svc:
            svc.issue_system_delegation_token.return_value = "minted"
            resp = client.post("/internal/describe-delegation",
                               json={"persona_client_id": "agience-server-sage", "resource_id": "a"})
        assert resp.status_code == 200, resp.text
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def _subject(life=3600):
    """The verified claims of a forwarded person token with `life` seconds left."""
    import time
    from origin import config
    return {"sub": "user-123", "exp": time.time() + life, "aud": config.AUTHORITY_ISSUER}


def _narrowed(persona, life=3600, exp=None):
    """The verified claims of a delegation narrowed to `persona`: the only subject token the
    exchange takes (review 27)."""
    import time
    return {"sub": "user-123", "exp": exp if exp is not None else time.time() + life,
            "aud": persona, "principal_type": "delegation", "narrowed": True,
            "act": {"sub": persona}, "scope": f"persona:{persona}"}


@pytest.mark.parametrize("extra", [
    {"token_type": "refresh"},
    {"token_type": "password_reset"},
    {"principal_type": "mcp_client"},
    {"principal_type": "api_key"},
    {"api_key_id": "k-1"},
    {"aud": "third-party-client"},
    {"aud": None},
])
def test_only_a_person_s_own_access_token_for_origin_is_exchanged(client: TestClient, origin_app,
                                                                  extra):
    """A refresh or other single-purpose token, a non-person principal, or a token addressed to
    anyone but Origin is never turned into a person delegation."""
    from origin.routers import auth_router
    from origin.services.dependencies import get_auth

    claims = {**_subject(), **extra}
    if extra.get("aud", "x") is None:
        claims.pop("aud")
    _as_service(origin_app, "chorus")
    try:
        with patch.object(auth_router, "verify_token", return_value=claims),                 patch.object(auth_router, "origin_auth_service") as svc:
            svc.issue_delegation_token.return_value = "minted-jwt"
            resp = client.post("/internal/delegation-token", json={
                "server_client_id": "agience-server-sage", "subject_token": "t"})
        assert resp.status_code == 403, resp.text
        svc.issue_delegation_token.assert_not_called()
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


@pytest.mark.parametrize("asked,life,granted", [(300, 3600, 300), (86400, 3600, 600),
                                                 (600, 120, 120)])
def test_a_delegation_lives_ten_minutes_at_most_and_never_past_its_token(
        client: TestClient, origin_app, asked, life, granted):
    """Capped at ten minutes, and at what is left of the token it is exchanged for. Each is
    recorded by `jti` so it can be checked and revoked.

    The clock is frozen: what is left of the token is measured at one instant, so the answer is
    exact rather than a second either side of a boundary."""
    from datetime import datetime as _real_datetime, timezone as _tz

    from origin.db.session import SessionLocal
    from origin.models.key_custody import DelegationRecord
    from origin.routers import auth_router
    from origin.services.dependencies import get_auth

    instant = _real_datetime(2026, 11, 2, 12, 0, 0, tzinfo=_tz.utc)

    class _Frozen(_real_datetime):
        @classmethod
        def now(cls, tz=None):
            return instant if tz is not None else instant.replace(tzinfo=None)

    claims = _narrowed("sage", exp=instant.timestamp() + life)
    _as_service(origin_app, "sage")
    try:
        with patch.object(auth_router, "verify_token", return_value=claims), \
                patch.object(auth_router, "datetime", _Frozen), \
                patch.object(auth_router, "origin_auth_service") as svc:
            svc.issue_delegation_token.return_value = "minted-jwt"
            resp = client.post("/internal/delegation-token", json={
                "server_client_id": "agience-server-sage", "subject_token": "t",
                "ttl_seconds": asked})
        assert resp.status_code == 200, resp.text
        ttl = svc.issue_delegation_token.call_args.args[2]
        assert ttl == granted
        jti = svc.issue_delegation_token.call_args.kwargs["jti"]
        with SessionLocal() as db:
            assert db.get(DelegationRecord, jti).subject == "user-123"
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def test_no_delegation_outlives_an_expiring_token(client: TestClient, origin_app):
    from origin.routers import auth_router
    from origin.services.dependencies import get_auth

    _as_service(origin_app, "sage")
    try:
        with patch.object(auth_router, "verify_token", return_value=_narrowed("sage", -5)):
            resp = client.post("/internal/delegation-token", json={
                "server_client_id": "agience-server-sage", "subject_token": "t"})
        assert resp.status_code == 400
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


# ---------------------------------------------------------------------------
# Review 15, L2: a system delegation lives five minutes at most, and names only the personas,
# audiences and actors listed for its scope
# ---------------------------------------------------------------------------

def test_a_system_delegation_never_lives_past_five_minutes(monkeypatch):
    from jose import jwt as jose_jwt

    from origin.services import auth_service
    import origin.service_identity as ksi
    monkeypatch.setattr(ksi, "get_host_id", lambda: "host-1")
    tok = auth_service.issue_system_delegation_token("sys-1", actor="agience-server-iris",
                                                     scope="platform.email.send",
                                                     audience="mantle", ttl_seconds=86400)
    claims = jose_jwt.get_unverified_claims(tok)
    assert claims["exp"] - claims["iat"] <= 300


def _minted(origin_app, client, path, body, auth):
    from origin.routers import auth_router
    from origin.services.dependencies import get_auth
    import origin.service_identity as ksi
    origin_app.dependency_overrides[get_auth] = lambda: auth
    try:
        with patch.object(auth_router.platform_settings, "get", return_value="operator-1"), \
             patch.object(ksi, "get_system_principal_id", return_value="sys-principal-1"), \
             patch.object(auth_router, "origin_auth_service") as svc:
            svc.issue_system_delegation_token.return_value = "minted"
            return client.post(path, json=body), svc
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def test_a_describe_delegation_names_only_a_known_persona(client: TestClient, origin_app):
    from origin.services.dependencies import AuthContext
    crystal = AuthContext(principal_id="crystal", principal_type="service", user_id=None)
    r, _ = _minted(origin_app, client, "/internal/describe-delegation",
                   {"persona_client_id": "agience-server-nobody", "resource_id": "a"}, crystal)
    assert r.status_code == 403, r.text
    r, _ = _minted(origin_app, client, "/internal/describe-delegation",
                   {"persona_client_id": "mantle", "resource_id": "a"}, crystal)
    assert r.status_code == 403, r.text
    r, svc = _minted(origin_app, client, "/internal/describe-delegation",
                     {"persona_client_id": "agience-server-sage", "resource_id": "a",
                      "ttl_seconds": 86400}, crystal)
    assert r.status_code == 200, r.text
    assert svc.issue_system_delegation_token.call_args.kwargs["ttl_seconds"] <= 300


def test_a_system_delegation_goes_only_to_the_actors_listed_for_its_purpose(client: TestClient,
                                                                            origin_app):
    from origin.services.dependencies import AuthContext
    chorus_as = lambda actor: AuthContext(principal_id="chorus", principal_type="service",  # noqa: E731
                                          actor=actor, user_id=None)
    r, _ = _minted(origin_app, client, "/internal/system-delegation", {"purpose": "platform-mail"},
                   chorus_as("agience-server-mallory"))
    assert r.status_code == 403, r.text
    r, _ = _minted(origin_app, client, "/internal/system-delegation",
                   {"purpose": "platform-stripe"}, chorus_as("agience-server-iris"))
    assert r.status_code == 403, r.text
    r, svc = _minted(origin_app, client, "/internal/system-delegation",
                     {"purpose": "platform-stripe", "ttl_seconds": 86400},
                     chorus_as("agience-server-ophan"))
    assert r.status_code == 200, r.text
    assert svc.issue_system_delegation_token.call_args.kwargs["ttl_seconds"] <= 300


def test_a_system_delegation_s_actor_is_bound_to_the_caller_who_signed(client: TestClient,
                                                                         origin_app):
    """Review 16, I1: the actor comes from the authenticated caller, not from a claim it makes:
    Mantle asserting Ophan or Iris is refused; Chorus acting as Ophan is a pairing listed here."""
    from origin.services.dependencies import AuthContext
    as_ = lambda principal, actor: AuthContext(principal_id=principal,  # noqa: E731
                                               principal_type="service", actor=actor,
                                               user_id=None)
    for principal, actor, purpose in (("mantle", "agience-server-ophan", "platform-stripe"),
                                      ("mantle", "agience-server-iris", "platform-mail"),
                                      ("chorus", "agience-server-iris", "platform-mail")):
        r, _ = _minted(origin_app, client, "/internal/system-delegation", {"purpose": purpose},
                       as_(principal, actor))
        assert r.status_code == 403, (principal, actor, r.text)
    r, svc = _minted(origin_app, client, "/internal/system-delegation",
                     {"purpose": "platform-stripe"}, as_("chorus", "agience-server-ophan"))
    assert r.status_code == 200, r.text
    assert svc.issue_system_delegation_token.call_args.kwargs["actor"] == "agience-server-ophan"


def test_mantle_calls_no_delegation_exchange(client: TestClient, origin_app):
    """Review 21: the exchange's platform-server fallback is the chorus host's alone; Mantle,
    which `_require_platform_server` admits for the person reads, is refused here."""
    from origin.routers import auth_router
    from origin.services.dependencies import get_auth

    _as_service(origin_app, "mantle")
    try:
        with patch.object(auth_router, "verify_token", return_value=_subject()):
            resp = client.post("/internal/delegation-token", json={
                "server_client_id": "agience-server-sage", "subject_token": "t"})
        assert resp.status_code == 403
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def test_only_crystal_asks_a_describe_delegation(client: TestClient, origin_app):
    """Review 21: Mantle and the chorus host, though platform services, are refused."""
    from origin.services.dependencies import AuthContext, get_auth

    for name in ("mantle", "chorus"):
        origin_app.dependency_overrides[get_auth] = lambda n=name: AuthContext(
            principal_id=n, principal_type="service", user_id=None)
        try:
            resp = client.post("/internal/describe-delegation",
                               json={"persona_client_id": "agience-server-sage",
                                     "resource_id": "art-9"})
            assert resp.status_code == 403, name
        finally:
            origin_app.dependency_overrides.pop(get_auth, None)

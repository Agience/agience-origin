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

from unittest.mock import patch

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


def test_delegation_token_happy_path(client: TestClient, origin_app):
    # Override auth via FastAPI dependency_overrides so the platform-service
    # guard accepts our synthetic context.
    from origin.routers import auth_router
    from origin.services.dependencies import AuthContext, get_auth

    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="mantle",
        principal_type="service",
        user_id=None,
    )
    try:
        # Origin verifies the forwarded user token and derives sub=user-123.
        with patch.object(auth_router, "verify_token", return_value={"sub": "user-123"}), \
             patch.object(auth_router, "origin_auth_service") as svc:
            svc.issue_delegation_token.return_value = "minted-jwt"
            resp = client.post(
                "/internal/delegation-token",
                json={
                    "server_client_id": "agience-server-aria",
                    "subject_token": "user.jwt.forwarded",
                },
            )
        assert resp.status_code == 200
        assert resp.json() == {"token": "minted-jwt"}
        # Subject came from the VERIFIED token, not the request body.
        svc.issue_delegation_token.assert_called_once_with(
            "agience-server-aria", "user-123", 300
        )
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


def test_delegation_token_rejects_invalid_subject_token(client: TestClient, origin_app):
    """A subject_token that fails verification gets 401 — no delegation minted."""
    from origin.routers import auth_router
    from origin.services.dependencies import AuthContext, get_auth

    origin_app.dependency_overrides[get_auth] = lambda: AuthContext(
        principal_id="mantle", principal_type="service", user_id=None,
    )
    try:
        with patch.object(auth_router, "verify_token", return_value=None):
            resp = client.post(
                "/internal/delegation-token",
                json={"server_client_id": "agience-server-aria", "subject_token": "garbage"},
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
        principal_id="mantle", principal_type="service", user_id=None,
    )
    try:
        with patch.object(
            auth_router, "verify_token",
            return_value={"sub": "chorus", "principal_type": "service"},
        ):
            resp = client.post(
                "/internal/delegation-token",
                json={"server_client_id": "agience-server-aria", "subject_token": "svc.jwt"},
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
                "server_client_id": "agience-server-aria",
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
                "server_client_id": "agience-server-aria",
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
        principal_id="mantle",
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
                json={"persona_client_id": "agience-server-aria", "resource_id": "art-9"},
            )
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"token": "minted-describe-jwt", "subject_id": "sys-principal-1"}
        _, kwargs = svc.issue_system_delegation_token.call_args
        assert kwargs["actor"] == "agience-server-aria"
        assert kwargs["scope"] == "platform.describe"
        assert kwargs["audience"] == "agience-server-aria"
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
            json={"persona_client_id": "agience-server-aria", "resource_id": "art-9"},
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
                json={"persona_client_id": "agience-server-aria", "resource_id": "art-9"},
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
        principal_id="chorus", principal_type="service", user_id=None,
    )
    try:
        with patch.object(auth_router.platform_settings, "get", return_value=None):
            resp = client.post("/internal/system-delegation", json={"purpose": "platform-mail"})
        assert resp.status_code == 409
    finally:
        origin_app.dependency_overrides.pop(get_auth, None)


# Origin has no secret-vault endpoints: material custody belongs to the service that owns the
# encrypted store.


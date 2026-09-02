"""HTTP tests for `origin.routers.auth_router`.

Covers the most security-critical paths:

- `/auth/password/login` — credential check, dummy-verify on missing user
  (timing-safe), 401 on bad password, token shape on success.
- `/auth/password/register` — gate, validation, token issuance.
- `/auth/token` (client_credentials) — platform fast-path with
  PLATFORM_INTERNAL_SECRET, bad secret → 401, unknown client → 401.
- `/auth/token` (refresh_token) — missing field → 400.
- `/auth/userinfo` + `/me/preferences` — auth required, returns user
  data + roles, preferences round-trip.
- `/auth/nonce` — not a route; the tests pin that it stays absent.
- `/auth/providers` — provider listing.

OAuth `/authorize` and `/callback` are end-to-end browser redirects that
need extensive OIDC stubbing — out of scope for this fast unit suite.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from origin.routers.auth_router import _email_fingerprint, auth_router, internal_router, root_router
from origin.services import auth_service
from origin.services.dependencies import AuthContext, get_auth, get_person
from origin.db.session import get_db


def _make_app(auth: AuthContext, *, person: object | None = None) -> FastAPI:
    app = FastAPI()
    app.include_router(auth_router)
    app.include_router(root_router)
    app.include_router(internal_router)

    def _override_auth() -> AuthContext:
        return auth

    def _override_person():
        if person is None:
            from fastapi import HTTPException
            raise HTTPException(status_code=401, detail="User identification required")
        return person

    def _override_db():
        yield MagicMock()

    app.dependency_overrides[get_auth] = _override_auth
    app.dependency_overrides[get_person] = _override_person
    app.dependency_overrides[get_db] = _override_db
    return app


def _person(**overrides):
    base = dict(
        id=uuid.uuid4(),
        username="alice",
        email="alice@example.com",
        name="Alice",
        picture=None,
        password_hash="$2b$12$abcdefghijklmnopqrstuv",
        email_verified=True,
        preferences={},
        google_id=None,
        oidc_provider=None,
        oidc_subject=None,
        created_time=None,
        modified_time=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


# ---------------------------------------------------------------------------
# Password login
# ---------------------------------------------------------------------------

class TestPasswordLogin:
    @pytest.fixture
    def anon_client(self):
        return TestClient(_make_app(AuthContext()))

    def test_disabled_returns_404(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool",
            return_value=False,
        ):
            resp = anon_client.post(
                "/auth/password/login",
                json={"identifier": "alice", "password": "x"},
            )
        assert resp.status_code == 404

    def test_missing_fields_400(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool",
            return_value=True,
        ):
            resp = anon_client.post(
                "/auth/password/login",
                json={"identifier": "", "password": ""},
            )
        assert resp.status_code == 400

    def test_unknown_user_runs_dummy_verify_and_401s(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool",
            return_value=True,
        ), patch(
            "origin.routers.auth_router.person_service.get_user_by_username",
            return_value=None,
        ), patch(
            "origin.routers.auth_router.dummy_verify_password",
        ) as dummy:
            resp = anon_client.post(
                "/auth/password/login",
                json={"identifier": "ghost", "password": "x"},
            )
        # Constant-time check still runs even though user is missing.
        dummy.assert_called_once_with("x")
        assert resp.status_code == 401

    def test_bad_password_401(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool",
            return_value=True,
        ), patch(
            "origin.routers.auth_router.person_service.get_user_by_username",
            return_value=_person(),
        ), patch(
            "origin.routers.auth_router.verify_password",
            return_value=False,
        ):
            resp = anon_client.post(
                "/auth/password/login",
                json={"identifier": "alice", "password": "wrong"},
            )
        assert resp.status_code == 401

    def test_email_identifier_routes_to_email_lookup(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool",
            return_value=True,
        ), patch(
            "origin.routers.auth_router.person_service.get_user_by_email",
            return_value=_person(),
        ) as by_email, patch(
            "origin.routers.auth_router.person_service.get_user_by_username"
        ) as by_username, patch(
            "origin.routers.auth_router.verify_password",
            return_value=True,
        ), patch(
            "origin.routers.auth_router.create_jwt_token",
            return_value="mock.jwt.token",
        ), patch(
            "origin.routers.auth_router._compute_roles",
            return_value=[],
        ):
            resp = anon_client.post(
                "/auth/password/login",
                json={"identifier": "ALICE@EXAMPLE.COM", "password": "ok"},
            )
        assert resp.status_code == 200
        # Email lookup ran with lowercased email; username lookup didn't fire.
        by_email.assert_called_once_with(by_email.call_args.args[0], "alice@example.com")
        by_username.assert_not_called()

    def test_success_returns_access_and_refresh_tokens(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool",
            return_value=True,
        ), patch(
            "origin.routers.auth_router.person_service.get_user_by_username",
            return_value=_person(),
        ), patch(
            "origin.routers.auth_router.verify_password",
            return_value=True,
        ), patch(
            "origin.routers.auth_router.create_jwt_token",
            side_effect=["access.jwt", "refresh.jwt"],
        ), patch(
            "origin.routers.auth_router._compute_roles",
            return_value=["operator"],
        ):
            resp = anon_client.post(
                "/auth/password/login",
                json={"identifier": "alice", "password": "ok"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["token_type"] == "bearer"
        assert body["access_token"] == "access.jwt"
        assert body["refresh_token"] == "refresh.jwt"
        # The derived window, not a literal — see `test_access_token_lifetime.py`. Asserting the
        # number here would mean editing this file every time the derivation's bounds move.
        assert body["expires_in"] == auth_service.access_token_expires_in_seconds()


# ---------------------------------------------------------------------------
# Password register
# ---------------------------------------------------------------------------

class TestPasswordRegister:
    @pytest.fixture
    def anon_client(self):
        return TestClient(_make_app(AuthContext()))

    def test_disabled_returns_404(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool",
            return_value=False,
        ):
            resp = anon_client.post(
                "/auth/password/register",
                json={"username": "alice", "password": "p" * 12},
            )
        assert resp.status_code == 404

    def test_username_required(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool",
            return_value=True,
        ):
            resp = anon_client.post(
                "/auth/password/register",
                json={"username": "", "password": "p" * 12},
            )
        assert resp.status_code == 400

    def test_short_password_400(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool",
            return_value=True,
        ), patch(
            "origin.routers.auth_router.platform_settings.get_int",
            return_value=12,
        ):
            resp = anon_client.post(
                "/auth/password/register",
                json={"username": "alice", "password": "short"},
            )
        assert resp.status_code == 400
        assert "12 characters" in resp.json()["detail"]

    def test_invalid_email_400(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool",
            return_value=True,
        ), patch(
            "origin.routers.auth_router.platform_settings.get_int",
            return_value=12,
        ):
            resp = anon_client.post(
                "/auth/password/register",
                json={"username": "alice", "password": "p" * 12, "email": "noatsign"},
            )
        assert resp.status_code == 400

    def test_invite_only_blocks_registration(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool",
            return_value=True,
        ), patch(
            "origin.routers.auth_router.platform_settings.get_int",
            return_value=12,
        ), patch(
            "origin.routers.auth_router.hash_password",
            return_value="HASH",
        ), patch(
            "origin.routers.auth_router.person_service.create_user_with_password",
            side_effect=PermissionError("Registration is invite-only"),
        ):
            resp = anon_client.post(
                "/auth/password/register",
                json={"username": "alice", "password": "p" * 12},
            )
        assert resp.status_code == 403

    def test_value_error_collapses_to_400_without_leak(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool",
            return_value=True,
        ), patch(
            "origin.routers.auth_router.platform_settings.get_int",
            return_value=12,
        ), patch(
            "origin.routers.auth_router.hash_password",
            return_value="HASH",
        ), patch(
            "origin.routers.auth_router.person_service.create_user_with_password",
            side_effect=ValueError("Username already taken"),
        ):
            resp = anon_client.post(
                "/auth/password/register",
                json={"username": "alice", "password": "p" * 12},
            )
        assert resp.status_code == 400
        # Generic message — never leak whether the username/email exists.
        assert resp.json()["detail"] == "Registration failed"

    def test_success_returns_tokens(self, anon_client):
        person = _person()
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool",
            return_value=True,
        ), patch(
            "origin.routers.auth_router.platform_settings.get_int",
            return_value=12,
        ), patch(
            "origin.routers.auth_router.hash_password",
            return_value="HASH",
        ), patch(
            "origin.routers.auth_router.person_service.create_user_with_password",
            return_value=person,
        ), patch(
            "origin.routers.auth_router.create_jwt_token",
            side_effect=["access.jwt", "refresh.jwt"],
        ), patch(
            "origin.routers.auth_router._compute_roles",
            return_value=[],
        ):
            resp = anon_client.post(
                "/auth/password/register",
                json={"username": "alice", "password": "p" * 12, "email": "a@b.co"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["access_token"] == "access.jwt"
        assert body["refresh_token"] == "refresh.jwt"


# ---------------------------------------------------------------------------
# /auth/token — client_credentials (platform fast-path)
# ---------------------------------------------------------------------------

class TestTokenClientCredentials:
    @pytest.fixture
    def anon_client(self):
        return TestClient(_make_app(AuthContext()))

    def test_missing_fields_400(self, anon_client):
        resp = anon_client.post(
            "/auth/token",
            data={"grant_type": "client_credentials"},
        )
        assert resp.status_code == 400
        body = resp.json()
        assert body["error"] == "invalid_request"

    def test_unknown_client_returns_401(self, anon_client):
        # There is no platform fast-path in this phase. Unknown clients fall
        # through to the standard DB-backed OAuth client check, which returns 401.
        with patch(
            "origin.routers.auth_router.db_server_credentials.get_by_client_id",
            return_value=None,
        ):
            resp = anon_client.post(
                "/auth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": "unknown",
                    "client_secret": "x",
                },
            )
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_client"

    # There is no platform-server fast-path. Platform callers sign their own
    # JWTs with their own service key and do not ask Origin for tokens, so
    # there is no `client_credentials` exchange with `PLATFORM_INTERNAL_SECRET`
    # to test here; mutual JWT verification is the peer's own suite to cover.

    def test_unsupported_grant_type_400(self, anon_client):
        resp = anon_client.post(
            "/auth/token",
            data={"grant_type": "magic", "client_id": "x", "client_secret": "y"},
        )
        assert resp.status_code == 400

    def test_refresh_token_missing_field_400(self, anon_client):
        resp = anon_client.post(
            "/auth/token",
            data={"grant_type": "refresh_token"},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /userinfo + /me/preferences
# ---------------------------------------------------------------------------

class TestUserInfo:
    def test_userinfo_requires_auth(self):
        client = TestClient(_make_app(AuthContext()))
        resp = client.get("/auth/userinfo")
        assert resp.status_code == 401

    def test_userinfo_returns_user_payload(self):
        person = _person()
        auth = AuthContext(principal_id=str(person.id), principal_type="user", user_id=str(person.id))
        client = TestClient(_make_app(auth, person=person))
        with patch("origin.routers.auth_router._compute_roles", return_value=["operator"]):
            resp = client.get("/auth/userinfo")
        assert resp.status_code == 200
        body = resp.json()
        assert body["email"] == "alice@example.com"
        assert body["roles"] == ["operator"]
        assert "platform_user_id" in body


class TestPreferences:
    def test_get_returns_existing_prefs(self):
        person = _person(preferences={"theme": "dark"})
        auth = AuthContext(principal_id=str(person.id), principal_type="user", user_id=str(person.id))
        client = TestClient(_make_app(auth, person=person))
        resp = client.get("/auth/me/preferences")
        assert resp.status_code == 200
        assert resp.json() == {"theme": "dark"}

    def test_get_handles_null_prefs(self):
        person = _person(preferences=None)
        auth = AuthContext(principal_id=str(person.id), principal_type="user", user_id=str(person.id))
        client = TestClient(_make_app(auth, person=person))
        resp = client.get("/auth/me/preferences")
        assert resp.status_code == 200
        assert resp.json() == {}

    def test_patch_round_trips(self):
        person = _person(preferences={"theme": "dark"})
        updated = _person(preferences={"theme": "light", "lang": "en"})
        auth = AuthContext(principal_id=str(person.id), principal_type="user", user_id=str(person.id))
        client = TestClient(_make_app(auth, person=person))
        with patch(
            "origin.routers.auth_router.person_service.update_preferences",
            return_value=updated,
        ):
            resp = client.patch(
                "/auth/me/preferences",
                json={"theme": "light", "lang": "en"},
            )
        assert resp.status_code == 200
        assert resp.json() == {"theme": "light", "lang": "en"}


# ---------------------------------------------------------------------------
# /nonce — deleted, and stays deleted
# ---------------------------------------------------------------------------

class TestNonceIsGone:
    """`GET /auth/nonce` gated on a `principal_type` Origin cannot mint, so it always 403'd.

    There is no such route rather than a fixed one: the principal it wanted is an inbound API
    key, and Origin verifies no key and resolves no grant. Adding the route back without an issuer
    for that principal would restore an endpoint that answers nobody.
    """

    def test_the_route_is_not_registered(self):
        auth = AuthContext(principal_id="user-1", principal_type="user", user_id="user-1")
        app = _make_app(auth)
        assert "/auth/nonce" not in {getattr(r, "path", None) for r in app.routes}

    def test_the_route_does_not_answer(self):
        auth = AuthContext(principal_id="user-1", principal_type="user", user_id="user-1")
        client = TestClient(_make_app(auth))
        assert client.get("/auth/nonce").status_code == 404

    def test_resolve_auth_still_cannot_mint_the_principal_it_wanted(self):
        """The premise of the deletion, pinned.

        `resolve_auth` dispatches every JWT it accepts into one of five principal types, and
        `api_key` is not among them — so the guard the route opened with could never pass. If a
        future change starts emitting `api_key`, this fails and the deletion wants revisiting.
        """
        import inspect

        from origin.services import dependencies as _deps

        src = inspect.getsource(_deps.resolve_auth)
        assert 'principal_type="api_key"' not in src
        assert "'api_key'" not in src.replace('"api_key"', "")


# ---------------------------------------------------------------------------
# /providers
# ---------------------------------------------------------------------------

class TestProviders:
    def test_returns_registered_providers(self):
        client = TestClient(_make_app(AuthContext()))
        with patch.dict(
            "origin.routers.auth_router.REGISTERED_PROVIDERS",
            {"google": {"label": "Google"}, "microsoft": {"label": "Microsoft"}},
            clear=True,
        ), patch(
            "origin.routers.auth_router.platform_settings.get_bool",
            return_value=True,
        ):
            resp = client.get("/auth/providers")
        assert resp.status_code == 200
        body = resp.json()
        assert {p["name"] for p in body["providers"]} == {"google", "microsoft"}
        assert body["password"] is True
        assert "otp" in body


# ---------------------------------------------------------------------------
# Password reset (forgot-password)
# ---------------------------------------------------------------------------

class TestPasswordReset:
    @pytest.fixture
    def anon_client(self):
        return TestClient(_make_app(AuthContext()))

    def test_request_sends_when_user_has_password(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
        ), patch(
            "origin.routers.auth_router.email_service.is_configured", return_value=True,
        ), patch(
            "origin.routers.auth_router.person_service.get_user_by_email",
            return_value=_person(),
        ), patch(
            "origin.routers.auth_router.create_jwt_token", return_value="reset.jwt",
        ), patch(
            "origin.routers.auth_router.email_service.send_password_reset",
        ) as send:
            resp = anon_client.post(
                "/auth/password/reset-request", json={"email": "ALICE@example.com"},
            )
        assert resp.status_code == 200
        assert resp.json() == {"sent": True}
        # Reset email queued (TestClient runs background tasks before returning).
        send.assert_called_once()
        assert send.call_args.args[0] == "alice@example.com"
        assert "reset.jwt" in send.call_args.args[1]

    def test_request_silent_for_unknown_email(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
        ), patch(
            "origin.routers.auth_router.email_service.is_configured", return_value=True,
        ), patch(
            "origin.routers.auth_router.person_service.get_user_by_email",
            return_value=None,
        ), patch(
            "origin.routers.auth_router.email_service.send_password_reset",
        ) as send:
            resp = anon_client.post(
                "/auth/password/reset-request", json={"email": "ghost@example.com"},
            )
        # Same 200 — never reveal whether the account exists; no email sent.
        assert resp.status_code == 200
        assert resp.json() == {"sent": True}
        send.assert_not_called()

    def test_request_silent_for_passwordless_account(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
        ), patch(
            "origin.routers.auth_router.email_service.is_configured", return_value=True,
        ), patch(
            "origin.routers.auth_router.person_service.get_user_by_email",
            return_value=_person(password_hash=None),
        ), patch(
            "origin.routers.auth_router.email_service.send_password_reset",
        ) as send:
            resp = anon_client.post(
                "/auth/password/reset-request", json={"email": "alice@example.com"},
            )
        assert resp.status_code == 200
        send.assert_not_called()

    def test_request_503_when_email_unconfigured(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
        ), patch(
            "origin.routers.auth_router.email_service.is_configured", return_value=False,
        ):
            resp = anon_client.post(
                "/auth/password/reset-request", json={"email": "alice@example.com"},
            )
        assert resp.status_code == 503

    def test_confirm_sets_password_on_valid_token(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
        ), patch(
            "origin.routers.auth_router.platform_settings.get_int", return_value=12,
        ), patch(
            "origin.routers.auth_router.verify_token",
            return_value={"token_type": "pwd_reset", "sub": "person-1", "pwf": "fp"},
        ), patch(
            "origin.routers.auth_router._pw_fingerprint", return_value="fp",
        ), patch(
            "origin.routers.auth_router.person_service.get_user_by_id",
            return_value=_person(id="person-1"),
        ), patch(
            "origin.routers.auth_router.hash_password", return_value="hashed-pw",
        ), patch(
            "origin.routers.auth_router.person_service.set_password",
        ) as set_pw:
            resp = anon_client.post(
                "/auth/password/reset-confirm",
                json={"token": "reset.jwt", "new_password": "a-long-enough-password"},
            )
        assert resp.status_code == 200
        assert resp.json() == {"reset": True}
        set_pw.assert_called_once()
        assert set_pw.call_args.args[1] == "person-1"
        assert set_pw.call_args.args[2] == "hashed-pw"

    def test_confirm_rejects_reused_token(self, anon_client):
        """A token whose embedded fingerprint no longer matches the current hash
        (already used, or password changed) is rejected — single-use."""
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
        ), patch(
            "origin.routers.auth_router.platform_settings.get_int", return_value=12,
        ), patch(
            "origin.routers.auth_router.verify_token",
            return_value={"token_type": "pwd_reset", "sub": "person-1", "pwf": "stale"},
        ), patch(
            "origin.routers.auth_router._pw_fingerprint", return_value="current",
        ), patch(
            "origin.routers.auth_router.person_service.get_user_by_id",
            return_value=_person(id="person-1"),
        ), patch(
            "origin.routers.auth_router.person_service.set_password",
        ) as set_pw:
            resp = anon_client.post(
                "/auth/password/reset-confirm",
                json={"token": "reused.jwt", "new_password": "a-long-enough-password"},
            )
        assert resp.status_code == 400
        set_pw.assert_not_called()

    def test_confirm_rejects_non_reset_token(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
        ), patch(
            "origin.routers.auth_router.verify_token",
            return_value={"token_type": "refresh", "sub": "person-1"},
        ), patch(
            "origin.routers.auth_router.person_service.set_password",
        ) as set_pw:
            resp = anon_client.post(
                "/auth/password/reset-confirm",
                json={"token": "wrong.jwt", "new_password": "a-long-enough-password"},
            )
        assert resp.status_code == 400
        set_pw.assert_not_called()

    def test_confirm_rejects_invalid_token(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
        ), patch(
            "origin.routers.auth_router.verify_token", return_value=None,
        ), patch(
            "origin.routers.auth_router.person_service.set_password",
        ) as set_pw:
            resp = anon_client.post(
                "/auth/password/reset-confirm",
                json={"token": "expired.jwt", "new_password": "a-long-enough-password"},
            )
        assert resp.status_code == 400
        set_pw.assert_not_called()

    def test_confirm_enforces_min_length(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
        ), patch(
            "origin.routers.auth_router.platform_settings.get_int", return_value=12,
        ), patch(
            "origin.routers.auth_router.verify_token",
            return_value={"token_type": "pwd_reset", "sub": "person-1"},
        ), patch(
            "origin.routers.auth_router.person_service.set_password",
        ) as set_pw:
            resp = anon_client.post(
                "/auth/password/reset-confirm",
                json={"token": "reset.jwt", "new_password": "short"},
            )
        assert resp.status_code == 400
        set_pw.assert_not_called()


# ---------------------------------------------------------------------------
# Email verification
# ---------------------------------------------------------------------------

class TestEmailVerification:
    @pytest.fixture
    def anon_client(self):
        return TestClient(_make_app(AuthContext()))

    def test_register_requires_verification(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
        ), patch(
            "origin.routers.auth_router.platform_settings.get_int", return_value=12,
        ), patch(
            "origin.routers.auth_router.email_verification_required", return_value=True,
        ), patch(
            "origin.routers.auth_router.person_service.create_user_with_password",
            return_value=_person(email_verified=False),
        ), patch(
            "origin.routers.auth_router.create_jwt_token", return_value="verify.jwt",
        ), patch(
            "origin.routers.auth_router.email_service.send_email_verification",
        ) as send:
            resp = anon_client.post(
                "/auth/password/register",
                json={"username": "bob", "password": "a-long-enough-pw", "email": "bob@example.com"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["verification_required"] is True
        assert "access_token" not in body
        send.assert_called_once()

    def test_register_without_verification_returns_tokens(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
        ), patch(
            "origin.routers.auth_router.platform_settings.get_int", return_value=12,
        ), patch(
            "origin.routers.auth_router.email_verification_required", return_value=False,
        ), patch(
            "origin.routers.auth_router.person_service.create_user_with_password",
            return_value=_person(),
        ), patch(
            "origin.routers.auth_router.create_jwt_token", side_effect=["access.jwt", "refresh.jwt"],
        ), patch(
            "origin.routers.auth_router.person_service.record_person_event",
        ), patch(
            "origin.routers.auth_router._compute_roles", return_value=[],
        ):
            resp = anon_client.post(
                "/auth/password/register",
                json={"username": "bob", "password": "a-long-enough-pw", "email": "bob@example.com"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["access_token"] == "access.jwt"
        assert "verification_required" not in body

    def test_login_blocked_when_unverified(self, anon_client):
        with patch(
            "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
        ), patch(
            "origin.routers.auth_router.person_service.get_user_by_email",
            return_value=_person(email_verified=False),
        ), patch(
            "origin.routers.auth_router.verify_password", return_value=True,
        ), patch(
            "origin.routers.auth_router.email_verification_required", return_value=True,
        ), patch(
            "origin.routers.auth_router.create_jwt_token", return_value="verify.jwt",
        ), patch(
            "origin.routers.auth_router.email_service.send_email_verification",
        ) as send:
            resp = anon_client.post(
                "/auth/password/login",
                json={"identifier": "alice@example.com", "password": "ok"},
            )
        assert resp.status_code == 403
        send.assert_called_once()

    def test_verify_confirm_marks_verified_and_returns_tokens(self, anon_client):
        # The link is minted for an account that has NOT verified yet — which is the only state a
        # real verification link is ever minted in, and the state its `evf` fingerprint binds.
        unverified = _person(id="person-1", email_verified=False)
        with patch(
            "origin.routers.auth_router.verify_token",
            return_value={
                "token_type": "email_verify",
                "sub": "person-1",
                "evf": _email_fingerprint(unverified),
            },
        ), patch(
            "origin.routers.auth_router.person_service.get_user_by_id",
            return_value=unverified,
        ), patch(
            "origin.routers.auth_router.person_service.set_email_verified",
        ) as setv, patch(
            "origin.routers.auth_router.create_jwt_token", side_effect=["access.jwt", "refresh.jwt"],
        ), patch(
            "origin.routers.auth_router.person_service.record_person_event",
        ), patch(
            "origin.routers.auth_router._compute_roles", return_value=[],
        ):
            resp = anon_client.post("/auth/email/verify-confirm", json={"token": "verify.jwt"})
        assert resp.status_code == 200
        assert resp.json()["access_token"] == "access.jwt"
        setv.assert_called_once()
        assert setv.call_args.args[1] == "person-1"

    def test_verify_confirm_rejects_a_replayed_link(self, anon_client):
        """The same token, presented a second time, is refused.

        The token is unchanged and still unexpired — what changed is the account, which is now
        verified, so the `evf` fingerprint minted against the unverified state no longer matches.
        Without this the link stays redeemable for its full 24 hours, and `verify-email.html`
        redeems it on page load without anyone clicking anything.
        """
        minted_against = _person(id="person-1", email_verified=False)
        already_redeemed = _person(id="person-1", email_verified=True)
        with patch(
            "origin.routers.auth_router.verify_token",
            return_value={
                "token_type": "email_verify",
                "sub": "person-1",
                "evf": _email_fingerprint(minted_against),
            },
        ), patch(
            "origin.routers.auth_router.person_service.get_user_by_id",
            return_value=already_redeemed,
        ), patch(
            "origin.routers.auth_router.person_service.set_email_verified",
        ) as setv:
            resp = anon_client.post("/auth/email/verify-confirm", json={"token": "verify.jwt"})

        assert resp.status_code == 400
        setv.assert_not_called()
        assert "access_token" not in resp.json(), (
            "a replayed verification link must not mint a fresh 30-day refresh token"
        )

    def test_verify_confirm_rejects_a_link_minted_for_a_different_address(self, anon_client):
        """Changing the email address kills links outstanding against the old one.

        Same reason the reset fingerprint covers any password change and not only this reset: the
        link proves control of the mailbox it was sent to, and after a change that is not the
        mailbox on the account.
        """
        old_address = _person(id="person-1", email="alice@example.com", email_verified=False)
        new_address = _person(id="person-1", email="alice@newmail.test", email_verified=False)
        with patch(
            "origin.routers.auth_router.verify_token",
            return_value={
                "token_type": "email_verify",
                "sub": "person-1",
                "evf": _email_fingerprint(old_address),
            },
        ), patch(
            "origin.routers.auth_router.person_service.get_user_by_id",
            return_value=new_address,
        ), patch(
            "origin.routers.auth_router.person_service.set_email_verified",
        ) as setv:
            resp = anon_client.post("/auth/email/verify-confirm", json={"token": "verify.jwt"})

        assert resp.status_code == 400
        setv.assert_not_called()

    def test_verify_confirm_rejects_a_token_carrying_no_fingerprint(self, anon_client):
        """Fail closed on a missing claim.

        Tokens minted before `evf` existed are refused rather than admitted by a
        backwards-compatible fallback — a fallback here would be a permanent bypass of the
        single-use property, kept alive to serve at most one day of outstanding links, and
        `verify-email.html` already offers the resend form on any failure.
        """
        with patch(
            "origin.routers.auth_router.verify_token",
            return_value={"token_type": "email_verify", "sub": "person-1"},
        ), patch(
            "origin.routers.auth_router.person_service.get_user_by_id",
            return_value=_person(id="person-1", email_verified=False),
        ), patch(
            "origin.routers.auth_router.person_service.set_email_verified",
        ) as setv:
            resp = anon_client.post("/auth/email/verify-confirm", json={"token": "verify.jwt"})

        assert resp.status_code == 400
        setv.assert_not_called()

    def test_verify_confirm_rejects_wrong_token_type(self, anon_client):
        with patch(
            "origin.routers.auth_router.verify_token",
            return_value={"token_type": "pwd_reset", "sub": "x"},
        ), patch(
            "origin.routers.auth_router.person_service.set_email_verified",
        ) as setv:
            resp = anon_client.post("/auth/email/verify-confirm", json={"token": "x"})
        assert resp.status_code == 400
        setv.assert_not_called()

    def test_verify_request_resends_when_unverified(self, anon_client):
        with patch(
            "origin.routers.auth_router.email_service.is_configured", return_value=True,
        ), patch(
            "origin.routers.auth_router.person_service.get_user_by_email",
            return_value=_person(email_verified=False),
        ), patch(
            "origin.routers.auth_router.create_jwt_token", return_value="verify.jwt",
        ), patch(
            "origin.routers.auth_router.email_service.send_email_verification",
        ) as send:
            resp = anon_client.post("/auth/email/verify-request", json={"email": "alice@example.com"})
        assert resp.status_code == 200
        send.assert_called_once()

    def test_verify_request_noop_when_already_verified(self, anon_client):
        with patch(
            "origin.routers.auth_router.email_service.is_configured", return_value=True,
        ), patch(
            "origin.routers.auth_router.person_service.get_user_by_email",
            return_value=_person(email_verified=True),
        ), patch(
            "origin.routers.auth_router.email_service.send_email_verification",
        ) as send:
            resp = anon_client.post("/auth/email/verify-request", json={"email": "alice@example.com"})
        assert resp.status_code == 200
        send.assert_not_called()


class TestEmailVerificationRequiredHelper:
    """Unit coverage for the config-driven email_verification_required gate."""

    def _set(self, monkeypatch, *, enabled, allowlist):
        from origin.services import auth_service
        monkeypatch.setattr(auth_service.config, "EMAIL_VERIFICATION_ENABLED", enabled, raising=False)
        monkeypatch.setattr(auth_service.config, "EMAIL_VERIFICATION_ALLOWLIST", allowlist, raising=False)
        return auth_service

    def test_disabled_returns_false(self, monkeypatch):
        svc = self._set(monkeypatch, enabled=False, allowlist=[])
        assert svc.email_verification_required("a@b.com") is False

    def test_enabled_no_allowlist_requires(self, monkeypatch):
        svc = self._set(monkeypatch, enabled=True, allowlist=[])
        assert svc.email_verification_required("a@b.com") is True

    def test_allowlisted_email_skips(self, monkeypatch):
        svc = self._set(monkeypatch, enabled=True, allowlist=["a@b.com"])
        assert svc.email_verification_required("A@B.com") is False

    def test_allowlisted_domain_skips(self, monkeypatch):
        svc = self._set(monkeypatch, enabled=True, allowlist=["b.com"])
        assert svc.email_verification_required("x@b.com") is False

    def test_non_allowlisted_requires(self, monkeypatch):
        svc = self._set(monkeypatch, enabled=True, allowlist=["b.com"])
        assert svc.email_verification_required("x@evil.com") is True

    def test_no_email_not_required(self, monkeypatch):
        svc = self._set(monkeypatch, enabled=True, allowlist=[])
        assert svc.email_verification_required(None) is False
        assert svc.email_verification_required("not-an-email") is False

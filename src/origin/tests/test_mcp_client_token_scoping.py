"""Which token an OAuth client gets, and the rule that only a named client gets the user's.

First-party is a configured fact and nothing else: `PLATFORM_CLIENT_ID` plus whatever
`PLATFORM_CLIENT_IDS` enrols. The `oauth_clients` registry that `POST /auth/register` writes is not
consulted here — a client that vouched for itself is third party. Everything else receives the
scoped `mcp_client` token — no email, no name, no picture, no roles, and `aud` set to the client
rather than to this authority.

The negative controls carry the weight. A predicate that answered "first party" to everything
would satisfy the first-party tests alone, and the scoped branch is now the default path rather
than a branch nothing reaches, so it is pinned on what it emits and not merely on being taken.
The first-party controls assert the flow crosses no service boundary at all: the transport is
severed for the whole request, so any outbound HTTP — to Mantle or anywhere else — fails the test.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------
@pytest.fixture
def db_client(origin_app):
    """A client whose in-memory SQLite actually has tables.

    Mirrors `test_authorize_local_methods.db_client`: `conftest.origin_app` skips migrations, so
    the schema is built from the models after lifespan has created the engine.
    """
    from fastapi.testclient import TestClient

    with TestClient(origin_app) as c:
        from origin.db.base import Base
        from origin.db.session import get_engine

        Base.metadata.create_all(get_engine())
        yield c


@pytest.fixture
def no_outbound_http(monkeypatch):
    """Sever real network transport for the duration of a test.

    `TestClient` drives the app over an in-process ASGI transport, so only calls that would leave
    this process land here. Nothing in a first-party sign-in may.
    """
    import httpx

    def _refuse(*_args, **_kwargs):
        raise AssertionError("a first-party sign-in must make no outbound HTTP call")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", _refuse)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", _refuse)


@pytest.fixture
def auth_router_module(origin_app):
    """The reloaded `auth_router` the app's routes are bound to."""
    import origin.routers.auth_router as ar

    return ar


PERSON_EMAIL = "person@example.com"
PERSON_NAME = "Test Person"


def _seed_code(auth_router_module, *, client_id, code="test-code", scope="read write"):
    """Put a spent-once authorization code in place, as the OAuth callback would."""
    auth_router_module.authorization_codes[code] = {
        "user_info": {
            "provider": "google",
            "sub": f"sub-for-{client_id}",
            "email": PERSON_EMAIL,
            "name": PERSON_NAME,
            "picture": "https://example.invalid/avatar.png",
            "email_verified": True,
        },
        "client_id": client_id,
        "redirect_uri": "http://localhost:8080/cb",
        "scope": scope,
        "code_challenge": None,
        "code_challenge_method": "S256",
        "timestamp": datetime.now(timezone.utc),
    }
    return code


def _exchange(client, *, code, client_id):
    return client.post(
        "/auth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:8080/cb",
            "client_id": client_id,
            "code_verifier": "v" * 64,
        },
    )


def _refresh(client, *, refresh_token):
    return client.post(
        "/auth/token",
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
    )


def _claims(token):
    import base64
    import json

    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _assert_pii_free(claims):
    """No identity attribute, under any claim name, and no role."""
    for claim in ("email", "name", "picture", "roles"):
        assert claim not in claims, f"{claim} leaked into a scoped mcp_client token"
    for value in claims.values():
        assert value not in (PERSON_EMAIL, PERSON_NAME)


# ---------------------------------------------------------------------------
# `/auth/authorize` — the redirect_uri gate
# ---------------------------------------------------------------------------
def _authorize(client, *, client_id, redirect_uri="http://localhost:8080/cb"):
    return client.get(
        "/auth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "state": "st",
        },
    )


def test_authorize_does_not_leave_this_process_for_the_platform_client(
    db_client, no_outbound_http
):
    """The first-party control. This node's own sign-in reaches the login page with no service
    other than Origin running, reachable, or consulted."""
    from origin import config

    resp = _authorize(db_client, client_id=config.PLATFORM_CLIENT_ID)
    assert resp.status_code == 200


def test_authorize_admits_a_registered_client_and_still_scopes_its_token(db_client, monkeypatch):
    """Admission and trust are different questions. A client that enrolled itself reaches the login
    page — and is still third party at the token, which is what the rest of this file pins.

    Written against a registered client rather than an arbitrary string because `/authorize` now
    refuses ids that are neither configured nor registered; the scoping claim is unchanged and is
    what this asserts."""
    from origin import config

    monkeypatch.setattr(config, "CLIENT_REGISTRATION_ENABLED", True)
    monkeypatch.setattr(config, "CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN", "")
    registered = db_client.post(
        "/auth/register", json={"redirect_uris": ["http://localhost:8080/cb"]}
    ).json()["client_id"]

    resp = _authorize(db_client, client_id=registered)
    assert resp.status_code == 200

    import origin.routers.auth_router as ar

    assert ar._is_first_party_client(registered) is False


def test_authorize_refuses_a_redirect_base_this_authority_does_not_admit(db_client):
    """The allowlist is the outer bound on delivery, and it holds for every client — here for a
    configured first-party one, which has no registration to be bound by instead."""
    from origin import config

    resp = _authorize(
        db_client, client_id=config.PLATFORM_CLIENT_ID, redirect_uri="https://evil.example/cb"
    )
    assert resp.status_code == 403
    # The operator reading this must be told where to look; an "Invalid redirect_uri" alone
    # cannot distinguish an unlisted facet from a first-party client nobody enrolled.
    detail = resp.json()["detail"]
    assert "PLATFORM_CLIENT_IDS" in detail
    assert "FACET_URIS" in detail


# ---------------------------------------------------------------------------
# `/auth/token` (authorization_code) — which token gets minted
# ---------------------------------------------------------------------------
def test_token_mints_the_full_user_jwt_for_the_platform_client(
    db_client, auth_router_module, no_outbound_http
):
    """The first-party control — the flow this change must not lock out, and which must stay
    independent of every other service."""
    from origin import config

    code = _seed_code(auth_router_module, client_id=config.PLATFORM_CLIENT_ID)
    resp = _exchange(db_client, code=code, client_id=config.PLATFORM_CLIENT_ID)
    assert resp.status_code == 200

    claims = _claims(resp.json()["access_token"])
    assert claims["email"] == PERSON_EMAIL
    assert claims["client_id"] == config.PLATFORM_CLIENT_ID
    assert claims["aud"] == config.AUTHORITY_ISSUER
    assert "principal_type" not in claims


def test_token_mints_the_full_user_jwt_for_a_client_enrolled_as_first_party(
    db_client, auth_router_module, monkeypatch
):
    """Mantle's browser client reads its own `MANTLE_OIDC_CLIENT_ID`, which has no default and
    need not equal `PLATFORM_CLIENT_ID`. Enrolling it is what keeps that sign-in whole."""
    from origin import config

    monkeypatch.setattr(config, "PLATFORM_CLIENT_IDS", ["mantle-browser"])

    code = _seed_code(auth_router_module, client_id="mantle-browser")
    resp = _exchange(db_client, code=code, client_id="mantle-browser")
    assert resp.status_code == 200

    claims = _claims(resp.json()["access_token"])
    assert claims["email"] == PERSON_EMAIL
    assert claims["client_id"] == "mantle-browser"
    assert "principal_type" not in claims


def test_an_operator_set_string_is_not_iterated_as_characters(db_client, auth_router_module, monkeypatch):
    """`PLATFORM_CLIENT_IDS=a,b` set by hand arrives as one string; splitting it is what makes
    membership mean ids rather than letters."""
    from origin import config

    monkeypatch.setattr(config, "PLATFORM_CLIENT_IDS", "mantle-browser, other-client")

    assert auth_router_module._is_first_party_client("other-client") is True
    assert auth_router_module._is_first_party_client("m") is False


def test_token_mints_a_scoped_pii_free_token_for_an_unknown_client(
    db_client, auth_router_module
):
    """The default path for everything nobody enrolled — pinned on what it emits."""
    code = _seed_code(auth_router_module, client_id="some-third-party", scope="read write")
    resp = _exchange(db_client, code=code, client_id="some-third-party")
    assert resp.status_code == 200

    body = resp.json()
    claims = _claims(body["access_token"])
    assert claims["principal_type"] == "mcp_client"
    assert claims["aud"] == "some-third-party"
    assert claims["scopes"] == ["read", "write"]
    assert claims["sub"]
    _assert_pii_free(claims)

    # The refresh token is minted from the same payload and lives thirty days — a leak there
    # outlives the access token by a month.
    _assert_pii_free(_claims(body["refresh_token"]))


def test_refreshing_a_scoped_token_does_not_acquire_the_users_roles(
    db_client, auth_router_module, monkeypatch
):
    """`sub` is present in the scoped token, so re-deriving roles from it on refresh would hand a
    third-party client the operator's `platform:admin` — the PII-free token growing authority it
    was never minted with."""
    monkeypatch.setattr(auth_router_module, "_compute_roles", lambda _uid: ["platform:admin"])

    code = _seed_code(auth_router_module, client_id="some-third-party")
    granted = _exchange(db_client, code=code, client_id="some-third-party").json()

    resp = _refresh(db_client, refresh_token=granted["refresh_token"])
    assert resp.status_code == 200
    claims = _claims(resp.json()["access_token"])
    assert claims["principal_type"] == "mcp_client"
    _assert_pii_free(claims)


# ---------------------------------------------------------------------------
# The scoping has to hold at the resource, not only in the claims
# ---------------------------------------------------------------------------
# Minting a PII-free token is half a guarantee. `resolve_auth` populates `user_id` from `sub` for an
# `mcp_client` token — `sub` is what makes the token delegable — so every route behind `get_person`
# accepted it, and `/auth/userinfo` served the very email, name and roles the mint path had just
# stripped. The omission was cosmetic: one more request undid it.
def _userinfo(client, token):
    return client.get("/auth/userinfo", headers={"Authorization": f"Bearer {token}"})


def _scoped_token(db_client, auth_router_module, *, scope="read write"):
    code = _seed_code(auth_router_module, client_id="some-third-party", scope=scope)
    return _exchange(db_client, code=code, client_id="some-third-party").json()["access_token"]


def test_userinfo_refuses_a_scoped_mcp_client_token(db_client, auth_router_module):
    """The whole point of the scoped token, enforced where the data actually lives."""
    resp = _userinfo(db_client, _scoped_token(db_client, auth_router_module))
    assert resp.status_code == 403


def test_userinfo_leaks_nothing_in_the_refusal(db_client, auth_router_module):
    """A 403 whose body carries the email would be the same leak with a different status."""
    resp = _userinfo(db_client, _scoped_token(db_client, auth_router_module))
    body = resp.text
    assert PERSON_EMAIL not in body
    assert PERSON_NAME not in body


def test_asking_for_the_email_scope_does_not_license_the_email(db_client, auth_router_module):
    """`scopes` records what the client asked for, and nothing vouched for the client — there is no
    consent step in this authority. If the claim gated the response, a client would license its own
    access to the mailbox by naming the scope it wants."""
    token = _scoped_token(db_client, auth_router_module, scope="openid email profile")
    assert _claims(token)["scopes"] == ["email", "openid", "profile"]

    resp = _userinfo(db_client, token)
    assert resp.status_code == 403
    assert PERSON_EMAIL not in resp.text


def test_the_scoped_token_cannot_read_or_write_preferences(db_client, auth_router_module):
    """`get_person` is the choke point, so the fix has to cover the account-mutating routes behind
    it too — not `/auth/userinfo` alone. A third-party client rewriting the user's preferences is
    the same defect with a verb."""
    token = _scoped_token(db_client, auth_router_module)
    headers = {"Authorization": f"Bearer {token}"}
    assert db_client.get("/auth/me/preferences", headers=headers).status_code == 403
    assert db_client.patch(
        "/auth/me/preferences", headers=headers, json={"theme": "dark"}
    ).status_code == 403


def test_userinfo_still_serves_the_full_user_token(
    db_client, auth_router_module, no_outbound_http
):
    """The control that matters most: the first-party sign-in this must not touch. A refusal that
    also caught the user's own token would be a broken account page, not a fix."""
    from origin import config

    code = _seed_code(auth_router_module, client_id=config.PLATFORM_CLIENT_ID)
    token = _exchange(
        db_client, code=code, client_id=config.PLATFORM_CLIENT_ID
    ).json()["access_token"]

    resp = _userinfo(db_client, token)
    assert resp.status_code == 200
    body = resp.json()
    assert body["email"] == PERSON_EMAIL
    assert body["name"] == PERSON_NAME
    assert "roles" in body
    assert "platform_user_id" in body


def test_refreshing_a_first_party_token_still_re_derives_roles(
    db_client, auth_router_module, monkeypatch
):
    """The control for the rule above: role re-derivation on refresh is what stops a demoted
    operator keeping `platform:admin` for a month, and it must survive for user tokens."""
    from origin import config

    monkeypatch.setattr(auth_router_module, "_compute_roles", lambda _uid: ["platform:admin"])

    code = _seed_code(auth_router_module, client_id=config.PLATFORM_CLIENT_ID)
    granted = _exchange(db_client, code=code, client_id=config.PLATFORM_CLIENT_ID).json()

    resp = _refresh(db_client, refresh_token=granted["refresh_token"])
    assert resp.status_code == 200
    assert _claims(resp.json()["access_token"])["roles"] == ["platform:admin"]

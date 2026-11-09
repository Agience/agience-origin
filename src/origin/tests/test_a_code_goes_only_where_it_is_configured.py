"""A sign-in's code goes only to a redirect URI configured for that client, and only with PKCE.

The rule (RFC 9700 §2.1, §4.1): no redirect target exists in code. A first-party client may be
delivered a code only at a URI listed for it in `CLIENT_REDIRECT_URIS`; a registered client only at
a URI in its own registration, which `CLIENT_REGISTRATION_REDIRECT_URIS` bounded. Every comparison
is the whole string. The one variation is RFC 8252 §7.3's: a listed http loopback URI admits any
port. Every `/authorize` refusal is a 403 naming the setting to change.

Every flow carries PKCE with S256; a code is single-use, short-lived, and redeemed only with the
exact redirect URI it was issued for.

Imports are function-local: `origin_app` reloads `origin.config`, so a module-level import would
bind to a module the running app no longer reads.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from origin.tests.conftest import PKCE, PKCE_CHALLENGE, PKCE_VERIFIER

#: Production's redirect URIs, per client (agience-cloud `settings/prod.toml`).
PROD = {
    "platform": ["https://my.agience.ai/auth/callback", "https://origin.agience.ai/",
                 "https://origin.agience.ai/passkey"],
    "agience-client": ["https://origin.agience.ai/auth/reauth/complete"],
}
APP_CB = PROD["platform"][0]


@pytest.fixture
def db_client(origin_app):
    from fastapi.testclient import TestClient

    with TestClient(origin_app, follow_redirects=False) as c:
        from origin.db.base import Base
        from origin.db.session import get_engine

        Base.metadata.create_all(get_engine())
        yield c


@pytest.fixture
def production(monkeypatch):
    """Production's settings: its four URIs, its first-party ids, Mantle's address."""
    from origin import config

    monkeypatch.setattr(config, "CLIENT_REDIRECT_URIS", {k: list(v) for k, v in PROD.items()},
                        raising=False)
    monkeypatch.setattr(config, "CLIENT_REGISTRATION_REDIRECT_URIS", [], raising=False)
    monkeypatch.setattr(config, "PLATFORM_CLIENT_ID", "agience-client")
    monkeypatch.setattr(config, "PLATFORM_CLIENT_IDS", ["platform"])
    monkeypatch.setattr(config, "MANTLE_URI", "https://mantle.agience.ai", raising=False)
    monkeypatch.setattr(config, "ORIGIN_URI", "https://origin.agience.ai", raising=False)
    monkeypatch.setattr(config, "APP_URI", "https://my.agience.ai", raising=False)


def _authorize(client, *, client_id="platform", redirect_uri=APP_CB, pkce=PKCE, **extra):
    params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
              "scope": "openid email profile", "state": "st", **pkce, **extra}
    return client.get("/auth/authorize", params=params)


# ---------------------------------------------------------------------------
# Production's callbacks: before and after
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("client_id,uri", [(c, u) for c, us in PROD.items() for u in us])
def test_each_production_callback_is_admitted_for_its_own_client(db_client, production,
                                                                 client_id, uri):
    assert _authorize(db_client, client_id=client_id, redirect_uri=uri).status_code == 200


@pytest.mark.parametrize("client_id,uri", [
    ("agience-client", APP_CB),
    ("platform", "https://origin.agience.ai/auth/reauth/complete"),
])
def test_a_production_callback_is_not_admitted_for_the_other_client(db_client, production,
                                                                    client_id, uri):
    resp = _authorize(db_client, client_id=client_id, redirect_uri=uri)
    assert resp.status_code == 403
    assert "CLIENT_REDIRECT_URIS" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Refused shapes, every one unless configured
# ---------------------------------------------------------------------------
REFUSED = [
    # An unlisted host.
    "https://evil.example/auth/callback",
    # A listed host, another path.
    "https://my.agience.ai/auth/other", "https://my.agience.ai/", "https://my.agience.ai/callback",
    # Prefix and suffix tricks.
    "https://my.agience.ai.evil.example/auth/callback",
    "https://evil-my.agience.ai/auth/callback",
    "https://my.agience.ai/auth/callback/../../evil",
    "https://my.agience.ai/auth/callback/extra",
    "https://my.agience.ai/auth/callback?next=https://evil.example",
    "https://my.agience.ai/auth/callback#frag",
    "https://my.agience.ai@evil.example/auth/callback",
    "https://evil.example/?u=https://my.agience.ai/auth/callback",
    # Case, trailing slash, port, scheme.
    "https://MY.agience.ai/auth/callback", "https://my.agience.ai/Auth/Callback",
    "https://my.agience.ai/auth/callback/", "https://my.agience.ai:443/auth/callback",
    "http://my.agience.ai/auth/callback", "https://my.agience.ai./auth/callback",
    # Every previously special host, with no setting.
    "https://oauth.pstmn.io/v1/browser-callback", "https://oauth.pstmn.io/v1/callback",
    "https://vscode.dev/redirect", "http://127.0.0.1:8765/cb", "http://localhost:3000/cb",
    "http://[::1]:8765/cb",
    # Mantle's origin, whatever lists it.
    "https://mantle.agience.ai/auth/callback",
]


@pytest.mark.parametrize("uri", REFUSED)
def test_an_unconfigured_uri_is_refused_with_a_403(db_client, production, uri):
    resp = _authorize(db_client, redirect_uri=uri)
    assert resp.status_code == 403, (uri, resp.status_code)
    assert "location" not in {k.lower() for k in resp.headers}
    assert "CLIENT_REDIRECT_URIS" in resp.json()["detail"]


@pytest.mark.parametrize("uri", REFUSED)
def test_the_check_refuses_every_shape_for_every_first_party_client(production, uri):
    from origin.services.auth_service import is_client_redirect_allowed

    for client_id in ("platform", "agience-client", "never-configured"):
        assert not is_client_redirect_allowed(uri, client_id=client_id), (client_id, uri)


def test_a_listed_mantle_uri_is_still_refused(production, monkeypatch):
    from origin import config
    from origin.services.auth_service import is_client_redirect_allowed

    monkeypatch.setattr(config, "CLIENT_REDIRECT_URIS",
                        {"platform": ["https://mantle.agience.ai/auth/callback"]})
    assert not is_client_redirect_allowed("https://mantle.agience.ai/auth/callback",
                                          client_id="platform")


def test_a_registered_client_cannot_use_another_clients_uri(db_client, production, monkeypatch):
    from origin import config

    monkeypatch.setattr(config, "CLIENT_REGISTRATION_ENABLED", True)
    monkeypatch.setattr(config, "CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN", "")
    monkeypatch.setattr(config, "CLIENT_REGISTRATION_REDIRECT_URIS",
                        ["http://127.0.0.1/a", "http://127.0.0.1/b"])
    a = db_client.post("/auth/register", json={"redirect_uris": ["http://127.0.0.1:5000/a"]})
    db_client.post("/auth/register", json={"redirect_uris": ["http://127.0.0.1:5000/b"]})
    a_id = a.json()["client_id"]
    assert _authorize(db_client, client_id=a_id,
                      redirect_uri="http://127.0.0.1:6000/a").status_code == 200
    for other in ("http://127.0.0.1:6000/b", APP_CB):
        resp = _authorize(db_client, client_id=a_id, redirect_uri=other)
        assert resp.status_code == 403, other


def test_registration_names_only_what_is_listed(db_client, production, monkeypatch):
    """With registration on and nothing listed for it, no address registers; a third-party page
    never does."""
    from origin import config

    monkeypatch.setattr(config, "CLIENT_REGISTRATION_ENABLED", True)
    monkeypatch.setattr(config, "CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN", "")
    for uri in ("https://oauth.pstmn.io/v1/browser-callback", "https://vscode.dev/redirect",
                "http://127.0.0.1:33418", APP_CB):
        resp = db_client.post("/auth/register", json={"redirect_uris": [uri]})
        assert resp.status_code == 400, uri
        assert resp.json()["error"] == "invalid_redirect_uri"


# ---------------------------------------------------------------------------
# PKCE: S256, always
# ---------------------------------------------------------------------------
def test_a_flow_without_pkce_starts_nothing(db_client, production):
    resp = _authorize(db_client, pkce={})
    assert resp.status_code == 400
    assert "code_challenge" in resp.json()["detail"]


def test_plain_pkce_is_refused(db_client, production):
    resp = _authorize(db_client, pkce={"code_challenge": PKCE_VERIFIER,
                                       "code_challenge_method": "plain"})
    assert resp.status_code == 400
    assert "S256" in resp.json()["detail"]


@pytest.mark.parametrize("challenge", ["x" * 42, "x" * 44, "!" * 43, "x" * 128])
def test_a_challenge_that_is_not_an_s256_digest_is_refused(db_client, production, challenge):
    resp = _authorize(db_client, pkce={"code_challenge": challenge,
                                       "code_challenge_method": "S256"})
    assert resp.status_code == 400


def test_the_lure_s_exact_request_is_refused(db_client, production):
    """This morning's link: the platform client, Postman's callback, no PKCE."""
    resp = db_client.get("/auth/authorize", params={
        "client_id": "agience-client",
        "redirect_uri": "https://oauth.pstmn.io/v1/browser-callback",
        "response_type": "code", "provider": "google", "scope": "openid email profile"})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# The code: exact redirect at the exchange, single use, short life
# ---------------------------------------------------------------------------
def _seed(ar, *, code="c-1", redirect_uri=APP_CB, age=timedelta(0), challenge=PKCE_CHALLENGE):
    ar.authorization_codes[code] = {
        "user_info": {"provider": "google", "sub": "s-1", "email": "a@example.test", "name": "A",
                      "picture": None, "email_verified": True},
        "client_id": "platform", "redirect_uri": redirect_uri, "scope": "openid",
        "code_challenge": challenge, "code_challenge_method": "S256",
        "timestamp": datetime.now(timezone.utc) - age,
    }
    return code


def _exchange(client, code, *, redirect_uri=APP_CB, verifier=PKCE_VERIFIER):
    return client.post("/auth/token", data={"grant_type": "authorization_code", "code": code,
                                            "redirect_uri": redirect_uri, "client_id": "platform",
                                            "code_verifier": verifier})


def test_the_exchange_needs_the_exact_redirect_uri(db_client, production):
    import origin.routers.auth_router as ar

    for variant in (APP_CB + "/", "https://MY.agience.ai/auth/callback", APP_CB + "?x=1"):
        code = _seed(ar, code=f"c-{variant}")
        assert _exchange(db_client, code, redirect_uri=variant).status_code == 400, variant


def test_a_code_is_redeemed_once(db_client, production):
    import origin.routers.auth_router as ar

    code = _seed(ar)
    assert _exchange(db_client, code).status_code == 200
    assert _exchange(db_client, code).status_code == 400


def test_a_failed_attempt_spends_the_code(db_client, production):
    """A wrong verifier, client or redirect spends the code as a success would: no second try."""
    import origin.routers.auth_router as ar

    code = _seed(ar)
    assert _exchange(db_client, code, verifier="w" * 64).status_code == 400
    assert code not in ar.authorization_codes
    assert _exchange(db_client, code).status_code == 400


def test_a_code_lives_a_minute(db_client, production):
    import origin.routers.auth_router as ar

    assert ar._CODE_TTL <= timedelta(minutes=1)
    code = _seed(ar, age=ar._CODE_TTL + timedelta(seconds=1))
    assert _exchange(db_client, code).status_code == 400


def test_a_code_without_an_s256_challenge_is_not_redeemed(db_client, production):
    import origin.routers.auth_router as ar

    code = _seed(ar, challenge=None)
    assert _exchange(db_client, code).status_code == 400


# ---------------------------------------------------------------------------
# A listed URI is not an audience
# ---------------------------------------------------------------------------
def test_a_listed_uri_off_the_app_and_origin_gets_no_token(db_client, production, monkeypatch):
    """Listing a URI says a code may go there, not who the token is for: a first-party code
    delivered anywhere but the app (`APP_URI`), Origin's own pages, or a facet in `NARROW_FACETS`
    is answered with no token (review 12)."""
    from origin import config
    import origin.routers.auth_router as ar

    elsewhere = "https://elsewhere.example/auth/callback"
    monkeypatch.setattr(config, "CLIENT_REDIRECT_URIS", {"platform": [APP_CB, elsewhere]})
    code = _seed(ar, redirect_uri=elsewhere)
    resp = _exchange(db_client, code, redirect_uri=elsewhere)
    assert resp.status_code == 400
    assert "access_token" not in resp.text


# ---------------------------------------------------------------------------
# The review's cases
# ---------------------------------------------------------------------------
def test_a_first_party_loopback_entry_is_exact_port_included(production, monkeypatch):
    """RFC 8252's port variance is for a registration; a first-party list names its own ports."""
    from origin import config
    from origin.services.auth_service import (is_client_redirect_allowed,
                                              is_registered_redirect_allowed)

    listed = "http://localhost:5173/auth/callback"
    monkeypatch.setattr(config, "CLIENT_REDIRECT_URIS", {"platform": [listed]})
    assert is_client_redirect_allowed(listed, client_id="platform")
    assert not is_client_redirect_allowed("http://localhost:9999/auth/callback",
                                          client_id="platform")
    assert is_registered_redirect_allowed("http://localhost:9999/auth/callback", [listed])


def test_discovery_offers_s256_alone(db_client):
    doc = db_client.get("/.well-known/oauth-authorization-server").json()
    assert doc["code_challenge_methods_supported"] == ["S256"]


def test_a_listed_uri_with_a_query_gets_the_code_appended_to_it():
    import origin.routers.auth_router as ar

    assert ar._with_query("https://app.example/cb?x=1", {"code": "c"}) == \
        "https://app.example/cb?x=1&code=c"
    assert ar._with_query("https://app.example/cb", {"code": "c"}) == "https://app.example/cb?code=c"

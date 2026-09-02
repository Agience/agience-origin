"""What Origin hands a browser by default: which cross-origin callers it answers, and whether the
sign-in cookie is allowed onto plain HTTP.

Both defaults could fail open on the service that mints every token in the platform: an unset
`ORIGIN_ALLOWED_ORIGINS` meaning CORS `["*"]`, and a login-flow session cookie carrying no `Secure`.
Neither is an exploit on its own — the API is bearer-only and the OAuth cookies are same-site — and
that is the problem with defaults of this shape: they are survivable because of a property that
holds today, on a service one handler away from not having it.

The tests below pin the *direction* the defaults fail in, not their contents. An operator can still
name any allowlist they like; what they cannot do is inherit the wildcard by configuring nothing.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

import origin.config as config_module


@pytest.fixture
def main_module(origin_app):
    """`origin.main`, freshly reloaded by the `origin_app` fixture."""
    import origin.main as m

    return m


def _reload_main_with(monkeypatch, main_module, **env):
    for k, v in env.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)
    importlib.reload(config_module)
    return importlib.reload(main_module)


def _middleware_kwargs(app, cls) -> dict:
    for mw in app.user_middleware:
        if mw.cls is cls:
            return dict(mw.kwargs)
    raise AssertionError(f"{cls.__name__} is not installed on the app")


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


def test_the_default_allowlist_is_never_the_wildcard(monkeypatch, main_module):
    """Configure nothing, inherit nothing permissive."""
    monkeypatch.delenv("ORIGIN_ALLOWED_ORIGINS", raising=False)
    origins = main_module._allowed_origins()

    assert origins, "an empty allowlist would refuse Origin's own front end"
    assert "*" not in origins


def test_the_default_is_derived_from_the_first_party_surfaces_already_configured(
    monkeypatch, main_module
):
    """The origins Origin will redirect a sign-in back to are the origins it answers XHR for.

    Not a fixed list and not a guess — the issuer, its own public URI and the facet bases
    `is_client_redirect_allowed` already admits.
    """
    monkeypatch.delenv("ORIGIN_ALLOWED_ORIGINS", raising=False)
    monkeypatch.setattr(config_module, "AUTHORITY_ISSUER", "https://id.example.test")
    monkeypatch.setattr(config_module, "ORIGIN_URI", "http://origin:8080")
    monkeypatch.setattr(config_module, "FACET_URI", "https://app.example.test")
    monkeypatch.setattr(config_module, "FACET_URIS", ["https://aria.example.test"])

    origins = main_module._allowed_origins()

    assert set(origins) == {
        "https://id.example.test",
        "http://origin:8080",
        "https://app.example.test",
        "https://aria.example.test",
    }


def test_local_development_still_works_out_of_the_box(monkeypatch, main_module):
    """The failure direction that matters for usability.

    A tightened default that breaks a developer's first run is a bad trade; the derived set is the
    localhost defaults on a machine that has configured nothing, so nothing has to be noticed.
    """
    monkeypatch.delenv("ORIGIN_ALLOWED_ORIGINS", raising=False)
    monkeypatch.setattr(config_module, "AUTHORITY_ISSUER", "http://localhost:8080")
    monkeypatch.setattr(config_module, "ORIGIN_URI", "http://localhost:8080")
    monkeypatch.setattr(config_module, "FACET_URI", "http://localhost:5173")
    monkeypatch.setattr(config_module, "FACET_URIS", [])

    assert set(main_module._allowed_origins()) == {
        "http://localhost:8080",
        "http://localhost:5173",
    }


def test_an_explicit_allowlist_wins(monkeypatch, main_module):
    monkeypatch.setenv(
        "ORIGIN_ALLOWED_ORIGINS", "https://a.example.test, https://b.example.test"
    )
    assert main_module._allowed_origins() == [
        "https://a.example.test",
        "https://b.example.test",
    ]


def test_a_configured_entry_is_reduced_to_what_a_browser_actually_sends(
    monkeypatch, main_module
):
    """A browser's `Origin` header carries no path, so an allowlist entry with one can never match
    and would read as a correctly-configured origin that is silently refused."""
    monkeypatch.setenv("ORIGIN_ALLOWED_ORIGINS", "https://app.example.test/ui/,not a url,")
    assert main_module._allowed_origins() == ["https://app.example.test"]


def test_an_explicit_wildcard_is_not_smuggled_back_in(monkeypatch, main_module):
    """`*` is not a URL, so it does not survive normalization — and an operator who writes it gets
    the derived default rather than the hole they asked for."""
    monkeypatch.setenv("ORIGIN_ALLOWED_ORIGINS", "*")
    assert "*" not in main_module._allowed_origins()


def test_the_app_is_wired_with_the_computed_allowlist(main_module):
    """Positive control on everything above: a correct function the middleware does not read is
    not a fix."""
    kwargs = _middleware_kwargs(main_module.app, CORSMiddleware)
    assert kwargs["allow_origins"] == main_module._allowed_origins()
    assert "*" not in kwargs["allow_origins"]


def test_a_cross_origin_caller_outside_the_allowlist_is_not_greeted(
    monkeypatch, main_module, jwt_keypair
):
    """Behavioural, not structural: the preflight of an unlisted origin comes back without an
    `access-control-allow-origin` header, and a listed one comes back with it."""
    from fastapi.testclient import TestClient

    reloaded = _reload_main_with(
        monkeypatch,
        main_module,
        ORIGIN_ALLOWED_ORIGINS="https://allowed.example.test",
        KEYS_DIR=str(jwt_keypair),
        ORIGIN_SKIP_MIGRATIONS="1",
        ORIGIN_SKIP_DB_SETTINGS="1",
        DATABASE_URL="sqlite:///:memory:",
    )

    with TestClient(reloaded.app) as client:
        allowed = client.options(
            "/healthz",
            headers={
                "Origin": "https://allowed.example.test",
                "Access-Control-Request-Method": "GET",
            },
        )
        refused = client.options(
            "/healthz",
            headers={
                "Origin": "https://evil.example.test",
                "Access-Control-Request-Method": "GET",
            },
        )

    assert allowed.headers.get("access-control-allow-origin") == "https://allowed.example.test"
    assert refused.headers.get("access-control-allow-origin") is None


# ---------------------------------------------------------------------------
# The session cookie
# ---------------------------------------------------------------------------


def test_the_session_cookie_is_secure_when_the_issuer_is_https(monkeypatch, main_module):
    monkeypatch.setattr(config_module, "AUTHORITY_ISSUER", "https://id.example.test")
    assert main_module._session_cookie_is_https_only() is True


def test_the_session_cookie_is_not_secure_on_a_plain_http_issuer(monkeypatch, main_module):
    """A `Secure` cookie is never sent over http at all, so forcing it on a deployment that says
    its browser-facing URL is http would not harden anything — it would delete the cookie."""
    monkeypatch.setattr(config_module, "AUTHORITY_ISSUER", "http://localhost:8080")
    assert main_module._session_cookie_is_https_only() is False


def test_the_flag_follows_the_issuer_and_not_the_internal_origin_uri(monkeypatch, main_module):
    """The deployment this has to get right: users arrive over TLS at a reverse proxy while peers
    dial `http://origin:8080` internally. Reading `ORIGIN_URI` — or the request's own scheme, which
    is the proxy's back leg — would mark the cookie insecure on exactly that node."""
    monkeypatch.setattr(config_module, "AUTHORITY_ISSUER", "https://id.example.test")
    monkeypatch.setattr(config_module, "ORIGIN_URI", "http://origin:8080")
    assert main_module._session_cookie_is_https_only() is True


def test_the_app_is_wired_with_the_computed_flag(main_module):
    kwargs = _middleware_kwargs(main_module.app, SessionMiddleware)
    assert "https_only" in kwargs, (
        "SessionMiddleware was installed without https_only — the flag defaults to False, which is "
        "the state this test exists to prevent"
    )
    assert kwargs["https_only"] == main_module._session_cookie_is_https_only()

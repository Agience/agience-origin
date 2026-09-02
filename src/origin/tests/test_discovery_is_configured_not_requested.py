"""A discovery document states this authority's identity — never the caller's view of it.

Built from `request.base_url`, `issuer` and every endpoint under it would reflect whatever scheme
and host the caller used to reach this process — which, behind a TLS-terminating proxy, is the
plaintext `http://` of the last hop, not the `https://` the authority is actually known as.

A relying party compares the `iss` claim exactly, so a mismatch
between the scheme this authority mints tokens with and the scheme it advertises here produces
tokens every verifier rejects as an unknown issuer — surfacing as "login is broken" with nothing in
the verifier's log pointing back here.

OIDC Discovery requires `issuer` to be a stable value matching the `iss` of the tokens this
authority mints. A value derived from the scheme, Host header or port of whoever asked cannot
satisfy that by construction.
"""
from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def app_with(monkeypatch):
    def _make(origin_uri: str, authority: str = ""):
        monkeypatch.setenv("ORIGIN_URI", origin_uri)
        if authority:
            monkeypatch.setenv("AUTHORITY_ISSUER", authority)
        else:
            monkeypatch.delenv("AUTHORITY_ISSUER", raising=False)
        import origin.config as cfg
        importlib.reload(cfg)
        import origin.routers.auth_router as ar
        importlib.reload(ar)
        return ar
    return _make


def _disco(ar, path: str = "/.well-known/openid-configuration"):
    """Call the endpoint directly — no server, no proxy, so the ONLY input is configuration."""
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(ar.root_router)
    return TestClient(app).get(path).json()


def test_the_issuer_is_the_configured_one(app_with):
    ar = app_with("https://origin.example.test")
    d = _disco(ar)
    assert d["issuer"] == "https://origin.example.test"


def test_a_plaintext_request_does_not_downgrade_the_published_issuer(app_with):
    """TestClient calls over `http://testserver`. The published issuer must not move because of how
    the caller arrived — which is exactly what a TLS-terminating proxy makes happen in
    production."""
    ar = app_with("https://origin.example.test")
    d = _disco(ar)
    assert d["issuer"].startswith("https://"), \
        "the request's scheme leaked into the published issuer: %r" % d["issuer"]
    assert "testserver" not in d["issuer"]


def test_every_endpoint_is_built_on_the_same_issuer(app_with):
    """A document whose `issuer` is right and whose endpoints are not is worse than one that is
    wrong throughout: the mismatch is only found by a client that follows a link."""
    ar = app_with("https://origin.example.test")
    d = _disco(ar)
    for k in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"):
        assert d[k].startswith(d["issuer"] + "/"), "%s is not under the issuer: %r" % (k, d[k])


def test_authority_issuer_wins_over_origin_uri(app_with):
    """They differ on a node whose authority is elsewhere. The document must state the identity
    this node SIGNS as, which is AUTHORITY_ISSUER."""
    ar = app_with("https://api.example.com", authority="https://origin.example.test")
    assert _disco(ar)["issuer"] == "https://origin.example.test"


def test_pkce_is_still_advertised(app_with):
    """The browser reads this to decide it can use the code flow at all. Losing it while fixing
    the issuer would trade one silent breakage for another."""
    ar = app_with("https://origin.example.test")
    assert "S256" in _disco(ar)["code_challenge_methods_supported"]
    assert "code" in _disco(ar)["response_types_supported"]


RFC8414_PATH = "/.well-known/oauth-authorization-server"


def test_the_rfc8414_path_is_served_at_all(app_with):
    """An MCP client probes RFC 8414 first and only falls back to OIDC discovery. A client that does
    not implement the fallback finds no authorization server here without this alias."""
    ar = app_with("https://origin.example.test")
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(ar.root_router)
    assert TestClient(app).get(RFC8414_PATH).status_code == 200


def test_both_discovery_paths_serve_the_identical_document(app_with):
    """One builder feeds both, so the two can never disagree about `issuer` or any endpoint. Two
    field lists would drift, and the drift is invisible until an OAuth-only client misses a field
    that was added to the OIDC document alone."""
    ar = app_with("https://origin.example.test")
    assert _disco(ar, RFC8414_PATH) == _disco(ar)


def test_the_rfc8414_document_carries_what_a_registering_client_needs(app_with, monkeypatch):
    """`registration_endpoint` is the field that makes self-registration possible, and RFC 8414 is
    the path the client reads it from. `issuer`, `authorization_endpoint` and `token_endpoint` are
    the rest of the minimum for the code flow."""
    monkeypatch.setenv("CLIENT_REGISTRATION_ENABLED", "true")
    ar = app_with("https://origin.example.test")
    d = _disco(ar, RFC8414_PATH)
    for k in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
              "response_types_supported", "grant_types_supported",
              "code_challenge_methods_supported"):
        assert k in d, "RFC 8414 document is missing %s" % k
    assert d.get("registration_endpoint") == d["issuer"] + "/auth/register"


def test_the_rfc8414_path_refuses_an_unconfigured_issuer_too(monkeypatch):
    """The alias must not become a second way to publish a request-derived issuer — the defect the
    OIDC path already refuses."""
    monkeypatch.setenv("ORIGIN_URI", "")
    monkeypatch.delenv("AUTHORITY_ISSUER", raising=False)
    import origin.config as cfg
    importlib.reload(cfg)
    import origin.routers.auth_router as ar
    importlib.reload(ar)
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(ar.root_router)
    r = TestClient(app, raise_server_exceptions=False).get(RFC8414_PATH)
    if r.status_code == 200:
        assert "testserver" not in r.json().get("issuer", "")
    else:
        assert r.status_code == 500


def test_no_configured_issuer_refuses_rather_than_guessing(app_with, monkeypatch):
    """Falling back to the request would be the original defect with extra steps. A wrong issuer is
    worse than no document: clients cache it, and every token minted afterwards fails to verify
    against something nobody can find."""
    monkeypatch.setenv("ORIGIN_URI", "")
    monkeypatch.delenv("AUTHORITY_ISSUER", raising=False)
    import origin.config as cfg
    importlib.reload(cfg)
    import origin.routers.auth_router as ar
    importlib.reload(ar)
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(ar.root_router)
    r = TestClient(app, raise_server_exceptions=False).get("/.well-known/openid-configuration")
    # Either no document, or a configured default — never the caller's own address.
    if r.status_code == 200:
        assert "testserver" not in r.json().get("issuer", ""), \
            "with no configured issuer the document fell back to the request"
    else:
        assert r.status_code == 500

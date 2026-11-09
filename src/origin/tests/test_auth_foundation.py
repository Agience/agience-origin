"""Tests for the Origin auth foundation: the primitives the auth routers are built on.

Covers:
- JWT issuance + verification roundtrip
- Password hash + verify
- Nonce issue + verify
- API key generation
- Allow-list (`is_person_allowed`)
- Redirect URI gate (`is_client_redirect_allowed`)
- AuthContext shape
"""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture
def auth_modules(monkeypatch, jwt_keypair):
    """Initialize JWT keys and return the freshly-loaded auth modules."""
    monkeypatch.setenv("KEYS_DIR", str(jwt_keypair))
    monkeypatch.setenv("ORIGIN_SKIP_MIGRATIONS", "1")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

    import origin.config as cfg
    import origin.key_manager as km

    importlib.reload(cfg)
    importlib.reload(km)
    km.init_jwt_keys()

    from origin.services import auth_service, auth_verifier
    from origin.services import dependencies as origin_deps

    importlib.reload(auth_service)
    importlib.reload(auth_verifier)
    importlib.reload(origin_deps)

    return {
        "config": cfg,
        "auth_service": auth_service,
        "auth_verifier": auth_verifier,
        "deps": origin_deps,
    }


def test_jwt_issue_and_verify_roundtrip(auth_modules):
    cfg = auth_modules["config"]
    issuance = auth_modules["auth_service"]
    verify = auth_modules["auth_verifier"]

    token = issuance.create_jwt_token(
        {"sub": "user-1", "aud": cfg.AUTHORITY_ISSUER, "principal_type": "user"}
    )
    payload = verify.verify_token(token, expected_audience=cfg.AUTHORITY_ISSUER)
    assert payload is not None
    assert payload["sub"] == "user-1"
    assert payload["principal_type"] == "user"


def test_jwt_rejects_wrong_audience(auth_modules):
    cfg = auth_modules["config"]
    issuance = auth_modules["auth_service"]
    verify = auth_modules["auth_verifier"]

    token = issuance.create_jwt_token({"sub": "user-1", "aud": cfg.AUTHORITY_ISSUER})
    assert verify.verify_token(token, expected_audience="not-the-issuer") is None


def test_service_token_surfaces_persona_in_actor(auth_modules, monkeypatch):
    """A chorus persona's service JWT signs as iss=sub="chorus" (the container
    holding the key) and carries the acting persona in `client_id`. resolve_auth
    must surface that persona as `actor` so authz/audit can tell Ophan from Iris,
    while `principal_id` stays the signing service (so platform-server gates hold)."""
    from unittest.mock import MagicMock

    deps = auth_modules["deps"]
    payload = {
        "sub": "chorus", "iss": "chorus", "aud": "origin",
        "principal_type": "service", "client_id": "agience-server-ophan",
    }
    monkeypatch.setattr(deps, "verify_token", lambda _t: payload)

    ctx = deps.resolve_auth("ey.fake.service.token", MagicMock())
    assert ctx.principal_type == "service"
    assert ctx.principal_id == "chorus"            # signer/service (gate-relevant)
    assert ctx.actor == "agience-server-ophan"     # acting persona, now surfaced


def test_delegation_token_includes_host_id(auth_modules, monkeypatch):
    """Origin's delegation minter must stamp the full chain — host_id included
    (the Host in Authority/Host/Server/User), derived via get_host_id()."""
    from jose import jwt as jose_jwt

    import origin.service_identity as ksi
    monkeypatch.setattr(ksi, "get_host_id", lambda: "host-abc-123")

    issuance = auth_modules["auth_service"]
    token = issuance.issue_delegation_token("agience-server-iris", "user-1")
    claims = jose_jwt.get_unverified_claims(token)

    assert claims["sub"] == "user-1"                 # User
    assert claims["act"]["sub"] == "agience-server-iris"  # Server
    assert claims["host_id"] == "host-abc-123"       # Host
    assert claims["principal_type"] == "delegation"


def test_system_delegation_token_carries_chain_and_scope(auth_modules, monkeypatch):
    """The system-delegation minter stamps the full chain plus a bounding scope,
    with the system principal as subject and the requesting persona as actor."""
    from jose import jwt as jose_jwt

    import origin.service_identity as ksi
    monkeypatch.setattr(ksi, "get_host_id", lambda: "host-abc")

    issuance = auth_modules["auth_service"]
    token = issuance.issue_system_delegation_token(
        "sys-principal-1", actor="agience-server-ophan",
        scope="platform.email.send", audience="mantle",
    )
    claims = jose_jwt.get_unverified_claims(token)

    assert claims["sub"] == "sys-principal-1"             # system principal (User slot)
    assert claims["act"]["sub"] == "agience-server-ophan" # Server
    assert claims["host_id"] == "host-abc"                # Host
    assert claims["aud"] == "mantle"
    assert claims["scope"] == "platform.email.send"
    assert claims["principal_type"] == "delegation"


def test_password_roundtrip(auth_modules):
    auth_service = auth_modules["auth_service"]
    h = auth_service.hash_password("correct horse battery staple")
    assert auth_service.verify_password("correct horse battery staple", h)
    assert not auth_service.verify_password("wrong password", h)
    assert not auth_service.verify_password("", h)


def test_password_rejects_malformed_hash(auth_modules):
    auth_service = auth_modules["auth_service"]
    assert not auth_service.verify_password("any", "not-a-valid-hash")


def test_origin_verifies_no_nonce(auth_modules):
    """Origin mints the inbound nonce (`issue_nonce`) and never verifies one: the verifying half
    is the resource server's, and Origin's copy was dead (review 21, F7)."""
    verify = auth_modules["auth_verifier"]
    assert not hasattr(verify, "verify_nonce")
    token, _exp = auth_modules["auth_service"].issue_nonce(key_id="k1", artifact_id="a1", secret="s")
    assert token


def test_api_key_format(auth_modules):
    auth_service = auth_modules["auth_service"]
    k = auth_service.generate_api_key()
    assert k.startswith("agc_")
    assert len(k) == len("agc_") + 32  # 16 bytes hex
    assert len(auth_service.hash_api_key(k)) == 64  # sha256 hex


def test_is_person_allowed_default_allow(auth_modules):
    cfg = auth_modules["config"]
    auth_service = auth_modules["auth_service"]
    cfg.ALLOWED_EMAILS = []
    cfg.ALLOWED_DOMAINS = []
    cfg.ALLOWED_GOOGLE_IDS = []
    assert auth_service.is_person_allowed(None, "anyone@example.com")


def test_is_person_allowed_domain_match(auth_modules):
    cfg = auth_modules["config"]
    auth_service = auth_modules["auth_service"]
    cfg.ALLOWED_EMAILS = []
    cfg.ALLOWED_DOMAINS = ["example.com"]
    cfg.ALLOWED_GOOGLE_IDS = []
    assert auth_service.is_person_allowed(None, "a@example.com")
    assert not auth_service.is_person_allowed(None, "a@evil.example")


def test_is_person_allowed_glob_pattern(auth_modules):
    cfg = auth_modules["config"]
    auth_service = auth_modules["auth_service"]
    cfg.ALLOWED_EMAILS = []
    cfg.ALLOWED_DOMAINS = ["*.example.com"]
    cfg.ALLOWED_GOOGLE_IDS = []
    assert auth_service.is_person_allowed(None, "user@team.example.com")
    assert not auth_service.is_person_allowed(None, "user@example.com")  # bare domain doesn't match *.x


def test_is_client_redirect_allowed(auth_modules, monkeypatch):
    """A first-party client's code goes only to a URI listed for it in `CLIENT_REDIRECT_URIS`."""
    cfg = auth_modules["config"]
    auth_service = auth_modules["auth_service"]
    monkeypatch.setattr(cfg, "CLIENT_REDIRECT_URIS",
                        {"platform": ["http://localhost:5173/callback"]}, raising=False)

    assert auth_service.is_client_redirect_allowed("http://localhost:5173/callback",
                                                   client_id="platform")
    # Another client id, another path, another host, another scheme: none is listed.
    assert not auth_service.is_client_redirect_allowed("http://localhost:5173/callback",
                                                       client_id="agience-client")
    for uri in ("http://localhost:5173/other", "http://evil.example/cb", "ftp://localhost:5173/",
                "https://vscode.dev/redirect", "http://127.0.0.1:9000/cb"):
        assert not auth_service.is_client_redirect_allowed(uri, client_id="platform"), uri


def test_facet_uris_no_longer_decides_a_redirect(auth_modules, monkeypatch):
    """`FACET_URI`, `FACET_URIS` and `ORIGIN_URI` name the node's surfaces; none of them admits a
    redirect. With nothing in `CLIENT_REDIRECT_URIS`, a facet's own callback is refused."""
    cfg = auth_modules["config"]
    auth_service = auth_modules["auth_service"]
    cfg.FACET_URI = "https://app.example.test"
    cfg.ORIGIN_URI = "https://origin.example.test"
    cfg.FACET_URIS = ["https://aria.example.test", "https://pharos.example.test"]
    monkeypatch.setattr(cfg, "CLIENT_REDIRECT_URIS", {}, raising=False)

    for uri in ("https://app.example.test/auth/callback", "https://origin.example.test/",
                "https://aria.example.test/auth/callback"):
        assert not auth_service.is_client_redirect_allowed(uri, client_id="platform"), uri


def test_one_uri_set_as_a_string_is_one_uri(auth_modules, monkeypatch):
    """A hand-written value can put one string where a client's list belongs; it is one URI, never
    its characters."""
    cfg = auth_modules["config"]
    auth_service = auth_modules["auth_service"]
    monkeypatch.setattr(cfg, "CLIENT_REDIRECT_URIS",
                        {"platform": "https://app.example.test/auth/callback"}, raising=False)

    assert auth_service.is_client_redirect_allowed("https://app.example.test/auth/callback",
                                                   client_id="platform")
    assert not auth_service.is_client_redirect_allowed("h", client_id="platform")


def test_authcontext_field_parity(auth_modules):
    """AuthContext carries every field a resource server's router code expects."""
    deps = auth_modules["deps"]
    ctx = deps.AuthContext()
    expected = {
        "principal_id",
        "principal_type",
        "user_id",
        "grants",
        "api_key_id",
        "api_key_entity",
        "server_id",
        "actor",
        "authority",
        "host_id",
        "bearer_grant",
        "target_artifact_id",
    }
    actual = set(ctx.__dataclass_fields__.keys())
    assert actual == expected, f"AuthContext shape drift: {actual ^ expected}"


def test_db_modules_import_cleanly():
    """Smoke check: all Origin DB CRUD modules import without errors.

    Origin's CRUD modules do not include grants or api_keys: Origin does no authorization.
    """
    from origin.db import persons, platform_settings, server_credentials  # noqa: F401

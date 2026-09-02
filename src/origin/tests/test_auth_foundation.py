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


def test_nonce_roundtrip(auth_modules):
    issuance = auth_modules["auth_service"]
    verify = auth_modules["auth_verifier"]

    token, _exp = issuance.issue_nonce(key_id="k1", artifact_id="a1", secret="s")
    assert verify.verify_nonce(token, "k1", "a1", "s")
    # Mismatched binding
    assert not verify.verify_nonce(token, "k1", "a2", "s")
    assert not verify.verify_nonce(token, "k2", "a1", "s")
    # Wrong secret
    assert not verify.verify_nonce(token, "k1", "a1", "different-secret")


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
    assert not auth_service.is_person_allowed(None, "a@evil.com")


def test_is_person_allowed_glob_pattern(auth_modules):
    cfg = auth_modules["config"]
    auth_service = auth_modules["auth_service"]
    cfg.ALLOWED_EMAILS = []
    cfg.ALLOWED_DOMAINS = ["*.example.com"]
    cfg.ALLOWED_GOOGLE_IDS = []
    assert auth_service.is_person_allowed(None, "user@team.example.com")
    assert not auth_service.is_person_allowed(None, "user@example.com")  # bare domain doesn't match *.x


def test_is_client_redirect_allowed(auth_modules):
    cfg = auth_modules["config"]
    auth_service = auth_modules["auth_service"]
    cfg.FACET_URI = "http://localhost:5173"
    cfg.ORIGIN_URI = "http://localhost:8081"

    assert auth_service.is_client_redirect_allowed("http://localhost:5173/callback")
    assert auth_service.is_client_redirect_allowed("http://localhost:8081/callback")
    assert auth_service.is_client_redirect_allowed("https://vscode.dev/redirect")
    assert auth_service.is_client_redirect_allowed("http://127.0.0.1:9000/cb")
    assert not auth_service.is_client_redirect_allowed("http://evil.example/cb")
    assert not auth_service.is_client_redirect_allowed("ftp://localhost:5173/")


def test_many_facets_are_admitted_and_an_unlisted_one_is_still_refused(auth_modules):
    """Many observation planes, one authority.

    A node runs several facets (mantle's browser, a persona's surface, pharos). `FACET_URIS`
    admits all of them: a delegation is minted from a user token a facet forwards, so a facet
    that cannot sign in never has one to forward.
    """
    cfg = auth_modules["config"]
    auth_service = auth_modules["auth_service"]
    # https + a non-local ORIGIN_URI, so the localhost dev-range escape hatch cannot be what passes.
    cfg.FACET_URI = "https://mantle.example.test"
    cfg.ORIGIN_URI = "https://origin.example.test"
    cfg.FACET_URIS = [
        "https://mantle.example.test",
        "https://aria.example.test",
        "https://pharos.example.test",
    ]

    assert auth_service.is_client_redirect_allowed("https://mantle.example.test/auth/callback")
    assert auth_service.is_client_redirect_allowed("https://aria.example.test/auth/callback")
    assert auth_service.is_client_redirect_allowed("https://pharos.example.test/auth/callback")

    # The controls: widening which bases are admitted must not loosen how one is matched.
    # `sage.` is a real sibling facet that simply was not listed — the everyday case.
    assert not auth_service.is_client_redirect_allowed("https://sage.example.test/auth/callback")
    # A suffix match would admit this; the netloc comparison must not.
    assert not auth_service.is_client_redirect_allowed("https://evil-aria.example.test/cb")
    # A prefix/substring match would admit both of these — the classic open-redirect shapes.
    assert not auth_service.is_client_redirect_allowed("https://aria.example.test.evil.com/cb")
    assert not auth_service.is_client_redirect_allowed(
        "https://evil.com/?next=https://aria.example.test/auth/callback"
    )


def test_facet_uris_survives_being_set_as_one_string(auth_modules):
    """An operator can set the env var by hand, and a bare string is iterable.

    Without normalisation, `extend()` over a str would admit its individual characters as allowed
    bases — a failure mode that resembles nothing that looks like a URL in any log.
    """
    cfg = auth_modules["config"]
    auth_service = auth_modules["auth_service"]
    cfg.FACET_URI = "https://mantle.example.test"
    cfg.ORIGIN_URI = "https://origin.example.test"
    cfg.FACET_URIS = "https://aria.example.test,https://pharos.example.test"

    assert auth_service.is_client_redirect_allowed("https://aria.example.test/auth/callback")
    assert auth_service.is_client_redirect_allowed("https://pharos.example.test/auth/callback")
    assert not auth_service.is_client_redirect_allowed("https://sage.example.test/auth/callback")


def test_an_empty_facet_uris_changes_nothing(auth_modules):
    """A node that declares only `FACET_URI` and leaves `FACET_URIS` empty is unaffected by it."""
    cfg = auth_modules["config"]
    auth_service = auth_modules["auth_service"]
    cfg.FACET_URI = "https://mantle.example.test"
    cfg.ORIGIN_URI = "https://origin.example.test"
    cfg.FACET_URIS = []

    assert auth_service.is_client_redirect_allowed("https://mantle.example.test/auth/callback")
    assert auth_service.is_client_redirect_allowed("https://origin.example.test/auth/callback")
    assert not auth_service.is_client_redirect_allowed("https://aria.example.test/auth/callback")


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

"""Origin pytest fixtures.

DB-dependent tests build the schema against an in-memory SQLite, the same engine production
uses. JWT/JWKS tests stub key loading with tmp PEM files, so the suite needs no running Origin.
"""

import os as _os
# Never load a real dev `.env` into the test environment — tests set their own env explicitly, and a
# machine-local `.env` (real creds) must not leak in (see origin.config.load_env).
_os.environ.setdefault("AGIENCE_NO_DOTENV", "1")

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _reset_password_guess_budget():
    """Give every test a full password guess budget.

    The budget is process-local by design (see `services/guess_budget`), so inside a test run it
    survives between tests exactly the way it survives between requests. Autouse and suite-wide
    rather than attached to `origin_app`, because the file with the most failed-login tests builds
    its own app and never asks for that fixture: without this, one test's deliberate failures
    throttle a later test's legitimate sign-in and the suite's result depends on execution order —
    a 429 arriving where a test asserted 401, in a file nobody had touched.
    """
    from origin.services import guess_budget

    guess_budget.reset()
    yield
    guess_budget.reset()


@pytest.fixture(scope="session")
def jwt_keypair(tmp_path_factory) -> Path:
    """Materialize all Origin key files in a tmp dir for the test session.

    Origin's lifespan reads several files: jwt private/public PEMs, encryption
    key (Fernet), platform internal secret, inbound nonce secret, identity
    password. We write minimal-but-real values so lifespan completes cleanly.
    """
    from cryptography.fernet import Fernet
    import secrets as _secrets

    keys_dir = tmp_path_factory.mktemp("origin_keys")
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (keys_dir / "origin.private.pem").write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (keys_dir / "origin.public.pem").write_bytes(
        private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    (keys_dir / "encryption.key").write_text(Fernet.generate_key().decode())
    (keys_dir / "platform_internal.secret").write_text(_secrets.token_urlsafe(48))
    (keys_dir / "inbound_nonce.secret").write_text(_secrets.token_urlsafe(48))
    return keys_dir


@pytest.fixture
def origin_app(monkeypatch, jwt_keypair):
    """Build a fresh Origin FastAPI app with stubbed key paths.

    Migrations are skipped via ORIGIN_SKIP_MIGRATIONS=1. The DB engine is
    initialized against an in-memory SQLite (matches production engine).
    """
    monkeypatch.setenv("KEYS_DIR", str(jwt_keypair))
    monkeypatch.setenv("ORIGIN_SKIP_MIGRATIONS", "1")
    monkeypatch.setenv("ORIGIN_SKIP_DB_SETTINGS", "1")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

    # Re-import after env vars are set so module-level Path resolution picks them up.
    import importlib
    import sys

    import origin.config as _cfg
    import origin.key_manager as _km
    import origin.db.session as _session
    import origin.main as _origin_main

    importlib.reload(_cfg)
    importlib.reload(_km)
    importlib.reload(_session)

    # Refresh anything routing or dependency-related already in sys.modules with stale
    # references. test_auth_foundation reloads `origin.services.dependencies`, which detaches
    # `get_auth` from every router module loaded before it.
    for mod_name in [
        "origin.services.auth_service",
        "origin.services.auth_verifier",
        "origin.services.dependencies",
        "origin.routers.auth_router",
        "origin.routers.passkey_router",
        "origin.routers.otp_router",
        "origin.routers.system_router",
        "origin.routers.server_credentials_router",
        "origin.routers.setup_router",
        # oracle_router resolves the caller through `get_auth` like every other router, so it has
        # to be reloaded alongside them — otherwise it keeps a stale `get_auth` symbol and both
        # dependency_overrides and the reloaded key_manager silently fail to apply to it.
        "origin.routers.oracle_router",
    ]:
        mod = sys.modules.get(mod_name)
        if mod is not None:
            importlib.reload(mod)

    importlib.reload(_origin_main)

    return _origin_main.app


@pytest.fixture
def client(origin_app):
    with TestClient(origin_app) as c:
        yield c

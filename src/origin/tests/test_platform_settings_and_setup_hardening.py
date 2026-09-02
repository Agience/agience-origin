"""Origin hardening: setup-token lifetime, secret classification, batch atomicity,
operator promotion, and role freshness on refresh.

Five properties this file pins, all on the live auth authority:

1. `/setup/validate-connection` is gated on both the setup token and
   `needs_setup()`. A token file that survives `delete_setup_token()` — the
   case on a read-only KEYS_DIR, where it reloads on restart — must not
   reopen a full-response SSRF and credential-testing oracle.
2. `platform.setup_operator_token` is written with `is_secret=True` and read
   with `get_secret()`, which does consult `_secrets` — so deferred-operator
   promotion works, and an instance set up without an operator can still
   gain one.
3. `is_secret` is not caller-supplied on `PATCH /system/settings`: a secret
   cannot be stored in plaintext, and an already-encrypted key cannot be
   silently downgraded.
4. `set_many` commits as one transaction, not per item, so a failure partway
   through cannot leave a half-applied batch.
5. The refresh grant recomputes `roles` rather than replaying the token's
   original ones, so a demoted operator loses `platform:admin` immediately.

Positive controls are paired with each rejection assertion.
"""

from __future__ import annotations


import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from origin.db.base import Base
from origin.services import platform_settings_service as pss


def is_secret_key(key: str) -> bool:
    """Resolved lazily, not imported at module scope.

    A module-level import would raise ImportError against a tree without the
    classifier, turning every test in this file into a collection error — which
    proves nothing about behaviour. Resolving here lets each test fail on its own
    assertion instead.
    """
    fn = getattr(pss, "is_secret_key", None)
    if fn is None:
        pytest.fail(
            "platform_settings_service.is_secret_key is missing — secret "
            "classification is caller-supplied, so a secret can be stored in "
            "plaintext and an encrypted key silently downgraded"
        )
    return fn(key)


@pytest.fixture
def db() -> Session:
    import origin.models  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        yield session


@pytest.fixture
def cache(monkeypatch, tmp_path) -> pss._SettingsCache:
    """A fresh settings cache with a real Fernet key."""
    from cryptography.fernet import Fernet

    key = Fernet.generate_key().decode()
    monkeypatch.setattr(pss, "get_encryption_key", lambda: key)
    return pss._SettingsCache()


# ---------------------------------------------------------------------------
# 2 + 3. Secret classification is the server's, and secrets are readable back
# ---------------------------------------------------------------------------


def test_sensitive_keys_are_classified_secret():
    for key in (
        "email.smtp.password",
        "email.resend.api_key",
        "platform.setup_operator_token",
        "some.client_secret",
        "x.private_key",
    ):
        assert is_secret_key(key) is True, f"{key} must be stored encrypted"


def test_ordinary_keys_are_not_classified_secret():
    """The classifier must not sweep everything into secrets,
    which would make every setting unreadable through the normal accessor."""
    for key in ("branding.title", "email.provider", "platform.log_level", "auth.invite_only"):
        assert is_secret_key(key) is False, f"{key} must stay a plain value"


def test_flag_keys_mentioning_password_are_not_secrets():
    """`auth.password.enabled` contains 'password' but is a boolean flag."""
    assert is_secret_key("auth.password.enabled") is False
    assert is_secret_key("auth.password.min_length") is False


def test_caller_cannot_downgrade_a_secret_to_plaintext(db: Session, cache):
    """`is_secret=False` on a sensitive key must not store plaintext."""
    cache.set_value(db, "email.smtp.password", "hunter2", is_secret=False)

    assert cache.get_secret("email.smtp.password") == "hunter2", (
        "value must be retrievable as a secret"
    )
    assert cache.get("email.smtp.password") is None, (
        "a secret leaked into the plaintext accessor — GET /settings masks only "
        "what is flagged secret, so this would be readable back"
    )

    from origin.db import platform_settings as db_settings

    row = db_settings.get(db, "email.smtp.password")
    assert row.is_secret is True
    assert row.value is None, "plaintext column must stay empty for a secret"
    assert row.secret_value and row.secret_value != "hunter2", "must be stored encrypted"


def test_caller_may_still_raise_a_key_to_secret(db: Session, cache):
    """Explicit is_secret=True is honoured for keys the classifier misses."""
    cache.set_value(db, "custom.unclassified", "sensitive", is_secret=True)

    assert cache.get_secret("custom.unclassified") == "sensitive"
    assert cache.get("custom.unclassified") is None


def test_secret_written_is_readable_via_get_secret(db: Session, cache):
    """`get()` never reads `_secrets`, so a secret-stored key is invisible to
    every `get()` caller; `get_secret()` is the accessor that can see it."""
    cache.set_value(db, "platform.setup_operator_token", "tok-abc")

    assert cache.get("platform.setup_operator_token") is None, (
        "documents WHY the promotion was dead: get() cannot see secrets"
    )
    assert cache.get_secret("platform.setup_operator_token") == "tok-abc", (
        "get_secret() is the correct accessor and must return the value"
    )


def test_auth_router_reads_the_operator_token_with_get_secret():
    """The call site must use the accessor that can actually see the value."""
    import ast
    import inspect

    from origin.routers import auth_router

    tree = ast.parse(inspect.getsource(auth_router))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "platform.setup_operator_token"
    ]

    assert calls, "expected a read of platform.setup_operator_token"
    assert all(c.func.attr == "get_secret" for c in calls), (
        "platform.setup_operator_token must be read with get_secret(), not get() "
        "— get() cannot see secrets, which made the promotion dead code"
    )


# ---------------------------------------------------------------------------
# 4. set_many is one transaction
# ---------------------------------------------------------------------------


def test_set_many_writes_all_items_positive_control(db: Session, cache):
    written = cache.set_many(
        db,
        [
            {"key": "branding.title", "value": "Agience", "category": "branding"},
            {"key": "email.provider", "value": "smtp", "category": "email"},
        ],
    )

    assert written == 2
    assert cache.get("branding.title") == "Agience"
    assert cache.get("email.provider") == "smtp"


def test_set_many_does_not_commit_per_item(db: Session, cache):
    """A failure partway through must not leave the batch half-applied."""
    import origin.db.platform_settings as db_settings

    original = db_settings.set_value
    calls = {"n": 0}

    def exploding_set_value(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("boom on the second item")
        return original(*args, **kwargs)

    db_settings.set_value = exploding_set_value
    try:
        with pytest.raises(RuntimeError):
            cache.set_many(
                db,
                [
                    {"key": "branding.title", "value": "First", "category": "branding"},
                    {"key": "email.provider", "value": "smtp", "category": "email"},
                ],
            )
    finally:
        db_settings.set_value = original

    db.rollback()

    assert cache.get("branding.title") != "First", (
        "the first item was cached despite the batch failing — a per-item commit "
        "leaves half-rotated credentials behind"
    )


def test_cache_is_not_updated_before_commit(db: Session, cache):
    """`commit=False` must defer the cache update, not just the DB commit."""
    cache.set_value(db, "branding.title", "Deferred", commit=False)

    assert cache.get("branding.title") != "Deferred", (
        "cache was updated before commit — readers would see a value that can "
        "still be rolled back"
    )

    db.commit()
    cache._apply_to_cache("branding.title", "Deferred", False)
    assert cache.get("branding.title") == "Deferred"


# ---------------------------------------------------------------------------
# 1. Setup token cannot outlive setup
# ---------------------------------------------------------------------------


def test_verify_setup_token_requires_needs_setup(monkeypatch):
    """A surviving token file must not re-open the wizard routes."""
    from fastapi import HTTPException

    from origin.routers import setup_router

    # The exact read-only-mount scenario: token still loadable after setup.
    monkeypatch.setattr(setup_router, "get_setup_token", lambda: "live-token")
    monkeypatch.setattr(setup_router.platform_settings, "needs_setup", lambda: False)

    with pytest.raises(HTTPException) as exc:
        setup_router._verify_setup_token("live-token")

    assert exc.value.status_code == 410, (
        "a valid setup token was accepted after setup completed — "
        "/setup/validate-connection is a full-response SSRF and credential oracle"
    )


def test_verify_setup_token_accepts_during_setup(monkeypatch):
    """The wizard still works before setup completes."""
    from origin.routers import setup_router

    monkeypatch.setattr(setup_router, "get_setup_token", lambda: "live-token")
    monkeypatch.setattr(setup_router.platform_settings, "needs_setup", lambda: True)

    setup_router._verify_setup_token("live-token")  # must not raise


def test_verify_setup_token_rejects_a_wrong_token(monkeypatch):
    from fastapi import HTTPException

    from origin.routers import setup_router

    monkeypatch.setattr(setup_router, "get_setup_token", lambda: "live-token")
    monkeypatch.setattr(setup_router.platform_settings, "needs_setup", lambda: True)

    with pytest.raises(HTTPException) as exc:
        setup_router._verify_setup_token("wrong-token")
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# 5. Refresh re-derives roles
# ---------------------------------------------------------------------------


def test_refresh_grant_recomputes_roles_rather_than_replaying_them():
    """A demoted operator must not keep platform:admin for the refresh lifetime."""
    import ast
    import inspect

    from origin.routers import auth_router

    src = inspect.getsource(auth_router._grant_refresh_token)
    tree = ast.parse(src.lstrip())

    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }

    assert "_compute_roles" in called, (
        "_grant_refresh_token copies claims from the refresh token verbatim. "
        "Refresh tokens live 30 days with no revocation list, so replayed roles "
        "keep a demoted operator as platform:admin for up to a month."
    )

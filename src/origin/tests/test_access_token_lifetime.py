"""How long an access token stays good, and why that number is the one that matters.

It is not a session setting. Peers verify Origin's tokens offline against the inline JWKS in their
authority manifest and never call back — no introspection, no revocation check, no callback of any
kind — so nothing Origin decides about a principal reaches the service that answers for the
principal's data. A token revoked here keeps opening that service until `exp` passes. That makes
`auth_service.access_token_ttl_hours()` the platform's revocation lag.

Five properties this pins:

1. **The window is bracketed**, between the lifetime Origin already hands a machine that renews
   itself and the shift a revocation has to land inside, and it moves when either bound moves. Same
   failure mode `test_sqlite_write_contention` guards: a derivation that returns the same number
   whatever it is handed is a constant in a costume.
2. **The floor is a fact, not a claim.** `_UNATTENDED_RENEWAL_HOURS` says a `client_credentials`
   machine gets an hour; the grant is asked what it actually issues.
3. **What is advertised is what is minted.** `expires_in` and the `exp` claim come from one
   derivation, so a grant cannot promise one lifetime and sign another.
4. **Tokens already in flight need nothing done about them.** Validity is `exp` inside the token
   and nothing reads the current window at verification time, so a deployment converges as the old
   tokens lapse.
5. **The refresh path is not collateral damage.** Shortening the window is only affordable if
   renewing is cheap, so the grant that renews must not re-derive a password hash or spend the
   password limiter's budget.

Positive controls throughout: every bound is paired with a proof that the value satisfies it, so a
derivation that collapsed to zero could not pass by failing everything.
"""

from __future__ import annotations

import importlib
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jose import jwt

from origin.db.session import get_db
from origin.routers.auth_router import auth_router
from origin.services import auth_service, guess_budget
from origin.services.dependencies import AuthContext, get_auth


@pytest.fixture
def signing(monkeypatch, jwt_keypair):
    """Origin's signing keys, and the freshly-loaded modules that use them."""
    monkeypatch.setenv("KEYS_DIR", str(jwt_keypair))
    monkeypatch.setenv("ORIGIN_SKIP_MIGRATIONS", "1")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

    import origin.config as cfg
    import origin.key_manager as km

    importlib.reload(cfg)
    importlib.reload(km)
    km.init_jwt_keys()

    from origin.services import auth_service as svc
    from origin.services import auth_verifier

    importlib.reload(svc)
    importlib.reload(auth_verifier)
    return {"auth_service": svc, "auth_verifier": auth_verifier}


def _claims(token: str) -> dict:
    return jwt.get_unverified_claims(token)


# ---------------------------------------------------------------------------
# The value is bracketed, not picked
# ---------------------------------------------------------------------------


def test_the_window_is_at_least_what_a_machine_that_renews_itself_gets():
    """Lower bound. Nothing in the fleet holds the refresh token — `web/app.js` saves the access
    token alone and Mantle's browse page restarts its PKCE flow on a 401 — so for a person this
    window is the whole sign-in, and its end is a password, an OTP or a passkey. A machine on
    `client_credentials` re-requests silently and gets an hour. Going below that charges a human
    more often than a process that pays nothing."""
    assert auth_service.access_token_ttl_hours() >= auth_service._UNATTENDED_RENEWAL_HOURS


def test_the_window_expires_inside_the_shift_a_revocation_lands_in():
    """Upper bound. A lag at or above a working day is an operator revoking a credential in the
    morning and watching it keep working until evening — the control exists, but not within the
    incident it was reached for."""
    assert auth_service.access_token_ttl_hours() < auth_service._WORKING_DAY_HOURS


def test_the_window_tracks_the_shift(monkeypatch):
    """A shorter shift must shorten the lag it bounds.

    The failure mode: a "derivation" that returns the same number whatever it is handed is a
    constant in a costume. Replacing the body with `return 4.0` fails here.
    """
    base = auth_service.access_token_ttl_hours()
    monkeypatch.setattr(auth_service, "_WORKING_DAY_HOURS", 2.0)
    assert auth_service.access_token_ttl_hours() < base
    monkeypatch.setattr(auth_service, "_WORKING_DAY_HOURS", 24.0)
    assert auth_service.access_token_ttl_hours() > base


def test_the_window_is_meaningfully_shorter_than_the_shift_and_not_merely_under_it():
    """The bound is "lands inside the shift", which a value one minute under would satisfy while
    meaning nothing. Half leaves the same margin again spare: revoke at the start of a shift and
    the token is dead by the middle of it."""
    assert auth_service.access_token_ttl_hours() <= auth_service._WORKING_DAY_HOURS / 2


# ---------------------------------------------------------------------------
# The floor is what that grant actually issues
# ---------------------------------------------------------------------------


def test_the_unattended_floor_is_the_lifetime_the_machine_grant_really_hands_out():
    """`_UNATTENDED_RENEWAL_HOURS` states a fact about `_grant_client_credentials`, so the grant is
    asked. A floor derived from a lifetime that has since moved is a floor under nothing."""
    app = FastAPI()
    app.include_router(auth_router)
    app.dependency_overrides[get_auth] = lambda: AuthContext()
    app.dependency_overrides[get_db] = lambda: MagicMock()

    credential = type(
        "Cred",
        (),
        {
            "is_active": True,
            "secret_hash": "$2b$12$stub",
            "id": "cred-1",
            "client_id": "machine",
            "authority": "test",
            "host_id": "host-1",
            "server_id": "server-1",
            "scopes": [],
            "resource_filters": {},
        },
    )()

    with patch(
        "origin.routers.auth_router.db_server_credentials.get_by_client_id",
        return_value=credential,
    ), patch(
        "origin.routers.auth_router.bcrypt.checkpw", return_value=True
    ), patch(
        "origin.routers.auth_router.db_server_credentials.update_last_used"
    ), patch(
        "origin.routers.auth_router.create_jwt_token", return_value="machine.jwt"
    ):
        resp = TestClient(app).post(
            "/auth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "machine",
                "client_secret": "s",
            },
        )

    assert resp.status_code == 200, resp.text
    assert resp.json()["expires_in"] == int(auth_service._UNATTENDED_RENEWAL_HOURS * 3600)


# ---------------------------------------------------------------------------
# What is advertised is what is minted
# ---------------------------------------------------------------------------


def test_the_advertised_lifetime_is_the_one_the_token_carries(signing):
    """`expires_in` and the `exp` claim came from separate literals, which is a grant free to
    promise one lifetime and sign another. Both now read the same derivation."""
    svc = signing["auth_service"]
    claims = _claims(svc.create_jwt_token({"sub": "u1"}))

    assert round(claims["exp"] - claims["iat"]) == svc.access_token_expires_in_seconds()


def test_every_user_grant_advertises_that_same_number():
    """The five `expires_in` sites in `auth_router` are the four sign-in paths and the refresh
    grant. A literal surviving at any of them is that path desynchronizing on the next change."""
    import inspect

    from origin.routers import auth_router as mod

    source = inspect.getsource(mod)
    assert "3600 * 12" not in source
    assert source.count('"expires_in": access_token_expires_in_seconds()') == 5


# ---------------------------------------------------------------------------
# Tokens already in flight
# ---------------------------------------------------------------------------


def test_a_token_keeps_the_lifetime_it_was_minted_with(signing):
    """Nothing reads the current window at verification time, so shortening it does not shorten a
    token already in a browser and does not invalidate one either. The fleet converges as the old
    tokens lapse, within one old lifetime, with nothing to run."""
    svc, verifier = signing["auth_service"], signing["auth_verifier"]
    long_lived = svc.create_jwt_token({"sub": "u1", "aud": "agience"}, expires_hours=12)

    claims = _claims(long_lived)
    assert round(claims["exp"] - claims["iat"]) == 12 * 3600
    assert verifier.verify_token(long_lived, expected_audience="agience") is not None


def test_verification_consults_no_revocation_state(signing):
    """Why the window is the lag. Verification is the token, a public key and a clock — there is no
    store to mark, so a subject Origin has no record of verifies exactly as well as one it does."""
    svc, verifier = signing["auth_service"], signing["auth_verifier"]
    stranger = svc.create_jwt_token({"sub": "nobody-has-this-id", "aud": "agience"})

    assert verifier.verify_token(stranger, expected_audience="agience") is not None


# ---------------------------------------------------------------------------
# Renewing must stay cheap
# ---------------------------------------------------------------------------


def test_renewing_neither_hashes_a_password_nor_spends_the_guess_budget():
    """A shorter window is only affordable if renewing is cheap. The refresh grant verifies an RSA
    signature and re-derives roles from a settings lookup; it must not reach the PBKDF2 path, and it
    must not be counted by the limiter that guards the password endpoints — which would throttle a
    renewing client into a 429 for holding a valid credential."""
    import inspect

    from origin.routers import auth_router as mod

    source = inspect.getsource(mod._grant_refresh_token)

    for forbidden in ("verify_password", "hash_password", "dummy_verify_password"):
        assert forbidden not in source, f"the refresh path reaches {forbidden}"
    for forbidden in ("guess_budget", "_reject_if_password_budget_spent", "_charge_password_failure"):
        assert forbidden not in source, f"the refresh path is metered by {forbidden}"

    # Positive control: the limiter it must not touch is real and does fire elsewhere.
    assert guess_budget.password_window_cap() >= 1

"""Password sign-in is rate limited, from a budget derived rather than typed in.

The OTP path bounds blind guessing from a stated attacker-success probability, and the password
path is held to the same derivation. Without it, PBKDF2's few hundred milliseconds is the whole of
the friction and a known username can be ground at whatever rate the box will serve. Anti-enumeration
does not help here: it stops an attacker *finding* an account, not working on one they already
know.

Four properties this pins:

1. **The cap is derived**, from `guess_budget`'s stated tolerance and candidate space, and moves
   when either input moves. Same failure mode `test_otp_bruteforce_and_stall` guards: a function
   that returns the same number whatever it is handed is a constant in a costume.
2. **There is one derivation, not two.** `otp_service` and the password path compute their caps
   through the same functions. Two copies of the arithmetic is one copy going stale.
3. **The limiter actually fires**, on both password endpoints, and stops charging once the
   credential proves correct.
4. **It does not become an account oracle.** A username that exists and one that does not are
   throttled on identical schedules, which is the whole reason the budget is keyed on the
   submitted string rather than on a resolved person.

Positive controls throughout: every "is refused" here is paired with a proof that the legitimate
attempt still succeeds. A suite that only asserts refusal passes just as happily when everything is
refused.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from origin.db.session import get_db
from origin.routers.auth_router import auth_router
from origin.services import guess_budget, otp_service


def _person(**overrides):
    base = dict(
        id=uuid.uuid4(),
        username="alice",
        email="alice@example.com",
        name="Alice",
        picture=None,
        password_hash="pbkdf2_sha256$600000$c2FsdA$aGFzaA",
        email_verified=True,
        preferences={},
        created_time=None,
        modified_time=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.fixture(autouse=True)
def _fresh_budget():
    guess_budget.reset()
    yield
    guess_budget.reset()


@pytest.fixture
def anon_client():
    app = FastAPI()
    app.include_router(auth_router)
    app.dependency_overrides[get_db] = lambda: SimpleNamespace(
        commit=lambda: None, rollback=lambda: None
    )
    with TestClient(app) as c:
        yield c


def _login(client, identifier="alice", password="wrong"):
    return client.post(
        "/auth/password/login", json={"identifier": identifier, "password": password}
    )


# ---------------------------------------------------------------------------
# 1. The cap is derived, and moves with its inputs
# ---------------------------------------------------------------------------


def test_the_cap_tracks_the_stated_guess_probability(monkeypatch):
    """Widen the tolerance, the budget widens. Tighten it, it tightens."""
    base = guess_budget.password_window_cap()
    assert base > 0

    monkeypatch.setattr(
        guess_budget,
        "_PASSWORD_MAX_GUESS_PROBABILITY_PER_WINDOW",
        guess_budget._PASSWORD_MAX_GUESS_PROBABILITY_PER_WINDOW * 10,
    )
    assert guess_budget.password_window_cap() > base, (
        "a 10x looser tolerance left the password cap unchanged — it is not derived from it"
    )

    monkeypatch.setattr(
        guess_budget,
        "_PASSWORD_MAX_GUESS_PROBABILITY_PER_WINDOW",
        guess_budget._PASSWORD_MAX_GUESS_PROBABILITY_PER_WINDOW / 100,
    )
    assert guess_budget.password_window_cap() < base


def test_the_cap_tracks_the_candidate_space(monkeypatch):
    """A larger space is a weaker guess per draw, so the same stated risk buys more draws.

    A cap that ignores the space is not bounding a probability at all — it is a number.
    """
    base = guess_budget.password_window_cap()
    monkeypatch.setattr(guess_budget, "_PASSWORD_GUESS_SPACE", guess_budget._PASSWORD_GUESS_SPACE * 100)
    assert guess_budget.password_window_cap() > base
    monkeypatch.setattr(guess_budget, "_PASSWORD_GUESS_SPACE", 100)
    assert guess_budget.password_window_cap() < base


def test_the_cap_holds_the_stated_probability_across_inputs(monkeypatch):
    """The invariant, not the number: whatever the inputs, one window's draws never exceed the
    stated probability of the candidate space."""
    for prob in (1e-3, 1e-4, 5e-3):
        for space in (10_000, 1_000, 1_000_000):
            monkeypatch.setattr(guess_budget, "_PASSWORD_MAX_GUESS_PROBABILITY_PER_WINDOW", prob)
            monkeypatch.setattr(guess_budget, "_PASSWORD_GUESS_SPACE", space)
            draws = guess_budget.password_window_cap()
            assert draws <= max(1, int(prob * space)), (
                f"{draws} draws exceeds the stated {prob} of a {space} space"
            )


def test_the_shipped_cap_is_what_the_shipped_inputs_produce():
    """The value assertion, kept last and small: on its own it proves nothing."""
    assert guess_budget.password_window_cap() == 10


# ---------------------------------------------------------------------------
# 2. One derivation, shared with the OTP limiter
# ---------------------------------------------------------------------------


def test_otp_reads_its_caps_through_the_shared_derivation(monkeypatch):
    """`otp_service` must compute through `guess_budget`, not from its own copy of the arithmetic.

    Breaking the shared function has to break the OTP caps too — that is what says there is one
    implementation. If `otp_service` had kept its own expression this would pass unchanged while
    the two limiters drifted.
    """
    monkeypatch.setattr(guess_budget, "draws_per_window", lambda p, space: 999)
    assert otp_service._max_draws_per_window() == 999, (
        "otp_service still computes its own draw budget — there are two derivations"
    )


def test_the_password_path_reads_the_same_derivation(monkeypatch):
    monkeypatch.setattr(guess_budget, "draws_per_window", lambda p, space: 42)
    assert guess_budget.password_window_cap() == 42


def test_a_budget_is_never_zero(monkeypatch):
    """A limiter that admits no attempt at all is an outage, not a rate limit."""
    monkeypatch.setattr(guess_budget, "_PASSWORD_MAX_GUESS_PROBABILITY_PER_WINDOW", 1e-30)
    assert guess_budget.password_window_cap() >= 1


# ---------------------------------------------------------------------------
# 3. The counter itself
# ---------------------------------------------------------------------------


def test_failures_accumulate_to_the_cap_and_then_stop_the_identifier():
    cap = guess_budget.password_window_cap()
    for _ in range(cap - 1):
        guess_budget.record_password_failure("alice")
    assert guess_budget.password_attempts_exhausted("alice") is False, (
        "one draw short of the cap must still be allowed — a positive control on the counter"
    )

    guess_budget.record_password_failure("alice")
    assert guess_budget.password_attempts_exhausted("alice") is True


def test_the_window_expires_so_a_burst_is_not_a_permanent_lockout():
    cap = guess_budget.password_window_cap()
    stale = datetime.now(timezone.utc) - guess_budget._PASSWORD_WINDOW - timedelta(seconds=1)
    for _ in range(cap * 2):
        guess_budget.record_password_failure("alice", now=stale)

    assert guess_budget.password_attempts_exhausted("alice") is False, (
        "failures older than the window must fall out, or one bad afternoon locks a user out "
        "forever"
    )


def test_success_clears_the_budget():
    cap = guess_budget.password_window_cap()
    for _ in range(cap):
        guess_budget.record_password_failure("alice")
    assert guess_budget.password_attempts_exhausted("alice") is True

    guess_budget.clear_password_failures("alice")
    assert guess_budget.password_attempts_exhausted("alice") is False, (
        "a user who mistypes to the cap and then succeeds must not stay throttled — that is a "
        "lockout wearing a rate limit's name"
    )


def test_the_budget_is_scoped_per_identifier():
    """One account under attack must not lock out everyone else."""
    for _ in range(guess_budget.password_window_cap()):
        guess_budget.record_password_failure("victim")

    assert guess_budget.password_attempts_exhausted("victim") is True
    assert guess_budget.password_attempts_exhausted("bystander") is False


def test_the_budget_is_case_insensitive():
    """Otherwise the cap is multiplied by however many ways the name can be capitalized."""
    for _ in range(guess_budget.password_window_cap()):
        guess_budget.record_password_failure("Alice")
    assert guess_budget.password_attempts_exhausted("aLiCe") is True


def test_tracked_identifiers_are_bounded(monkeypatch):
    """The counter is reachable unauthenticated and keyed by caller-supplied text.

    Unbounded, a spray of distinct identifiers is a memory-growth attack on the control meant to
    stop the attack.
    """
    monkeypatch.setattr(guess_budget, "_MAX_TRACKED_IDENTIFIERS", 50)
    for i in range(500):
        guess_budget.record_password_failure(f"user-{i}")
    assert len(guess_budget._failures) <= 50


# ---------------------------------------------------------------------------
# 4. Both endpoints enforce it, and it is not an account oracle
# ---------------------------------------------------------------------------


def test_password_login_throttles_after_the_cap(anon_client):
    cap = guess_budget.password_window_cap()
    with patch(
        "origin.routers.auth_router.platform_settings.get_bool", return_value=True
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_username",
        return_value=_person(),
    ), patch(
        "origin.routers.auth_router.verify_password", return_value=False
    ):
        codes = [_login(anon_client).status_code for _ in range(cap)]
        assert codes == [401] * cap, (
            "every attempt inside the budget must reach the credential check — a positive control"
        )
        assert _login(anon_client).status_code == 429


def test_the_throttle_refuses_before_the_key_derivation_runs(anon_client):
    """The refusal must not cost Origin a PBKDF2.

    An unthrottled password endpoint is a CPU amplifier — one unauthenticated request buys hundreds
    of milliseconds of key derivation. A limit applied after the derivation bounds the guessing and
    not the amplification.
    """
    for _ in range(guess_budget.password_window_cap()):
        guess_budget.record_password_failure("alice")

    with patch(
        "origin.routers.auth_router.platform_settings.get_bool", return_value=True
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_username"
    ) as lookup, patch(
        "origin.routers.auth_router.verify_password"
    ) as verify, patch(
        "origin.routers.auth_router.dummy_verify_password"
    ) as dummy:
        assert _login(anon_client).status_code == 429

    verify.assert_not_called()
    dummy.assert_not_called()
    lookup.assert_not_called()


def test_an_unknown_identifier_throttles_on_the_same_schedule(anon_client):
    """The throttle must not become the account oracle anti-enumeration closed.

    A 429 that arrives only for identifiers naming a real account answers the one question the
    dummy-verify and the identical 401 exist to refuse.
    """
    cap = guess_budget.password_window_cap()
    with patch(
        "origin.routers.auth_router.platform_settings.get_bool", return_value=True
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_username", return_value=None
    ):
        known = [_login(anon_client, identifier="ghost").status_code for _ in range(cap + 1)]

    assert known[:-1] == [401] * cap
    assert known[-1] == 429, (
        "an identifier naming no account went unthrottled while a real one was throttled — the "
        "rate limiter is now an account-existence oracle"
    )


def test_a_throttled_response_says_nothing_about_the_account(anon_client):
    """Same status, same body, whether or not the identifier names anything."""
    cap = guess_budget.password_window_cap()
    with patch(
        "origin.routers.auth_router.platform_settings.get_bool", return_value=True
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_username",
        return_value=_person(),
    ), patch(
        "origin.routers.auth_router.verify_password", return_value=False
    ):
        for _ in range(cap):
            _login(anon_client, identifier="real")
        real = _login(anon_client, identifier="real")

    guess_budget.reset()
    with patch(
        "origin.routers.auth_router.platform_settings.get_bool", return_value=True
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_username", return_value=None
    ):
        for _ in range(cap):
            _login(anon_client, identifier="ghost")
        ghost = _login(anon_client, identifier="ghost")

    assert real.status_code == ghost.status_code == 429
    assert real.json() == ghost.json()


def test_the_authorize_password_endpoint_shares_the_same_budget(anon_client):
    """Two password endpoints must not be two budgets.

    `/authorize/password` proves the same credential as `/auth/password/login` by a different
    route; a budget it counted into separately would be the same budget handed to the attacker
    twice, and a limiter that can be halved by changing URL is not a limiter.
    """
    for _ in range(guess_budget.password_window_cap()):
        guess_budget.record_password_failure("alice")

    with patch(
        "origin.routers.auth_router._pop_local_auth_request", return_value={}
    ), patch(
        "origin.routers.auth_router.platform_settings.get_bool", return_value=True
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_username"
    ) as lookup:
        resp = anon_client.post(
            "/auth/authorize/password",
            json={"oauth_state": "s", "identifier": "alice", "password": "x"},
        )

    assert resp.status_code == 429
    lookup.assert_not_called()


def test_a_successful_login_clears_what_the_failures_charged(anon_client):
    """End to end: mistype to one short of the cap, then succeed, then mistype again freely."""
    cap = guess_budget.password_window_cap()
    with patch(
        "origin.routers.auth_router.platform_settings.get_bool", return_value=True
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_username",
        return_value=_person(),
    ), patch(
        "origin.routers.auth_router._compute_roles", return_value=[]
    ), patch(
        "origin.routers.auth_router._upgrade_password_hash_if_stale"
    ), patch(
        "origin.routers.auth_router.person_service.record_person_event"
    ), patch(
        "origin.routers.auth_router.create_jwt_token", side_effect=["a.jwt", "r.jwt"]
    ), patch(
        "origin.routers.auth_router.verify_password", side_effect=[False] * (cap - 1) + [True]
    ):
        for _ in range(cap - 1):
            assert _login(anon_client).status_code == 401
        assert _login(anon_client, password="right").status_code == 200

    assert guess_budget.password_attempts_exhausted("alice") is False

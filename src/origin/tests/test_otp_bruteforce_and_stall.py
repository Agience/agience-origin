"""OTP: bounded brute force, single-code verification, bcrypt off the event loop.

Three properties this pins, covering one route pair:

1. **Guessing is capped, requesting is not what is counted.** `count_recent_misses` counts
   every wrong guess against an address's codes in the window, and a new code is refused once its
   attempts could carry them past the draw budget. A code nobody guesses at counts nothing, so
   asking for codes cannot use up the codes the address's owner is due.
2. **Verification targets exactly one code.** The lookup returns a single row, not a list, so a
   guess is checked against one bcrypt hash rather than every live code.
3. **The bcrypt comparison runs off the event loop.** `verify_otp` is a coroutine the router
   awaits, so the comparison (~100ms) does not stall other requests on the loop.

Positive controls: every "is rejected" assertion below is paired with a proof
that the legitimate flow still succeeds. A suite that only asserts rejection passes just as
happily when everything is rejected.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from origin.db import otp_codes as db_otp
from origin.db.base import Base
from origin.services import otp_service


@pytest.fixture
def db() -> Session:
    import origin.models  # noqa: F401 — registers models on Base.metadata

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        yield session


def _issue(db: Session, email: str, code: str, *, minutes_ago: int = 0, used: bool = False,
           attempts: int = 0):
    now = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return db_otp.create(
        db,
        {
            "email": email,
            "code_hash": otp_service._hash_code(code),
            "expires_at": now + timedelta(minutes=otp_service._OTP_EXPIRY_MINUTES),
            "attempts": attempts,
            "used": used,
            "created_time": now,
        },
    )


# ---------------------------------------------------------------------------
# 1. Verification tests exactly one code
# ---------------------------------------------------------------------------


def test_correct_code_verifies_positive_control(db: Session):
    """The happy path succeeds: a freshly-issued code verifies."""
    _issue(db, "user@example.com", "123456")
    db.flush()

    otp = db_otp.get_latest_valid_for_email(db, "user@example.com", 3)

    assert otp is not None, "a live code must be findable"
    assert otp_service._verify_code_hash("123456", otp.code_hash) is True


def test_only_the_newest_code_is_live(db: Session):
    """Issuing supersedes earlier codes, so verification has exactly one target.

    Without this invariant, a single-code lookup would be merely cheaper rather
    than correct — older codes would linger and stay guessable.
    """
    _issue(db, "user@example.com", "111111", minutes_ago=2)
    _issue(db, "user@example.com", "222222", minutes_ago=1)
    db.flush()

    superseded = db_otp.supersede_live_for_email(db, "user@example.com")
    _issue(db, "user@example.com", "333333")
    db.flush()

    assert superseded == 2, "both earlier codes should have been retired"

    live = db_otp.get_latest_valid_for_email(db, "user@example.com", 3)
    assert live is not None
    assert otp_service._verify_code_hash("333333", live.code_hash) is True
    assert otp_service._verify_code_hash("111111", live.code_hash) is False


def test_get_latest_returns_a_single_row_not_a_list(db: Session):
    """The lookup must be single-valued; a list is what let N bcrypts happen."""
    for i in range(5):
        _issue(db, "user@example.com", f"{i:06d}", minutes_ago=i)
    db.flush()

    result = db_otp.get_latest_valid_for_email(db, "user@example.com", 3)

    assert result is not None
    assert not isinstance(result, list), "verification must target one code, not many"


# ---------------------------------------------------------------------------
# 2. Guessing is actually capped
# ---------------------------------------------------------------------------


def _since():
    return datetime.now(timezone.utc) - timedelta(minutes=otp_service._ISSUE_WINDOW_MINUTES)


def test_the_miss_counter_counts_guesses_not_codes(db: Session):
    """Untried codes count nothing; each guess counts one, on used and superseded codes alike."""
    for i in range(10):
        _issue(db, "user@example.com", f"{i:06d}")
    _issue(db, "user@example.com", "100000", attempts=3)
    _issue(db, "user@example.com", "100001", attempts=2, used=True)
    db.flush()

    assert db_otp.count_recent_misses(db, "user@example.com", _since()) == 3 + 2


def test_the_miss_counter_respects_the_window(db: Session):
    """Old guesses fall out of the window, so a person is not locked out forever after one burst."""
    for i in range(10):
        _issue(db, "user@example.com", f"{i:06d}", minutes_ago=60, attempts=3)
    db.flush()

    assert db_otp.count_recent_misses(db, "user@example.com", _since()) == 0


def test_the_miss_counter_is_scoped_per_email(db: Session):
    """One address's burst must not lock out an unrelated user."""
    for i in range(10):
        _issue(db, "attacker@example.com", f"{i:06d}", attempts=3)
    db.flush()

    assert db_otp.count_recent_misses(db, "attacker@example.com", _since()) == 30
    assert db_otp.count_recent_misses(db, "victim@example.com", _since()) == 0


def test_a_new_code_is_refused_once_its_attempts_could_pass_the_draw_budget(db: Session):
    """The bound itself: whatever codes were issued, a window never yields more draws than the
    stated tolerance buys. Positive control first: one guess short of the edge still gets a code."""
    budget = otp_service._max_draws_per_window()
    per_code = otp_service._MAX_ATTEMPTS_PER_CODE
    now = datetime.now(timezone.utc)

    _issue(db, "user@example.com", "000000", attempts=budget - per_code)
    db.flush()
    assert otp_service._limit_reached(db, "user@example.com", now) is None

    _issue(db, "user@example.com", "000001", attempts=1)
    db.flush()
    assert otp_service._limit_reached(db, "user@example.com", now) == "guess-rate"


def test_requesting_codes_alone_never_locks_the_owner_out(db: Session):
    """Codes nobody guessed at, however many, leave the owner's next code available. A cap on
    issued codes let one client asking for codes use up the owner's."""
    for i in range(otp_service._window_cap() * 4):
        _issue(db, "owner@example.com", f"{i:06d}")
    db.flush()

    assert otp_service._limit_reached(db, "owner@example.com", datetime.now(timezone.utc)) is None


def test_issuance_cap_is_configured_below_the_old_effective_infinity():
    assert otp_service._window_cap() > 0
    assert otp_service._window_cap() <= 10, (
        "cap must be low enough to bound the draw count meaningfully"
    )


# ---------------------------------------------------------------------------
# 3. bcrypt is off the event loop
# ---------------------------------------------------------------------------


def test_verify_otp_is_a_coroutine():
    """A sync `verify_otp` called from an `async def` handler blocks the loop."""
    assert inspect.iscoroutinefunction(otp_service.verify_otp), (
        "verify_otp must be awaitable so bcrypt can be moved off the event loop"
    )


def test_router_awaits_verify_otp():
    """The handler must actually await it — a forgotten await returns a coroutine
    object, which is truthy, and would authenticate everyone."""
    import ast
    from pathlib import Path

    src = Path(otp_service.__file__).parent.parent / "routers" / "otp_router.py"
    tree = ast.parse(src.read_text(encoding="utf-8-sig"))

    awaited = {
        node.value.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Await)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
    }

    assert "verify_otp" in awaited, "otp_router must `await otp_service.verify_otp(...)`"


def test_event_loop_is_not_blocked_during_verification(db: Session):
    """The loop keeps ticking during bcrypt.

    A comparison that ran inline on the loop would block a concurrent task until it finished.
    bcrypt is ~100ms; the ticker below should still get many turns during it.
    """
    _issue(db, "user@example.com", "123456")
    db.commit()

    async def scenario() -> int:
        ticks = 0
        stop = False

        async def ticker():
            nonlocal ticks
            while not stop:
                ticks += 1
                await asyncio.sleep(0.001)

        task = asyncio.ensure_future(ticker())
        await asyncio.sleep(0)  # let the ticker start

        # Wrong code on purpose: exercises the bcrypt path without needing the
        # person-creation machinery.
        await otp_service.verify_otp(db, "user@example.com", "000000")

        stop = True
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        return ticks

    ticks = asyncio.run(scenario())

    assert ticks > 1, (
        f"event loop got only {ticks} tick(s) during bcrypt — the comparison is "
        "still running on the loop, so one unauthenticated request stalls Origin"
    )


def test_missing_code_still_costs_a_bcrypt(db: Session):
    """No-live-code and wrong-code must cost the same, or timing reveals which."""
    start = time.perf_counter()
    result = asyncio.run(otp_service.verify_otp(db, "nobody@example.com", "000000"))
    elapsed = time.perf_counter() - start

    assert result is None
    assert elapsed > 0.005, (
        "the no-code path returned too fast — response time distinguishes "
        "'no code outstanding' from 'wrong code'"
    )


# ── The rate-limit caps are derived, and these tests prove it ────────────────────────────
# `_window_cap()` computes the cap from `_MAX_GUESS_PROBABILITY_PER_WINDOW` (the module's one
# stated tolerance) and `_CODE_SPACE` (a specification fixed by `_generate_code`), rather than
# returning a fixed constant.
#
# The failure mode these tests catch: a "derivation" that returns the same number whatever it is
# handed is a constant wearing a function. Each test below perturbs a module-level input and
# asserts `_window_cap()` moves, which only works because the cap is computed each time it is
# asked for. Replacing the body with `return 5` fails both of the tracking tests below.


def test_the_otp_caps_track_the_stated_guess_probability(monkeypatch):
    """Widen the tolerance, the cap must widen. Tighten it, it must tighten."""
    base = otp_service._window_cap()
    assert base > 0

    monkeypatch.setattr(otp_service, "_MAX_GUESS_PROBABILITY_PER_WINDOW",
                        otp_service._MAX_GUESS_PROBABILITY_PER_WINDOW * 10)
    assert otp_service._window_cap() > base, (
        "a 10x looser guess-probability tolerance left the code cap unchanged — the cap is "
        "not derived from it"
    )

    monkeypatch.setattr(otp_service, "_MAX_GUESS_PROBABILITY_PER_WINDOW",
                        base and 1.5e-6)
    assert otp_service._window_cap() < base, (
        "a 10x tighter guess-probability tolerance left the code cap unchanged"
    )


def test_the_otp_caps_track_the_code_space(monkeypatch):
    """A larger code space is a weaker guess per draw, so the same stated risk buys more draws.
    A cap that ignores the space is not bounding a probability at all."""
    base = otp_service._window_cap()
    monkeypatch.setattr(otp_service, "_CODE_SPACE", otp_service._CODE_SPACE * 100)
    assert otp_service._window_cap() > base, (
        "growing the code space 100x did not widen the draw budget"
    )
    monkeypatch.setattr(otp_service, "_CODE_SPACE", 10_000)
    assert otp_service._window_cap() < base


def test_the_attempts_partition_the_budget_rather_than_enlarging_it(monkeypatch):
    """More attempts per code must buy fewer codes, not more draws. If both moved the same way the
    budget would not be a budget."""
    draws_before = otp_service._max_draws_per_window()
    cap_before = otp_service._window_cap()
    monkeypatch.setattr(otp_service, "_MAX_ATTEMPTS_PER_CODE",
                        otp_service._MAX_ATTEMPTS_PER_CODE * 3)
    assert otp_service._max_draws_per_window() == draws_before, (
        "tripling attempts-per-code enlarged the DRAW budget — attempts are supposed to partition "
        "it, not extend it"
    )
    assert otp_service._window_cap() < cap_before


def test_the_cap_holds_the_stated_probability_across_inputs(monkeypatch):
    """The invariant, not the number: whatever the inputs, one window's draws never exceed the
    stated probability of the code space (plus at most one code's worth from integer flooring)."""
    for prob in (1.5e-5, 1e-4, 1e-3, 5e-6):
        for space in (1_000_000, 10_000, 100_000_000):
            for att in (1, 3, 8):
                monkeypatch.setattr(otp_service, "_MAX_GUESS_PROBABILITY_PER_WINDOW", prob)
                monkeypatch.setattr(otp_service, "_CODE_SPACE", space)
                monkeypatch.setattr(otp_service, "_MAX_ATTEMPTS_PER_CODE", att)
                draws = otp_service._window_cap() * att
                assert draws <= max(att, int(prob * space) + att), (
                    f"{draws} draws exceeds the stated {prob} of a {space} space"
                )


def test_the_shipped_cap_is_what_the_shipped_inputs_produce():
    """The value assertion, kept last and small: on its own it proves nothing — the tests above are
    what say the number is derived."""
    assert otp_service._window_cap() == 5
    assert otp_service._max_draws_per_window() == 15



@pytest.mark.parametrize("guesses_per_code", [1, 2, 3])
def test_no_schedule_of_codes_and_guesses_exceeds_the_draw_budget(db: Session, monkeypatch,
                                                                  guesses_per_code):
    """End to end through `issue_otp` and `verify_otp`: request a code, guess at it, request
    another, however many times. Replacing a code retires it as `used`, and a count that treated
    `used` as verified handed those guesses back. The total guesses taken must stay within the
    budget whatever the schedule."""
    async def fast_hash(code):
        return "$2b$04$" + "x" * 53

    async def never_matches(code, code_hash):
        return False

    monkeypatch.setattr(otp_service, "_hash_code_async", fast_hash)
    monkeypatch.setattr(otp_service, "_verify_code_hash_async", never_matches)

    async def schedule():
        for _ in range(60):
            if await otp_service.issue_otp(db, "target@example.com") is None:
                continue
            for _ in range(guesses_per_code):
                await otp_service.verify_otp(db, "target@example.com", "000000")

    asyncio.run(schedule())
    taken = sum(r.attempts for r in db.query(db_otp.OtpCode).filter_by(email="target@example.com"))
    assert taken <= otp_service._max_draws_per_window(), (
        f"{taken} guesses in one window against a budget of {otp_service._max_draws_per_window()}")
    assert taken > 0, "the schedule never reached a guess"

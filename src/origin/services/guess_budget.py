"""One derivation of "how many guesses does a window buy an attacker", and the store the
password paths count their guesses in.

Caps are computed from a stated attacker-guess probability rather than typed in. The derivation
lives here and both `otp_service` and the password paths call it with their own inputs, so there is
one implementation of the arithmetic and not two that can drift.

The two limiters differ in where they count, and the difference is not stylistic:

* OTP counts in the database, because an OTP *is* a row — `otp_codes` records every code issued and
  every attempt spent against it, so `count_recent_issued` and `count_recent_failed` are reading
  the attacker's draws off a ledger that exists for other reasons.
* A password attempt leaves no row. Nothing in Origin's schema records a failed sign-in, so there
  is no ledger to read and the OTP counters cannot be pointed at the password path — they count
  `OtpCode` rows keyed by email, and a password attempt produces neither. Giving passwords their
  own table would mean a model, a migration and a reaper, for state whose whole useful life is
  fifteen minutes.

So the counting lives in this process, in `_failures` below, alongside `authorization_codes` and
`pkce_challenges` in `auth_router` — which are process-local for the same reason and are already
load-bearing for every OAuth sign-in Origin completes. This adds no assumption Origin was not
already making: `main._refuse_multiple_workers` refuses to boot multi-worker, and a second worker
would already break the authorization-code flow long before it weakened this.
A deployment that ever fans Origin out across processes must move all three together, and the
right shape then is a shared store, not three private ones.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# The derivation — shared with `otp_service`
# ---------------------------------------------------------------------------
def draws_per_window(max_guess_probability: float, space: int) -> int:
    """Every guess a window is allowed to buy, derived from a stated tolerance and a space.

    The guess probability is `draws / space` — each guess is one draw from the candidate space —
    so the budget is that probability times the space. Never zero: a limiter that admits no
    attempt at all is a denial of service on the legitimate user, not a rate limit.
    """
    return max(1, int(max_guess_probability * space))


def window_cap(max_guess_probability: float, space: int, draws_per_unit: int) -> int:
    """The draw budget divided by what one countable unit costs in draws.

    `draws_per_unit` is how the budget is partitioned, not how large it is: OTP counts codes and
    spends `_MAX_ATTEMPTS_PER_CODE` draws on each, so it divides; the password path counts the
    draws themselves and passes 1, which is the same arithmetic with the partition set to none.

    Computed at the call site rather than frozen at import, for the reason `otp_service` gives:
    a module constant assigned from an expression is indistinguishable from the same number typed
    in, and a test can only tell the two apart by perturbing an input and watching.
    """
    return max(1, draws_per_window(max_guess_probability, space) // max(1, draws_per_unit))


# ---------------------------------------------------------------------------
# Password login — the stated inputs
# ---------------------------------------------------------------------------

#: The candidate space an online password guesser actually works from.
#:
#: Not `alphabet ** auth.password.min_length`. That number is astronomically large and derives a
#: cap that bounds nothing, because it assumes passwords are drawn uniformly from the policy space.
#: They are not: an online attacker walks a ranked list of breached passwords and stops early or
#: not at all.
#:
#: So the space is stated as the pessimistic floor instead: the size of the published
#: common-password blocklists that NIST SP 800-63B requires memorized secrets to be screened
#: against. Origin performs no such screening today, so that list is exactly the set of passwords a
#: user may still be holding and an attacker will try first. Adding blocklist screening at
#: registration is what would let this number be raised; until then it is the honest one.
_PASSWORD_GUESS_SPACE = 10_000

#: The one stated tolerance of the password limiter — the same question `otp_service` asks, in the
#: same units: what chance of a successful guess, per window, against one *known* account, is
#: Origin willing to hand an attacker?
#:
#: It reads looser than OTP's 1.5e-5 and is not comparable to it, because the spaces are not
#: comparable. OTP's space is genuinely uniform, so its probability is exact for every user. This
#: one is a probability against the *worst* user Origin has — someone whose password sits in the
#: blocklist. For any user outside that list the real per-window probability is smaller by many
#: orders of magnitude, since the space they are drawn from is the full policy space.
#:
#: A different value is right if the cost of a compromised password changes, or if screening lands
#: and `_PASSWORD_GUESS_SPACE` stops being a floor.
_PASSWORD_MAX_GUESS_PROBABILITY_PER_WINDOW = 1e-3

#: How long a window lasts. Sets the *rate*, given the cap: a shorter window with the same cap is a
#: faster attack, so this is not a free knob. At the shipped values an attacker gets
#: `password_window_cap()` guesses per 15 minutes against one identifier — 960 a day, so covering
#: `_PASSWORD_GUESS_SPACE` takes on the order of ten days of continuous, logged failures against a
#: single account rather than the seconds it takes unthrottled.
_PASSWORD_WINDOW = timedelta(minutes=15)

#: A password attempt is one draw. Unlike an OTP code, it is not a container that several guesses
#: are spent against, so there is nothing to partition and the cap is the draw budget itself.
_PASSWORD_DRAWS_PER_ATTEMPT = 1

#: Ceiling on how many identifiers are tracked at once. The counter is reachable unauthenticated
#: and keyed by whatever string the caller submits, so without a bound a spray of distinct
#: identifiers is a memory-growth attack on the control that is supposed to stop it. Well above any
#: plausible count of accounts failing to sign in inside one window; eviction is oldest-first, and
#: an evicted attacker is back to a full budget, which is the safe direction to fail.
_MAX_TRACKED_IDENTIFIERS = 10_000


def password_window_cap() -> int:
    """Failed password attempts one identifier may spend inside `_PASSWORD_WINDOW`."""
    return window_cap(
        _PASSWORD_MAX_GUESS_PROBABILITY_PER_WINDOW,
        _PASSWORD_GUESS_SPACE,
        _PASSWORD_DRAWS_PER_ATTEMPT,
    )


# ---------------------------------------------------------------------------
# Password login — the store
# ---------------------------------------------------------------------------
#: identifier -> failure timestamps inside the window, oldest first. `OrderedDict` so eviction has
#: an order to work with.
_failures: "OrderedDict[str, list[datetime]]" = OrderedDict()
_lock = threading.Lock()


def _key(identifier: str) -> str:
    """What the window is counted against.

    The *submitted* identifier, normalized, and never a resolved person id — which is the whole of
    the anti-enumeration property. Counting against an account would mean an identifier naming no
    account could never be throttled, and "this one throttles, that one does not" is an account
    oracle built out of the rate limiter. Lower-cased so `Alice` and `alice` are one budget; email
    lookup already lower-cases, and usernames are not worth a second budget per capitalization.
    """
    return (identifier or "").strip().lower()


def _live(stamps: list[datetime], now: datetime) -> list[datetime]:
    cutoff = now - _PASSWORD_WINDOW
    return [s for s in stamps if s > cutoff]


def password_attempts_exhausted(identifier: str, *, now: datetime | None = None) -> bool:
    """True when this identifier has spent its whole budget for the current window.

    Asked *before* the PBKDF2 comparison, not after. Two reasons, and the second is the one that
    matters: an unthrottled password endpoint is a CPU amplifier — one unauthenticated request buys
    hundreds of milliseconds of key derivation — and refusing before the derivation is what makes
    the limit cost the attacker more than it costs Origin.

    Returning early does make a throttled response faster than an unthrottled one. That timing
    difference says nothing about whether the account exists, because the key is the submitted
    string: an unknown identifier throttles on exactly the same schedule as a known one.
    """
    now = now or datetime.now(timezone.utc)
    key = _key(identifier)
    with _lock:
        stamps = _live(_failures.get(key, []), now)
        if stamps:
            _failures[key] = stamps
        else:
            _failures.pop(key, None)
        return len(stamps) >= password_window_cap()


def record_password_failure(identifier: str, *, now: datetime | None = None) -> None:
    """Charge one draw against this identifier's window."""
    now = now or datetime.now(timezone.utc)
    key = _key(identifier)
    cap = password_window_cap()
    with _lock:
        stamps = _live(_failures.get(key, []), now)
        stamps.append(now)
        # Nothing above the cap is ever read, so nothing above the cap is kept.
        _failures[key] = stamps[-cap:]
        _failures.move_to_end(key)
        while len(_failures) > _MAX_TRACKED_IDENTIFIERS:
            _failures.popitem(last=False)


def clear_password_failures(identifier: str) -> None:
    """Forget this identifier's failures — called when the credential proves correct.

    Without this a user who mistypes to the cap and then succeeds stays throttled for the rest of
    the window, which is a lockout dressed as a rate limit.
    """
    with _lock:
        _failures.pop(_key(identifier), None)


def reset() -> None:
    """Drop all counted state. For tests; nothing in the serving path calls it."""
    with _lock:
        _failures.clear()

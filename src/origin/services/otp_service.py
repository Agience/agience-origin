"""Origin OTP service.

Email send goes through Origin's `email_service`; person lookup/create uses
Origin's `person_service`.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import anyio.to_thread
import bcrypt
from sqlalchemy.orm import Session

from origin.db import otp_codes as db_otp
from origin.services import guess_budget

logger = logging.getLogger(__name__)

_OTP_EXPIRY_MINUTES = 10
_LOCKOUT_WINDOW_MINUTES = 5
_ISSUE_WINDOW_MINUTES = 15

#: The size of the code space, fixed by `_generate_code`, which draws
#: `secrets.randbelow(1000000)` and formats it `%06d`. Not a policy number: change the code
#: format and this must change with it, which is why it is written next to nothing else.
_CODE_SPACE = 1_000_000

#: The one stated tolerance of this module. Everything below is derived from it and from
#: `_CODE_SPACE`; nothing else here is typed in.
#:
#: It answers the only question a rate limit actually asks: what probability of a successful
#: blind guess, per rate-limit window, is this service willing to hand an attacker? That is a
#: policy choice — the same shape as a false-alarm level — and it is the honest place to put one,
#: because it is stated in units that mean something without reference to the implementation.
#:
#: A different value is right if, and only if, the cost of a successful guess changes. Raise it and
#: the caps below widen; lower it and they tighten. The number itself is answerable: at 1.5e-5 an
#: attacker gets one expected success per ~67,000 windows against a single address.
#:
#: This is the sole input the caps below are computed from — `_max_draws_per_window` and
#: `_window_cap` derive from it and from `_CODE_SPACE` rather than being set independently, so the
#: numbers always stay consistent with the stated tolerance.
_MAX_GUESS_PROBABILITY_PER_WINDOW = 1.5e-5

#: How the draw budget is partitioned, not how large it is. Attempts per code is a typo allowance
#: for the legitimate user; it spends the budget faster but does not enlarge it, because the caps
#: below divide by it. A different value is right if users mistype more or less often.
_MAX_ATTEMPTS_PER_CODE = 3


def _max_draws_per_window() -> int:
    """Every draw an attacker is allowed inside one window, derived from the stated tolerance.

    The guess probability is `draws / _CODE_SPACE` — each guess is one uniform draw from the space,
    and `supersede_live_for_email` keeps at most one live code per address so the draws do not
    overlap — hence the budget is that probability times the space.

    The arithmetic itself lives in `guess_budget`, which the password limiter reads too. Two
    limiters computing the same quantity from copies of the same expression is one of them going
    stale, so there is one expression."""
    return guess_budget.draws_per_window(_MAX_GUESS_PROBABILITY_PER_WINDOW, _CODE_SPACE)


def _window_cap() -> int:
    """How many codes one window may yield: the draw budget divided by what a single code costs in
    draws.

    Computed at the decision site, not frozen at import: a module constant assigned from an
    expression cannot be told apart from the same number typed in, so a test can only perturb an
    input and watch — and by then the assignment has already happened. As a function the
    perturbation reaches it, which is what lets
    `test_the_otp_caps_track_the_stated_guess_probability` fail when it should. The inputs are read
    off this module on every call for the same reason — `guess_budget` holds the arithmetic, this
    module holds the policy.

    Both limbs of the limiter bound the same quantity — draws taken from the code space in one
    window — so both read this: `count_recent_failed` counts codes already burned through their
    attempts, and `count_recent_issued` caps the requests themselves, which is what stops the
    attacker choosing their own number of draws."""
    return guess_budget.window_cap(
        _MAX_GUESS_PROBABILITY_PER_WINDOW, _CODE_SPACE, _MAX_ATTEMPTS_PER_CODE
    )

# A bcrypt comparison against a hash that matches nothing, used to keep the
# "no live code" path the same cost as the "wrong code" path.
_DUMMY_HASH = bcrypt.hashpw(b"dummy-timing-equalizer", bcrypt.gensalt()).decode()


def _generate_code() -> str:
    return f"{secrets.randbelow(1000000):06d}"


def _hash_code(code: str) -> str:
    return bcrypt.hashpw(code.encode(), bcrypt.gensalt()).decode()


def _verify_code_hash(code: str, code_hash: str) -> bool:
    try:
        return bcrypt.checkpw(code.encode(), code_hash.encode())
    except Exception:
        return False


async def _hash_code_async(code: str) -> str:
    """bcrypt off the event loop — see `_verify_code_hash_async`."""
    return await anyio.to_thread.run_sync(_hash_code, code)


async def _verify_code_hash_async(code: str, code_hash: str) -> bool:
    """bcrypt is deliberately slow (~100ms); running it on the event loop stalls every other
    request in the process for that long. The handlers are `async def`, so a direct call blocks
    the loop — running the comparison in a worker thread is what keeps one OTP check from stalling
    the rest of Origin.
    """
    return await anyio.to_thread.run_sync(_verify_code_hash, code, code_hash)


async def request_otp(db: Session, email: str) -> bool:
    from origin.services import email_service

    now = datetime.now(timezone.utc)

    # Guess-rate limit: too many codes already burned through their attempts.
    failed_cutoff = now - timedelta(minutes=_LOCKOUT_WINDOW_MINUTES)
    recent_failed = db_otp.count_recent_failed(
        db, email, failed_cutoff, _MAX_ATTEMPTS_PER_CODE
    )
    if recent_failed >= _window_cap():
        logger.warning("OTP guess-rate limit exceeded for %s", email)
        return False

    # Issuance limit. Without this the attacker sets their own odds: each issued
    # code is another 3 draws from a 10^6 space, and nothing counted requests.
    issue_cutoff = now - timedelta(minutes=_ISSUE_WINDOW_MINUTES)
    recent_issued = db_otp.count_recent_issued(db, email, issue_cutoff)
    if recent_issued >= _window_cap():
        logger.warning("OTP issuance limit exceeded for %s", email)
        return False

    # At most one live code per address. This is what makes the single-code
    # lookup in verify correct, not just cheaper.
    db_otp.supersede_live_for_email(db, email, now=now)

    code = _generate_code()
    db_otp.create(
        db,
        {
            "email": email,
            "code_hash": await _hash_code_async(code),
            "expires_at": now + timedelta(minutes=_OTP_EXPIRY_MINUTES),
            "attempts": 0,
            "used": False,
        },
    )
    db.commit()

    sent = await email_service.send_otp(email, code)
    if not sent:
        logger.warning("Failed to send OTP email to %s", email)
        return False
    logger.info("OTP sent to %s", email)
    return True


async def verify_otp(db: Session, email: str, code: str) -> Optional[str]:
    """Verify an OTP code. Returns person_id on success.

    Auto-creates the person when the email is unknown — mirrors the OIDC auto-create flow so OTP
    login works for first-time users.

    Exactly one code is tested, and the bcrypt comparison runs in a worker thread off the event
    loop: comparing on the loop would let one unauthenticated request choose how many draws its
    guess got, and stall the whole process while they ran.
    """
    otp = db_otp.get_latest_valid_for_email(db, email, _MAX_ATTEMPTS_PER_CODE)

    if otp is None:
        # Burn an equivalent bcrypt so "no live code" and "wrong code" cost the
        # same, and don't leak which one it was via response time.
        await _verify_code_hash_async(code, _DUMMY_HASH)
        db.commit()
        logger.warning("OTP verification failed for %s", email)
        return None

    db_otp.increment_attempts(db, otp.id)
    matched = await _verify_code_hash_async(code, otp.code_hash)
    if not matched:
        db.commit()
        logger.warning("OTP verification failed for %s", email)
        return None

    db_otp.mark_used(db, otp.id)
    from origin.services.person_service import get_or_create_user_by_email

    try:
        person = get_or_create_user_by_email(db, email)
    except (ValueError, PermissionError) as exc:
        logger.warning("OTP verified but person creation denied for %s: %s", email, exc)
        db.rollback()
        return None
    db.commit()
    logger.info("OTP verified for %s", email)
    return str(person.id)


def cleanup_expired(db: Session) -> int:
    count = db_otp.delete_expired(db)
    db.commit()
    return count

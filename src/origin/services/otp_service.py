"""Origin OTP service.

Email send goes through Origin's `email_service`; person lookup/create uses
Origin's `person_service`.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from sqlalchemy.orm import Session

from origin.db import otp_codes as db_otp
from origin.services import guess_budget
from origin.services.auth_service import log_tag, run_kdf

logger = logging.getLogger(__name__)

_OTP_EXPIRY_MINUTES = 10
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

    The limiter itself counts draws, not codes (`_limit_reached`). This is the rate the mail
    budget allows one (address, client) pair (`guess_budget.mail_send_cap`): as many codes as one
    window's draws would buy if every code were guessed to its limit."""
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
    return await run_kdf(_hash_code, code)


async def _verify_code_hash_async(code: str, code_hash: str) -> bool:
    """bcrypt is deliberately slow (~100ms); running it on the event loop stalls every other
    request in the process for that long. The handlers are `async def`, so a direct call blocks
    the loop — running the comparison in a worker thread is what keeps one OTP check from stalling
    the rest of Origin. The thread comes from the key-derivation limiter (`run_kdf`), not the
    default pool the database dependencies share.
    """
    return await run_kdf(_verify_code_hash, code, code_hash)


def normalize_email(email: str) -> str:
    """The one form of an address the OTP ledger is keyed by: stripped and lower-cased, the form
    `person_service` stores addresses in.

    Every entry point normalises before it looks anything up. Keyed by the raw string instead, a
    whitespace or case variant of an address would get a ledger of its own — its own live code and
    its own caps — while still resolving to the same person when it verified.
    """
    return (email or "").strip().lower()


def _limit_reached(db: Session, email: str, now: datetime) -> Optional[str]:
    """Which limit, if any, refuses another code for this address now.

    One quantity bounds guessing: the wrong guesses taken against this address's codes in the
    window (`count_recent_misses`). A new code is refused when its own attempts could carry them
    past `_max_draws_per_window()`, so a window never yields more draws than the stated tolerance
    buys, however the codes were requested. A code nobody guesses at costs nothing here. Asking
    for codes is bounded by the mail budget instead (`guess_budget.mail_send_*`, charged by the
    routes), so one client asking cannot use up the codes the address's owner is due, as a cap on
    issued codes let it."""
    since = now - timedelta(minutes=_ISSUE_WINDOW_MINUTES)
    if db_otp.count_recent_misses(db, email, since) + _MAX_ATTEMPTS_PER_CODE \
            > _max_draws_per_window():
        return "guess-rate"
    return None


async def spend_code_hash() -> None:
    """Hash a code and discard it: the derivation `issue_otp` spends, for a request that issues
    nothing (an unknown address, a refused one), so every request to the issuing routes costs the
    same and none of them says by its timing whether the address holds an account."""
    await _hash_code_async(_generate_code())


async def issue_otp(db: Session, email: str) -> Optional[str]:
    """Record a new code for this address and return it for mailing, or None when a limit refuses
    one. Spends one code hash either way (`spend_code_hash`).

    The code is hashed before the write transaction begins, not inside it. SQLite admits one
    writer; `supersede_live_for_email` takes that lock, and holding it across an awaited hash —
    which may also wait in the derivation queue — would leave every other writer in Origin blocked
    on `busy_timeout`, on the event loop. So: check the limits (reads), release the connection,
    hash, then re-check and supersede, create and commit with nothing awaited in between. The
    re-check is what keeps the caps exact when two requests for one address hash at the same time.
    """
    email = normalize_email(email)
    tag = log_tag(email)

    why = _limit_reached(db, email, datetime.now(timezone.utc))
    db.rollback()
    if why:
        logger.warning("OTP %s limit exceeded for address %s", why, tag)
        await spend_code_hash()
        return None

    code = _generate_code()
    code_hash = await _hash_code_async(code)

    now = datetime.now(timezone.utc)
    why = _limit_reached(db, email, now)
    if why:
        db.rollback()
        logger.warning("OTP %s limit exceeded for address %s", why, tag)
        return None
    # At most one live code per address. This is what makes the single-code
    # lookup in verify correct, not just cheaper.
    db_otp.supersede_live_for_email(db, email, now=now)
    db_otp.create(
        db,
        {
            "email": email,
            "code_hash": code_hash,
            "expires_at": now + timedelta(minutes=_OTP_EXPIRY_MINUTES),
            "attempts": 0,
            "used": False,
        },
    )
    db.commit()
    return code


async def deliver_otp(email: str, code: str, context: str = "") -> bool:
    """Mail a code `issue_otp` returned. The routes run it as a background task, after the
    response, so the time a mail server takes is not part of what a caller can measure."""
    from origin.services import email_service

    email = normalize_email(email)
    sent = await email_service.send_otp(email, code, context)
    if not sent:
        logger.warning("Failed to send OTP email to address %s", log_tag(email))
        return False
    logger.info("OTP sent to address %s", log_tag(email))
    return True


async def request_otp(db: Session, email: str) -> bool:
    """Issue a code and mail it inline (`issue_otp`, then `deliver_otp`): True when a code went
    out. The HTTP routes do not use this; they answer before the mail is sent and never say
    whether a code was issued."""
    code = await issue_otp(db, email)
    if code is None:
        return False
    return await deliver_otp(email, code)


async def verify_otp(db: Session, email: str, code: str) -> Optional[str]:
    """Verify an OTP code. Returns person_id on success.

    Auto-creates the person when the email is unknown — mirrors the OIDC auto-create flow so OTP
    login works for first-time users.

    Exactly one code is tested, and the bcrypt comparison runs in a worker thread off the event
    loop: comparing on the loop would let one unauthenticated request choose how many draws its
    guess got, and stall the whole process while they ran.

    The attempt is spent (`claim_attempt`) and committed before the comparison is awaited, so no
    write lock is held across it and guesses arriving together cannot test more than the code's
    attempts between them. The comparison runs outside any write transaction; only then is the code
    marked used (`claim_use`, which one verification alone can win) and the person written.
    """
    email = normalize_email(email)
    tag = log_tag(email)
    now = datetime.now(timezone.utc)

    otp = db_otp.get_latest_valid_for_email(db, email, _MAX_ATTEMPTS_PER_CODE, now=now)
    claimed = otp is not None and db_otp.claim_attempt(db, otp.id, _MAX_ATTEMPTS_PER_CODE, now=now)
    otp_id = otp.id if claimed else None
    code_hash = otp.code_hash if claimed else None
    db.commit()

    if not claimed:
        # Burn an equivalent bcrypt so "no live code" and "wrong code" cost the
        # same, and don't leak which one it was via response time.
        await _verify_code_hash_async(code, _DUMMY_HASH)
        logger.warning("OTP verification failed for address %s", tag)
        return None

    if not await _verify_code_hash_async(code, code_hash):
        logger.warning("OTP verification failed for address %s", tag)
        return None

    if not db_otp.claim_use(db, otp_id):
        # Another verification of this same code won it while this one compared.
        db.rollback()
        logger.warning("OTP verification failed for address %s (code already used)", tag)
        return None
    from origin.services.person_service import get_or_create_user_by_email

    try:
        person = get_or_create_user_by_email(db, email)
    except (ValueError, PermissionError) as exc:
        logger.warning("OTP verified but person creation denied for address %s: %s", tag, exc)
        db.rollback()
        return None
    db.commit()
    logger.info("OTP verified for address %s", tag)
    return str(person.id)


def cleanup_expired(db: Session) -> int:
    count = db_otp.delete_expired(db)
    db.commit()
    return count

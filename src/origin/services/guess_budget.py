"""One derivation of "how many guesses does a window buy an attacker", the store the password
paths count their guesses in, and the store unauthenticated mail sends are counted in.

Caps are computed from a stated attacker-guess probability rather than typed in. The derivation
lives here and both `otp_service` and the password paths call it with their own inputs, so there is
one implementation of the arithmetic and not two that can drift.

The two limiters differ in where they count, and the difference is not stylistic:

* OTP counts in the database, because an OTP *is* a row — `otp_codes` records every code issued and
  every attempt spent against it, so `count_recent_misses` reads the attacker's draws off a
  ledger that exists for other reasons.
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

import ipaddress
import logging
import random
import threading
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Annotated

from pydantic import Field

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
#: faster attack, so this is not a free knob. At the shipped values the cap is 10 guesses per
#: 15-minute window per identifier: 40 an hour, 960 a day, so covering `_PASSWORD_GUESS_SPACE`
#: through one name takes about ten and a half days of continuous, logged failures rather than the
#: seconds it takes unthrottled. Each name is its own budget (see
#: `auth_router._spend_password_attempt`), so an account reachable by two names, a username that
#: differs from its email, gets 20 per window: about five and a quarter days.
_PASSWORD_WINDOW = timedelta(minutes=15)

#: A password attempt is one draw. Unlike an OTP code, it is not a container that several guesses
#: are spent against, so there is nothing to partition and the cap is the draw budget itself.
_PASSWORD_DRAWS_PER_ATTEMPT = 1

#: Ceiling on how many keys each store tracks at once. The stores are reachable unauthenticated and
#: keyed by strings the caller submits (bounded at 254 characters by the request models), so
#: without a bound a spray of distinct keys is a memory-growth attack on the control meant to stop
#: it. Well above any plausible count of accounts failing to sign in inside one window.
#:
#: When a store is full, a key whose window has passed is dropped first. Writes move a key to the
#: back of the store, so the front is the key written least recently; since writes arrive in time
#: order, it is dead whenever any key is, and checking the front finds one in O(1).
#:
#: When no key is dead, the key evicted is drawn uniformly at random, so which key goes does not
#: depend on anything a caller controls: not its count, not its age, not the order keys arrived in.
#: Each insertion evicts a given key with probability 1/N (N this bound), so a key survives about N
#: insertions on average. On the password store every insertion is a failed sign-in, for which
#: Origin runs a key derivation and the attacker makes a request; an eviction hands back at most
#: one window cap of guesses (`password_window_cap()`) per ~N such failures.
#:
#: The store never fails closed: an untracked key reads as unspent, so no volume of junk locks out
#: an account that has no live window of its own.
_MAX_TRACKED_IDENTIFIERS = 10_000

#: A caller-submitted email address or username, bounded at RFC 5321's 254-character path limit.
#: These strings key the stores here (and the OTP ledger), so an unbounded one is memory an
#: unauthenticated caller chooses the size of. The request models that feed them declare it.
Identifier = Annotated[str, Field(max_length=254)]


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
class _Ledger(OrderedDict):
    """key -> stamps inside the window, oldest first, in order of last write (least recent first),
    with the keys also held in a list so one can be drawn uniformly at random in O(1)."""

    def __init__(self) -> None:
        super().__init__()
        self.slots: list = []
        self.slot_of: dict = {}

    def clear(self) -> None:
        super().clear()
        self.slots.clear()
        self.slot_of.clear()


#: The eviction draw. `SystemRandom` so the choice cannot be predicted from earlier ones; a test
#: substitutes a seeded `random.Random` for a deterministic run.
_rng: random.Random = random.SystemRandom()


#: identifier -> failure timestamps inside the window, oldest first. Bounded by
#: `_MAX_TRACKED_IDENTIFIERS` (see there for which key is evicted).
_failures: _Ledger = _Ledger()
#: Re-entrant, so a step made of several store operations (`spend_password_attempt`) can hold it
#: across all of them.
_lock = threading.RLock()


def _key(identifier: str) -> str:
    """What the window is counted against.

    The *submitted* identifier, normalized, and never a resolved person id — which is the whole of
    the anti-enumeration property. Counting against an account would mean an identifier naming no
    account could never be throttled, and "this one throttles, that one does not" is an account
    oracle built out of the rate limiter. Lower-cased so `Alice` and `alice` are one budget; email
    lookup already lower-cases, and usernames are not worth a second budget per capitalization.
    """
    return (identifier or "").strip().lower()


def _live(stamps: list[datetime], now: datetime, window: timedelta) -> list[datetime]:
    cutoff = now - window
    return [s for s in stamps if s > cutoff]


def _drop(store: _Ledger, key: str) -> None:
    """Forget `key`. Caller holds `_lock`."""
    store.pop(key, None)
    i = store.slot_of.pop(key, None)
    if i is None:
        return
    last = store.slots.pop()
    if last != key:
        store.slots[i] = last
        store.slot_of[last] = i


def _make_room(store: _Ledger, window: timedelta, now: datetime) -> None:
    """Bring the store under `_MAX_TRACKED_IDENTIFIERS`: dead keys from the front first, then keys
    drawn uniformly at random. Caller holds `_lock`."""
    while store and len(store) >= _MAX_TRACKED_IDENTIFIERS:
        front = next(iter(store))
        if not _live(store[front], now, window):
            _drop(store, front)
            continue
        _drop(store, store.slots[_rng.randrange(len(store.slots))])


def _spent(store: _Ledger, key: str, window: timedelta, cap: int, now: datetime) -> bool:
    """True when `key` has `cap` stamps inside `window`. An untracked key is unspent. Prunes what
    has aged out as it reads, without moving the key: its place records its last write."""
    with _lock:
        held = store.get(key)
        if held is None:
            return False
        stamps = _live(held, now, window)
        if not stamps:
            _drop(store, key)
            return False
        if len(stamps) != len(held):
            store[key] = stamps
        return len(stamps) >= cap


def _charge(store: _Ledger, key: str, window: timedelta, cap: int, now: datetime) -> None:
    """Add one stamp for `key`, keeping at most `cap`, evicting to stay within the bound."""
    with _lock:
        stamps = _live(store.get(key, []), now, window)
        if key not in store:
            _make_room(store, window, now)
            store.slot_of[key] = len(store.slots)
            store.slots.append(key)
        stamps.append(now)
        # Nothing above the cap is ever read, so nothing above the cap is kept.
        store[key] = stamps[-cap:]
        store.move_to_end(key)


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
    return _spent(_failures, _key(identifier), _PASSWORD_WINDOW, password_window_cap(), now)


def record_password_failure(identifier: str, *, now: datetime | None = None) -> None:
    """Charge one draw against this identifier's window."""
    now = now or datetime.now(timezone.utc)
    _charge(_failures, _key(identifier), _PASSWORD_WINDOW, password_window_cap(), now)


def spend_password_attempt(identifier: str, *, now: datetime | None = None) -> bool:
    """Charge one attempt against this identifier's window, unless the window is already spent.

    True when the attempt is admitted (and charged); False when it must be refused. The check and
    the charge are one step under one lock, and the charge comes before the key derivation, not
    after: an attempt charged only once its derivation finished would let every guess sent at the
    same moment pass the check while all of them were still in flight. The charge is taken back by
    `clear_password_failures` when the password proves correct.
    """
    now = now or datetime.now(timezone.utc)
    key = _key(identifier)
    cap = password_window_cap()
    with _lock:
        if _spent(_failures, key, _PASSWORD_WINDOW, cap, now):
            return False
        _charge(_failures, key, _PASSWORD_WINDOW, cap, now)
        return True


#: Password attempts at email confirmation (`auth_router.email_verify_confirm`), per account. A
#: ledger of its own rather than keys in `_failures`: sign-in charges `_failures` under whatever
#: identifier the caller types, so any key there, prefixed or not, is one anyone can spend.
_confirmations: _Ledger = _Ledger()


def spend_confirmation_attempt(person_id: str, *, now: datetime | None = None) -> bool:
    """`spend_password_attempt` for the password check that confirms an account's address: the
    same window and cap, keyed by the account, in `_confirmations`. Only a holder of a valid
    confirmation link for the account reaches it."""
    now = now or datetime.now(timezone.utc)
    cap = password_window_cap()
    with _lock:
        if _spent(_confirmations, person_id, _PASSWORD_WINDOW, cap, now):
            return False
        _charge(_confirmations, person_id, _PASSWORD_WINDOW, cap, now)
        return True


def clear_confirmation_failures(person_id: str) -> None:
    """Forget this account's confirmation attempts — called when the password proves correct."""
    with _lock:
        _drop(_confirmations, person_id)


def clear_password_failures(identifier: str) -> None:
    """Forget this identifier's failures — called when the credential proves correct.

    Without this a user who mistypes to the cap and then succeeds stays throttled for the rest of
    the window, which is a lockout dressed as a rate limit.
    """
    with _lock:
        _drop(_failures, _key(identifier))


# ---------------------------------------------------------------------------
# Unauthenticated mail — a send budget, not a guess budget
# ---------------------------------------------------------------------------
# Every unauthenticated route that mails — resend, reset, the sign-in-code requests, and the
# confirmation link sent on registration or on a password sign-in to an unconfirmed account (see
# `auth_router._mail_send_admitted`) — hands its caller mail sent to an address of their choosing.
# They share one budget, so none is the cheaper way to fill an inbox. Three bounds, all on sends:
#
# * per (address, client): the one a caller meets. It is `otp_service._window_cap()` over
#   `_ISSUE_WINDOW_MINUTES` — as many codes as one window's guesses would buy — read from there on
#   every call so the two cannot drift. Keyed by client as well as address so one remote caller spending its budget
#   does not spend the address owner's.
# * per address: `_MAIL_SEND_CLIENTS` times that, so mail to one inbox stays bounded however many
#   clients ask for it.
# * per client: across every address, so one client cannot reach an unbounded number of inboxes by
#   naming a new one each time. Not applied to a client in `SHARED_CLIENT_NETWORKS`, whose
#   requests are many people's, and logged at WARNING once per window when a client reaches it.
#
# Every request with a well-formed address is charged against all three whether or not an account
# answers to the address: a budget that only accounts could spend would make the limiter an account
# oracle. A client is its network (`_client_network`), not its exact address.
_mail_sends: _Ledger = _Ledger()

#: How many distinct clients one person plausibly asks for mail from inside one window — a
#: laptop, a phone on mobile data, a second network such as work or a VPN, and one spare. This is the
#: only looseness in the per-address cap: a person resending from more places than this inside one
#: window meets the per-address cap, and still has signing in, which mails a fresh link itself.
_MAIL_SEND_CLIENTS = 4


def mail_send_window() -> timedelta:
    """The window mail sends are counted over — the OTP issuance window."""
    from origin.services import otp_service

    return timedelta(minutes=otp_service._ISSUE_WINDOW_MINUTES)


def mail_send_cap() -> int:
    """Sends one (address, client) pair may request inside `mail_send_window()` —
    `otp_service._window_cap()`."""
    from origin.services import otp_service

    return otp_service._window_cap()


def mail_send_address_cap() -> int:
    """Sends one address may receive inside the window, across every client."""
    return mail_send_cap() * _MAIL_SEND_CLIENTS


#: How many people plausibly ask for mail from one client address inside one window. One client
#: address is often many people: an office, a campus, a carrier-grade NAT that puts hundreds of
#: subscribers behind one IPv4 address. The per-client cap only has to stop one client from
#: reaching an unbounded number of inboxes, so it is set well above a busy shared address — 20
#: people each asking for the pair cap — and a client that reaches it is logged, so a shared
#: address that outgrows it is seen rather than silently dropping mail.
_MAIL_SEND_PEOPLE_PER_CLIENT = 20


def mail_send_client_cap() -> int:
    """Sends one client may request inside the window, across every address."""
    return mail_send_cap() * _MAIL_SEND_PEOPLE_PER_CLIENT


def _shared_client_networks() -> tuple:
    """`config.SHARED_CLIENT_NETWORKS` parsed, cached on the configured value.

    An entry is used only if it says exactly what it covers. `10.0.0.5/8` (host bits set) is
    refused, not widened to all of 10/8: widening would exempt a whole network from the per-client
    cap on the strength of what is most likely a typo for one host. An IPv4-mapped IPv6 entry
    (`::ffff:10.0.0.5`) is refused too, because client addresses are compared as IPv4 and it could
    never match; the warning says to write it as IPv4. Each refusal is logged at WARNING, naming
    the entry, whenever the setting is read anew.
    """
    from origin import config

    raw = getattr(config, "SHARED_CLIENT_NETWORKS", None) or []
    if isinstance(raw, str):
        raw = [u.strip() for u in raw.split(",") if u.strip()]
    key = tuple(raw)
    if _shared_networks_cache.get("key") != key:
        nets = []
        for entry in raw:
            try:
                net = ipaddress.ip_network(entry, strict=True)
            except ValueError:
                logger.warning(
                    "SHARED_CLIENT_NETWORKS entry %r is not an IP network, or has host bits set; "
                    "ignored (write a single host as a.b.c.d/32, a network by its base address)",
                    entry)
                continue
            if net.version == 6 and net.prefixlen >= 96 \
                    and net.network_address.ipv4_mapped is not None:
                logger.warning(
                    "SHARED_CLIENT_NETWORKS entry %r is an IPv4-mapped IPv6 network, which never "
                    "matches (clients are compared as IPv4); ignored — write it as IPv4", entry)
                continue
            nets.append(net)
        _shared_networks_cache.update(key=key, nets=tuple(nets))
    return _shared_networks_cache["nets"]


_shared_networks_cache: dict = {}


def _is_shared_client_network(client: str) -> bool:
    try:
        ip = ipaddress.ip_address((client or "").strip())
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip.version == n.version and ip in n for n in _shared_client_networks())


#: (kind, key) -> when it was last logged, so a condition that holds for a whole window is logged
#: once per window, not once per request. Bounded: cleared whole past `_MAX_TRACKED_IDENTIFIERS`.
_logged_at: dict = {}


def _log_once_per_window(kind: str, key: str, now: datetime, window: timedelta, message: str,
                         *args, to: logging.Logger | None = None) -> None:
    """Log `message` at WARNING, to `to` (this module's logger by default), unless the same
    (kind, key) was logged inside `window`."""
    with _lock:
        last = _logged_at.get((kind, key))
        if last is not None and now - last < window:
            return
        if len(_logged_at) >= _MAX_TRACKED_IDENTIFIERS:
            _logged_at.clear()
        _logged_at[(kind, key)] = now
    (to or logger).warning(message, *args)


def _client_network(client: str) -> str:
    """The unit one client controls: an IPv4 address, or an IPv6 /64, which a single host or
    subscriber is routinely assigned whole. Keying the full IPv6 address would give one /64 an
    unlimited number of clients. An IPv4-mapped address is its IPv4 address; anything that does not
    parse is used as given."""
    try:
        ip = ipaddress.ip_address((client or "").strip())
    except ValueError:
        return client or ""
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 4:
        return str(ip)
    return str(ipaddress.ip_network(f"{ip}/64", strict=False))


def _pair_key(email: str, client: str) -> str:
    return "c|" + _key(email) + "|" + _client_network(client)


def _address_key(email: str) -> str:
    return "a|" + _key(email)


def _client_key(client: str) -> str:
    return "k|" + _client_network(client)


def mail_sends_exhausted(email: str, client: str, *, now: datetime | None = None) -> bool:
    """True when this client has used its sends for this address, the address has had all its
    sends from every client, or this client has used its sends across every address. The last is
    skipped for a client in `SHARED_CLIENT_NETWORKS`."""
    now = now or datetime.now(timezone.utc)
    window = mail_send_window()
    if _spent(_mail_sends, _pair_key(email, client), window, mail_send_cap(), now):
        return True
    if _spent(_mail_sends, _address_key(email), window, mail_send_address_cap(), now):
        from origin.services.auth_service import log_tag

        _log_once_per_window(
            "address-cap", _key(email), now, window,
            "address %s reached its cap of %d mailed sends in %s; mail to it is dropped until the "
            "window passes. Several clients asking for one address is a flood aimed at its owner, "
            "who can still sign in with a password, a passkey or a federated account",
            log_tag(email.lower()), mail_send_address_cap(), window)
        return True
    network = _client_network(client)
    if _is_shared_client_network(client):
        _log_once_per_window(
            "proxy", network, now, window,
            "mail sends from %s are not capped per client: it is in SHARED_CLIENT_NETWORKS",
            network)
        return False
    if _spent(_mail_sends, _client_key(client), window, mail_send_client_cap(), now):
        _log_once_per_window(
            "client-cap", network, now, window,
            "client %s reached the per-client mail cap (%d sends in %s); further mail from it is "
            "dropped this window. If this is a reverse proxy, Origin is not seeing real client "
            "addresses (FORWARDED_ALLOW_IPS; see SHARED_CLIENT_NETWORKS in config.py)",
            network, mail_send_client_cap(), window)
        return True
    return False


def record_mail_send(email: str, client: str, *, now: datetime | None = None) -> None:
    """Charge one send request against the pair, the address and (unless it is a listed proxy
    peer) the client."""
    now = now or datetime.now(timezone.utc)
    window = mail_send_window()
    _charge(_mail_sends, _pair_key(email, client), window, mail_send_cap(), now)
    _charge(_mail_sends, _address_key(email), window, mail_send_address_cap(), now)
    if not _is_shared_client_network(client):
        _charge(_mail_sends, _client_key(client), window, mail_send_client_cap(), now)


def reset() -> None:
    """Drop all counted state. For tests; nothing in the serving path calls it."""
    with _lock:
        _failures.clear()
        _confirmations.clear()
        _mail_sends.clear()
        _logged_at.clear()
        _shared_networks_cache.clear()

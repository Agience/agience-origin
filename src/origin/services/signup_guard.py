"""What stands between a sign-up form and a mail Origin sends (FR-027, John 2026-11-14).

A bot that registers someone else's address, or a malformed one, makes Origin mail it: the address's
owner receives mail they never asked for, and a malformed address bounces back to us. Origin mails
only when it is certain the request is real:

  * the address is one SMTP can carry (`mailable_address`, RFC 5321/5322 dot-atom), checked on
    every unauthenticated mail path;
  * the form was really filled in: a hidden field a person never sees stays empty, and a token the
    form fetched when it opened is at least `MIN_FILL_SECONDS` old and at most `MAX_FORM_AGE`
    (`form_token`, `form_is_real`);
  * sign-up mail stays under a global hourly ceiling (`signup_mail_admitted`);
  * one client address makes at most `DEFAULT_SIGNUPS_PER_IP_PER_HOUR` accounts an hour, and one
    network (an IPv4 /24, an IPv6 /48) at most `DEFAULT_SIGNUPS_PER_NET_PER_DAY` a day
    (`signup_from_admitted`);
  * an address is sent at most one confirmation link a day, and none once its account is
    `UNVERIFIED_DAYS` old (`verification_mail_admitted`); such accounts expire
    (`person_service.expire_unverified`).

Soft signals (`soft_signals`) block nothing: they mark the operator's new-account notice [SPAM?].

A request that fails the form check is answered exactly as a real one is, and nothing is created or
mailed, so a bot learns nothing.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
import threading
import time
from typing import Optional

#: The least time a person takes to fill in the form, and the longest a form token stays good.
MIN_FILL_SECONDS = 3
MAX_FORM_AGE = 2 * 60 * 60
#: Sign-up mails Origin sends in an hour, across every address and client.
DEFAULT_SIGNUP_MAILS_PER_HOUR = 60
#: Accounts one client address makes in an hour, and one network in a day.
DEFAULT_SIGNUPS_PER_IP_PER_HOUR = 3
DEFAULT_SIGNUPS_PER_NET_PER_DAY = 20
#: An account that has not proved its address in this many days is mailed nothing and expires.
UNVERIFIED_DAYS = 7
#: Local parts that name a role, not a person: a scraped business address.
ROLE_LOCAL_PARTS = frozenset({
    "admin", "billing", "careers", "contact", "enquiries", "hello", "help", "hr", "info",
    "inquiries", "jobs", "mail", "marketing", "office", "portrait", "postmaster", "sales",
    "support", "team", "webmaster",
})

# RFC 5322 `atext` for a dot-atom local part; quoted local parts are not accepted.
_ATEXT = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]"
_LOCAL = re.compile(rf"{_ATEXT}+(\.{_ATEXT}+)*")
_LABEL = re.compile(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def mailable_address(email: str) -> bool:
    """Whether SMTP can carry mail to `email` (RFC 5321 §4.1.2, §4.5.3.1): one `@`, a dot-atom
    local part of at most 64 octets with no leading, trailing or doubled dot, a domain of LDH labels
    of at most 63 octets each (an IDN in its ASCII form), at most 254 octets in all."""
    if not isinstance(email, str) or len(email) > 254 or email.count("@") != 1:
        return False
    local, domain = email.split("@")
    if not local or len(local) > 64 or not _LOCAL.fullmatch(local):
        return False
    labels = domain.split(".")
    return bool(domain) and all(_LABEL.fullmatch(lab) for lab in labels)


def _key() -> bytes:
    """The form-token key: derived from the secret the session cookie is signed with, under its
    own label, as `auth_service._log_tag_key` derives the log-tag key. Before that file exists, a
    random per-process key: tokens then hold within one run only."""
    from origin import config
    try:
        secret = (config.KEYS_DIR / "platform_internal.secret").read_bytes().strip()
    except OSError:
        secret = b""
    if not secret:
        return _FALLBACK
    return hmac.new(secret, b"origin signup form v1", hashlib.sha256).digest()


_FALLBACK = secrets.token_bytes(32)


def form_token(now: Optional[float] = None) -> str:
    """A token the sign-up form fetches when it opens: the time, signed."""
    ts = str(int(now if now is not None else time.time()))
    sig = hmac.new(_key(), ts.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{ts}.{sig}"


def form_is_real(token: str, honeypot: str, now: Optional[float] = None) -> bool:
    """Was the form filled in by a person? The hidden field is empty, and the token is ours, at
    least `MIN_FILL_SECONDS` old and at most `MAX_FORM_AGE`."""
    if honeypot:
        return False
    ts, _, sig = (token or "").partition(".")
    if not ts.isdigit() or not sig:
        return False
    want = hmac.new(_key(), ts.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, want):
        return False
    age = (now if now is not None else time.time()) - int(ts)
    return MIN_FILL_SECONDS <= age <= MAX_FORM_AGE


_lock = threading.Lock()
_sent: list = []


def signup_mail_admitted(per_hour: Optional[int] = None, now: Optional[float] = None) -> bool:
    """Charge one sign-up mail to the global hourly ceiling; False when it is spent."""
    if per_hour is None:
        from origin.services.platform_settings_service import settings as _platform
        try:
            per_hour = int(_platform.get("auth.signup.mails_per_hour")
                           or DEFAULT_SIGNUP_MAILS_PER_HOUR)
        except (TypeError, ValueError):
            per_hour = DEFAULT_SIGNUP_MAILS_PER_HOUR
    t = now if now is not None else time.time()
    with _lock:
        while _sent and _sent[0] <= t - 3600:
            _sent.pop(0)
        if len(_sent) >= per_hour:
            return False
        _sent.append(t)
        return True


def _setting_int(key: str, default: int) -> int:
    from origin.services.platform_settings_service import settings as _platform
    try:
        return int(_platform.get(key) or default)
    except (TypeError, ValueError):
        return default


def _network(client: str) -> str:
    """The network a client address belongs to: its IPv4 /24 or IPv6 /48. A host that is not an
    IP address (a test client, a socket path) is its own network."""
    try:
        ip = ipaddress.ip_address(client)
    except ValueError:
        return client
    return str(ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 48}", strict=False))


_by_ip: dict = {}
_by_net: dict = {}


def _live(stamps: list, t: float, window: float) -> list:
    return [s for s in stamps if s > t - window]


def signup_from_admitted(client: str, now: Optional[float] = None) -> tuple[bool, bool]:
    """Charge one sign-up to `client` and its network. Returns `(admitted, burst)`: admitted is
    False past either cap, and nothing is charged then; burst is True when this client already
    signed up within the hour, a soft signal for the notice."""
    t = now if now is not None else time.time()
    per_ip = _setting_int("auth.signup.per_ip_per_hour", DEFAULT_SIGNUPS_PER_IP_PER_HOUR)
    per_net = _setting_int("auth.signup.per_network_per_day", DEFAULT_SIGNUPS_PER_NET_PER_DAY)
    client = client or "unknown"
    net = _network(client)
    with _lock:
        ip_stamps = _live(_by_ip.get(client, []), t, 3600)
        net_stamps = _live(_by_net.get(net, []), t, 86400)
        if len(ip_stamps) >= per_ip or len(net_stamps) >= per_net:
            _by_ip[client], _by_net[net] = ip_stamps, net_stamps
            return False, True
        _by_ip[client] = ip_stamps + [t]
        _by_net[net] = net_stamps + [t]
        return True, bool(ip_stamps)


_mailed: dict = {}


def _address_key(email: str) -> str:
    return hashlib.sha256((email or "").strip().lower().encode("utf-8")).hexdigest()


def verification_mail_admitted(email: str, created_time=None, now: Optional[float] = None) -> bool:
    """Charge one confirmation link to `email`: False when one went in the last day, or when the
    account (created at `created_time`) is `UNVERIFIED_DAYS` old without proving its address."""
    t = now if now is not None else time.time()
    if created_time is not None:
        created = created_time.timestamp() if hasattr(created_time, "timestamp") else float(created_time)
        if t - created >= UNVERIFIED_DAYS * 86400:
            return False
    key = _address_key(email)
    with _lock:
        for k in [k for k, v in _mailed.items() if v <= t - 86400]:
            del _mailed[k]
        if key in _mailed:
            return False
        _mailed[key] = t
        return True


def soft_signals(email: str, username: str, name: str, burst: bool = False) -> list[str]:
    """What makes a new account look like a bot's, for the notice only: a blank name, a username
    that copies the address's local part, a role address, a burst from one client. A username
    equal to the whole address is no signal: both sign-up forms set it so."""
    email = (email or "").strip().lower()
    username = (username or "").strip().lower()
    local = email.partition("@")[0]
    out = []
    if not (name or "").strip():
        out.append("blank name")
    if username and username == local:
        out.append("username copies the address")
    if local in ROLE_LOCAL_PARTS:
        out.append("role address")
    if burst:
        out.append("several sign-ups from one client within the hour")
    return out


def _reset_for_tests() -> None:
    with _lock:
        _sent.clear()
        _by_ip.clear()
        _by_net.clear()
        _mailed.clear()

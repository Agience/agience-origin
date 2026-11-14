"""What stands between a sign-up form and a mail Origin sends (FR-027, John 2026-11-14).

A bot that registers someone else's address, or a malformed one, makes Origin mail it: the address's
owner receives mail they never asked for, and a malformed address bounces back to us. Origin mails
only when it is certain the request is real:

  * the address is one SMTP can carry (`mailable_address`, RFC 5321/5322 dot-atom), checked on
    every unauthenticated mail path;
  * the form was really filled in: a hidden field a person never sees stays empty, and a token the
    form fetched when it opened is at least `MIN_FILL_SECONDS` old and at most `MAX_FORM_AGE`
    (`form_token`, `form_is_real`);
  * sign-up mail stays under a global hourly ceiling (`signup_mail_admitted`).

A request that fails the form check is answered exactly as a real one is, and nothing is created or
mailed, so a bot learns nothing.
"""
from __future__ import annotations

import hashlib
import hmac
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


def _reset_for_tests() -> None:
    with _lock:
        _sent.clear()

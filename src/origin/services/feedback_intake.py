"""What stands between the Help panel's "Send feedback" and the item it files (John, 2026-11-14).

Feedback is text a person sends, signed in or not. It is filed only when the request is real, by
the same tests a sign-up form passes (FR-027, `signup_guard`): the hidden field stays empty and the
form token is ours and was fetched a few seconds before. It is also within `MAX_CHARS`, and under
two hourly ceilings: one per client address, one across all of them. A request that fails any of
these gets the same answer as one that passes, so a bot learns nothing, and nothing is filed.

`admit` decides; the router files what it admits.
"""
from __future__ import annotations

import threading
import time
from typing import Optional

from origin.services import signup_guard

#: The longest feedback filed, in characters.
MAX_CHARS = 4000
#: Feedback filed in an hour from one client address, and across all of them.
PER_ADDRESS_PER_HOUR = 5
GLOBAL_PER_HOUR = 60

_lock = threading.Lock()
_by_address: dict = {}
_all: list = []


def _charge(address: str, now: float) -> bool:
    """Charge one item to both ceilings; False, charging neither, when either is spent."""
    cut = now - 3600
    with _lock:
        while _all and _all[0] <= cut:
            _all.pop(0)
        mine = [t for t in _by_address.get(address, []) if t > cut]
        if len(_all) >= GLOBAL_PER_HOUR or len(mine) >= PER_ADDRESS_PER_HOUR:
            _by_address[address] = mine
            return False
        mine.append(now)
        _by_address[address] = mine
        _all.append(now)
        return True


def admit(text: str, honeypot: str, form_token: str, address: str,
          now: Optional[float] = None) -> Optional[str]:
    """The text to file, trimmed, or None when this request files nothing."""
    t = now if now is not None else time.time()
    body = (text or "").strip()
    if not body or len(body) > MAX_CHARS:
        return None
    if not signup_guard.form_is_real(form_token, honeypot, now=t):
        return None
    if not _charge(address or "-", t):
        return None
    return body


def _reset_for_tests() -> None:
    with _lock:
        _by_address.clear()
        _all.clear()

"""The Key Oracle — Origin as the managed store for secrets and encryption keys.

Secrets/keys are stored **encrypted at rest** (via Origin's `encryption.key`, reusing the platform
secret store) and released only to an authenticated operator. For high-value keys, `split_secret`
produces **Shamir k-of-n shares** (the "key halves"): redundancy (any k recover it) + security
(< k shares reveal nothing) + no single point of custody.
"""
from __future__ import annotations

import base64
from typing import List

from sqlalchemy import text
from sqlalchemy.orm import Session

from origin.services.platform_settings_service import settings as platform_settings
from origin.services import shamir

_NS = "oracle."


def store_secret(db: Session, key_id: str, value: str) -> None:
    """Store (or replace) a managed secret/key — encrypted at rest."""
    platform_settings.set_value(db, _NS + key_id, value, is_secret=True, category="oracle")


def get_secret(db: Session, key_id: str) -> str | None:
    """Release a managed secret/key (operator-gated at the router)."""
    return platform_settings.get_secret(_NS + key_id)


def list_ids(db: Session) -> List[str]:
    rows = db.execute(text("SELECT key FROM platform_settings WHERE key LIKE :p"),
                      {"p": _NS + "%"}).fetchall()
    return sorted(r[0][len(_NS):] for r in rows if r and r[0])


def has(db: Session, key_id: str) -> bool:
    return get_secret(db, key_id) is not None


# --- Shamir key-halves (redundant, no-single-point custody) ---
def split_secret(value: str, *, k: int, n: int) -> List[str]:
    """Split a secret into n shares (any k reconstruct). Each share is `"<x>:<base64(y)>"` — hand
    the shares to separate custodians (operator keystore, offline backup, a co-signer)."""
    shares = shamir.split(value.encode("utf-8"), k=k, n=n)
    return [f"{x}:{base64.b64encode(y).decode('ascii')}" for x, y in shares]


def combine_shares(share_strs: List[str]) -> str:
    parsed = []
    for s in share_strs:
        x, b = s.split(":", 1)
        parsed.append((int(x), base64.b64decode(b)))
    return shamir.combine(parsed).decode("utf-8")

"""Origin's custody of one share of each Mantle master key.

Mantle keeps each principal's master key as a 2-of-3 Shamir split (`prism.trust.shamir`): share 1
in its own store under its KEK, share 2 here, share 3 sealed to an offline age recipient for the
operator. Mantle combines shares 1 and 2 to use a key, so neither node alone holds one.

A share lives in its own table (`models.key_custody.KeyCustodyShare`), with the share bytes
Fernet-encrypted under Origin's `encryption.key`. It is not a platform setting: no settings route
lists, reads or writes it, and `platform_settings_service` refuses the `custody.` prefix outright.
The operator's `/oracle` routes do not reach it either, so an operator token plus a Mantle node is
not a whole key.

Each share is stored with its key-check value (`kcv`), a MAC of the master key that Mantle computes
and checks after combining. Origin cannot verify it (it never sees the key); it uses it only to
tell a share of the same key from a share of a different one, which decides whether a write may
replace what is stored:

  * nothing stored                        -> stored
  * the same share                        -> unchanged (an idempotent retry)
  * a share of the same key (same kcv)    -> replaced (a re-split, as after a rollback)
  * a share of another key                -> refused, unless the caller names the stored kcv in
                                             `supersedes` (Mantle does so only for a key it wrote
                                             and never used: a `put` that did not complete)

The decision and the write are one step: an insert that fails on the primary key, or an update
conditioned on the stored kcv and ciphertext, so two writes cannot both act on what they read.
A share that cannot be decrypted is refused (`ShareUnreadable`), never reported as absent: absent
would let Mantle mint a key over one that exists.
"""
from __future__ import annotations

import base64
import binascii
import re
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import delete, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from origin.key_manager import get_encryption_key
from origin.models.key_custody import KeyCustodyNonce, KeyCustodyShare

_PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9._:@-]{1,128}$")
_KCV_RE = re.compile(r"^[0-9a-f]{32}$")
_MAX_SHARE_BYTES = 64

#: Origin runs one process (`main` refuses more workers), so this serializes every write; the
#: conditional statements below hold the rule even without it.
_WRITE_LOCK = threading.Lock()


class ShareRejected(ValueError):
    """The request is malformed. The message names the field and carries no share."""


class ShareConflict(Exception):
    """A share of a different key is stored for this principal, or it changed under the write."""


class ShareUnreadable(Exception):
    """A share is stored for this principal and could not be decrypted."""


def valid_principal(principal_id: str) -> bool:
    return bool(_PRINCIPAL_RE.match(principal_id or ""))


def _fernet() -> Fernet:
    return Fernet(get_encryption_key().encode())


def _validate(share: dict) -> dict:
    x = share.get("x")
    if not isinstance(x, int) or isinstance(x, bool) or not 1 <= x <= 255:
        raise ShareRejected("x must be an integer in 1..255")
    y = share.get("y")
    try:
        raw = base64.b64decode(y, validate=True) if isinstance(y, str) else b""
    except (binascii.Error, ValueError):
        raw = b""
    if not 1 <= len(raw) <= _MAX_SHARE_BYTES:
        raise ShareRejected("y must be base64 of 1..64 bytes")
    kcv = share.get("kcv")
    if not isinstance(kcv, str) or not _KCV_RE.match(kcv):
        raise ShareRejected("kcv must be 32 lowercase hex characters")
    return {"x": x, "y": y, "kcv": kcv}


def _read(db: Session, principal_id: str) -> Optional[KeyCustodyShare]:
    db.expire_all()
    return db.get(KeyCustodyShare, principal_id)


def _open(row: KeyCustodyShare) -> dict:
    try:
        y = _fernet().decrypt(row.y_sealed.encode("ascii")).decode("ascii")
    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise ShareUnreadable(row.principal_id) from exc
    return {"x": row.x, "y": y, "kcv": row.kcv}


def release_share(db: Session, principal_id: str) -> Optional[dict]:
    """The stored share for `principal_id`, None when none is stored, or `ShareUnreadable`."""
    row = _read(db, principal_id)
    return None if row is None else _open(row)


def store_share(db: Session, principal_id: str, share: dict, *,
                supersedes: Optional[str] = None) -> str:
    """Store a share; returns `stored`, `unchanged` or `replaced`. See the module note."""
    if not valid_principal(principal_id):
        raise ShareRejected("principal id is malformed")
    new = _validate(share)
    sealed = _fernet().encrypt(new["y"].encode("ascii")).decode("ascii")
    with _WRITE_LOCK:
        row = _read(db, principal_id)
        if row is None:
            db.add(KeyCustodyShare(principal_id=principal_id, x=new["x"], y_sealed=sealed,
                                   kcv=new["kcv"]))
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                raise ShareConflict(principal_id) from None
            return "stored"
        try:
            if _open(row) == new:
                return "unchanged"
        except ShareUnreadable:
            pass                              # replaceable only by a share of the same key
        if row.kcv != new["kcv"] and row.kcv != supersedes:
            raise ShareConflict(principal_id)
        result = db.execute(
            update(KeyCustodyShare)
            .where(KeyCustodyShare.principal_id == principal_id,
                   KeyCustodyShare.kcv == row.kcv,
                   KeyCustodyShare.y_sealed == row.y_sealed)
            .values(x=new["x"], y_sealed=sealed, kcv=new["kcv"],
                    updated_time=datetime.now(timezone.utc)))
        if result.rowcount != 1:
            db.rollback()
            raise ShareConflict(principal_id)
        db.commit()
        return "replaced"


def spend_token(db: Session, jti: str, expires_at: datetime) -> bool:
    """Record a token's `jti`; False if it was already spent. Expired records are dropped."""
    now = datetime.now(timezone.utc)
    db.execute(delete(KeyCustodyNonce).where(KeyCustodyNonce.expires_at < now - timedelta(seconds=5)))
    db.add(KeyCustodyNonce(jti=jti, expires_at=expires_at))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return False
    return True

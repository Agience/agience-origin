"""Origin's JWT signing key, and its rollover (John, 2026-11-02: rotate the root-era keys at cutover).

The current pair is `origin.private.pem` / `origin.public.pem` in Origin's keys folder, and its
`kid` is in `origin.kid` (absent: `origin-1`, the kid every manifest has named so far). A rollover
(`scripts.rotate_signing_key`) leaves the old public key beside it as
`origin.retired.<kid>.public.pem`, so the JWKS still names the old key for as long as anything
signed with it could be presented; its private half is gone.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from typing import List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

DEFAULT_KID = "origin-1"
KID_FILE = "origin.kid"
#: Set by a rollover run in this process on a keys folder other than the default.
_active_dir: Optional[Path] = None


def keys_dir() -> Path:
    if _active_dir is not None:
        return _active_dir
    from origin import key_manager
    return Path(key_manager._DEFAULT_PRIVATE_KEY_PATH).parent


def current_kid(folder: Optional[Path] = None) -> str:
    f = (folder or keys_dir()) / KID_FILE
    try:
        kid = f.read_text(encoding="ascii").strip()
    except OSError:
        return DEFAULT_KID
    return kid or DEFAULT_KID


def fingerprint(public_pem: bytes) -> str:
    """The SHA-256 of the key's SubjectPublicKeyInfo, hex."""
    key = serialization.load_pem_public_key(public_pem)
    der = key.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def kid_of(public_pem: bytes) -> str:
    """A kid named by the key itself: `origin-` and the first 16 hex of its fingerprint."""
    return "origin-" + fingerprint(public_pem)[:16]


def _jwk(public_pem: bytes, kid: str) -> dict:
    key = serialization.load_pem_public_key(public_pem)
    if not isinstance(key, RSAPublicKey):
        raise NotImplementedError("Only RSA keys are supported")
    n = key.public_numbers()

    def b64(i: int) -> str:
        return base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")) \
            .rstrip(b"=").decode()

    return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": b64(n.n),
            "e": b64(n.e)}


def retired_key_lifetime() -> timedelta:
    """How long a retired key stays published: the longest life of any token it signed. An access
    token's life, or a delegation's (ten minutes at most), whichever is longer, and a margin;
    refresh tokens all end at a rollover, so they need none."""
    from origin.services.auth_service import access_token_expires_in_seconds
    return timedelta(seconds=max(access_token_expires_in_seconds(), 600)) + timedelta(minutes=5)


def _retired_at_file(folder: Path, kid: str) -> Path:
    return folder / f"origin.retired.{kid}.at"


def record_retired(kid: str, *, folder: Optional[Path] = None,
                   at: Optional[datetime] = None) -> None:
    """Record when `kid` was retired (`origin.retired.<kid>.at`, an ISO time)."""
    folder = folder or keys_dir()
    when = (at or datetime.now(timezone.utc)).isoformat()
    _retired_at_file(folder, kid).write_text(when, encoding="ascii")


def _retired_at(f: Path, kid: str) -> datetime:
    at = _retired_at_file(f.parent, kid)
    try:
        t = datetime.fromisoformat(at.read_text(encoding="ascii").strip())
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    except (OSError, ValueError):
        return datetime.fromtimestamp(f.stat().st_mtime, timezone.utc)


def published_jwks(now: Optional[datetime] = None) -> List[dict]:
    """The current key, then every retired one still within `retired_key_lifetime` of its
    retirement: no token it signed can still be live after that, so it is published no longer
    (review 11, H2)."""
    from origin.key_manager import get_jwk_public
    now = now or datetime.now(timezone.utc)
    life = retired_key_lifetime()
    keys = [get_jwk_public()]
    for f in sorted(keys_dir().glob("origin.retired.*.public.pem")):
        kid = f.name[len("origin.retired."):-len(".public.pem")]
        if kid and kid != keys[0].get("kid") and _retired_at(f, kid) + life > now:
            keys.append(_jwk(f.read_bytes(), kid))
    return keys

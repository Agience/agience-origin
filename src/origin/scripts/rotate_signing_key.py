"""Roll Origin's JWT signing key over, on the operator's acceptance (John, 2026-11-02).

    python -m origin.scripts.rotate_signing_key --print          # mint the next pair, print it
    python -m origin.scripts.rotate_signing_key --accept KID     # make it current

`--print` writes the next pair (`origin.next.private.pem`, `origin.next.public.pem`) into Origin's
keys folder, if none is there yet, and prints its `kid` and fingerprint. Nothing trusts it yet.
`--accept KID`, with the kid printed, makes it the current pair:
  * `origin.kid` names the new key, which signs everything from now on;
  * the old public key stays in Origin's own JWKS (`origin.retired.<kid>.public.pem`, retired at
    the time in `origin.retired.<kid>.at`) only until the longest life of a token it signed has
    passed (`signing_keys.retired_key_lifetime`), then leaves it; its private half is gone now;
  * every refresh-token family and Origin session ends, and every credential issued before now is
    refused at Origin (`services.not_before`): everyone signs in again once.

What the peers need, because each verifies Origin's tokens offline against the JWKS inline in its
own authority manifest and never fetches Origin's: on acceptance the release tool's `rotate-keys`
replaces Origin's anchor in every peer manifest (Mantle, Ember, Crystal, Chorus and each persona)
with the new key alone, so a token signed with the old key is refused there at once; and the peers
read Origin's published not-before (`GET /auth/not-before`, signed), so a token issued before the
rollover by the new key's predecessor's sessions ends there too. Run on Origin's host, as Origin's
own user, then restart Origin.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from origin.services import signing_keys

NEXT_PRIVATE = "origin.next.private.pem"
NEXT_PUBLIC = "origin.next.public.pem"


class RotationRefused(Exception):
    pass


def _write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".part")
    if tmp.exists():
        tmp.unlink()
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def mint_next(keys_dir: Optional[Path] = None) -> dict:
    """The next pair, minted once; `{"kid", "fingerprint"}`."""
    folder = Path(keys_dir) if keys_dir else signing_keys.keys_dir()
    pub = folder / NEXT_PUBLIC
    if not pub.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _write(folder / NEXT_PRIVATE, key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        _write(pub, key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    data = pub.read_bytes()
    return {"kid": signing_keys.kid_of(data), "fingerprint": signing_keys.fingerprint(data)}


def accept(kid: str, keys_dir: Optional[Path] = None) -> dict:
    """Make the next pair current, if `kid` names it; end every session and refresh family."""
    folder = Path(keys_dir) if keys_dir else signing_keys.keys_dir()
    priv, pub = folder / NEXT_PRIVATE, folder / NEXT_PUBLIC
    if not (priv.exists() and pub.exists()):
        raise RotationRefused("no next key: run --print first")
    next_pub = pub.read_bytes()
    if signing_keys.kid_of(next_pub) != kid:
        raise RotationRefused("the kid accepted is not the next key's")
    next_priv = priv.read_bytes()
    old_kid = signing_keys.current_kid(folder)
    cur_pub = folder / "origin.public.pem"
    if cur_pub.exists():
        _write(folder / f"origin.retired.{old_kid}.public.pem", cur_pub.read_bytes())
        signing_keys.record_retired(old_kid, folder=folder)
    _write(folder / "origin.private.pem", next_priv)
    _write(cur_pub, next_pub)
    _write(folder / signing_keys.KID_FILE, kid.encode("ascii"))
    priv.unlink()
    pub.unlink()
    from origin.key_manager import init_jwt_keys
    init_jwt_keys(folder / "origin.private.pem", cur_pub, key_id=kid)
    if keys_dir:
        signing_keys._active_dir = folder
    _end_every_session()
    return {"kid": kid, "retired": old_kid}


def _end_every_session() -> None:
    from sqlalchemy import update

    from origin.db.session import SessionLocal
    from origin.models.origin_session import OriginSession
    from origin.models.refresh_token import RefreshToken
    from origin.services import not_before

    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        db.execute(update(RefreshToken).where(RefreshToken.revoked_at.is_(None))
                   .values(revoked_at=now))
        db.execute(update(OriginSession).where(OriginSession.revoked_time.is_(None))
                   .values(revoked_time=now))
        not_before.end_everyone(db)
        db.commit()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--print", action="store_true", dest="show")
    g.add_argument("--accept", metavar="KID")
    args = ap.parse_args(argv)
    try:
        if args.show:
            out = mint_next()
            print(f"next kid {out['kid']} fingerprint {out['fingerprint']}")
        else:
            out = accept(args.accept)
            print(f"current kid {out['kid']} (retired {out['retired']}); every session ended")
    except RotationRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

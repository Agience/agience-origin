"""/internal/key-shares — Origin's share of each Mantle master key, for Mantle alone.

Mantle splits each principal's master key 2-of-3 and keeps share 2 here (`services.key_shares`
says how it is stored and when a write may replace one). Mantle combines its own share with this
one to use a key, so these two routes are the whole of Origin's part in key custody:

    PUT /internal/key-shares/{principal_id}   {"x", "y", "kcv", "supersedes"?}
    GET /internal/key-shares/{principal_id}   -> {"x", "y", "kcv"}
                                              |  404 {"absent": true}  (no share stored)
                                              |  503                   (a share that will not open)

The caller must be Mantle's enrolled service identity: a service JWT addressed to Origin
(`aud=origin`), signed by the key the authority manifest anchors for `mantle`, which `get_auth`
verifies as it does for every peer call. No other service, no person and no delegation reaches a
share. Chorus is a platform service too, and is refused here: it has no part in key custody.

Each token is also bound to the one call it was signed for, so a token taken from a log or a proxy
opens nothing else and nothing twice: it lives at most `MAX_TOKEN_TTL` seconds, carries a `jti`
that is accepted once (`key_custody_nonces`), and names the method (`htm`), the route path (`htu`)
and the principal (`principal_id`), each of which must match the request.

Every call is logged, refusals at WARNING. A release names the principal, the caller and the first
eight characters of the key-check value, never the share.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from jose import jwt as jose_jwt
from sqlalchemy.orm import Session

from origin.db.session import get_db
from origin.services import key_shares
from origin.services.dependencies import AuthContext, get_auth

logger = logging.getLogger(__name__)
_PREFIX = "/internal/key-shares"
key_share_router = APIRouter(prefix=_PREFIX, tags=["Internal"], include_in_schema=False)

#: The one service that holds the other share. A set of one, named, so a test can read it.
CUSTODIAN_PEERS = frozenset({"mantle"})

#: The longest lifetime (`exp - iat`) a custody token may have.
MAX_TOKEN_TTL = 60


def _require_mantle(auth: AuthContext = Depends(get_auth)) -> AuthContext:
    """Mantle's own service token, or 403.

    `principal_id` is the verified `iss`; `actor` is set only when a service token carries a
    `client_id` (a persona riding a shared key), which Mantle's never does.
    """
    if (auth.principal_type != "service" or auth.principal_id not in CUSTODIAN_PEERS
            or auth.actor is not None):
        logger.warning(
            "key share access refused: principal_type=%s principal=%s actor=%s",
            auth.principal_type, auth.principal_id, auth.actor,
        )
        raise HTTPException(status_code=403, detail="key custody peer only")
    return auth


def _bound(request: Request, principal_id: str, db: Session) -> None:
    """Refuse (401) a token not bound to this method, path and principal, or already spent.

    Runs after `_require_mantle`, so the signature is already verified; the claims are read from
    the same token."""
    if not key_shares.valid_principal(principal_id):
        raise HTTPException(status_code=400, detail="malformed principal id")
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header[:7].lower() == "bearer " else ""
    claims = jose_jwt.get_unverified_claims(token)
    why = ""
    iat, exp, jti = claims.get("iat"), claims.get("exp"), claims.get("jti")
    if not isinstance(iat, int) or not isinstance(exp, int) or exp - iat > MAX_TOKEN_TTL:
        why = f"lifetime over {MAX_TOKEN_TTL}s"
    elif not isinstance(jti, str) or not 8 <= len(jti) <= 128:
        why = "no jti"
    elif claims.get("htm") != request.method:
        why = "method"
    elif claims.get("htu") != f"{_PREFIX}/{principal_id}":
        why = "path"
    elif claims.get("principal_id") != principal_id:
        why = "principal"
    elif not key_shares.spend_token(db, jti, datetime.fromtimestamp(exp, timezone.utc)):
        why = "replayed"
    if why:
        logger.warning("key share access refused: principal=%s token not bound to this call (%s)",
                       principal_id, why)
        raise HTTPException(status_code=401, detail="token not bound to this call")


@key_share_router.put("/{principal_id}")
def put_share(principal_id: str, request: Request, body: dict = Body(...),
              db: Session = Depends(get_db), auth: AuthContext = Depends(_require_mantle)):
    _bound(request, principal_id, db)
    supersedes = body.get("supersedes")
    try:
        outcome = key_shares.store_share(
            db, principal_id, {k: body.get(k) for k in ("x", "y", "kcv")},
            supersedes=supersedes if isinstance(supersedes, str) else None,
        )
    except key_shares.ShareRejected as exc:
        logger.warning("key share store refused: principal=%s caller=%s (%s)",
                       principal_id, auth.principal_id, exc)
        raise HTTPException(status_code=400, detail=str(exc))
    except key_shares.ShareConflict:
        logger.warning(
            "key share store refused: principal=%s caller=%s a share of another key is stored",
            principal_id, auth.principal_id,
        )
        raise HTTPException(status_code=409, detail="a share of another key is stored")
    logger.info("key share %s: principal=%s caller=%s kcv=%s", outcome, principal_id,
                auth.principal_id, str(body.get("kcv"))[:8])
    return {"principal_id": principal_id, "outcome": outcome}


@key_share_router.get("/{principal_id}")
def get_share(principal_id: str, request: Request, db: Session = Depends(get_db),
              auth: AuthContext = Depends(_require_mantle)):
    _bound(request, principal_id, db)
    try:
        share = key_shares.release_share(db, principal_id)
    except key_shares.ShareUnreadable:
        logger.error("key share release refused: principal=%s the stored share does not decrypt",
                     principal_id)
        raise HTTPException(status_code=503, detail="the stored share could not be decrypted")
    if share is None:
        logger.info("key share release: principal=%s caller=%s NOT FOUND",
                    principal_id, auth.principal_id)
        return JSONResponse(status_code=404,
                            content={"absent": True, "principal_id": principal_id})
    logger.warning("key share released: principal=%s caller=%s kcv=%s",
                   principal_id, auth.principal_id, str(share.get("kcv"))[:8])
    return {"principal_id": principal_id, **share}

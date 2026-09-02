"""/oracle — the Key Oracle API. Operator-gated managed custody of secrets + encryption keys,
with Shamir k-of-n splitting for redundant, no-single-point key custody.

All routes require a valid Origin token whose principal is the platform operator (or carries
platform:admin). Secrets are encrypted at rest; release happens only over this authenticated door.

Every route here writes a log line, refusals included. This is the surface that releases plaintext
secrets and custodial key shares, so without a record a secret can be stored, read out in the clear,
split among custodians and reconstructed with nothing noting that it happened. An operator-only door
is a strong control and an unrecorded one is not auditable: it cannot answer "was this key released,
and when", and a stolen operator token used exactly as intended looks like nothing at all.

The value is never logged, only its identifier. A log that records what the vault released is a
second copy of the vault, in a file with weaker access control than the vault has.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session

from origin.db.session import get_db
from origin.services import key_oracle
from origin.services.dependencies import AuthContext, get_auth
from origin.services.platform_settings_service import settings as platform_settings

logger = logging.getLogger(__name__)
oracle_router = APIRouter(prefix="/oracle", tags=["Oracle"])


def _require_operator(auth: AuthContext = Depends(get_auth)) -> AuthContext:
    """Resolve the caller as the platform operator, or 403.

    Depends on `get_auth`, which enforces two properties this gate relies on before the check below
    even runs: `resolve_auth` rejects any token carrying `token_type` (a password-reset,
    email-verify, or refresh token is not an access token — see `dependencies.py`), and validates
    the audience for the principal. The vault has no reason to route around either — bypassing them
    would let a token minted for an unrelated purpose, or for a different audience, stand in as the
    operator here.

    Two conditions, matching `system_router._platform_admin_user_id` — this codebase's canonical
    operator gate:
      • `principal_type == "user"` rejects mcp_client / service / server. The vault is not a
        machine-to-machine surface.
      • `actor is None` rejects a delegation, which `resolve_auth` normalizes to
        `principal_type="user"` with `actor=act.sub` before this gate sees it — a `principal_type`
        check alone cannot distinguish one. The vault is the one door where a delegated machine
        token must never stand in for the human it acts for.

    Admin status is `user_id == platform.operator_id`, recomputed on every call — not a `roles`
    claim baked into the token, which would stay valid for the life of a 30-day refresh cycle even
    after the operator changed.

    A refusal is logged at WARNING. A rejected attempt on the vault is the more interesting of the
    two outcomes: the successes are the operator working, and a run of these is somebody else
    trying.
    """
    if auth.principal_type != "user" or auth.actor is not None or not auth.user_id:
        logger.warning(
            "oracle access refused: principal_type=%s user_id=%s actor=%s (not an operator)",
            auth.principal_type,
            auth.user_id,
            auth.actor,
        )
        raise HTTPException(status_code=403, detail="operator only")
    op = platform_settings.get("platform.operator_id")
    if op and str(auth.user_id) == str(op):
        return auth
    logger.warning("oracle access refused: user %s is not the platform operator", auth.user_id)
    raise HTTPException(status_code=403, detail="operator only")


@oracle_router.get("/secrets")
def list_secrets(db: Session = Depends(get_db), auth: AuthContext = Depends(_require_operator)):
    ids = key_oracle.list_ids(db)
    logger.info("oracle list: operator=%s count=%d", auth.user_id, len(ids))
    return {"ids": ids}


@oracle_router.put("/secrets/{key_id}")
def put_secret(key_id: str, body: dict = Body(...), db: Session = Depends(get_db), auth: AuthContext = Depends(_require_operator)):
    value = body.get("value")
    if not isinstance(value, str) or not value:
        raise HTTPException(status_code=400, detail="body.value (string) required")
    key_oracle.store_secret(db, key_id, value)
    logger.info("oracle store: operator=%s key_id=%s", auth.user_id, key_id)
    return {"stored": key_id}


@oracle_router.get("/secrets/{key_id}")
def get_secret(key_id: str, db: Session = Depends(get_db), auth: AuthContext = Depends(_require_operator)):
    v = key_oracle.get_secret(db, key_id)
    if v is None:
        logger.info("oracle release: operator=%s key_id=%s NOT FOUND", auth.user_id, key_id)
        raise HTTPException(status_code=404, detail="not found")
    # The one line that says a plaintext secret left the process.
    logger.warning("oracle release: operator=%s key_id=%s plaintext returned", auth.user_id, key_id)
    return {"id": key_id, "value": v}


@oracle_router.post("/secrets/{key_id}/split")
def split_secret(key_id: str, body: dict = Body(default={}), db: Session = Depends(get_db), auth: AuthContext = Depends(_require_operator)):
    """Return Shamir k-of-n shares of a stored secret (the 'key halves'). Distribute the shares to
    separate custodians; any k reconstruct the key, fewer than k reveal nothing."""
    v = key_oracle.get_secret(db, key_id)
    if v is None:
        logger.info("oracle split: operator=%s key_id=%s NOT FOUND", auth.user_id, key_id)
        raise HTTPException(status_code=404, detail="not found")
    k = int(body.get("k", 2))
    n = int(body.get("n", 3))
    if not (2 <= k <= n <= 255):
        raise HTTPException(status_code=400, detail="require 2 <= k <= n <= 255")
    logger.warning(
        "oracle split: operator=%s key_id=%s k=%d n=%d shares issued", auth.user_id, key_id, k, n
    )
    return {"id": key_id, "k": k, "n": n, "shares": key_oracle.split_secret(v, k=k, n=n)}


@oracle_router.post("/combine")
def combine(body: dict = Body(...), db: Session = Depends(get_db), auth: AuthContext = Depends(_require_operator)):
    """Reconstruct a secret from >= k Shamir shares (verification / recovery).

    A successful combine is not proof the right secret came back. `shamir.combine` does not know
    `k` — the threshold is not carried in a share — so interpolating k-1 shares of a k-of-n split,
    or shares belonging to two different secrets, returns wrong bytes rather than raising. The one
    backstop is the UTF-8 decode in `key_oracle.combine_shares`, which catches most garbage and not
    all of it. Binding the threshold and a checksum into the share format would close it, and it
    changes the share encoding, so it is not made here.

    The log line below is what makes a wrong reconstruction visible after the fact: it records the
    share count, which distinguishes a correct combine from an under-threshold one to anyone who
    knows how the secret was split.
    """
    shares = body.get("shares")
    if not isinstance(shares, list) or len(shares) < 2:
        raise HTTPException(status_code=400, detail="body.shares (>=2) required")
    try:
        value = key_oracle.combine_shares(shares)
    except Exception:
        logger.warning(
            "oracle combine: operator=%s shares=%d FAILED", auth.user_id, len(shares), exc_info=True
        )
        raise HTTPException(status_code=400, detail="could not combine shares")
    logger.warning(
        "oracle combine: operator=%s shares=%d plaintext reconstructed", auth.user_id, len(shares)
    )
    return {"value": value}

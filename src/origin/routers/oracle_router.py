"""/oracle — the Key Oracle API. Operator-gated managed custody of secrets + encryption keys,
with Shamir k-of-n splitting for redundant, no-single-point key custody.

Every operator route requires the platform operator signed in to Origin's own operator console
(a console token no other service ever receives) and a fresh passkey step-up bound to the request
(`_require_operator`, `services/operator_console.py`). Secrets are encrypted at rest; release
happens only over this door.

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
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from origin.db.session import get_db
from origin.services import key_oracle, operator_console
from origin.services.dependencies import AuthContext
from origin.services.platform_settings_service import settings as platform_settings

logger = logging.getLogger(__name__)
oracle_router = APIRouter(prefix="/oracle", tags=["Oracle"])


def _operator_id() -> Optional[str]:
    op = platform_settings.get("platform.operator_id")
    return str(op) if op else None


async def _require_operator(request: Request, db: Session = Depends(get_db),
                            who: str = Depends(operator_console.get_console_auth)) -> AuthContext:
    """The platform operator, signed in to Origin's own operator console, with a fresh passkey
    step-up for this very request; otherwise 403.

    Two things, both checked on every call (`services/operator_console.py`):
      - The bearer is a console token: minted only by `/oracle/console/sign-in` after a passkey
        sign-in by the operator, addressed to an audience no other token carries and no other
        service accepts, and naming the operator recomputed now from `platform.operator_id`. An
        ordinary access token, a delegation, a refresh or reset token, or a token minted for any
        other audience is refused.
      - The `X-Operator-Step-Up` header holds a passkey assertion, with user verification, over a
        single-use challenge whose leading bytes are the digest of this request's method, path
        and body. An assertion for another call, or a spent one, is refused.

    A refusal is logged at WARNING: the successes are the operator working, and a run of refusals
    is somebody else trying.
    """
    try:
        body = await request.body()
        operator_console.verify_step_up(db, who, request.headers.get(
            operator_console.STEP_UP_HEADER, ""), request.method,
            request.url.path + (f"?{request.url.query}" if request.url.query else ""), body)
    except HTTPException as exc:
        logger.warning("oracle access refused on %s %s: %s", request.method, request.url.path,
                       exc.detail)
        raise
    return AuthContext(principal_id=who, principal_type="user", user_id=who)


# -- the operator console: sign-in and step-up ---------------------------------------------------

@oracle_router.post("/console/sign-in-options")
def console_sign_in_options(db: Session = Depends(get_db)):
    """A passkey challenge for the operator to sign in to the console."""
    operator = _operator_id()
    if not operator:
        raise HTTPException(status_code=409, detail="no platform operator is set")
    return operator_console.sign_in_options(db, operator)


@oracle_router.post("/console/sign-in")
def console_sign_in(body: dict = Body(...), db: Session = Depends(get_db)):
    """A console token, for the operator's verified passkey assertion."""
    operator = _operator_id()
    if not operator or not isinstance(body.get("credential"), dict)             or not isinstance(body.get("challenge"), str):
        raise HTTPException(status_code=401, detail="operator console sign-in failed")
    issued = operator_console.sign_in(db, operator, body["credential"], body["challenge"])
    logger.info("operator console sign-in by %s", operator)
    return issued


@oracle_router.post("/console/step-up-options")
def console_step_up_options(body: dict = Body(...), db: Session = Depends(get_db),
                            who: str = Depends(operator_console.get_console_auth)):
    """A step-up challenge for one operator request: `{method, path, body_sha256}`."""
    method, path = body.get("method"), body.get("path")
    if not isinstance(method, str) or not isinstance(path, str) or not path.startswith(
            operator_console.STEP_UP_PATHS):
        raise HTTPException(status_code=400, detail="method and a console path ("
                            + ", ".join(operator_console.STEP_UP_PATHS) + ") are required")
    return operator_console.step_up_options(db, who, method, path, str(body.get("body_sha256")))


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


# ---------------------------------------------------------------------------
# Background work, and the authority ledger's integrity
# ---------------------------------------------------------------------------
#
# Background work runs only on a job grant (John, 2026-11-02): a person grants a named job over
# their own key, an Admin over a collection's, as an entry in the ledger. The operator lists and
# revokes them here, and grants jobs for the platform's own principal only. There is no standing
# authority: what no one granted stays shut.

@oracle_router.get("/job-grants")
def list_job_grants(db: Session = Depends(get_db), auth: AuthContext = Depends(_require_operator)):
    from origin.services import authority_ledger
    return {"grants": authority_ledger.job_grants(db)}


@oracle_router.post("/job-grants")
def grant_platform_job(body: dict = Body(...), db: Session = Depends(get_db),
                       auth: AuthContext = Depends(_require_operator)):
    """A job for the platform's own principal: `{"job", "hours", "collections"?}`; or the split
    of a non-person principal's key: `{"job": "platform.custody", "hours", "principal"}` (review
    26, H1). A person's or a collection's key is theirs or its Admins' to grant, never the
    operator's."""
    from origin.services import authority_ledger
    principal = body.get("principal")
    if principal is not None:
        if body.get("job") != authority_ledger.NON_PERSON_CUSTODY_JOB or body.get("collections"):
            raise HTTPException(status_code=400, detail="over a principal other than the "
                                "platform's own, the operator grants only "
                                f"{authority_ledger.NON_PERSON_CUSTODY_JOB}, and over its key alone")
    job, hours = body.get("job"), body.get("hours", 24)
    cols = body.get("collections") or []
    if not isinstance(job, str) or not isinstance(hours, int) or isinstance(hours, bool) \
            or not isinstance(cols, list):
        raise HTTPException(status_code=400, detail="body.job, body.hours (integer) and "
                            "body.collections (list) are required")
    try:
        receipt = authority_ledger.operator_job_grant(db, job=job, hours=hours, collections=cols,
                                                      operator_id=str(auth.user_id), ref="job",
                                                      principal=principal)
    except authority_ledger.EntryRefused as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    logger.warning("job grant for the platform principal: job=%s by %s", job, auth.user_id)
    return receipt


@oracle_router.post("/charged-roots/{principal_id}/rotation")
def record_charged_root_rotation(principal_id: str, body: dict = Body(...),
                                 db: Session = Depends(get_db),
                                 auth: AuthContext = Depends(_require_operator)):
    """Step 21 rotated this charged root's key: `{"kcv"}`, the rotated key's key-check value as
    `rekey_collections` reports it (`charged_roots.<root>.kcv`), review 31. The operator's
    `platform.custody` grant over a charged root needs this record, and Origin stores and
    releases that root's share only for this key, while its split reads back."""
    from origin.services import authority_ledger
    try:
        out = authority_ledger.record_rotation(db, principal_id, body.get("kcv"),
                                               str(auth.user_id))
    except authority_ledger.EntryRefused as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    return out


@oracle_router.get("/charged-roots/shares")
def charged_root_shares(db: Session = Depends(get_db),
                        auth: AuthContext = Depends(_require_operator)):
    """Step 23's check (review 32): each charged root's share at Origin, as counts and ids only:
    `activated`, `pending` (split but not activated: re-run step 21, record the fresh kcv, grant
    and split again) and `none` (no share: not split, or its key was removed)."""
    from origin.services import authority_ledger
    out = authority_ledger.charged_root_shares(db)
    logger.info("charged-root shares listed by %s: %d activated, %d pending, %d none",
                auth.user_id, out["activated_count"], out["pending_count"], out["none_count"])
    return out


@oracle_router.post("/job-grants/{grant_id}/revoke")
def revoke_job_grant(grant_id: str, db: Session = Depends(get_db),
                     auth: AuthContext = Depends(_require_operator)):
    from origin.services import authority_ledger
    try:
        receipt = authority_ledger.revoke_job_grant(db, grant_id, str(auth.user_id), "revoke")
    except authority_ledger.EntryRefused as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    logger.warning("job grant %s revoked by operator %s", grant_id, auth.user_id)
    return {"grant_id": grant_id, "revoked": True, "receipt": receipt}


@oracle_router.put("/settings/{key}")
def put_console_setting(key: str, body: dict = Body(...), db: Session = Depends(get_db),
                        auth: AuthContext = Depends(_require_operator)):
    """A setting the console, bootstrap, step-up or custody reads (`is_console_key`), changed by
    the operator through the console with a step-up. Nothing else writes these."""
    from origin.services.platform_settings_service import is_console_key

    if not is_console_key(key):
        raise HTTPException(status_code=400, detail="not a console setting; use /system/settings")
    value = body.get("value")
    if not isinstance(value, str) or not value:
        raise HTTPException(status_code=400, detail="body.value is a non-empty string")
    pinning = key.lower() == "platform.authority_collection_id"
    if pinning:
        # Pinned only to a collection Origin's own replica knows: the operator reads its root,
        # creator and admins at `/oracle/authority-ledger/collection/{id}`, never Mantle's report.
        from origin.services import authority_ledger
        if authority_ledger.collection_view(db, value) is None:
            raise HTTPException(status_code=409, detail="Origin's replica does not know this "
                                "collection; pin only one its root or creation edge brought in")
    platform_settings.set_many(db, [{"key": key, "value": value,
                                     "category": key.split(".")[0]}], updated_by=str(auth.user_id))
    logger.warning("oracle console setting changed: %s by %s", key, auth.user_id)
    appointed = None
    if pinning:
        appointed = authority_ledger.pinned_admin_alerts(db, value, str(auth.user_id))
    return {"key": key, "updated": True, **({"admins_alerted": appointed} if pinning else {})}


@oracle_router.get("/authority-ledger/collection/{collection_id}")
def collection_view(collection_id: str, db: Session = Depends(get_db),
                    auth: AuthContext = Depends(_require_operator)):
    """Origin's own view of a collection: its root and creator as the replica holds them, and
    every person holding live Admin on it. What the operator checks before pinning it."""
    from origin.services import authority_ledger
    view = authority_ledger.collection_view(db, collection_id)
    if view is None:
        raise HTTPException(status_code=404, detail="Origin's replica does not know this "
                            "collection")
    return view


# -- the ledger: what is pending, and what a credential did --------------------------------------

@oracle_router.get("/authority-ledger/unconfirmed")
def list_unconfirmed(db: Session = Depends(get_db), auth: AuthContext = Depends(_require_operator)):
    """Entries whose write Mantle has not confirmed: a write that may not have committed, or a
    withdrawal still due at Mantle."""
    from origin.services import authority_ledger

    return {"entries": authority_ledger.unconfirmed(db)}


@oracle_router.post("/authority-ledger/resolve")
def resolve_unconfirmed(body: dict = Body(...), db: Session = Depends(get_db),
                        auth: AuthContext = Depends(_require_operator)):
    """Settle one unconfirmed entry: `{"seq", "decision": "withdraw" | "keep"}`. A withdrawal is
    the operator's own entry in the ledger; either way Mantle's due withdrawal clears."""
    from origin.services import authority_ledger

    seq, decision = body.get("seq"), body.get("decision")
    if not isinstance(seq, int) or isinstance(seq, bool) or decision not in ("withdraw", "keep"):
        raise HTTPException(status_code=400, detail="seq and decision (withdraw or keep)")
    try:
        out = authority_ledger.resolve_unconfirmed(db, seq, decision, str(auth.user_id),
                                                   f"console:{auth.user_id}")
    except authority_ledger.EntryRefused as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    logger.warning("authority ledger: operator %s resolved entry %s (%s)", auth.user_id, seq,
                   decision)
    return out


@oracle_router.get("/authority-ledger/entries")
def list_entries(credential_ref: Optional[str] = None, since: Optional[str] = None,
                 until: Optional[str] = None, db: Session = Depends(get_db),
                 auth: AuthContext = Depends(_require_operator)):
    """Ledger entries made on one credential (`credential_ref`) and/or in a time window."""
    from origin.services import authority_ledger

    try:
        lo = authority_ledger.parse_time(since) if since else None
        hi = authority_ledger.parse_time(until) if until else None
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="since and until are ISO-8601 times")
    return {"entries": authority_ledger.entries_by_credential(db, credential_ref, lo, hi)}


@oracle_router.post("/authority-ledger/revoke")
def revoke_entries(body: dict = Body(...), db: Session = Depends(get_db),
                   auth: AuthContext = Depends(_require_operator)):
    """Undo entries, `{"seqs": [...]}`: each grant they made is revoked and each edge they added
    removed, as the operator's own entries. For grants co-signed during a compromise."""
    from origin.services import authority_ledger

    seqs = body.get("seqs")
    if not isinstance(seqs, list) or not all(isinstance(s, int) and not isinstance(s, bool)
                                             for s in seqs):
        raise HTTPException(status_code=400, detail="seqs is a list of entry numbers")
    out = []
    for s in seqs:
        try:
            out.append({"seq": s, "receipt": authority_ledger.revoke_entry(
                db, s, str(auth.user_id), f"console:{auth.user_id}")})
        except authority_ledger.EntryRefused as exc:
            out.append({"seq": s, "refused": str(exc)})
    logger.warning("authority ledger: operator %s revoked entries %s", auth.user_id, seqs)
    return {"revoked": out}


@oracle_router.post("/seed-credential")
def mint_seed_credential(body: dict = Body(default={}), db: Session = Depends(get_db),
                         auth: AuthContext = Depends(_require_operator)):
    """Mint the credential one seed pass runs on: the platform system principal's, scoped to
    seeding, ten minutes at most. A deliberate act by the operator for each pass; background work
    can never widen reach, and a seed that grants needs this."""
    from origin.services import share_credentials

    minutes = body.get("minutes", 10)
    if not isinstance(minutes, int) or isinstance(minutes, bool) or minutes < 1:
        raise HTTPException(status_code=400, detail="body.minutes must be a positive integer")
    rekey = body.get("rekey_shares")
    if rekey is not None and (not isinstance(rekey, list)
                              or not all(isinstance(k, str) and k for k in rekey)):
        raise HTTPException(status_code=400, detail="body.rekey_shares is a list of key ids")
    # The pass's planned entries, by digest (review 25, M4): the seed makes these and no others.
    import re as _re
    plan = body.get("plan")
    if plan is not None and (not isinstance(plan, list) or not all(
            isinstance(d, str) and _re.fullmatch(r"[0-9a-f]{64}", d) for d in plan)):
        raise HTTPException(status_code=400, detail="body.plan is a list of entry digests")
    try:
        minted = share_credentials.mint_seed_credential(db, str(auth.user_id), minutes,
                                                        rekey_shares=rekey, plan=plan)
    except share_credentials.CredentialRefused as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    logger.warning("seed credential minted: operator=%s jti=%s expires=%s planned=%d",
                   auth.user_id, minted["jti"], minted["expires_at"], len(plan or []))
    return minted


@oracle_router.delete("/seed-credential/{jti}")
def revoke_seed_credential(jti: str, db: Session = Depends(get_db),
                           auth: AuthContext = Depends(_require_operator)):
    from origin.services import share_credentials

    if not share_credentials.revoke_seed_credential(db, jti):
        raise HTTPException(status_code=404, detail="no such seed credential")
    logger.warning("seed credential revoked: operator=%s jti=%s", auth.user_id, jti)
    return {"jti": jti, "revoked": True}


@oracle_router.delete("/delegations/{jti}")
def revoke_delegation(jti: str, db: Session = Depends(get_db),
                      auth: AuthContext = Depends(_require_operator)):
    """Revoke a person's delegation by `jti`: it stops acting at a key release or on the
    authority ledger at once."""
    from origin.services import share_credentials

    if not share_credentials.revoke_delegation(db, jti):
        raise HTTPException(status_code=404, detail="no such delegation")
    logger.warning("delegation revoked: operator=%s jti=%s", auth.user_id, jti)
    return {"jti": jti, "revoked": True}


@oracle_router.post("/authority-ledger/bootstrap")
def open_authority_bootstrap(body: dict = Body(default={}), db: Session = Depends(get_db),
                             auth: AuthContext = Depends(_require_operator)):
    """Issue the bootstrap credential `mantle.system.cosign_authority` presents: good for
    bootstrap entries and nothing else, `minutes` long (60 by default and at most). Returned once;
    `DELETE` withdraws every one."""
    from origin.services import authority_ledger

    minutes = body.get("minutes", 60)
    if not isinstance(minutes, int) or isinstance(minutes, bool) or minutes < 1:
        raise HTTPException(status_code=400, detail="body.minutes must be a positive integer")
    ids = body.get("ids")
    if ids is not None and (not isinstance(ids, list) or not all(isinstance(i, str) for i in ids)):
        raise HTTPException(status_code=400, detail="body.ids is a list of ids")
    issued = authority_ledger.issue_bootstrap_credential(db, str(auth.user_id), minutes, ids=ids)
    logger.warning("authority ledger bootstrap credential issued: operator=%s jti=%s until %s",
                   auth.user_id, issued["id"], issued["expires_at"])
    return issued


@oracle_router.delete("/authority-ledger/bootstrap")
def close_authority_bootstrap(db: Session = Depends(get_db),
                              auth: AuthContext = Depends(_require_operator)):
    from origin.services import authority_ledger

    closed = authority_ledger.close_bootstrap(db)
    logger.warning("authority ledger bootstrap closed: operator=%s windows=%d", auth.user_id,
                   closed)
    return {"closed": closed}


@oracle_router.get("/authority-ledger/verify")
def verify_authority_ledger(db: Session = Depends(get_db),
                            auth: AuthContext = Depends(_require_operator)):
    """Recompute every entry's hash and link, check every co-signature against the key that made
    it, and compare the replay of the whole chain with the replica tables."""
    from origin.services import authority_ledger

    ok, detail = authority_ledger.verify_chain(db)
    seq, digest = authority_ledger.head(db)
    if not ok:
        logger.error("authority ledger verification failed: %s", detail)
    return {"ok": ok, "detail": detail, "seq": seq, "entry_hash": digest}


# -- key shares, roots and alerts (the sixth review, 2026-11-02) --------------------------------

@oracle_router.get("/key-shares/{principal_id}/history")
def key_share_history(principal_id: str, db: Session = Depends(get_db),
                      auth: AuthContext = Depends(_require_operator)):
    """The shares a replacement superseded for this key, newest first (never their `y`)."""
    from origin.services import key_shares
    return {"principal_id": principal_id, "history": key_shares.share_history(db, principal_id)}


@oracle_router.post("/key-shares/{principal_id}/restore")
def restore_key_share(principal_id: str, body: dict = Body(...), db: Session = Depends(get_db),
                      auth: AuthContext = Depends(_require_operator)):
    """Put back a superseded share (`{"history_id"}`); the share it replaces is kept."""
    from origin.services import key_shares
    hid = body.get("history_id")
    if not isinstance(hid, int) or isinstance(hid, bool):
        raise HTTPException(status_code=400, detail="body.history_id is an integer")
    try:
        out = key_shares.restore_share(db, principal_id, hid, str(auth.user_id))
    except key_shares.ShareRejected as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    logger.warning("key share %s restored from history %s by operator %s", principal_id, hid,
                   auth.user_id)
    return out


@oracle_router.post("/authority-ledger/retire-root")
def retire_root(body: dict = Body(...), db: Session = Depends(get_db),
                auth: AuthContext = Depends(_require_operator)):
    """Clear a planted root or node (`{"principal_id", "reason"}`): its grants revoked, its edges
    removed, then the root and node retired, each the operator's own entry."""
    from origin.services import authority_ledger
    pid = body.get("principal_id")
    if not isinstance(pid, str) or not pid:
        raise HTTPException(status_code=400, detail="body.principal_id is required")
    try:
        receipts = authority_ledger.retire_root(db, pid, str(auth.user_id),
                                                str(body.get("reason") or "")[:64] or "retire")
    except authority_ledger.EntryRefused as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    logger.warning("root %s retired by operator %s (%d entries)", pid, auth.user_id,
                   len(receipts))
    return {"principal_id": pid, "receipts": receipts}




@oracle_router.get("/alerts")
def list_alerts(all: bool = False, db: Session = Depends(get_db),  # noqa: A002
                auth: AuthContext = Depends(_require_operator)):
    """The operator's alerts: every Admin grant and every grant on the Authorities collection,
    as co-signed; unacknowledged ones unless `all`."""
    from origin.services import authority_ledger
    return {"alerts": authority_ledger.alerts(db, include_acknowledged=all)}


@oracle_router.post("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db),
                      auth: AuthContext = Depends(_require_operator)):
    from origin.services import authority_ledger
    if not authority_ledger.acknowledge_alert(db, alert_id, str(auth.user_id)):
        raise HTTPException(status_code=404, detail="no such alert")
    return {"id": alert_id, "acknowledged": True}

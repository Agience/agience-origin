"""Origin auth issuance + low-level helpers.

Owns:
- JWT issuance (user, server, delegation tokens)
- Refresh token + nonce issuance
- Password hashing (PBKDF2)
- Allow-list and redirect-uri checks
- PKCE helpers
- OAuth2 error constants

Token verification (`verify_token`) lives in `origin/services/auth_verifier.py`. Origin signs;
Origin and its peers verify. A nonce is verified by the resource server, never here.

Origin neither generates nor verifies API keys.
"""

from __future__ import annotations

import base64
import fnmatch
import functools
import hashlib
import hmac
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from urllib.parse import urlparse

import anyio.to_thread
from anyio import CapacityLimiter
from anyio.lowlevel import RunVar
from fastapi import HTTPException
from jose import jwt

from origin import config
from origin.key_manager import get_key_id, get_private_key_pem

_logger = logging.getLogger(__name__)

JWT_ALGORITHM = "RS256"
NONCE_TTL_SECONDS = 1800

# Password hashing
_PWD_ALG = "pbkdf2_sha256"


# ---------------------------------------------------------------------------
# How long an access token stays good
# ---------------------------------------------------------------------------
# This is the platform's revocation lag, and not a preference about session length. Peers verify
# Origin's tokens OFFLINE, against the inline JWKS in their authority manifest, and never call
# back — no introspection, no revocation check, no callback of any kind — so nothing decided here
# reaches them. Deleting an account, demoting an operator, resetting a password: none of them stop
# a token already in a browser. It stops when `exp` passes, and that is the only thing that stops
# it.
#
# The value is bracketed rather than chosen, by two facts about this platform.

#: LOWER BOUND — the shortest lifetime Origin already issues, and it goes to the holder that renews
#: without a human: `_grant_client_credentials` mints one hour to a machine that can re-request
#: silently whenever it likes.
#:
#: No client in the fleet refreshes: each keeps the access token alone and drops the refresh token
#: the grant hands it. For a person this window is therefore the whole sign-in, and its end is a
#: password, an OTP or a passkey rather than a round trip. Going below the machine's hour would be
#: the platform charging a human more often than it charges a process that pays nothing.
_UNATTENDED_RENEWAL_HOURS = 1.0

#: UPPER BOUND — the shift the revocation has to land inside. A lag at or above a working day is an
#: operator revoking a credential in the morning and watching it keep working until evening: the
#: control exists, but not within the incident it was reached for.
#:
#: Everything a peer does to make a revoke land promptly — expiring cached read verdicts,
#: re-resolving an open socket's authentication — sits under this number, because a verdict
#: re-asked every 30 seconds is re-asked on behalf of a credential nobody can withdraw.
_WORKING_DAY_HOURS = 8.0


def access_token_ttl_hours() -> float:
    """Half the shift: a credential revoked at any point in one stops working before it ends.

    At the values above that is 4 hours: revoke at the start of a shift and the token is dead by
    the middle of it. It is four times the unattended-renewal floor, so a person signs in at most
    twice across a working day where a machine renews eight times.

    Both bounds move it. A fleet that grows a client which actually holds the refresh token lowers
    the floor, because renewal stops costing a credential; a deployment that must answer faster than
    half a shift lowers the ceiling.

    A function rather than a module constant, for the reason `db.session.sqlite_busy_timeout_ms`
    gives: a constant assigned from an expression is indistinguishable from the same number typed
    in, and a test can only tell the two apart by perturbing an input and watching — which requires
    the expression still to be there when it looks.
    """
    return _WORKING_DAY_HOURS / 2


def access_token_expires_in_seconds() -> int:
    """The `expires_in` a token grant advertises, in the seconds OAuth states it in.

    Derived from the same function the `exp` claim is, so a grant cannot advertise one lifetime
    while minting another.
    """
    return int(access_token_ttl_hours() * 3600)


# ---------------------------------------------------------------------------
# JWT issuance
# ---------------------------------------------------------------------------
def create_jwt_token(user_data: dict, expires_hours: Optional[float] = None) -> str:
    """Sign a JWT with Origin's RSA private key (RS256).

    `expires_hours` resolves at call time rather than in the signature: a default bound at import is
    a copy of whatever the derivation returned once, which is the same constant-in-a-costume the
    function exists to avoid.
    """
    payload = user_data.copy()
    # A service account's access token is a delegation narrowed to its audience, whatever route
    # signs it in (review 11, M5): Origin narrows it, the service cannot widen it.
    if (not payload.get("token_type") and payload.get("principal_type", "user") == "user"
            and not payload.get("act") and payload.get("sub")):
        from origin.services import service_accounts
        audience = service_accounts.audience_of(str(payload["sub"]))
        if audience:
            scopes = narrow_audiences().get(audience)
            if scopes is None:
                raise ValueError(f"service account audience {audience!r} is not a narrow audience")
            return issue_narrow_delegation(str(payload["sub"]), audience, scopes)
    now = datetime.now(timezone.utc)
    hours = access_token_ttl_hours() if expires_hours is None else expires_hours
    payload.setdefault("iat", now.timestamp())
    payload.setdefault("exp", (now + timedelta(hours=hours)).timestamp())
    payload.setdefault("iss", config.AUTHORITY_ISSUER)
    return jwt.encode(
        payload,
        get_private_key_pem(),
        algorithm=JWT_ALGORITHM,
        headers={"kid": get_key_id()},
    )


#: The one answer a deactivated account gets, from every route that would sign it in.
DEACTIVATED_DETAIL = "This account is deactivated. Contact support to restore it."


def is_deactivated(person) -> bool:
    return bool(getattr(person, "deactivated_at", None))


def refuse_if_deactivated(person) -> None:
    """403 for a deactivated account. Called by `person_token_claims`, so no route mints a person
    token for one, and before that by the routes that would otherwise do something first (send a
    confirmation link, mint an authorization code, refresh)."""
    if is_deactivated(person):
        raise HTTPException(status_code=403, detail=DEACTIVATED_DETAIL)


def person_token_claims(person, *, client_id: str, roles: Optional[list[str]] = None) -> dict:
    """The claims of an access token that names a person, for every route that signs one in.

    `email_verified` is the stored fact about `email`, and peers decide access from it: Mantle
    matches an email or domain invite only when the token asserts it, and reads its absence as
    false. Every person mint goes through here so no sign-in route can issue a token that omits
    it. A refresh copies these claims forward, so a refreshed token carries it too.

    `roles` is included only when the caller computes it; the OTP and passkey routes mint without
    it and the refresh grant derives it.
    """
    refuse_if_deactivated(person)
    claims = {
        "sub": str(person.id),
        "email": person.email or "",
        "name": person.name or "",
        "picture": person.picture or "",
        "email_verified": bool(person.email_verified),
        "client_id": client_id,
        "aud": config.AUTHORITY_ISSUER,
    }
    if roles is not None:
        claims["roles"] = roles
    return claims


#: Where a persona's server delegation is addressed: Mantle, the one service it is sent to.
SERVER_DELEGATION_AUDIENCE = "mantle"


def job_reach_of(claims: dict) -> Optional[dict]:
    """The timer job a verified delegation was minted under, as the claims every delegation
    exchanged from it carries on (`job_reach`, `job_grant`), or None. A delegation that carries a
    reach is never exchanged for one that does not."""
    if not isinstance(claims, dict) or "job_reach" not in claims:
        return None
    reach = claims.get("job_reach")
    return {"job_reach": [str(r) for r in reach] if isinstance(reach, list) else [],
            "job_grant": str(claims.get("job_grant") or "")}


def _job_claims(job_reach: Optional[list], job_grant: Optional[str]) -> dict:
    if job_reach is None:
        return {}
    return {"job_reach": sorted({str(r) for r in job_reach if r}),
            **({"job_grant": job_grant} if job_grant else {})}


def issue_delegation_token(server_client_id: str, user_id: str, ttl_seconds: int = 300,
                           *, signer: str = "", jti: Optional[str] = None,
                           narrowed_scope: Optional[str] = None,
                           job_reach: Optional[list] = None,
                           job_grant: Optional[str] = None) -> str:
    """Short-lived RFC 8693 delegation JWT — server acting on behalf of a user.

    `user_id` MUST already be derived from a token Origin itself verified (see
    `POST /internal/delegation-token`) — never a caller-asserted subject. This
    helper only signs; the endpoint owns proving the subject.

    Carries the full identity chain a resource server needs: sub=user_id (User),
    act.sub=server_client_id (Server), iss=AUTHORITY_ISSUER (Authority), host_id (Host). It is
    addressed to Mantle (`aud` `mantle`, review 22), where the persona sends it, and never to the
    persona itself: one addressed to the persona would be taken back at the persona by whoever it
    was sent to. host_id is derived from the shared instance
    namespace (`KEYS_DIR/instance.uuid`) so it matches the host artifact's id
    without Origin needing to read the platform topology.

    `act.iss` names the service whose signature asked for it: the persona itself when it signed
    with its own enrolled key, `chorus` when the shared identity asked for it. A resource server
    trusts the actor (`act.sub`) as proven only when the two agree.

    `narrowed_scope`, when the delegation was exchanged from one narrowed to the persona, carries
    that narrowing on: the scope and Origin's `narrowed` claim, so a resource server bounds the
    server delegation as it bounds the narrowed one (review 12, H5).
    """
    from origin.service_identity import get_host_id

    host_id = get_host_id()

    now = datetime.now(timezone.utc)
    payload = {
        "iss": config.AUTHORITY_ISSUER,
        "sub": user_id,
        "aud": SERVER_DELEGATION_AUDIENCE,
        "act": {"sub": server_client_id, **({"iss": signer} if signer else {})},
        "principal_type": "delegation",
        "host_id": host_id,
        "iat": now.timestamp(),
        "exp": (now + timedelta(seconds=ttl_seconds)).timestamp(),
        **({"jti": jti} if jti else {}),
        **({"narrowed": True, "scope": narrowed_scope} if narrowed_scope is not None else {}),
        **_job_claims(job_reach, job_grant),
    }
    return jwt.encode(
        payload,
        get_private_key_pem(),
        algorithm=JWT_ALGORITHM,
        headers={"kid": get_key_id()},
    )


def issue_use_verdict(*, persona: str, subject: str, delegation_jti: str, credential_id: str,
                      card_id: str, grants: dict, sealed_sha256: str = "",
                      endpoints_sha256: str = "", nonce: str = "") -> str:
    """Origin's signed verdict that `persona` may use `credential_id`'s secret for `card_id`, on
    the delegation `delegation_jti` for `subject` (review 21, F1). The claims are
    `prism.trust.use_verdict`'s; `token_type` keeps it from ever being taken as an access token.
    It also carries the digests of the persona's sealed copy and of the endpoint list as the
    credential's writer recorded them, and the persona's own nonce for this one use (review 22).
    The caller (`services.use_verdict`) has already decided it."""
    from prism.trust import use_verdict

    now = datetime.now(timezone.utc)
    payload = {
        "iss": config.AUTHORITY_ISSUER, "sub": str(subject),
        "aud": f"{use_verdict.SERVER_PREFIX}{persona}", "token_type": use_verdict.TOKEN_TYPE,
        "persona": persona, "delegation_jti": delegation_jti, "credential_id": credential_id,
        "card_id": card_id, "grants": {k: str(grants[k]) for k in use_verdict.GRANT_CLAIMS},
        "sealed_sha256": sealed_sha256, "endpoints_sha256": endpoints_sha256, "nonce": nonce,
        "iat": int(now.timestamp()), "exp": int(now.timestamp()) + use_verdict.VERDICT_TTL,
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, get_private_key_pem(), algorithm=JWT_ALGORITHM,
                      headers={"kid": get_key_id()})


#: The longest a system delegation lives (review 15).
SYSTEM_DELEGATION_MAX_TTL = 300


def issue_system_delegation_token(
    subject_id: str,
    *,
    actor: str,
    signer: str = "",
    scope: str,
    audience: str,
    ttl_seconds: int = 300,
    jti: Optional[str] = None,
) -> str:
    """Mint a delegation for the platform's system principal (not an arbitrary user).

    Used by the system-delegation exchange so platform automation (webhooks,
    background sends) can act as the operator-rooted `platform-system` principal.
    Carries the full identity chain — Authority (iss), Host (host_id), Server
    (act.sub = the requesting platform service), User (sub = the system principal) —
    plus a `scope` bounding what it may do. The subject is fixed to the system
    principal by the caller (the endpoint), not chosen by the requester.
    """
    from origin.service_identity import get_host_id

    # Never longer than `SYSTEM_DELEGATION_MAX_TTL`, whatever was asked (review 15).
    ttl_seconds = max(1, min(int(ttl_seconds or 0), SYSTEM_DELEGATION_MAX_TTL))
    now = datetime.now(timezone.utc)
    payload = {
        "iss": config.AUTHORITY_ISSUER,
        "sub": subject_id,
        "aud": audience,
        "act": {"sub": actor, **({"iss": signer} if signer else {})},
        "scope": scope,
        "principal_type": "delegation",
        "host_id": get_host_id(),
        "iat": now.timestamp(),
        "exp": (now + timedelta(seconds=ttl_seconds)).timestamp(),
        **({"jti": jti} if jti else {}),
    }
    return jwt.encode(
        payload,
        get_private_key_pem(),
        algorithm=JWT_ALGORITHM,
        headers={"kid": get_key_id()},
    )


# ---------------------------------------------------------------------------
# Password (PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------------------------
#: The fallback when `config.PASSWORD_PBKDF2_ITERS` is missing or zero, and the value `config`
#: itself defaults to — OWASP's current PBKDF2-HMAC-SHA256 floor for password storage. Named once
#: here so the fallback and the configured default cannot drift apart into a state where the
#: timing-equalizing dummy costs something different from a real verify.
DEFAULT_PBKDF2_ITERS = 600_000


def _configured_iters() -> int:
    return int(getattr(config, "PASSWORD_PBKDF2_ITERS", 0) or DEFAULT_PBKDF2_ITERS)


def kdf_threads() -> int:
    """How many key derivations (PBKDF2 here, bcrypt for OTP codes and client secrets) run at once.

    `ORIGIN_KDF_THREADS` when set to a positive integer. Otherwise one fewer than the CPUs this
    process may run on — `os.sched_getaffinity` where the platform has it, so a pinned or
    cpuset-limited process counts its own CPUs rather than the host's, else `os.cpu_count()`. The
    derivations are CPU-bound and `hashlib.pbkdf2_hmac` releases the GIL, so they run in parallel up
    to that many cores; the one held back is for the event loop, which also runs every database
    query. The floor is 1, not 2: on a single-CPU process the loop and one derivation share the
    core, and a second derivation thread would only take time from the loop. A CPU quota (cgroup
    `cpu.max`) is invisible to both calls; a quota-limited deployment sets `ORIGIN_KDF_THREADS`.
    """
    raw = os.getenv("ORIGIN_KDF_THREADS", "").strip()
    if raw:
        try:
            n = int(raw)
        except ValueError:
            n = 0
        if n >= 1:
            return n
    try:
        cpus = len(os.sched_getaffinity(0))
    except AttributeError:
        cpus = os.cpu_count() or 1
    return max(1, cpus - 1)


#: The limiter those derivations queue on, one per event loop (the same shape anyio uses for its
#: default limiter), sized by `kdf_threads()` when it is first used. Separate from anyio's default
#: thread limiter on purpose: that one (40 threads) also runs every synchronous dependency,
#: `get_db` among them, so derivations sharing it let a spray of failing sign-ins take every thread
#: and stall each request that touches the database. A derivation waiting here holds no thread.
_kdf_limiter: RunVar = RunVar("origin_kdf_limiter")


def kdf_limiter() -> CapacityLimiter:
    try:
        return _kdf_limiter.get()
    except LookupError:
        limiter = CapacityLimiter(kdf_threads())
        _kdf_limiter.set(limiter)
        return limiter


async def run_kdf(func, *args):
    """Run `func(*args)` — a key derivation, or code that performs one — in a worker thread on
    `kdf_limiter()`, off the event loop and off the default thread pool."""
    return await anyio.to_thread.run_sync(func, *args, limiter=kdf_limiter())


# ---------------------------------------------------------------------------
# Admission to the routes that spend a key derivation
# ---------------------------------------------------------------------------
#: How many derivation-spending requests may be admitted per derivation thread, beyond the one each
#: thread is running. A derivation takes a few hundred milliseconds at the configured cost, so at
#: this depth the last request admitted waits about a second for its turn. Past it, a quick 503
#: with `Retry-After` serves a person better than a request that sits in a queue for seconds. The
#: count is of requests admitted — running, queued, or still on their way to the queue — so the
#: number of derivation-spending requests open at once is at most
#: `(KDF_QUEUE_PER_THREAD + 1) * kdf_threads()`, however many arrive together. It reads only that
#: count, never who is asking, so a refusal says nothing about any account.
KDF_QUEUE_PER_THREAD = 4

#: How many derivation-spending requests one client may have in flight at once. One person signs
#: in one request at a time; this leaves room for several people behind one address (a household,
#: an office NAT) and, at a few hundred milliseconds per derivation, still sustains roughly a dozen
#: sign-ins a second from one address. What it stops is one client occupying the whole queue, so
#: the shedding above falls on everyone. A client is its network (`guess_budget._client_network`);
#: a peer in `SHARED_CLIENT_NETWORKS` carries many people's requests and is exempt.
KDF_IN_FLIGHT_PER_CLIENT = 4

#: Seconds a refused caller is told to wait: about the time the queue above takes to drain.
KDF_RETRY_AFTER_S = 2

#: How often a refusal is logged: once per client (or once for the shed) per window, the quarter
#: hour the mail cap logs on, so a sustained refusal is visible without a line per request.
KDF_LOG_WINDOW = timedelta(minutes=15)

#: client network -> requests in flight. Entries are removed when they reach zero, so the dict
#: holds at most one entry per client with a request currently open.
_kdf_in_flight: dict = {}

#: Derivation-spending requests admitted and not yet released, across every client.
_kdf_admitted = 0


class KdfRefused(Exception):
    """A derivation-spending request refused at admission: the status, the text, a
    machine-readable `error` (`busy` for the shed, `too_many_in_flight` for the per-client cap), and
    the wait to report."""

    def __init__(self, status_code: int, detail: str, error: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.error = error
        self.retry_after = KDF_RETRY_AFTER_S


def kdf_admit(client: Optional[str]) -> Optional[str]:
    """Admit one derivation-spending request from `client`, or raise `KdfRefused`.

    Every admitted request must be handed to `kdf_release` exactly once when it ends, with what this
    returned: the client's key, or None for a peer in `SHARED_CLIENT_NETWORKS`, which is exempt from
    the per-client cap but still counted toward the shed. A request with no client address (a Unix
    socket, some ASGI servers) is counted as the client "unknown". Runs on the event loop, with no
    await, so the checks and the counts are one step.
    """
    global _kdf_admitted
    from origin.services import guess_budget

    now = datetime.now(timezone.utc)
    limiter = kdf_limiter()
    if _kdf_admitted >= (KDF_QUEUE_PER_THREAD + 1) * limiter.total_tokens:
        guess_budget._log_once_per_window(
            "kdf-shed", "all", now, KDF_LOG_WINDOW,
            "sign-in requests are being shed with 503: %d derivation-spending requests are open, "
            "the most %d derivation threads admit", _kdf_admitted, limiter.total_tokens, to=_logger)
        raise KdfRefused(503, "Sign-in is busy. Please try again in a moment.", "busy")
    client = client or "unknown"
    key = None
    if not guess_budget._is_shared_client_network(client):
        key = guess_budget._client_network(client)
        if _kdf_in_flight.get(key, 0) >= KDF_IN_FLIGHT_PER_CLIENT:
            guess_budget._log_once_per_window(
                "kdf-client", key, now, KDF_LOG_WINDOW,
                "client %s reached the in-flight sign-in cap (%d); further sign-ins from it get 429 "
                "while it holds them. If this is a reverse proxy, Origin is not seeing real client "
                "addresses (FORWARDED_ALLOW_IPS; see SHARED_CLIENT_NETWORKS in config.py)",
                key, KDF_IN_FLIGHT_PER_CLIENT, to=_logger)
            raise KdfRefused(
                429, "Too many sign-ins in progress from your network; retry in a moment.",
                "too_many_in_flight")
        _kdf_in_flight[key] = _kdf_in_flight.get(key, 0) + 1
    _kdf_admitted += 1
    return key


def kdf_release(key: Optional[str]) -> None:
    """End one admitted request: `key` is what `kdf_admit` returned for it."""
    global _kdf_admitted
    _kdf_admitted = max(0, _kdf_admitted - 1)
    if key is None:
        return
    left = _kdf_in_flight.get(key, 0) - 1
    if left <= 0:
        _kdf_in_flight.pop(key, None)
    else:
        _kdf_in_flight[key] = left


# ---------------------------------------------------------------------------
# Log tags
# ---------------------------------------------------------------------------
def log_tag(value: str) -> str:
    """A short, stable tag for an address or username in the log: enough to correlate lines about
    one value, without writing what an unauthenticated caller typed into the log.

    Keyed, not a bare hash: an unkeyed hash of an address is reversed by hashing a list of
    candidate addresses. The key is derived from `platform_internal.secret` (see `_log_tag_key`),
    so a log that leaves the box cannot be matched against guesses without that file too."""
    return hmac.new(_log_tag_key(), (value or "").encode(), hashlib.sha256).hexdigest()[:12]


@functools.lru_cache(maxsize=1)
def _log_tag_key() -> bytes:
    """The log-tag key: derived from the secret the session cookie is signed with
    (`KEYS_DIR/platform_internal.secret`, which every provisioned node has), under its own label so
    the signing key itself is never used for anything else. Before that file exists, a random
    per-process key: tags then correlate within one run only."""
    path = config.KEYS_DIR / "platform_internal.secret"
    try:
        secret = path.read_bytes().strip()
    except OSError:
        secret = b""
    if not secret:
        return secrets.token_bytes(32)
    return hmac.new(secret, b"origin log tag v1", hashlib.sha256).digest()


def _pbkdf2_sha256(password: str, salt: bytes, iters: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)


def hash_password(password: str) -> str:
    """Hash a password. Stored format: pbkdf2_sha256$<iters>$<salt_b64>$<hash_b64>.

    The count goes into the stored string, which is what makes it raisable: `verify_password` reads
    it back per hash, so old hashes keep verifying at the count they were written with and only new
    ones cost more. `_upgrade_password_hash_if_stale` in `auth_router` is what moves the old ones
    forward, at the one moment the plaintext is available.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Password is required")
    iters = _configured_iters()
    salt = secrets.token_bytes(16)
    dk = _pbkdf2_sha256(password, salt, iters)
    return f"{_PWD_ALG}${iters}${_b64(salt)}${_b64(dk)}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Whether `password` matches `stored_hash`, at no less than the configured cost.

    A hash stored at a lower count derives faster than `dummy_verify_password`, and one in an
    unknown format or unparseable derives nothing, so either would tell a caller timing a failed
    sign-in which accounts carry such a hash. Each spends the difference after its answer is
    known, so every failed verify costs at least the configured count."""
    if not password or not stored_hash:
        return False
    configured = _configured_iters()
    try:
        alg, iters_s, salt_b64, dk_b64 = stored_hash.split("$", 3)
        if alg != _PWD_ALG:
            _spend_derivation(password, configured)
            return False
        iters = int(iters_s)
        salt = _b64d(salt_b64)
        expected = _b64d(dk_b64)
        actual = _pbkdf2_sha256(password, salt, iters)
    except Exception:
        _spend_derivation(password, configured)
        return False
    if iters < configured:
        _spend_derivation(password, configured - iters)
    return secrets.compare_digest(actual, expected)


def _spend_derivation(password: str, iters: int) -> None:
    """Run `iters` rounds of the password derivation and discard the result."""
    if iters > 0:
        _pbkdf2_sha256(password or "", b"\x00" * 16, iters)


def password_hash_is_current(stored_hash: str | None) -> bool:
    """Whether `stored_hash` was derived at the cost in force now.

    False for a hash written at a lower count, which is the case worth acting on, and also for an
    unparseable or absent one — a caller re-hashing on False writes a well-formed hash at the
    current cost, which is the right outcome for both.
    """
    if not stored_hash:
        return False
    try:
        alg, iters_s, _salt, _dk = stored_hash.split("$", 3)
    except ValueError:
        return False
    if alg != _PWD_ALG:
        return False
    try:
        return int(iters_s) >= _configured_iters()
    except ValueError:
        return False


def dummy_verify_password(password: str) -> None:
    """Spend roughly the same CPU as a real verify — anti-enumeration."""
    try:
        secrets.compare_digest(
            _pbkdf2_sha256(password or "", b"\x00" * 16, _configured_iters()), b"\x00" * 32
        )
    except Exception:
        return


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------
def generate_api_key() -> str:
    """Generate a new raw API key (`agc_<32 hex>`)."""
    return f"agc_{secrets.token_bytes(16).hex()}"


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Nonce — stateless HMAC challenge tokens
# ---------------------------------------------------------------------------
def issue_nonce(key_id: str, artifact_id: str, secret: str) -> Tuple[str, datetime]:
    if not secret:
        raise ValueError("no inbound nonce secret was supplied")
    ts = str(int(time.time()))
    payload = f"{ts}:{artifact_id}:{key_id}"
    sig = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    token = base64.urlsafe_b64encode(f"{payload}:{sig}".encode("utf-8")).decode("utf-8")
    return token, datetime.fromtimestamp(int(ts) + NONCE_TTL_SECONDS, tz=timezone.utc)


# ---------------------------------------------------------------------------
# Allow-list + redirect-uri checks
# ---------------------------------------------------------------------------
def _match_exact_or_glob(value: str, exact: set[str], patterns: list[str]) -> bool:
    if value in exact:
        return True
    return any(fnmatch.fnmatchcase(value, p) for p in patterns)


def is_person_allowed(google_id: Optional[str], email: Optional[str]) -> bool:
    """Allow-list gate. Default-allow when nothing is configured.

    Reads from `origin.config` at call time so settings loaded from the database win.
    """
    allowed_emails = getattr(config, "ALLOWED_EMAILS", None) or []
    allowed_domains = getattr(config, "ALLOWED_DOMAINS", None) or []
    allowed_google_ids = getattr(config, "ALLOWED_GOOGLE_IDS", None) or []

    if not (allowed_emails or allowed_domains or allowed_google_ids):
        return True
    if "*" in allowed_emails or "*" in allowed_domains or "*" in allowed_google_ids:
        return True

    gid_ok = bool(google_id) and google_id in set(allowed_google_ids)

    email_l = (email or "").lower()
    domain = email_l.split("@")[-1] if "@" in email_l else ""

    exact_emails = {e.lower() for e in allowed_emails if "*" not in e}
    email_patterns = [e.lower() for e in allowed_emails if "*" in e]
    exact_domains = {d.lower() for d in allowed_domains if "*" not in d}
    domain_patterns = [d.lower() for d in allowed_domains if "*" in d]

    email_ok = bool(email_l) and _match_exact_or_glob(email_l, exact_emails, email_patterns)
    domain_ok = bool(domain) and _match_exact_or_glob(domain, exact_domains, domain_patterns)
    return gid_ok or email_ok or domain_ok


def email_verification_required(email: Optional[str]) -> bool:
    """True when a new password sign-up with this email must verify it first.

    False when verification is globally disabled, when no email is given, or when
    the email (or its domain) is on the verification allowlist. Reads from
    `origin.config` at call time so settings loaded from the database win.
    """
    if not getattr(config, "EMAIL_VERIFICATION_ENABLED", False):
        return False
    email_l = (email or "").strip().lower()
    if not email_l or "@" not in email_l:
        return False  # no real email to verify
    allowlist = getattr(config, "EMAIL_VERIFICATION_ALLOWLIST", None) or []
    if not allowlist:
        return True
    if "*" in allowlist:
        return False  # everyone auto-verified
    domain = email_l.split("@")[-1]
    return not (email_l in allowlist or domain in allowlist)


#: The hosts a LISTED redirect URI may name and have its port left out of the comparison
#: (RFC 8252 §7.3): the IP literals, and `localhost`. Exact spelling, as written in the list.
_LOOPBACK_REDIRECT_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _loopback(host: str) -> bool:
    """Every spelling of the visitor's own machine: `localhost` and its subdomains, 127.0.0.0/8,
    `::1`, an IPv4-mapped loopback, and the unspecified addresses."""
    import ipaddress
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_unspecified


def _same_redirect_origin(a, b) -> bool:
    """Two `_redirect_origin`s naming one server: equal, or both loopback with one scheme and port
    (`localhost`, `127.0.0.1` and `[::1]` reach the same process on a loopback install)."""
    if a is None or b is None:
        return False
    if a == b:
        return True
    return a[0] == b[0] and a[2] == b[2] and _loopback(a[1]) and _loopback(b[1])


def _redirect_origin(uri: str):
    """`(scheme, host, port)` of an http(s) URL, the default port made explicit; None otherwise."""
    try:
        p = urlparse(uri or "")
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        return p.scheme, p.hostname.lower().rstrip("."), p.port or (443 if p.scheme == "https"
                                                                     else 80)
    except ValueError:
        return None


def _origin_of(uri: str) -> str:
    try:
        p = urlparse(str(uri))
        return f"{p.scheme}://{p.netloc}".lower() if p.scheme and p.netloc else ""
    except ValueError:
        return ""


def _facet_origins() -> list:
    facets = getattr(config, "FACET_URIS", None) or []
    if isinstance(facets, str):
        facets = [u.strip() for u in facets.split(",") if u.strip()]
    return [_origin_of(f) for f in facets]


def _never_narrowed_origins() -> set:
    return {_origin_of(getattr(config, "APP_URI", "") or ""),
            _origin_of(getattr(config, "ORIGIN_URI", "") or ""),
            _origin_of(getattr(config, "MANTLE_URI", "") or ""), ""}


def facet_narrowing(redirect_uri: str):
    """How a first-party sign-in delivered to `redirect_uri` is answered (review 12): `None` (the
    full token) for the web app (`APP_URI`) and Origin's own pages (`ORIGIN_URI`); the audience
    for a facet Origin lists (`NARROW_FACETS`); and `False`, no token at all, for anywhere else.
    Listing a URI in `CLIENT_REDIRECT_URIS` says a code may be delivered there, not who the token
    is for: a redirect URL never makes itself an audience, and never a full-token one."""
    origin = _origin_of(redirect_uri or "")
    if not origin:
        return False
    if origin in _never_narrowed_origins():
        return None
    if origin in narrow_audiences() and origin in (getattr(config, "NARROW_FACETS", None) or []):
        return origin
    return False


def narrow_audiences() -> dict:
    """Every narrow audience and the scopes it may carry: `NARROW_AUDIENCES`, plus each facet
    origin Origin lists (`NARROW_FACETS`), other than the web app (`APP_URI`), Origin's own and
    Mantle's, with scope `persona`. A facet a redirect may name (`FACET_URIS`) is not an audience
    by being named (review 12). None of them carries `platform:admin`."""
    if getattr(config, "NARROW_AUDIENCES_MALFORMED", False):
        return {}                     # a malformed setting closes every narrowed audience
    never = getattr(config, "NEVER_NARROWED", frozenset({"platform:admin"}))
    out = {str(k): [s for s in v if s not in never]
           for k, v in (getattr(config, "NARROW_AUDIENCES", None) or {}).items()}
    skip = _never_narrowed_origins()
    for f in getattr(config, "NARROW_FACETS", None) or []:
        o = _origin_of(f)
        if o not in skip:
            out.setdefault(o, ["persona"])
    return out


#: A narrowed delegation lives five minutes at most.
NARROW_TTL_SECONDS = 300

#: The audience of the token the web app calls Mantle on (review 23), and how long it lives. It is
#: issued only in the person's Origin session, and Origin takes it as no session and exchanges it
#: for nothing, so Mantle, which holds it, mints nothing with it.
MANTLE_AUDIENCE = "mantle"
MANTLE_TOKEN_TTL_SECONDS = 600


def issue_mantle_token(person, *, client_id: str) -> str:
    """The person's access token addressed to Mantle (`aud` `mantle`), ten minutes long."""
    claims = {**person_token_claims(person, client_id=client_id), "aud": MANTLE_AUDIENCE}
    return create_jwt_token(claims, expires_hours=MANTLE_TOKEN_TTL_SECONDS / 3600.0)
#: Scopes a narrowed delegation carries only when its exchange names them. None now: Ember's share,
#: the one there was, is gone (John, 2026-11-02).
OPT_IN_SCOPES: frozenset = frozenset()


def issue_narrow_delegation(person_id: str, audience: str, scopes: list, *,
                            expires_at: Optional[datetime] = None,
                            hop: Optional[dict] = None, actor: Optional[str] = None,
                            job_reach: Optional[list] = None,
                            job_grant: Optional[str] = None) -> str:
    """A delegation for `person_id` narrowed to `audience` and `scopes`: `aud` and `act.sub` are
    the audience, it lives `NARROW_TTL_SECONDS` (and never past `expires_at` when given), it never
    carries `platform:admin`, and no refresh token comes with it. `hop` records the narrowed
    delegation it was exchanged from, for a cross-persona hop (`/internal/narrow-hop`). `actor`,
    when given, is `act.sub` in place of the audience: Ember's delegation exchanged for one
    addressed to Mantle (`aud` `mantle`, actor `ember`, review 21). `job_reach`, for a delegation
    minted under a timer's job grant or exchanged from one, is the ids it may touch, carried on by
    every exchange (`job_reach_of`); `job_grant` names the grant."""
    from origin.service_identity import get_host_id

    now = datetime.now(timezone.utc)
    end = now + timedelta(seconds=NARROW_TTL_SECONDS)
    if expires_at is not None and expires_at < end:
        end = expires_at
    payload = {"iss": config.AUTHORITY_ISSUER, "sub": str(person_id), "aud": audience,
               "act": {"sub": actor or audience}, "principal_type": "delegation", "narrowed": True,
               "scope": " ".join(s for s in scopes
                                 if s not in getattr(config, "NEVER_NARROWED", ())
                                 and s != "platform:admin"),
               "host_id": get_host_id(), "iat": now.timestamp(),
               "exp": end.timestamp(),
               "jti": secrets.token_hex(16), **({"hop": hop} if hop else {}),
               **_job_claims(job_reach, job_grant)}
    return jwt.encode(payload, get_private_key_pem(), algorithm=JWT_ALGORITHM,
                      headers={"kid": get_key_id()})


def configured_redirect_uris(client_id: str) -> list:
    """The exact redirect URIs `CLIENT_REDIRECT_URIS` lists for this first-party client; empty when
    it lists none. Read at each call, so a test or a settings reload sees the current value."""
    mapping = getattr(config, "CLIENT_REDIRECT_URIS", None) or {}
    uris = mapping.get(client_id) if isinstance(mapping, dict) else None
    if isinstance(uris, str):
        uris = [uris]
    return [u for u in (uris or []) if isinstance(u, str) and u]


def _on_mantle(uri: str) -> bool:
    """Is `uri` on Mantle's origin (scheme, host, port)? Mantle serves pages there, so a code
    delivered to it would hand Mantle a sign-in (review 7, F2), whatever a list names. Mantle's
    address is configuration (`MANTLE_URI`), not a host written here."""
    mantle = _redirect_origin(getattr(config, "MANTLE_URI", "") or "")
    return bool(mantle) and _same_redirect_origin(_redirect_origin(uri), mantle)


def is_client_redirect_allowed(uri: str, *, client_id: str) -> bool:
    """May a first-party client's code be delivered to `uri`? Only when `CLIENT_REDIRECT_URIS`
    lists `uri` for that client.

    No redirect target exists in code: no tool page, no loopback, no local-development range, no
    base taken from `FACET_URI`/`FACET_URIS`/`ORIGIN_URI`. A node, a local install included, lists
    the exact URIs its own pages use, and the comparison is `redirect_uri_matches_registered`'s:
    the whole string, so another path, a trailing slash, a different case, another port or a
    longer host is a different URI and is refused.
    """
    if not isinstance(uri, str) or not uri or _on_mantle(uri):
        return False
    # Exact, loopback included: RFC 8252's port variance is for a native client's registration,
    # and a first-party list names the ports its own pages use.
    return redirect_uri_matches_registered(uri, configured_redirect_uris(client_id),
                                           loopback_any_port=False)


def is_registered_redirect_allowed(uri: str, registered) -> bool:
    """May a registered client's code be delivered to `uri`? Only to a URI in its own
    registration (`redirect_uri_matches_registered`), and never on Mantle's origin."""
    if not isinstance(uri, str) or not uri or _on_mantle(uri):
        return False
    return redirect_uri_matches_registered(uri, registered)


def is_registration_redirect_allowed(uri: str) -> bool:
    """May `POST /auth/register` record `uri`? Only when `CLIENT_REGISTRATION_REDIRECT_URIS` lists
    it, so what a client may register is the operator's configuration, and nothing registers an
    arbitrary third-party address. Empty refuses every URI."""
    if not isinstance(uri, str) or not uri or _on_mantle(uri):
        return False
    listed = getattr(config, "CLIENT_REGISTRATION_REDIRECT_URIS", None) or []
    if isinstance(listed, str):
        listed = [u.strip() for u in listed.split(",") if u.strip()]
    return redirect_uri_matches_registered(uri, listed)


def redirect_uri_matches_registered(requested: str, registered, *,
                                    loopback_any_port: bool = True) -> bool:
    """Is `requested` one of the listed redirect URIs? The one comparison every list is read with:
    a first-party client's configured URIs (`loopback_any_port=False`: exact, always), a client's
    registration, and the registration bound.

    RFC 6749 §3.1.2.2 makes it a simple string comparison: scheme, host, port, path, query and
    fragment, byte for byte, with no normalising. That is the rule for every URI but one shape.

    A loopback entry is compared without its port. RFC 8252 §7.3: "The authorization server MUST
    allow any port to be specified at the time of the request for loopback IP redirect URIs, to
    accommodate clients that obtain an available ephemeral port from the operating system at the
    time of the request." The relaxation applies only when the LISTED entry is itself an http
    loopback URI (`127.0.0.1`, `[::1]` or `localhost`); nothing adds loopback to a list that does
    not name it. Scheme, host, path, query and fragment are still compared exactly, and userinfo
    must be absent on both sides. A port on the loopback interface is reachable only from the
    machine already running the client, so "any port" widens where a code can go by nothing; the
    code is unredeemable there without the client's PKCE verifier besides.
    """
    if not registered or not isinstance(requested, str):
        return False
    if isinstance(registered, str):
        # A hand-written value can put one string where a list belongs; iterating it would compare
        # against its individual characters, which match nothing and hide the cause.
        registered = [registered]
    try:
        want = urlparse(requested)
    except Exception:
        return False
    for entry in registered:
        if not isinstance(entry, str) or not entry:
            continue
        if entry == requested:
            return True
        if not loopback_any_port:
            continue
        try:
            have = urlparse(entry)
        except Exception:
            continue
        have_host = _host_as_written(have.netloc)
        if (have.scheme != "http" or have_host is None
                or have_host.strip("[]") not in _LOOPBACK_REDIRECT_HOSTS):
            continue
        # The host as written, without its port: `urlparse`'s `hostname` lower-cases, and a case
        # variant is a different URI. Userinfo makes `_host_as_written` None on either side.
        want_host = _host_as_written(want.netloc)
        if (
            want_host is not None
            and want.scheme == have.scheme
            and want_host == have_host
            and want.path == have.path
            and want.params == have.params
            and want.query == have.query
            and want.fragment == have.fragment
        ):
            return True
    return False


def _host_as_written(netloc: str):
    """`netloc`'s host exactly as written, its port dropped; None when it carries userinfo or its
    port is not digits. `[::1]` keeps its brackets."""
    if not netloc or "@" in netloc:
        return None
    if netloc.startswith("["):
        end = netloc.find("]")
        if end < 0:
            return None
        host, rest = netloc[:end + 1], netloc[end + 1:]
    else:
        host, _, port = netloc.partition(":")
        rest = (":" + port) if _ else ""
    if rest and not (rest.startswith(":") and rest[1:].isdigit()):
        return None
    return host


# ---------------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------------
def generate_pkce_challenge() -> tuple[str, str]:
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return code_verifier, code_challenge


def verify_pkce_challenge(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode()).digest()
        computed = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    elif method == "plain":
        computed = code_verifier
    else:
        return False
    return secrets.compare_digest(computed, code_challenge)


# ---------------------------------------------------------------------------
# OAuth2 error constants
# ---------------------------------------------------------------------------
class OAuth2Error:
    INVALID_REQUEST = "invalid_request"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    ACCESS_DENIED = "access_denied"
    UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
    INVALID_SCOPE = "invalid_scope"
    SERVER_ERROR = "server_error"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"

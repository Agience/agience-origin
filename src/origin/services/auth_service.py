"""Origin auth issuance + low-level helpers.

Owns:
- JWT issuance (user, server, delegation tokens)
- Refresh token + nonce issuance
- Password hashing (PBKDF2)
- Allow-list and redirect-uri checks
- PKCE helpers
- OAuth2 error constants

Verification (`verify_token`, `verify_nonce`) lives in
`origin/services/auth_verifier.py`. Origin signs; Origin and its peers verify.

Origin neither generates nor verifies API keys.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from urllib.parse import urlparse

from jose import jwt

from origin import config
from origin.key_manager import get_key_id, get_private_key_pem

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


def issue_delegation_token(server_client_id: str, user_id: str, ttl_seconds: int = 300) -> str:
    """Short-lived RFC 8693 delegation JWT — server acting on behalf of a user.

    `user_id` MUST already be derived from a token Origin itself verified (see
    `POST /internal/delegation-token`) — never a caller-asserted subject. This
    helper only signs; the endpoint owns proving the subject.

    Carries the full identity chain a resource server needs: sub=user_id (User),
    aud=server_client_id + act.sub=server_client_id (Server), iss=AUTHORITY_ISSUER
    (Authority), host_id (Host). host_id is derived from the shared instance
    namespace (`KEYS_DIR/instance.uuid`) so it matches the host artifact's id
    without Origin needing to read the platform topology.
    """
    from origin.service_identity import get_host_id

    host_id = get_host_id()

    now = datetime.now(timezone.utc)
    payload = {
        "iss": config.AUTHORITY_ISSUER,
        "sub": user_id,
        "aud": server_client_id,
        "act": {"sub": server_client_id},
        "principal_type": "delegation",
        "host_id": host_id,
        "iat": now.timestamp(),
        "exp": (now + timedelta(seconds=ttl_seconds)).timestamp(),
    }
    return jwt.encode(
        payload,
        get_private_key_pem(),
        algorithm=JWT_ALGORITHM,
        headers={"kid": get_key_id()},
    )


def issue_system_delegation_token(
    subject_id: str,
    *,
    actor: str,
    scope: str,
    audience: str,
    ttl_seconds: int = 300,
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

    now = datetime.now(timezone.utc)
    payload = {
        "iss": config.AUTHORITY_ISSUER,
        "sub": subject_id,
        "aud": audience,
        "act": {"sub": actor},
        "scope": scope,
        "principal_type": "delegation",
        "host_id": get_host_id(),
        "iat": now.timestamp(),
        "exp": (now + timedelta(seconds=ttl_seconds)).timestamp(),
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
    if not password or not stored_hash:
        return False
    try:
        alg, iters_s, salt_b64, dk_b64 = stored_hash.split("$", 3)
        if alg != _PWD_ALG:
            return False
        salt = _b64d(salt_b64)
        expected = _b64d(dk_b64)
        actual = _pbkdf2_sha256(password, salt, int(iters_s))
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False


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


#: The hosts a redirect URI may name and still count as loopback. RFC 8252 §7.3 is written about the
#: IP literals; `localhost` is in the set because this allow-list has always admitted it, and taking
#: it out would refuse a redirect that works today. ONE definition, read by the authority-wide
#: allow-list below and by the per-client match beside it, so "is this loopback" cannot come to mean
#: two different things inside a single request.
_LOOPBACK_REDIRECT_HOSTS = frozenset({"127.0.0.1", "localhost"})


def is_client_redirect_allowed(uri: str) -> bool:
    """Built-in platform client redirect-uri check (RFC 8252 + well-known tools).

    Many facets, one authority: `FACET_URIS` carries every observation plane this Origin admits;
    `FACET_URI` stays as the first entry so nothing that declares only it changes behaviour. A node
    runs several facets — mantle's browser, a persona's surface, pharos — and each is a distinct
    host that must be able to start an authorization-code flow against this issuer.

    Still an allow-list, and the match is still exact on `scheme://netloc`. Widening which bases
    are admitted does not loosen how one is matched: no wildcards, no prefix matching, no suffix
    matching — a check that accepted `https://evil.com/?x=https://facet` or
    `https://facet.evil.com` would be an open redirect, and both are what prefix/suffix comparison
    would produce. An unlisted host does not match, which is asserted by test.

    This answers "may a code be delivered here at all", not "may *this* client have it". It is
    authority-wide and client-blind by construction — the same answer for every caller — so on its
    own it lets any client name any admitted callback, including another client's. What binds a
    client to its own callbacks is `redirect_uri_matches_registered` below, applied by `/authorize`
    to a client that has a registration. This function stays the outer bound in both cases: a URI it
    refuses is refused for everyone, registered or not.
    """
    allowed_bases = [config.FACET_URI, getattr(config, "ORIGIN_URI", "")]
    # Read with getattr and normalised to a list: a DB-stored value arrives through
    # `_CSV_LIST_KEYS`, but an operator who sets the env var by hand can still hand us one string.
    # Treating that string as an iterable would admit its individual characters as bases.
    _extra = getattr(config, "FACET_URIS", None) or []
    if isinstance(_extra, str):
        _extra = [u.strip() for u in _extra.split(",") if u.strip()]
    allowed_bases.extend(u.rstrip("/") for u in _extra if u)
    always_allowed = {"https://vscode.dev", "https://oauth.pstmn.io"}
    allowed_loopback_hosts = _LOOPBACK_REDIRECT_HOSTS

    backend_local = (getattr(config, "ORIGIN_URI", "") or "").startswith(("http://localhost", "http://127.0.0.1"))
    frontend_local = (config.FACET_URI or "").startswith(("http://localhost", "http://127.0.0.1"))
    if backend_local or frontend_local:
        allowed_bases.extend([f"http://localhost:{p}" for p in range(3000, 9000)])

    try:
        parsed = urlparse(uri)
        if parsed.scheme not in ("http", "https"):
            return False
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        if base_url in allowed_bases or base_url in always_allowed:
            return True
        if parsed.scheme == "http" and parsed.hostname in allowed_loopback_hosts:
            return True
        return False
    except Exception:
        return False


def redirect_uri_matches_registered(requested: str, registered) -> bool:
    """Is `requested` one of the redirect URIs this client registered?

    The client-specific half of the pair. `is_client_redirect_allowed` says where this authority
    will deliver a code at all; this says where it will deliver *this* client's code, and a client
    with a registration is held to both.

    RFC 6749 §3.1.2.2 makes the comparison a simple string comparison, and that is the rule here for
    every URI but one shape.

    Loopback is compared without its port. RFC 8252 §7.3: "The authorization server
    MUST allow any port to be specified at the time of the request for loopback IP redirect URIs, to
    accommodate clients that obtain an available ephemeral port from the operating system at the
    time of the request." A native client — an MCP client is exactly this — asks the OS for a free
    port at the moment it starts the flow, so the port it registered on its first run is not the
    port it listens on for its second. Simple string comparison would therefore admit one run and
    refuse every run after it, turning a registration into a record of one afternoon's ephemeral
    port. So for a loopback host, and only for a loopback host, the port is left out of the
    comparison; scheme, host, path and query are all still compared exactly.

    The relaxation reaches no further than the loopback interface, which is the reason the RFC can
    require it: a port on 127.0.0.1 is reachable only from the machine already running the client,
    so "any port" widens the set of addresses a code can reach by nothing. Every other URI is
    compared whole, port included — a registered `https://facet.example:8443` does not admit
    `https://facet.example:9000`.

    A consequence of that rule: two loopback clients registering the same path have registered the
    same address, and each matches the other's request. `http://127.0.0.1:1000/callback` and
    `http://127.0.0.1:2000/callback` are one address under §7.3, because the port is not part of it,
    and no comparison both honours "MUST allow any port" and tells those two apart. The cost is
    already spent elsewhere: an attacker who can bind a loopback port is executing on the machine,
    and the code delivered there is unredeemable without the `code_verifier` the legitimate client
    kept. Two loopback clients are distinguished by their path (`/a/callback` vs `/b/callback`),
    which is compared, and that is where the distinction is made.
    """
    if not registered:
        return False
    if isinstance(registered, str):
        # An operator or a hand-written row can put one string where a list belongs; iterating it
        # would compare against its individual characters, which match nothing and hide the cause.
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
        try:
            have = urlparse(entry)
        except Exception:
            continue
        if (have.hostname or "").lower() not in _LOOPBACK_REDIRECT_HOSTS:
            continue
        # Compared by `hostname` rather than by `netloc`, which is what actually takes the port out
        # of the comparison — and userinfo out with it, so the two are required absent on both sides
        # rather than silently ignored. `http://user@127.0.0.1/cb` is not `http://127.0.0.1/cb`.
        if (
            want.scheme == have.scheme
            and (want.hostname or "").lower() == (have.hostname or "").lower()
            and want.path == have.path
            and want.query == have.query
            and not want.username
            and not have.username
        ):
            return True
    return False


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

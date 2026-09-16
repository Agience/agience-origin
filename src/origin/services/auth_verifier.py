"""Origin auth verification.

Reads api_keys from Origin's own database. JWT verification uses Origin's local
public key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import datetime, timezone
from typing import Any, Optional

from jose import JWTError, jwt

from origin import config
from origin.key_manager import get_public_key_pem

JWT_ALGORITHM = "RS256"

#: Service names whose tokens are verified against the authority manifest rather than against
#: Origin's own key. This answers "CAN this token be verified", which is a different question from
#: `auth_router._PLATFORM_SERVICES`'s "may this caller read person records" — authentication is not
#: authorization, and the two lists are deliberately separate so a service can be admitted here
#: without being granted there.
#:
#: They are not independent, though: a name in the authorization list that is absent here can never
#: authenticate, so its grant is dead. `test_platform_service_lists_agree.py` holds that direction.
#:
#: Named rather than inlined so a test can read it. An inline tuple is unreachable from outside this
#: function, so the relationship above could only ever be asserted by re-typing the names in the
#: test — a second copy, which is the thing being guarded against.
PLATFORM_ISSUERS = frozenset({"mantle", "chorus"})


def verify_token(token: str, expected_audience: Optional[str] = None) -> Optional[dict[str, Any]]:
    """Verify and decode an incoming JWT.

    Dispatches by the unverified `iss` claim:
    - `iss` names a platform service  → platform-service mutual JWT. Verified
      against the inline JWKS in the platform authority manifest via
      `origin.authority_trust`.
    - Anything else (typically `iss == AUTHORITY_ISSUER` URL) → token issued by
      Origin itself. Verified with Origin's local public key.
    """
    try:
        unverified = jwt.get_unverified_claims(token)
    except JWTError:
        return None

    iss = unverified.get("iss", "")

    # Platform-service mutual JWT.
    #
    # ⭐ TWO NAMES, NOT FOUR [2026-09-16]. `crystal` and `lumen` were listed here and could never
    # arrive: `iss` is `identity.name` from `prism.trust.service_identity`, set by
    # `init_service_identity(<name>)` at lifespan startup, and NOTHING in this platform calls it
    # with either name — only `"origin"` (origin/main.py) and `"chorus"` (five sites in chorus).
    # Crystal's own process loads a `CrystalIdentity` and reaches mantle with `MANTLE_API_KEY`
    # instead; the `sign_service_jwt` calls that live in the crystal REPOSITORY are chorus-host
    # code (`crystal/push.py` calls `init_service_identity("chorus")` itself), so they sign as
    # chorus. A repository path is not a runtime identity.
    #
    # Listing a name that cannot be produced costs nothing at runtime and is not free: it reads as
    # "this authority accepts crystal tokens", which is what `_PLATFORM_SERVICES` in
    # `auth_router.py` then grants five internal endpoints to.
    if iss in PLATFORM_ISSUERS:
        from origin.authority_trust import verify_jwt as _verify_via_authority
        from jose.exceptions import JWTError as _JoseJWTError

        try:
            payload = _verify_via_authority(
                token,
                expected_issuer_service=iss,
                expected_audience=expected_audience,
                expected_issuer_claim=iss,
            )
        except (KeyError, _JoseJWTError):
            return None
        exp = payload.get("exp")
        if exp and datetime.now(timezone.utc).timestamp() > exp:
            return None
        return payload

    # Legacy / standard: Origin-signed token
    try:
        decode_kwargs: dict = {
            "algorithms": [JWT_ALGORITHM],
            "issuer": config.AUTHORITY_ISSUER,
            "options": {"verify_iss": True},
        }
        if expected_audience is not None:
            decode_kwargs["audience"] = expected_audience
        else:
            decode_kwargs["options"]["verify_aud"] = False

        payload = jwt.decode(token, get_public_key_pem(), **decode_kwargs)
        exp = payload.get("exp")
        if exp and datetime.now(timezone.utc).timestamp() > exp:
            return None
        return payload
    except JWTError:
        return None


def verify_nonce(
    token: str,
    key_id: str,
    artifact_id: str,
    secret: str,
    ttl_seconds: int = 1800,
) -> bool:
    """Verify a nonce token issued by `auth_service.issue_nonce`.

    Returns False (not raise) on any failure — caller decides the HTTP status.
    """
    if not secret or not token:
        return False
    try:
        padding = "=" * (4 - len(token) % 4)
        decoded = base64.urlsafe_b64decode(token + padding).decode("utf-8")
        parts = decoded.split(":", 3)
        if len(parts) != 4:
            return False
        ts_str, nonce_artifact_id, nonce_key_id, sig = parts
        ts = int(ts_str)
    except Exception:
        return False

    if nonce_artifact_id != artifact_id or nonce_key_id != key_id:
        return False
    if int(datetime.now(timezone.utc).timestamp()) - ts > ttl_seconds:
        return False

    expected_payload = f"{ts_str}:{artifact_id}:{key_id}"
    expected_sig = hmac.new(
        secret.encode("utf-8"), expected_payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(sig, expected_sig)

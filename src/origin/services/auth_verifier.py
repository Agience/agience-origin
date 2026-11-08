"""Origin auth verification.

Reads api_keys from Origin's own database. JWT verification uses Origin's local
public key.
"""

from __future__ import annotations

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
#: The chorus personas sign as themselves once each holds an enrolled key; each is verified against
#: its own anchor (a persona with none fails verification), and the delegation exchange is the one
#: route that admits them (`auth_router`). Crystal signs as itself with `crystal.private.pem`
#: (`crystal.identity.CrystalIdentity`) and reaches its own exchange and the describe delegation
#: only (review 21); it is not among the services that read person records.
from prism.trust.service_identity import PERSONA_NAMES as _PERSONA_NAMES  # noqa: E402
PLATFORM_ISSUERS = frozenset({"mantle", "chorus", "crystal", *_PERSONA_NAMES})


def verify_token(token: str, expected_audience: Optional[str] = None) -> Optional[dict[str, Any]]:
    """Verify and decode an incoming JWT.

    Dispatches by the unverified `iss` claim:
    - `iss` names a platform service  → platform-service mutual JWT. Verified
      against the inline JWKS in the platform authority manifest via
      `origin.authority_trust`, and returned only when it is that service's own
      token (`principal_type == "service"`, `sub == iss`).
    - Anything else (typically `iss == AUTHORITY_ISSUER` URL) → token issued by
      Origin itself. Verified with Origin's local public key.
    """
    try:
        unverified = jwt.get_unverified_claims(token)
    except JWTError:
        return None

    iss = unverified.get("iss", "")

    # Platform-service mutual JWT: a service's own token, verified against that service's anchor.
    # Which services may read person records is `auth_router._PLATFORM_SERVICES`'s to say, not
    # this list's.
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
        except (KeyError, _JoseJWTError, TypeError, ValueError, ArithmeticError):
            return None
        # A service token with no `exp` (or one that is not a number) never lapses: no token
        # (review 27).
        exp = payload.get("exp")
        if (isinstance(exp, bool) or not isinstance(exp, (int, float))
                or datetime.now(timezone.utc).timestamp() > exp):
            return None
        # A platform service's key speaks only for that service. Every caller of this function reads
        # `principal_type` and `sub` from the payload, so a token verified against a service's
        # anchor is returned only as that service's own token: anything claiming a person, a
        # delegation or another service is refused here, once, for every route. Only Origin's own
        # key (below) signs tokens that stand for a person.
        if payload.get("principal_type") != "service" or payload.get("sub") != iss:
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
        # Every token Origin signs carries `exp`; one with none (or a null, or a non-number) is no
        # token of Origin's, and would otherwise never lapse (review 26, I3).
        exp = payload.get("exp")
        if (isinstance(exp, bool) or not isinstance(exp, (int, float))
                or datetime.now(timezone.utc).timestamp() > exp):
            return None
        return payload
    # A claim of the wrong type (a null or odd `exp`, one past any date) is no token, as at
    # prism's `verify_jwt` (review 25), never a 500.
    except (JWTError, TypeError, ValueError, ArithmeticError):
        return None


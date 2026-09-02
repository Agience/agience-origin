"""Origin passkey service.

Implements the WebAuthn registration and authentication ceremonies, storing
challenges and credentials in Origin's own database.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AuthenticationCredential,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from origin import config
from origin.db import passkey_challenges as db_challenges
from origin.db import passkey_credentials as db_passkeys
from origin.db import persons as db_persons
from origin.services.platform_settings_service import settings

logger = logging.getLogger(__name__)


def _get_rp_id() -> str:
    """Derive the Relying Party ID from the frontend hostname.

    Origin runs at a different host than the frontend; WebAuthn binds to the
    frontend origin (`config.FACET_URI`), so the rpId must match its host.
    """
    try:
        from urllib.parse import urlparse

        parsed = urlparse(config.FACET_URI)
        return parsed.hostname or "localhost"
    except Exception:
        return "localhost"


def _get_rp_name() -> str:
    return settings.get("branding.title", "Agience") or "Agience"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
def get_registration_options(db: Session, user_id: str, email: str) -> dict:
    existing = db_passkeys.list_for_person(db, user_id)
    exclude_credentials = [
        PublicKeyCredentialDescriptor(
            id=_b64url_decode(c.id),
            transports=list(c.transports or []),
        )
        for c in existing
    ]
    options = generate_registration_options(
        rp_id=_get_rp_id(),
        rp_name=_get_rp_name(),
        user_id=user_id.encode("utf-8"),
        user_name=email,
        user_display_name=email,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
        exclude_credentials=exclude_credentials,
        timeout=60000,
    )
    # Remember it before handing it out — see get_authentication_options.
    encoded_challenge = _b64url_encode(options.challenge)
    db_challenges.create(
        db, challenge=encoded_challenge, purpose="register", person_id=user_id
    )
    return {
        "rp": {"id": options.rp.id, "name": options.rp.name},
        "user": {
            "id": _b64url_encode(options.user.id),
            "name": options.user.name,
            "displayName": options.user.display_name,
        },
        "challenge": _b64url_encode(options.challenge),
        "pubKeyCredParams": [
            {"type": "public-key", "alg": p.alg} for p in options.pub_key_cred_params
        ],
        "timeout": options.timeout,
        "excludeCredentials": [
            {
                "id": _b64url_encode(c.id),
                "type": "public-key",
                "transports": c.transports or [],
            }
            for c in (options.exclude_credentials or [])
        ],
        "authenticatorSelection": {
            "residentKey": options.authenticator_selection.resident_key.value
            if options.authenticator_selection
            else "preferred",
            "userVerification": options.authenticator_selection.user_verification.value
            if options.authenticator_selection
            else "preferred",
        },
    }


def verify_registration(
    db: Session,
    user_id: str,
    credential: dict,
    challenge: str,
    device_name: Optional[str] = None,
) -> dict:
    """Verify a registration attestation against a challenge WE issued.

    Same contract as :func:`verify_authentication`: `challenge` is a lookup key,
    not the expected value. Lower severity than login (this route is behind
    `_require_interactive_user` and enrols the caller's own credential), but the
    freshness guarantee has to hold here too.
    """
    claimed = db_challenges.consume(db, challenge, purpose="register")
    if claimed is None:
        raise ValueError("registration challenge unknown, already used, or expired")
    if claimed.person_id and str(claimed.person_id) != str(user_id):
        raise ValueError("registration challenge was issued to a different user")

    registration = RegistrationCredential.model_validate(credential)
    verification = verify_registration_response(
        credential=registration,
        expected_challenge=_b64url_decode(claimed.challenge),
        expected_rp_id=_get_rp_id(),
        expected_origin=config.FACET_URI,
    )
    credential_id = _b64url_encode(verification.credential_id)
    db_passkeys.create(
        db,
        {
            "id": credential_id,
            "person_id": user_id,
            "public_key": verification.credential_public_key,
            "sign_count": verification.sign_count,
            "device_name": device_name,
            "transports": credential.get("response", {}).get("transports", []),
            "created_time": datetime.now(timezone.utc),
        },
    )
    logger.info("Passkey registered for user %s (device: %s)", user_id, device_name)
    return {"credential_id": credential_id, "device_name": device_name}


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
def _build_authentication_options(descriptors: list[PublicKeyCredentialDescriptor]):
    """The one call that shapes a login challenge, real or decoy.

    Shared so the decoy path cannot drift from the real one. It is not a style preference: the
    challenge `generate_authentication_options` mints is 64 bytes, and a decoy that rolled its own
    32-byte challenge would be identifiable by response length alone — the enumeration oracle back
    in a form nobody would think to look for. Going through the library means every field, and any
    the library changes later, matches by construction.
    """
    return generate_authentication_options(
        rp_id=_get_rp_id(),
        allow_credentials=descriptors,
        user_verification=UserVerificationRequirement.PREFERRED,
        timeout=60000,
    )


def _serialize_authentication_options(options) -> dict:
    """Wire shape for a login challenge. Shared by both paths, for the reason above."""
    return {
        "challenge": _b64url_encode(options.challenge),
        "rpId": options.rp_id,
        "timeout": options.timeout,
        "allowCredentials": [
            {
                "id": _b64url_encode(c.id),
                "type": "public-key",
                "transports": c.transports or [],
            }
            for c in (options.allow_credentials or [])
        ],
        "userVerification": options.user_verification.value
        if options.user_verification
        else "preferred",
    }


def get_authentication_options(db: Session, email: str) -> Optional[dict]:
    person = db_persons.get_by_email(db, email)
    if not person:
        return None
    creds = db_passkeys.list_for_person(db, str(person.id))
    if not creds:
        return None
    options = _build_authentication_options(
        [
            PublicKeyCredentialDescriptor(
                id=_b64url_decode(c.id),
                transports=list(c.transports or []),
            )
            for c in creds
        ]
    )
    # Remember it before handing it out, bound to this person — otherwise
    # `verify_authentication` has nothing to check the echo against.
    encoded = _serialize_authentication_options(options)
    db_challenges.create(
        db, challenge=encoded["challenge"], purpose="login", person_id=str(person.id)
    )
    return encoded


#: Domain-separation labels. The decoy key is the inbound-nonce secret, an HMAC secret this service
#: already loads at boot: `main.lifespan` calls `init_nonce_secret()`, which RAISES on a missing
#: file, so it is present on any node that serves at all. Reusing it needs the separation below —
#: without distinct labels, a decoy credential id and an inbound nonce would be two HMACs of
#: attacker-influenced text under one key.
#:
#: Read through `key_manager.get_nonce_secret()`, which is the one source. `config` deliberately
#: mirrors no key material into a module global: a second copy is correct only while something
#: remembers to populate it, and an empty one would send every passkey login down the no-secret
#: branch below.
_DECOY_COUNT_LABEL = b"passkey-login-decoy-count|"
_DECOY_CRED_LABEL = b"passkey-login-decoy-cred|"

#: Raw credential-id length for a decoy, in bytes. Not a tuned constant: it is the length
#: `generate_registration_options` hands the authenticator to echo back, and what the platform
#: authenticators that produce real rows in `passkey_credentials` return.
_DECOY_CRED_ID_BYTES = 32


def _decoy_secret() -> bytes:
    """The key the decoys derive from, or empty if the node has none.

    Read at call time rather than import time: the secret is loaded during lifespan, after this
    module may already be imported.
    """
    from origin.key_manager import get_nonce_secret

    try:
        return (get_nonce_secret() or "").encode("utf-8")
    except RuntimeError:
        # Not initialized — only on a node that has not completed startup.
        return b""


def get_decoy_authentication_options(email: str) -> Optional[dict]:
    """A plausible authentication challenge for an email with no passkeys — or no account.

    This exists to stop an account-existence oracle, and it is the WebAuthn-shaped version of
    what `otp_router.request_otp` and `/auth/email/verify-request` already do: answer an unknown
    address exactly as a known one. Those two return a fixed `{"sent": true}`, which costs nothing
    because their real response carries no per-user data. A login ceremony does — `allowCredentials`
    is a list of the account's actual credential ids — so matching them means *fabricating* that
    list rather than omitting it.

    Two properties make the fabrication hold up, and both are requirements, not decoration:

    * **Stable per email.** A real account's credential ids do not change between calls, so decoys
      derived from `secrets.token_bytes` would out a non-account the moment a probe asked twice.
      They are HMACs over the normalized email under a server-held key, so they are stable for as
      long as the key is, and unpredictable without it.
    * **Freshly random challenge.** The `challenge` is the one field that MUST differ every call,
      because a real one does. It is generated the same way `generate_authentication_options`
      generates one, and — unlike a real challenge — deliberately not recorded: `verify_authentication`
      opens by consuming a stored row, so an assertion built against a decoy fails at exactly the
      point a replayed or unknown challenge fails, with the same 401 and no separate branch.

    Returns None when no secret is configured, which is the caller's signal to fall back rather
    than to publish a guessable list. Unreachable on a booting node (see `_decoy_secret`); it is
    here so a key-loading regression degrades to the old behaviour visibly instead of emitting
    decoys an attacker could recompute.
    """
    key = _decoy_secret()
    if not key:
        logger.warning(
            "No inbound nonce secret: passkey login-options cannot generate decoys, so this node "
            "answers unknown and known emails differently. This is an enumeration oracle."
        )
        return None

    # Normalized so `Alice@Example.com` and `alice@example.com` do not present as two different
    # non-accounts — `db_persons.get_by_email` resolves them to one row.
    subject = (email or "").strip().lower().encode("utf-8")

    def _mac(label: bytes, extra: bytes = b"") -> bytes:
        return hmac.new(key, label + subject + extra, hashlib.sha256).digest()

    # One or two credentials. Most accounts hold one; a second is common enough that a fixed
    # count would itself be the tell.
    count = 1 + (_mac(_DECOY_COUNT_LABEL)[0] % 2)

    descriptors = [
        PublicKeyCredentialDescriptor(
            id=_mac(_DECOY_CRED_LABEL, bytes([i]))[:_DECOY_CRED_ID_BYTES],
            # What a platform authenticator reports for a resident key — the kind
            # `get_registration_options` asks for (`ResidentKeyRequirement.PREFERRED`).
            transports=[AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID],
        )
        for i in range(count)
    ]
    # Same builder and same serializer as the real path, so the challenge is the library's own
    # 64-byte value and no field can drift into a distinguisher. Deliberately NOT recorded in
    # `passkey_challenges`: see this function's docstring.
    return _serialize_authentication_options(_build_authentication_options(descriptors))


def verify_authentication(
    db: Session,
    credential: dict,
    challenge: str,
) -> Optional[str]:
    """Verify a login assertion against a challenge WE issued and have not yet spent.

    `challenge` is the b64url string the client echoes back. It is not trusted as
    "what the server expected" — it is a lookup key into the challenge table. The
    expected challenge and the expected user both come from the stored row, so a
    replayed body fails at `consume` before any crypto runs.
    """
    claimed = db_challenges.consume(db, challenge, purpose="login")
    if claimed is None:
        logger.warning("Passkey login rejected: challenge unknown, spent, or expired")
        return None
    if not claimed.person_id:
        logger.warning("Passkey login rejected: challenge carries no subject")
        return None

    expected_challenge = _b64url_decode(claimed.challenge)
    expected_user_id = str(claimed.person_id)

    authentication = AuthenticationCredential.model_validate(credential)
    credential_id = _b64url_encode(authentication.raw_id)
    stored = db_passkeys.get_by_id_and_person(db, credential_id, expected_user_id)
    if stored is None:
        logger.warning("Passkey credential not found: %s", credential_id)
        return None
    try:
        verification = verify_authentication_response(
            credential=authentication,
            expected_challenge=expected_challenge,
            expected_rp_id=_get_rp_id(),
            expected_origin=config.FACET_URI,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count or 0,
        )
    except Exception as exc:
        logger.warning("Passkey verification failed: %s", exc)
        return None
    db_passkeys.update_sign_count(db, credential_id, verification.new_sign_count)
    logger.info("Passkey authentication successful for user %s", stored.person_id)
    return str(stored.person_id)


# ---------------------------------------------------------------------------
# Management
# ---------------------------------------------------------------------------
def list_credentials(db: Session, user_id: str) -> list[dict]:
    creds = db_passkeys.list_for_person(db, user_id)
    return [
        {
            "credential_id": c.id,
            "device_name": c.device_name,
            "created_at": c.created_time.isoformat() if c.created_time else None,
            "last_used_at": c.last_used_at.isoformat() if c.last_used_at else None,
        }
        for c in creds
    ]


def delete_credential(db: Session, user_id: str, credential_id: str) -> bool:
    return db_passkeys.delete_for_person(db, credential_id, user_id)


def has_passkeys(db: Session, email: str) -> bool:
    person = db_persons.get_by_email(db, email)
    if person is None:
        return False
    return len(db_passkeys.list_for_person(db, str(person.id))) > 0

"""Origin person service.

Origin owns identity only: it does not provision a workspace or inbox and seeds
no collections. Those belong to whichever peer holds the store.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx
from sqlalchemy.orm import Session

from origin import config
from origin.db import person_identities as db_identities
from origin.db import persons as db_persons
from origin.models.person import Person
from origin.services.auth_service import is_person_allowed
from origin.services.email_address import canonical_email, lookup_email, require_canonical_email


class RegistrationPaused(PermissionError):
    """New accounts are paused: no path makes one (review 12, L11)."""


def registration_paused() -> bool:
    """Are new accounts paused (`REGISTRATION_PAUSED`, or the platform setting
    `auth.registration.paused`)? Read by every path that would make a person: the register routes,
    OTP verification and a first federated sign-in."""
    if getattr(config, "REGISTRATION_PAUSED", False):
        return True
    try:
        from origin.services.platform_settings_service import settings as platform_settings
        stored = str(platform_settings.get("auth.registration.paused") or "").strip().lower()
    except Exception:  # noqa: BLE001 — no settings loaded: only the env decides
        stored = ""
    return stored in ("1", "true", "yes")


def _refuse_new_account() -> None:
    if registration_paused():
        raise RegistrationPaused("New accounts are temporarily paused. Sign in with an existing "
                                 "account.")

logger = logging.getLogger(__name__)


class IdentityLinkRefused(Exception):
    """A sign-in resolved to an email that already belongs to someone, and linking is not safe.

    Raised instead of doing either obvious thing, because both are wrong: linking anyway is
    account takeover (see `get_or_create_user_by_oidc_identity`), and creating a second person
    carrying the same address leaves two accounts on one address, with grants split across them
    and nothing anywhere recording it.

    The caller turns this into a 409 naming the method the person already has. The deliberate way
    to add a provider to an existing account is `POST /auth/me/link-provider`, which requires being
    signed in first — i.e. proving the account is yours, which is exactly the proof missing here.
    """


async def record_person_event(payload: dict, event_type: str = "person") -> None:
    """Fire-and-forget POST to the configured external event webhook.

    No-op when the webhook isn't configured. Matches the peer behaviour so
    auth event emission survives the move unchanged.
    """
    uri = getattr(config, "EVENT_LOGGER_URI", None)
    user = getattr(config, "EVENT_LOGGER_USERNAME", None)
    password = getattr(config, "EVENT_LOGGER_PASSWORD", None)
    if not uri or not user or not password:
        return
    try:
        body = {**payload, "event_type": event_type}
        async with httpx.AsyncClient(
            timeout=2.0, auth=httpx.BasicAuth(username=user, password=password)
        ) as client:
            await client.post(uri, json=body)
    except Exception:
        logger.exception("Failed to record person event")


def get_user_by_id(db: Session, user_id: str) -> Optional[Person]:
    return db_persons.get_by_id(db, user_id)


def get_user_by_email(db: Session, email: str) -> Optional[Person]:
    return db_persons.get_by_email(db, email)


def get_user_by_username(db: Session, username: str) -> Optional[Person]:
    return db_persons.get_by_username(db, username)


def get_user_by_oidc_identity(
    db: Session, oidc_provider: str, oidc_subject: str
) -> Optional[Person]:
    """Resolve an OIDC identity to its person via `person_identities`."""
    row = db_identities.get_by_identity(
        db, method="oidc", provider=oidc_provider, subject=oidc_subject)
    return get_user_by_id(db, row.person_id) if row else None


def get_user_by_google_id(db: Session, google_id: str) -> Optional[Person]:
    return get_user_by_oidc_identity(db, "google", google_id)


def get_or_create_user_by_oidc_identity(
    db: Session,
    oidc_provider: str,
    oidc_subject: str,
    email: str,
    name: str,
    picture: Optional[str] = None,
    email_verified: bool = False,
) -> Person:
    """Resolve a completed sign-in to the one person it belongs to.

    Every sign-in method arrives here, which is why the linking rule lives here and nowhere else.
    Google's callback, the local OTP leg and the local password leg all mint an authorization code
    carrying the same `user_info` shape, and `_grant_authorization_code` calls this function on it.
    One implementation of "who is this?" cannot disagree with itself; three would, and the
    disagreement would be an account split nobody noticed for months.

    The order is deliberate:

      1. `(provider, subject)` — the durable key. An IdP's subject never changes; an email does.
         A hit here wins outright and no email is consulted.
      2. otherwise, if this email already belongs to someone, refuse (`IdentityLinkRefused`):
         joining an identity to an account is the account's own act, with a fresh step-up.
      3. otherwise, a new person.

    Why an address both sides proved is still not enough: it says the same mailbox, not that the
    account's owner consents. A provider, or whoever controls one (a custom OIDC provider the
    operator's settings name), asserting a verified address would otherwise sign in as the
    account at that address. So the join is the account's own act: `POST /auth/me/link-provider`,
    with a fresh step-up by a method the account already has (`services.person_step_up`).

    `email_verified` decides only whether a new person's address is recorded as confirmed.

    The provider's address is canonicalised (`email_address.lookup_email`), never refused: a
    sign-in the provider completed is not the person typing an address, and the canonical form is
    what makes `x@d.com.` from a provider find the account at `x@d.com`.
    """
    email = lookup_email(email)
    name = (name or "").strip() or "User"
    google_id = oidc_subject if oidc_provider == "google" else None
    if not is_person_allowed(google_id, email):
        logger.warning("Login denied: provider=%r subject=%r email=%r", oidc_provider, oidc_subject, email)
        raise PermissionError("Person is not allowed to access this system")

    existing = get_user_by_oidc_identity(db, oidc_provider, oidc_subject)
    if existing:
        dirty = False
        if existing.email != email:
            # A new address is confirmed only if the provider says so. The account's old address
            # being confirmed says nothing about this one.
            existing.email = email
            existing.email_verified = bool(email_verified)
            dirty = True
        if existing.name != name:
            existing.name = name
            dirty = True
        if existing.picture != picture:
            existing.picture = picture
            dirty = True
        if dirty:
            db.flush()
        return existing

    # ── 2. this address already belongs to an account reached by another method ─────────────────
    # Not joined. An address both sides proved is still not the account's consent: a provider, or
    # whoever controls one, asserting a verified address would otherwise sign in as its owner. The
    # account joins another identity only by its own act, with a fresh step-up by a method it
    # already has (`POST /auth/me/link-provider`, `services.person_step_up`).
    claimed = get_user_by_email(db, email) if email else None
    if claimed is not None:
        logger.warning(
            "Refusing to join %s identity %r to existing account %s by email: linking is the "
            "account's own act", oidc_provider, oidc_subject, claimed.id,
        )
        raise IdentityLinkRefused(
            "An account already exists for this email. Sign in with your existing method, then "
            "add this one from your account page."
        )

    # ── 3. nobody holds this address: a new person ─────────────────────────────────────────────
    _refuse_new_account()
    # Confirmed only if the provider says so. The column defaults to confirmed, and a provider that
    # lets anyone type an address would otherwise hand them a confirmed account at someone else's:
    # one that password reset and email invites (Mantle's claim by address) then treat as theirs.
    person = db_persons.create(
        db,
        {"email": email, "name": name, "picture": picture,
         "email_verified": bool(email_verified)},
    )
    # The identity is a row, attached after the person exists. `verified=True` because reaching
    # here means the provider completed its flow and vouched for this subject.
    db_identities.add(
        db, person_id=person.id, method="oidc",
        provider=oidc_provider, subject=oidc_subject, verified=True,
    )
    return person


def create_user_with_password(
    db: Session,
    *,
    username: str,
    name: str,
    password_hash: str,
    email: str = "",
    email_verified: bool = False,
    allow_paused: bool = False,
) -> Person:
    """A new account with a password. Refused while new accounts are paused, except for the
    operator's own bootstrap claim (`allow_paused`). Its address is unverified unless the caller
    says otherwise: a password proves nothing about the mailbox."""
    if not allow_paused:
        _refuse_new_account()
    username = (username or "").strip()
    # Typed by the person creating the account: refused unless already canonical (apart from case
    # and surrounding space), never rewritten. A ValueError, which both register routes answer
    # with their one refusal.
    email = require_canonical_email(email) if (email or "").strip() else ""
    # Only the name the person gave. A username is often their address, and a name made from it
    # would show the address to everyone they are shared with.
    name = (name or "").strip()

    if not username:
        raise ValueError("Username is required")
    if email and not is_person_allowed(None, email):
        raise PermissionError("Person is not allowed to access this system")

    if get_user_by_username(db, username):
        raise ValueError("Username already taken")
    if email and get_user_by_email(db, email):
        raise ValueError("Email already registered")

    return db_persons.create(
        db,
        {
            "username": username,
            "email": email or None,
            "name": name,
            "password_hash": password_hash,
            "email_verified": email_verified,
        },
    )


def get_or_create_user_by_email(db: Session, email: str) -> Person:
    """Used for email-OTP login. Creates a passwordless user if missing, at the canonical form of
    the address the code was mailed to (the OTP ledger is keyed by that form already)."""
    email = canonical_email(email)
    if not is_person_allowed(None, email):
        raise PermissionError("Person is not allowed to access this system")

    existing = get_user_by_email(db, email)
    if existing:
        return existing

    _refuse_new_account()
    return db_persons.create(
        db,
        # No name until the person gives one: a name made from the address would show the
        # address's local part to everyone they are shared with.
        {"email": email, "name": ""},
    )


def link_identity(
    db: Session, *, user_id: str, method: str, provider: str, subject: str,
    proof: Optional[str] = None,
) -> Person:
    """Attach an identity to an already-authenticated account. Additive.

    The caller must already be signed in as `user_id`. Linking authenticates as the account and
    then proves the new identity — never the reverse. The dangerous flow this forbids is "sign in
    with a provider, find no account, match on the email it asserted, attach to that person": that
    trusts an unverified third-party claim to hand over an existing account. A matched email may
    invite a link; it may never complete one.

    `method` is open, so this is also how a peer origin is linked (`method="origin"`,
    `provider=<issuer url>`, `subject=<their principal id>`). The direction is irrelevant — either
    origin may hold the row.
    """
    owner = db_identities.get_by_identity(db, method=method, provider=provider, subject=subject)
    if owner:
        if str(owner.person_id) == str(user_id):
            return get_user_by_id(db, user_id)      # already linked — idempotent
        raise ValueError("This identity is already linked to another account")

    user = get_user_by_id(db, user_id)
    if user is None:
        raise ValueError("User not found")

    # Linking does not require removing an existing identity first; an account may hold
    # multiple identities at once.
    db_identities.add(db, person_id=user.id, method=method, provider=provider,
                      subject=subject, verified=True, proof=proof)
    return user


def link_oidc_identity(
    db: Session, *, user_id: str, oidc_provider: str, oidc_subject: str
) -> Person:
    """OIDC-shaped wrapper over `link_identity` — the shape the auth router already speaks."""
    return link_identity(db, user_id=user_id, method="oidc",
                         provider=oidc_provider, subject=oidc_subject)


def unlink_identity(
    db: Session, *, user_id: str, method: str, provider: str, subject: str
) -> Person:
    """Detach one identity, leaving the others.

    At least one means of signing in must survive — a password, or another verified identity.
    Removing the last one would leave the account existing and unreachable, so `unlink_identity`
    raises instead.
    """
    user = get_user_by_id(db, user_id)
    if user is None:
        raise ValueError("User not found")

    remaining = db_identities.count_verified(db, user.id) - 1
    if remaining <= 0 and not user.password_hash:
        raise ValueError(
            "Cannot unlink: this is the only way to sign in to this account. "
            "Set a password or link another identity first.")

    removed = db_identities.remove(
        db, person_id=user.id, method=method, provider=provider, subject=subject)
    if not removed:
        raise ValueError("No such identity is linked to this account")
    return user


def unlink_oidc_identity(db: Session, user_id: str, provider: str, subject: str) -> Person:
    """OIDC-shaped wrapper over `unlink_identity`.

    `provider` and `subject` are required: with more than one OIDC identity linked, an unlink that
    does not say which one would have to guess, so the caller names it."""
    return unlink_identity(db, user_id=user_id, method="oidc", provider=provider, subject=subject)


def list_identities(db: Session, user_id: str):
    """Every identity linked to this account."""
    return db_identities.list_for_person(db, user_id)


def update_preferences(db: Session, user_id: str, preferences: dict) -> Person:
    user = get_user_by_id(db, user_id)
    if user is None:
        raise ValueError(f"Person {user_id} not found")
    merged = dict(user.preferences or {})
    merged.update(preferences or {})
    user.preferences = merged
    db.flush()
    return user


def set_password(db: Session, user_id: str, password_hash: str) -> Person:
    """Set (or reset) a person's password hash. Used by the password-reset flow
    and any future change-password endpoint. Caller hashes the password and
    commits the session."""
    user = get_user_by_id(db, user_id)
    if user is None:
        raise ValueError(f"Person {user_id} not found")
    user.password_hash = password_hash
    db.flush()
    return user


def find(db: Session, identifier: str) -> Optional[Person]:
    """The person an email address, username or id names."""
    ident = (identifier or "").strip()
    if not ident:
        return None
    if "@" in ident:
        return get_user_by_email(db, ident)
    try:
        found = get_user_by_id(db, ident)
    except (ValueError, TypeError):
        found = None
    return found or get_user_by_username(db, ident)


def deactivate(db: Session, user_id: str, reason: str) -> Person:
    """Switch an account off. Nothing but the two deactivation fields changes, so `reactivate`
    restores it exactly. Caller commits the session."""
    user = get_user_by_id(db, user_id)
    if user is None:
        raise ValueError(f"Person {user_id} not found")
    if user.deactivated_at is None:
        from datetime import datetime, timezone
        user.deactivated_at = datetime.now(timezone.utc)
    user.deactivated_reason = reason
    # Every refresh token of theirs ends with the account, and stays ended if it is reactivated.
    from origin.services import origin_session, refresh_tokens
    refresh_tokens.revoke_person(db, str(user.id))
    # And every Origin session: no session route serves them (the routes refuse a deactivated
    # person too), and a reactivated account signs in again.
    origin_session.revoke_person(db, str(user.id))
    db.flush()
    return user


def reactivate(db: Session, user_id: str, password_hash: Optional[str] = None) -> Person:
    """Switch an account back on. `password_hash` puts back a hash removed by hand before this
    state existed; it is refused when the account already has one. Caller commits the session."""
    user = get_user_by_id(db, user_id)
    if user is None:
        raise ValueError(f"Person {user_id} not found")
    if password_hash is not None:
        if user.password_hash:
            raise ValueError(f"Person {user_id} already has a password; nothing to restore")
        user.password_hash = password_hash
    user.deactivated_at = None
    user.deactivated_reason = None
    db.flush()
    return user


def set_email_verified(db: Session, user_id: str, verified: bool = True) -> Person:
    """Mark a person's email as verified (or not). Caller commits the session."""
    user = get_user_by_id(db, user_id)
    if user is None:
        raise ValueError(f"Person {user_id} not found")
    user.email_verified = verified
    db.flush()
    return user

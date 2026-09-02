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
      2. otherwise, if this email already belongs to someone, link — but only under the rule below.
      3. otherwise, a new person.

    The rule: both sides must have proved the address, and each half stops a different attack.

      · `email_verified` (the IdP vouched for it). Without this half, any provider that lets a user
        type an arbitrary unverified address mints a token asserting `email: you@example.com`, and
        the account at that address is handed over on the strength of an unverified claim — the
        classic "Sign in with X" takeover.
      · `claimed.email_verified` (this account proved it). Without this half the attack runs the
        other way: an attacker registers a password account on the victim's address, never
        verifies it, waits, and the victim's real Google sign-in links into the attacker's
        account — password already known, and the victim sees their own data because it is, by
        then, one account.

    Neither half is redundant and neither implies the other. When either is missing,
    `IdentityLinkRefused` is raised rather than guessing in either direction — the deliberate path
    is `POST /auth/me/link-provider`, which requires an existing session and therefore supplies the
    proof of ownership that is missing here.

    `email_verified` defaults to False, which is the safe direction: a caller who has not thought
    about it raises `IdentityLinkRefused` rather than linking. Every caller that can vouch says so
    explicitly.
    """
    email = (email or "").strip().lower()
    name = (name or "").strip() or "User"
    google_id = oidc_subject if oidc_provider == "google" else None
    if not is_person_allowed(google_id, email):
        logger.warning("Login denied: provider=%r subject=%r email=%r", oidc_provider, oidc_subject, email)
        raise PermissionError("Person is not allowed to access this system")

    existing = get_user_by_oidc_identity(db, oidc_provider, oidc_subject)
    if existing:
        dirty = False
        if existing.email != email:
            existing.email = email
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

    # ── 2. this address may already belong to an account reached by another method ──────────────
    claimed = get_user_by_email(db, email) if email else None
    if claimed is not None:
        if not email_verified:
            logger.warning(
                "Refusing to link %s identity %r to existing account %s: the provider did not "
                "assert email_verified", oidc_provider, oidc_subject, claimed.id,
            )
            raise IdentityLinkRefused(
                f"{oidc_provider} did not verify this email address, so it cannot be linked to the "
                "existing account. Sign in with your existing method, then add this provider from "
                "your account page."
            )
        if not bool(claimed.email_verified):
            logger.warning(
                "Refusing to link %s identity %r to existing account %s: the local address was "
                "never verified", oidc_provider, oidc_subject, claimed.id,
            )
            raise IdentityLinkRefused(
                "An account already exists for this email but the address was never confirmed. "
                "Verify it from your existing sign-in method first, then this provider can be "
                "linked to it."
            )
        # Both sides proved it: the same human, arriving by a second door. One person, one more
        # identity row. `verified=True` because the provider completed its flow for this subject.
        db_identities.add(
            db, person_id=claimed.id, method="oidc",
            provider=oidc_provider, subject=oidc_subject, verified=True,
        )
        # Fill only what is empty. A second provider is not authority to overwrite a name or avatar
        # the person already has — and the email is the thing that matched, so it is already equal.
        if not claimed.name or claimed.name == "User":
            claimed.name = name
        if not claimed.picture and picture:
            claimed.picture = picture
        db.flush()
        logger.info(
            "Linked %s identity to existing account %s via verified email", oidc_provider, claimed.id
        )
        return claimed

    # ── 3. nobody holds this address: a new person ─────────────────────────────────────────────
    person = db_persons.create(
        db,
        {"email": email, "name": name, "picture": picture},
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
    email_verified: bool = True,
) -> Person:
    username = (username or "").strip()
    email = (email or "").strip().lower()
    name = (name or username).strip() or "User"

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
    """Used for email-OTP login. Creates a passwordless user if missing."""
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        raise ValueError("Valid email is required")
    if not is_person_allowed(None, email):
        raise PermissionError("Person is not allowed to access this system")

    existing = get_user_by_email(db, email)
    if existing:
        return existing

    return db_persons.create(
        db,
        {"email": email, "name": email.split("@")[0]},
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


def set_email_verified(db: Session, user_id: str, verified: bool = True) -> Person:
    """Mark a person's email as verified (or not). Caller commits the session."""
    user = get_user_by_id(db, user_id)
    if user is None:
        raise ValueError(f"Person {user_id} not found")
    user.email_verified = verified
    db.flush()
    return user

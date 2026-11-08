"""Origin's custody of one share of each Mantle master key, and the tokens already spent on it.

`key_custody_shares` holds share 2 of each principal's 2-of-3 split (`services.key_shares`), apart
from `platform_settings` so that no settings route can list, read or write one. The share bytes are
Fernet-encrypted under Origin's `encryption.key`; the x-coordinate and the key-check value are not
secret (the check value is a MAC of a 256-bit random key) and stay in the clear, so a conditional
write can compare them without decrypting.

`key_custody_nonces` holds the `jti` of every token presented to `/internal/key-shares` until it
expires, so a token is accepted once. `key_custody_background`, `key_custody_delegations` and
`key_custody_releases` record the operator's background authority, the delegations minted under it
and each release (see their classes).
"""
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class KeyCustodyShare(Base):
    __tablename__ = "key_custody_shares"

    principal_id = Column(String(128), primary_key=True)
    x = Column(Integer, nullable=False)
    y_sealed = Column(Text, nullable=False)
    kcv = Column(String(32), nullable=False)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow,
                          onupdate=_utcnow)
    #: Replaceable: a first share until Mantle activates its key, or one the operator's seed or
    #: bootstrap credential marked for re-key. Otherwise a stored share is never replaced.
    rekey_pending = Column(Boolean, nullable=False, default=True)
    #: Who stored this first share (the acting credential's subject), until it is activated:
    #: whoever stored a first share may activate it (review 26, L3). Cleared at activation.
    stored_by = Column(String(128), nullable=True)


class KeyCustodyShareHistory(Base):
    """Every share a replacement superseded, kept: never deleted."""

    __tablename__ = "key_custody_share_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    principal_id = Column(String(128), nullable=False, index=True)
    x = Column(Integer, nullable=False)
    y_sealed = Column(Text, nullable=False)
    kcv = Column(String(32), nullable=False)
    superseded_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    superseded_by = Column(String(128), nullable=False)


class ChargedRootRotation(Base):
    """Step 21's rotation of a charged root's master key, as the operator recorded it (review 31):
    the rotated key's key-check value, from the rotation's own report. The operator grants
    `platform.custody` over a charged root only while one is recorded, and Origin releases or
    stores that root's share only for this key, and only while its split is reading back."""

    __tablename__ = "charged_root_rotations"

    principal_id = Column(String(128), primary_key=True)
    kcv = Column(String(32), nullable=False)
    recorded_by = Column(String(128), nullable=False)
    #: When the current record was made; set by `record_rotation` alone, never by an update.
    recorded_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    #: The one custody grant this record opens the split under (review 32): the first made after
    #: it. Once that grant has ended, the split is closed until a new record of a fresh kcv.
    grant_id = Column(String(128), nullable=True)
    #: A share of the recorded kcv was written after this record (review 32): only such a share
    #: is ever read back, never one Origin held before.
    share_written = Column(Boolean, nullable=False, default=False)


class KeyCustodyNonce(Base):
    __tablename__ = "key_custody_nonces"

    jti = Column(String(128), primary_key=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)


class UseNonce(Base):
    """A persona's use nonce, spent once by the verdict it was signed into (review 23, I2): kept
    apart from Mantle's custody-token jtis, so neither is spent as the other."""
    __tablename__ = "use_nonces"

    nonce_key = Column(String(128), primary_key=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)


class KeyCustodyBackground(Base):
    """A standing background authority the operator granted at Origin.

    While one is live (not revoked, not expired), Mantle may ask Origin to mint a delegation for one
    principal for background work (`KeyCustodyDelegation`). It is never a token anyone holds."""

    __tablename__ = "key_custody_background"

    id = Column(String(32), primary_key=True)
    issued_by = Column(String(128), nullable=False)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)


class KeyCustodyDelegation(Base):
    """A background delegation Origin minted for one principal (`subject`), minutes long.

    Recorded by `jti` so it can be checked and revoked; the token itself is returned once at
    minting and never stored."""

    __tablename__ = "key_custody_delegations"

    jti = Column(String(64), primary_key=True)
    subject = Column(String(128), nullable=False, index=True)
    issued_by = Column(String(128), nullable=False)
    authority_id = Column(String(32), nullable=True)
    #: The job grant it was minted under (`authority_job_grants`), the job it names, and the
    #: collections that grant covers (a JSON list): it opens nothing else.
    job_grant_id = Column(String(128), nullable=True, index=True)
    job = Column(String(64), nullable=True)
    collections = Column(Text, nullable=True)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)


class DelegationRecord(Base):
    """A person's delegation Origin issued (`/internal/delegation-token`), by `jti`: who for, to
    whom, until when, and whether it was revoked. The token itself is never stored. A delegation
    with no record here acts for no one at a key release or the authority ledger."""

    __tablename__ = "delegation_tokens"

    jti = Column(String(64), primary_key=True)
    subject = Column(String(128), nullable=False, index=True)
    audience = Column(String(128), nullable=False)
    signer = Column(String(128), nullable=False)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)


class SeedCredential(Base):
    """A credential the operator minted for one seed pass, as a deliberate act: the platform
    system principal's, scoped to `authority.seed`, minutes long. Recorded by `jti`; the token is
    returned once and never stored."""

    __tablename__ = "seed_credentials"

    jti = Column(String(64), primary_key=True)
    #: The digests of the entries this pass may make (review 25, M4), a JSON list; none, no entry.
    plan = Column(Text, nullable=True)
    subject = Column(String(128), nullable=False)
    issued_by = Column(String(128), nullable=False)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    #: The shares this pass may mark for re-key (`/rekey-pending`): a JSON list, or null for none.
    rekey_shares = Column(Text, nullable=True)
    #: The one batch this seed pass writes in: the first it opened (review 11).
    first_batch = Column(String(64), nullable=True)


class OperatorEnrolmentCode(Base):
    """A one-time code for enrolling the operator's first passkey, generated on Origin's host by
    `python -m origin.scripts.operator_enrolment_code` and never over HTTP. Only its SHA-256 is
    kept; it lives minutes and is spent by the enrolment it authorizes."""

    __tablename__ = "operator_enrolment_codes"

    code_sha256 = Column(String(64), primary_key=True)
    operator_id = Column(String(128), nullable=False)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)


class KeyCustodyRelease(Base):
    """One row per share released: which principal's share, for whom, on which credential, for
    which collection.

    `credential_ref` is the credential's `jti` when it has one, else a SHA-256 prefix of the token,
    never the token."""

    __tablename__ = "key_custody_releases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    principal_id = Column(String(128), nullable=False, index=True)
    subject = Column(String(128), nullable=False, index=True)
    credential_kind = Column(String(16), nullable=False)
    credential_ref = Column(String(64), nullable=False, index=True)
    collection_id = Column(String(128), nullable=True)
    released_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

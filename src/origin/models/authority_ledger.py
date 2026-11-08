"""The authority ledger and Origin's replica of what decides reach.

`authority_ledger` is the hash-chained, co-signed log of every change Mantle made that affects who
reaches what: grants put (created, updated, revoked, retired), containment edges added or removed,
and each key principal's origin root. Each entry holds structure only (ids, CRUDEASIO actions,
effect, state, expiry, an invite's target digest and claim limit, propagate masks), never a name,
note, label, address or content.

The replica tables are the ledger applied: `authority_nodes` (every id Origin has seen, and who
brought it into being), `authority_grants`, `authority_edges` and `authority_roots`. Origin writes
them only by appending a co-signed entry (`services.authority_ledger`), so the replica holds
nothing the ledger does not. `authority_signing_keys` keeps the public half of every key that has
co-signed an entry, so a rotated key's entries still verify. `authority_bootstrap_windows` records
each bootstrap credential the operator obtained.
"""
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from origin.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuthorityEntry(Base):
    __tablename__ = "authority_ledger"

    seq = Column(Integer, primary_key=True, autoincrement=False)
    kind = Column(String(16), nullable=False)
    body = Column(Text, nullable=False)                 # canonical JSON
    actor = Column(String(128), nullable=False)         # the credential's subject
    credential_kind = Column(String(16), nullable=False)
    credential_ref = Column(String(64), nullable=False)
    bootstrap = Column(Boolean, nullable=False, default=False)
    #: The entry this one withdraws (a write that did not commit at Mantle), or NULL.
    compensates = Column(Integer, nullable=True)
    #: For an invite claim, the invite it spent (proven by the claim token, which is not kept).
    claimed_from = Column(String(128), nullable=True)
    #: Mantle's service token for the submission: its `jti` and the body digest it signed.
    submitted_jti = Column(String(128), nullable=False)
    body_sha256 = Column(String(64), nullable=False)
    prev_hash = Column(String(64), nullable=False)
    entry_hash = Column(String(64), nullable=False, unique=True)
    signature = Column(Text, nullable=False)            # Origin's co-signature over entry_hash
    kid = Column(String(128), nullable=False)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    #: Mantle said the write this entry was made for committed. Only an unconfirmed entry may be
    #: withdrawn: a withdrawal is for a write that did not commit.
    confirmed = Column(Boolean, nullable=False, default=False)
    #: The submission batch (one Mantle operation) the entry came in: a creation's own grant is
    #: the one co-signed in the batch that creates it.
    batch = Column(String(64), nullable=True, index=True)
    #: The service that submitted it (the bound token's issuer); only it confirms the entry.
    submitted_by = Column(String(64), nullable=True)
    #: The operator who resolved an unconfirmed entry through the console, and when.
    resolved_by = Column(String(128), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)


class AuthorityBatch(Base):
    """A submission batch Origin issued: one operation, on one credential, for a short window.
    A creation's own grant is accepted only in the batch that created the id."""

    __tablename__ = "authority_batches"

    batch_id = Column(String(64), primary_key=True)
    credential_ref = Column(String(64), nullable=False)
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)


class AuthoritySigningKey(Base):
    __tablename__ = "authority_signing_keys"

    kid = Column(String(128), primary_key=True)
    public_pem = Column(Text, nullable=False)
    first_used = Column(DateTime(timezone=True), nullable=False, default=_utcnow)


class AuthorityBootstrapWindow(Base):
    """A bootstrap credential the operator obtained (`id` is its `jti`). Bootstrap entries are
    accepted only on a live one."""

    __tablename__ = "authority_bootstrap_windows"

    id = Column(String(32), primary_key=True)
    opened_by = Column(String(128), nullable=False)
    opened_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    closed_at = Column(DateTime(timezone=True), nullable=True)
    #: When the ledger already has ordinary entries: the unseen ids this window may state.
    ids = Column(Text, nullable=True)


class AuthorityNode(Base):
    """An id Origin's replica has seen, and who brought it into being ("" by bootstrap)."""

    __tablename__ = "authority_nodes"

    node_id = Column(String(128), primary_key=True)
    created_by = Column(String(128), nullable=False)
    seq = Column(Integer, nullable=False)
    #: It has had a creation parent. A member stays one for the creator's base case, whatever
    #: later happens to that edge.
    member = Column(Boolean, nullable=False, default=False)
    #: On a root: the entry that last removed a node under it (review 29), and the operator's
    #: confirmation that nothing is left under its master key. While the removal is the later of
    #: the two, the root's master key opens for its own principal alone.
    part_removed_seq = Column(Integer, nullable=True)
    confirmed_empty_seq = Column(Integer, nullable=True)


class AuthorityGrant(Base):
    __tablename__ = "authority_grants"

    grant_id = Column(String(128), primary_key=True)
    grantee_id = Column(String(128), nullable=False, index=True)
    grantee_type = Column(String(32), nullable=False)
    resource_id = Column(String(128), nullable=False, index=True)
    actions = Column(String(128), nullable=False)       # comma-separated CRUDEASIO names
    effect = Column(String(16), nullable=False)
    state = Column(String(32), nullable=False)
    expires_at = Column(String(64), nullable=True)
    target_kind = Column(String(16), nullable=True)     # an invite's target: kind and digest
    target_digest = Column(String(64), nullable=True)
    max_claims = Column(Integer, nullable=True)
    claimed_from = Column(String(128), nullable=True, index=True)   # the invite a claim spent
    created_by = Column(String(128), nullable=False)
    seq = Column(Integer, nullable=False)


class AuthorityEdge(Base):
    __tablename__ = "authority_edges"

    src = Column(String(128), primary_key=True)
    dst = Column(String(128), primary_key=True, index=True)
    origin = Column(Boolean, nullable=False)
    propagate = Column(Text, nullable=True)             # JSON list of actions, or NULL (all)
    added_by = Column(String(128), nullable=False)      # the actor who added it; "" by bootstrap
    seq = Column(Integer, nullable=False)


class AuthorityRoot(Base):
    __tablename__ = "authority_roots"

    principal_id = Column(String(128), primary_key=True)
    root_id = Column(String(128), nullable=False)
    registered_by = Column(String(128), nullable=False)
    seq = Column(Integer, nullable=False)


class OperatorAlert(Base):
    """Something the operator is told of (John, 2026-11-02: detect-and-revoke plus alert): every
    grant carrying Admin, and every grant on the platform's Authorities collection, as Origin
    co-signed it. The console lists them (`GET /oracle/alerts`) and acknowledges them."""

    __tablename__ = "operator_alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    kind = Column(String(32), nullable=False)            # admin_grant | platform_admin
    seq = Column(Integer, nullable=False, index=True)    # the entry that raised it
    resource_id = Column(String(128), nullable=False)
    subject = Column(String(128), nullable=False)        # the grantee
    actor = Column(String(128), nullable=False)          # who made the entry
    detail = Column(Text, nullable=False, default="")
    created_time = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    acknowledged_by = Column(String(128), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)


class AuthorityJobGrant(Base):
    """A named background job's own narrow authority (John, 2026-11-02), as the ledger applied
    it: which job, over which key principal and collections, until when. Granted by the person
    whose key it is or an Admin of each collection (the operator for the platform's own principal),
    revocable. A background delegation is minted only under a live one."""

    __tablename__ = "authority_job_grants"

    grant_id = Column(String(128), primary_key=True)
    job = Column(String(64), nullable=False)
    principal = Column(String(128), nullable=False, index=True)
    collections = Column(Text, nullable=False, default="[]")     # JSON list of collection ids
    expires_at = Column(String(64), nullable=False)
    state = Column(String(32), nullable=False)
    created_by = Column(String(128), nullable=False)
    seq = Column(Integer, nullable=False)

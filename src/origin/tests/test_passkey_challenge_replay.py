"""Passkey login must not be replayable.

The sign-count backstop does not save it: py_webauthn skips the monotonicity
check when `auth_data.sign_count == 0 and stored == 0`, and every platform
authenticator (Touch ID, Windows Hello, iCloud Keychain) reports 0.

Positive controls: a suite that only asserts "this is
rejected" passes just as happily when everything is rejected. Every rejection
test here is paired with a proof that the same flow succeeds once.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from origin.db.base import Base
from origin.db import passkey_challenges as db_challenges


@pytest.fixture
def db() -> Session:
    """In-memory DB with the real schema, from the models' own metadata."""
    import origin.models  # noqa: F401  — registers every model on Base.metadata

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        yield session


# ---------------------------------------------------------------------------
# The core property: a challenge is single-use
# ---------------------------------------------------------------------------


def test_challenge_is_consumable_once_positive_control(db: Session):
    """A freshly-issued challenge is accepted the first time it is used.

    Without this, the replay test below would pass even if `consume` rejected
    everything unconditionally.
    """
    person_id = uuid.uuid4()
    db_challenges.create(db, challenge="chal-abc", purpose="login", person_id=person_id)

    claimed = db_challenges.consume(db, "chal-abc", purpose="login")

    assert claimed is not None, "a fresh challenge must be accepted once"
    assert str(claimed.person_id) == str(person_id), "subject must come from the stored row"


def test_replayed_challenge_is_rejected(db: Session):
    """A second use of the same challenge is rejected."""
    db_challenges.create(db, challenge="chal-abc", purpose="login", person_id=uuid.uuid4())

    first = db_challenges.consume(db, "chal-abc", purpose="login")
    replay = db_challenges.consume(db, "chal-abc", purpose="login")

    assert first is not None, "sanity: first use should succeed"
    assert replay is None, (
        "a replayed challenge was accepted — a captured login-complete body is "
        "reusable and grants a 30-day refresh token"
    )


def test_unknown_challenge_is_rejected(db: Session):
    """A challenge the server never issued must not authenticate anything."""
    assert db_challenges.consume(db, "never-issued", purpose="login") is None


def test_expired_challenge_is_rejected(db: Session):
    past = datetime.now(timezone.utc) - timedelta(seconds=10)
    db_challenges.create(
        db,
        challenge="chal-old",
        purpose="login",
        person_id=uuid.uuid4(),
        ttl_seconds=1,
        now=past - timedelta(seconds=60),
    )

    assert db_challenges.consume(db, "chal-old", purpose="login") is None


def test_challenge_is_bound_to_its_purpose(db: Session):
    """A registration challenge must not satisfy a login ceremony."""
    db_challenges.create(db, challenge="chal-reg", purpose="register", person_id=uuid.uuid4())

    assert db_challenges.consume(db, "chal-reg", purpose="login") is None
    # It still works for the purpose it was issued for.
    assert db_challenges.consume(db, "chal-reg", purpose="register") is not None


def test_challenge_carries_its_own_subject(db: Session):
    """The subject comes from the stored row, never from the request.
    """
    victim = uuid.uuid4()
    db_challenges.create(db, challenge="chal-bound", purpose="login", person_id=victim)

    claimed = db_challenges.consume(db, "chal-bound", purpose="login")

    assert claimed is not None
    assert str(claimed.person_id) == str(victim)


# ---------------------------------------------------------------------------
# The wire contract
# ---------------------------------------------------------------------------


def test_login_complete_does_not_accept_client_supplied_user_id():
    """`user_id` must be gone from the request model, not merely ignored."""
    from origin.routers.passkey_router import LoginCompleteRequest

    assert "user_id" not in LoginCompleteRequest.model_fields, (
        "LoginCompleteRequest still accepts user_id — it was passed through as "
        "expected_user_id, so the client chose which account to authenticate as"
    )


def test_verify_authentication_takes_a_challenge_key_not_an_expected_value():
    """The service must look the challenge up, not be handed what to expect.

    The old signature was `(db, credential, expected_challenge: bytes,
    expected_user_id: str)` — both attacker-controlled. The new one takes a
    single `challenge` lookup key and derives both expectations from storage.
    """
    import inspect

    from origin.services import passkey_service

    params = inspect.signature(passkey_service.verify_authentication).parameters

    assert "expected_challenge" not in params, (
        "verify_authentication still accepts expected_challenge from its caller"
    )
    assert "expected_user_id" not in params, (
        "verify_authentication still accepts expected_user_id from its caller"
    )
    assert "challenge" in params, "expected a `challenge` lookup key"


def test_issued_challenge_is_persisted(db: Session):
    """Issuing must write the challenge down; otherwise there is nothing to check."""
    from origin.models.passkey_challenge import PasskeyChallenge

    before = db.query(PasskeyChallenge).count()
    db_challenges.create(db, challenge="issued-1", purpose="login", person_id=uuid.uuid4())
    db.flush()

    assert db.query(PasskeyChallenge).count() == before + 1

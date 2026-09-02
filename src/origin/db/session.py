"""SQLite engine + session factory for Origin.

The DB file lives at `${ORIGIN_DB_PATH}`, defaulting to `.data/origin/origin.db` under the
install root. The parent directory is created if it is absent; SQLAlchemy creates the file on
first connect.

WAL mode, foreign-key enforcement and `busy_timeout` are set via a connect-time PRAGMA hook, so
concurrent reads don't block writes, ON DELETE CASCADE actually fires, and a writer that loses the
race queues instead of raising `SQLITE_BUSY` at the caller.

`DATABASE_URL` is honored as a test override (`sqlite:///:memory:` in conftest.py).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


# ---------------------------------------------------------------------------
# How long a blocked writer queues before giving up
# ---------------------------------------------------------------------------
# SQLite admits one writer at a time. Without `busy_timeout` the loser of a race does not wait —
# it gets `SQLITE_BUSY` immediately, which surfaces as a 500 on a request that was correct and
# would have succeeded a few hundred milliseconds later. Origin's writers are exactly the paths
# users hit at the same moment: OTP issuance, sign-in, token grants.
#
# The value is bracketed rather than chosen, by two facts about this service.

#: LOWER BOUND — the longest a write transaction stays open here. Origin's writes are single-row
#: and instant, but `otp_service.request_otp` takes the write lock (`supersede_live_for_email`)
#: and then awaits a bcrypt before committing, so the lock is held for a hash, not for an UPDATE.
#: bcrypt at its default cost is ~0.25s. A timeout below this cannot clear even one writer ahead.
_LONGEST_HELD_WRITE_S = 0.25

#: UPPER BOUND — Origin is served with `--timeout-graceful-shutdown 10`, so ten seconds is the
#: longest anything in this process is entitled to still be waiting when a shutdown begins. A
#: `busy_timeout` at or above it turns a routine restart into killed in-flight writers, which is a
#: worse failure than the SQLITE_BUSY it was meant to absorb.
_GRACEFUL_SHUTDOWN_S = 10.0

def sqlite_busy_timeout_ms() -> int:
    """Half the shutdown window: the whole queue drains inside it with the same margin again spare.

    At the values above that is 5s, or twenty writers queued ahead of you — far past any contention
    a single-worker identity service produces, and still a bounded wait rather than a hang. Both
    bounds move it: a slower hash inside the write transaction, or a longer shutdown window, widen
    the room; a shorter shutdown window narrows it.

    A function rather than a module constant, for the reason `otp_service._window_cap` gives: a
    constant assigned from an expression is indistinguishable from the same number typed in, so a
    test can only tell them apart by perturbing an input and watching — which requires the
    expression still to be there when it looks.
    """
    return int((_GRACEFUL_SHUTDOWN_S / 2) * 1000)


def _default_db_path() -> Path:
    """`<install root>/.data/origin/origin.db`.

    Derived from `config.BASE_DIR`, which is the same root `KEYS_DIR` hangs off, so an operator who
    sets `AGIENCE_BASE_DIR` moves both together. Deriving it from the working directory instead
    would mean a process started from elsewhere silently opened a different, empty database.
    """
    from origin import config

    return config.BASE_DIR / ".data" / "origin" / "origin.db"


def build_database_url() -> str:
    """Build the SQLAlchemy connection URL for Origin's SQLite DB.

    Honors `DATABASE_URL` if set (test override). Otherwise composes from
    `ORIGIN_DB_PATH` env var, falling back to a sensible default.
    """
    override = os.getenv("DATABASE_URL")
    if override:
        return override

    db_path_env = os.getenv("ORIGIN_DB_PATH")
    db_path = Path(db_path_env) if db_path_env else _default_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{db_path}"


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite:")


def _is_in_memory(url: str) -> bool:
    return url in ("sqlite://", "sqlite:///:memory:") or url.startswith("sqlite:///:memory:")


def init_engine(url: str | None = None) -> Engine:
    """Build the global SQLAlchemy engine. Idempotent."""
    global _engine, _SessionLocal
    if _engine is not None:
        return _engine

    resolved = url or build_database_url()
    kwargs: dict = {"future": True}

    if _is_sqlite(resolved):
        # FastAPI uses multiple threads; SQLite's default thread-check is too strict.
        kwargs["connect_args"] = {"check_same_thread": False}
        # In-memory DBs need a shared cache across connections (used by tests).
        if _is_in_memory(resolved):
            from sqlalchemy.pool import StaticPool

            kwargs["poolclass"] = StaticPool
    else:
        kwargs["pool_pre_ping"] = True

    _engine = create_engine(resolved, **kwargs)

    if _is_sqlite(resolved):
        @event.listens_for(_engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _conn_record) -> None:
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            # Unconditional, next to `foreign_keys` rather than inside the file-DB branch below:
            # it is a property of every connection Origin opens, and one exception fewer to reason
            # about. On the in-memory DB there is a single pooled connection and nothing to wait
            # for, so it costs nothing there.
            cur.execute(f"PRAGMA busy_timeout={sqlite_busy_timeout_ms()}")
            if not _is_in_memory(resolved):
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()

    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, future=True)
    return _engine


def get_engine() -> Engine:
    if _engine is None:
        raise RuntimeError("Engine not initialized — call init_engine() at startup.")
    return _engine


def SessionLocal() -> Session:
    if _SessionLocal is None:
        raise RuntimeError("Session factory not initialized — call init_engine() at startup.")
    return _SessionLocal()


def get_db() -> Iterator[Session]:
    """FastAPI dependency: yields a Session, closes it on request exit."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

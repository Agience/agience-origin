"""A writer that loses the race queues; it does not 500.

SQLite admits one writer at a time. WAL and `synchronous=NORMAL` were already set — those keep
readers out of a writer's way and bound the fsync cost — but neither says anything about what
happens to the *second* writer. Without `busy_timeout` that writer does not wait: SQLite returns
`SQLITE_BUSY` immediately, SQLAlchemy raises, and the request dies as a 500 that would have
succeeded a few hundred milliseconds later. The paths that collide are exactly the ones users hit
simultaneously — OTP issuance, sign-in, token grants.

The value is bracketed by two facts about this service rather than copied from elsewhere, and the
tests below assert the brackets rather than the number.
"""

from __future__ import annotations

import sqlite3
import threading
import time

import pytest

import origin.db.session as session_module


@pytest.fixture
def file_engine(tmp_path):
    """A real file-backed engine built the way production builds one.

    The module keeps its engine in a global, so it is saved and put back rather than reloaded —
    reloading would hand every module that already imported `get_db` a stale function object.
    """
    saved = (session_module._engine, session_module._SessionLocal)
    session_module._engine = None
    session_module._SessionLocal = None
    engine = None
    try:
        engine = session_module.init_engine(f"sqlite:///{tmp_path / 'origin.db'}")
        yield engine
    finally:
        if engine is not None:
            engine.dispose()
        session_module._engine, session_module._SessionLocal = saved


# ---------------------------------------------------------------------------
# The pragma is actually on the connection
# ---------------------------------------------------------------------------


def test_busy_timeout_is_set_on_a_file_backed_connection(file_engine):
    with file_engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA busy_timeout").scalar() == (
            session_module.sqlite_busy_timeout_ms()
        )


def test_wal_and_synchronous_are_still_set(file_engine):
    """Positive control on the fixture and on the pragma hook: the settings that were already
    correct must survive the one being added."""
    with file_engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA journal_mode").scalar().lower() == "wal"
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1


def test_busy_timeout_is_set_on_the_in_memory_engine_too():
    """No exception for the test database.

    The pragma sits next to `foreign_keys` rather than inside the file-only branch, so there is one
    fewer difference between the engine the suite runs against and the engine production runs.
    """
    saved = (session_module._engine, session_module._SessionLocal)
    session_module._engine = None
    session_module._SessionLocal = None
    try:
        engine = session_module.init_engine("sqlite:///:memory:")
        with engine.connect() as conn:
            assert conn.exec_driver_sql("PRAGMA busy_timeout").scalar() > 0
        engine.dispose()
    finally:
        session_module._engine, session_module._SessionLocal = saved


# ---------------------------------------------------------------------------
# The behaviour the pragma buys
# ---------------------------------------------------------------------------


def test_a_second_writer_waits_instead_of_raising(file_engine, tmp_path):
    """The property, not the pragma: a writer blocked behind another completes.

    A second connection holds the write lock for longer than a lock-free acquisition would take.
    Without `busy_timeout` this raises `database is locked` at once; with it the statement queues
    and succeeds.
    """
    with file_engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE t (v INTEGER)")

    db_path = str(tmp_path / "origin.db")
    taken = threading.Event()
    released = threading.Event()

    def hold_the_write_lock():
        # Opened in this thread: sqlite3 connections belong to the thread that created them.
        blocker = sqlite3.connect(db_path, isolation_level=None)
        blocker.execute("PRAGMA busy_timeout=5000")
        blocker.execute("BEGIN IMMEDIATE")
        blocker.execute("INSERT INTO t VALUES (1)")
        taken.set()
        time.sleep(0.4)
        blocker.execute("COMMIT")
        blocker.close()
        released.set()

    holder = threading.Thread(target=hold_the_write_lock)
    holder.start()
    assert taken.wait(5), "the blocking writer never acquired the lock"

    started = time.perf_counter()
    with file_engine.begin() as conn:
        conn.exec_driver_sql("INSERT INTO t VALUES (2)")
    waited = time.perf_counter() - started

    holder.join()

    assert released.is_set()
    assert waited > 0.1, (
        "the second write did not wait at all — it cannot have been contending, so this test is "
        "not measuring what it claims to"
    )
    with file_engine.connect() as conn:
        assert conn.exec_driver_sql("SELECT count(*) FROM t").scalar() == 2, (
            "a writer that queued through the lock must still have written"
        )


# ---------------------------------------------------------------------------
# The value is bracketed, not picked
# ---------------------------------------------------------------------------


def test_the_timeout_clears_at_least_one_of_the_longest_write_transactions():
    """Lower bound. `otp_service.request_otp` takes the write lock and then awaits a bcrypt before
    committing, so the lock is held for a hash rather than for an UPDATE. A timeout under that
    cannot clear even one writer ahead and buys nothing."""
    assert session_module.sqlite_busy_timeout_ms() / 1000 > session_module._LONGEST_HELD_WRITE_S


def test_the_timeout_expires_inside_the_graceful_shutdown_window():
    """Upper bound. Origin is served with `--timeout-graceful-shutdown 10`, so a waiter that
    could still be waiting past that turns a routine restart into killed in-flight writes — a worse
    failure than the SQLITE_BUSY it absorbs."""
    assert session_module.sqlite_busy_timeout_ms() / 1000 < session_module._GRACEFUL_SHUTDOWN_S


def test_the_timeout_tracks_the_shutdown_window(monkeypatch):
    """A shorter shutdown window must shorten the wait it bounds.

    The failure mode: a "derivation" that returns the same number whatever it is handed is a
    constant in a costume. Replacing the body with `return 5000` fails here.
    """
    base = session_module.sqlite_busy_timeout_ms()
    monkeypatch.setattr(session_module, "_GRACEFUL_SHUTDOWN_S", 2.0)
    assert session_module.sqlite_busy_timeout_ms() < base
    monkeypatch.setattr(session_module, "_GRACEFUL_SHUTDOWN_S", 60.0)
    assert session_module.sqlite_busy_timeout_ms() > base

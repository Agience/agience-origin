"""Origin refuses to boot multi-worker, because its OAuth stores are per-process.

A guard nobody has seen fire is a guard nobody knows works. Every branch below is demonstrated
raising, and the pass-through cases are demonstrated NOT raising — otherwise a guard that refused
everything would look identical to one that refused the right things.

The thing being protected is in `routers/auth_router.py`: `authorization_codes` and
`pkce_challenges` are module-level dicts, so a second worker mints a code the next worker cannot
find. That failure is intermittent and silent, which is what makes a loud refusal worth more than
a comment.
"""
from __future__ import annotations

import pytest

from origin.main import _refuse_multiple_workers

_VARS = ("WEB_CONCURRENCY", "UVICORN_WORKERS", "GUNICORN_CMD_ARGS")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """No worker signal set, so each test states its own. Without this the developer's own
    environment decides the result."""
    for name in _VARS:
        monkeypatch.delenv(name, raising=False)


def test_a_clean_environment_starts():
    """The vacuous-pass guard, inverted: if this raised, every refusal below would pass for the
    wrong reason."""
    _refuse_multiple_workers()


@pytest.mark.parametrize("name", ["WEB_CONCURRENCY", "UVICORN_WORKERS"])
def test_more_than_one_worker_is_refused(monkeypatch, name):
    monkeypatch.setenv(name, "4")
    with pytest.raises(RuntimeError) as exc:
        _refuse_multiple_workers()
    msg = str(exc.value)
    assert name in msg, "the refusal must name which setting caused it"
    assert "auth_router" in msg, "the refusal must name what breaks, not just that something does"
    assert "passkey_challenge" in msg, "the refusal must name the fix, not only the problem"


@pytest.mark.parametrize("name", ["WEB_CONCURRENCY", "UVICORN_WORKERS"])
@pytest.mark.parametrize("value", ["1", " 1 "])
def test_exactly_one_worker_is_allowed(monkeypatch, name, value):
    """One worker is the supported configuration and must not be refused — a guard that blocks the
    normal case gets deleted rather than fixed."""
    monkeypatch.setenv(name, value)
    _refuse_multiple_workers()


@pytest.mark.parametrize("args", ["--workers 4", "-w 8", "--bind 0.0.0.0:8080 --workers 2"])
def test_gunicorn_worker_flags_are_refused(monkeypatch, args):
    monkeypatch.setenv("GUNICORN_CMD_ARGS", args)
    with pytest.raises(RuntimeError):
        _refuse_multiple_workers()


def test_gunicorn_args_without_workers_are_allowed(monkeypatch):
    """`GUNICORN_CMD_ARGS` is not itself a worker request — refusing it wholesale would block a
    perfectly good timeout or bind setting."""
    monkeypatch.setenv("GUNICORN_CMD_ARGS", "--timeout 60 --bind 0.0.0.0:8080")
    _refuse_multiple_workers()


@pytest.mark.parametrize("junk", ["two", "", "  ", "4x"])
def test_an_unreadable_worker_count_is_refused_not_ignored(monkeypatch, junk):
    """An unparseable value is a setting somebody meant. Treating it as absent is how a guard
    passes on the exact configuration it exists to catch.

    The empty cases are the interesting ones and are deliberately NOT refusals: an empty string
    is how a shell exports a variable it has no value for, and refusing that would break every
    deployment that templates its environment.
    """
    monkeypatch.setenv("WEB_CONCURRENCY", junk)
    if junk.strip() == "":
        _refuse_multiple_workers()          # empty means unset, not malformed
        return
    with pytest.raises(RuntimeError) as exc:
        _refuse_multiple_workers()
    assert "could not be read" in str(exc.value)


def test_the_stores_this_guard_protects_are_still_per_process():
    """The guard's own premise, asserted rather than assumed.

    If someone moves these to the database, this test fails — and that failure is the signal to
    DELETE the guard, not to weaken it. A guard whose reason has gone is a guard that will one day
    refuse a configuration that had become perfectly safe.
    """
    from origin.routers import auth_router

    assert isinstance(auth_router.authorization_codes, dict), (
        "authorization_codes is no longer a plain dict — if it moved to storage, remove "
        "`_refuse_multiple_workers` and this test with it")
    assert isinstance(auth_router.pkce_challenges, dict), (
        "pkce_challenges is no longer a plain dict — same conclusion as above")

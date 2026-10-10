"""Operational properties of Origin's unauthenticated auth endpoints.

* The per-client mail cap does not turn a shared relay into a platform-wide mail limit: peers in
  `SHARED_CLIENT_NETWORKS` are exempt from it, ordinary clients are not, and a client reaching it is
  logged at WARNING once per window.
  An entry that does not say exactly what it covers is refused with a WARNING.
* Key derivations run off the event loop and on their own thread limiter, so a slow derivation
  does not stall other requests, and a flood of them does not take the threads that database
  dependencies need.
* A password failure is charged to the identifier as typed and to nothing else, so the budget
  cannot be used to learn which names belong to one account.
* Addresses and identifiers reach the log only as a keyed tag.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import threading

import httpx
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from origin import config
from origin.db.session import get_db
from origin.routers.auth_router import auth_router
from origin.services import guess_budget


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(auth_router)

    def _override_db():
        yield MagicMock()

    app.dependency_overrides[get_db] = _override_db
    return app


def _person(**overrides):
    base = dict(id="person-1", username="alice", email="alice@example.com", name="Alice",
                picture=None, password_hash="HASH", email_verified=True)
    base.update(overrides)
    return SimpleNamespace(**base)


def _resend(email, client, user=None):
    with patch(
        "origin.routers.auth_router.email_service.is_configured", return_value=True,
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_email",
        return_value=user or _person(email=email, email_verified=False),
    ), patch(
        "origin.routers.auth_router.create_jwt_token", return_value="verify.jwt",
    ), patch(
        "origin.routers.auth_router.email_service.send_email_verification",
    ) as send:
        resp = TestClient(_app(), client=(client, 1)).post(
            "/auth/email/verify-request", json={"email": email})
    return resp, send


# ---------------------------------------------------------------------------
# 1. The per-client mail cap and relays
# ---------------------------------------------------------------------------
def _fill_client(client: str, n: int) -> None:
    now = datetime.now(timezone.utc)
    for i in range(n):
        guess_budget.record_mail_send(f"fill{i}@example.com", client, now=now)


def test_an_ordinary_client_is_capped_across_addresses(monkeypatch):
    monkeypatch.setattr(config, "SHARED_CLIENT_NETWORKS", [])
    _fill_client("198.51.100.9", guess_budget.mail_send_client_cap())
    resp, send = _resend("one-more@example.com", "198.51.100.9")
    assert resp.json() == {"sent": True}
    send.assert_not_called()


def test_a_listed_shared_network_is_not_capped_per_client(monkeypatch):
    """Every hosted user reaches Origin through one relay; capping it per client would be a
    platform-wide mail limit."""
    monkeypatch.setattr(config, "SHARED_CLIENT_NETWORKS", ["198.51.100.0/24"])
    _fill_client("198.51.100.20", guess_budget.mail_send_client_cap() + 10)
    resp, send = _resend("one-more@example.com", "198.51.100.20")
    assert resp.json() == {"sent": True}
    send.assert_called_once()


def test_a_listed_shared_network_still_meets_the_per_address_caps(monkeypatch):
    monkeypatch.setattr(config, "SHARED_CLIENT_NETWORKS", ["198.51.100.0/24"])
    for _ in range(guess_budget.mail_send_cap()):
        _resend("same@example.com", "198.51.100.20")
    resp, send = _resend("same@example.com", "198.51.100.20")
    send.assert_not_called()


def test_a_client_reaching_the_cap_is_warned_once_per_window(monkeypatch, caplog):
    monkeypatch.setattr(config, "SHARED_CLIENT_NETWORKS", [])
    _fill_client("192.0.2.44", guess_budget.mail_send_client_cap())
    with caplog.at_level(logging.WARNING, logger="origin.services.guess_budget"):
        for i in range(5):
            assert guess_budget.mail_sends_exhausted(f"x{i}@example.com", "192.0.2.44")
    lines = [r for r in caplog.records if "per-client mail cap" in r.getMessage()]
    assert len(lines) == 1, [r.getMessage() for r in caplog.records]
    assert "192.0.2.44" in lines[0].getMessage()
    assert "FORWARDED_ALLOW_IPS" in lines[0].getMessage()


def test_an_address_reaching_its_cap_is_warned_once_per_window_without_the_address(caplog):
    """Several clients spending an address's sends is a flood aimed at its owner: it is named in
    the journal once per window, by tag, never by the address itself."""
    for c in range(guess_budget._MAIL_SEND_CLIENTS):
        for _ in range(guess_budget.mail_send_cap()):
            guess_budget.record_mail_send("owner@example.com", f"192.0.2.{c + 1}")
    with caplog.at_level(logging.WARNING, logger="origin.services.guess_budget"):
        for c in range(5):
            assert guess_budget.mail_sends_exhausted("owner@example.com", f"203.0.113.{c + 1}")
    lines = [r.getMessage() for r in caplog.records if "reached its cap" in r.getMessage()]
    assert len(lines) == 1, [r.getMessage() for r in caplog.records]
    assert "owner@example.com" not in lines[0]


def test_a_shared_network_is_logged_once_per_window(monkeypatch, caplog):
    monkeypatch.setattr(config, "SHARED_CLIENT_NETWORKS", ["198.51.100.0/24"])
    with caplog.at_level(logging.WARNING, logger="origin.services.guess_budget"):
        for i in range(5):
            guess_budget.mail_sends_exhausted(f"p{i}@example.com", "198.51.100.3")
    assert sum("SHARED_CLIENT_NETWORKS" in r.getMessage() for r in caplog.records) == 1


def test_the_per_client_cap_is_well_above_the_per_address_cap():
    assert guess_budget.mail_send_client_cap() >= 10 * guess_budget.mail_send_cap()


def test_a_shared_network_entry_with_host_bits_set_is_refused_not_widened(monkeypatch, caplog):
    """`10.0.0.5/8` is most likely a typo for one host; widening it would exempt all of 10/8."""
    monkeypatch.setattr(config, "SHARED_CLIENT_NETWORKS", ["10.0.0.5/8"])
    with caplog.at_level(logging.WARNING, logger="origin.services.guess_budget"):
        assert guess_budget._is_shared_client_network("10.200.0.1") is False
        assert guess_budget._is_shared_client_network("10.0.0.5") is False
    assert any("'10.0.0.5/8'" in r.getMessage() and "host bits" in r.getMessage()
               for r in caplog.records), [r.getMessage() for r in caplog.records]


def test_an_ipv4_mapped_shared_network_entry_is_refused_with_a_warning(monkeypatch, caplog):
    monkeypatch.setattr(config, "SHARED_CLIENT_NETWORKS", ["::ffff:10.0.0.5"])
    with caplog.at_level(logging.WARNING, logger="origin.services.guess_budget"):
        assert guess_budget._is_shared_client_network("10.0.0.5") is False
    assert any("'::ffff:10.0.0.5'" in r.getMessage() and "IPv4-mapped" in r.getMessage()
               for r in caplog.records), [r.getMessage() for r in caplog.records]


def test_exact_shared_network_entries_match(monkeypatch, caplog):
    monkeypatch.setattr(config, "SHARED_CLIENT_NETWORKS", ["10.0.0.5/32", "192.168.0.0/16"])
    with caplog.at_level(logging.WARNING, logger="origin.services.guess_budget"):
        assert guess_budget._is_shared_client_network("10.0.0.5") is True
        assert guess_budget._is_shared_client_network("::ffff:10.0.0.5") is True
        assert guess_budget._is_shared_client_network("192.168.40.2") is True
        assert guess_budget._is_shared_client_network("10.0.0.6") is False
    assert not caplog.records, "a well-formed entry was warned about"


# ---------------------------------------------------------------------------
# 2. The key derivation does not block the event loop
# ---------------------------------------------------------------------------
def test_a_slow_key_derivation_does_not_stall_other_requests():
    app = _app()

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    def slow_kdf(*_args):
        time.sleep(1.0)

    async def scenario():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            # Timed from the start of the login, not of the ping: a derivation on the loop stalls
            # the sleep below as well, so a clock started after it would miss the stall.
            t0 = time.monotonic()
            login = asyncio.create_task(c.post(
                "/auth/password/login", json={"identifier": "ghost@example.com", "password": "x"}))
            await asyncio.sleep(0.2)  # the login is inside its derivation
            pong = await c.get("/ping")
            ping_took = time.monotonic() - t0
            resp = await login
        return pong, ping_took, resp

    with patch(
        "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_email", return_value=None,
    ), patch(
        "origin.routers.auth_router.dummy_verify_password", side_effect=slow_kdf,
    ):
        pong, ping_took, resp = asyncio.run(scenario())

    assert pong.status_code == 200
    assert resp.status_code == 401
    assert ping_took < 0.8, (
        f"a concurrent request finished {ping_took:.2f}s after a login whose derivation sleeps 1s "
        "began: the derivation is running on the event loop")


def test_a_saturated_kdf_limiter_does_not_block_a_database_request(monkeypatch):
    """Derivations queue on their own limiter, not on anyio's default one.

    The default limiter (40 threads) also runs every synchronous dependency, `get_db` among them.
    More concurrent failing sign-ins than it has threads, each held inside its derivation, must not
    leave a request that needs the database waiting for a thread. The sign-ins come from distinct
    clients, and the derivation limiter is sized so none is shed, so that all of them are in flight.
    """
    monkeypatch.setenv("ORIGIN_KDF_THREADS", "10")
    app = _app()

    @app.get("/uses-db")
    async def uses_db(db=Depends(get_db)):
        return {"ok": True}

    release = threading.Event()

    def held_kdf(*_args):
        release.wait(10)

    logins = 45  # more than anyio's default thread limiter holds

    async def login_from(i):
        transport = httpx.ASGITransport(app=app, client=(f"10.20.0.{i + 1}", 1000))
        async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30) as c:
            return await c.post(
                "/auth/password/login", json={"identifier": f"ghost{i}@example.com", "password": "x"})

    async def scenario():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            pending = [asyncio.create_task(login_from(i)) for i in range(logins)]
            await asyncio.sleep(0.5)  # every login is inside, or queued for, its derivation
            t0 = time.monotonic()
            try:
                db_resp = await asyncio.wait_for(c.get("/uses-db"), timeout=3)
                took = time.monotonic() - t0
            except asyncio.TimeoutError:
                db_resp, took = None, None
            finally:
                release.set()
            results = await asyncio.gather(*pending)
        return db_resp, took, results

    with patch(
        "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_email", return_value=None,
    ), patch(
        "origin.routers.auth_router.dummy_verify_password", side_effect=held_kdf,
    ):
        db_resp, took, results = asyncio.run(scenario())

    assert db_resp is not None, (
        f"a request needing the database got no thread in 3s while {logins} derivations were held: "
        "the derivations are on the default thread limiter")
    assert db_resp.status_code == 200 and took < 1.0, took
    assert all(r.status_code == 401 for r in results)


# ---------------------------------------------------------------------------
# 4. Each name is its own password budget
# ---------------------------------------------------------------------------
def _login(identifier: str, person) -> int:
    with patch(
        "origin.routers.auth_router.platform_settings.get_bool", return_value=True,
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_email", return_value=person,
    ), patch(
        "origin.routers.auth_router.person_service.get_user_by_username", return_value=person,
    ), patch(
        "origin.routers.auth_router.verify_password", return_value=False,
    ):
        return TestClient(_app()).post(
            "/auth/password/login", json={"identifier": identifier, "password": "wrong"},
        ).status_code


def test_spending_a_username_budget_says_nothing_about_the_email():
    """Charging an account's other names on a failure would make the counter an oracle: spend the
    username's budget, then a candidate email answering 429 instead of 401 would confirm that both
    name one account."""
    alice = _person()
    for _ in range(guess_budget.password_window_cap()):
        assert _login("alice", alice) == 401
    assert _login("alice", alice) == 429, "a positive control: the username's own budget is spent"
    assert _login("alice@example.com", alice) == 401, (
        "the email throttled after only the username's budget was spent: the budget links names")


def test_an_unknown_identifier_charges_only_itself():
    for _ in range(guess_budget.password_window_cap()):
        _login("ghost", None)
    assert guess_budget.password_attempts_exhausted("ghost") is True
    assert guess_budget.password_attempts_exhausted("ghost@example.com") is False


# ---------------------------------------------------------------------------
# 5. Log tags are keyed
# ---------------------------------------------------------------------------
def test_the_log_tag_is_keyed_by_the_node_secret(tmp_path, monkeypatch):
    from origin.services import auth_service

    monkeypatch.setattr(config, "KEYS_DIR", tmp_path)
    (tmp_path / "platform_internal.secret").write_text("first-secret")
    auth_service._log_tag_key.cache_clear()
    try:
        first = auth_service.log_tag("someone@example.com")
        assert first == auth_service.log_tag("someone@example.com"), "not stable"
        assert first != hashlib.sha256(b"someone@example.com").hexdigest()[:12], (
            "the tag is an unkeyed hash, reversible from a list of candidate addresses")

        (tmp_path / "platform_internal.secret").write_text("second-secret")
        auth_service._log_tag_key.cache_clear()
        assert auth_service.log_tag("someone@example.com") != first
    finally:
        auth_service._log_tag_key.cache_clear()


def test_password_failures_log_a_tag_not_the_identifier(caplog):
    with caplog.at_level(logging.WARNING, logger="origin.routers.auth_router"):
        for _ in range(guess_budget.password_window_cap() + 1):
            _login("private.person@example.com", None)
    assert any("password authentication failed" in r.getMessage() for r in caplog.records)
    assert any("password attempt throttled" in r.getMessage() for r in caplog.records)
    assert "private.person@example.com" not in caplog.text.lower()

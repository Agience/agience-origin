"""What Origin's sign-in paths guarantee when many requests arrive at once.

* The password budget holds under concurrency: guesses sent at the same moment are each charged
  before any of them reaches its key derivation, so no more than the window cap are tested.
* A sign-in waiting for its key derivation holds no database connection, so more concurrent
  sign-ins than the pool holds neither fail nor freeze the event loop.
* An OTP request holds no SQLite write lock across its awaited hash, so two concurrent requests for
  two addresses both succeed without freezing the loop.
* The OTP ledger is keyed by the normalised address: whitespace and case variants share one
  ledger, one live code and one set of caps.
* Admission to derivation-spending routes sheds with 503 and `Retry-After` when the derivation
  queue is too deep, caps each client's requests in flight (429), and exempts clients in `SHARED_CLIENT_NETWORKS`.
* `kdf_threads()` counts the CPUs this process may use, keeps one for the event loop, and yields to
  `ORIGIN_KDF_THREADS`.
* OTP logs name addresses only by their keyed tag.

The concurrent scenarios run requests from distinct client addresses unless a test is about one
client, so that the per-client admission cap does not stand in for the property under test.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
import time
from collections import Counter
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI

from origin.services import guess_budget


def _modules():
    """The live router and session modules. `conftest.origin_app` reloads them in place, so they
    are looked up when a test runs, not bound when this file is imported."""
    import origin.db.session  # noqa: F401
    import origin.routers.auth_router  # noqa: F401
    import origin.routers.otp_router  # noqa: F401

    return (sys.modules["origin.routers.auth_router"], sys.modules["origin.routers.otp_router"],
            sys.modules["origin.db.session"])


def _app(*, mock_db: bool) -> FastAPI:
    auth_router_module, otp_router_module, session_module = _modules()
    dependencies = sys.modules["origin.services.dependencies"]
    app = FastAPI()
    app.include_router(auth_router_module.auth_router)
    app.include_router(otp_router_module.otp_router)
    # As `main.py` registers it, so refusals carry their `error` code.
    app.add_exception_handler(dependencies.KdfAdmissionRefused,
                              dependencies.kdf_admission_refused_handler)
    if mock_db:
        def _override_db():
            yield MagicMock()

        app.dependency_overrides[session_module.get_db] = _override_db
    return app


def _host(i: int) -> str:
    return f"10.{40 + i // 250}.{i % 250}.1"


async def _post_from(app, host: str, path: str, json: dict) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, client=(host, 1000), raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=120) as c:
        return await c.post(path, json=json)


class _LoopWatch:
    """The longest the event loop went without running a 10ms ticker."""

    def __init__(self) -> None:
        self.longest = 0.0
        self._stop = False
        self._task = None

    async def __aenter__(self):
        async def tick():
            last = time.monotonic()
            while not self._stop:
                await asyncio.sleep(0.01)
                now = time.monotonic()
                self.longest = max(self.longest, now - last)
                last = now

        self._task = asyncio.create_task(tick())
        return self

    async def __aexit__(self, *exc):
        self._stop = True
        await self._task


@pytest.fixture
def file_db(tmp_path, monkeypatch):
    """A file-backed SQLite database built the way production builds one (`init_engine`: WAL,
    `busy_timeout`, the default connection pool), in place of the test suite's in-memory one."""
    import origin.models  # noqa: F401 — registers the models
    from origin.db.base import Base

    _, _, session_module = _modules()
    monkeypatch.setattr(session_module, "_engine", None)
    monkeypatch.setattr(session_module, "_SessionLocal", None)
    engine = session_module.init_engine(f"sqlite:///{tmp_path / 'origin.db'}")
    Base.metadata.create_all(bind=engine)
    yield session_module
    engine.dispose()


# ---------------------------------------------------------------------------
# 1. Concurrent guesses are each charged before any derivation
# ---------------------------------------------------------------------------
def test_concurrent_guesses_test_no_more_passwords_than_the_cap(monkeypatch):
    monkeypatch.setenv("ORIGIN_KDF_THREADS", "16")  # deep enough that nothing is shed
    app = _app(mock_db=True)
    alice = SimpleNamespace(id="p1", username="alice", email="alice@example.com", name="Alice",
                            picture=None, password_hash="pbkdf2_sha256$1$AA$AA", email_verified=True)
    tested = []
    lock = threading.Lock()

    def slow_wrong(*_a):
        with lock:
            tested.append(1)
        time.sleep(0.2)
        return False

    guesses = 50

    async def scenario():
        return await asyncio.gather(*[
            _post_from(app, _host(i), "/auth/password/login",
                       {"identifier": "alice", "password": f"guess-{i}"})
            for i in range(guesses)])

    with patch("origin.routers.auth_router.platform_settings.get_bool", return_value=True), \
            patch("origin.routers.auth_router.person_service.get_user_by_username",
                  return_value=alice), \
            patch("origin.routers.auth_router.verify_password", side_effect=slow_wrong):
        results = asyncio.run(scenario())

    cap = guess_budget.password_window_cap()
    statuses = Counter(r.status_code for r in results)
    assert len(tested) <= cap, (
        f"{len(tested)} passwords were tested from {guesses} concurrent guesses; the window allows "
        f"{cap}. Statuses: {dict(statuses)}")
    assert statuses == Counter({401: cap, 429: guesses - cap}), dict(statuses)


# ---------------------------------------------------------------------------
# 2. No database connection is held across a derivation
# ---------------------------------------------------------------------------
def test_more_concurrent_sign_ins_than_the_pool_holds_neither_fail_nor_freeze(file_db, monkeypatch):
    """The default pool is 5 connections plus 10 overflow, and a checkout past that blocks the
    event loop for up to 30s. Sign-ins waiting for their derivation must not be holding one."""
    monkeypatch.setenv("ORIGIN_KDF_THREADS", "8")
    app = _app(mock_db=False)
    sign_ins = 24

    def slow_kdf(*_a):
        time.sleep(0.5)

    async def scenario():
        async with _LoopWatch() as watch:
            results = await asyncio.gather(*[
                _post_from(app, _host(i), "/auth/password/login",
                           {"identifier": f"junk{i}@example.com", "password": "x"})
                for i in range(sign_ins)])
        return results, watch.longest

    with patch("origin.routers.auth_router.platform_settings.get_bool", return_value=True), \
            patch("origin.routers.auth_router.dummy_verify_password", side_effect=slow_kdf):
        results, longest = asyncio.run(scenario())

    statuses = Counter(r.status_code for r in results)
    assert statuses == Counter({401: sign_ins}), dict(statuses)
    assert longest < 1.0, f"the event loop went {longest:.1f}s without a tick"


# ---------------------------------------------------------------------------
# 3. No SQLite write lock is held across the OTP hash
# ---------------------------------------------------------------------------
def test_two_concurrent_otp_requests_both_succeed_without_freezing_the_loop(file_db, monkeypatch):
    """A queue of derivations ahead makes the OTP hash wait; the write lock must not wait with it,
    or the second request's write blocks the loop on `busy_timeout` and fails."""
    from origin.db import persons as db_persons

    monkeypatch.setenv("ORIGIN_KDF_THREADS", "2")
    with file_db.SessionLocal() as s:
        db_persons.create(s, {"email": "alice@example.com", "name": "alice"})
        db_persons.create(s, {"email": "bob@example.com", "name": "bob"})
        s.commit()
    app = _app(mock_db=False)

    def slow_kdf(*_a):
        time.sleep(0.5)

    async def scenario():
        async with _LoopWatch() as watch:
            spray = [asyncio.create_task(_post_from(
                app, _host(i), "/auth/password/login",
                {"identifier": f"junk{i}@example.com", "password": "x"})) for i in range(6)]
            await asyncio.sleep(0.1)
            a = asyncio.create_task(_post_from(
                app, "192.0.2.1", "/auth/otp/request", {"email": "alice@example.com"}))
            await asyncio.sleep(0.1)
            b = asyncio.create_task(_post_from(
                app, "192.0.2.2", "/auth/otp/request", {"email": "bob@example.com"}))
            ra, rb = await a, await b
            await asyncio.gather(*spray)
        return ra, rb, watch.longest

    with patch("origin.routers.otp_router.email_service.is_configured", return_value=True), \
            patch("origin.services.email_service.send_otp", new=AsyncMock(return_value=True)), \
            patch("origin.routers.auth_router.platform_settings.get_bool", return_value=True), \
            patch("origin.routers.auth_router.dummy_verify_password", side_effect=slow_kdf):
        ra, rb, longest = asyncio.run(scenario())

    assert (ra.status_code, rb.status_code) == (200, 200), (ra.text, rb.text)
    assert longest < 1.0, f"the event loop went {longest:.1f}s without a tick"


# ---------------------------------------------------------------------------
# 4. One ledger per address, whatever its spelling
# ---------------------------------------------------------------------------
def test_address_variants_share_one_otp_ledger_and_one_cap():
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session
    from sqlalchemy.pool import StaticPool

    import origin.models  # noqa: F401
    from origin.db import otp_codes as db_otp
    from origin.db import persons as db_persons
    from origin.db.base import Base
    from origin.services import otp_service

    auth_router_module, otp_router_module, session_module = _modules()
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    with Session(engine) as s:
        db_persons.create(s, {"email": "alice@example.com", "name": "alice"})
        s.commit()

    app = FastAPI()
    app.include_router(otp_router_module.otp_router)

    def _db():
        with Session(engine) as s:
            yield s

    app.dependency_overrides[session_module.get_db] = _db
    sent = []

    async def fake_send(email, code):
        sent.append((email, code))
        return True

    variants = [" alice@example.com", "alice@example.com ", "\talice@example.com",
                "ALICE@example.com", "Alice@Example.COM "]
    with patch("origin.routers.otp_router.email_service.is_configured", return_value=True), \
            patch("origin.services.email_service.send_otp", side_effect=fake_send), \
            patch("origin.routers.otp_router.create_jwt_token",
                  side_effect=lambda d, **k: "jwt-for-" + d["email"]):
        c = TestClient(app)
        cap = otp_service._window_cap()
        first = [c.post("/auth/otp/request", json={"email": "alice@example.com"}).status_code
                 for _ in range(cap)]
        after = [c.post("/auth/otp/request", json={"email": v}).status_code for v in variants]

        with Session(engine) as s:
            keyed_by = {row[0] for row in s.execute(text("select email from otp_codes"))}
            live = db_otp.list_valid_for_email(s, "alice@example.com",
                                               otp_service._MAX_ATTEMPTS_PER_CODE)
        email, code = sent[-1]
        verified = c.post("/auth/otp/verify", json={"email": " ALICE@example.com", "code": code})

    assert first == [200] * cap
    # A refused request answers exactly as an issued one (`{"sent": true}`); what shows the cap
    # held is the mail: no variant got a code of its own.
    assert after == [200] * len(variants), after
    assert len(sent) == cap, (
        f"{len(sent)} codes mailed for {cap} allowed: variants of a capped address each got a cap")
    assert keyed_by == {"alice@example.com"}, keyed_by
    assert len(live) == 1, f"{len(live)} live codes for one address"
    assert {e for e, _ in sent} == {"alice@example.com"}
    assert verified.status_code == 200 and verified.json()["access_token"] == (
        "jwt-for-alice@example.com")


# ---------------------------------------------------------------------------
# 5. Admission: shed when the queue is deep, cap each client's requests in flight
# ---------------------------------------------------------------------------
def _held_logins(app, hosts, release, extra_host):
    """Start one login per host with its derivation held on `release`, then send one more from
    `extra_host`. A refused request answers at once, an admitted one waits for its derivation, so
    the extra is given a moment before the derivations are released. Returns the extra response,
    whether it had answered before the release, and the held responses."""

    async def scenario():
        held = [asyncio.create_task(_post_from(
            app, h, "/auth/password/login", {"identifier": f"g{i}@example.com", "password": "x"}))
            for i, h in enumerate(hosts)]
        await asyncio.sleep(0.4)  # each is inside, or queued for, its derivation
        extra = asyncio.create_task(_post_from(
            app, extra_host, "/auth/password/login",
            {"identifier": "last@example.com", "password": "x"}))
        await asyncio.sleep(0.3)
        answered_at_once = extra.done()
        release.set()
        return await extra, answered_at_once, await asyncio.gather(*held)

    return asyncio.run(scenario())


@pytest.fixture
def held_kdf():
    release = threading.Event()

    def kdf(*_a):
        release.wait(10)

    with patch("origin.routers.auth_router.platform_settings.get_bool", return_value=True), \
            patch("origin.routers.auth_router.person_service.get_user_by_email", return_value=None), \
            patch("origin.routers.auth_router.dummy_verify_password", side_effect=kdf):
        yield release


def test_a_deep_derivation_queue_is_shed_with_503_and_retry_after(monkeypatch, held_kdf, caplog):
    from origin.services import auth_service

    monkeypatch.setenv("ORIGIN_KDF_THREADS", "1")
    depth = auth_service.KDF_QUEUE_PER_THREAD * 1
    app = _app(mock_db=True)
    with caplog.at_level(logging.WARNING, logger="origin.services.auth_service"):
        extra, at_once, held = _held_logins(app, [_host(i) for i in range(1 + depth)], held_kdf,
                                            _host(999))
    assert extra.status_code == 503 and at_once, extra.text
    assert extra.json()["error"] == "busy"
    assert extra.headers.get("Retry-After") == str(auth_service.KDF_RETRY_AFTER_S)
    assert all(r.status_code == 401 for r in held), [r.status_code for r in held]
    assert sum("being shed" in r.getMessage() for r in caplog.records) == 1, (
        "a shed must be logged, once per window")


def test_below_the_shed_depth_nothing_is_shed(monkeypatch, held_kdf):
    """A positive control for the shed: one fewer request queued and the next one is admitted."""
    from origin.services import auth_service

    monkeypatch.setenv("ORIGIN_KDF_THREADS", "1")
    depth = auth_service.KDF_QUEUE_PER_THREAD * 1
    app = _app(mock_db=True)
    extra, _, _ = _held_logins(app, [_host(i) for i in range(depth)], held_kdf, _host(999))
    assert extra.status_code == 401, extra.text


def test_one_client_is_capped_on_requests_in_flight(monkeypatch, held_kdf, caplog):
    from origin.services import auth_service

    monkeypatch.setenv("ORIGIN_KDF_THREADS", "8")
    cap = auth_service.KDF_IN_FLIGHT_PER_CLIENT
    app = _app(mock_db=True)
    with caplog.at_level(logging.WARNING, logger="origin.services.auth_service"):
        extra, at_once, held = _held_logins(app, ["198.51.100.7"] * cap, held_kdf, "198.51.100.7")
    assert extra.status_code == 429 and at_once, extra.text
    assert extra.json() == {
        "detail": "Too many sign-ins in progress from your network; retry in a moment.",
        "error": "too_many_in_flight",
    }, "the in-flight cap must not read as the password lockout"
    assert extra.headers.get("Retry-After") == str(auth_service.KDF_RETRY_AFTER_S)
    assert all(r.status_code == 401 for r in held)
    lines = [r.getMessage() for r in caplog.records if "in-flight sign-in cap" in r.getMessage()]
    assert len(lines) == 1 and "198.51.100.7" in lines[0], lines


def test_another_client_is_not_held_by_one_clients_cap(monkeypatch, held_kdf):
    from origin.services import auth_service

    monkeypatch.setenv("ORIGIN_KDF_THREADS", "8")
    cap = auth_service.KDF_IN_FLIGHT_PER_CLIENT
    app = _app(mock_db=True)
    extra, _, _ = _held_logins(app, ["198.51.100.7"] * cap, held_kdf, "198.51.100.8")
    assert extra.status_code == 401, extra.text


def test_a_listed_shared_network_is_exempt_from_the_in_flight_cap(monkeypatch, held_kdf):
    from origin import config
    from origin.services import auth_service

    monkeypatch.setenv("ORIGIN_KDF_THREADS", "8")
    monkeypatch.setattr(config, "SHARED_CLIENT_NETWORKS", ["198.51.100.7/32"])
    cap = auth_service.KDF_IN_FLIGHT_PER_CLIENT
    app = _app(mock_db=True)
    extra, _, _ = _held_logins(app, ["198.51.100.7"] * cap, held_kdf, "198.51.100.7")
    assert extra.status_code == 401, extra.text


def test_in_flight_slots_are_released(monkeypatch, held_kdf):
    from origin.services import auth_service

    monkeypatch.setenv("ORIGIN_KDF_THREADS", "8")
    app = _app(mock_db=True)
    _held_logins(app, ["198.51.100.9"] * auth_service.KDF_IN_FLIGHT_PER_CLIENT, held_kdf,
                 "198.51.100.10")
    assert auth_service._kdf_in_flight == {}, auth_service._kdf_in_flight
    assert auth_service._kdf_admitted == 0, auth_service._kdf_admitted


def test_requests_with_no_client_address_leave_no_slot_behind(monkeypatch):
    """A request whose ASGI scope has no client (a Unix socket, some servers) is counted as the
    client "unknown" and released like any other: sequential requests never meet the cap."""
    from origin.services import auth_service

    monkeypatch.setenv("ORIGIN_KDF_THREADS", "8")
    app = _app(mock_db=True)

    async def one():
        transport = httpx.ASGITransport(app=app, client=None, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30) as c:
            return await c.post("/auth/password/login",
                                json={"identifier": "nobody@example.com", "password": "x"})

    with patch("origin.routers.auth_router.platform_settings.get_bool", return_value=True), \
            patch("origin.routers.auth_router.person_service.get_user_by_email", return_value=None), \
            patch("origin.routers.auth_router.dummy_verify_password"):
        statuses = [asyncio.run(one()).status_code
                    for _ in range(auth_service.KDF_IN_FLIGHT_PER_CLIENT + 1)]
    assert statuses == [401] * (auth_service.KDF_IN_FLIGHT_PER_CLIENT + 1), statuses
    assert auth_service._kdf_in_flight == {}, auth_service._kdf_in_flight
    assert auth_service._kdf_admitted == 0


def test_a_simultaneous_burst_is_shed_beyond_the_bound(monkeypatch):
    """The shed counts requests admitted, not only those already waiting on the derivation queue,
    so a burst that arrives all at once cannot overfill it before any of it is waiting."""
    from origin.services import auth_service

    monkeypatch.setenv("ORIGIN_KDF_THREADS", "1")
    bound = (auth_service.KDF_QUEUE_PER_THREAD + 1) * 1
    app = _app(mock_db=True)
    peak = 0

    def kdf(*_a):
        time.sleep(0.05)

    async def scenario():
        nonlocal peak
        stop = asyncio.Event()

        async def watch():
            nonlocal peak
            while not stop.is_set():
                peak = max(peak, auth_service.kdf_limiter().statistics().tasks_waiting)
                await asyncio.sleep(0.005)

        w = asyncio.create_task(watch())
        results = await asyncio.gather(*[
            _post_from(app, _host(i), "/auth/password/login",
                       {"identifier": f"b{i}@example.com", "password": "x"}) for i in range(100)])
        stop.set()
        await w
        return results

    with patch("origin.routers.auth_router.platform_settings.get_bool", return_value=True), \
            patch("origin.routers.auth_router.person_service.get_user_by_email", return_value=None), \
            patch("origin.routers.auth_router.dummy_verify_password", side_effect=kdf):
        results = asyncio.run(scenario())

    statuses = Counter(r.status_code for r in results)
    assert statuses[401] <= bound, (
        f"{statuses[401]} of a simultaneous burst of 100 were admitted against a bound of {bound}: "
        f"{dict(statuses)}")
    assert statuses[401] + statuses[503] == 100, dict(statuses)
    assert peak <= auth_service.KDF_QUEUE_PER_THREAD, f"peak queue {peak}"


def test_registration_frees_its_admission_slot_before_the_background_mail():
    """The verification mail is a background task that runs after the response. The admission slot
    (and the per-client count) must already be free while it runs."""
    from origin.services import auth_service

    app = _app(mock_db=True)
    seen = {}

    async def send(email, url):
        seen["admitted"] = auth_service._kdf_admitted
        seen["in_flight"] = dict(auth_service._kdf_in_flight)
        return True

    person = SimpleNamespace(id="00000000-0000-0000-0000-000000000001", username="new@example.com",
                             email="new@example.com", name="new", password_hash="H",
                             email_verified=False)
    with patch("origin.routers.auth_router.platform_settings.get_bool", return_value=True), \
            patch("origin.routers.auth_router.platform_settings.get_int", return_value=12), \
            patch("origin.routers.auth_router.hash_password", return_value="H"), \
            patch("origin.routers.auth_router.email_verification_required", return_value=True), \
            patch("origin.routers.auth_router.create_jwt_token", return_value="verify.jwt"), \
            patch("origin.routers.auth_router.person_service.create_user_with_password",
                  return_value=person), \
            patch("origin.routers.auth_router.email_service.send_email_verification",
                  side_effect=send):
        r = asyncio.run(_post_from(app, "198.51.100.44", "/auth/password/register", {
            "username": "new@example.com", "email": "new@example.com",
            "password": "a-long-enough-password"}))
    assert r.status_code == 200, r.text
    assert seen == {"admitted": 0, "in_flight": {}}, seen


# ---------------------------------------------------------------------------
# 2 (round 9). A password re-hash never overwrites a reset committed meanwhile
# ---------------------------------------------------------------------------
def test_a_reset_committed_during_the_rehash_wins(file_db, monkeypatch):
    from origin import config
    from origin.db import persons as db_persons
    from origin.services import auth_service, person_service

    auth_router_module, _, _ = _modules()
    real_hash = auth_service.hash_password
    with patch.object(config, "PASSWORD_PBKDF2_ITERS", 1000, create=True):
        stale = real_hash("old password!")  # below the current cost, so sign-in re-hashes it
    with file_db.SessionLocal() as s:
        person = db_persons.create(s, {"email": "bob@example.com", "username": "bob@example.com",
                                       "name": "bob", "password_hash": stale,
                                       "email_verified": True})
        s.commit()
        person_id = str(person.id)
    reset_hash = real_hash("NEW password after reset")

    def hash_while_a_reset_commits(pw):
        with file_db.SessionLocal() as s:
            person_service.set_password(s, person_id, reset_hash)
            s.commit()
        return real_hash(pw)

    app = _app(mock_db=False)
    with patch("origin.routers.auth_router.platform_settings.get_bool", return_value=True), \
            patch("origin.routers.auth_router.create_jwt_token", return_value="jwt"), \
            patch("origin.routers.auth_router._compute_roles", return_value=[]), \
            patch("origin.routers.auth_router.person_service.record_person_event"), \
            patch.object(auth_router_module, "hash_password", side_effect=hash_while_a_reset_commits):
        r = asyncio.run(_post_from(app, "198.51.100.50", "/auth/password/login",
                                   {"identifier": "bob@example.com", "password": "old password!"}))
    assert r.status_code == 200, r.text
    with file_db.SessionLocal() as s:
        final = db_persons.get_by_id(s, person_id).password_hash
    assert final == reset_hash, "the re-hash of the old password overwrote the reset"
    assert auth_service.verify_password("NEW password after reset", final)
    assert not auth_service.verify_password("old password!", final)


def test_a_stale_hash_is_still_upgraded_when_nothing_raced_it(file_db):
    """A positive control: the conditional write does write when the hash is unchanged."""
    from origin import config
    from origin.db import persons as db_persons
    from origin.services import auth_service

    with patch.object(config, "PASSWORD_PBKDF2_ITERS", 1000, create=True):
        stale = auth_service.hash_password("old password!")
    with file_db.SessionLocal() as s:
        person = db_persons.create(s, {"email": "carl@example.com", "username": "carl@example.com",
                                       "name": "carl", "password_hash": stale,
                                       "email_verified": True})
        s.commit()
        person_id = str(person.id)
    app = _app(mock_db=False)
    with patch("origin.routers.auth_router.platform_settings.get_bool", return_value=True), \
            patch("origin.routers.auth_router.create_jwt_token", return_value="jwt"), \
            patch("origin.routers.auth_router._compute_roles", return_value=[]), \
            patch("origin.routers.auth_router.person_service.record_person_event"):
        r = asyncio.run(_post_from(app, "198.51.100.51", "/auth/password/login",
                                   {"identifier": "carl@example.com", "password": "old password!"}))
    assert r.status_code == 200, r.text
    with file_db.SessionLocal() as s:
        final = db_persons.get_by_id(s, person_id).password_hash
    assert final != stale and auth_service.password_hash_is_current(final)
    assert auth_service.verify_password("old password!", final)


# ---------------------------------------------------------------------------
# 6. How many derivation threads
# ---------------------------------------------------------------------------
def test_kdf_threads_keeps_a_cpu_for_the_loop_and_yields_to_the_override(monkeypatch):
    from origin.services import auth_service

    monkeypatch.delenv("ORIGIN_KDF_THREADS", raising=False)
    monkeypatch.setattr(auth_service.os, "sched_getaffinity", lambda _pid: {0, 1, 2, 3},
                        raising=False)
    assert auth_service.kdf_threads() == 3
    monkeypatch.setattr(auth_service.os, "sched_getaffinity", lambda _pid: {0}, raising=False)
    assert auth_service.kdf_threads() == 1, "the floor is one derivation thread"

    monkeypatch.setenv("ORIGIN_KDF_THREADS", "5")
    assert auth_service.kdf_threads() == 5
    for bad in ("0", "-2", "many"):
        monkeypatch.setenv("ORIGIN_KDF_THREADS", bad)
        assert auth_service.kdf_threads() == 1, f"{bad!r} must be ignored, not obeyed"


# ---------------------------------------------------------------------------
# 7. OTP logs carry tags, not addresses
# ---------------------------------------------------------------------------
def test_otp_paths_log_a_tag_not_the_address(caplog):
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from sqlalchemy.pool import StaticPool

    import origin.models  # noqa: F401
    from origin.db import persons as db_persons
    from origin.db.base import Base

    _, otp_router_module, session_module = _modules()
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    with Session(engine) as s:
        db_persons.create(s, {"email": "known.person@example.com", "name": "k"})
        s.commit()
    app = FastAPI()
    app.include_router(otp_router_module.otp_router)

    def _db():
        with Session(engine) as s:
            yield s

    app.dependency_overrides[session_module.get_db] = _db
    with patch("origin.routers.otp_router.email_service.is_configured", return_value=True), \
            patch("origin.services.email_service.send_otp", new=AsyncMock(return_value=False)), \
            caplog.at_level(logging.INFO):
        c = TestClient(app)
        c.post("/auth/otp/request", json={"email": "known.person@example.com"})
        c.post("/auth/otp/request", json={"email": "unknown.person@example.com"})
        c.post("/auth/otp/verify", json={"email": "known.person@example.com", "code": "000000"})
        c.post("/auth/otp/verify", json={"email": "unknown.person@example.com", "code": "000000"})
    text = caplog.text.lower()
    assert "otp" in text, "no OTP log lines captured — this check is measuring nothing"
    assert "known.person@example.com" not in text
    assert "unknown.person@example.com" not in text

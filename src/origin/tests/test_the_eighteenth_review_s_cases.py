"""Review 18, F1: Mantle's catch-up reads the whole ledger, page after page, before it decides
what the latest change to each row is. Origin's feed answers `FEED_PAGE` entries at a time.

These run Origin's real feed handler (its service-token check stubbed) and Mantle's real
`apply_remote` and `catch_up_skipped`.
"""
# ruff: noqa: F811
from __future__ import annotations

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares
from origin.tests.test_origin_co_signs_only_changes_the_actor_may_make import (  # noqa: F401
    ALL, world)

custody_client = _shares.custody_client


class _RealFeed:
    def ledger_feed(self, after):
        from origin.db.session import SessionLocal
        from origin.routers import authority_router
        with SessionLocal() as db:
            return authority_router.ledger_feed(None, after=after, db=db, auth=None)


@pytest.fixture
def mantle_store(tmp_path, monkeypatch):
    from jose import jwk
    from mantle.db import lattice_api as la
    from mantle.services import authority_ledger as mantle_ledger
    from origin.key_manager import get_key_id, get_public_key_pem
    from origin.routers import authority_router
    monkeypatch.setattr(authority_router, "bound_call", lambda *a, **k: "")
    key = jwk.construct(get_public_key_pem(), "RS256")
    monkeypatch.setattr(mantle_ledger, "_origin_keys", lambda: {get_key_id(): key})
    return la.LatticeDatabase(str(tmp_path / "m.db"), origin="m")


def _head():
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger
    with SessionLocal() as db:
        return authority_ledger.head(db)[0]


def _cursor(store):
    row = store.graph.db.read().execute(
        "SELECT seq FROM authority_receipt WHERE subject = 'ledger:applied'").fetchone()
    return int(row[0]) if row else 0


def _old_mantle_walks(store, monkeypatch, head):
    """What a Mantle before review 17 did: walk the feed a page per pass, applying no session
    entry and running no catch-up."""
    from mantle.services import authority_ledger as mantle_ledger
    with monkeypatch.context() as m:
        m.setattr(mantle_ledger, "MANTLE_APPLIES", frozenset({"origin_page", "operator"}))
        m.setattr(mantle_ledger, "catch_up_skipped", lambda *a, **k: 0)
        while _cursor(store) < head:
            before = _cursor(store)
            mantle_ledger.apply_remote(store, _RealFeed())
            assert _cursor(store) > before


def _fill(c, alice_id, carol_id, upto):
    while _head() < upto:
        af.ok(af.session_submit(c, alice_id, af.grant(f"g-fill-{_head()}", carol_id, "W",
                                                      ["update"])))


def test_a_grant_revoked_past_the_first_page_stays_revoked(custody_client, world, mantle_store,
                                                           monkeypatch):
    """The reviewer's case, at Origin's real page size."""
    from mantle.db import lattice_api as la
    from mantle.services import authority_ledger as mantle_ledger
    c = custody_client
    alice_id, carol_id = world["alice"][0], world["carol"][0]
    af.ok(af.session_submit(c, alice_id, af.grant("g-cr", carol_id, "W", ["read"])))
    _fill(c, alice_id, carol_id, 505)
    af.ok(af.session_submit(c, alice_id, af.grant("g-cr", carol_id, "W", ["read"],
                                                  state="revoked")))
    head = _head()
    assert head > 500
    _old_mantle_walks(mantle_store, monkeypatch, head)
    assert la.get_grant_by_id(mantle_store, "g-cr") is None
    mantle_ledger.apply_remote(mantle_store, _RealFeed())
    assert la.get_grant_by_id(mantle_store, "g-cr").state == "revoked"
    assert mantle_ledger.catch_up_skipped(mantle_store, _RealFeed()) == 0


@pytest.fixture
def small_pages(monkeypatch):
    from origin.routers import authority_router
    monkeypatch.setattr(authority_router, "FEED_PAGE", 5)


def test_a_store_an_earlier_one_page_run_marked_is_caught_up_again(custody_client, world,
                                                                    mantle_store, monkeypatch,
                                                                    small_pages):
    """A store marked by review 17's one-page run, which put an early session state back, is
    caught up again under the new marker."""
    from mantle.db import lattice_api as la
    from mantle.services import authority_ledger as mantle_ledger
    c = custody_client
    alice_id, carol_id = world["alice"][0], world["carol"][0]
    af.ok(af.session_submit(c, alice_id, af.grant("g-cr", carol_id, "W", ["read"])))
    _fill(c, alice_id, carol_id, 12)
    af.ok(af.session_submit(c, alice_id, af.grant("g-cr", carol_id, "W", ["read"],
                                                  state="revoked")))
    head = _head()
    _old_mantle_walks(mantle_store, monkeypatch, head)
    # What review 17's one-page run left: the early grant written back, and its marker set.
    early = next(e for e in _RealFeed().ledger_feed(0)["entries"]
                 if e["body"].get("grant_id") == "g-cr")
    mantle_ledger._apply_session(mantle_store, early)
    with mantle_store.graph.db.write() as cur:
        cur.execute("INSERT OR REPLACE INTO authority_receipt(subject, kind, seq, entry_hash) "
                    "VALUES('ledger:catchup-review17', 'catchup', ?, NULL)", (head,))
    assert la.get_grant_by_id(mantle_store, "g-cr").state == "active"
    mantle_ledger.apply_remote(mantle_store, _RealFeed())
    assert la.get_grant_by_id(mantle_store, "g-cr").state == "revoked"


def test_an_operator_revoke_past_the_first_page_is_not_overwritten(custody_client, world,
                                                                    mantle_store, monkeypatch,
                                                                    small_pages):
    """An operator's revoke, past the first page, that Mantle had already applied, stands: the
    catch-up does not put the earlier session grant back over it."""
    from mantle.db import lattice_api as la
    from mantle.services import authority_ledger as mantle_ledger
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityGrant
    from origin.services import authority_ledger as origin_ledger
    c = custody_client
    alice_id, carol_id = world["alice"][0], world["carol"][0]
    af.ok(af.session_submit(c, alice_id, af.grant("g-cr", carol_id, "W", ["read"])))
    _fill(c, alice_id, carol_id, 12)
    with SessionLocal() as db:
        seq = db.get(AuthorityGrant, "g-cr").seq
        origin_ledger.revoke_entry(db, seq, "operator-1", "r18")
    head = _head()
    _old_mantle_walks(mantle_store, monkeypatch, head)
    mantle_ledger.apply_remote(mantle_store, _RealFeed())
    held = la.get_grant_by_id(mantle_store, "g-cr")
    assert held is not None and held.state != "active"


def test_a_short_page_leaves_the_catch_up_undone(custody_client, world, mantle_store,
                                                 monkeypatch, small_pages):
    from mantle.services import authority_ledger as mantle_ledger
    c = custody_client
    alice_id, carol_id = world["alice"][0], world["carol"][0]
    _fill(c, alice_id, carol_id, 12)
    head = _head()
    _old_mantle_walks(mantle_store, monkeypatch, head)

    class _Short(_RealFeed):
        def ledger_feed(self, after):
            page = super().ledger_feed(after)
            return page if after == 0 else {"entries": [], "head": page["head"]}
    assert mantle_ledger.catch_up_skipped(mantle_store, _Short()) == 0
    row = mantle_store.graph.db.read().execute(
        "SELECT seq FROM authority_receipt WHERE subject = ?",
        (mantle_ledger._CATCHUP,)).fetchone()
    assert row is None                                      # not marked: it runs again


# -- F2: one stored expiry, read one way on both sides -------------------------------------------

def test_a_padded_expiry_is_stored_canonical_and_past_on_both_sides():
    from datetime import datetime, timedelta, timezone

    from mantle.db.lattice_api import _unexpired as mantle_unexpired
    from origin.services.authority_ledger import normalise
    from origin.services.authority_reach import unexpired as origin_unexpired

    when = (datetime.now(timezone.utc) - timedelta(hours=2)).replace(microsecond=0)
    past = when.astimezone(timezone(timedelta(hours=14))).isoformat() + " "
    stored = normalise({"kind": "grant", "grant_id": "g", "grantee_id": "u",
                        "grantee_type": "user", "resource_id": "W", "actions": ["read"],
                        "effect": "allow", "state": "active", "expires_at": past,
                        "target": None, "max_claims": None})["expires_at"]
    assert stored == when.isoformat()                        # UTC ISO, the canonical value
    assert origin_unexpired(stored) is False
    assert mantle_unexpired({"expires_at": stored}) is False
    assert mantle_unexpired({"expires_at": past}) is False   # Mantle strips it too


def test_an_expiry_mantle_cannot_parse_is_already_past():
    from mantle.db.lattice_api import _unexpired as mantle_unexpired
    assert mantle_unexpired({"expires_at": "9999 never"}) is False
    assert mantle_unexpired({"expires_at": None}) is True


def test_the_chain_of_an_entry_stored_before_canonical_expiries_still_verifies(custody_client,
                                                                               world):
    """An entry stored with its raw expiry (before review 18) still verifies: the chain check
    reads a stored body as it was stored."""
    import json

    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityEntry
    from origin.services import authority_ledger
    with SessionLocal() as db:
        ok, detail = authority_ledger.verify_chain(db)
        assert ok, detail
        row = db.query(AuthorityEntry).order_by(AuthorityEntry.seq.desc()).first()
        body = json.loads(row.body)
        assert authority_ledger.canonical(
            authority_ledger.normalise(body, canonical_times=False)) == row.body


# -- F4: the manifest is read only from Origin's own folder ---------------------------------------

def test_the_manifest_is_read_only_from_origin_s_own_folder(tmp_path, monkeypatch):
    """`manifest.yml` beside Origin's database, in a folder this process owns at 0700, the file
    its own and writable by no one else; nothing is read from a default path or `DATA_PATH`."""
    import os

    from origin.services import manifest

    home = tmp_path / "origin"
    home.mkdir()
    (home / "manifest.yml").write_text("operator:\n  email: op@x.test\n")
    monkeypatch.setenv("ORIGIN_DB_PATH", str(home / "origin.db"))
    monkeypatch.setenv("DATA_PATH", str(tmp_path / "elsewhere"))
    assert manifest.manifest_path() == home / "manifest.yml"
    me = 1001
    ok_dir, ok_file = {"uid": me, "mode": 0o700}, {"uid": me, "mode": 0o600}
    monkeypatch.setattr(manifest, "_euid", lambda: me)
    monkeypatch.setattr(manifest, "_owner_mode",
                        lambda path: ok_dir if path == home else ok_file)
    assert manifest.load()["operator"]["email"] == "op@x.test"
    for d, f in (({"uid": me, "mode": 0o755}, ok_file), ({"uid": 0, "mode": 0o700}, ok_file),
                 (ok_dir, {"uid": me, "mode": 0o666}), (ok_dir, {"uid": 7, "mode": 0o600})):
        monkeypatch.setattr(manifest, "_owner_mode",
                            lambda path, d=d, f=f: d if path == home else f)
        assert manifest.load() == {}, (d, f)
    monkeypatch.setattr(manifest, "_euid", lambda: None)      # no process user to check against
    monkeypatch.setattr(manifest, "_owner_mode", lambda path: ok_dir if path == home else ok_file)
    assert manifest.load() == {}
    monkeypatch.delenv("ORIGIN_DB_PATH")
    assert manifest.manifest_path() is None
    assert os.getenv("DATA_PATH")                              # set, and never read


# -- info: custody needs the database folder Origin's own, 0700 ---------------------------------

def test_custody_needs_the_database_folder_origin_s_own_at_0700(monkeypatch):
    from origin.services import custody_plane
    monkeypatch.setattr(custody_plane, "TEST_OVERRIDE", None)
    monkeypatch.setenv("AGIENCE_PLANE", "production")
    good = {"euid": 1001, "no_new_privs": True, "keys_uid": 1001, "keys_mode": 0o700,
            "db_uid": 1001, "db_mode": 0o700}
    assert custody_plane.custody_refusal(evidence=good) is None
    for bad in ({"db_mode": 0o750}, {"db_uid": 0}, {"db_uid": None, "db_mode": None}):
        why = custody_plane.custody_refusal(evidence={**good, **bad})
        assert why and "ORIGIN_DB_PATH" in why, bad


# -- info: HELD_FOR_TESTS is a test-only seam ------------------------------------------------------

def test_no_grant_is_held_without_a_grantor_outside_tests():
    from origin.services import authority_ledger
    assert not hasattr(authority_ledger, "HELD_FOR_TESTS")


# -- review 19, info: no test code ships, and the test seam cannot exist in a wheel ---------------

def test_the_wheel_ships_no_tests():
    import tomllib
    from pathlib import Path
    root = Path(__file__).resolve().parents[3]
    find = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))[
        "tool"]["setuptools"]["packages"]["find"]
    assert "origin.tests*" in find.get("exclude", [])


def test_the_held_for_tests_seam_needs_the_source_tree(monkeypatch):
    """The seam is honoured only for the fixtures module of this source tree's own `tests`
    folder, which no wheel carries: a module planted under that name elsewhere is ignored."""
    import sys
    import types

    from origin.services import authority_ledger
    from origin.tests import authority_fixtures as real
    real.HELD_FOR_TESTS.add("g-seam")
    try:
        assert authority_ledger._held_for_tests("g-seam") is True
        planted = types.ModuleType("origin.tests.authority_fixtures")
        planted.HELD_FOR_TESTS = {"g-seam"}
        planted.__file__ = "/usr/lib/python3/site-packages/origin/tests/authority_fixtures.py"
        monkeypatch.setitem(sys.modules, "origin.tests.authority_fixtures", planted)
        assert authority_ledger._held_for_tests("g-seam") is False
    finally:
        real.HELD_FOR_TESTS.discard("g-seam")

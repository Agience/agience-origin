"""A pending email invite shows whom it went to, and when, to the people who may share the item
(BUG-069; John, 2026-11-14: store it at Origin, owner-only). A member is named by display name,
else verified address (BUG-078).

The ledger keeps only an invited address's digest. Origin's own `invite_addresses` row holds the
address and the sent time; it is never a ledger entry, so Mantle's feed never carries it. It is
listed only by `GET /auth/me/authority/grants`, which answers only someone who may share the item,
and only while the invite is pending; once the invite is claimed, declined, revoked or expired the
row is deleted.
"""
from __future__ import annotations

from origin.tests import test_an_invite_is_accepted_in_the_app_without_its_email as base

custody_client = base.custody_client
mailed = base.mailed
_hdr, _owner, _as, _invite, _listed = base._hdr, base._owner, base._as, base._invite, base._listed


def _stored(invite_id):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import InviteAddress
    with SessionLocal() as db:
        row = db.get(InviteAddress, invite_id)
        return row.email if row is not None else None


def _no_name(pid):
    import uuid
    from origin.db.session import SessionLocal
    from origin.models.person import Person
    with SessionLocal() as db:
        db.get(Person, uuid.UUID(pid)).name = ""
        db.commit()


def test_a_pending_invite_lists_its_address_and_sent_time(custody_client, mailed):
    c = custody_client
    ann = _owner(c)
    inv = _invite(c, ann, email="new.person@team.test")
    g = _listed(c, ann, inv)
    assert g["invited_address"] == "new.person@team.test"
    assert g["sent_at"]


def test_the_address_is_not_in_the_ledger_entry(custody_client, mailed):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityEntry
    c = custody_client
    ann = _owner(c)
    _invite(c, ann, email="new.person@team.test")
    with SessionLocal() as db:
        for e in db.query(AuthorityEntry).all():
            assert "new.person@team.test" not in str(getattr(e, "body", "") or "")
            assert "new.person@team.test" not in str(getattr(e, "entry", "") or "")


def test_someone_who_may_not_share_is_not_shown_the_list(custody_client, mailed):
    from origin.tests import authority_fixtures as af
    c = custody_client
    ann = _owner(c)
    _invite(c, ann)
    eve, _ = af.person("Eve", email="eve@team.test", verified=True)
    _as(c, eve)
    r = c.get("/auth/me/authority/grants", params={"resource_id": "W"}, headers=_hdr())
    assert r.status_code == 403


def test_a_revoked_invite_forgets_its_address(custody_client, mailed):
    c = custody_client
    ann = _owner(c)
    inv = _invite(c, ann)
    assert _stored(inv) == "bob@team.test"
    _as(c, ann)
    r = c.post(f"/auth/me/authority/grants/{inv}/revoke", headers=_hdr())
    assert r.status_code == 200, r.text
    assert _stored(inv) is None
    assert "invited_address" not in _listed(c, ann, inv)


def test_an_accepted_invite_forgets_its_address_and_names_the_member(custody_client, mailed):
    from origin.tests import authority_fixtures as af
    c = custody_client
    ann = _owner(c)
    bob, _ = af.person("", email="bob@team.test", verified=True)
    _no_name(bob)
    inv = _invite(c, ann)
    _as(c, bob)
    r = c.post(f"/auth/me/authority/invites/{inv}/accept", headers=_hdr())
    assert r.status_code == 200, r.text
    assert _stored(inv) is None
    _as(c, ann)
    grants = c.get("/auth/me/authority/grants", params={"resource_id": "W"},
                   headers=_hdr()).json()["grants"]
    member = next(g for g in grants if g["grantee_id"] == str(bob))
    # No display name: named by the verified address, never "Someone (<id>)" (BUG-078).
    assert member["grantee_name"] == "bob@team.test"


def test_a_declined_invite_forgets_its_address(custody_client, mailed):
    from origin.tests import authority_fixtures as af
    c = custody_client
    ann = _owner(c)
    bob, _ = af.person("Bob", email="bob@team.test", verified=True)
    inv = _invite(c, ann)
    _as(c, bob)
    assert c.post(f"/auth/me/authority/invites/{inv}/decline", headers=_hdr()).status_code == 200
    assert _stored(inv) is None


def test_the_migration_keeps_its_rows_across_a_rollback(tmp_path):
    """0033 builds the table the model declares, and a rollback (stamp back to 0032) followed by a
    roll-forward keeps every row: the addresses are not in the ledger, so none could be rebuilt."""
    from pathlib import Path

    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig

    import origin
    from origin.models.authority_ledger import InviteAddress

    db = tmp_path / "origin.db"
    here = Path(origin.__file__).resolve().parent
    cfg = AlembicConfig(str(here / "alembic.ini"))
    cfg.set_main_option("script_location", str(here / "alembic"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db}")
    command.upgrade(cfg, "head")
    engine = sa.create_engine(f"sqlite:///{db}")
    try:
        cols = {c["name"] for c in sa.inspect(engine).get_columns("invite_addresses")}
        assert cols == set(InviteAddress.__table__.columns.keys())
        with engine.begin() as cx:
            cx.execute(sa.text("INSERT INTO invite_addresses (grant_id, email, sent_at) "
                               "VALUES ('inv-1', 'bob@team.test', '2026-11-14 20:00:00')"))
        command.downgrade(cfg, "0032_authority_keys")
        command.stamp(cfg, "0032_authority_keys")
        command.upgrade(cfg, "head")
        with engine.connect() as cx:
            rows = cx.execute(sa.text("SELECT grant_id, email FROM invite_addresses")).all()
        assert [tuple(r) for r in rows] == [("inv-1", "bob@team.test")]
    finally:
        engine.dispose()

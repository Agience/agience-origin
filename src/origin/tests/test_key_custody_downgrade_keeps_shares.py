"""Migration 0009's downgrade refuses while Origin holds any key share.

Dropping `key_custody_shares` destroys share 2 of every split master key; with the escrow share
offline, that leaves each key one recovery away from gone. The way back is
`mantle.system.split_master_keys --combine`, which writes every key whole and leaves the table
safe to empty.
"""
from __future__ import annotations

import importlib.util
import pathlib

import pytest
import sqlalchemy as sa

_PATH = (pathlib.Path(__file__).resolve().parents[1] / "alembic" / "versions"
         / "0009_key_custody.py")


def _migration():
    spec = importlib.util.spec_from_file_location("m0009", _PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Op:
    def __init__(self, conn):
        self.conn, self.dropped = conn, []

    def get_bind(self):
        return self.conn

    def drop_table(self, name, **_kw):
        self.dropped.append(name)

    def drop_index(self, name, **_kw):
        self.dropped.append(name)


@pytest.fixture()
def conn():
    engine = sa.create_engine("sqlite://")
    with engine.connect() as c:
        c.execute(sa.text("CREATE TABLE key_custody_shares (principal_id TEXT PRIMARY KEY)"))
        yield c


def test_the_downgrade_refuses_while_a_share_is_stored(conn, monkeypatch):
    mod = _migration()
    conn.execute(sa.text("INSERT INTO key_custody_shares VALUES ('p-1')"))
    op = _Op(conn)
    monkeypatch.setattr(mod, "op", op)
    with pytest.raises(RuntimeError, match="split_master_keys --combine"):
        mod.downgrade()
    assert op.dropped == []


def test_the_downgrade_drops_an_empty_table(conn, monkeypatch):
    mod = _migration()
    op = _Op(conn)
    monkeypatch.setattr(mod, "op", op)
    mod.downgrade()
    assert "key_custody_shares" in op.dropped

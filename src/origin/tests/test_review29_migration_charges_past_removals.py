"""Migration 0029 charges each past removal of a creation edge to the root its source sat under at
that entry, the ledger walked as `replay` walks it, so a part removed before the migration refuses
the root's master key as one removed after it (reviews 29 and 31)."""
from __future__ import annotations

import contextlib
import importlib.util
import json
import pathlib

import sqlalchemy as sa

_PATH = (pathlib.Path(__file__).resolve().parents[1] / "alembic" / "versions"
         / "0029_root_part_removed.py")


def _migration():
    spec = importlib.util.spec_from_file_location("m0029", _PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Op:
    def __init__(self, conn):
        self.conn = conn

    def get_bind(self):
        return self.conn

    @contextlib.contextmanager
    def batch_alter_table(self, name):
        conn = self.conn

        class _Batch:
            def add_column(self, col):
                conn.execute(sa.text(f"ALTER TABLE {name} ADD COLUMN {col.name} INTEGER"))
        yield _Batch()


def test_a_past_removal_is_charged_to_its_root(monkeypatch):
    engine = sa.create_engine("sqlite://")
    with engine.connect() as c:
        c.execute(sa.text("CREATE TABLE authority_nodes (node_id TEXT PRIMARY KEY)"))
        c.execute(sa.text("CREATE TABLE authority_edges (src TEXT, dst TEXT, origin BOOLEAN)"))
        c.execute(sa.text("CREATE TABLE authority_ledger (seq INTEGER, kind TEXT, body TEXT, "
                          "bootstrap BOOLEAN, compensates INTEGER)"))
        for n in ("R", "C", "X", "S"):
            c.execute(sa.text("INSERT INTO authority_nodes VALUES (:n)"), {"n": n})
        c.execute(sa.text("INSERT INTO authority_edges VALUES ('R', 'C', 1)"))       # still there
        entries = [(1, "root", {"principal_id": "R", "root_id": "R"}),
                   (2, "root", {"principal_id": "S", "root_id": "S"}),
                   (3, "edge.add", {"src": "R", "dst": "C", "origin": True}),
                   (4, "edge.add", {"src": "C", "dst": "X", "origin": True}),
                   (5, "edge.add", {"src": "S", "dst": "R", "origin": False}),     # secondary
                   (6, "edge.remove", {"src": "C", "dst": "X"}),                   # a part of R
                   (7, "edge.remove", {"src": "S", "dst": "R"})]                   # no part
        for seq, kind, body in entries:
            c.execute(sa.text("INSERT INTO authority_ledger VALUES (:s, :k, :b, 0, NULL)"),
                      {"s": seq, "k": kind, "b": json.dumps({"kind": kind, **body})})
        mod = _migration()
        monkeypatch.setattr(mod, "op", _Op(c))
        mod.upgrade()
        got = dict(c.execute(sa.text(
            "SELECT node_id, part_removed_seq FROM authority_nodes")).fetchall())
    assert got == {"R": 6, "C": None, "X": None, "S": None}

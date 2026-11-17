"""The request, note and spend tables are named for what they hold. A node made under their first
names has them renamed, rows and indexes kept; a rollback renames them back."""
import importlib
from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config as AlembicConfig

import origin
from origin.models.decision_note import DecisionNote, DecisionRequest, DecisionSpend

MODELS = (DecisionRequest, DecisionNote, DecisionSpend)


def _cfg(db):
    here = Path(origin.__file__).resolve().parent
    cfg = AlembicConfig(str(here / "alembic.ini"))
    cfg.set_main_option("script_location", str(here / "alembic"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db}")
    return cfg


def _indexes(engine, table):
    return {ix["name"] for ix in sa.inspect(engine).get_indexes(table)}


def test_the_models_name_the_tables_for_what_they_hold():
    assert [m.__tablename__ for m in MODELS] == [
        "decision_requests", "decision_notes", "decision_spends"]


def test_a_node_made_under_the_first_names_is_renamed_with_its_rows(tmp_path):
    first = dict(importlib.import_module(
        "origin.alembic.versions.0037_decision_tables")._TABLES)
    db = tmp_path / "origin.db"
    cfg = _cfg(db)
    command.upgrade(cfg, "head")
    engine = sa.create_engine(f"sqlite:///{db}")
    try:
        with engine.begin() as cx:
            cx.execute(sa.text("INSERT INTO decision_spends (jti, action, id, req, spent_time) "
                               "VALUES ('j1', 'sha256:a', 's1', 'r1', '2026-11-17 15:00:00')"))
        command.downgrade(cfg, "0036_agent_approvals")
        names = set(sa.inspect(engine).get_table_names())
        assert set(first) <= names and not {m.__tablename__ for m in MODELS} & names
        command.upgrade(cfg, "head")
        names = set(sa.inspect(engine).get_table_names())
        assert not set(first) & names
        with engine.connect() as cx:
            rows = cx.execute(sa.text("SELECT jti, id FROM decision_spends")).all()
        assert [tuple(r) for r in rows] == [("j1", "s1")]
        for m in MODELS:
            assert _indexes(engine, m.__tablename__) == {ix.name for ix in m.__table__.indexes}
    finally:
        engine.dispose()

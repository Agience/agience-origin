"""The request, note and spend tables are named for what they hold, and a node at head holds them
under those names with the models' indexes."""
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


def test_a_node_at_head_holds_the_tables_and_indexes_the_models_name(tmp_path):
    db = tmp_path / "origin.db"
    command.upgrade(_cfg(db), "head")
    engine = sa.create_engine(f"sqlite:///{db}")
    try:
        names = set(sa.inspect(engine).get_table_names())
        for m in MODELS:
            assert m.__tablename__ in names
            assert _indexes(engine, m.__tablename__) == {ix.name for ix in m.__table__.indexes}
    finally:
        engine.dispose()

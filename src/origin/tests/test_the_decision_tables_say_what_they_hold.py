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


FIRST = {"decision_requests": "chair_requests", "decision_notes": "chair_notes",
         "decision_spends": "chair_spends"}


def _ix(engine, prefix):
    with engine.connect() as cx:
        return sorted(r[0] for r in cx.execute(sa.text(
            "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE :p"), {"p": prefix + "%"}))


def _first_names(engine):
    """The shape of a node made under the first names: each table and its `ix_` indexes."""
    with engine.begin() as cx:
        for m in MODELS:
            new, old = m.__tablename__, FIRST[m.__tablename__]
            ixs = [ix for ix in sa.inspect(cx).get_indexes(new) if ix["name"].startswith("ix_")]
            for ix in ixs:
                cx.execute(sa.text(f"DROP INDEX {ix['name']}"))
            cx.execute(sa.text(f"ALTER TABLE {new} RENAME TO {old}"))
            for ix in ixs:
                name = ix["name"].replace(f"ix_{new}_", f"ix_{old}_", 1)
                cols = ", ".join(ix["column_names"])
                cx.execute(sa.text(f"CREATE INDEX {name} ON {old} ({cols})"))


def _spend(engine, table):
    with engine.begin() as cx:
        cx.execute(sa.text(f"INSERT INTO {table} (jti, action, id, req, spent_time) "
                           "VALUES ('j1', 'sha256:a', 's1', 'r1', '2026-11-17 15:00:00')"))


def _spends(engine, table):
    with engine.connect() as cx:
        return [tuple(r) for r in cx.execute(sa.text(f"SELECT jti, id FROM {table}")).all()]


def _at_head(engine):
    names = set(sa.inspect(engine).get_table_names())
    assert not set(FIRST.values()) & names
    assert _ix(engine, "ix_chair_") == []
    for m in MODELS:
        assert m.__tablename__ in names
        assert _indexes(engine, m.__tablename__) == {ix.name for ix in m.__table__.indexes}


def test_a_node_at_0035_under_the_first_names_is_renamed_and_renamed_back(tmp_path):
    db = tmp_path / "origin.db"
    cfg = _cfg(db)
    command.upgrade(cfg, "0035_request_resource")
    engine = sa.create_engine(f"sqlite:///{db}")
    try:
        _first_names(engine)
        _spend(engine, "chair_spends")
        assert _ix(engine, "ix_chair_")
        command.upgrade(cfg, "head")
        _at_head(engine)
        assert _spends(engine, "decision_spends") == [("j1", "s1")]
        command.downgrade(cfg, "0036_agent_approvals")
        names = set(sa.inspect(engine).get_table_names())
        assert set(FIRST.values()) <= names and not set(FIRST) & names
        assert "alembic_0037_renamed" not in names
        assert _ix(engine, "ix_decision_") == []
        assert _spends(engine, "chair_spends") == [("j1", "s1")]
        command.upgrade(cfg, "head")
        _at_head(engine)
    finally:
        engine.dispose()


def test_a_node_at_0037_with_the_names_upgrades_and_downgrades_unchanged(tmp_path):
    db = tmp_path / "origin.db"
    cfg = _cfg(db)
    command.upgrade(cfg, "0036_agent_approvals")
    command.stamp(cfg, "0037_decision_tables")
    engine = sa.create_engine(f"sqlite:///{db}")
    try:
        _spend(engine, "decision_spends")
        command.upgrade(cfg, "head")
        _at_head(engine)
        command.downgrade(cfg, "0036_agent_approvals")
        _at_head(engine)
        assert _spends(engine, "decision_spends") == [("j1", "s1")]
    finally:
        engine.dispose()


def test_a_fresh_node_upgrades_and_downgrades_unchanged(tmp_path):
    db = tmp_path / "origin.db"
    cfg = _cfg(db)
    command.upgrade(cfg, "head")
    engine = sa.create_engine(f"sqlite:///{db}")
    try:
        _at_head(engine)
        assert "alembic_0037_renamed" not in sa.inspect(engine).get_table_names()
        command.downgrade(cfg, "0036_agent_approvals")
        _at_head(engine)
    finally:
        engine.dispose()

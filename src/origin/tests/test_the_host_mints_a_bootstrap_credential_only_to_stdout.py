"""On Origin's host, `python -m origin.scripts.authority_bootstrap` mints the operator's bootstrap
credential and prints it alone on stdout, never in a log or on stderr; it lives at most thirty
minutes, needs an operator and a database, `--close` withdraws it, and `--count` reads the
replica's grant, root and edge counts.

Each test runs against the real Origin app (`custody_client`), calling the script's `main`.
"""
from __future__ import annotations

import logging

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client


def _run(capfd, *argv):
    from origin.scripts import authority_bootstrap

    code = authority_bootstrap.main(list(argv))
    out, err = capfd.readouterr()
    return code, out, err


def _verify(token):
    from origin.db.session import SessionLocal
    from origin.services import authority_ledger

    with SessionLocal() as db:
        return authority_ledger.verify_bootstrap_credential(db, token, af.OPERATOR)


def test_the_credential_is_printed_alone_and_verifies_for_the_operator(custody_client, monkeypatch,
                                                                       capfd, caplog):
    af.operator(monkeypatch)
    caplog.set_level(logging.DEBUG)
    code, out, err = _run(capfd)
    assert code == 0
    lines = out.splitlines()
    assert len(lines) == 1 and out == lines[0] + "\n"
    token = lines[0]
    assert _verify(token) == af.OPERATOR
    assert token not in err
    assert token not in caplog.text
    assert all(token not in r.getMessage() for r in caplog.records)


def test_the_lifetime_is_thirty_minutes_at_most(custody_client, monkeypatch, capfd):
    af.operator(monkeypatch)
    for minutes in ("31", "0"):
        code, out, err = _run(capfd, "--minutes", minutes)
        assert code != 0 and out == "" and "--minutes" in err
    code, out, _ = _run(capfd, "--minutes", "30")
    assert code == 0 and _verify(out.strip()) == af.OPERATOR


def test_no_operator_is_a_non_zero_exit(custody_client, monkeypatch, capfd):
    from origin.services.platform_settings_service import settings as platform_settings

    real_get = platform_settings.get
    monkeypatch.setattr(platform_settings, "get", lambda k, *a, **kw:
                        None if k == "platform.operator_id" else real_get(k, *a, **kw))
    code, out, err = _run(capfd)
    assert code != 0 and out == "" and "operator" in err


def test_no_database_is_a_non_zero_exit(custody_client, monkeypatch, capfd):
    import origin.db.session as session

    def _no_db():
        raise RuntimeError("no database")

    af.operator(monkeypatch)
    monkeypatch.setattr(session, "SessionLocal", _no_db)
    code, out, err = _run(capfd)
    assert code != 0 and out == "" and "no database" in err


def test_close_withdraws_the_window(custody_client, monkeypatch, capfd):
    from origin.services.authority_ledger import EntryRefused

    af.operator(monkeypatch)
    _, out, _ = _run(capfd)
    token = out.strip()
    assert _verify(token) == af.OPERATOR
    code, out, _ = _run(capfd, "--close")
    assert code == 0 and out == "bootstrap closed: 1 window(s)\n"
    with pytest.raises(EntryRefused):
        _verify(token)


def test_count_reports_the_replica_s_counts(custody_client, monkeypatch, capfd):
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityEdge, AuthorityGrant, AuthorityRoot

    af.operator(monkeypatch)
    code, out, _ = _run(capfd, "--count")
    assert code == 0 and out == "grants=0 roots=0 edges=0\n"
    _, out, _ = _run(capfd)
    boot = out.strip()
    af.ok(af.submit(custody_client, boot, af.root("B"), bootstrap=True))
    af.ok(af.submit(custody_client, boot, af.grant("g-b", af.OPERATOR, "B"), bootstrap=True))
    af.ok(af.submit(custody_client, boot, af.edge("B", "m-1"), bootstrap=True))
    with SessionLocal() as db:
        want = (f"grants={db.query(AuthorityGrant).count()} "
                f"roots={db.query(AuthorityRoot).count()} "
                f"edges={db.query(AuthorityEdge).count()}\n")
    code, out, _ = _run(capfd, "--count")
    assert code == 0 and out == want
    assert out != "grants=0 roots=0 edges=0\n"


def test_a_process_of_its_own_builds_the_engine(tmp_path):
    """The release tool runs the script as a fresh process, where Origin's startup has not built
    the engine; the script builds it from the same settings and reads the database."""
    import os
    import subprocess
    import sys

    from sqlalchemy import create_engine

    import origin.models  # noqa: F401 — registers every table on the metadata
    from origin.db.base import Base

    url = f"sqlite:///{(tmp_path / 'origin.db').as_posix()}"
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    engine.dispose()
    env = {**os.environ, "DATABASE_URL": url}
    run = subprocess.run([sys.executable, "-m", "origin.scripts.authority_bootstrap", "--count"],
                         capture_output=True, text=True, env=env, timeout=120)
    assert run.returncode == 0, run.stderr
    assert run.stdout == "grants=0 roots=0 edges=0\n"

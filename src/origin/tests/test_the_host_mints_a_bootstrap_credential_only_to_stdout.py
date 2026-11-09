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


def _own_process(tmp_path, keys_dir, *argv):
    """The script as the release tool runs it: a fresh process where Origin's startup has not run,
    against a database file that holds Origin's tables and an operator, made at the first call."""
    import os
    import subprocess
    import sys

    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    import origin.models  # noqa: F401 — registers every table on the metadata
    from origin.db.base import Base
    from origin.models.platform_setting import PlatformSetting

    path = tmp_path / "origin.db"
    url = f"sqlite:///{path.as_posix()}"
    if not path.exists():
        engine = create_engine(url)
        Base.metadata.create_all(engine)
        with Session(engine) as db:
            db.add(PlatformSetting(key="platform.operator_id", value=af.OPERATOR, is_secret=False))
            db.commit()
        engine.dispose()
    env = {k: v for k, v in os.environ.items() if not k.startswith("ORIGIN_SKIP")}
    env.update({"DATABASE_URL": url, "KEYS_DIR": str(keys_dir), "AGIENCE_NO_DOTENV": "1"})
    return subprocess.run([sys.executable, "-m", "origin.scripts.authority_bootstrap", *argv],
                          capture_output=True, text=True, env=env, timeout=120)


def test_a_process_of_its_own_counts_mints_and_closes(tmp_path, jwt_keypair):
    """Run as its own process, the script builds what Origin's startup builds (keys, identity,
    engine): it reads the replica, mints a credential that is one line on stdout, and closes."""
    run = _own_process(tmp_path, jwt_keypair, "--count")
    assert run.returncode == 0, run.stderr
    assert run.stdout == "grants=0 roots=0 edges=0\n"
    run = _own_process(tmp_path, jwt_keypair)
    assert run.returncode == 0, run.stderr
    lines = run.stdout.splitlines()
    assert len(lines) == 1 and lines[0].count(".") == 2, "one line: the credential, a JWT"
    assert lines[0] not in run.stderr
    run = _own_process(tmp_path, jwt_keypair, "--close")
    assert run.returncode == 0, run.stderr
    assert run.stdout == "bootstrap closed: 1 window(s)\n"


class _Answer:
    def __init__(self, r):
        self.status, self._body = r.status_code, r.content

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _through(client, monkeypatch):
    """The probe's HTTP call, delivered to the app under test instead of a network."""
    import io
    import urllib.error
    import urllib.request

    def urlopen(req, timeout=None):
        path = req.full_url.split("://", 1)[1]
        r = client.get(path[path.index("/"):], headers=dict(req.header_items()))
        if r.status_code >= 400:
            raise urllib.error.HTTPError(req.full_url, r.status_code, "refused", {}, io.BytesIO(r.content))
        return _Answer(r)
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)


def test_the_owner_probe_reads_the_grants_route_as_an_owner_and_ends_its_session(custody_client,
                                                                                    monkeypatch, capfd):
    from origin import config
    from origin.db.session import SessionLocal
    from origin.models.origin_session import OriginSession

    monkeypatch.setattr(config, "APP_URI", "https://app.example.com")   # the web app it speaks as
    af.operator(monkeypatch)
    owner, _ = af.person("owner")
    _, out, _ = _run(capfd)
    boot = out.strip()
    af.ok(af.submit(custody_client, boot, af.root("B"), bootstrap=True))
    af.ok(af.submit(custody_client, boot, af.grant("g-o", owner, "B", ("read", "share")), bootstrap=True))
    _through(custody_client, monkeypatch)
    code, out, err = _run(capfd, "--probe-owner", "http://127.0.0.1:8180")
    assert code == 0, out + err
    assert out == "owner probe: 200 grants=1\n"
    with SessionLocal() as db:
        mine = db.query(OriginSession).filter(OriginSession.person_id == owner).all()
        assert mine and all(s.revoked_time is not None for s in mine), "the probe's session is ended"


def test_the_owner_probe_fails_when_no_one_may_share(custody_client, monkeypatch, capfd):
    af.operator(monkeypatch)
    _through(custody_client, monkeypatch)
    code, out, err = _run(capfd, "--probe-owner", "http://127.0.0.1:8180")
    assert code == 1 and out == "" and "no active account" in err


def _stdin(monkeypatch, *ids):
    import io
    import sys
    monkeypatch.setattr(sys, "stdin", io.StringIO("".join(f"{i}\n" for i in ids)))


def test_unseen_prints_only_the_ids_no_ordinary_entry_brought_into_being(custody_client, monkeypatch, capfd):
    """2026-11-09, the RC's seed rehearsal: once accounts are made with their authority journaled,
    Origin's replica holds ids an ordinary entry made, and a bootstrap that restates one is refused.
    The seed states only the ids Origin says it has not seen."""
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityNode

    af.operator(monkeypatch)
    with SessionLocal() as db:
        db.add(AuthorityNode(node_id="New", created_by="someone", seq=1))
        db.add(AuthorityNode(node_id="Boot", created_by="", seq=2))     # stated by a bootstrap
        db.commit()
    _stdin(monkeypatch, "New", "Old", "Boot", "Old", "")
    code, out, _ = _run(capfd, "--unseen")
    assert code == 0 and out == "Boot\nOld\n"


def test_a_listed_window_states_only_the_ids_on_stdin(custody_client, monkeypatch, capfd):
    af.operator(monkeypatch)
    _stdin(monkeypatch, "Old", "g-old")
    code, out, err = _run(capfd, "--ids-stdin")
    assert code == 0, err
    boot = out.strip()
    af.ok(af.submit(custody_client, boot, af.root("Old"), bootstrap=True))
    af.ok(af.submit(custody_client, boot, af.grant("g-old", "someone", "Old"), bootstrap=True))
    r = af.submit(custody_client, boot, af.root("Other"), bootstrap=True)
    assert r.status_code == 403 and "lists" in r.json()["detail"]


def test_a_listed_window_with_no_ids_is_not_opened(custody_client, monkeypatch, capfd):
    af.operator(monkeypatch)
    _stdin(monkeypatch)
    code, out, err = _run(capfd, "--ids-stdin")
    assert code == 1 and out == "" and "no ids" in err

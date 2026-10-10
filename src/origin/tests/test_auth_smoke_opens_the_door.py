"""`node/auth_smoke.py`'s full register -> login path, run against the real app.

The smoke is the check an operator runs against a local node; if its requests do not match what
the password routes accept, it reports a broken login on a healthy node. Its HTTP helpers are
routed into a `TestClient` so the bodies it sends are judged by the routes themselves.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

_SMOKE = Path(__file__).resolve().parents[3] / "node" / "auth_smoke.py"


@pytest.fixture
def smoke(origin_app, monkeypatch):
    from origin import config

    monkeypatch.setattr(config, "EMAIL_VERIFICATION_ENABLED", False)
    spec = importlib.util.spec_from_file_location("auth_smoke_under_test", _SMOKE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    with TestClient(origin_app) as client:
        from origin.db.base import Base
        from origin.db.session import get_engine

        Base.metadata.create_all(get_engine())

        def _path(url: str) -> str:
            parts = urlsplit(url)
            return parts.path + (("?" + parts.query) if parts.query else "")

        def _get(url, *, allow_redirect=True, timeout=10.0):
            r = client.get(_path(url), follow_redirects=allow_redirect)
            return r.status_code, dict(r.headers), r.content

        def _post(url, data, timeout=10.0):
            r = client.post(_path(url), data=data)
            return r.status_code, r.content

        def _post_json(url, data, timeout=10.0):
            r = client.post(_path(url), json=data)
            return r.status_code, r.content

        monkeypatch.setattr(mod, "_get", _get)
        monkeypatch.setattr(mod, "_post", _post)
        monkeypatch.setattr(mod, "_post_json", _post_json, raising=False)
        yield mod


def test_the_full_flow_registers_and_signs_in(smoke, capsys):
    smoke.run("http://testserver", allow_write=True)
    lines = [ln for ln in capsys.readouterr().out.splitlines() if "door-opens (full)" in ln]
    assert len(lines) == 1, lines
    assert " PASS " in lines[0], lines[0]

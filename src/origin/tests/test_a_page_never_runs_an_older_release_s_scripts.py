"""A page never runs scripts a browser kept from an older release.

2026-11-09, after the release: Origin served `/web/app.js` and the rest with no `Cache-Control` and
unversioned names, so a browser kept the previous release's scripts (fresh by its own heuristic)
against the new pages, and its sign-in looped back to `/login`. Now `/web/*` is answered with
`Cache-Control: no-cache` (revalidated by ETag before use), the pages too, and each page names its
scripts and stylesheets by their content (`?v=<sha256 prefix>`), so a stale copy is never chosen.
"""
from __future__ import annotations

import hashlib
import re

import pytest

PAGES = ["/login", "/reset-password", "/verify-email", "/logout"]


@pytest.fixture
def client(origin_app):
    from fastapi.testclient import TestClient

    with TestClient(origin_app) as c:
        yield c


def test_web_assets_are_revalidated(client):
    for asset in ("/web/app.js", "/web/index-page.js", "/web/app.css", "/web/bg.js"):
        r = client.get(asset)
        assert r.status_code == 200, asset
        assert r.headers.get("cache-control") == "no-cache", (asset, r.headers.get("cache-control"))
        assert r.headers.get("etag"), asset


@pytest.mark.parametrize("path", PAGES)
def test_a_page_is_revalidated_and_names_its_scripts_by_content(client, path):
    from origin import main

    r = client.get(path)
    assert r.status_code == 200, path
    assert r.headers.get("cache-control") == "no-cache"
    refs = re.findall(r'(?:src|href)="/web/([\w.-]+\.(?:js|css))(\?v=([0-9a-f]{12}))?"', r.text)
    assert refs, "the page references its scripts"
    for name, query, version in refs:
        assert query, f"{name} is referenced without its version"
        want = hashlib.sha256((main._WEB_DIR / name).read_bytes()).hexdigest()[:12]
        assert version == want, name


def test_a_changed_script_gets_a_new_name(client, tmp_path, monkeypatch):
    from origin import main

    web = tmp_path / "web"
    web.mkdir()
    (web / "app.js").write_text("one")
    page = web / "p.html"
    page.write_text('<script src="/web/app.js"></script>')
    monkeypatch.setattr(main, "_WEB_DIR", web)
    first = main._versioned_page(page)
    (web / "app.js").write_text("two")
    assert main._versioned_page(page) != first

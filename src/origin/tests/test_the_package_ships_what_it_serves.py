"""The runtime assets Origin serves are inside the package that ships them.

## The failure this exists for

A path that climbs out of the package — `Path(__file__).parent.parent.parent / "web"` — is
`<repo>/web` in a checkout, which exists, so every page handler works and the suite is green. An
installed distribution has no repository above it, so the same expression resolves to a directory
nothing creates and every page route answers 500 there.

An assertion that imports `_WEB_DIR` and checks the pages under it exist cannot see that: it is a
true statement about the checkout it runs in, and the deployment it describes is a different one.
Every path-derived assertion has that property, which is why the checks below are not more of them.
They compare the resolved location against the package boundary, and the assets against what
`[tool.setuptools.package-data]` declares.

## Why the declaration and not a built wheel

Building a wheel here would need a build backend in the test environment and several seconds per
run, to catch the same defect one step later. The declaration is what decides the wheel's contents,
so reading it against the tree catches an asset added and not declared — which is the mistake that
actually happens.

The real artifact is checked where building one is free: `.github/workflows/build.yml`'s `wheel`
job installs the built distribution into a bare virtualenv, starts it outside the checkout, and
requires every published route to answer.
"""
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

import pytest

from origin import main

#: `<repo>/src/origin/tests/` → parents[3] is the repo root. Asserted rather than trusted: a wrong
#: depth here would read some other tree's pyproject and report on it confidently.
_REPO = Path(__file__).resolve().parents[3]
assert (_REPO / "pyproject.toml").is_file(), (
    "path depth is wrong: parents[3] should be the agience-origin repo root, got %s" % _REPO)

#: Where the `origin` package sits in this checkout — asked of the module, never spelled out, so
#: moving the package fails the assertions that are actually about the package.
_PKG = Path(main.__file__).resolve().parent


def _declared_globs() -> list[str]:
    """The `package-data` patterns for the `origin` package, read from `pyproject.toml`."""
    with (_REPO / "pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)["tool"]["setuptools"]["package-data"]["origin"]


def _declared_files() -> set[Path]:
    """Every file under the package that a declared pattern matches."""
    declared: set[Path] = set()
    for pattern in _declared_globs():
        matched = set(_PKG.glob(pattern))
        assert matched, (
            f"package-data pattern {pattern!r} matches nothing under {_PKG}. A pattern that "
            "matches nothing reads as a claim that such files exist — remove it or fix it.")
        declared |= matched
    return declared


#: Every asset Origin loads at runtime from a path derived from its own module location, with the
#: module that loads it. Derived from the loading module rather than written out, so the reader of
#: a failure is sent to the code that does the loading.
_RUNTIME_ASSETS = (
    (main._WEB_DIR, "origin/main.py serves it as Path(__file__).parent / 'web'",
     "/, /login, /account, /reset-password and /verify-email"),
    (_PKG / "uvicorn_log_config.json",
     "origin/logging_utils.py reads it as Path(__file__).parent / 'uvicorn_log_config.json'",
     "log formatting on every uvicorn startup and access line"),
)


@pytest.mark.parametrize("asset,loaded_by,breaks", _RUNTIME_ASSETS,
                         ids=[a[0].name for a in _RUNTIME_ASSETS])
def test_a_runtime_asset_lives_inside_the_package(asset: Path, loaded_by: str,
                                                  breaks: str) -> None:
    """Each asset exists in the tree first, then is shown to be under the package.

    Order matters: without the existence check, deleting the asset would fail this with a message
    about packaging for a problem that is not in the packaging."""
    assert asset.exists(), (
        f"{asset} is not in the source tree, so its absence from an install is not a packaging "
        f"finding — {loaded_by}")

    resolved = asset.resolve()
    assert _PKG == resolved or _PKG in resolved.parents, (
        f"{asset} is outside the origin package at {_PKG}, so an installed distribution does not "
        f"contain it. {loaded_by}, and without it {breaks} fail — in an install only, never here. "
        f"Move it under src/origin/.")


def test_the_web_surface_resolves_inside_the_package() -> None:
    """The same fact stated the other way round, because this is the form a reader checks by eye.

    `_WEB_DIR` being under the `origin` package is what makes one expression correct in both places
    the code runs: `src/origin/web` in a checkout and `<site-packages>/origin/web` in an install. A
    `_WEB_DIR` that climbs OUT of the package is resolving against the repository layout, which only
    one of those two has.
    """
    web = main._WEB_DIR.resolve()
    assert _PKG == web.parent, (
        f"_WEB_DIR is {web}, which is not directly inside the origin package at {_PKG}. A path "
        "that climbs above the package resolves against the repo checkout — an install has no "
        "repo, so the pages 500 there while this suite stays green.")
    assert web.is_dir(), f"{web} is not a directory"


def test_the_pages_the_surface_serves_are_all_present() -> None:
    """Every filename `main.py` passes to `_page`, checked as a set.

    Read out of the source rather than listed here: a new page added to `main.py` and forgotten in
    the tree would otherwise be invisible until a user hit it."""
    source = Path(main.__file__).resolve().read_text(encoding="utf-8")
    served = sorted({
        chunk.split('"')[0]
        for chunk in source.split('_page("')[1:]
    })
    assert served, "no _page(\"...\") calls found in main.py — this test is reading the wrong file"
    missing = [name for name in served if not (main._WEB_DIR / name).is_file()]
    assert not missing, (
        f"main.py serves {missing} but no such file is under {main._WEB_DIR}")


def test_a_missing_page_is_503_and_not_500(tmp_path, monkeypatch) -> None:
    """The answer for a deployment with no surface, given at the route rather than by the crash.

    `FileResponse` on an absent path raises while the response is being sent, which the app's
    global handler turns into 500 "Internal Server Error" — a sentence about a bug, for a condition
    that is not one. 503 says the address is right and this instance cannot serve it, which is what
    is true and what a load balancer can act on. 404 would say the address is wrong; `/login` is a
    published part of Origin's contract and other services build sign-in links to it.
    """
    from fastapi.testclient import TestClient

    monkeypatch.setattr(main, "_WEB_DIR", tmp_path)   # a real, empty directory
    client = TestClient(main.app, raise_server_exceptions=False)

    for path in ("/", "/login", "/account", "/reset-password", "/verify-email"):
        resp = client.get(path)
        assert resp.status_code == 503, (
            f"{path} answered {resp.status_code} with no surface deployed; 500 means the "
            "FileResponse raised on send and the generic handler caught it")
        assert resp.json()["error"] == "account_surface_missing"
        assert resp.headers.get("cache-control") == "no-store", (
            f"{path}'s 503 is cacheable — a proxy would keep serving it after the surface is fixed")


def test_the_packaging_declares_the_whole_surface() -> None:
    """`web/` is not a package — no `__init__.py`, so `packages.find` never sees it and only
    `[tool.setuptools.package-data]` puts it in a distribution. What this catches is an asset added
    to `src/origin/web/` with the declaration not updated: the install works and the asset is just
    absent, which is silent until someone loads the page.
    """
    declared = _declared_files()
    present = {p for p in (_PKG / "web").iterdir() if p.is_file()}
    undeclared = sorted(p.name for p in present - declared)
    assert not undeclared, (
        f"these files are in src/origin/web/ but no [tool.setuptools.package-data] pattern matches "
        f"them: {undeclared}. They are present in a checkout and absent from an installed "
        "distribution, so the surface has holes in it wherever Origin is actually installed.")


#: What `main._run_migrations` needs beside the package, as (path relative to the package, why).
#: `alembic/versions/` is not listed: it carries an `__init__.py`, so `packages.find` ships the
#: revisions as an ordinary subpackage and no declaration is involved.
_MIGRATION_FILES = (
    ("alembic.ini", "AlembicConfig reads it, and alembic/env.py hands the same path to fileConfig, "
                    "which raises FileNotFoundError on a missing file."),
    ("alembic/script.py.mako", "It is the template `alembic revision` renders a new migration from."),
)


@pytest.mark.parametrize("relpath,why", _MIGRATION_FILES, ids=[r for r, _ in _MIGRATION_FILES])
def test_an_install_can_run_its_own_migrations(relpath: str, why: str) -> None:
    """`main.lifespan` calls `_run_migrations()` on every boot, so a distribution that omits the
    migration config installs cleanly and then fails the first time it is started — the failure
    lands at startup, not at install, which is where it is most expensive to read.
    """
    asset = _PKG / relpath
    assert asset.is_file(), f"{relpath} is not in the source tree. {why}"

    assert asset in _declared_files(), (
        f"{relpath} is not matched by any [tool.setuptools.package-data] pattern, so it is present "
        f"in a checkout and absent from an install. {why} "
        f"Declared patterns: {_declared_globs()}")


def test_the_runtime_dependencies_are_declared() -> None:
    """A distribution that declares no dependencies installs importable and without a web framework.

    The pins live in `requirements.txt` and `pyproject.toml` reads that same file, so there is one
    list rather than two that can drift. What this pins is that the reading is actually declared —
    dropping it would leave `pip install agience-origin` resolving nothing, and the failure would
    land on whoever tried to start it.
    """
    with (_REPO / "pyproject.toml").open("rb") as fh:
        project = tomllib.load(fh)["project"]

    assert "dependencies" in project.get("dynamic", []), (
        "pyproject no longer declares dependencies dynamically; an installed Origin would resolve "
        "none of its pins")

    requirements = (_REPO / "requirements.txt").read_text(encoding="utf-8")
    named = [line.split("=")[0].split(">")[0].split("[")[0].strip()
             for line in requirements.splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    for essential in ("fastapi", "uvicorn", "sqlalchemy", "alembic"):
        assert essential in named, (
            f"{essential} is not in requirements.txt, which is what pyproject reads for "
            f"[project.dependencies] — an install could not start. Found: {sorted(named)}")


def test_this_file_is_not_asserting_against_an_installed_copy() -> None:
    """The last control. If the suite imported `origin` from site-packages rather than this
    checkout, every assertion above would be a true statement about somebody else's tree."""
    assert _REPO in _PKG.parents, (
        f"origin was imported from {_PKG}, outside this checkout — the suite is reading an "
        f"installed copy, so nothing here is evidence about {_REPO}. sys.path[0]={sys.path[0]!r}")

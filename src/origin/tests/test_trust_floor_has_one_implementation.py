"""The trust floor has a single implementation. `origin.*` stays a re-export of `prism.trust.*`.

What must hold, and why each is checked rather than assumed:

  identity   `origin.X is prism.trust.X` — the same module object, not merely equal contents. This
             is the property a star-import shim would quietly fail: it binds copies of the names, so
             a consumer's test fixture writing `service_identity._loaded` or
             `authority_trust._manifest` through the `origin.` name would land on the shim while the
             readers kept using prism's globals. Nothing raises; the fixture just stops taking effect.
  surface    every name the consumers import still resolves. Consumer repositories import these
             names from `origin.*`, and they must not have to care which module answers.
  no cycle   prism never imports origin. The direction is what makes this legal at all — and
             `prism.trust` is Apache-2.0 while origin is AGPL, so permissive-into-copyleft is the
             only compatible direction. A cycle would also make the shim recursive.
  thin       the shims stay shims. A 300-line `origin/key_manager.py` is the fork returning, whether
             or not it agrees with prism on the day it lands.
"""
from __future__ import annotations

import ast
import importlib
import pathlib

import pytest

MODULES = ["authority_trust", "key_manager", "service_identity"]

ORIGIN_SRC = pathlib.Path(__file__).resolve().parents[1]      # …/src/origin


@pytest.mark.parametrize("name", MODULES)
def test_origin_module_IS_the_prism_module(name):
    """Not 'equivalent to' — the same object. See the SURFACE/IDENTITY note above."""
    o = importlib.import_module(f"origin.{name}")
    p = importlib.import_module(f"prism.trust.{name}")
    assert o is p, (
        f"origin.{name} is no longer the same module object as prism.trust.{name}. If this file was "
        f"changed to `from prism.trust.{name} import *`, revert it: a star-import breaks callers "
        f"that WRITE module state (a consumer's fixtures set `_loaded` and `_manifest`), and it breaks "
        f"them silently — the write lands on the shim and the readers never see it.")


@pytest.mark.parametrize("name", MODULES)
def test_the_shim_stays_a_shim(name):
    """A re-export that grows a body is the fork coming back."""
    path = ORIGIN_SRC / f"{name}.py"
    # `utf-8-sig`, not `utf-8`: some of this tree's Python files carry a UTF-8 BOM. Python
    # tolerates one on import, so those files run; `ast.parse` on a plain `utf-8` read does not,
    # and raises `invalid non-printable character U+FEFF`. Reading with `utf-8-sig` keeps this
    # check about what it is for rather than about which editor last saved the file.
    tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    defs = [n for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    assert not defs, (
        f"origin/{name}.py has grown its own implementation ({[d.name for d in defs]}). The trust "
        f"floor lives in prism.trust; add it there so both names get it.")


def test_the_full_consumer_surface_still_resolves():
    """The names consumer repositories actually import.

    Listed explicitly, not derived from `dir()`: deriving the expected surface from the thing under
    test is the check that cannot fail — it would agree with whatever the module happens to expose,
    including nothing."""
    from origin.authority_trust import (  # noqa: F401
        AuthorityManifest, get_authority_manifest, load_authority_manifest,
        reload_authority_manifest, reset_authority_manifest_for_tests,
        verify_delegation_jwt, verify_jwt, verify_service_jwt,
    )
    from origin.key_manager import (  # noqa: F401
        KEYS_DIR, delete_setup_token, get_encryption_key, get_jwk_public, get_key_id,
        get_nonce_secret, get_private_key_pem, get_public_key_pem, get_setup_token,
        init_encryption_key, init_jwt_keys, init_nonce_secret, init_setup_token,
    )
    from origin.service_identity import (  # noqa: F401
        DEFAULT_DELEGATION_TTL_SECONDS, DEFAULT_TTL_SECONDS, SERVICE_NAMES, ServiceIdentity,
        get_host_id, get_instance_namespace, get_service_identity, get_system_principal_id,
        init_service_identity, reset_service_identity_for_tests,
        sign_delegation_jwt, sign_service_jwt,
    )


@pytest.mark.parametrize("name", MODULES)
def test_writes_through_the_origin_name_are_seen_through_the_prism_name(name):
    """The property a consumer's fixtures depend on, exercised directly rather than assumed to still
    hold. It writes a sentinel to a scratch attribute, so it touches no real state."""
    o = importlib.import_module(f"origin.{name}")
    p = importlib.import_module(f"prism.trust.{name}")
    sentinel = f"__fork_probe_{name}__"
    try:
        setattr(o, sentinel, "written through origin")
        assert getattr(p, sentinel, None) == "written through origin", (
            f"a write to origin.{name} is not visible through prism.trust.{name} — the two names no "
            f"longer share one namespace, so module-level state has silently forked.")
    finally:
        for m in (o, p):
            if hasattr(m, sentinel):
                delattr(m, sentinel)


def test_prism_never_imports_origin():
    """The direction is load-bearing: it is what makes the re-export legal (no cycle) and what keeps
    the Apache floor free of AGPL code. Checked at the source, since an import that only fires on
    some code path would not show up by importing the package here."""
    import prism
    prism_root = pathlib.Path(prism.__file__).resolve().parent
    offenders, unreadable = [], []
    for path in prism_root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        try:
            # `utf-8-sig` for the same BOM reason as above; `errors="replace"` alone turned an
            # unreadable byte into a replacement character and let the parse fail downstream.
            tree = ast.parse(path.read_text(encoding="utf-8-sig", errors="replace"))
        except SyntaxError:
            # An unparseable module is not checked for the import cycle; without tracking that,
            # "no offenders" would cover fewer files than it claims. Counted and asserted below —
            # an unreadable file is a finding, not something to pass over.
            unreadable.append(path.name)
            continue
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                mods = [node.module or ""]
            if any(m == "origin" or m.startswith("origin.") for m in mods):
                offenders.append(f"{path.name}:{node.lineno}")
    # Coverage first: a scan that skipped files cannot support "no offenders", so the skip list is
    # asserted before the finding it would otherwise hide.
    assert not unreadable, (
        "these prism modules could not be parsed and were therefore NOT checked for the import "
        "cycle: %s. The clean result below would have covered fewer files than it claims."
        % unreadable)
    assert not offenders, (
        "prism imports origin at " + ", ".join(offenders) + " — that is a dependency CYCLE (origin's "
        "trust modules re-export prism's) and it puts AGPL-licensed code behind an Apache-2.0 "
        "package. The floor must depend on nothing above it.")

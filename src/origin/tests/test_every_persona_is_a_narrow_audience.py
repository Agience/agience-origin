"""Every persona Chorus hosts is a narrow audience the app may call directly, and Crystal may hop
to each (John, 2026-11-10, FR-006: aria, astra, ophan and seraph were refused, 400 "audience is not
a narrow audience")."""
from __future__ import annotations

from prism.trust.service_identity import PERSONA_NAMES


def test_every_persona_is_narrowed_to_with_its_own_scope_only(monkeypatch):
    from origin import config
    monkeypatch.delenv("NARROW_AUDIENCES", raising=False)
    out = config._default_narrow_audiences()
    for name in PERSONA_NAMES:
        assert out.get(name) == [f"persona:{name}"], name


def test_crystal_hops_to_every_persona(monkeypatch):
    from origin import config
    monkeypatch.delenv("NARROW_HOPS", raising=False)
    hops = config._narrow_hops_from_env()
    assert sorted(hops["crystal"]) == sorted(PERSONA_NAMES)

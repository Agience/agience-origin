"""The home node, while it is the test gate, holds test custody over its own keys (John, 2026-11-11).

A run, a timer and their approvals are then accepted on the home node before promote. Test custody
claims no separation: what keeps it apart from production is an issuer production never trusts,
under `home.agience.ai`, and that it has no peers. Production's own rule is unchanged.
"""
from __future__ import annotations

import pytest

from origin.services import custody_plane as cp


@pytest.fixture
def home(monkeypatch, tmp_path):
    monkeypatch.setattr(cp, "TEST_OVERRIDE", None)
    monkeypatch.setenv("AGIENCE_PLANE", "home")
    monkeypatch.setenv("ORIGIN_URI", "https://origin.home.agience.ai")
    monkeypatch.delenv("AUTHORITY_ISSUER", raising=False)
    monkeypatch.delenv("EMBER_PEERS", raising=False)
    monkeypatch.setenv("KEYS_DIR", str(tmp_path / "keys"))
    from origin import config
    monkeypatch.setattr(config, "AUTHORITY_ISSUER", "https://origin.home.agience.ai")
    return monkeypatch


def test_the_home_node_holds_test_custody(home):
    assert cp.custody_refusal() is None


def test_it_is_given_up_once_the_node_peers(home):
    home.setenv("EMBER_PEERS", "http://peer.example.invalid:8091")
    assert "peers" in cp.custody_refusal()


@pytest.mark.parametrize("issuer", ["https://origin.agience.ai", "https://origin.staging.agience.ai",
                                    "https://home.agience.ai.example.invalid", "http://localhost:8080"])
def test_a_node_whose_issuer_is_not_a_home_host_holds_none(home, issuer):
    home.setenv("AUTHORITY_ISSUER", issuer)
    assert "home node" in cp.custody_refusal()


def test_it_needs_its_own_keys_folder(home):
    home.delenv("KEYS_DIR")
    assert "KEYS_DIR" in cp.custody_refusal()


@pytest.mark.parametrize("plane", ["rc", "dev", "", "test"])
def test_every_other_plane_but_production_is_still_refused(home, plane):
    home.setenv("AGIENCE_PLANE", plane)
    assert "isolated production" in cp.custody_refusal()


def test_production_still_asks_for_isolation_whatever_its_issuer(home):
    home.setenv("AGIENCE_PLANE", "production")
    assert cp.custody_refusal(evidence={"euid": None}) is not None


def test_a_node_that_signs_as_another_issuer_holds_none(home):
    """The issuer Origin signs with is settled at startup from ORIGIN_URI or the stored facet URI,
    not from AUTHORITY_ISSUER: each must be a home host (review, 2026-11-11)."""
    from origin import config
    home.setenv("AUTHORITY_ISSUER", "https://origin.home.agience.ai")
    home.setenv("ORIGIN_URI", "https://my.agience.ai")
    assert "home node" in cp.custody_refusal()
    home.setenv("ORIGIN_URI", "https://origin.home.agience.ai")
    home.setattr(config, "AUTHORITY_ISSUER", "https://origin.agience.ai")
    assert "home node" in cp.custody_refusal()

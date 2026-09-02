"""`/.well-known/agience` — the one URL a new peer needs.

The endpoint is a projection of the authority manifest. Three properties are asserted, and the
second one is the load-bearing one:

  1. It publishes the mantle URI, so a client can find the mesh with one hostname.
  2. It never publishes `bootstrap_token_hash`. That value gates first-boot enrolment; publishing
     it hands an attacker the offline target for the one secret that admits a new service. The
     endpoint projects an allow-list, so this test is what proves the allow-list is actually
     applied — a deny-list version of the same code would pass every other assertion here and
     still leak the next field somebody adds to the manifest.
  3. A missing manifest is a 503, never a 200 with an empty service map. A discovery document that
     succeeds with no members teaches every client that the mesh is empty, and they cache it.
"""
from __future__ import annotations

import json

import pytest

from origin import authority_trust


@pytest.fixture
def manifest(tmp_path, monkeypatch):
    """A minimal authority manifest on disk, with a secret in it that must not be republished."""
    doc = {
        "issuer": "https://origin.example.test",
        "artifact_id": "urn:agience:authority:test",
        "bootstrap_token_hash": "SECRET-MUST-NOT-BE-PUBLISHED",
        "trust_anchors": {
            "origin": {"uri": "https://origin.example.test",
                       "jwks": {"keys": [{"kid": "o1", "kty": "RSA"}]},
                       "private_note": "also must not be published"},
            "mantle": {"uri": "https://mantle.example.test",
                       "jwks": {"keys": [{"kid": "m1", "kty": "RSA"}]}},
        },
    }
    (tmp_path / "authority.manifest.json").write_text(json.dumps(doc), encoding="utf-8")
    monkeypatch.setenv("KEYS_DIR", str(tmp_path))
    authority_trust.reset_authority_manifest_for_tests()
    yield doc
    authority_trust.reset_authority_manifest_for_tests()


def test_publishes_the_mantle_uri_so_one_hostname_is_enough(client, manifest):
    body = client.get("/.well-known/agience").json()
    assert body["services"]["mantle"]["uri"] == "https://mantle.example.test"
    assert body["issuer"] == "https://origin.example.test"
    assert body["authority_artifact"] == "urn:agience:authority:test"


def test_roles_are_stated_not_inferred_from_the_name(client, manifest):
    """`mantle` is the lattice, not a peer.

    There is deliberately no ember on the mantle endpoint — it is a plain REST service holding the
    store. Publishing it as `peer` would invite an ember to attempt ember-to-ember reconciliation
    against something that does not speak it. Embers peer with each other; they use the lattice as
    shared substrate."""
    body = client.get("/.well-known/agience").json()
    assert body["services"]["mantle"]["role"] == "lattice"
    assert body["services"]["origin"]["role"] == "authority"


def test_an_unlisted_service_defaults_to_peer(client, manifest, tmp_path):
    """A service nobody classified is another ember until stated otherwise."""
    doc = dict(manifest)
    doc["trust_anchors"] = {**manifest["trust_anchors"],
                            "ember-home": {"uri": "https://home.example.test", "jwks": {"keys": []}}}
    (tmp_path / "authority.manifest.json").write_text(json.dumps(doc), encoding="utf-8")
    authority_trust.reset_authority_manifest_for_tests()
    body = client.get("/.well-known/agience").json()
    assert body["services"]["ember-home"]["role"] == "peer"


def test_the_bootstrap_token_hash_is_never_published(client, manifest):
    """The whole reason the projection is an allow-list."""
    raw = client.get("/.well-known/agience").text
    assert "SECRET-MUST-NOT-BE-PUBLISHED" not in raw
    assert "bootstrap_token_hash" not in raw


def test_unknown_anchor_fields_are_not_published(client, manifest):
    """A field nobody thought about must default to private.

    `private_note` is not secret in itself — it stands in for the next field added to a trust
    anchor. Under an allow-list it stays in; under a deny-list it ships."""
    raw = client.get("/.well-known/agience").text
    assert "private_note" not in raw
    assert "also must not be published" not in raw


def test_public_jwks_is_published_because_that_is_the_point(client, manifest):
    """The anchor is what makes the document verifiable away from this hostname."""
    body = client.get("/.well-known/agience").json()
    assert body["services"]["mantle"]["jwks"]["keys"][0]["kid"] == "m1"


def test_a_service_without_a_uri_is_omitted(client, manifest, tmp_path, monkeypatch):
    """An anchor with no deployment URI is not a reachable service; listing it would advertise
    something a client cannot connect to."""
    doc = dict(manifest)
    doc["trust_anchors"] = {**manifest["trust_anchors"], "ghost": {"jwks": {"keys": []}}}
    (tmp_path / "authority.manifest.json").write_text(json.dumps(doc), encoding="utf-8")
    authority_trust.reset_authority_manifest_for_tests()
    body = client.get("/.well-known/agience").json()
    assert "ghost" not in body["services"]
    assert "mantle" in body["services"]


def test_a_missing_manifest_is_503_not_an_empty_success(client, tmp_path, monkeypatch):
    """A missing manifest is a 503, not a vacuous success."""
    monkeypatch.setenv("KEYS_DIR", str(tmp_path / "nonexistent"))
    authority_trust.reset_authority_manifest_for_tests()
    resp = client.get("/.well-known/agience")
    assert resp.status_code == 503
    assert resp.json()["error"] == "authority_manifest_missing"
    authority_trust.reset_authority_manifest_for_tests()

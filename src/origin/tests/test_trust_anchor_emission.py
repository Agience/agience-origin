"""`origin-emit-anchor` produces exactly what a peer's authority manifest is read for.

The failure this guards is the quietest one in the trust chain. A peer reads Origin's JWKS INLINE
from `trust_anchors.origin` in its own `KEYS_DIR/authority.manifest.json` and never fetches, so an
Origin that is running, reachable and publishing a correct `/.well-known/jwks.json` still has every
one of its tokens rejected 401 by a peer whose manifest has no such anchor. Nothing logs a mismatch,
because from the peer's side there is no mismatch — there is simply no such issuer.

A hand-extracted JWK fails the same way and for a smaller reason: a `kid` that does not match what
Origin stamps, or a modulus re-encoded with padding, produces a manifest that loads cleanly and
selects no key. So the assertions below are about the two things that are invisible until a real
token is rejected — the exact shape a peer indexes, and the `kid` agreeing with `main.py`.

That shape is written out here as literal lookups rather than imported: this repo depends on no
peer, and must not, so the contract is pinned by restating the access path a peer performs.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from origin.scripts import emit_trust_anchor as emit


@pytest.fixture(autouse=True)
def _restore_key_state():
    """`init_jwt_keys` loads into module globals shared with the running app.

    Without this, emitting an anchor here would leave this test's throwaway key installed as the
    process's signing key, and whichever test ran next would verify tokens against it. The failure
    would land in an unrelated file."""
    from origin import key_manager as km

    saved = (km._private_key_pem, km._public_key_pem, km._key_id)
    yield
    km._private_key_pem, km._public_key_pem, km._key_id = saved


def _emit(capsys, *argv) -> dict:
    code = emit.main(list(argv))
    assert code == 0, f"origin-emit-anchor exited {code}"
    return json.loads(capsys.readouterr().out)


def test_the_kid_matches_what_main_actually_signs_with() -> None:
    """The single value that makes a well-formed anchor useless.

    A peer selects a verification key by `kid`. If the manifest says `origin-1` and Origin stamps
    something else, the JWKS is present, parses, and matches nothing — a 401 that looks exactly
    like an absent anchor. Read out of `main.py` rather than duplicated as a constant, because a
    constant is what drifts.
    """
    from origin import main

    source = Path(main.__file__).resolve().read_text(encoding="utf-8")
    found = re.search(r'init_jwt_keys\(key_id=["\']([^"\']+)["\']\)', source)
    assert found, (
        "no `init_jwt_keys(key_id=...)` call found in main.py — this test can no longer tell what "
        "Origin signs with, so it cannot certify the emitted anchor")
    assert found.group(1) == emit.DEFAULT_KID, (
        f"main.py signs with kid={found.group(1)!r} but origin-emit-anchor defaults to "
        f"{emit.DEFAULT_KID!r}. Every token Origin issues would be rejected by a peer that "
        "installed this anchor, with no error naming the cause.")


def test_the_fragment_is_shaped_the_way_a_peer_reads_it(jwt_keypair, capsys) -> None:
    """The access path a peer performs when it loads its manifest anchors, performed here:

        anchors     = manifest.get("trust_anchors", {})
        anchor      = anchors.get("origin") or {}
        jwks        = anchor.get("jwks")            # must be a dict, or it is skipped
    """
    out = _emit(capsys, "--keys-dir", str(jwt_keypair), "--uri", "https://origin.example.com")

    anchors = out.get("trust_anchors", {})
    assert "origin" in anchors, (
        f"the fragment has no `origin` anchor, so a peer loading it finds nothing and Origin-signed "
        f"USER tokens go unverified; got keys {sorted(anchors)}")

    anchor = anchors["origin"]
    assert anchor.get("uri") == "https://origin.example.com"

    jwks = anchor.get("jwks")
    assert isinstance(jwks, dict), (
        "a peer requires `jwks` to be a dict; anything else is skipped silently")
    assert isinstance(jwks.get("keys"), list) and jwks["keys"], "empty JWKS"

    jwk = jwks["keys"][0]
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == emit.DEFAULT_KID
    assert jwk["alg"] == "RS256"
    for field in ("n", "e"):
        assert jwk[field] and "=" not in jwk[field], (
            f"{field} is padded base64 — JWK requires unpadded base64url, and a padded value "
            "makes key selection fail after the manifest has already loaded cleanly")


def test_the_emitted_jwk_is_the_one_origin_publishes(jwt_keypair, capsys) -> None:
    """Byte-identical to `/.well-known/jwks.json`, because both come from `get_jwk_public()`.

    This is the whole reason the script routes through that function instead of converting the PEM
    itself: an anchor that merely looks right is what a hand-extraction also produces."""
    from origin.key_manager import get_jwk_public, init_jwt_keys

    out = _emit(capsys, "--keys-dir", str(jwt_keypair), "--uri", "https://origin.example.com")

    init_jwt_keys(
        private_key_path=jwt_keypair / "origin.private.pem",
        public_key_path=jwt_keypair / "origin.public.pem",
        key_id=emit.DEFAULT_KID,
    )
    assert out["trust_anchors"]["origin"]["jwks"]["keys"][0] == get_jwk_public()


@pytest.mark.parametrize("fmt,check", [
    ("anchor", lambda d: set(d) == {"uri", "jwks"}),
    ("jwks", lambda d: set(d) == {"keys"}),
])
def test_the_narrower_formats_emit_the_value_alone(jwt_keypair, capsys, fmt, check) -> None:
    """`--format anchor` is what an operator pastes at `trust_anchors.origin`; `--format jwks` is
    the JWKS on its own. Both must be the bare value — a nested copy of the fragment here would be
    placed one level too deep and read as no anchor at all."""
    out = _emit(capsys, "--keys-dir", str(jwt_keypair), "--format", fmt)
    assert check(out), f"--format {fmt} emitted {sorted(out)}"


def test_it_writes_nothing(jwt_keypair, tmp_path, capsys) -> None:
    """The command reads key material and emits. Placement is the operator's decision, and a
    command that also wrote would make it Origin's."""
    before = {p.name: p.stat().st_mtime_ns for p in jwt_keypair.iterdir()}
    _emit(capsys, "--keys-dir", str(jwt_keypair))
    after = {p.name: p.stat().st_mtime_ns for p in jwt_keypair.iterdir()}
    assert before == after, "origin-emit-anchor modified the keys directory"
    assert not list(tmp_path.iterdir()), "origin-emit-anchor wrote into the working area"


def test_absent_key_material_is_a_named_failure_not_a_traceback(tmp_path, capsys) -> None:
    """An empty keys dir is the ordinary state on a box the installer has not reached yet.

    It must exit non-zero naming the directory, and must not print a fragment — a partial or empty
    anchor placed in a manifest is worse than none, because it looks provisioned."""
    code = emit.main(["--keys-dir", str(tmp_path)])
    captured = capsys.readouterr()

    assert code == 2, f"expected exit 2 for missing key material, got {code}"
    assert captured.out == "", f"emitted something despite having no key: {captured.out!r}"
    assert str(tmp_path) in captured.err, "the error does not name the directory it looked in"
    assert "Traceback" not in captured.err


def test_no_keys_dir_at_all_is_refused(monkeypatch, capsys) -> None:
    """Defaulting to prism's `/data/keys` here would read some other install's key material on a
    box where that path happens to exist, and emit an anchor for a key Origin does not sign with."""
    monkeypatch.delenv("KEYS_DIR", raising=False)
    with pytest.raises(SystemExit) as exc:
        emit.main([])
    assert exc.value.code != 0

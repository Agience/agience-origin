#!/usr/bin/env python3
"""Print Origin's public trust anchor, in the shape a peer's authority manifest expects.

    origin-emit-anchor                          # the {"trust_anchors": {"origin": …}} fragment
    origin-emit-anchor --format anchor          # just the value to place at trust_anchors.origin
    origin-emit-anchor --format jwks            # just the JWKS
    origin-emit-anchor --keys-dir ./.data/keys --uri https://origin.example.com

## The gap this closes

A peer verifies Origin-signed tokens from an INLINE JWKS in its own
`KEYS_DIR/authority.manifest.json`, never by fetching. It reads `trust_anchors.origin.jwks` and
registers it under both `origin` (for platform-service JWTs, whose `iss` is the service NAME) and
`AUTHORITY_ISSUER` (for user tokens and delegations, whose `iss` is a URL).

So Origin publishing `/.well-known/jwks.json` does not make a peer able to verify anything. Two
services can be running, healthy and mutually reachable, and every Origin-signed token is still a
flat 401 until Origin's public JWK is physically present in that manifest. A peer's own key init
writes only its own anchor — an entry for someone else would assert a public key for a service
whose private key is elsewhere, which is a trust statement rather than a convenience — so Origin
emits its half here. Extracting the JWK by hand instead is where a wrong `kid` or a re-encoded
modulus comes from, and both fail as the SAME 401.

## Why it emits rather than writes

This prints to stdout and touches nothing. Writing into a peer's keyset from here would mean one
service reaching into another's key material to install trust in itself, which is the one direction
a trust anchor must never travel — the operator (or the platform installer) decides what a peer
trusts, and that decision has to be theirs to make. Placement is one shell redirect away and
documented in the README.

## Why it goes through `get_jwk_public()`

The JWK is produced by the same function `/.well-known/jwks.json` serves, not by a second
conversion written here. A private re-implementation would be free to disagree about `kid` or about
the base64url encoding of the modulus, and the result would be a manifest that parses, loads, and
selects no key — a 401 indistinguishable from the missing-anchor case this command exists to fix.
One implementation means what is placed in the peer's manifest is byte-identical to what Origin
publishes.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

#: The `kid` Origin stamps on every token it signs. `main.py`'s lifespan calls
#: `init_jwt_keys(key_id="origin-1")`, and a manifest carrying any other value describes a key no
#: verifier will select — the signature check never runs, and the token is rejected as untrusted.
#: `tests/test_trust_anchor_emission.py` reads the literal out of `main.py` and fails if the two
#: ever drift.
DEFAULT_KID = "origin-1"

#: The anchor name a peer looks under: it reads `trust_anchors.get("origin")`
#: specifically to pair with `AUTHORITY_ISSUER`; under any other name the JWKS still registers as a
#: service issuer, but Origin-signed USER tokens — the browser sign-in — go unverified.
ANCHOR_NAME = "origin"


def build_anchor(*, keys_dir: Path, uri: str, kid: str) -> dict:
    """The `trust_anchors.origin` value: `{"uri": …, "jwks": {"keys": [<jwk>]}}`.

    Both key files must be present. `init_jwt_keys` loads the pair, and the pair is what Origin
    itself needs to serve, so a host that cannot satisfy this is a host where Origin does not run.
    """
    from origin.key_manager import get_jwk_public, init_jwt_keys

    init_jwt_keys(
        private_key_path=keys_dir / "origin.private.pem",
        public_key_path=keys_dir / "origin.public.pem",
        key_id=kid,
    )
    return {"uri": uri, "jwks": {"keys": [get_jwk_public()]}}


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="origin-emit-anchor",
        description="Print Origin's public trust anchor for a peer's authority manifest. "
                    "Reads key material; writes nothing.",
        epilog="Place it in the peer's KEYS_DIR/authority.manifest.json under "
               "trust_anchors.origin — see the README's 'Letting a peer verify Origin' section.",
    )
    parser.add_argument(
        "--keys-dir",
        default=os.getenv("KEYS_DIR"),
        help="Where origin.public.pem lives. Defaults to $KEYS_DIR; required if that is unset.",
    )
    parser.add_argument(
        "--uri",
        default=None,
        help="The anchor's `uri` — Origin's public address. Defaults to config.AUTHORITY_ISSUER.",
    )
    parser.add_argument(
        "--kid",
        default=DEFAULT_KID,
        help="The key id stamped on Origin's tokens (default: %(default)s). Change this only "
             "alongside main.py's init_jwt_keys call — a mismatch is a silent 401.",
    )
    parser.add_argument(
        "--format",
        choices=("fragment", "anchor", "jwks"),
        default="fragment",
        help="fragment: {\"trust_anchors\": {\"origin\": …}}, mergeable as-is (default). "
             "anchor: the value alone, for placing at trust_anchors.origin. "
             "jwks: the JWKS alone.",
    )
    args = parser.parse_args(argv)

    if not args.keys_dir:
        parser.error("no --keys-dir and no KEYS_DIR in the environment; nothing to read")
    keys_dir = Path(args.keys_dir).expanduser().resolve()

    uri = args.uri
    if not uri:
        from origin import config
        uri = getattr(config, "AUTHORITY_ISSUER", "") or config.ORIGIN_URI

    try:
        anchor = build_anchor(keys_dir=keys_dir, uri=uri, kid=args.kid)
    except RuntimeError as exc:
        # `init_jwt_keys` raises this when either half of the pair is absent. Its message names
        # the directory and points at key initialisation, which is the right advice on a managed
        # node and confusing on a laptop, so the path is restated plainly.
        print(f"origin-emit-anchor: {exc}", file=sys.stderr)
        print(f"  looked for origin.private.pem and origin.public.pem under {keys_dir}",
              file=sys.stderr)
        print("  Origin has no key generator of its own — key material comes from the platform "
              "installer (agience-observe) or your own custody process.", file=sys.stderr)
        return 2

    payload = {
        "fragment": {"trust_anchors": {ANCHOR_NAME: anchor}},
        "anchor": anchor,
        "jwks": anchor["jwks"],
    }[args.format]

    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":       # `python src/origin/scripts/emit_trust_anchor.py`, no install
    raise SystemExit(main())

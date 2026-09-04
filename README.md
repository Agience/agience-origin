# Agience Origin

[![PyPI](https://img.shields.io/pypi/v/agience-origin)](https://pypi.org/project/agience-origin/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-AGPL%203.0-blue)](LICENSE)
[![CI](https://github.com/Agience/agience-origin/actions/workflows/build.yml/badge.svg)](https://github.com/Agience/agience-origin/actions/workflows/build.yml)

**Identity, authority.**

Origin says who. It is the identity and authorization authority — the trust anchor the rest of the
system verifies against, and the entity everything else asks "who is this, and may they?"

As the OIDC issuer it mints and verifies tokens, publishes the JWKS that peer services check
signatures against, and owns the passkey/OTP account and setup flows.

The shared foundation is **`agience-prism-py`** — Origin's only workspace dependency.

## Layout

| Path | Purpose |
|---|---|
| `src/origin/` | The FastAPI service: `api/`, `routers/`, `services/` (auth, verifier, key custody via Shamir + key-oracle), `models/`, `db/`, `scripts/` (operator commands), plus `alembic/` (migrations) and `tests/`. |
| `src/origin/web/` | The static auth UI (login / passkey / setup), served at `/`, `/login`, `/account`, `/reset-password` and `/verify-email`, and mounted for its assets at `/web`. |

`web/` lives **inside** the package, beside the module that serves it. `main.py` resolves it as
`Path(__file__).resolve().parent / "web"`, which gives one answer in both places the code runs: a
checkout and an installed distribution. A path that climbs out of the package resolves against the
repository layout, which only a checkout has.
`src/origin/tests/test_the_package_ships_what_it_serves.py` holds it there.

## Running it

Origin is an ordinary Python package. It needs no container, and installing it pulls its own
pinned dependencies:

    pip install ../agience-prism/py          # the trust floor
    pip install .                            # or -e ".[test]" to work on it
    KEYS_DIR=/path/to/keys python -m uvicorn origin.main:app --host 127.0.0.1 --port 8080

It applies its own migrations at startup, so the first boot creates the database. Requires Python
3.11 or newer.

Bind loopback and put a reverse proxy in front for anything public. A service on the public
interface answers past whatever header and path rules the proxy applies.

`KEYS_DIR` must already contain `origin.private.pem`, `origin.public.pem`, `encryption.key` and
`inbound_nonce.secret`. **Origin ships no key generator** — every loader in
`prism.trust.key_manager` raises rather than inventing a key it did not write, which is correct for
an authority and means an empty directory is a hard stop. Key material comes from the platform
installer (`agience-observe`), a KMS, or a one-shot key-init step. `.env.example` documents the
full set.

For a managed install, `agience-observe/package/manager` does all of the above: it finds a Python,
builds the virtualenv, installs Origin into it and supervises the process.

## Letting a peer verify Origin

Publishing `/.well-known/jwks.json` is **not** what makes a peer able to verify an Origin-signed
token. Agience peers read their trust **inline**, from `trust_anchors` in the
`authority.manifest.json` of their own keyset, and never fetch. Until Origin's public JWK is
physically present there under `trust_anchors.origin`, two healthy, mutually reachable services
answer **401** for every user token and nothing logs a reason: from the peer's side there is no
mismatch, there is simply no such issuer.

A peer's own key init writes only its own anchor — asserting a public key for a service whose
private key is elsewhere is a trust statement, not a convenience. Origin emits its half:

    origin-emit-anchor                                   # the mergeable fragment
    origin-emit-anchor --format anchor --uri https://origin.example.com
    origin-emit-anchor --format jwks --keys-dir /path/to/keys
    python -m origin.scripts.emit_trust_anchor           # no install needed

`--format` chooses `fragment` (a mergeable `{"trust_anchors": {"origin": …}}`, the default), `anchor`
(the value alone, for placing at `trust_anchors.origin`), or `jwks` (the JWKS alone). `--keys-dir`
defaults to `$KEYS_DIR`, and `--uri` to `config.AUTHORITY_ISSUER`.

It reads `KEYS_DIR/origin.public.pem`, produces the JWK through the same `get_jwk_public()` that
serves `/.well-known/jwks.json` — so what you place is byte-identical to what Origin publishes,
`kid` included — and **writes nothing**. Placement is the operator's decision; a command that
installed trust in itself on a peer would be the one direction a trust anchor must never travel.

To place it, merge into the peer's manifest:

    origin-emit-anchor --format anchor > /tmp/origin-anchor.json
    python - <<'EOF'
    import json, pathlib
    m = pathlib.Path("/path/to/peer/keys/authority.manifest.json")
    doc = json.loads(m.read_text())
    doc.setdefault("trust_anchors", {})["origin"] = json.load(open("/tmp/origin-anchor.json"))
    m.write_text(json.dumps(doc, indent=2) + "\n")
    EOF

Then restart the peer. A wrong `kid` or a re-encoded modulus fails as the same silent 401, which is
why the JWK is emitted rather than transcribed.

## Configuration

`.env.example` is the template — copy it to `.env`. It states the in-code default for every value
and warns where an unset variable is itself a decision: `KEYS_DIR` unset means the process does not
boot, and `ORIGIN_ALLOWED_ORIGINS` unset derives the CORS allow-list from the issuer, `ORIGIN_URI`
and the facet bases rather than falling back to a wildcard.

## License

**Dual-licensed: AGPL-3.0-only *or* commercial.** See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE);
commercial and white-label terms in [`COMMERCIAL_LICENSE.md`](COMMERCIAL_LICENSE.md). Contributing:
[`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CLA.md`](CLA.md).

## Star History

<a href="https://www.star-history.com/?repos=Agience%2Fagience-origin&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=Agience/agience-origin&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=Agience/agience-origin&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=Agience/agience-origin&type=date&legend=top-left" />
 </picture>
</a>

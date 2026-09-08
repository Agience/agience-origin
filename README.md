# Agience Origin

[![PyPI](https://img.shields.io/pypi/v/agience-origin)](https://pypi.org/project/agience-origin/)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![License](https://img.shields.io/pypi/l/agience-origin)](LICENSE)
[![CI](https://github.com/Agience/agience-origin/actions/workflows/build.yml/badge.svg)](https://github.com/Agience/agience-origin/actions/workflows/build.yml)
[![Sponsor](https://img.shields.io/badge/Sponsor-Agience-EA4AAA?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/Agience)

**Identity and authority — the OIDC issuer.**

Origin is the trust anchor peers verify against, and the service everything else asks *who is this,
and may they?* It mints and verifies tokens, publishes the JWKS that peers check signatures against,
and owns the passkey, OTP and account-setup flows.

## Running it

An ordinary Python package — no container, and installing it pulls its own pinned dependencies.

```bash
pip install agience-origin
KEYS_DIR=/path/to/keys python -m uvicorn origin.main:app --host 127.0.0.1 --port 8080
```

It applies its own migrations at startup, so the first boot creates the database. Requires Python
3.11 or newer.

Bind loopback and put a reverse proxy in front of anything public — a service on the public
interface answers past whatever header and path rules the proxy applies.

`KEYS_DIR` must already contain `origin.private.pem`, `origin.public.pem`, `encryption.key` and
`inbound_nonce.secret`. Every key loader raises rather than inventing a key it did not write, which
is correct for an authority and makes an empty directory a hard stop. Key material comes from a
platform installer, a KMS, or a one-shot key-init step; [`.env.example`](.env.example) documents the
full set.

## Letting a peer verify Origin

Agience peers read their trust **inline**, from `trust_anchors` in the `authority.manifest.json` of
their own keyset. Publishing `/.well-known/jwks.json` is therefore not what makes a peer able to
verify an Origin-signed token: until Origin's public JWK is physically present under
`trust_anchors.origin`, two healthy and mutually reachable services answer **401** for every user
token, with nothing to log — from the peer's side there is no mismatch, there is simply no such
issuer.

A peer's own key init writes only its own anchor, since asserting a public key for a service whose
private key is elsewhere is a trust statement rather than a convenience. Origin emits its half:

```bash
origin-emit-anchor                                    # the mergeable fragment
origin-emit-anchor --format anchor --uri https://origin.example.com
origin-emit-anchor --format jwks --keys-dir /path/to/keys
python -m origin.scripts.emit_trust_anchor            # straight from a checkout
```

`--format` chooses `fragment` (a mergeable `{"trust_anchors": {"origin": …}}`, the default), `anchor`
(the value alone, for placing at `trust_anchors.origin`), or `jwks`. `--keys-dir` defaults to
`$KEYS_DIR` and `--uri` to `config.AUTHORITY_ISSUER`.

It reads `KEYS_DIR/origin.public.pem` and produces the JWK through the same `get_jwk_public()` that
serves `/.well-known/jwks.json`, so what you place is byte-identical to what Origin publishes, `kid`
included. It writes nothing: placement is the operator's decision, and a command that installed
trust in itself on a peer would send a trust anchor the one direction it must never travel.

To place it, merge into the peer's manifest:

```bash
origin-emit-anchor --format anchor > /tmp/origin-anchor.json
python - <<'EOF'
import json, pathlib
m = pathlib.Path("/path/to/peer/keys/authority.manifest.json")
doc = json.loads(m.read_text())
doc.setdefault("trust_anchors", {})["origin"] = json.load(open("/tmp/origin-anchor.json"))
m.write_text(json.dumps(doc, indent=2) + "\n")
EOF
```

Then restart the peer. A wrong `kid` or a re-encoded modulus fails as the same silent 401, which is
why the JWK is emitted rather than transcribed.

## Configuration

[`.env.example`](.env.example) is the template — copy it to `.env`. It states the in-code default for
every value and marks where an unset variable is itself a decision: `KEYS_DIR` unset means the
process does not boot, and `ORIGIN_ALLOWED_ORIGINS` unset derives the CORS allow-list from the
issuer, `ORIGIN_URI` and the facet bases.

## Layout

| path | what it is |
|---|---|
| [`src/origin/main.py`](src/origin/main.py) | the FastAPI app, and the startup that runs its own migrations |
| [`src/origin/routers/`](src/origin/routers/) | `auth` · `otp` · `passkey` · `setup` · `oracle` · `server_credentials` · `system` |
| [`src/origin/services/`](src/origin/services/) | `auth_service` and `auth_verifier`, key custody through `shamir` and `key_oracle`, `passkey_service`, `otp_service`, `person_service`, `oidc_providers`, `platform_settings_service`, `guess_budget` |
| [`src/origin/models/`](src/origin/models/) · [`src/origin/db/`](src/origin/db/) · [`src/origin/api/`](src/origin/api/) | the entities, the store and the request/response models |
| [`src/origin/alembic/`](src/origin/alembic/) | the migrations, applied at boot |
| [`src/origin/scripts/`](src/origin/scripts/) | the operator commands — `emit_trust_anchor` |
| [`src/origin/web/`](src/origin/web/) | the static auth UI served at `/`, `/login`, `/account`, `/reset-password` and `/verify-email`, with its assets mounted at `/web` |
| [`src/origin/tests/`](src/origin/tests/) | the suite, including the check that the package ships what it serves |

`web/` lives **inside** the package, beside the module that serves it: `main.py` resolves it as
`Path(__file__).resolve().parent / "web"`, which gives one answer in both places the code runs — a
checkout and an installed distribution. A path that climbs out of the package resolves against the
repository layout, which only a checkout has.

## Star history

<a href="https://www.star-history.com/?repos=Agience%2Fagience-origin&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=Agience/agience-origin&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=Agience/agience-origin&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=Agience/agience-origin&type=date&legend=top-left" />
 </picture>
</a>

Security issues: email **connect@agience.ai** rather than opening a public issue.

Dual-licensed — see [`LICENSE`](LICENSE), [`COMMERCIAL_LICENSE.md`](COMMERCIAL_LICENSE.md),
[`NOTICE`](NOTICE) and [`CLA.md`](CLA.md).

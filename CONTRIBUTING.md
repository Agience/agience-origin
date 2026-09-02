# Contributing to Agience Origin

Origin says **who**: the OIDC issuer that mints and verifies tokens, publishes the JWKS every other
service checks signatures against, and owns the passkey/OTP flows. It is the root of the trust
chain.

## Tests

```bash
pip install -e ../agience-prism/py      # the trust floor, beside this repo
pip install -e ".[test]"                # Origin, its pins, and the test runners
python -m pytest -q src/origin/tests
```

Runtime pins live in `requirements.txt`, which `pyproject.toml` reads for `[project.dependencies]`
— so there is one list, and `pip install agience-origin` resolves it. Test-only dependencies are the
`test` extra.

## `src/origin/web/` lives inside the package

It sits beside the module that serves it, and `main.py` resolves it as
`Path(__file__).parent / "web"` — one answer in both places the code runs: a checkout and an
installed distribution.

A path that climbs *out* of the package resolves against the **repository layout**, which only a
checkout has, so it works in the suite and fails wherever Origin is installed.
`test_the_package_ships_what_it_serves.py` holds it there. **Do not "simplify" that path. Do not
delete that test.**

## Live verification is mandatory for auth changes

Token minting, verification, JWKS publication, delegation and the passkey/OTP flows must be
exercised against a running Origin, not only in unit tests:

```bash
KEYS_DIR=/path/to/keys python -m uvicorn origin.main:app --host 127.0.0.1 --port 8080
```

Say in the PR what you verified and how.

## Rules

- **Migrations are `alembic/`.** A schema change without one is a local mutation, not a change.
- Origin does **not** rotate refresh tokens. Clients that hold one keep it for its full lifetime;
  changing that changes the credential lifecycle of every client at once.
- `agience-prism-py` is Apache-2.0 and is the only workspace dependency. Do not invert that
  direction.

## Contributing

**Sign the CLA** — Origin is AGPL-3.0-only **or** commercially licensed
([`COMMERCIAL_LICENSE.md`](COMMERCIAL_LICENSE.md)), so the project must hold the right to relicense
every line it ships. The bot checks on PR open and links [`CLA.md`](CLA.md).

Fork, branch from `main`, sign off every commit (`git commit -s`), open a PR. Commit format:
`fix:` / `feat(scope):` / `docs:` / `test:` / `chore:`.

**Security vulnerabilities: do not open a public issue** — email **connect@agience.ai**.

## License

**Dual-licensed: AGPL-3.0-only or commercial.** See [`LICENSE`](LICENSE),
[`COMMERCIAL_LICENSE.md`](COMMERCIAL_LICENSE.md) and [`NOTICE`](NOTICE). "-only" constrains the
licence *version*, not commercial use: AGPL-compliant commercial use is free.

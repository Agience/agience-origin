"""Mint the platform operator's authority-ledger bootstrap credential on Origin's own host.

Run as Origin's service user, against Origin's database: the host is the trust root, so the release
tool seeds Origin's authority ledger with no HTTP call and no ceremony. The credential is the one
`POST /oracle/authority-ledger/bootstrap` issues (`authority_ledger.issue_bootstrap_credential`),
for the operator in `platform.operator_id`, and lives at most thirty minutes.

    python -m origin.scripts.authority_bootstrap [--minutes N]   # the credential, alone, on stdout
    python -m origin.scripts.authority_bootstrap --close         # bootstrap closed: <n> window(s)
    python -m origin.scripts.authority_bootstrap --count         # grants=<n> roots=<n> edges=<n>

stdout carries only the answer, one line. Anything else goes to stderr, and the credential is never
logged. Exit 0 on success; non-zero, with a stderr message, when there is no operator, no database,
or the credential cannot be minted. `--close` withdraws every open bootstrap window, as
`DELETE /oracle/authority-ledger/bootstrap` does. `--count` reads the replica tables so the tool can
check a seed.
"""
from __future__ import annotations

import argparse
import sys

#: The longest life this script gives a bootstrap credential, in minutes.
MAX_MINUTES = 30


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m origin.scripts.authority_bootstrap",
                                description="Mint, close or count Origin's authority bootstrap.")
    what = p.add_mutually_exclusive_group()
    what.add_argument("--minutes", type=int, default=MAX_MINUTES,
                      help=f"credential lifetime, 1 to {MAX_MINUTES} minutes")
    what.add_argument("--close", action="store_true", help="withdraw every open bootstrap window")
    what.add_argument("--count", action="store_true",
                      help="print the replica's grant, root and edge counts")
    return p


def _operator(db) -> str:
    from origin.services.platform_settings_service import settings as platform_settings

    platform_settings.load_all(db)
    operator = platform_settings.get("platform.operator_id")
    return str(operator) if operator else ""


def _count(db) -> str:
    from origin.models.authority_ledger import AuthorityEdge, AuthorityGrant, AuthorityRoot

    return (f"grants={db.query(AuthorityGrant).count()} roots={db.query(AuthorityRoot).count()} "
            f"edges={db.query(AuthorityEdge).count()}")


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    if not args.close and not args.count and not 1 <= args.minutes <= MAX_MINUTES:
        print(f"--minutes must be 1 to {MAX_MINUTES}", file=sys.stderr)
        return 2
    try:
        from origin.db.session import SessionLocal
        from origin.services import authority_ledger

        with SessionLocal() as db:
            if args.count:
                print(_count(db))
                return 0
            operator = _operator(db)
            if not operator:
                print("no platform operator is set", file=sys.stderr)
                return 1
            if args.close:
                print(f"bootstrap closed: {authority_ledger.close_bootstrap(db)} window(s)")
                return 0
            issued = authority_ledger.issue_bootstrap_credential(db, operator, args.minutes)
    except Exception as exc:  # noqa: BLE001 — any failure is a stderr line and a non-zero exit
        # Raised before a credential exists, so the message cannot carry one.
        print(f"authority bootstrap failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"authority bootstrap credential issued: window {issued['id']} until "
          f"{issued['expires_at']}", file=sys.stderr)
    print(issued["token"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

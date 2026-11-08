"""Mark an Origin account as a service's own (review 11, M5).

    python -m origin.scripts.service_account --person <id> --audience ember
    python -m origin.scripts.service_account --person <id> --unmark

Run on Origin's host, as Origin's own user. Every token Origin issues for a marked account is a
delegation narrowed to its audience (`services.service_accounts`).
"""
from __future__ import annotations

import argparse
import sys


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--person", required=True)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--audience")
    g.add_argument("--unmark", action="store_true")
    args = ap.parse_args(argv)
    from origin.db.session import SessionLocal, init_engine
    from origin.services import service_accounts
    init_engine()
    with SessionLocal() as db:
        if args.unmark:
            done = service_accounts.unmark(db, args.person)
            print("unmarked" if done else "not a service account")
        else:
            service_accounts.mark(db, args.person, args.audience)
            print(f"{args.person} is the service account for {args.audience}")
        db.commit()
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Operator commands against this Origin's database. Run where Origin runs, with its environment.

    python -m origin.admin person show <email|username|id>
    python -m origin.admin person deactivate <email|username|id> --reason TEXT
    python -m origin.admin person reactivate <email|username|id> [--restore-password-from FILE]

`deactivate` switches an account off: it signs in nowhere and is mailed nothing. Nothing else about
it changes, so `reactivate` restores it exactly. `--restore-password-from` puts back a password hash
removed by hand before deactivation existed, from a JSON backup of person rows (`id`,
`password_hash`); it is refused for an account that has a password. No hash is ever printed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from origin.db.session import SessionLocal, init_engine
from origin.services import person_service


def scheme(password_hash: str | None) -> str:
    """The hash's algorithm and cost (`pbkdf2_sha256/600000`), never the hash: `none` when unset,
    `unreadable` for anything `verify_password` cannot parse."""
    if not password_hash:
        return "none"
    parts = password_hash.split("$")
    if len(parts) == 4 and parts[1].isdigit():
        return f"{parts[0]}/{parts[1]}"
    return "unreadable"


def describe(p) -> str:
    modified = getattr(p, "modified_time", None)
    return (f"{p.id}  username={p.username or '-'}  email={p.email or '-'}  "
            f"verified={bool(p.email_verified)}  password={scheme(p.password_hash)}  "
            f"modified={modified.isoformat() if modified else '-'}  "
            f"deactivated={p.deactivated_at.isoformat() if p.deactivated_at else 'no'}"
            + (f"  reason={p.deactivated_reason!r}" if p.deactivated_reason else ""))


def backed_up_hash(path: Path, person_id: str) -> str:
    rows = json.loads(path.read_text(encoding="utf-8"))
    for row in rows if isinstance(rows, list) else rows.get("rows", []):
        if str(row.get("id")) == person_id and row.get("password_hash"):
            return row["password_hash"]
    raise ValueError(f"{path} holds no password hash for person {person_id}")


def run(argv: list[str] | None = None, out=print) -> int:
    ap = argparse.ArgumentParser(prog="python -m origin.admin", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="noun", required=True)
    person = sub.add_parser("person").add_subparsers(dest="verb", required=True)
    person.add_parser("show").add_argument("who")
    d = person.add_parser("deactivate")
    d.add_argument("who")
    d.add_argument("--reason", required=True)
    r = person.add_parser("reactivate")
    r.add_argument("who")
    r.add_argument("--restore-password-from", type=Path, metavar="FILE")
    args = ap.parse_args(argv)

    init_engine()
    db = SessionLocal()
    try:
        p = person_service.find(db, args.who)
        if p is None:
            out(f"no person is named {args.who!r}")
            return 1
        if args.verb == "deactivate":
            person_service.deactivate(db, str(p.id), args.reason)
            db.commit()
        elif args.verb == "reactivate":
            restored = (backed_up_hash(args.restore_password_from, str(p.id))
                        if args.restore_password_from else None)
            person_service.reactivate(db, str(p.id), restored)
            db.commit()
        db.refresh(p)
        out(describe(p))
        return 0
    except ValueError as e:
        db.rollback()
        out(f"refused: {e}")
        return 2
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(run())

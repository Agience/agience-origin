"""Mint the platform operator's authority-ledger bootstrap credential on Origin's own host.

Run as Origin's service user, against Origin's database: the host is the trust root, so the release
tool seeds Origin's authority ledger with no HTTP call and no ceremony. The credential is the one
`POST /oracle/authority-ledger/bootstrap` issues (`authority_ledger.issue_bootstrap_credential`),
for the operator in `platform.operator_id`, and lives at most thirty minutes.

    python -m origin.scripts.authority_bootstrap [--minutes N] [--ids-stdin]   # the credential, alone, on stdout
    python -m origin.scripts.authority_bootstrap --unseen        # of the ids on stdin, those not seen
    python -m origin.scripts.authority_bootstrap --close         # bootstrap closed: <n> window(s)
    python -m origin.scripts.authority_bootstrap --count         # grants=<n> roots=<n> edges=<n>
    python -m origin.scripts.authority_bootstrap --probe-owner URL   # owner probe: <status> grants=<n>

stdout carries only the answer, one line (`--unseen`: one id per line). Anything else goes to stderr, and the credential is never
logged. Exit 0 on success; non-zero, with a stderr message, when there is no operator, no database,
or the credential cannot be minted. `--close` withdraws every open bootstrap window, as
`DELETE /oracle/authority-ledger/bootstrap` does. `--count` reads the replica tables so the tool can
check a seed. Once the ledger has ordinary entries it takes a bootstrap only for ids it has not seen
and the window lists: `--unseen` reads ids on stdin (one per line) and prints those no ordinary
entry brought into being (`authority_ledger.seen`), and `--ids-stdin` lists the ids on stdin in the
window it opens. `--probe-owner URL` asks the Origin at URL what a person sees: it takes the first
account the replica lets share a resource, opens an Origin session for it, calls
`GET /auth/me/authority/grants` for that resource as the web app does, and ends the session; it
exits 0 on a 200 only. The release candidate's seed rehearsal runs it; the session's value is never
printed.
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
    what.add_argument("--probe-owner", metavar="URL",
                      help="call the grants route at this Origin as an owner the replica holds")
    what.add_argument("--unseen", action="store_true",
                      help="of the ids on stdin, print those no ordinary entry brought into being")
    p.add_argument("--ids-stdin", action="store_true",
                   help="the window states only the ids on stdin, one per line")
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


def _an_owner(db):
    """(person, resource) for the first grant whose grantee the replica lets share or administer
    that resource and whose account is active; None when there is none."""
    from origin.db import persons as db_persons
    from origin.models.authority_ledger import AuthorityGrant
    from origin.services import authority_ledger

    reach = authority_ledger.reach(db)
    for g in db.query(AuthorityGrant).filter(AuthorityGrant.grantee_type == "user").order_by(AuthorityGrant.seq):
        if not {"share", "admin"} & set(g.actions.split(",")):
            continue
        try:
            person = db_persons.get_by_id(db, g.grantee_id)
        except ValueError:   # a grantee id that is not a person's
            continue
        if (person is not None and person.deactivated_at is None
                and reach.has_any_action(g.grantee_id, g.resource_id, "share", "admin")):
            return g.grantee_id, g.resource_id
    return None


def _probe_owner(db, url: str) -> int:
    import json
    import urllib.error
    import urllib.request
    from datetime import datetime, timezone
    from urllib.parse import quote, urlparse

    from origin import config
    from origin.models.origin_session import OriginSession
    from origin.routers.authority_session_router import HEADER
    from origin.services import origin_session

    found = _an_owner(db)
    if found is None:
        print("owner probe: the replica lets no active account share anything", file=sys.stderr)
        return 1
    person, resource = found
    raw = origin_session.issue(db, person)
    db.commit()
    app = urlparse(config.APP_URI)
    req = urllib.request.Request(
        f"{url.rstrip('/')}/auth/me/authority/grants?resource_id={quote(resource, safe='')}",
        headers={"Cookie": f"{origin_session.cookie_name()}={raw}", HEADER: "1",
                 "Origin": f"{app.scheme}://{app.netloc}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            status, body = r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        status, body = e.code, {}
        print(f"owner probe: refused: {e.read()[:300].decode('utf-8', 'replace')}", file=sys.stderr)
    finally:
        row = db.get(OriginSession, origin_session._digest(raw))
        if row is not None:
            row.revoked_time = datetime.now(timezone.utc)
            db.commit()
    print(f"owner probe: {status} grants={len(body.get('grants') or [])}")
    return 0 if status == 200 else 1


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    if args.ids_stdin and (args.close or args.count or args.probe_owner or args.unseen):
        print("--ids-stdin goes with minting a credential", file=sys.stderr)
        return 2
    if not 1 <= args.minutes <= MAX_MINUTES:
        print(f"--minutes must be 1 to {MAX_MINUTES}", file=sys.stderr)
        return 2
    try:
        from origin.db.session import SessionLocal
        from origin.process import init_process
        from origin.services import authority_ledger

        # A process of its own, as the release tool runs it: it builds what Origin's startup
        # builds (keys, identity, engine) before it reads the database or signs.
        init_process()
        with SessionLocal() as db:
            if args.count:
                print(_count(db))
                return 0
            if args.probe_owner:
                return _probe_owner(db, args.probe_owner)
            if args.unseen:
                for nid in sorted({ln.strip() for ln in sys.stdin if ln.strip()}):
                    if not authority_ledger.seen(db, nid):
                        print(nid)
                return 0
            operator = _operator(db)
            if not operator:
                print("no platform operator is set", file=sys.stderr)
                return 1
            if args.close:
                print(f"bootstrap closed: {authority_ledger.close_bootstrap(db)} window(s)")
                return 0
            ids = None
            if args.ids_stdin:
                ids = sorted({ln.strip() for ln in sys.stdin if ln.strip()})
                if not ids:
                    print("no ids on stdin: a window that lists none states nothing", file=sys.stderr)
                    return 1
            issued = authority_ledger.issue_bootstrap_credential(db, operator, args.minutes, ids=ids)
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

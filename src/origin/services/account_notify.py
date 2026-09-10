"""Tell the operator when a new account is created on this authority.

⭐ WHY THIS HOOKS THE INSERT AND NOT THE FOUR REGISTRATION HANDLERS.
An account can be created down four paths — `/auth/password/register`,
`/auth/authorize/register`, the federated callback (`get_or_create_user_by_oidc_identity`), and
`get_or_create_user_by_email`. Adding a call to each is the arrangement that silently misses the
fifth, and a fifth is exactly what `/auth/authorize/register` was a week ago. Every one of them
ends at `db_persons.create`, i.e. at one `INSERT` on `Person`, so that is where this listens.

⚠ AND IT FIRES ON COMMIT, NOT ON INSERT. `create()` does not commit — its callers do, and
`password_register` rolls back on `PermissionError` and on a duplicate address. Mailing at insert
time would announce accounts that were never created. `after_insert` only collects; `after_commit`
sends.

Best-effort by construction: the send runs on a worker thread and every failure is swallowed with
a log line. A notification is not worth failing a registration for, and this is the last thing to
touch the request.

Configured with:
    ACCOUNT_NOTIFY_TO      where to send. Unset disables the whole thing.
    ACCOUNT_NOTIFY_SUBJECT optional prefix, default "[Agience]".
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
from typing import Any, List

from sqlalchemy import event
from sqlalchemy.orm import Session as _Session

# `agience.origin.account_notify`, not `__name__`. The service runs without `--log-config`, so
# only the loggers main.py configures have a handler — a module logger named after its own path
# writes into a void. A notification system whose failures are invisible is one you cannot trust,
# and "did it send?" was unanswerable from the journal until this line changed.
logger = logging.getLogger("agience.origin.account_notify")

#: The key the pending list is stashed under on `session.info`. Per-session, so two concurrent
#: requests cannot see each other's new accounts.
_PENDING = "_account_notify_pending"


def _recipient() -> str:
    return (os.getenv("ACCOUNT_NOTIFY_TO") or "").strip()


def is_enabled() -> bool:
    return bool(_recipient())


def _describe(person: Any) -> tuple[str, str]:
    email = getattr(person, "email", None) or "(no address)"
    username = getattr(person, "username", None) or ""
    name = getattr(person, "name", None) or ""
    verified = bool(getattr(person, "email_verified", False))
    created = getattr(person, "created_time", "") or ""

    subject = f"{os.getenv('ACCOUNT_NOTIFY_SUBJECT', '[Agience]')} New account: {email}"
    body = "\n".join([
        "A new account was created on origin.agience.ai.",
        "",
        f"email     : {email}",
        f"username  : {username}",
        f"name      : {name}",
        # Said plainly because it is the one field that decides whether this is a person or a
        # throwaway: `.invalid` addresses are auto-verified by the allowlist and cannot receive
        # mail, so "verified" alone would be misleading for them.
        f"verified  : {verified}",
        f"created   : {created}",
        f"id        : {getattr(person, 'id', '')}",
    ])
    return subject, body


#: Top-level domains RFC 2606 and RFC 6761 reserve so that they can never be delegated. Nothing
#: under them resolves anywhere, by permanent guarantee of the standard — there is no registrar
#: that could ever sell one.
_RESERVED_TLDS = (".invalid", ".test", ".example", ".localhost")


def _is_probe(person: Any) -> bool:
    """True for an address that cannot belong to a person.

    ⚠ NARROW ON PURPOSE. This is not a judgement about whether a sign-up looks genuine — no
    heuristic, no scoring, nothing about the shape of the name or the address. It is the RFC 2606
    reserved-TLD list and nothing else, so the set it hides is exactly the set that could never
    have reached a human being. A real registration cannot be suppressed by it.

    It exists because the platform's own end-to-end check registers an account on every
    `--allow-write` run, and each one raised "a new account was created" about a probe. An alert
    that fires for the system's own test traffic is an alert that gets ignored, and this one is
    the only notice that a real person signed up.
    """
    email = (getattr(person, "email", "") or "").strip().lower()
    return email.endswith(_RESERVED_TLDS)


def _send(person: Any) -> None:
    """Runs on a worker thread. Never raises."""
    try:
        from origin.services import email_service

        if _is_probe(person):
            logger.info("account-created notification skipped: reserved-TLD address (a probe)")
            return
        if not email_service.is_configured():
            logger.info("account-created notification skipped: no email provider configured")
            return
        subject, body = _describe(person)
        html = "<pre style='font:14px/1.5 ui-monospace,monospace'>" + body + "</pre>"
        asyncio.run(email_service.send_email(_recipient(), subject, html, body))
        logger.info("account-created notification sent to %s", _recipient())
    except Exception:
        # The account exists and the person is signed in. A failed notification changes nothing
        # for them, so it must not change anything for the request either.
        logger.warning("account-created notification failed", exc_info=True)


def install() -> None:
    """Register the listeners. Idempotent, and a no-op when no recipient is configured."""
    if not is_enabled():
        logger.info("account-created notifications are off (ACCOUNT_NOTIFY_TO unset)")
        return

    from origin.models.person import Person

    if getattr(install, "_done", False):
        return

    @event.listens_for(Person, "after_insert")
    def _collect(_mapper, connection, target):  # noqa: ANN001
        sess = getattr(connection, "info", {}).get("session")
        # `connection.info["session"]` is not always populated; fall back to the object session.
        if sess is None:
            sess = _Session.object_session(target)
        if sess is None:
            return
        sess.info.setdefault(_PENDING, []).append(target)

    @event.listens_for(_Session, "after_commit")
    def _flush(session):  # noqa: ANN001
        pending: List[Any] = session.info.pop(_PENDING, [])
        for person in pending:
            # A thread, not a task: this runs inside a sync commit that may or may not have a
            # running event loop under it, and `asyncio.run` cannot be called from a thread that
            # already has one.
            threading.Thread(target=_send, args=(person,), daemon=True).start()

    @event.listens_for(_Session, "after_rollback")
    def _discard(session):  # noqa: ANN001
        # The registration failed — a duplicate address, or a refused principal. Nothing was
        # created, so nothing is announced.
        session.info.pop(_PENDING, None)

    install._done = True  # type: ignore[attr-defined]
    logger.info("account-created notifications on, to %s", _recipient())

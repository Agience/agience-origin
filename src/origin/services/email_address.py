"""The one form of an email address Origin stores and looks up.

One account per address: `persons.email` is unique, and that rule holds only if every spelling of
one mailbox reaches the column as the same string. Mail treats `john@ikailo.com.` (a fully
qualified domain), `john@IKAILO.com` and `john@bücher.de` / `john@xn--bcher-kva.de` as the same
destination, so each must be one key here too.

The canonical form:

  * surrounding whitespace removed and the whole address lower-cased;
  * exactly one `@`, with a non-empty local part and a non-empty domain;
  * the domain without its trailing dot, every label non-empty;
  * the domain in its IDNA ASCII form (punycode), from the standard library's `idna` codec. A
    domain the codec refuses is not an address.

The local part is kept as written (lower-cased): `a.b@` and `ab@`, `a+x@` and `a@` are distinct
mailboxes at most providers, and folding them would join two people's accounts.

Three uses, three functions:

  * `canonical_email` — the form, or `ValueError` when the input cannot be an address.
  * `lookup_email` — the form for a lookup or a ledger key; the stripped, lower-cased input when
    there is no canonical form (an input like that matches no stored canonical address).
  * `require_canonical_email` — where a person types an address to create or change an account:
    the address must already be canonical apart from case and surrounding space, and anything else
    is refused rather than rewritten, so nobody holds an account at a spelling they did not type.
"""

from __future__ import annotations

from typing import Optional


class NonCanonicalEmail(ValueError):
    """An address that names a mailbox but is not written in its canonical form."""

    def __init__(self, given: str, canonical: str):
        super().__init__(f"Enter the address as {canonical}")
        self.given = given
        self.canonical = canonical


def canonical_email(raw: Optional[str]) -> str:
    """The canonical form of `raw`; `ValueError` when `raw` cannot be an address."""
    s = (raw or "").strip().lower()
    if s.count("@") != 1:
        raise ValueError("An email address has exactly one @")
    local, domain = s.split("@")
    if not local or not domain:
        raise ValueError("An email address needs a name before the @ and a domain after it")
    if domain.endswith("."):
        domain = domain[:-1]
    if not domain or any(not label for label in domain.split(".")):
        raise ValueError("The address's domain has an empty part")
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("The address's domain is not a valid domain name") from exc
    # The codec can map a label to nothing or keep a trailing dot; either would be a second form.
    if not ascii_domain or ascii_domain.endswith(".") or any(
            not label for label in ascii_domain.split(".")):
        raise ValueError("The address's domain is not a valid domain name")
    return f"{local}@{ascii_domain.lower()}"


def lookup_email(raw: Optional[str]) -> str:
    """The key a lookup uses: the canonical form, or the stripped, lower-cased input when there is
    none. The fallback never equals a stored canonical address, so it finds nobody."""
    try:
        return canonical_email(raw)
    except ValueError:
        return (raw or "").strip().lower()


def require_canonical_email(raw: Optional[str]) -> str:
    """The canonical form of an address a person typed to create or change an account. Case and
    surrounding space are accepted, as they always were; any other difference from the canonical
    form (a trailing dot, a Unicode domain) raises `NonCanonicalEmail`, and an input that is not
    an address raises `ValueError`."""
    canonical = canonical_email(raw)
    if canonical != (raw or "").strip().lower():
        raise NonCanonicalEmail((raw or "").strip(), canonical)
    return canonical


def is_canonical_email(stored: Optional[str]) -> bool:
    """Whether a stored value is exactly its own canonical form (no stripping, no case folding)."""
    if stored is None:
        return True
    try:
        return canonical_email(stored) == stored
    except ValueError:
        return False


def non_canonical_rows(db) -> list[dict]:
    """Every person whose stored address is not canonical: read-only, for the operator.

    Each row names the person, the stored address, its canonical form (None when it has none), and
    the id of the person who holds that canonical form, if anyone does. Lookups use the canonical
    form, so these rows are reachable by id only; the operator deactivates them by id
    (`python -m origin.admin person deactivate <id> --reason ...`)."""
    from sqlalchemy import select

    from origin.models.person import Person

    found: list[dict] = []
    rows = db.execute(select(Person).where(Person.email.is_not(None))).scalars().all()
    for p in rows:
        if is_canonical_email(p.email):
            continue
        try:
            canonical: Optional[str] = canonical_email(p.email)
        except ValueError:
            canonical = None
        holder = None
        if canonical is not None:
            holder = db.execute(
                select(Person.id).where(Person.email == canonical).limit(1)
            ).scalar_one_or_none()
        found.append({
            "id": str(p.id), "email": p.email, "canonical": canonical,
            "canonical_holder": str(holder) if holder is not None else None,
            "deactivated": p.deactivated_at is not None,
        })
    return found

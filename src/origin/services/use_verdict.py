"""Origin decides whether a persona may use a sealed secret, and signs the verdict (review 21, F1).

Mantle hands a persona the copy of a credential sealed to the persona's key (`POST
/artifacts/{id}/use`). Mantle's yes alone would let a Mantle that is taken over have any person's
secret used, so Mantle asks Origin first (`POST /internal/authority/use-verdict`), showing the
persona's own delegation as the acting credential, and returns Origin's verdict beside the sealed
copy. The persona opens nothing without it (`prism.trust.use_verdict.verify`).

The acting credential is a delegation Origin issued to the persona, asked for by the persona
signing with its own enrolled key, and recorded by its `jti` (`delegation_tokens`) with that
signer, not revoked, issued after its person's sign-in bound:

  person     a person's delegation the persona asked for, addressed to Mantle (`aud`
             `mantle`, `act.sub` `agience-server-<persona>`, `act.iss` `<persona>`, review 22),
             with no scope or only the persona's own narrowed scope, for a live person
  platform   a system delegation for a platform purpose `prism.trust.use_verdict.SYSTEM_SCOPES`
             names for this persona (Iris's platform mail), for the platform system principal

Anything else decides no use: a grant key, a token another key signed, a delegation the shared
`chorus` identity asked for, a describe delegation, a person's own access token, Ember's.

Origin then walks its own replica of the authority ledger: the subject's Invoke on the card and
on the credential, and the persona's own principal's Read on the credential, none of them under a
deny anywhere up the creation chain. The verdict names the three grants that decided it.

It also carries the digests of the persona's sealed copy and of the credential's endpoint list, as
the credential's writer recorded them here (`record_seals`, review 22): a copy Mantle sealed itself
does not match. A credential with no record gets no verdict. And it carries the persona's own nonce
for the one use it asked for, used once: a verdict Mantle asks for on its own is for no use the
persona made, and the persona opens nothing on it.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from sqlalchemy.orm import Session

from origin import config

logger = logging.getLogger(__name__)


class UseRefused(Exception):
    """No verdict. The message names why and carries no token."""


@dataclass(frozen=True)
class PersonaCredential:
    persona: str
    subject: str
    jti: str
    kind: str                # person | platform


def verify_persona_credential(db: Session, token: str) -> PersonaCredential:
    """The persona delegation `token` acts as, or `UseRefused`."""
    from prism.trust import use_verdict as shared
    from prism.trust.service_identity import SERVER_DELEGATION_SIGNERS

    from origin.models.key_custody import DelegationRecord
    from origin.services import not_before
    from origin.services.auth_verifier import verify_token

    if not token:
        raise UseRefused("no acting credential")
    claims = verify_token(token)
    if not claims or claims.get("iss") != config.AUTHORITY_ISSUER:
        raise UseRefused("not a live credential Origin issued")
    if claims.get("principal_type") != "delegation" or claims.get("token_type"):
        raise UseRefused("a secret is used only on a persona's delegation")
    act = claims.get("act") if isinstance(claims.get("act"), dict) else {}
    persona = str(act.get("iss") or "")
    if persona not in SERVER_DELEGATION_SIGNERS or act.get("sub") != shared.SERVER_PREFIX + persona:
        raise UseRefused("the delegation's actor is not a persona proven by its own key")
    subject, jti = str(claims.get("sub") or ""), str(claims.get("jti") or "")
    if not subject or not jti:
        raise UseRefused("the delegation names no subject or carries no jti")
    if not_before.ended(db, claims):
        raise UseRefused("a delegation issued before its person signed out")
    row = db.get(DelegationRecord, jti)
    if row is None or row.subject != subject or (row.signer or "") != persona:
        raise UseRefused("a delegation Origin holds no record of, for this subject and persona")
    if row.revoked_at is not None:
        raise UseRefused("a revoked delegation")

    scope = claims.get("scope")
    aud = claims.get("aud")
    if scope is not None and shared.SYSTEM_SCOPES.get(str(scope)) == persona:
        from origin.service_identity import get_system_principal_id
        if aud != "mantle" or subject != (get_system_principal_id() or None):
            raise UseRefused("a platform purpose's delegation for another principal")
        return PersonaCredential(persona, subject, jti, "platform")
    scopes = str(scope or "").split()
    if aud != "mantle" or any(
            not s.startswith(f"persona:{persona}") for s in scopes):
        raise UseRefused("a delegation issued for another purpose or addressed elsewhere")
    from origin.services.share_credentials import CredentialRefused, _live_person
    try:
        _live_person(db, subject)
    except CredentialRefused as exc:
        raise UseRefused(str(exc)) from None
    return PersonaCredential(persona, subject, jti, "person")


def _grant(rc, subject: str, node: str, action: str) -> Optional[str]:
    if rc.denies(subject, node, action):
        return None
    return rc.reach_grant(subject, node, action)


def decide(db: Session, cred: PersonaCredential, credential_id: str, card_id: str) -> dict:
    """The three grants that allow this use, by Origin's own walk; `UseRefused` otherwise."""
    from prism.trust import use_verdict as shared

    from origin.services import authority_ledger

    rc = authority_ledger.reach(db)
    grants = {
        "invoke_card": _grant(rc, cred.subject, card_id, "invoke"),
        "invoke_credential": _grant(rc, cred.subject, credential_id, "invoke"),
        "read": _grant(rc, shared.SERVER_PREFIX + cred.persona, credential_id, "read"),
    }
    if not grants["invoke_card"] or not grants["invoke_credential"]:
        raise UseRefused("the subject holds no Invoke on the card and its credential")
    if not grants["read"]:
        raise UseRefused(f"{cred.persona} holds no Read of its own on the credential")
    return grants


def _system_id() -> str:
    from origin.service_identity import get_system_principal_id
    return get_system_principal_id() or ""


def system_written(rc, credential_id: str) -> bool:
    """Is `credential_id` the platform system principal's (reviews 24 and 25): its creation edge
    added by the system principal, or stated by the cutover bootstrap (no one recorded as adding
    it) under a collection where the system principal holds Admin."""
    system = _system_id()
    if not system:
        return False
    creator = rc.r.origin_added_by(credential_id)
    if creator:
        return creator == system
    parent = rc.origin_parent(credential_id)
    return bool(parent and parent[0]) and rc.reaches(system, str(parent[0]), "admin")


def may_record(rc, subject: str, kind: str, credential_id: str) -> bool:
    """May this subject's record of the credential's seals stand, now? A seed's, while the
    credential is the system's; anyone else's, while they reach it for Update with no deny on
    Update up its creation chain."""
    if kind == "seed" or (subject and subject == _system_id()):
        return system_written(rc, credential_id)
    return bool(_grant(rc, subject, credential_id, "update"))


def _seals(db: Session, credential_id: str, persona: str) -> tuple:
    """`(sealed_sha256, endpoints_sha256)` recorded for this persona, while its recorder may still
    have made it (review 25, M2); otherwise `UseRefused` until someone who may reseals it."""
    import json

    from origin.models.credential_seal import CredentialSeal
    from origin.services import authority_ledger

    row = db.get(CredentialSeal, credential_id)
    sealed = (json.loads(row.sealed_sha256 or "{}") if row is not None else {}).get(persona)
    if row is None or not sealed:
        raise UseRefused("no seal of this credential for this persona was recorded by its writer; "
                         "its Admin writes it again")
    if not may_record(authority_ledger.reach(db), str(row.recorded_by or ""), "", credential_id):
        raise UseRefused("the seal record was made by someone who may no longer update the "
                         "credential; someone who may writes it again")
    return str(sealed), str(row.endpoints_sha256)


def _digest(value) -> bool:
    import re
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def record_seals(db: Session, cred, rc, credential_id: str, sealed_sha256: dict,
                 endpoints_sha256: str) -> None:
    """Keep the digests of a credential's sealed copies (`may_record`): from a subject who may
    update it now (review 24, M1), by Origin's own walk with no deny on Update up its creation
    chain; or, on the operator's seed credential, for a credential the system principal wrote
    (`system_written`, which counts a bootstrap-stated edge under a collection the system
    administers, review 25). A record replaces the one before it, except that a seed never
    replaces a person's (review 25, L1). Each verdict asks again whether the record's maker may
    still have made it (`_seals`). Otherwise `UseRefused`."""
    import json
    from datetime import datetime, timezone

    from origin.models.credential_seal import CredentialSeal

    if (not isinstance(sealed_sha256, dict) or not sealed_sha256
            or not all(isinstance(k, str) and 0 < len(k) <= 32 and _digest(v)
                       for k, v in sealed_sha256.items())
            or not _digest(endpoints_sha256)):
        raise ValueError("digests are SHA-256 hex, by persona")
    if not may_record(rc, cred.subject, cred.kind, credential_id):
        raise UseRefused("a seed records seals only for a credential the system wrote"
                         if cred.kind == "seed" else
                         "only someone who may update the credential records its seals")
    prior = db.get(CredentialSeal, credential_id)
    # A seed never replaces a person's record (review 25, L1).
    if cred.kind == "seed" and prior is not None and prior.recorded_by             and prior.recorded_by != cred.subject:
        raise UseRefused("a seed does not replace a person's record of a credential's seals")
    row = prior or CredentialSeal(credential_id=credential_id)
    row.sealed_sha256 = json.dumps(sealed_sha256, sort_keys=True)
    row.endpoints_sha256, row.recorded_by = endpoints_sha256, cred.subject
    row.updated_at = datetime.now(timezone.utc)
    db.merge(row)
    db.commit()
    logger.warning("credential seals recorded: credential=%s personas=%s by=%s (%s)",
                   credential_id, sorted(sealed_sha256), cred.subject, cred.kind)


def _spend_nonce(db: Session, persona: str, nonce: str, until) -> bool:
    """Record a persona's use nonce in its own table (`use_nonces`, review 23); False when it was
    already spent. Expired ones are dropped."""
    import hashlib
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import delete
    from sqlalchemy.exc import IntegrityError

    from origin.models.key_custody import UseNonce

    now = datetime.now(timezone.utc)
    db.execute(delete(UseNonce).where(UseNonce.expires_at < now - timedelta(seconds=5)))
    db.add(UseNonce(nonce_key=hashlib.sha256(f"{persona}:{nonce}".encode()).hexdigest(),
                    expires_at=until))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return False
    return True


def issue(db: Session, token: str, credential_id: str, card_id: str, nonce: str = "") -> str:
    """Verify, decide and sign; the verdict, or `UseRefused`."""
    from datetime import datetime, timedelta, timezone

    from prism.trust import use_verdict as shared

    from origin.services.auth_service import issue_use_verdict

    from prism.trust.service_identity import PERSONA_NAMES

    cred = verify_persona_credential(db, token)
    if cred.persona not in PERSONA_NAMES:
        # A secret is used by a persona alone; Crystal holds a server delegation and uses none
        # (review 29, I2).
        raise UseRefused("a secret is used only by a persona")
    grants = decide(db, cred, credential_id, card_id)
    sealed, endpoints = _seals(db, credential_id, cred.persona)
    until = datetime.now(timezone.utc) + timedelta(seconds=shared.VERDICT_TTL * 2)
    if not _spend_nonce(db, cred.persona, nonce, until):
        raise UseRefused("this nonce was already used for a verdict")
    verdict = issue_use_verdict(persona=cred.persona, subject=cred.subject,
                                delegation_jti=cred.jti, credential_id=credential_id,
                                card_id=card_id, grants=grants, sealed_sha256=sealed,
                                endpoints_sha256=endpoints, nonce=nonce)
    logger.warning("secret use allowed: persona=%s for=%s (%s %s) credential=%s card=%s "
                   "grants=%s", cred.persona, cred.subject, cred.kind, cred.jti, credential_id,
                   card_id, grants)
    return verdict

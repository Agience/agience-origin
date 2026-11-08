"""The fifth review's cases, each asserting the safe outcome (in-process app, temp DB).

A batch is Origin's to issue and a creation grant is the first grant on what that batch created;
restating an edge creates nothing; an edge's mask is Admin's; Read does not replace a share; a
retried withdrawal never lifts a deny."""
from __future__ import annotations

import pytest

from origin.tests import authority_fixtures as af
from origin.tests import test_a_key_share_is_released_only_to_mantle as _shares

custody_client = _shares.custody_client
ALL = ["create", "read", "update", "delete", "evict", "add", "share", "admin"]


@pytest.fixture
def people(custody_client):
    return {n: af.person(n, email=f"{n}@team.test") for n in ("alice", "bob", "carol")}


def test_a_batch_name_reused_later_regains_nothing(custody_client, people):
    """Carol creates K in batch kb, hands admin to Bob, Bob revokes Carol. A later submission
    in the same batch name re-opens the creation grant."""
    c = custody_client
    carol, bob = people["carol"], people["bob"]
    af.ok(af.submit(c, carol[1], af.root("K"), batch="kb"))
    af.ok(af.submit(c, carol[1], af.grant("g-ck", carol[0], "K", ALL), batch="kb"))
    af.ok(af.submit(c, carol[1], af.grant("g-bk", bob[0], "K", ALL), batch="kb"))
    af.store_share(c, "ck:K")
    assert af.release(c, "ck:K", carol[1]).status_code == 200
    af.ok(af.submit(c, bob[1], af.grant("g-ck", carol[0], "K", ALL, state="revoked"),
                    batch="bob-op"))
    assert af.release(c, "ck:K", carol[1]).status_code == 403
    # a different operation reusing the batch name
    r = af.submit(c, carol[1], af.grant("g-ck-again", carol[0], "K", ALL), batch="kb")
    af.release(c, "ck:K", carol[1])
    assert r.status_code == 403, "batch reuse re-opened the creation grant"


def test_restating_a_creation_edge_creates_nothing(
        custody_client, people):
    """Bob holds read+add on Alice's W; X is Alice's member of W. Bob restates X's creation
    edge (None -> full list, no narrowing) and then files a 'creation grant' on X."""
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    af.ok(af.submit(c, alice[1], af.root("W"), batch="a1"))
    af.ok(af.submit(c, alice[1], af.grant("g-aw", alice[0], "W", ALL), batch="a1"))
    af.ok(af.submit(c, alice[1], af.edge("W", "X"), batch="a2"))
    af.ok(af.submit(c, alice[1], af.grant("g-bw", bob[0], "W", ["read", "add", "share"]),
                    batch="a3"))
    full = ["create", "read", "update", "delete", "evict", "invoke", "add", "share", "admin"]
    af.submit(c, bob[1], af.edge("W", "X", propagate=full), batch="bobx")
    r2 = af.submit(c, bob[1], af.grant("g-bx", bob[0], "X", ["read", "add", "share"]),
                   batch="bobx")
    # Alice revokes Bob on W; his direct grant on X stays
    af.ok(af.submit(c, alice[1], af.grant("g-bw", bob[0], "W", ["read", "add", "share"],
                                          state="revoked"), batch="a4"))
    af.submit(c, bob[1], af.invite("inv-x", "tok", "X", ["read", "add"]), batch="bob2")
    af.submit(c, bob[1], af.edge("X", "Y"), batch="bob3")
    assert r2.status_code == 403, "a creation grant attached to an id not created in the batch"


def test_a_restated_edge_and_a_root_for_a_seen_id_create_nothing(custody_client, people):
    """As P2, then a root entry for X in the same batch, then a grant with admin."""
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    af.ok(af.submit(c, alice[1], af.root("W"), batch="a1"))
    af.ok(af.submit(c, alice[1], af.grant("g-aw", alice[0], "W", ALL), batch="a1"))
    af.ok(af.submit(c, alice[1], af.edge("W", "X"), batch="a2"))
    af.ok(af.submit(c, alice[1], af.grant("g-bw", bob[0], "W", ["read", "add"]), batch="a3"))
    full = ["create", "read", "update", "delete", "evict", "invoke", "add", "share", "admin"]
    af.submit(c, bob[1], af.edge("W", "X", propagate=full), batch="bobx")
    af.submit(c, bob[1], af.root("X", "W"), batch="bobx")
    r3 = af.submit(c, bob[1], af.grant("g-bx", bob[0], "X", ALL), batch="bobx")
    assert r3.status_code == 403


def test_add_does_not_narrow_another_member_s_edge(custody_client, people):
    """Bob holds only add on W. He narrows the creation edge of Alice's X to conduct nothing."""
    c = custody_client
    alice, bob, carol = people["alice"], people["bob"], people["carol"]
    af.ok(af.submit(c, alice[1], af.root("W"), batch="a1"))
    af.ok(af.submit(c, alice[1], af.grant("g-aw", alice[0], "W", ALL), batch="a1"))
    af.ok(af.submit(c, alice[1], af.edge("W", "X"), batch="a2"))
    af.ok(af.submit(c, alice[1], af.grant("g-cw", carol[0], "W", ["read"]), batch="a2"))
    af.ok(af.submit(c, alice[1], af.grant("g-bw", bob[0], "W", ["add"]), batch="a3"))
    r = af.submit(c, bob[1], af.edge("W", "X", propagate=[]), batch="b")
    assert r.status_code == 403


def test_read_alone_does_not_replace_a_share(custody_client, people):
    """Bob holds read alone on Alice's C. Origin's share of ck:C is replaced on his credential
    with a share of another key, naming the old kcv as superseded."""
    import base64
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    af.ok(af.submit(c, alice[1], af.root("C"), batch="a1"))
    af.ok(af.submit(c, alice[1], af.grant("g-ac", alice[0], "C", ALL), batch="a1"))
    af.ok(af.submit(c, alice[1], af.grant("g-bc", bob[0], "C", ["read"]), batch="a2"))
    assert af.store_share(c, "ck:C", credential=alice[1]).status_code == 200
    other = base64.b64encode(bytes(range(100, 132))).decode()
    r = af.store_share(c, "ck:C", credential=bob[1], y=other, kcv=_shares.KCV_B,
                       supersedes=_shares.KCV_A)
    assert r.status_code == 403, "Read alone replaced Origin's share of the collection key"


@pytest.fixture
def system(custody_client, monkeypatch):
    from origin import service_identity

    sys_id = "00000000-0000-0000-0000-00000000aaaa"
    monkeypatch.setattr(service_identity, "get_system_principal_id", lambda: sys_id)
    return sys_id, af.background(sys_id)


def test_a_retried_withdrawal_never_lifts_a_deny(
        custody_client, people, system):
    """Alice (admin) denies Bob read on C. Mantle never confirms. Later, under a background
    delegation, Mantle 'retries a withdrawal' and the deny is gone."""
    from datetime import datetime, timedelta, timezone
    from origin.db.session import SessionLocal
    from origin.models.authority_ledger import AuthorityEntry
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    _sys, bg = system
    af.ok(af.submit(c, alice[1], af.root("C"), batch="a1"))
    af.ok(af.submit(c, alice[1], af.grant("g-ac", alice[0], "C", ALL), batch="a1"))
    af.ok(af.submit(c, alice[1], af.grant("g-bc", bob[0], "C", ["read"]), batch="a2"))
    af.store_share(c, "ck:C", credential=alice[1])
    assert af.release(c, "ck:C", bob[1]).status_code == 200
    d = af.ok(af.submit(c, alice[1], af.grant("g-deny", bob[0], "C", ["read"], effect="deny"),
                        batch="a3"))
    assert af.release(c, "ck:C", bob[1]).status_code == 403
    with SessionLocal() as db:                                   # a day passes
        row = db.get(AuthorityEntry, d["seq"])
        row.created_time = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()
    r = af.submit(c, bg, af.grant("g-deny", bob[0], "C", ["read"], effect="deny",
                                  state="retired"), compensates=d["seq"], batch="retry")
    assert r.status_code == 403


def test_a_batch_is_issued_by_origin_to_one_credential_for_a_short_window(custody_client, people,
                                                                         monkeypatch):
    from origin.services import authority_ledger

    c = custody_client
    alice, bob = people["alice"], people["bob"]
    first = af.ok(af.submit(c, alice[1], af.root("Q"), batch=None))
    assert first["batch"]
    tok_extra = {"htu": "/internal/authority/entries"}

    def send(cred, entry, batch, proof=None):
        from origin.services.authority_ledger import body_digest, proof_digest
        extra = dict(tok_extra)
        if proof:
            extra["proof_sha256"] = proof_digest(proof)
        tok = _shares._token("POST", "-", body_sha256=body_digest(entry), batch=batch, **extra)
        body = {"entry": entry, "bootstrap": False, "batch": batch}
        if proof:
            body["proof"] = proof
        return c.post("/internal/authority/entries", json=body,
                      headers={"Authorization": f"Bearer {tok}", "X-Acting-Credential": cred})

    # Bob cannot submit in Alice's batch, even to create something of his own.
    r = send(bob[1], af.root("Bobs"), first["batch"], proof=af.creation(bob[1]))
    assert r.status_code == 403 and "batch" in r.json()["detail"]
    assert send(alice[1], af.grant("g-q", alice[0], "Q", ALL), "chosen-by-me").status_code == 403
    monkeypatch.setattr(authority_ledger, "BATCH_WINDOW_SECONDS", -1)
    assert send(alice[1], af.grant("g-q", alice[0], "Q", ALL), first["batch"]).status_code == 403
    monkeypatch.setattr(authority_ledger, "BATCH_WINDOW_SECONDS", 60)
    assert send(alice[1], af.grant("g-q", alice[0], "Q", ALL), first["batch"]).status_code == 200


def _activate(c, principal, credential):
    """On the acting credential of one holding Admin on what the key keys (review 25)."""
    tok = _shares._token("POST", principal, htu=f"/internal/key-shares/{principal}/activate")
    return c.post(f"/internal/key-shares/{principal}/activate",
                  headers={"Authorization": f"Bearer {tok}", "X-Acting-Credential": credential})


def test_a_share_is_replaced_only_while_marked_and_by_admin_and_the_old_one_is_kept(
        custody_client, people):
    import base64
    from origin.db.session import SessionLocal
    from origin.models.key_custody import KeyCustodyShareHistory

    c = custody_client
    alice = people["alice"]
    af.ok(af.submit(c, alice[1], af.root("C"), batch="a1"))
    af.ok(af.submit(c, alice[1], af.grant("g-ac", alice[0], "C", ALL), batch="a1"))
    assert af.store_share(c, "ck:C", credential=alice[1]).status_code == 200
    other = base64.b64encode(bytes(range(100, 132))).decode()
    r = af.store_share(c, "ck:C", credential=alice[1], y=other, kcv=_shares.KCV_B,
                       supersedes=_shares.KCV_A)
    assert r.status_code == 200 and r.json()["outcome"] == "replaced"   # not yet activated
    assert _activate(c, "ck:C", alice[1]).status_code == 200
    third = base64.b64encode(bytes(range(50, 82))).decode()
    r = af.store_share(c, "ck:C", credential=alice[1], y=third, kcv="c" * 32,
                       supersedes=_shares.KCV_B)
    assert r.status_code == 403 and "re-key" in r.json()["detail"]    # activated: fixed
    with SessionLocal() as db:
        kept = [h.kcv for h in db.query(KeyCustodyShareHistory).filter_by(principal_id="ck:C")]
    assert kept == [_shares.KCV_A]


def test_only_the_seed_or_bootstrap_credential_marks_a_share_for_re_key(custody_client, people,
                                                                       monkeypatch):
    c = custody_client
    alice = people["alice"]
    af.ok(af.submit(c, alice[1], af.root("C"), batch="a1"))
    af.ok(af.submit(c, alice[1], af.grant("g-ac", alice[0], "C", ALL), batch="a1"))
    af.store_share(c, "ck:C", credential=alice[1])
    _activate(c, "ck:C", alice[1])
    path = "/internal/key-shares/ck:C/rekey-pending"
    tok = _shares._token("POST", "ck:C", htu=path)
    assert c.post(path, headers={"Authorization": f"Bearer {tok}",
                                 "X-Acting-Credential": alice[1]}).status_code == 403
    boot = af.open_bootstrap(c, af.operator(monkeypatch), ids=["C"])   # its window lists C
    tok = _shares._token("POST", "ck:C", htu=path)
    assert c.post(path, headers={"Authorization": f"Bearer {tok}",
                                 "X-Acting-Credential": boot}).status_code == 200


def test_the_feed_serves_entries_after_a_seq(custody_client, people):
    c = custody_client
    alice = people["alice"]
    a = af.ok(af.submit(c, alice[1], af.root("F1"), batch="f"))
    b = af.ok(af.submit(c, alice[1], af.root("F2"), batch="g"))
    tok = _shares._token("GET", "-", htu="/internal/authority/feed")
    r = c.get(f"/internal/authority/feed?after={a['seq']}",
              headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200 and [e["seq"] for e in r.json()["entries"]] == [b["seq"]]


def test_delete_on_the_collection_does_not_remove_a_member_s_edge(custody_client, people):
    """Evict removes a secondary edge (architecture §51), or Admin, or Delete reaching the member
    itself; Delete on the collection alone does not, as Mantle's own removal route asks for Evict
    or Admin. Removing a creation edge deletes the member, so Evict alone does not remove that one
    (review 15)."""
    c = custody_client
    alice, bob = people["alice"], people["bob"]
    af.ok(af.submit(c, alice[1], af.root("W"), batch="a1"))
    af.ok(af.submit(c, alice[1], af.grant("g-aw", alice[0], "W", ALL), batch="a1"))
    af.ok(af.submit(c, alice[1], af.edge("W", "X", propagate=["read"]), batch="a2"))  # no delete
    af.ok(af.submit(c, alice[1], af.grant("g-bw", bob[0], "W", ["delete"]), batch="a3"))
    assert af.submit(c, bob[1], af.unedge("W", "X"), batch="b").status_code == 403
    af.ok(af.submit(c, alice[1], af.grant("g-bw", bob[0], "W", ["evict"]), batch="a4"))
    assert af.submit(c, bob[1], af.unedge("W", "X"), batch="b2").status_code == 403
    af.ok(af.submit(c, alice[1], af.root("Y"), batch="a5"))
    af.ok(af.submit(c, alice[1], af.grant("g-ay", alice[0], "Y", ALL), batch="a5"))
    af.ok(af.submit(c, alice[1], af.edge("W", "Y", origin=False), batch="a6"))
    af.ok(af.submit(c, bob[1], af.unedge("W", "Y"), batch="b3"))

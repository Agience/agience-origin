"""Review 25, M2, M3 and L1: a seal record holds only while its recorder may make it.

M2: a record was checked against its recorder's authority only when it was made, so one Mantle
recorded on a subject later revoked stood for every later verdict. At verdict time Origin now asks
again: the recorder still reaches the credential for Update with no deny up its creation chain,
or, for a seed's record, the credential is still the system principal's. Otherwise no verdict
until someone who may reseals it.

M3: a credential the cutover bootstrap stated has a creation edge nobody is recorded as adding,
so a seed could not record its seals, and the platform mail secrets could get no verdict. Such an
edge, under a collection where the system principal holds Admin, counts as the system's.

L1: a seed never replaces a person's record.
"""
from __future__ import annotations

from jose import jwt as jose_jwt

from origin.tests import authority_fixtures as af
from origin.tests import test_review21_a_secret_is_used_only_on_origin_s_verdict as r21
from origin.tests import test_review22_a_verdict_binds_the_sealed_copy as r22
from origin.tests import test_review23_only_a_credential_s_creator_records_its_seals as r23
from origin.tests import test_review24_seals_are_recorded_on_current_authority as r24

custody_client = r21.custody_client
unsealed_world = r21.unsealed_world
PLATFORM, AUTHORIZER = "platform-collection", "platform-email-authorizer-secret"


def _carol_records(c, alice):
    carol = af.person("Carol")
    af.ok(af.submit(c, alice[1], af.grant("g-carol", carol[0], r21.SHELF, r24.RIGHTS), batch="c"))
    af.ok(af.submit(c, carol[1], af.edge(r21.SHELF, "team-cred"), batch="c2"))
    assert r22.record(c, r24._mantle_token(carol[0]), cred="team-cred",
                      sealed={"iris": "d" * 64}, endpoints="e" * 64).status_code == 200
    return carol


def test_a_record_does_not_outlive_its_recorder_s_authority(unsealed_world):
    c, alice, bob = unsealed_world
    carol = _carol_records(c, alice)
    af.ok(af.submit(c, alice[1], af.grant("g-carol", carol[0], r21.SHELF, r24.RIGHTS,
                                          state="revoked"), batch="c3"))
    af.ok(af.submit(c, alice[1], af.grant("d-carol", carol[0], r21.SHELF,
                                          ["read", "update", "invoke", "admin"], effect="deny"),
                    batch="c4"))
    v = r24._verdict_for(c, bob, "team-cred")
    assert v.status_code == 403 and "seal" in v.text
    # Alice, who may update it, reseals; the next verdict names her copy.
    assert r22.record(c, alice[1], cred="team-cred").status_code == 200
    v = r24._verdict_for(c, bob, "team-cred" + "")
    claims = jose_jwt.get_unverified_claims(v.json()["verdict"]) if v.status_code == 200 else {}
    assert claims.get("sealed_sha256") == r22.SEALED, v.text


def _bootstrapped(c, monkeypatch, alice=None):
    """The platform collection and its mail secret as `cosign_authority` states them; with
    `alice`, also her Update on the collection."""
    seed = r23._seed(c, monkeypatch)
    ids = [PLATFORM, AUTHORIZER, "g-sys-platform"] + (["g-alice-p"] if alice else [])
    boot = af.open_bootstrap(c, ids=ids)
    af.ok(af.submit(c, boot, af.root(PLATFORM), bootstrap=True, batch=None))
    af.ok(af.submit(c, boot, af.grant("g-sys-platform", r23.SYSTEM, PLATFORM, r21.ALL),
                    bootstrap=True, batch=None))
    if alice:
        af.ok(af.submit(c, boot, af.grant("g-alice-p", alice[0], PLATFORM, ["read", "update"]),
                        bootstrap=True, batch=None))
    af.ok(af.submit(c, boot, af.edge(PLATFORM, AUTHORIZER), bootstrap=True, batch=None))
    return seed


def test_a_seed_records_seals_for_a_credential_the_bootstrap_stated(unsealed_world, monkeypatch):
    c, _alice, _bob = unsealed_world
    seed = _bootstrapped(c, monkeypatch)
    assert r22.record(c, seed, cred=AUTHORIZER).status_code == 200


def test_not_under_a_collection_the_system_principal_administers(unsealed_world, monkeypatch):
    c, alice, _bob = unsealed_world
    seed = r23._seed(c, monkeypatch)
    boot = af.open_bootstrap(c, ids=["alices-old", "g-alice-old", "alice-old-cred"])
    af.ok(af.submit(c, boot, af.root("alices-old"), bootstrap=True, batch=None))
    af.ok(af.submit(c, boot, af.grant("g-alice-old", alice[0], "alices-old", r21.ALL),
                    bootstrap=True, batch=None))
    af.ok(af.submit(c, boot, af.edge("alices-old", "alice-old-cred"), bootstrap=True, batch=None))
    assert r22.record(c, seed, cred="alice-old-cred").status_code == 403


def test_a_seed_never_replaces_a_person_s_record(unsealed_world, monkeypatch):
    c, alice, _bob = unsealed_world
    seed = _bootstrapped(c, monkeypatch, alice=alice)
    assert r22.record(c, alice[1], cred=AUTHORIZER).status_code == 200
    assert r22.record(c, seed, cred=AUTHORIZER).status_code == 403

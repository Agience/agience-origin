# Changelog

All notable changes to `agience-origin` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.21] - 2026-11-12

### Fixed
- The sign-in page names each button and field once (BUG-064). The one-time-code form's button reads "Sign in with this code" and its field "Email to send the code to", and the sign-up form's link reads "Already have an account? Go to sign-in". Before this, a screen reader or a script asking for "Sign in" got three buttons.

## [0.2.20] - 2026-11-11

### Fixed
- A sign-in for an app this sign-in service doesn't list says so: the account page names the app it wasn't sent back to, instead of showing the account with no reason. A listed app that is handed nothing still lands on the account page as before. The sign-up form's password field is labelled "New password", so it is no longer a second "Password" beside the sign-in one.

### Changed
- The home node holds test custody while it is the test gate (John, 2026-11-11): with `AGIENCE_PLANE=home`, an issuer under `home.agience.ai`, no peers (`EMBER_PEERS`) and its own keys folder (`custody_plane.home_test_refusal`), so runs, timers and their approvals can be accepted there before promote. Production never trusts the home issuer. Every other plane but production is still refused, and production's own rule is unchanged.

## [0.2.19] - 2026-11-11

### Fixed
- A step-up's sign-in asks only for the password or passkey (BUG-055): it names the person as OIDC `login_hint`, and Origin's sign-in page fills in the account and puts the cursor in the password. The hint fills in the account and proves nothing; whoever signs in is still checked against the step-up's person.
- A job's key release covers an artifact held in one its grant lists (John, 2026-11-11, BUG-052): `bind_to_job_reach` walks the read chain, as Mantle does, and still opens only the key that artifact is keyed under.
- A refused job grant shows why and offers only Close (BUG-060): Approve stayed on the page, so each click took another sign-in and met the same refusal.

## [0.2.18] - 2026-11-10

### Changed
- Approving a timer or a run, or stopping its grant, asks once (John, 2026-11-10, BUG-055: "Don't duplicate or re-ask"). Origin's job-grant page is the confirmation: its Approve goes straight into the step-up (the passkey prompt with no second confirm, or the sign-in with no start page asking again), and the approval finishes and the window closes on return, with no "Approve again". A stop starts its step-up as the page opens, the app having asked for exactly that. A change to how one signs in keeps its start page.

### Fixed

## [0.2.17] - 2026-11-10

### Added
- A workflow's "Run now" runs on a one-shot job grant (John, 2026-11-10). Job `lumen.run.<workflow>.<nonce>`, made at Origin's `/job-grant` page in the person's Origin session with a step-up, over the person's own key and no collection, naming its `reach` (the workflow, its steps' operators and the items they link). It ends within `RUN_GRANT_MAX_MINUTES` (15; the page asks for 10), and only one delegation is ever minted under it, narrowed to Crystal and carrying the reach; a second, or one for Lumen, is refused. It releases a key share only for an artifact its reach lists, as a timer's does, and never a background delegation. The page and its step-up name it as one run.

## [0.2.16] - 2026-11-10

### Fixed
- A step-up taken at Origin's own sign-in returns to the Origin page that asked for it (BUG-037). Approving a timer, linking or removing a sign-in, or adding a passkey without a passkey sends the person to sign in again; afterwards they were left on "return to Origin's page" with that page gone, in the same tab, so the approval never finished. The confirmation page now goes back to it, an Origin page only, where approving again sends the request on the proven step-up.

## [0.2.15] - 2026-11-10

### Changed
- A timer's firing opens its owner's content key for the artifacts its job grant lists, by id, and for nothing else (John, 2026-11-10). At a key share release, and there alone, Origin takes a persona's server delegation carrying a live timer grant (`job_grant`, `job_reach` equal to the grant's reach) as the person's acting credential for an artifact the grant lists, and only for the key that artifact is keyed under (its creation collection's, or the person's or its root's master key); a release naming no artifact, or another one, or another key, is refused, as is any such delegation once its grant is revoked or over. It still stores no share, writes nothing to the ledger and mints no background delegation.

## [0.2.14] - 2026-11-10

### Added
- A timer runs on a job grant the person approves at Origin (BUG-024, BUG-035; John, 2026-11-10). A job grant may name a `reach`, the ids its delegations touch; a timer's (`lumen.timer.<timer id>`) must, over the person's own key and no collection, and no other grant may. Origin's `/job-grant` page shows the grant and makes it in the person's Origin session behind a step-up bound to its body, then posts its id back to the app's origin only. `POST /internal/job-delegation` mints, for Lumen on its own key, a five-minute delegation narrowed to Lumen or Crystal under the live timer grant it names (never another for the same timer), carrying `job_reach`; the server delegation and every hop exchanged from it keep it. A timer's grant releases no key share.

## [0.2.13] - 2026-11-10

### Changed
- Every persona Chorus hosts is a narrow audience the app may call directly (FR-006, John 2026-11-10): aria, astra, ophan and seraph join iris, lumen, sage and crystal in the defaults (`PERSONA_AUDIENCES`), each with its own `persona:<name>` scope only, and Crystal may hop to each (`NARROW_HOPS`). They were refused with 400 "audience is not a narrow audience".

## [0.2.12] - 2026-11-09

### Added
- `python -m origin.scripts.authority_bootstrap --unseen` reads ids on stdin and prints those no ordinary entry brought into being (`authority_ledger.seen`, the predicate the bootstrap rule itself uses). `--ids-stdin` opens a bootstrap window that lists the ids on stdin, the only kind Origin accepts once its ledger has ordinary entries; a window with no ids is not opened.
- `--probe-owner URL` calls `GET /auth/me/authority/grants` at that Origin as an owner the replica holds: it takes the first active account the replica lets share a resource, opens an Origin session for it, sends the web app's headers, and ends the session. It exits 0 on a 200 only. The release candidate's seed rehearsal runs it; the session's value is never printed.

### Fixed
- `python -m origin.scripts.authority_bootstrap` builds what Origin's startup builds before it reads or signs: the service's `.env`, the signing keys, the encryption key, the nonce and setup secrets, Origin's service identity and the database engine (`origin.process.init_process`, which the startup now calls too). Run as its own process, the credential could not be minted (`JWT keys not initialized`), so the authority-ledger seed of release 2026.11.3 did not run.

## [0.2.12] - 2026-11-09

### Fixed
- `python -m origin.scripts.authority_bootstrap` builds Origin's database engine itself (`init_engine()`), from the settings Origin's startup reads. Run as a process of its own, as the release tool runs it, every mode failed with `Session factory not initialized`, so the authority-ledger seed of release 2026.11.2 did not run.

## [0.2.12] - 2026-11-09

### Added
- `python -m origin.scripts.authority_bootstrap`, run on Origin's host as its service user, mints the platform operator's authority-ledger bootstrap credential with no HTTP call: the host is the trust root. stdout carries only the credential, one line; it is never logged. `--minutes N` sets its life, 1 to 30 (default 30); no operator, no database or a failed mint exits non-zero with a stderr line. `--close` withdraws every open bootstrap window, as `DELETE /oracle/authority-ledger/bootstrap` does, and prints `bootstrap closed: <n> window(s)`. `--count` prints `grants=<n> roots=<n> edges=<n>` from the replica tables, so the release tool can check a seed.

### Security
- An invite mail carries one link, Origin's own `/invite/<token>`. The inviter's display name and the resource name they typed are defanged in the subject, the plain-text part and the HTML part (`origin.services.defang`, the website's lead-mail rules): `https://` becomes `hxxps://`, other link schemes have a letter bracketed, every host dot is bracketed (full-width and ideographic dots, Unicode, lookalike and punycode hosts, IPv4 included), and markdown links and HTML anchors become their text with the target defanged. The HTML escapes all of it; no inviter text sits inside an anchor.
- The mail names its sender by display name and verified address. `POST /auth/me/authority/invites` from an account whose address is not verified is refused (403) and nothing is mailed or recorded. `email_service.send_invite` takes the sender's address (`from_email`) and no longer takes a personal message: no route ever passed one.

## [0.2.12] - 2026-11-09

### Fixed
- Origin's pages name their scripts and stylesheets by content (`/web/app.js?v=<sha256 prefix>`), and the pages and `/web/*` are served with `Cache-Control: no-cache`, revalidated by ETag. After a release a browser kept the previous release's unversioned `/web/app.js`, cached by heuristic, against the new pages, and its sign-in looped back to `/login`.

## [0.2.12] - 2026-11-08

### Security
- `/auth/authorize` delivers a code only to a redirect URI configured for the client, compared whole: a first-party client's entry in the new `CLIENT_REDIRECT_URIS` (a JSON object, client id to exact URIs), or a registered client's own registration. No redirect target exists in code: the tool pages (`vscode.dev`, `oauth.pstmn.io`), `PLATFORM_DEV_REDIRECTS`, the built-in loopback allowance and the local-development port range are removed, and `FACET_URI`, `FACET_URIS` and `ORIGIN_URI` no longer admit redirects. A listed http loopback URI admits any port (RFC 8252 §7.3). Every refusal is a 403 naming the setting; a URI on Mantle's origin is refused whatever lists it.
- `POST /auth/register` records only redirect URIs listed in the new `CLIENT_REGISTRATION_REDIRECT_URIS`; empty refuses every one (400 `invalid_redirect_uri`).
- PKCE with S256 is required on every authorization-code flow: a missing `code_challenge`, `plain`, or a challenge that is not a 43-character base64url digest is refused (400).
- An authorization code is single-use from the first exchange attempt: a wrong client, redirect URI or verifier spends it. It lives 60 seconds and is redeemed only with the exact redirect URI it was issued for.
- A first-party code delivered anywhere but the web app (`APP_URI`), Origin's own pages, or a facet in `NARROW_FACETS` is answered with no token.
- One account per address, however the address is written. Every address Origin stores or looks up goes through one canonical form (`services.email_address`): stripped, lower-cased, the domain without a trailing dot and in its IDNA ASCII form (punycode), exactly one `@`. `john@ikailo.com.` and `anna@bücher.de` find the accounts at `john@ikailo.com` and `anna@xn--bcher-kva.de`. Registration (`/auth/password/register`, `/auth/authorize/register`), the setup wizard, the bootstrap claim and the manifest operator refuse an address that is not already canonical apart from case and surrounding space, and rewrite none; sign-in codes, password reset, the verification resend, passkey sign-in, invites, and an address a provider asserts are canonicalised, not refused. Plus-addressing and dots in the local part stay distinct. `python -m origin.admin person noncanonical` lists, read-only, every stored address that is not canonical, with the canonical form and who holds it; the operator deactivates such a row by its id (`person deactivate <id> --reason ...`), since its address now finds the canonical account. No stored address is changed.

### Removed
- The retired `lumen.agience.ai` site is gone from the suite: the sign-in and return-list tests use a neutral listed SP (`sp.agience.ai`), and the `/auth/userinfo` case for a narrowed delegation is stated for the staging gate, the one `forward_auth` that still asks it. `NARROWED_ROUTES` keeps `GET /auth/userinfo` for that gate.

### Fixed (release build)
- Reviews 17–19's cross-repository cases skip, with the reason, where Mantle or Crystal is not importable: a lone checkout of Origin, as GitHub's build runs it, failed 31 of them on the import. The sovereign CI's workspace has both and runs them all.

### Fixed (local check, 2026-11-08)
- A password sign-in, a registration that signs in, or a mailed-code sign-in on Origin's own page (`/auth/password/login`, `/auth/password/register`, `/auth/otp/verify`, with Origin's own origin as `Origin` or `Referer`) starts the person's Origin session, as `/auth/authorize`'s form does: HttpOnly, SameSite=Strict, `__Host-` on https. One posted from any other page starts none.
- `is_client_redirect_allowed` refuses Mantle's origin (scheme, host and port), not every port on Mantle's host, so Origin's own `/auth/reauth/complete` stays a redirect base on a single-host install. Mantle's origin is refused through the local-development range and the loopback rule too.
- The step-up for `POST /auth/me/job-grants` needs the request's body, and its confirm page names the job, its collections and its expiry; one asked for with the digest alone is refused (400). A revoke's page names the grant it stops.
- `GET /auth/me/authority/grants` gives a person grantee's display name (`grantee_name`) and an invite's `claims` and `max_claims`; the preview names a grantee of the item itself, never one on a parent. `POST /auth/me/authority/invite-context` says whether the signed-in person's own address is verified (`address_verified`).
- `POST /auth/me/authority/mantle-token` takes `expect_sub`, the person the web app signed in, and answers 409 when the browser's Origin session is someone else's.
- The redirect check treats every loopback spelling of Mantle's host (`localhost`, `127.0.0.1`, `::1`) as Mantle's origin.
- Origin's sign-in page hands a token only to a listed return URI (`sso_return_uris`): the web app (`app_uri`) gets the person's token, and any other listed service provider a delegation narrowed to its origin in the person's Origin session, or nothing. Mantle's origin is never the app nor a listed return, from any setting.
- Deactivating a person revokes their Origin sessions, and every session route refuses a deactivated person.
- `GET /logout` and `POST /auth/sign-out` end the Origin session the browser carries: the session is revoked and its cookie deleted under both names (`__Host-` and plain). Signing out everywhere still ends every one of the person's sessions.
- A job grant's confirm page names its expiry first and as many collections as fit, then "and N more"; one that cannot be named whole starts no step-up (400).
- A new account's display name is the one the person gives, or none; it is never made from the address or username.
- On https Origin refuses to start when `APP_URI` is its own origin (`ORIGIN_URI` or `AUTHORITY_ISSUER`).

### Changed (review 35)
- A new rotation record revokes the earlier record's custody grant before it is committed; a grant is bound to a record by one conditional update, and a grant that loses the race is revoked and refused.
- `GET /oracle/charged-roots/shares` gives each pending root's `pending_detail` (`share_written`, `released_since_record`).

### Changed (review 34)
- Activation over a charged root spends its rotation record: the activated kcv is never recorded again, even after a seed's re-mark.
- A new rotation record revokes the custody grant bound to the record before it.

### Changed (review 33)
- A charged root's rotation is recorded again with the same kcv when its pending share was written under an earlier record of that kcv (a split whose read-back failed at Mantle); the new record still needs a fresh write before any release.
- Activation over a charged root takes only the recorded key's share, written under the record.
- `charged_root_rotations.recorded_time` is set by the record alone.

### Changed (review 32)
- A charged root's rotation record refuses a kcv Origin holds or held a share of, and its share is released only once a share of the recorded kcv was written after the record (`charged_root_rotations.share_written`).
- Each record opens its split under one custody grant, the first made after it (`grant_id`); the split closes when that grant ends, and a later grant needs a new record of a fresh kcv. Under a record, the split's store replaces a pending share of an earlier key.
- `GET /oracle/charged-roots/shares` lists each charged root's share as activated, pending or none, by count and id (step 23's check).

### Changed (review 31)
- The operator grants `platform.custody` over a charged root only once step 21's rotation is recorded for it (`POST /oracle/charged-roots/{principal}/rotation` with the rotated key's `kcv`, migration `0030_charged_root_rotations`), for two hours at most. Origin stores that root's share only for the recorded key, releases it only while that pending share is read back, and revokes the grant when the share is activated.
- The withdrawal of a creation whose write never committed (a compensating `edge.remove`) charges no root; a Trash purge, a real removal, still does.
- `_apply` and `replay` charge a historical demotion as migration `0029` does, and `0029` charges each removal to the root its source sat under at that entry, in ledger order, so `verify_chain` passes on a migrated ledger.
- The `agience-prism[trust]` floor is 0.1.9.

### Changed (review 30)
- A charged root (a part of it removed) stays charged: its master key opens for its own principal alone, and the operator may grant `platform.custody` over it; `root.confirm_empty` and its console route are removed, the kind kept only so an older ledger replays. `principal-kinds` names the charged roots.
- A creation edge is removed, never demoted, by bootstrap too, and bootstrap gives a gone node no creation edge; migration `0029` charges past demotions.
- `verify_chain` replays removal charges; a memoized full reader-Admin answer lapses at the earliest expiry it rested on; the platform's own principals include Crystal's server principal.

### Changed (review 29)
- Once a node under a root is removed, the root's master key opens for its own principal alone, and no job is granted over it, until the operator confirms on the console that nothing is left under it (`POST /oracle/authority-ledger/confirm-empty`, a `root.confirm_empty` entry); migration `0029_root_part_removed` records removals, past ones included.
- A full reader-Admin is never of a platform principal; the walk reads grants once, fails closed past the walk ceiling, and is memoized per ledger head.
- A use verdict is a persona's alone; Crystal gets none.

### Changed (review 28)
- A root's master key is released to a full reader-Admin of the root (Admin on it, Read on everything under it, no deny), and only such a subject grants a job over it.
- Crystal's own server delegation is a persona's delegation, by prism's one list of services that hold one, with verdicts bounded to read, invoke and create; it releases no key.
- A share release says whether the share is pending; `principal-kinds` says `member` for a node with a creation parent.

### Changed (review 27)
- `POST /internal/authority/principal-kinds` says what each key principal is by Origin's replica (person, collection key, platform, root, unknown), for Mantle's counts and gate.
- A root's Admin grants `platform.custody` and `platform.rekey` over the root's own master key; the operator's `platform.custody` grant names only the platform user, the system principal or a persona's server principal.
- A persona's server delegation is no acting credential, whoever signed its exchange; `/internal/delegation-token` exchanges only a delegation narrowed to the asking persona.
- The storer of a first share may replace it while it is pending; marking a share for re-key is refused off isolated production; `verify_token` refuses a service token with no `exp`.

### Changed (review 26)
- The operator grants `platform.custody` over a non-person principal's key (`POST /oracle/job-grants` with `principal`); a person's key and a collection's stay theirs and their Admins' to grant.
- A persona's server delegation makes ledger entries on one bounded path: a new member for its person, by its creation edge, and its person's creation grant on it.
- Whoever stored a key's first share may activate it, until its first activation (migration `0028_share_stored_by`); activation is refused off isolated production.
- `verify_token` refuses an Origin-signed token with no `exp`.

### Changed (review 25)
- `/internal/authority/reach` answers a persona's server delegation and Iris's platform mail delegation, verified by the use verdict's own definition and bounded to the actions they take; key release never takes them.
- A seal record gives a verdict only while its recorder may still make it; a bootstrap-stated credential under a collection the system principal administers counts as system-written; a seed never replaces a person's record.
- A seed credential is minted with the digests of its pass's planned entries (`plan`) and makes no others; every grant on a seed raises a `seed_grant` alert (migration `0027_seed_plan`).
- Activating a key share takes the acting credential of the key's principal or an Admin on what it keys.
- `verify_token` reads a token whose claims have the wrong type as no token.

### Changed (review 24)
- A credential's seal record is kept from a subject who may update it now (Update by Origin's walk, no deny up its creation chain), replacing creator only; a seed still counts only for a credential the system principal wrote.

### Changed (review 23)
- A person's bearer is never narrowed at the token endpoint. `POST /auth/me/authority/narrow` narrows in the person's Origin session; `POST /auth/me/authority/mantle-token` issues the token the web app calls Mantle on (`aud` `mantle`), which is no session here and exchanges for nothing. The default narrow audiences include `relay` (`relay:host`).
- A credential's seals are recorded only by its creator; a seed records them only for a credential it wrote.
- `POST /internal/describe-delegation/for-mantle`: a persona's own copy of a describe delegation, addressed to Mantle. Describe delegations carry a `jti`.
- Use nonces are spent in their own table (migration `0026_use_nonces`).

### Changed (review 22)
- A persona's server delegation is addressed to Mantle (`aud` `mantle`, `act.sub` the persona); nothing addressed to a persona acts as an acting credential, and the use verdict takes the person kind only with `aud` `mantle`.
- `POST /internal/authority/credential-seals`: the writer's record of each persona's sealed-copy digest and the endpoint-list digest (migration `0025_credential_seals`). Every use verdict carries `sealed_sha256` and `endpoints_sha256`; a credential with no record gets none.
- The use verdict takes the persona's `nonce`, signs it in, and spends it once.
- A person lookup's subject token is a person's own access token for Origin: no `token_type`, `aud` Origin's issuer.

### Changed (review 21)
- `POST /internal/authority/use-verdict` (Mantle's token, bound to the body): Origin's signed verdict that a persona may use a credential's sealed secret for a card, decided by its own walk on the persona's own delegation (`services.use_verdict`). It binds the persona, the subject, the delegation's `jti`, the credential, the card and the three grants (the subject's Invoke on card and credential, the persona's Read on the credential). `Reach.reach_grant` names the grant a walk reaches by.
- System delegations carry a `jti`, recorded with the signer that asked.
- `/internal/describe-delegation` takes Crystal's own token only. `/internal/delegation-token`'s platform-server fallback takes the chorus host only.
- Crystal's own service token is verified (`PLATFORM_ISSUERS`), as a service token only; it reads no person.
- A non-narrowed delegation is a bearer at Origin only when addressed to Origin (`aud` its issuer or `origin`).
- `/internal/billing-recipients/{id}`: Ophan records a billed person (`PUT`) and reads their address only (`GET`), each read recorded. Migration `0024_billing_recipients`.
- The token endpoint exchanges Ember's delegation, with Ember's own account token as `actor_token`, for the same person's delegation addressed to Mantle (`aud` `mantle`, actor `ember`); it acts as Ember's narrowed credential.
- The acting-credential audiences name the personas by client id (`agience-server-<name>`).
- `auth_verifier.verify_nonce` is removed.

### Changed (review 19)
- The reach digest is `prism.trust.ledger.canonical_reach`, with expiry, invite target and claim limit.
- The wheel excludes `origin.tests*`; the held-for-tests seam needs this source tree's own tests folder.

### Changed (review 18)
- The feed's page size is `FEED_PAGE` (500); each answer carries the head.
- Every expiry is stored as UTC ISO-8601. Body digests and the chain check of older entries read it as given.
- `manifest.yml` is read only from the folder holding `ORIGIN_DB_PATH`, owned by Origin at 0700. `DATA_PATH` and `MANIFEST_PATH` are gone.
- Custody also needs the database folder to be Origin's own, at 0700.
- The test-only job grants held without a grantor are behind a seam honoured only while pytest is loaded.

### Changed (review 17)
- The ledger's shared names (the credential kinds, which of them Mantle applies, the genesis, the envelope version, the entry kinds, the `ck:` prefix and the invite target digest) come from `prism.trust.ledger`, which Mantle reads too.
- The session preview also describes the resource itself (`resource_detail`: creator, creation date, member and grantee counts).

### Changed (review 16)
- Writing without reading is an Add grant (John, 2026-11-03). Drop keys are not part of the authority model. The `drop_key` entry is refused (400), and its table (migration 0023), console replacement, read route, operator alerts and replica fields are removed. An old `drop_key` entry in the chain still verifies and applies nothing.
- A deny anywhere up a node's creation chain holds at release, whatever the edges below it conduct.
- A background delegation makes no change of its own: no narrowing, no demotion or removal of a creation edge, and no grant retired. It restates what is held, or re-submits a withdrawal of a secondary edge within its job grant's collections.
- `retire_root` removes the id's live key shares (its own and `ck:<id>`), and a node deleted at Origin is not registered as a root.
- The session preview names each parent's creator and its creation date (`parent_details`).
- A system delegation's actor is bound to the caller who signed. Chorus acting as Ophan is the one listed pairing.

### Changed (review 15)
- Removing a node's creation edge deletes it at Origin. The node, and every member under it, then opens no key and takes no new edge or grant, and no action on it counts for anyone. Its remaining edges are still removed, and an allow grant on it is still retired.
- No token Mantle holds lifts a deny. A deletion's request to retire one is answered as unchanged, and only the owner's Origin session retires a deny. The "deleted in this batch" exception is removed. The reach digest leaves out a deny on a deleted node, so Mantle's parity check agrees.
- Removing a creation edge needs Delete reaching the member, or Admin on the collection. Evict alone removes only a secondary edge.
- A system delegation lives at most 300 s. A describe delegation names only a known persona, and each system purpose is minted only for the actors it lists.
- `POST /auth/me/authority/preview` returns what Origin holds about an item: its parent chain, its grantees, and a digest. `POST /auth/me/authority/invites` and `/grants` require that digest (`preview`) and refuse a stale one.
- The session cookie's scheme follows `AUTHORITY_ISSUER`.
- Origin, Mantle and Chorus are never grantees.
- `persons.email_verified` defaults to unverified (migration 0022). The operator's bootstrap paths record the operator's address as verified explicitly.

### Changed (review 14)
- A Mantle-held token lifts a deny or retires a grant on a resource "deleted in this batch" only when the batch removes that resource's own creation edge (the co-signed `edge.add` with `origin: true` for that parent and resource). A secondary edge removed deletes nothing, and a root is never deleted this way. The same rule decides which parents' grants a deletion withdraws.
- On https, Origin reads and counts only the `__Host-` cookie names. `RefuseTossedCookies` drops unprefixed guarded cookies before the app runs, and refuses more than one value of a guarded cookie.
- A grant to an `agience-server-*` principal names only a known persona server.
- The invite answer, and the invite mail, name the item (`resource_id`) and the name the owner confirmed (`resource_name`); the answer also echoes `email`.
- A hop's client assertion must carry a `jti`, which is spent (used once), and a `subject_digest` binding it to its subject token. An `iat` more than 30 s ahead of the clock, or an `exp` more than `HOP_ASSERTION_MAX_TTL` after now, is refused.
- A password sign-up stores its address unverified whatever the plane's verification setting is. Only the verification link, an OTP sign-in or a provider's assertion verifies it, so a targeted invite is claimed only on a proven address.

### Added
- Invites are made and mailed by Origin (`POST /auth/me/authority/invites`): the owner names one address, Origin mints the token, targets the invite at that address (one claim) and mails the link as it mails sign-in codes; no answer carries the token. `POST /auth/me/authority/invite-context` shows an invite's context in the session.
- Grants in the session are Origin's own record: `GET /auth/me/authority/grants?resource_id=`, `POST /auth/me/authority/grants` (Origin mints the id), `POST /auth/me/authority/grants/{id}/change` and `/revoke` (built from Origin's row; an unknown id gets 404).
- `POST /auth/me/authority/entries`: a person makes grants, invites, invite claims, denies and edge changes in their Origin session (custom header `X-Origin-Session`, the web app's or Origin's own `Origin`, credentialed CORS for the web app alone), decided by the ledger's rules and confirmed when appended. `POST /auth/me/authority/claim` claims an invite there by its token alone.
- Cross-persona hops: a persona exchanges its narrowed delegation for one narrowed to the next persona, at `/auth/token` on its own RFC 7523 client assertion or at `/internal/narrow-hop` on its own service token, only along `NARROW_HOPS` (Crystal to each persona, Lumen to Sage), for the same person, five minutes and never past its source; each hop is recorded (`narrow_hops`, migration 0021).
- `GET /auth/not-before`: the not-before times peers enforce, signed by Origin's key.
- Service accounts (`service_accounts`, migration 0019; `python -m origin.scripts.service_account`): every token Origin issues for a service's own account is a delegation narrowed to its audience.
- Persona servers (Iris, Lumen, Sage, Crystal) receive a caller only as a narrowed delegation (`persona:<name>`, five minutes, no refresh), which only that persona may exchange for its own server delegation.
- Ember's narrowed delegation is an acting credential for its scoped acts only: `ember:memory` makes the person's own memory collection and members in it; `ember:share` makes one Read grant on a single artifact to a person, for at most 7 days, where the person may give it; `ember:read` asks reach verdicts. It never releases or replaces a key share.
- `POST /auth/me/link-attempts`: a link begins in the Origin session with a random state bound to the sign-in's PKCE challenge (`link_attempts`, migration 0017).
- `python -m origin.scripts.rotate_signing_key --print | --accept KID`: rolls Origin's signing key over on the operator's acceptance; the JWKS keeps the old public key; every session and refresh family ends.
- `POST /auth/me/job-grants`, `GET /auth/me/job-grants` and `POST /auth/me/job-grants/{id}/revoke`: a person makes a job grant only at Origin's own page, in their Origin session with a fresh step-up, and lists and revokes their own there (also on `/passkey`). `/passkey` also links another sign-in method.
- Job grants (`job_grant` ledger entries, `authority_job_grants`, migration 0015): a person grants a named background job over their own key, an Admin over a collection's; the console lists and revokes them and grants the platform principal's own jobs (`/oracle/job-grants`).
- `GET /oracle/authority-ledger/collection/{id}`: Origin's own view of a collection, read before pinning Authorities.
- Origin's own session (`origin_sessions`, migration 0016): an HttpOnly, SameSite=Strict cookie on Origin's host, set by every sign-in on Origin's own pages, never in a body or a token.
- RFC 8693 token exchange at `/auth/token`: a person's own access token for a delegation narrowed to one audience (`NARROW_AUDIENCES`, by default Ember; each persona facet in `FACET_URIS` with scope `persona`), five minutes, never `platform:admin`, no refresh token.
- `POST /auth/sign-out` and `POST /auth/sign-out-everywhere`.
- Origin's own passkey page (`/passkey`, strict CSP): sign-in, adding and removing a passkey behind a fresh step-up, and the operator console's sign-in.
- Refresh tokens are recorded by `jti` in a family per sign-in (`refresh_tokens`, migration 0014).
- `GET /internal/authority/reach` and `POST /internal/authority/verify`: Mantle-only, bound and single-use. The first answers reach for one action by Origin's walk; the second compares Mantle's digest of reach with the replica (`services.authority_digest`).
- Operator alerts (`operator_alerts`, migration 0012): every live grant carrying Admin and every grant on the pinned Authorities collection is recorded and logged; the console lists and acknowledges them (`GET /oracle/alerts`, `POST /oracle/alerts/{id}/acknowledge`).
- Console routes: `GET /oracle/key-shares/{id}/history` and `POST /oracle/key-shares/{id}/restore` (a superseded share put back, the replaced one kept), `POST /oracle/authority-ledger/retire-root` (a planted root or node cleared: grants revoked, edges removed, then a `root.retire` entry), and `POST /oracle/authority-ledger/drop-key`.
- A person's step-up for changing how they sign in (`POST /auth/me/step-up-options`, `X-Step-Up`): a passkey assertion with user verification, or, with no passkey, a re-authentication at Origin's own pages (`/auth/reauth/start`, `/auth/reauth/complete`, `person_step_ups`, migration 0013).
- The operator console: the `/oracle/*` routes accept only a console token and a fresh passkey for each use.
  - `POST /oracle/console/sign-in-options` and `POST /oracle/console/sign-in` sign the platform operator in with a registered passkey, user verification required, and return a console token (audience `origin-operator-console`, `token_type=operator_console`, fifteen minutes). No other token carries that audience, Origin's ordinary authentication refuses any token with a `token_type`, and Mantle never receives it.
  - `POST /oracle/console/step-up-options` gives a single-use challenge for one request: its method, path with query string, and body digest, followed by random bytes. Each operator action carries the passkey assertion over it in `X-Operator-Step-Up`; an assertion for another request, a spent one, or one without user verification is refused.
- Collection keys (`ck:<collection>`): Origin releases a collection key's share to a subject whose own walk reaches that collection for `read`, or reaches an artifact created in it, and to a background delegation minted for that key. A master key's share is released only to its own principal; reach to a collection under it opens that collection's key, never the master or a sibling's. A collection key is known to Origin when its collection is, and its creator may re-store its first share.
- Seed credentials: the operator mints one for each seed pass at `POST /oracle/seed-credential` (the platform system principal's, `scope=authority.seed`, ten minutes at most, recorded in `seed_credentials`), and revokes one at `DELETE /oracle/seed-credential/{jti}`. Accepted as an acting credential that may widen reach, under the system principal's own rights; a background delegation still only narrows.
- The authority ledger (`authority_ledger`, migration `0011_authority_ledger`): a hash-chained log of every change Mantle makes that affects reach, each entry co-signed by Origin (RS256 over the entry hash). The hash covers the body, the actor, the credential kind and reference, the key id, any compensation, and the invite a claim spent.
  - Entry kinds are `grant` (id, grantee and type, resource, CRUDEASIO actions, effect, state, expiry, an invite's target as a kind and digest, its claim limit), `edge.add` and `edge.remove` (a containment edge and its `propagate` mask) and `root` (a key principal and its origin root).
  - Entries hold structure only; a body with any other field is refused.
  - Origin's replica (`authority_nodes`, `authority_grants`, `authority_edges`, `authority_roots`) is written only by applying an appended entry.
  - Every key that co-signed is kept by kid (`authority_signing_keys`).
  - Origin keeps the `jti` and body digest of Mantle's submission token, not the token.
  - Each receipt names the ledger's head (`head_seq`), so Mantle can see the ledger never goes backwards.
  - Every expiry is parsed and compared as an aware time; an entry whose expiry does not parse is refused, and a stored one that does not parse confers nothing.
- `POST /internal/authority/entries` takes one entry from Mantle on a bound service token naming the SHA-256 of the body and of any proof, with the acting person's credential in `X-Acting-Credential`. Origin verifies the credential, then checks the change against its own replica with Mantle's rules ported in `services.authority_reach`:
  - A direct grant, or any change to one, needs admin held on the resource; an invite needs share or admin. A grant is no wider than what the actor holds there. Changing a grant's effect to deny needs admin.
  - Adding an edge needs create or add reaching the collection. Widening an existing edge's mask needs admin; narrowing needs create or add.
  - Removing an edge needs evict or delete, and delete on a resource retires its grants.
  - The grantee may give up a grant, and its issuer may narrow it, keeping its effect.
  - An entry that would change nothing answers `unchanged` with the receipt of the entry that set that state.
  - `GET /internal/authority/head` gives the head.
- Ids Origin has not seen come into being only by their own creation: a `root` entry or a creation edge, submitted by the creator.
  - A person's id comes into being only by that person.
  - A `root` for any other unseen id comes with the creation the store recorded for it (`proof`: made by the actor, within the last ten minutes).
  - A grant or edge naming an unseen id is refused.
  - A creation edge never names a person or an existing id: a member has one creation edge, and a move is secondary containment.
  - The creator of a self-rooted resource (no creation parent) sets it up while every grant on it is theirs, as Mantle's own base case. A member gets no base case: whoever added its creation edge records a grant to themselves of no more than their walk already reaches on it, so a create-only member opens no collection key through what they create.
- An invite claim carries its claim token as proof. Origin checks the token's hash against the invite, the invite's target against the claimant's own id or verified address, and the claim limit counted in its replica. A claim takes no more than the invite's actions and keeps its expiry. Only the issuer or an admin closes a live invite, and an invite's target and limit never change.
- A background delegation acts on the ledger only as the platform system principal, and never creates or widens a grant or an edge, nor issues a new grant. Its narrowings are accepted whatever the system principal holds (retiring a grant, shortening an expiry, removing an edge, narrowing a mask), so mesh revocations, erasure and other system revocations land.
- A compensating entry (`compensates`) withdraws the same actor's entry for a write that did not commit at Mantle: on the same credential, within 60 seconds, while it is still the latest change to its row. Withdrawing a deny is refused. On a background delegation it may withdraw any actor's entry past the window, still only while that entry is the latest change to its row.
- `created_by` grants nothing (architecture §51): a creator's rights are the creation grant co-signed in the same submission batch (`batch`) as the root or creation edge that creates the id; the creator base case is gone. A node that has ever had a creation parent stays a member (`authority_nodes.member`).
- An unconfirmed deny is withdrawn by its actor; a resolved entry answers 410 to a withdrawal; a 409 names the row's latest entry.
- Operator routes: `/oracle/authority-ledger/unconfirmed`, `/resolve`, `/entries` and `/revoke`.
- `POST /internal/authority/confirm` is body-bound and confirms only this service's pending entries.
- Origin issues each submission batch (`authority_batches`): with the first receipt, to one credential, for 60 seconds. A creation grant is accepted only in the batch whose own entry created the id, and only while no other grant names it.
- Changing an existing edge's mask needs Admin; removing an edge needs Evict or Admin on the collection, or Delete reaching the member. A restated mask is `unchanged`.
- A retried withdrawal never lifts a deny.
- `/internal/authority/feed` serves entries after a seq, for Mantle to apply what it did not submit.
- A share is replaced only by its principal or Admin on what it keys, and only while marked replaceable (`/internal/key-shares/{id}/activate`, `/rekey-pending` on the seed or bootstrap credential); superseded shares are kept (`key_custody_share_history`).
- No action but Read releases a collection key, and a first share needs its principal, a subject that may open it, or Admin on what it keys.
- A bootstrap entry is accepted only on the operator's bootstrap credential. The operator obtains it at `POST /oracle/authority-ledger/bootstrap` and withdraws it at `DELETE`; it lives an hour at most, and `verify_share_credential` refuses it as an acting credential. Bootstrap entries record no creator. Mantle's `mantle.system.cosign_authority` uses one to co-sign the authority Mantle already holds.
  - It states only ids Origin has not seen; an id with a creator, a grant with an issuer, or an edge someone added is refused.
  - A window that lists ids (`ids`) states those ids only; once the ledger has ordinary entries, a window must list them.
  - It keeps the person-id checks: no creation edge into a person's id, and a person's key roots to that person.
  - `POST /internal/authority/bootstrap-done` ends it after its batch.
- A collection key is released through an artifact only on a grant someone else issued on it; a member's own owner grant does not outlast their reach on the collection. Shortening a deny's expiry counts as widening.
- `POST /internal/authority/seed-done` revokes the seed credential its pass ran on, so one serves one pass.
- `GET /oracle/authority-ledger/verify` (operator) recomputes every entry's hash and link and checks every co-signature against the key that made it. It also replays the whole chain and compares the result with every replica table, including who created each node and who added each edge.
- A key share is released only when Origin's own walk over its replica says the acting credential's subject may open it (`Reach.may_release`): a collection key as above, a master key to its own principal alone. A master key the replica holds no root for is refused.
  - Grants are walked up the origin chain, deny nearer first, each edge's mask attenuating; revoked and expired grants reach nothing.
  - The collection and artifact are query parameters bound in the service token.
  - For a key Origin knows, reach is asked before absence is reported. An id Origin knows nothing about answers 404 `{"absent": true}`.
  - Replacing a stored share needs a credential that reaches the key.
- The acting credential (`X-Acting-Credential`), verified by Origin itself, is one of:
  - a person's access token (this authority's audience, the person active);
  - a delegation Origin issued for a person (addressed to Mantle or a persona, the person active, ten minutes at most, recorded at issue and not revoked);
  - a background delegation Origin minted for one principal.

  Anything else is refused. Each release is recorded in `key_custody_releases` with the principal, the collection, the credential's subject, kind and reference (its `jti` or a hash), never the token (migration `0010_key_custody_credentials`).
- Background work: the operator grants, lists and withdraws a background authority at `/oracle/custody-background` (`key_custody_background`, `hours`, 24 at most and by default; `days` is refused). While one is in force, `POST /internal/custody-delegations/{principal_id}` mints, for Mantle on a bound service token, a delegation for one key principal Origin's replica knows or for the platform system principal (`scope=custody.share.release`, `aud=origin`, five minutes, ten at most), recorded by `jti` in `key_custody_delegations`. It opens that principal and no other, and stops opening anything once the authority is withdrawn.

### Changed
- The generic session route (`/auth/me/authority/entries`) makes edge changes only; no grant, deny or invite is made there.
- An invite is claimed in the session only by the person whose verified address it targets; a claim by anyone else refuses and spends nothing, and an untargeted invite is neither made nor claimed there.
- On https the session cookie is `__Host-origin_session`; a request carrying more than one of a guarded cookie is refused.
- Origin takes no change to authority on a token Mantle holds (a person's access token or a delegation). On one, only the creator's own creation grant in its creation batch, a grant retired with its resource deleted in the same batch, new edges and edge removals are taken; a withdrawal undoes only Mantle's own failed write, while its actor still holds what it was made under.
- No grant is co-signed to a grantee that does not exist.
- The ledger feed carries each entry's chain fields, co-signature and the public key of its kid.
- A server delegation made from a narrowed delegation keeps its scope and the `narrowed` claim.
- `GET /auth/not-before?after=<seq>` serves changes by a monotonic sequence; the document carries `seq`.
- The registration pause stops every path that makes an account, OTP verification and a first federated sign-in too.
- A missing `service_accounts` table issues no person token.
- A sign-in is narrowed only to the facets Origin lists (`NARROW_FACETS`); one to an unlisted facet gets no token.
- Ember's share is removed: `ember:share` is never issued, an Ember delegation makes no grant, no memory collection and no drop key and stores no key share; it only creates a member in the person's own memory collection and asks reach verdicts. A malformed `NARROW_AUDIENCES` closes every narrowed audience. Narrowed delegations carry Origin's `narrowed` claim.
- Delete retires a grant, a deny included, only with the resource deleted (its creation edge removed) in the same batch on the same credential. A deny on a collection refuses its key by every path. The first drop key needs Read and Admin. A withdrawal that would widen is decided again as that change. The pinned Authorities collection is never retired, and a creation grant on it alerts; `retire_root` clears a planted deny. Derived ids follow a change of address, and a squat found at sign-up raises `derived_id_squatted`. A seed credential writes one batch (migration 0018).
- A retired signing key leaves the JWKS once the longest token life has passed.
- The refresh grant requires `client_id` and checks it against the family; a confidential client refreshes nothing.
- Every Origin page, `/web/*` included, is sent with a CSP forbidding framing and inline script, and with `X-Frame-Options: DENY`; no page carries an inline script. Revoking a job grant needs a step-up.
- Registration pauses in Origin itself (`REGISTRATION_PAUSED`, `auth.registration.paused`); Origin refuses to start trusting every TCP peer's forwarded headers.
- A re-authentication completes only in the Origin session that began it and starts no session; neither does a sign-in on its way to it or to a link. A link's code must be a first-party client's, returning to `/passkey`. The operator's passkeys are never stepped up as a person's.
- `ember:share` is issued only when the exchange asks for it.
- Origin's own routes refuse a narrowed delegation except `GET /auth/userinfo`.
- A job grant over a collection needs Read on it as well as Admin, the platform principal's included.
- Sign-out ends the person's access tokens at Origin; sign-out-everywhere ends every token issued before it, legacy refresh tokens included (`person_not_before`). With no `REFRESH_LEGACY_CUTOFF` on a production plane, refresh tokens without a `jti` are refused.
- The refresh retry grace is removed: a used refresh token presented again revokes its family, and one presented by another client is refused.
- A link needs its attempt's state and the code's PKCE (S256); the passkey step-up names what is linked, and the page links only after a confirm.
- A job grant is never made on a bearer token or a delegation alone. Every job grant raises an operator alert. Signing out everywhere revokes the person's job grants.
- A job grant is live only while its grantor is an active person who still holds what it was granted under (the key's own person, or Admin on each collection it names), checked at mint and at use. The operator's job grants cover only collections the platform principal holds Admin on.
- A background delegation is bound to its job: on use its job must be its grant's.
- A background delegation is minted only under a live job grant naming the job (bound in Mantle's service token) and covering the principal; each grant mints at most 30 a minute, each issuance is recorded, and the operator is alerted once per grant per hour; it releases nothing outside its grant's collections. The standing background authority (`/oracle/custody-background`) is removed.
- Pinning `platform.authority_collection_id` refuses an id the replica does not know and raises an alert for every admin it appoints; a bootstrap's Admin grants raise one summary per credential.
- Custody is refused unless `AGIENCE_PLANE=production` and the process shows isolation (`services.custody_plane`).
- A change to how a person signs in is made only in their Origin session; a bearer token alone, even with a step-up, is refused. A re-authentication is started only from that session, its start page shows the exact action and needs a confirm, and a sign-in with no `auth_time` proves nothing. Passkey registration options and completion are issued only in that session.
- A sign-in delivered to a persona's facet gets only a delegation narrowed to that facet.
- An exact retry of a refresh within 30 seconds gets the same new token; rotation is one transaction; a refreshed access token carries its own `jti`; refresh tokens without a `jti` are refused after `REFRESH_LEGACY_CUTOFF`.
- The platform client's development redirect bases are opt-in (`PLATFORM_DEV_REDIRECTS`); registered native clients keep their loopback callback. Mantle's host is filtered out of `ORIGIN_ALLOWED_ORIGINS`, `SSO_RETURN_URIS` and `APP_URI`.
- Every passkey ceremony's relying party and expected origin is Origin's own address, never `FACET_URI`; an assertion made on another page, or a passkey registered under another relying party, is refused.
- Mantle's host (`MANTLE_URI`) is never a redirect base or a CORS origin.
- A refresh grant rotates the refresh token and returns the next one; a used one presented again revokes its whole family; deactivation revokes a person's refresh tokens.
- Only `branding.title` changes on the ordinary token.
- A re-authentication asks the provider for a fresh sign-in (`prompt=login`, `max_age=0`) and refuses an `auth_time` older than its ticket.
- A withdrawal on a background or operator credential only narrows: it never makes a grant more live, or an edge conduct more, than it does now. The entry's own actor, on its own credential, within its window, still undoes its own write; the operator lifts an unconfirmed deny by settling it.
- No operator alert is raised for a creator's own creation grant in its creating batch; every other grant carrying Admin still raises one.
- Platform admin, and whether one has been appointed, counts only live grants to a person.
- A bootstrap credential marks for re-key only the shares its window lists.
- Every id Mantle derives from a person (card, own card, Inbox, observations container, local collection by id or email, the platform's well-known identity keys, per-person seeded slugs) is registered or created only by that person.
- Any write to a key share Origin holds, whatever key check it claims, is taken only while the share is marked replaceable, and only from the key's principal or Admin on what it keys; restating the very share changes nothing.
- A seed credential marks for re-key only the shares the operator listed when minting it (`rekey_shares`).
- A deny is changed only by Admin on its resource, its issuer included. A withdrawal restores the row as the entry before it left it, and Origin appends that state. An invite is closed by Share or Admin on its resource; an issuer no longer narrows a grant on being its issuer.
- An id derived from a person's id (their card, own card, Inbox, observations container) is registered or created only by that person.
- An expired grant, an invite or a non-person grantee appoints no platform admin.
- Every platform setting but `branding.title`, `branding.email_logo_url` and `email.from_name` is changed only through the operator console with a passkey step-up, including any key added later; `PATCH /system/settings` refuses the rest on the operator's ordinary token.
- Linking or unlinking a sign-in identity (`/auth/me/link-provider`), and registering or deleting a passkey, need a fresh step-up by a method the person already has, bound to that request.
- A new sign-in identity whose email belongs to an existing account is refused (409) instead of joined.
- `/auth/clients` takes the operator console with a step-up.
- `POST /internal/delegation-token` issues a delegation of at most ten minutes, never past the remaining life of the token it exchanges, with a `jti` recorded in `delegation_tokens`. It answers `expires_in`, and refuses a subject token about to expire. The operator revokes one at `DELETE /oracle/delegations/{jti}`.
- `POST /internal/delegation-token` exchanges only a person's own access token for Origin: a subject token carrying `token_type` (refresh, reset, verify), an API-key token, any principal type but a person (`mcp_client` included), or one addressed to anyone but Origin is refused.
- The operator's ordinary access token no longer opens `/oracle/*`; the operator console does.
- The operator's passkeys change only through the console with a step-up, or, for the first, with a one-time enrolment code from `python -m origin.scripts.operator_enrolment_code` on Origin's host (`operator_enrolment_codes`, fifteen minutes, single-use).
- `platform.operator_id` and `oracle.*` are refused by `PATCH /system/settings` and changed at `PUT /oracle/settings/{key}`.
- A first key share is stored only for a key Origin's replica knows, on the credential of its principal or its creator.
- Only an entry Mantle has not confirmed (`POST /internal/authority/confirm`) may be withdrawn by compensation, and a 409 to a withdrawal names the row's latest entry.
- Origin's ordinary authentication refuses a custody credential (a background, seed or bootstrap delegation addressed to Origin) as a bearer token.
- `GET /internal/authority/platform-users` lists one page of person records for Mantle, on a service token bound to the page and the caller's own person credential, only for a platform admin by Origin's replica: Admin on the Authorities collection Origin has pinned (`platform.authority_collection_id`, a console key), or the operator while no one holds it.
- Every `/oracle/` route but the console's three entrances is held, route by route, to refuse without the console token and without a fresh step-up for that request (`test_every_console_route_refuses_without_the_console_and_a_fresh_step_up.py`).

### Fixed
- The passkey page's Remove button sends the credential's id; a person with no passkey keeps the link through the re-authentication.
- The operator's passkey registration requires user verification and refuses "none" attestation.
- `test_the_decoy_key_is_one_the_node_actually_loads` boots the node itself, so it passes in any order.
- Passkey registration keeps its challenge (`register-options` commits it), so registration works, and a malformed credential answers 400.
- Passkey registration and sign-in parse the browser's credential with the webauthn 2.x parsers. They called the webauthn 1.x `model_validate`, which webauthn 2.x (the pinned version) does not have, so every passkey ceremony failed.

## [0.2.11] - 2026-10-31

### Added
- `/internal/key-shares/{principal_id}` (`PUT`, `GET`) holds Origin's share of each Mantle master key under threshold custody, in its own table (`key_custody_shares`, migration `0009_key_custody`) with the share encrypted under Origin's `encryption.key`. No settings route and no `/oracle` route lists, reads or writes it.
- Only Mantle's own service JWT, verified against its anchor in the authority manifest, reaches a share; other platform services, the operator and delegations are refused. Each token must be bound to the call: a lifetime of at most 60 seconds, a `jti` accepted once (`key_custody_nonces`), and claims naming the method, the path and the principal of the request.
- A store is one conditional write: a share of a different key is not overwritten unless the caller names the stored key-check value as superseded, and two stores cannot both act on the same read. A share that cannot be decrypted is refused with 503, never reported absent; an absent share answers 404 with `{"absent": true}`. Every release is logged at WARNING with the principal and the first characters of the key-check value, never the share.
- Migration `0009_key_custody` refuses to downgrade while `key_custody_shares` holds any share, naming `mantle.system.split_master_keys --combine` as the way back.
- Platform settings reserve the `custody.` prefix: no route or writer may store a setting under it, and none is listed.

### Changed
- `origin.services.shamir` is `prism.trust.shamir`, re-exported as one module object; `key_oracle.split_secret` and `combine_shares` are unchanged. The `agience-prism[trust]` floor is 0.1.8, the release that has it.

## [0.2.10] - 2026-10-29

### Changed
- The `build` workflow in `.github/workflows/build.yml` now also runs on pushes to `release/**` branches, so the platform release can deploy the `dist` artifacts from that run.

## [0.2.9] - 2026-10-18

### Added
- A system-delegation purpose may name the persona that carries it out; platform mail names Iris. Iris, signing with its own key, may obtain the platform-mail delegation and no other, recorded as its proven signer (`act.iss`).
- The delegation exchange (`/internal/delegation-token`) admits a chorus persona signing with its own enrolled key, for its own delegation only, and records the proven signer in the delegation (`act.iss`). The shared `chorus` identity may still ask for any persona; its delegations say `act.iss=chorus`, and Mantle releases no secret on one. A persona is not admitted to any other internal route.

### Fixed
- `/internal/describe-delegation` admits Crystal, the event-driven describer it serves. Crystal was not among the services the platform-service guard admits, so no event-driven describe could run.

## [0.2.8] - 2026-10-12

### Changed
- A password reset link carries a 32-character random token instead of a signed one of about 600 characters. Origin stores only the token's SHA-256, in the new `password_resets` table (migration `0008_password_resets`, applied at startup), with the account, the password fingerprint at sending and the expiry (1 hour). Setting a password through a link deletes every reset link for that account; a link also stops working once the password changes any other way. Links sent before this version stop working.

## [0.2.7] - 2026-10-11

### Added
- `EMAIL_PROVIDER=outbox` sends nothing and writes each message as one JSON file (`to`, `subject`, `text`, `html`, `sent_at`) in `EMAIL_OUTBOX_DIR`, for a test stack to read. Without `EMAIL_OUTBOX_DIR` the provider counts as not configured.

## [0.2.6] - 2026-10-11

### Added
- `GET /logout` ends Origin's session for the browser: it clears the server session, the page clears the stored token, then it returns to the `return` address only when Origin lists it (`app_uri` or an `sso_return_uris` entry), else to Origin's sign-in page. The account page's "Sign out" goes through it.

## [0.2.5] - 2026-10-11

### Added
- `POST /auth/password/reset-check` returns the address of the account a reset link resets, only while the link would still be accepted (signed, unused, unexpired, password unchanged since it was sent).

### Changed
- The password reset link carries no address. The reset page names the account from `reset-check`, so the account shown is always the one the link resets, and an expired or used link says so before a password is typed. The account field is read-only and is never sent to the server.

## [0.2.4] - 2026-10-11

### Added
- Sign-in code, password reset and email verification mails state when and from what they were requested, for example "Requested on 11 Oct 2026 at 15:48 UTC from Chrome on Windows." Browser and system names come only from a set list; nothing a caller sends is copied into the mail.
- The password reset link carries the account's address (`&email=`), and the reset page shows it in a read-only `username` field beside the new password, so a password manager saves the new password under that account.

### Changed
- Every input on the sign-in and reset pages has a `name`, so password managers fill them.

## [0.2.3] - 2026-10-11

### Added
- `email.reply_to` setting sets the `Reply-To` address on outgoing mail; when empty, replies go to the sender address.
- `branding.email_logo_url` setting chooses the logo shown at the top of every email. By default the message uses the 320 px logo this Origin serves at `/web/logo_mail.png`.
- Mail sent through the `email_service` SMTP and Gmail providers now carries `Date` and `Message-ID` headers, the latter on the sender's own domain, and its text and HTML parts are encoded as UTF-8.

### Changed
- Sign-in code, password reset, email verification and invitation messages from `email_service` are complete HTML documents with a preview line, the logo, and a footer saying who sent the message and why. Each has a fuller plain-text version, names the recipient address, and uses new subject lines, for example "Your Agience sign-in code" and "Confirm your email for Agience".
- Invitation emails escape the inviter's name, the resource name and the personal message, so they show as plain text in the HTML.
- Links in emails are escaped inside the HTML and appear whole in the plain-text version.

## [0.2.2] - 2026-10-11

### Changed
- `origin.admin` person output (`person show`, `person reactivate` and related commands) now reports the password hash's algorithm and cost, such as `password=pbkdf2_sha256/600000`, in place of `password=set`. It shows `none` when no password is set and `unreadable` for a hash that cannot be parsed. The hash itself is never printed.
- `origin.admin` person output now includes a `modified=` field with the person's last modified time, or `-` when none is recorded.

## [0.2.1] - 2026-10-11

### Added
- The `persons` table gains nullable `deactivated_at` and `deactivated_reason` columns (migration `0007_person_deactivation`, applied at startup). Existing accounts stay active. Downgrading drops both columns, so every deactivated account becomes active again.
- Accounts can be deactivated. A deactivated account cannot sign in through `/auth/password/login`, the local password and one-time-code authorize routes, the authorization-code grant, the `refresh_token` grant on `/auth/token`, or email verification confirmation. Each of these returns a 403 with the same message, `This account is deactivated. Contact support to restore it.`
- `python -m origin.admin person show|deactivate|reactivate <email|username|id>` lets operators manage account state. `deactivate` requires `--reason`. `reactivate` restores the account exactly, and `--restore-password-from FILE` puts back a password hash from a JSON backup of person rows, only for an account that has no password. Password hashes are never printed.

### Changed
- The password routes return 403 only after the correct password is supplied, so only the password's holder learns the account is deactivated. Other credentials get the usual 401.
- A deactivated account is sent no mail. `/auth/otp/request`, `/auth/password/reset-request` and the email verification resend send nothing and give the same reply as for an unknown address. Outstanding password reset links stop working for it.

## [0.2.0] - 2026-10-09

### Breaking

- An email-confirmation link signs in only the browser that started the sign-up, identified by a nonce it holds. A forwarded or nonce-less link still confirms the address but signs nobody in.
- The unauthenticated routes that send mail (one-time codes, confirmation resends, password resets, registration) share one budget per address and per client. Over the budget the response is unchanged and no mail is sent. An IPv6 /64 counts as one client.
- Sign-in requests that spend a key derivation are shed with `503` and `Retry-After` when the queue is deep. One client may hold a bounded number of sign-ins in flight.

### Added

- Every access token that names a person carries `email_verified`, the stored fact about the address, on every sign-in path (password, link, one-time code, passkey, code grant, refresh, setup wizard).
- `APP_URI` sets where the account page's "Continue to Agience" leads (also the `branding.app_uri` setting). Loopback hosts and Origin's own address are refused.
- `SSO_RETURN_URIS` lists the exact https URLs a signed-in visitor is returned to without a click, beyond `APP_URI`'s root (also `branding.sso_return_uris`).
- `SHARED_CLIENT_NETWORKS` lists relays whose requests are many people's; they are exempt from the per-client mail and in-flight caps. Entries must be exact (`a.b.c.d/32` for a host); others are refused with a warning.
- `ORIGIN_KDF_THREADS` sets how many key derivations run at once (default: one fewer than the CPUs available, at least 1).
- The holder of a mailbox can disown a registration they did not make, and an account without a password confirms from the link alone.
- The login refusal for an unconfirmed address carries a machine-readable code.

### Changed

- A one-time-code request is answered the same whether or not the address holds an account, capped or not, and whether or not the mail was sent.
- A password check that does not match costs at least the configured derivation count, whatever the stored hash.
- Request bodies bound the length of identifiers and addresses; an oversized one is refused before it reaches the store.
- Logs name an address or identifier by a keyed tag, never in the clear.
- Key derivations run in a bounded thread pool, so a slow derivation does not stall other requests or database access.
- The account and confirmation pages lead back to the app.

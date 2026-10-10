// Behaviour of the session helpers in `origin/web/app.js`, run with `node --test`.
//
// The file is loaded as the browser loads it — a classic script whose top-level declarations become
// globals — into a VM context whose `localStorage`, `sessionStorage`, `location` and `history` are
// stubs this file controls. `test_app_js_behaviour.py` runs it under pytest.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const APP_JS = path.join(__dirname, "..", "..", "web", "app.js");
const SOURCE = fs.readFileSync(APP_JS, "utf8").replace(/^﻿/, "");

function storage(initial) {
  const m = new Map(Object.entries(initial || {}));
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => { m.set(k, String(v)); },
    removeItem: (k) => { m.delete(k); },
    _map: m,
  };
}

// A page at `href`, sharing `local` (one browser) and holding its own `session` (one tab).
function page(href, { local, session, fetchBody, now } = {}) {
  const url = new URL(href);
  const navigations = [];
  const ctx = {
    localStorage: local || storage(),
    sessionStorage: session || storage(),
    location: {
      get href() { return url.href; },
      set href(v) { navigations.push(["href", v]); },
      get search() { return url.search; },
      get origin() { return url.origin; },
      get pathname() { return url.pathname; },
      replace: (v) => navigations.push(["replace", v]),
      assign: (v) => navigations.push(["assign", v]),
    },
    history: { replaceState: (a, b, u) => { url.href = new URL(u, url.href).href; } },
    URL, URLSearchParams, JSON, Array, Uint8Array, Map,
    crypto: globalThis.crypto,
    atob: (s) => Buffer.from(s, "base64").toString("binary"),
    fetch: async () => ({ ok: true, status: 200, json: async () => (fetchBody || {}) }),
    Date: now === undefined ? Date : class extends Date {
      constructor(...a) { super(...(a.length ? a : [now()])); }
      static now() { return now(); }
    },
    navigations,
  };
  vm.createContext(ctx);
  vm.runInContext(SOURCE, ctx, { filename: APP_JS });
  return ctx;
}

const run = (ctx, code) => vm.runInContext(code, ctx);
const SP = "https://my.agience.ai/";
const stashFor = (rd, extra) => JSON.stringify(Object.assign({ n: "abc", rd, st: "S", ts: Date.now() }, extra));

// ── readReturn / SP_ALLOW against hostile stored values ─────────────────────────────────────────
test("an allowlisted stored return is read back", () => {
  const ctx = page("https://origin.agience.ai/verify-email", { local: storage({ "agience.verify": stashFor(SP) }) });
  assert.equal(run(ctx, "readReturn()").rd, SP);
});

for (const rd of [
  "https://evil.example/",
  "https://agience.ai.evil.example/",
  "https://agience.ai@evil.example/",
  "https://evil.example@agience.ai.evil.example/",
  "https://evil.example\\.agience.ai/",
  "//my.agience.ai/",
  "http://my.agience.ai/",
  "javascript:alert(1)//agience.ai/",
  "JAVASCRIPT:alert(1)",
  "",
]) {
  test(`a stored return of ${JSON.stringify(rd)} is not followed`, () => {
    const ctx = page("https://origin.agience.ai/verify-email", { local: storage({ "agience.verify": stashFor(rd) }) });
    assert.equal(run(ctx, "readReturn()"), null);
    assert.equal(run(ctx, "signInHref()"), "/");
    assert.equal(run(ctx, `restoreReturn(${JSON.stringify([rd])})`), false, "listing it does not make a hostile target acceptable");
    assert.equal(run(ctx, `isListedReturn(${JSON.stringify(rd)}, ${JSON.stringify([rd])})`), false);
  });
}

// ── exact return list: silent hand-offs go only to published targets ──────────────────────────
const LISTED = ["https://my.agience.ai/", "https://lumen.agience.ai/auth/cb"];
for (const [rd, ok] of [
  ["https://my.agience.ai/", true],
  ["https://MY.agience.ai/", true],
  ["https://my.agience.ai:443/", false],
  ["https://lumen.agience.ai/auth/cb", true],
  ["https://my.agience.ai", true],
  ["https://evil.agience.ai/", false],
  ["https://user-content.agience.ai/me/page.html", false],
  ["https://my.agience.ai/redirect", false],
  ["https://lumen.agience.ai/auth/cb/extra", false],
  ["https://my.agience.ai/?next=https://evil.example", false],
  ["https://my.agience.ai/#x", false],
  ["https://x@my.agience.ai/", false],
  ["https://my.agience.ai./", false],
]) {
  test(`isListedReturn(${rd}) is ${ok}`, () => {
    assert.equal(run(page("https://origin.agience.ai/login"), `isListedReturn(${JSON.stringify(rd)}, ${JSON.stringify(LISTED)})`), ok);
  });
}

test("a stashed return to an agience.ai page that is not listed is not restored", () => {
  const local = storage({ "agience.verify": stashFor("https://user-content.agience.ai/x") });
  const ctx = page("https://origin.agience.ai/verify-email?token=T", { local });
  assert.equal(run(ctx, `restoreReturn(${JSON.stringify(LISTED)})`), false);
  assert.notEqual(local.getItem("agience.verify"), null, "an unrestored stash is left for the Continue link");
});

test("a hostile redirect_uri on the page is not stashed", () => {
  const local = storage();
  const ctx = page("https://origin.agience.ai/login?redirect_uri=https%3A%2F%2Fagience.ai%40evil.example%2F&state=S", { local });
  run(ctx, 'stashVerification("n1", "A@Example.com")');
  const s = JSON.parse(local.getItem("agience.verify"));
  assert.equal(s.rd, "");
  assert.equal(s.st, "");
  assert.equal(s.n, "n1", "the nonce is kept even when there is no return to keep");
  assert.equal(s.e, "a@example.com");
});

test("a stash that is not an object, or has no numeric ts, is discarded", () => {
  for (const raw of ["not json", "42", '"x"', JSON.stringify({ n: "a", rd: SP, ts: "1" })]) {
    const local = storage({ "agience.verify": raw });
    const ctx = page("https://origin.agience.ai/verify-email", { local });
    assert.equal(run(ctx, "readReturn()"), null, raw);
    assert.equal(run(ctx, "readNonce()"), null, raw);
  }
});

// ── time: a future ts and an expired stash ──────────────────────────────────────────────────────
test("a stash stamped in the future is refused and cleared", () => {
  const local = storage({ "agience.verify": stashFor(SP, { ts: Date.now() + 10 * 60 * 1000 }) });
  const ctx = page("https://origin.agience.ai/verify-email", { local });
  assert.equal(run(ctx, "readReturn()"), null);
  assert.equal(run(ctx, "readNonce()"), null);
  assert.equal(local.getItem("agience.verify"), null);
});

test("the return expires after an hour; the nonce lives as long as the link", () => {
  const local = storage({ "agience.verify": stashFor(SP, { ts: Date.now() - 61 * 60 * 1000 }) });
  const ctx = page("https://origin.agience.ai/verify-email", { local });
  assert.equal(run(ctx, "readReturn()"), null);
  assert.equal(run(ctx, "readNonce()"), "abc");
});

test("past 24 hours nothing survives", () => {
  const local = storage({ "agience.verify": stashFor(SP, { ts: Date.now() - 24 * 60 * 60 * 1000 - 1 }) });
  const ctx = page("https://origin.agience.ai/verify-email", { local });
  assert.equal(run(ctx, "readNonce()"), null);
  assert.equal(local.getItem("agience.verify"), null);
});

// ── the silent-SSO loop guard ───────────────────────────────────────────────────────────────────
test("at most two hand-offs per tab inside 30 seconds, then the form", () => {
  let t = 1_000_000;
  const session = storage();
  const ctx = page("https://origin.agience.ai/login", { session, now: () => t });
  assert.equal(run(ctx, "ssoHandoffAllowed()"), true);
  t += 1000;
  assert.equal(run(ctx, "ssoHandoffAllowed()"), true);
  t += 1000;
  assert.equal(run(ctx, "ssoHandoffAllowed()"), false);
  assert.equal(run(ctx, "ssoHandoffAllowed()"), false, "a refusal does not reset the count");
  t += 31_000;
  assert.equal(run(ctx, "ssoHandoffAllowed()"), true, "the window expires");
});

test("the count lives in the tab: a fresh page load in the same tab keeps it", () => {
  const session = storage();
  for (let i = 0; i < 2; i++) assert.equal(run(page("https://origin.agience.ai/login", { session }), "ssoHandoffAllowed()"), true);
  assert.equal(run(page("https://origin.agience.ai/login", { session }), "ssoHandoffAllowed()"), false);
  assert.equal(run(page("https://origin.agience.ai/login"), "ssoHandoffAllowed()"), true, "another tab has its own count");
});

test("a tab whose sessionStorage throws gets the form", () => {
  const broken = { getItem() { throw new Error("blocked"); }, setItem() { throw new Error("blocked"); } };
  assert.equal(run(page("https://origin.agience.ai/login", { session: broken }), "ssoHandoffAllowed()"), false);
});

// ── the nonce round trip ────────────────────────────────────────────────────────────────────────
test("register stashes the nonce it sent; the link tab reads it, restores the return and hands off", () => {
  const local = storage();
  const reg = page("https://origin.agience.ai/login?redirect_uri=https%3A%2F%2Fmy.agience.ai%2F&state=S1", { local });
  const nonce = run(reg, "newNonce()");
  assert.match(nonce, /^[0-9a-f]{64}$/);
  run(reg, `stashVerification(${JSON.stringify(nonce)}, "me@example.com")`);

  const link = page("https://origin.agience.ai/verify-email?token=T", { local });
  assert.equal(run(link, "readNonce()"), nonce, "the tab the mail opens sees the same nonce");
  assert.equal(run(link, `restoreReturn(${JSON.stringify(LISTED)})`), true);
  assert.equal(link.location.href, "https://origin.agience.ai/verify-email?redirect_uri=https%3A%2F%2Fmy.agience.ai%2F&state=S1");
  assert.equal(local.getItem("agience.verify"), null, "restoring consumes the stash, nonce included");
  run(link, 'finishLogin("ACCESS")');
  assert.deepEqual(link.navigations, [["replace", "https://my.agience.ai/#access_token=ACCESS&state=S1"]]);
});

test("two nonces are never the same", () => {
  const ctx = page("https://origin.agience.ai/login");
  assert.notEqual(run(ctx, "newNonce()"), run(ctx, "newNonce()"));
});

test("a page without its own return keeps the live one already stashed", () => {
  const local = storage({ "agience.verify": stashFor(SP) });
  const ctx = page("https://origin.agience.ai/login", { local });
  run(ctx, 'stashVerification("n2", "")');
  const s = JSON.parse(local.getItem("agience.verify"));
  assert.equal(s.rd, SP);
  assert.equal(s.st, "S");
  assert.equal(s.n, "n2");
});

test("the verified marker is claimed only for the stashed address", () => {
  const local = storage({ "agience.verify": stashFor(SP, { e: "me@example.com" }) });
  const ctx = page("https://origin.agience.ai/verify-email?sent=1", { local });
  assert.equal(run(ctx, `verifiedIsMine(${JSON.stringify(JSON.stringify({ email: "me@example.com", ts: 1 }))})`), true);
  assert.equal(run(ctx, `verifiedIsMine(${JSON.stringify(JSON.stringify({ email: "other@example.com", ts: 1 }))})`), false);
  assert.equal(run(ctx, 'verifiedIsMine("12345")'), false, "a bare timestamp names no address");
  run(ctx, 'markVerified("Me@Example.com")');
  assert.equal(run(ctx, `verifiedIsMine(localStorage.getItem("agience.verified"))`), true);
});

test("another browser has no nonce to present", () => {
  const ctx = page("https://origin.agience.ai/verify-email?token=T", { local: storage() });
  assert.equal(run(ctx, "readNonce()"), null);
});

// ── never replacing someone else's session ──────────────────────────────────────────────────────
function jwt(claims) {
  const b = (o) => Buffer.from(JSON.stringify(o)).toString("base64").replace(/=+$/, "");
  return b({ alg: "none" }) + "." + b(claims) + ".x";
}

test("a live session for another person is detected; the same person, or none, is not", () => {
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const mine = jwt({ sub: "victim", exp }), theirs = jwt({ sub: "attacker", exp });
  assert.equal(run(page("https://o.agience.ai/", { local: storage({ access_token: mine }) }), `sessionIsAnotherAccount(${JSON.stringify(theirs)})`), true);
  assert.equal(run(page("https://o.agience.ai/", { local: storage({ access_token: mine }) }), `sessionIsAnotherAccount(${JSON.stringify(mine)})`), false);
  assert.equal(run(page("https://o.agience.ai/", { local: storage() }), `sessionIsAnotherAccount(${JSON.stringify(theirs)})`), false);
  const expired = jwt({ sub: "victim", exp: 1 });
  assert.equal(run(page("https://o.agience.ai/", { local: storage({ access_token: expired }) }), `sessionIsAnotherAccount(${JSON.stringify(theirs)})`), false);
});

// ── continue target ─────────────────────────────────────────────────────────────────────────────
test("continue goes to a live listed return, else to app_uri, else nowhere", async () => {
  const withReturn = page("https://origin.agience.ai/account", { local: storage({ "agience.verify": stashFor(SP) }), fetchBody: { sso_return_uris: [SP], app_uri: "https://app.agience.ai/" } });
  assert.equal(await run(withReturn, "continueHref()"), "/login?redirect_uri=https%3A%2F%2Fmy.agience.ai%2F&state=S");
  const unlisted = page("https://origin.agience.ai/account", { local: storage({ "agience.verify": stashFor("https://user-content.agience.ai/x") }), fetchBody: { sso_return_uris: [SP], app_uri: SP } });
  assert.equal(await run(unlisted, "continueHref()"), SP, "an unlisted stashed return is passed over for the app");
  const nothingListed = page("https://origin.agience.ai/account", { local: storage({ "agience.verify": stashFor(SP) }), fetchBody: { app_uri: SP } });
  assert.equal(await run(nothingListed, "continueHref()"), SP);
  assert.equal(await run(page("https://origin.agience.ai/account", { fetchBody: { app_uri: SP } }), "continueHref()"), SP);
  assert.equal(await run(page("https://origin.agience.ai/account", { fetchBody: { app_uri: "javascript:alert(1)" } }), "continueHref()"), null);
  assert.equal(await run(page("https://origin.agience.ai/account", { fetchBody: { app_uri: null } }), "continueHref()"), null);
});

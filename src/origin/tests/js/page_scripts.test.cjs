// Behaviour of the inline scripts of `origin/web/index.html` and `origin/web/verify-email.html`,
// run with `node --test`.
//
// Each page is loaded the way a browser loads it: `app.js`, then the page's own inline script, as
// classic scripts sharing one global scope. The DOM is a minimal stand-in (elements are created on
// first `querySelector` and record what the script does to them), and `fetch`, `localStorage`,
// `sessionStorage`, `location` and `history` are stubs this file controls.
// `test_app_js_behaviour.py` runs it under pytest.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const WEB = path.join(__dirname, "..", "..", "web");
const APP_JS = fs.readFileSync(path.join(WEB, "app.js"), "utf8").replace(/^﻿/, "");
function inlineScript(file) {
  const html = fs.readFileSync(path.join(WEB, file), "utf8");
  const blocks = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  assert.equal(blocks.length, 1, `${file} should carry one inline script`);
  return blocks[0];
}
const INDEX = inlineScript("index.html");
const VERIFY = inlineScript("verify-email.html");

const SP = "https://my.agience.ai/";
const LISTED = [SP];

function storage(initial) {
  const m = new Map(Object.entries(initial || {}));
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => { m.set(k, String(v)); },
    removeItem: (k) => { m.delete(k); },
  };
}

function element(sel, classes) {
  const cls = new Set(classes || []);
  const e = {
    sel, className: "", value: "", href: "", disabled: false, type: "", style: {},
    children: [], listeners: {}, innerHTMLWrites: 0, _text: "",
    classList: {
      add: (c) => cls.add(c), remove: (c) => cls.delete(c), contains: (c) => cls.has(c),
      toggle: (c, f) => { (f === undefined ? !cls.has(c) : f) ? cls.add(c) : cls.delete(c); },
    },
    addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); },
    appendChild(c) { this.children.push(c); return c; },
    focus() {},
    get textContent() { return this._text + this.children.map((c) => c.textContent).join(""); },
    set textContent(v) { this._text = String(v); this.children = []; },
    get innerHTML() { return ""; },
    set innerHTML(v) { this.innerHTMLWrites++; this._text = String(v); this.children = []; },
  };
  return e;
}

// One page load. `local` is the browser's localStorage (shared across tabs), `session` this tab's.
function load(file, href, { local, session, routes } = {}) {
  const url = new URL(href);
  const navigations = [];
  const calls = [];
  const els = new Map();
  const seeded = { "#resend": ["hidden"], "#continue": ["hidden"], "#otp": ["hidden"], "#register": ["hidden"],
                   "#confirm": ["hidden"] };
  const $ = (sel) => { if (!els.has(sel)) els.set(sel, element(sel, seeded[sel])); return els.get(sel); };
  const windowListeners = {};
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
    document: {
      querySelector: $,
      querySelectorAll: () => [],
      createElement: (tag) => element(tag),
      createTextNode: (t) => ({ textContent: String(t) }),
    },
    navigator: {},
    addEventListener: (t, f) => { (windowListeners[t] = windowListeners[t] || []).push(f); },
    removeEventListener: (t, f) => { windowListeners[t] = (windowListeners[t] || []).filter((g) => g !== f); },
    fetch: async (p, init) => {
      const body = init && init.body ? JSON.parse(init.body) : null;
      calls.push([p, body]);
      const r = (routes || {})[p] || { status: 200, body: {} };
      const out = await (typeof r === "function" ? r(body) : r);
      return { ok: out.status < 400, status: out.status, json: async () => out.body };
    },
    URL, URLSearchParams, JSON, Array, Uint8Array, Map, Set, Promise, Date, Math, String, Error,
    crypto: globalThis.crypto,
    TextEncoder,
    atob: (s) => Buffer.from(s, "base64").toString("binary"),
    btoa: (s) => Buffer.from(s, "binary").toString("base64"),
    setTimeout,
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  vm.runInContext(APP_JS, ctx, { filename: "app.js" });
  vm.runInContext(file === "index.html" ? INDEX : VERIFY, ctx, { filename: file });
  return { ctx, $, navigations, calls, windowListeners, local: ctx.localStorage, session: ctx.sessionStorage };
}

const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r)); };

function jwt(claims) {
  const b = (o) => Buffer.from(JSON.stringify(o)).toString("base64").replace(/=+$/, "");
  return b({ alg: "none" }) + "." + b(claims) + ".x";
}
const EXP = Math.floor(Date.now() / 1000) + 3600;
const SESSION = jwt({ sub: "me", exp: EXP });
const providers = (extra) => ({ "/auth/providers": { status: 200, body: Object.assign({ providers: [], sso_return_uris: LISTED, app_uri: SP }, extra) } });
const handedOff = (nav) => nav.some(([, u]) => u.includes("access_token="));

// ── index.html: the silent SSO gate ─────────────────────────────────────────────────────────────
const LOGIN = "https://origin.agience.ai/login?redirect_uri=" + encodeURIComponent(SP) + "&state=S1";

test("a live session is handed to a listed SP without a click", async () => {
  const p = load("index.html", LOGIN, { local: storage({ access_token: SESSION }), routes: providers() });
  await settle();
  assert.deepEqual(p.navigations, [["replace", SP + "#access_token=" + encodeURIComponent(SESSION) + "&state=S1"]]);
});

for (const [name, href] of [
  ["prompt=login", LOGIN + "&prompt=login"],
  ["a federated ?code= return", LOGIN + "&code=abc"],
  ["an ?error= return", LOGIN + "&error=access_denied"],
  ["an agience.ai target that is not listed", "https://origin.agience.ai/login?redirect_uri=" + encodeURIComponent("https://user-content.agience.ai/page") + "&state=S"],
  ["a listed host with another path", "https://origin.agience.ai/login?redirect_uri=" + encodeURIComponent("https://my.agience.ai/redirect?to=x")],
  ["a target outside agience.ai", "https://origin.agience.ai/login?redirect_uri=" + encodeURIComponent("https://evil.example/")],
]) {
  test(`no silent hand-off for ${name}`, async () => {
    const p = load("index.html", href, { local: storage({ access_token: SESSION }), routes: providers() });
    await settle();
    assert.equal(handedOff(p.navigations), false, JSON.stringify(p.navigations));
  });
}

test("no silent hand-off when the server lists nothing", async () => {
  const p = load("index.html", LOGIN, { local: storage({ access_token: SESSION }), routes: providers({ sso_return_uris: [] }) });
  await settle();
  assert.equal(handedOff(p.navigations), false);
});

test("the loop guard stops the third hand-off in a tab", async () => {
  const session = storage();
  for (let i = 0; i < 2; i++) {
    const p = load("index.html", LOGIN, { local: storage({ access_token: SESSION }), session, routes: providers() });
    await settle();
    assert.equal(handedOff(p.navigations), true, `hand-off ${i + 1}`);
  }
  const p = load("index.html", LOGIN, { local: storage({ access_token: SESSION }), session, routes: providers() });
  await settle();
  assert.equal(handedOff(p.navigations), false);
});

for (const [name, act] of [
  ["a password sign-in", (p) => p.$("#loginForm").listeners.submit[0]({ preventDefault() {} })],
  ["a registration", (p) => { p.$("#remail").value = "new@example.com"; p.$("#rpassword").value = "p".repeat(12); return p.$("#registerForm").listeners.submit[0]({ preventDefault() {} }); }],
  ["an emailed-code request", (p) => { p.$("#otpEmail").value = "me@example.com"; return p.$("#otpSendForm").listeners.submit[0]({ preventDefault() {} }); }],
  ["an emailed-code sign-in", (p) => { p.$("#otpEmail").value = "me@example.com"; p.$("#otpCode").value = "123456"; return p.$("#otpCodeForm").listeners.submit[0]({ preventDefault() {} }); }],
  ["a federated start", (p) => vm.runInContext('startFederated("google")', p.ctx)],
]) {
  test(`${name} begun while the return list is in flight abandons the silent hand-off`, async () => {
    let release;
    const gate = new Promise((r) => { release = r; });
    const routes = {
      "/auth/providers": () => gate.then(() => ({ status: 200, body: { providers: [], sso_return_uris: LISTED } })),
      "/auth/password/login": { status: 401, body: {} },
      "/auth/password/register": { status: 400, body: { detail: "no" } },
    };
    const p = load("index.html", LOGIN, { local: storage({ access_token: SESSION }), routes });
    await settle();
    await act(p);
    release();
    await settle();
    assert.equal(handedOff(p.navigations), false, JSON.stringify(p.navigations));
  });
}

test("with no sign-in begun, the same in-flight list still hands off once it arrives", async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const routes = { "/auth/providers": () => gate.then(() => ({ status: 200, body: { providers: [], sso_return_uris: LISTED } })) };
  const p = load("index.html", LOGIN, { local: storage({ access_token: SESSION }), routes });
  await settle();
  assert.equal(handedOff(p.navigations), false);
  release();
  await settle();
  assert.equal(handedOff(p.navigations), true);
});

test("an expired session is not handed off", async () => {
  const p = load("index.html", LOGIN, { local: storage({ access_token: jwt({ sub: "me", exp: 1 }) }), routes: providers() });
  await settle();
  assert.equal(handedOff(p.navigations), false);
});

test("a live session with no SP waiting goes to the account page", async () => {
  const p = load("index.html", "https://origin.agience.ai/login", { local: storage({ access_token: SESSION }), routes: providers() });
  await settle();
  assert.deepEqual(p.navigations, [["replace", "/account"]]);
});

// ── index.html: a busy node is not an OTP-less node ─────────────────────────────────────────────
async function otpSend(body503) {
  const routes = Object.assign(providers(), { "/auth/otp/request": { status: 503, body: body503 } });
  const p = load("index.html", "https://origin.agience.ai/login", { routes });
  await settle();
  p.$("#otpEmail").value = "me@example.com";
  await p.$("#otpSendForm").listeners.submit[0]({ preventDefault() {} });
  await settle();
  return p.$("#msg").textContent;
}

test("a shed OTP request says the node is busy, not that email sign-in is unavailable", async () => {
  const text = await otpSend({ detail: "Sign-in is busy. Please try again in a moment.", error: "busy" });
  assert.match(text, /busy/i);
  assert.doesNotMatch(text, /isn't available/);
});

test("a 503 without the busy code still says email sign-in is unavailable", async () => {
  const text = await otpSend({ detail: "Email service not configured. Use password login instead." });
  assert.match(text, /isn't available on this node/);
});

// ── index.html: what a refused sign-in stashes ──────────────────────────────────────────────────
async function refusedLogin(error, { local } = {}) {
  const routes = Object.assign(providers(), {
    "/auth/password/login": { status: 403, body: Object.assign({ detail: "refused" }, error ? { error } : {}) },
  });
  const p = load("index.html", LOGIN, { local: local || storage(), routes });
  await settle();
  p.$("#identifier").value = "Me@Example.com";
  p.$("#password").value = "pw";
  await p.$("#loginForm").listeners.submit[0]({ preventDefault() {} });
  await settle();
  return p;
}

test("the unverified 403 stashes the nonce it sent, with the address", async () => {
  const p = await refusedLogin("email_unverified");
  const sent = p.calls.find(([u]) => u === "/auth/password/login")[1];
  const s = JSON.parse(p.local.getItem("agience.verify"));
  assert.equal(s.n, sent.verify_nonce);
  assert.equal(s.e, "me@example.com");
  assert.equal(s.rd, SP);
});

test("any other 403 leaves the stash as it was", async () => {
  const before = JSON.stringify({ n: "old", e: "x@example.com", rd: SP, st: "S0", ts: Date.now() });
  const p = await refusedLogin(null, { local: storage({ "agience.verify": before }) });
  assert.equal(p.local.getItem("agience.verify"), before);
});

// ── verify-email.html: redeeming a link ─────────────────────────────────────────────────────────
function verifyRoutes(confirm) {
  return Object.assign(providers(), { "/auth/email/verify-confirm": confirm });
}
const LINK = "https://origin.agience.ai/verify-email?token=T";
const stashed = (extra) => JSON.stringify(Object.assign({ n: "N", e: "me@example.com", rd: SP, st: "S1", ts: Date.now() }, extra));

test("with its nonce, the link tab restores the listed return and hands the new session off", async () => {
  const minted = jwt({ sub: "me", exp: EXP });
  const local = storage({ "agience.verify": stashed() });
  const p = load("verify-email.html", LINK, { local, routes: verifyRoutes({ status: 200, body: { verified: true, email: "me@example.com", access_token: minted } }) });
  await settle();
  const sent = p.calls.find(([u]) => u === "/auth/email/verify-confirm")[1];
  assert.equal(sent.verify_nonce, "N", "the stashed nonce is presented");
  assert.deepEqual(p.navigations, [["replace", SP + "#access_token=" + encodeURIComponent(minted) + "&state=S1"]]);
  assert.equal(local.getItem("access_token"), minted);
  assert.equal(local.getItem("agience.verify"), null, "the stash is consumed");
  assert.equal(JSON.parse(local.getItem("agience.verified")).email, "me@example.com", "the marker is written first");
});

test("a return that is not listed is not followed; the session is kept and Continue offered", async () => {
  const minted = jwt({ sub: "me", exp: EXP });
  const local = storage({ "agience.verify": stashed({ rd: "https://user-content.agience.ai/x" }) });
  const p = load("verify-email.html", LINK, { local, routes: verifyRoutes({ status: 200, body: { verified: true, email: "me@example.com", access_token: minted } }) });
  await settle();
  assert.equal(handedOff(p.navigations), false);
  assert.equal(p.$("#continue").classList.contains("hidden"), false);
});

test("a session for someone else is never replaced and nothing is handed off", async () => {
  const theirs = jwt({ sub: "attacker", exp: EXP });
  const local = storage({ access_token: SESSION, "agience.verify": stashed() });
  const p = load("verify-email.html", LINK, { local, routes: verifyRoutes({ status: 200, body: { verified: true, email: "a@x.com", access_token: theirs } }) });
  await settle();
  assert.equal(local.getItem("access_token"), SESSION);
  assert.equal(p.navigations.length, 0);
  assert.match(p.$("#msg").textContent, /someone else/);
});

test("verified without a token: nothing saved, a sign-in link offered", async () => {
  const local = storage();
  const p = load("verify-email.html", LINK, { local, routes: verifyRoutes({ status: 200, body: { verified: true, email: "me@example.com" } }) });
  await settle();
  assert.equal(local.getItem("access_token"), null);
  assert.equal(p.navigations.length, 0);
  const link = p.$("#msg").children.find((c) => c.className === "signin");
  assert.ok(link, "no sign-in link was built");
  assert.equal(link.href, "/");
});

test("server detail is rendered as text, and already-verified hides the resend form", async () => {
  const p = load("verify-email.html", LINK, { routes: verifyRoutes({ status: 400, body: { detail: "<img src=x onerror=alert(1)>", error: "already_verified" } }) });
  await settle();
  assert.equal(p.$("#msg").innerHTMLWrites, 0, "innerHTML must not be written");
  assert.match(p.$("#msg").textContent, /<img src=x/);
  assert.equal(p.$("#resend").classList.contains("hidden"), true);
});

test("any other failure offers the resend form", async () => {
  const p = load("verify-email.html", LINK, { routes: verifyRoutes({ status: 400, body: { detail: "no longer valid" } }) });
  await settle();
  assert.equal(p.$("#resend").classList.contains("hidden"), false);
});

test("an account with a password: the link asks for it, and confirms with it", async () => {
  const local = storage({ "agience.verify": stashed() });
  const answers = [{ status: 200, body: { password_required: true } },
                   { status: 401, body: { detail: "That password doesn't match this account." } },
                   { status: 200, body: { verified: true, email: "me@example.com" } }];
  const p = load("verify-email.html", LINK, { local, routes: verifyRoutes(() => answers.shift()) });
  await settle();
  assert.equal(p.$("#confirm").classList.contains("hidden"), false, "no password prompt");
  assert.equal(p.$("#resend").classList.contains("hidden"), true);

  p.$("#cpassword").value = "wrong";
  await p.$("#confirm").listeners.submit[0]({ preventDefault() {} });
  assert.match(p.$("#msg").textContent, /doesn't match/);
  assert.equal(p.$("#confirm").classList.contains("hidden"), false, "the prompt stays after a wrong password");

  p.$("#cpassword").value = "right";
  await p.$("#confirm").listeners.submit[0]({ preventDefault() {} });
  const bodies = p.calls.filter(([u]) => u === "/auth/email/verify-confirm").map(([, b]) => b);
  assert.equal(bodies[2].password, "right");
  assert.equal(bodies[2].verify_nonce, "N", "the nonce still goes with the password");
  assert.equal(p.$("#confirm").classList.contains("hidden"), true);
  assert.match(p.$("#msg").textContent, /Email verified/);
});

test("an empty password is not sent, and never reads as verified", async () => {
  const p = load("verify-email.html", LINK, { routes: verifyRoutes({ status: 200, body: { password_required: true } }) });
  await settle();
  const before = p.calls.length;
  await p.$("#confirm").listeners.submit[0]({ preventDefault() {} });
  assert.equal(p.calls.length, before, "an empty password was posted");
  assert.equal(p.$("#confirm").classList.contains("hidden"), false);
  assert.doesNotMatch(p.$("#msg").textContent, /verified/i);
});

test("a busy or throttled answer keeps the prompt", async () => {
  for (const status of [429, 503]) {
    const answers = [{ status: 200, body: { password_required: true } }, { status, body: { detail: "busy" } }];
    const p = load("verify-email.html", LINK, { routes: verifyRoutes(() => answers.shift()) });
    await settle();
    p.$("#cpassword").value = "pw";
    await p.$("#confirm").listeners.submit[0]({ preventDefault() {} });
    assert.equal(p.$("#confirm").classList.contains("hidden"), false, `a ${status} hid the prompt`);
    assert.equal(p.$("#resend").classList.contains("hidden"), true, `a ${status} offered a resend`);
  }
});

test("the mailbox's holder can disown an account they did not create", async () => {
  const answers = [{ status: 200, body: { password_required: true } },
                   { status: 200, body: { verified: true, password_cleared: true } }];
  const p = load("verify-email.html", LINK, { routes: verifyRoutes(() => answers.shift()) });
  await settle();
  const before = p.calls.length;
  await p.$("#disownBtn").listeners.click[0]();
  assert.equal(p.calls.length, before, "one click disowned: it takes two");
  await p.$("#disownBtn").listeners.click[0]();
  const last = p.calls.filter(([u]) => u === "/auth/email/verify-confirm").pop()[1];
  assert.deepEqual(last, { token: "T", disown: true }, "disowning sends no password and no nonce");
  assert.match(p.$("#msg").textContent, /password set when this account was created was removed/);
  assert.equal(p.$("#confirm").classList.contains("hidden"), true);
});

// ── verify-email.html: the tab waiting on ?sent=1 ───────────────────────────────────────────────
test("the waiting tab flips only for its own address, and hands nothing off", async () => {
  const local = storage({ "agience.verify": stashed() });
  const p = load("verify-email.html", "https://origin.agience.ai/verify-email?sent=1", { local, routes: providers() });
  await settle();
  const [listener] = p.windowListeners.storage;
  assert.ok(listener, "no storage listener in the sent state");

  listener({ key: "access_token", newValue: SESSION });
  listener({ key: "agience.verified", newValue: JSON.stringify({ email: "someone.else@example.com", ts: Date.now() }) });
  await settle();
  assert.match(p.$("#msg").textContent, /Check your inbox/);

  listener({ key: "agience.verified", newValue: JSON.stringify({ email: "me@example.com", ts: Date.now() }) });
  await settle();
  assert.match(p.$("#msg").textContent, /Email verified/);
  assert.equal(p.$("#continue").classList.contains("hidden"), false);
  assert.equal(p.$("#continue").href, "/login?redirect_uri=" + encodeURIComponent(SP) + "&state=S1");
  assert.equal(p.navigations.length, 0);
  assert.equal(local.getItem("access_token"), null);
});

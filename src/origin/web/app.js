/* Agience Origin — shared auth helpers (vanilla, same-origin /auth/*). */
async function api(method, path, body) {
  let r;
  try {
    r = await fetch(path, {
      method,
      headers: { "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    return { ok: false, status: 0, data: {}, detail: "Network error" };
  }
  let data = {};
  try { data = await r.json(); } catch (e) { /* empty body */ }
  return { ok: r.ok, status: r.status, data, detail: (data && data.detail) || null };
}
const post = (p, b) => api("POST", p, b);
const get = (p) => api("GET", p, null);

function saveToken(t) { try { localStorage.setItem("access_token", t); } catch (e) {} }
function getToken() { try { return localStorage.getItem("access_token"); } catch (e) { return null; } }
function clearToken() { try { localStorage.removeItem("access_token"); } catch (e) {} }
function decodeJwt(t) {
  try { return JSON.parse(atob(t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))); }
  catch (e) { return null; }
}
function isAuthed() {
  const t = getToken(); if (!t) return false;
  const c = decodeJwt(t);
  return !!(c && (!c.exp || c.exp * 1000 > Date.now()));
}
function qs(n) { return new URLSearchParams(location.search).get(n); }

// The animated background lives in `bg.js`, not here: this file is not presentation.
// `/auth/authorize` needs the background but must not have `saveToken`/`finishLogin` below in
// reach: it is an authorization-code + PKCE surface, and a page that cannot save a token cannot
// leak one. Every page that wants the background loads `/web/bg.js`; only the pages that hold a
// session load this one.

// SSO: if an allowlisted SP sent us here with ?redirect_uri, hand the token back in the fragment.
// This is the implicit flow, and the authorization-code flow at `/auth/authorize` is preferred:
// an unvalidated `redirect_uri` is an open redirector, a token in a fragment lands in history and
// `Referer`, and `localStorage` outlives the tab. It survives here only for the pages that already
// use it — no new caller should reach for it.
//
// `SP_ALLOW` admits any `*.agience.ai` page, and is the bound for a hand-off the person has just
// signed in for. A hand-off with no sign-in in between (silent SSO, or the verify page returning to
// a stashed target) additionally needs `isListedReturn`: the target's origin and path must be one
// of the exact return URIs the server publishes (`sso_return_uris` on `/auth/providers`). Without
// that, an open redirect or a user-authored page on any subdomain would receive a token with no
// click at all.
const SP_ALLOW = /^https:\/\/([a-z0-9-]+\.)*agience\.ai(\/|$)/i;
function isListedReturn(rd, listed) {
  if (typeof rd !== "string" || !SP_ALLOW.test(rd) || !Array.isArray(listed)) return false;
  let u;
  try { u = new URL(rd); } catch (e) { return false; }
  if (u.username || u.password || u.search || u.hash) return false;
  return listed.indexOf(u.origin + u.pathname) !== -1;
}
async function ssoReturnUris() {
  const r = await get("/auth/providers");
  const list = r.ok && r.data && r.data.sso_return_uris;
  return Array.isArray(list) ? list.filter((u) => typeof u === "string") : [];
}
function finishLogin(token) {
  saveToken(token);
  const rd = qs("redirect_uri");
  if (rd && SP_ALLOW.test(rd)) {
    clearVerification();
    const sep = rd.includes("#") ? "&" : "#";
    const st = qs("state");
    location.replace(rd + sep + "access_token=" + encodeURIComponent(token) + (st ? "&state=" + encodeURIComponent(st) : ""));
    return;
  }
  location.href = "/account";
}

// Verification state, kept in this browser across the verification email: `{n, e, rd, st, ts}`.
//
// `n` is the verification nonce. The page that starts a verification (registration, or a sign-in
// refused as unverified) generates it, sends it with the request that mails the link — the server
// binds its hash into the link — and keeps it here. Redeeming the link signs in only when the
// redeeming browser presents it, so a link forwarded from someone else's mailbox verifies that
// address and signs nobody in here. It lives as long as the link does, 24 hours.
//
// `e` is the address being verified, so a waiting tab claims only its own verification.
//
// `rd`/`st` are the SP's `redirect_uri`/`state`, which neither `/verify-email?sent=1` nor the
// mailed link carries. They are put back on the URL before `finishLogin`, which then hands off
// exactly as if the round trip never happened. One hour: long enough to find the mail and click
// it, short enough that a shared browser does not carry one person's pending return into someone
// else's session. Past it the person still verifies and is offered the app URL instead.
//
// `localStorage`, not `sessionStorage`: the link opens a different tab.
const VERIFY_KEY = "agience.verify";
const NONCE_TTL_MS = 24 * 60 * 60 * 1000;
const RETURN_TTL_MS = 60 * 60 * 1000;
// Written by the tab that redeems a link, as `{email, ts}`, so a tab waiting on `?sent=1` learns
// of it and can tell whether it was its own address. A key of its own rather than `access_token`,
// which every sign-in writes.
const VERIFIED_KEY = "agience.verified";
function clearVerification() { try { localStorage.removeItem(VERIFY_KEY); } catch (e) {} }
function newNonce() {
  const v = new Uint8Array(32); crypto.getRandomValues(v);
  return Array.from(v, (b) => b.toString(16).padStart(2, "0")).join("");
}
// A page without its own return target keeps the one already stashed and still live, so a second
// attempt from a bare `/login` does not discard where the person came from.
function stashVerification(nonce, email) {
  const rd = qs("redirect_uri"), ok = !!rd && SP_ALLOW.test(rd), kept = ok ? null : readReturn();
  try {
    localStorage.setItem(VERIFY_KEY, JSON.stringify({
      n: nonce, e: (email || "").toLowerCase(),
      rd: ok ? rd : (kept ? kept.rd : ""), st: ok ? (qs("state") || "") : (kept ? kept.st : ""),
      ts: Date.now(),
    }));
  } catch (e) {}
}
function readVerification() {
  let s = null;
  try { s = JSON.parse(localStorage.getItem(VERIFY_KEY) || "null"); } catch (e) { s = null; }
  const age = s && typeof s.ts === "number" ? Date.now() - s.ts : -1;
  if (!s || typeof s !== "object" || !(age >= 0 && age < NONCE_TTL_MS)) {
    if (s !== null) clearVerification();
    return null;
  }
  return s;
}
function readNonce() {
  const s = readVerification();
  return s && typeof s.n === "string" && s.n ? s.n : null;
}
function readReturn() {
  const s = readVerification();
  if (!s || typeof s.rd !== "string" || !SP_ALLOW.test(s.rd) || Date.now() - s.ts >= RETURN_TTL_MS) return null;
  return s;
}
// Put a live return back on this page's URL and consume the stash, when its target is one of the
// exact `listed` return URIs. True when it did.
function restoreReturn(listed) {
  const s = readReturn(); if (!s || !isListedReturn(s.rd, listed)) return false;
  clearVerification();
  const url = new URL(location.href);
  url.search = "";
  url.searchParams.set("redirect_uri", s.rd);
  if (s.st) url.searchParams.set("state", s.st);
  history.replaceState(null, "", url.toString());
  return true;
}
function markVerified(email) {
  try { localStorage.setItem(VERIFIED_KEY, JSON.stringify({ email: (email || "").toLowerCase(), ts: Date.now() })); } catch (e) {}
}
// True when a `VERIFIED_KEY` value names the address this browser stashed for verification.
function verifiedIsMine(value) {
  let v = null;
  try { v = JSON.parse(value || "null"); } catch (e) { v = null; }
  const s = readVerification();
  return !!(v && typeof v.email === "string" && v.email && s && typeof s.e === "string" && s.e === v.email);
}
// True when this browser already holds a live session for a different person than `token` names.
// The verify page never replaces such a session.
function sessionIsAnotherAccount(token) {
  const cur = isAuthed() ? decodeJwt(getToken()) : null, next = decodeJwt(token);
  return !!(cur && next && cur.sub && next.sub && cur.sub !== next.sub);
}
// Where "Sign in" should go: `/login` carrying a live return, so an existing session hands off
// silently and a fresh sign-in still returns to the SP.
function signInHref() {
  const s = readReturn(); if (!s) return "/";
  const p = new URLSearchParams({ redirect_uri: s.rd });
  if (s.st) p.set("state", s.st);
  return "/login?" + p.toString();
}

// Silent SSO loop guard. If an SP refuses the token it is handed (a revoked key, a clock skew) it
// sends the person straight back, and the sign-in page would hand the same token over again. At
// most `SSO_MAX` hand-offs per tab inside `SSO_WINDOW_MS`; past that the form is shown. A tab
// whose `sessionStorage` cannot be used gets the form too, since its hand-offs cannot be counted.
const SSO_KEY = "agience.sso";
const SSO_MAX = 2;
const SSO_WINDOW_MS = 30 * 1000;
function ssoHandoffAllowed() {
  const now = Date.now();
  let a;
  try { a = JSON.parse(sessionStorage.getItem(SSO_KEY) || "[]"); } catch (e) { return false; }
  if (!Array.isArray(a)) a = [];
  a = a.filter((t) => typeof t === "number" && now - t >= 0 && now - t < SSO_WINDOW_MS);
  const allowed = a.length < SSO_MAX;
  if (allowed) a.push(now);
  try { sessionStorage.setItem(SSO_KEY, JSON.stringify(a)); } catch (e) { return false; }
  return allowed;
}
// Where "Continue to Agience" goes: the stashed return if one is live and among the server's exact
// return URIs, else the app URL Origin is configured with (`app_uri`), else null. Both come from
// `/auth/providers`.
async function continueHref() {
  const r = await get("/auth/providers");
  const d = (r.ok && r.data) || {};
  const s = readReturn();
  if (s && isListedReturn(s.rd, Array.isArray(d.sso_return_uris) ? d.sso_return_uris : [])) return signInHref();
  const app = d.app_uri;
  return (typeof app === "string" && /^https?:\/\//i.test(app)) ? app : null;
}

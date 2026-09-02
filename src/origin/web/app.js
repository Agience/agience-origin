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
const SP_ALLOW = /^https:\/\/([a-z0-9-]+\.)*agience\.ai(\/|$)/i;
function finishLogin(token) {
  saveToken(token);
  const rd = qs("redirect_uri");
  if (rd && SP_ALLOW.test(rd)) {
    const sep = rd.includes("#") ? "&" : "#";
    const st = qs("state");
    location.replace(rd + sep + "access_token=" + encodeURIComponent(token) + (st ? "&state=" + encodeURIComponent(st) : ""));
    return;
  }
  location.href = "/account";
}

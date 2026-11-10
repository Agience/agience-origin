/* Agience Origin — every passkey ceremony, on Origin's own page (review 7, F1).
 *
 * Origin is the WebAuthn relying party and the only origin it accepts an assertion or a
 * registration from is its own address, so these ceremonies run here and nowhere else: sign-in,
 * registering and removing a passkey (each behind a fresh step-up), and the operator console's
 * sign-in. Every request goes same-origin to Origin; nothing is relayed through another site.
 * Needs app.js (api, post, get, getToken, saveToken, finishLogin).
 */
function b64uToBuf(s) {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s), out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
function bufToB64u(buf) {
  const b = new Uint8Array(buf); let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function strToB64u(str) { return bufToB64u(new TextEncoder().encode(str)); }
async function sha256Hex(text) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text || ""));
  return Array.from(new Uint8Array(d)).map(function (x) { return x.toString(16).padStart(2, "0"); }).join("");
}

function requestOptions(o) {
  return { publicKey: Object.assign({}, o, {
    challenge: b64uToBuf(o.challenge),
    allowCredentials: (o.allowCredentials || []).map(function (c) {
      return Object.assign({}, c, { id: b64uToBuf(c.id) }); }) }) };
}
function creationOptions(o) {
  return { publicKey: Object.assign({}, o, {
    challenge: b64uToBuf(o.challenge),
    user: Object.assign({}, o.user, { id: b64uToBuf(o.user.id) }),
    excludeCredentials: (o.excludeCredentials || []).map(function (c) {
      return Object.assign({}, c, { id: b64uToBuf(c.id) }); }) }) };
}
function assertionJSON(cred) {
  const r = cred.response;
  return { id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type, response: {
    clientDataJSON: bufToB64u(r.clientDataJSON), authenticatorData: bufToB64u(r.authenticatorData),
    signature: bufToB64u(r.signature), userHandle: r.userHandle ? bufToB64u(r.userHandle) : null } };
}
function attestationJSON(cred) {
  const r = cred.response;
  return { id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type, response: {
    clientDataJSON: bufToB64u(r.clientDataJSON), attestationObject: bufToB64u(r.attestationObject),
    transports: r.getTransports ? r.getTransports() : [] } };
}

async function authed(method, path, body, extra) {
  const headers = Object.assign({ "Content-Type": "application/json",
                                  Authorization: "Bearer " + (getToken() || "") }, extra || {});
  const r = await fetch(path, { method: method, headers: headers,
                                body: body === undefined ? undefined : body });
  let data = {}; try { data = await r.json(); } catch (e) {}
  return { ok: r.ok, status: r.status, data: data, detail: data && data.detail };
}

/* Sign in with a passkey. */
async function passkeySignIn(email) {
  const o = await post("/auth/passkey/login-options", { email: email });
  if (!o.ok) return o;
  const cred = await navigator.credentials.get(requestOptions(o.data.options));
  const done = await post("/auth/passkey/login-complete",
                          { challenge: o.data.options.challenge, credential: assertionJSON(cred) });
  if (done.ok) { saveToken(done.data.access_token); finishLogin(done.data.access_token); }
  return done;
}

/* A fresh step-up for exactly this request: a passkey assertion, or, with no passkey, a
 * re-authentication at Origin's own sign-in (a ticket, proven there, then sent back). */
async function stepUp(method, path, bodyText) {
  const o = await authed("POST", "/auth/me/step-up-options", JSON.stringify(
    { method: method, path: path, body_sha256: await sha256Hex(bodyText) }));
  if (!o.ok) throw new Error(o.detail || "step-up refused");
  if (o.data.kind === "reauth") {
    sessionStorage.setItem("pending_step_up", JSON.stringify({ method: method, path: path,
                                                                ticket: o.data.ticket,
                                                                back: location.href }));
    location.href = o.data.url;               // Origin's own sign-in; comes back proven
    return null;
  }
  if (!window.confirm("Origin is asking for your passkey to: " + (o.data.action || path) +
                      ". Continue?")) return null;
  const cred = await navigator.credentials.get(requestOptions(o.data.options));
  return strToB64u(JSON.stringify({ challenge: o.data.options.challenge,
                                    credential: assertionJSON(cred) }));
}
function provenTicket(method, path) {
  try {
    const p = JSON.parse(sessionStorage.getItem("pending_step_up") || "null");
    if (p && p.method === method && p.path === path) {
      sessionStorage.removeItem("pending_step_up"); return "reauth:" + p.ticket;
    }
  } catch (e) {}
  return null;
}

/* Register a passkey for the signed-in person, behind a fresh step-up. */
async function registerPasskey(deviceName) {
  const path = "/auth/passkey/register-options", body = "";
  const step = provenTicket("POST", path) || await stepUp("POST", path, body);
  if (step === null) return null;
  const o = await authed("POST", path, undefined, { "X-Step-Up": step });
  if (!o.ok) return o;
  const cred = await navigator.credentials.create(creationOptions(o.data.options));
  return authed("POST", "/auth/passkey/register-complete", JSON.stringify(
    { challenge: o.data.options.challenge, credential: attestationJSON(cred),
      device_name: deviceName || "" }));
}

/* Remove one of the signed-in person's passkeys, behind a fresh step-up. */
async function removePasskey(id) {
  const path = "/auth/passkey/credentials/" + encodeURIComponent(id);
  const step = provenTicket("DELETE", path) || await stepUp("DELETE", path, "");
  if (step === null) return null;
  return authed("DELETE", path, undefined, { "X-Step-Up": step });
}

/* The operator console's sign-in: the console token stays in this tab's session storage. */
async function consoleSignIn() {
  const o = await post("/oracle/console/sign-in-options", {});
  if (!o.ok) return o;
  const cred = await navigator.credentials.get(requestOptions(o.data));
  const done = await post("/oracle/console/sign-in",
                          { challenge: o.data.challenge, credential: assertionJSON(cred) });
  if (done.ok) sessionStorage.setItem("console_token", done.data.token);
  return done;
}

/* Link another sign-in method to this account (review 9). The person signs in through the method
 * to add, fresh, with Origin's own platform client, coming back to this page with a code; the
 * link is then sent behind a step-up, in their Origin session. */
/* A link attempt is begun here, in your Origin session: Origin records a random state for it and
   the PKCE challenge the sign-in must carry, and links nothing that does not come back with both. */
async function linkStart() {
  const verifier = bufToB64u(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = bufToB64u(await crypto.subtle.digest("SHA-256",
                                                          new TextEncoder().encode(verifier)));
  const a = await authed("POST", "/auth/me/link-attempts",
                         JSON.stringify({ code_challenge: challenge }));
  if (!a.ok) throw new Error(a.detail || "link refused");
  sessionStorage.setItem("link_verifier", verifier);
  sessionStorage.setItem("link_state", a.data.state);
  const back = location.origin + "/passkey";
  location.href = "/auth/authorize?" + new URLSearchParams({
    client_id: "platform", response_type: "code", redirect_uri: back, scope: "openid",
    state: a.data.state, code_challenge: challenge, code_challenge_method: "S256",
    prompt: "login", max_age: "0" }).toString();
}
async function linkFinish(code, state) {
  const verifier = sessionStorage.getItem("link_verifier");
  const mine = sessionStorage.getItem("link_state");
  if (!verifier || !mine || mine !== state) {
    return { ok: false, detail: "This sign-in was not started here." };
  }
  const path = "/auth/me/link-provider";
  const body = JSON.stringify({ code: code, code_verifier: verifier, state: state,
                                redirect_uri: location.origin + "/passkey" });
  const step = provenTicket("POST", path) || await stepUpWithBody("POST", path, body);
  if (step === null) return null;
  sessionStorage.removeItem("link_verifier");
  sessionStorage.removeItem("link_state");
  return authed("POST", path, body, { "X-Step-Up": step });
}
/* As stepUp, with the body shown to Origin so its page can name exactly what is being linked. */
async function stepUpWithBody(method, path, bodyText) {
  const o = await authed("POST", "/auth/me/step-up-options", JSON.stringify(
    { method: method, path: path, body_sha256: await sha256Hex(bodyText), body: bodyText }));
  if (!o.ok) throw new Error(o.detail || "step-up refused");
  if (o.data.kind === "reauth") {
    sessionStorage.setItem("pending_step_up", JSON.stringify({ method: method, path: path,
                                                                ticket: o.data.ticket,
                                                                body: bodyText,
                                                                back: location.href }));
    location.href = o.data.url;
    return null;
  }
  if (!window.confirm("Origin is asking for your passkey to: " + (o.data.action || path) +
                      ". Continue?")) return null;
  const cred = await navigator.credentials.get(requestOptions(o.data.options));
  return strToB64u(JSON.stringify({ challenge: o.data.options.challenge,
                                    credential: assertionJSON(cred) }));
}

/* The person's own background job grants: listed, and revoked, here. */
async function jobGrants() { return authed("GET", "/auth/me/job-grants"); }
/* Revoking a grant needs a fresh step-up too (review 11, M7): a click stolen in a framed page
 * proves nothing, and Origin's pages are never framed anyway. */
async function revokeJobGrant(id) {
  const path = "/auth/me/job-grants/" + encodeURIComponent(id) + "/revoke";
  const step = provenTicket("POST", path) || await stepUp("POST", path, "");
  if (step === null) return null;
  return authed("POST", path, undefined, { "X-Step-Up": step });
}

const $=(s)=>document.querySelector(s), msg=$("#msg");
function show(t,cls){ msg.className="msg "+(cls||"muted"); msg.textContent=t||""; }

// Sent here from a sign-in whose app this service doesn't list (`finishLogin`): name the app.
// Text only, so the origin can never be markup.
(function(){
  const unlisted = new URLSearchParams(location.search).get("unlisted");
  if (unlisted) show("You're signed in, but " + unlisted + " isn't registered with this sign-in " +
                     "service, so you weren't sent back to it.", "err");
})();

// Who is signed in comes from Origin, not from the token in this browser: a token for an account
// this store doesn't hold, or one since deactivated, is answered with a refusal and signs out here.
let claims = {};
(async function(){
  const t = getToken();
  if (!t) return;
  let r;
  try { r = await fetch("/auth/userinfo", { headers: { Authorization: "Bearer " + t }, cache: "no-store" }); }
  catch (e) { show("The sign-in service can't be reached. Try again shortly.", "err"); return; }
  if (r.status === 401 || r.status === 403 || r.status === 404) { clearToken(); location.replace("/logout"); return; }
  if (!r.ok) { show("Your account couldn't be loaded. Try again shortly.", "err"); return; }
  let me = {}; try { me = await r.json(); } catch (e) { /* empty body */ }
  claims = { name: me.name, email: me.email, roles: me.roles, sub: me.id };
  const rows = [
    ["Name", claims.name || "—"],
    ["Email", claims.email || "—"],
    ["Roles", (claims.roles && claims.roles.length ? claims.roles.join(", ") : "—")],
    ["ID", claims.sub || "—"],
  ];
  $("#details").innerHTML = rows.map(function(r){
    return '<div class="kv"><span class="k">'+r[0]+'</span><span>'+String(r[1]).replace(/&/g,"&amp;").replace(/</g,"&lt;")+'</span></div>';
  }).join("");
})();

// The way back to the app: the SP that sent this person here if its return is still stashed,
// else the app URL Origin is configured with. Hidden when there is neither.
continueHref().then(function(href){
  if (!href) return;
  const a=$("#continue"); a.href=href; a.classList.remove("hidden");
});

// change password = trigger a reset email to the account's email (needs email on file)
$("#changePw").addEventListener("click", async ()=>{
  if (!claims.email) { show("No email on file for this account — can't send a reset link.","err"); return; }
  const b=$("#changePw"); b.disabled=true; show("Sending reset link…");
  await post("/auth/password/reset-request", { email: claims.email });
  show("Reset link sent to " + claims.email + " — check your inbox.","ok");
  setTimeout(()=>{ b.disabled=false; }, 1500);
});

$("#signout").addEventListener("click", ()=>{ clearToken(); location.href="/logout"; });

// Actions that need the Origin session (the one the approvals page signs in): shown when it
// answers. With neither a bearer token nor a session, there is nothing to show here.
async function sessionCall(method, path, body) {
  try {
    const r = await fetch(path, { method: method, credentials: "same-origin", referrerPolicy: "same-origin",
                                  headers: body ? { "Content-Type": "application/json" } : {},
                                  body: body ? JSON.stringify(body) : undefined, cache: "no-store" });
    let data = {}; try { data = await r.json(); } catch (e) { /* empty body */ }
    return { ok: r.ok, status: r.status, data: data, detail: (data && data.detail) || null };
  } catch (e) { return { ok: false, status: 0, data: {}, detail: "Network error" }; }
}
(async function(){
  const authed = isAuthed();
  if (!authed) { $("#details").classList.add("hidden"); $("#changePw").parentNode.classList.add("hidden"); }
  const s = await sessionCall("GET", "/notes/page/state");
  if (!s.ok) { if (!authed) location.replace("/"); return; }
  let state = s.data;
  const label = function(){
    const n = (state.notes || []).length, b = $("#revokeAll");
    b.textContent = "Revoke all unspent approvals" + (n ? " (" + n + ")" : "");
    b.disabled = !n;
  };
  label();
  $("#sessionActions").classList.remove("hidden");
  $("#revokeAll").addEventListener("click", async ()=>{
    if (!confirm("Revoke every unspent approval? Agents holding one can no longer act on it.")) return;
    const r = await sessionCall("POST", "/notes/page/revoke-all", { form: state.revoke_all_form });
    if (!r.ok) { show(r.detail || "Revoking failed.", "err"); return; }
    show("Revoked " + r.data.revoked + " approval" + (r.data.revoked === 1 ? "" : "s") + ".", "ok");
    const again = await sessionCall("GET", "/notes/page/state");
    if (again.ok) { state = again.data; label(); }
  });
  $("#signOutAll").addEventListener("click", async ()=>{
    if (!confirm("Sign out of every device and end every job grant? Approvals already given stay " +
                 "until you revoke them.")) return;
    const r = await sessionCall("POST", "/notes/page/sign-out-everywhere", { form: state.sign_out_form });
    if (!r.ok) { show(r.detail || "Signing out failed.", "err"); return; }
    clearToken(); location.href = "/logout";
  });
})();

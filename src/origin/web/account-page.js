if (!isAuthed()) location.replace("/");
const $=(s)=>document.querySelector(s), msg=$("#msg");
function show(t,cls){ msg.className="msg "+(cls||"muted"); msg.textContent=t||""; }

// Sent here from a sign-in whose app this service doesn't list (`finishLogin`): name the app.
// Text only, so the origin can never be markup.
(function(){
  const unlisted = new URLSearchParams(location.search).get("unlisted");
  if (unlisted) show("You're signed in, but " + unlisted + " isn't registered with this sign-in " +
                     "service, so you weren't sent back to it.", "err");
})();

const claims = decodeJwt(getToken()) || {};
const rows = [
  ["Name", claims.name || "—"],
  ["Email", claims.email || "—"],
  ["Roles", (claims.roles && claims.roles.length ? claims.roles.join(", ") : "—")],
  ["ID", claims.sub || "—"],
];
$("#details").innerHTML = rows.map(function(r){
  return '<div class="kv"><span class="k">'+r[0]+'</span><span>'+String(r[1]).replace(/</g,"&lt;")+'</span></div>';
}).join("");

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

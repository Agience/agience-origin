const $ = (s)=>document.querySelector(s), msg=$("#msg");
const token = qs("token");
function show(t,cls){ msg.className="msg "+(cls||"muted"); msg.textContent=t||""; }

if (token) { $("#request").classList.add("hidden"); $("#confirm").classList.remove("hidden"); }
// The account comes from the token (server-side), never from the URL: a link cannot be made to
// name one account while resetting another.
if (token) {
  post("/auth/password/reset-check", { token }).then((r) => {
    if (r.ok && r.data && r.data.email) {
      $("#user").value = r.data.email;
      $("#user").classList.remove("hidden"); $("#userLabel").classList.remove("hidden");
    } else {
      $("#confirm").classList.add("hidden");
      show("This reset link is invalid or has expired. Request a new one.", "err");
    }
  });
}

// request a reset link
$("#reqForm") && $("#reqForm").addEventListener("submit", async (e)=>{
  e.preventDefault(); const b=$("#reqBtn"); b.disabled=true; show("Sending…");
  await post("/auth/password/reset-request", { email: $("#email").value.trim().toLowerCase() });
  // same UX whether or not the account exists
  $("#reqForm").classList.add("hidden"); $("#reqSent").classList.remove("hidden"); show("");
});

// confirm new password
$("#confForm") && $("#confForm").addEventListener("submit", async (e)=>{
  e.preventDefault();
  if ($("#np").value !== $("#np2").value) { show("Passwords do not match.","err"); return; }
  if ($("#np").value.length < 12) { show("Password must be at least 12 characters.","err"); return; }
  const b=$("#confBtn"); b.disabled=true; show("Updating…");
  const r = await post("/auth/password/reset-confirm", { token, new_password: $("#np").value });
  if (r.ok) { $("#confirm").classList.add("hidden"); show("Password updated ✓ — redirecting to sign in…","ok"); setTimeout(()=>location.href="/",1400); return; }
  show(r.detail || "This reset link is invalid or has expired. Request a new one.","err"); b.disabled=false;
});

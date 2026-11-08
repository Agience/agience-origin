const S = document.body.dataset.state;
const msg = document.getElementById("msg");
const say = (t, cls) => { msg.className = "msg " + (cls || "muted"); msg.textContent = t || ""; };
async function post(url, body){
  const r = await fetch(url, {method:"POST", headers:{"content-type":"application/json"},
                             body: JSON.stringify(body)});
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.detail || ("request failed (" + r.status + ")"));
  return d;
}
const $ = (s) => document.querySelector(s);
/* Every method ends the same way: the server hands back the redirect it already computed from the
   pending request. The page never assembles a redirect itself and never sees a token. */
const finish = (d) => location.assign(d.redirect);

const pwForm = $("#pwForm");
if (pwForm) pwForm.onsubmit = async (e) => {
  e.preventDefault();
  const btn = $("#pwBtn"); btn.disabled = true; say("");
  try {
    finish(await post("/auth/authorize/password", {oauth_state: S,
      identifier: $("#identifier").value.trim(), password: $("#password").value}));
  } catch (err) { say(err.message, "err"); btn.disabled = false; }
};

const otpToggle = $("#otpToggle");
if (otpToggle) otpToggle.onclick = () => {
  $("#local").classList.add("hidden");
  $("#otp").classList.remove("hidden");
  $("#email").focus(); say("");
};
const otpBack = $("#otpBack");
if (otpBack) otpBack.onclick = () => {
  $("#otp").classList.add("hidden");
  $("#local").classList.remove("hidden"); say("");
};
const sendForm = $("#sendForm");
if (sendForm) sendForm.onsubmit = async (e) => {
  e.preventDefault();
  const btn = $("#send"); btn.disabled = true;
  try {
    await post("/auth/authorize/otp/request", {oauth_state: S, email: $("#email").value.trim()});
    $("#step1").classList.add("hidden");
    $("#step2").classList.remove("hidden");
    $("#code").focus();
    /* Said the same way whether or not the account exists — the server does not disclose it and
       neither may this text, keeping the page as free of account-enumeration as the API. */
    say("If that address has an account, a code is on its way.");
  } catch (err) { say(err.message, "err"); btn.disabled = false; }
};
/* Registration shares the chooser's one rule: the page posts, the server computes the redirect.
   A `verification_required` answer is not a failure — the account exists, the flow simply cannot
   continue until the mailbox is proved, and saying so is the whole message. */
const regToggle = $("#regToggle");
if (regToggle) regToggle.onclick = () => {
  $("#local").classList.add("hidden");
  const o = $("#otp"); if (o) o.classList.add("hidden");
  $("#reg").classList.remove("hidden");
  $("#remail").focus(); say("");
};
const regBack = $("#regBack");
if (regBack) regBack.onclick = () => {
  $("#reg").classList.add("hidden");
  $("#local").classList.remove("hidden"); say("");
};
const regForm = $("#regForm");
if (regForm) regForm.onsubmit = async (e) => {
  e.preventDefault();
  const btn = $("#regBtn"); btn.disabled = true; say("Creating your account…");
  try {
    const d = await post("/auth/authorize/register", {oauth_state: S,
      email: $("#remail").value.trim(), password: $("#rpassword").value});
    if (d.verification_required) {
      $("#reg").classList.add("hidden");
      say("Account created. Check " + d.email + " for a link to confirm it, then sign in.", "ok");
      return;
    }
    finish(d);
  } catch (err) { say(err.message, "err"); btn.disabled = false; }
};

const codeForm = $("#codeForm");
if (codeForm) codeForm.onsubmit = async (e) => {
  e.preventDefault();
  const btn = $("#verify"); btn.disabled = true; say("");
  try {
    finish(await post("/auth/authorize/otp/verify", {oauth_state: S,
      email: $("#email").value.trim(), code: $("#code").value.trim()}));
  } catch (err) { say(err.message, "err"); btn.disabled = false; }
};
/* The provider buttons: each names where it goes in `data-href`; no inline handler. */
document.querySelectorAll("button.provider[data-href]").forEach((b) => {
  b.addEventListener("click", () => location.assign(b.dataset.href));
});

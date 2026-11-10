/* A timer's job grant, approved or stopped at Origin's own page (John, 2026-11-10).
 *
 * The app opens this page with the grant to make (`job`, `reach`, `days`, `title`) or the grant to
 * stop (`revoke`), and `back`, its own origin, which Origin checked before serving the page. The
 * grant is made in the person's Origin session, behind a fresh step-up bound to the request's
 * exact body, and only its id goes back, to `back` alone. */
(function () {
  const $ = function (s) { return document.querySelector(s); }, msg = $("#msg");
  function show(t, cls) { msg.className = "msg " + (cls || "muted"); msg.textContent = t || ""; }
  const q = new URLSearchParams(location.search);
  const back = (q.get("back") || "").replace(/\/+$/, "");
  const job = q.get("job") || "", revoke = q.get("revoke") || "";
  const reach = (q.get("reach") || "").split(",").map(function (s) { return s.trim(); })
    .filter(Boolean);
  const title = q.get("title") || job;
  const days = Math.max(1, Math.min(30, parseInt(q.get("days") || "30", 10) || 30));
  /* A workflow's one run, now: ten minutes, and used once (John, 2026-11-10). */
  const isRun = job.indexOf("lumen.run.") === 0;
  const PATH = "/auth/me/job-grants";

  function answer(message) {
    if (window.opener && back) window.opener.postMessage(message, back);
  }
  function done(message) {
    answer(message);
    setTimeout(function () { window.close(); }, 600);
  }

  /* The body a step-up was taken over is kept until the request is sent: a re-authentication
   * leaves this page, and the request sent on return must be the same bytes. */
  /* Kept under the exact grant shown (job, reach and term), and only while a re-authentication for
   * it is pending: a page opened for another grant, or after one closed, starts from what it shows. */
  const KEY = "job_grant_body:" + JSON.stringify([job, reach, isRun ? "run" : days]);
  if (!sessionStorage.getItem("pending_step_up")) {
    Object.keys(sessionStorage).forEach(function (k) {
      if (k.indexOf("job_grant_body:") === 0) sessionStorage.removeItem(k);
    });
  }
  function bodyFor() {
    const key = KEY;
    const kept = sessionStorage.getItem(key);
    if (kept) return kept;
    /* An hour inside the term, so a clock running a little fast still asks for one Origin takes. */
    const until = new Date(isRun ? Date.now() + 10 * 60000
                                 : Date.now() + days * 86400000 - 3600000).toISOString();
    const body = JSON.stringify({ job: job, expires_at: until, reach: reach });
    sessionStorage.setItem(key, body);
    return body;
  }

  function render() {
    $("#grant").classList.remove("hidden");
    const list = $("#reach"); list.textContent = "";
    if (revoke) {
      $("#heading").textContent = "Disarm a timer";
      $("#what").textContent = "Stop the job grant " + revoke + (title ? " (" + title + ")" : "") +
        ". Its timer no longer runs.";
      $("#approveBtn").textContent = "Stop it";
      return;
    }
    if (isRun) {
      $("#heading").textContent = "Run a workflow";
      $("#what").textContent = "Run “" + title + "” once, now, as you: it reads, writes and runs " +
        "operations in these items and what they contain, and nowhere else:";
      $("#until").textContent = "This run only, and only until " + JSON.parse(bodyFor()).expires_at +
        ". Mantle still holds it to what you yourself may do.";
    } else {
      $("#what").textContent = "While you are away, the timer “" + title + "” reads, " +
        "writes and runs operations as you, in these items and what they contain, and nowhere else:";
      $("#until").textContent = "Until " + JSON.parse(bodyFor()).expires_at +
        ", or until you disarm it. Mantle still holds it to what you yourself may do.";
    }
    reach.forEach(function (id) {
      const row = document.createElement("div"); row.className = "kv";
      const name = document.createElement("span"); name.textContent = id;
      row.appendChild(name); list.appendChild(row);
    });
  }

  async function approve() {
    if (revoke) {
      const out = await revokeJobGrant(revoke);
      if (!out) return;
      if (out.ok) { show("Stopped.", "ok"); done({ type: "agience.job-grant-revoked", grant_id: revoke }); }
      else show(out.detail || "Refused.", "err");
      return;
    }
    const body = bodyFor();
    const step = provenTicket("POST", PATH) || await stepUpWithBody("POST", PATH, body);
    if (step === null) return;
    const out = await authed("POST", PATH, body, { "X-Step-Up": step });
    if (!out.ok) { show(out.detail || "Refused.", "err"); return; }
    sessionStorage.removeItem(KEY);
    show("Approved.", "ok");
    done({ type: "agience.job-grant", job: job, grant_id: out.data && out.data.grant_id });
  }

  if (!back || (!revoke && (!job || !reach.length))) {
    show("This page was opened without a grant to approve.", "err");
    return;
  }
  if (!isAuthed()) {
    $("#signin").classList.remove("hidden");
  } else {
    render();
    if (sessionStorage.getItem("pending_step_up")) show("Confirmed. Approve again to finish it.");
  }
  /* A passkey sign-in that stays on this page (`passkeySignIn` goes on to the account page). */
  $("#signinBtn").addEventListener("click", async function () {
    try {
      const o = await post("/auth/passkey/login-options", { email: $("#email").value });
      if (!o.ok) { show(o.detail || "Passkey sign-in failed.", "err"); return; }
      const cred = await navigator.credentials.get(requestOptions(o.data.options));
      const r = await post("/auth/passkey/login-complete",
                           { challenge: o.data.options.challenge, credential: assertionJSON(cred) });
      if (!r.ok) { show(r.detail || "Passkey sign-in failed.", "err"); return; }
      saveToken(r.data.access_token);
      $("#signin").classList.add("hidden"); show(""); render();
    } catch (e) { show("Passkey sign-in was cancelled.", "err"); }
  });
  $("#approveBtn").addEventListener("click", function () {
    approve().catch(function (e) { show("Cancelled: " + e.message, "err"); });
  });
  $("#cancelBtn").addEventListener("click", function () {
    sessionStorage.removeItem(KEY);
    done({ type: revoke ? "agience.job-grant-revoke-declined" : "agience.job-grant-declined" });
  });
})();

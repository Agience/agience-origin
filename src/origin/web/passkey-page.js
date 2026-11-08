/* The passkey page's wiring (kept out of the HTML so the page's CSP needs no inline script). */
(function () {
  const $ = function (s) { return document.querySelector(s); }, msg = $("#msg");
  function show(t, cls) { msg.className = "msg " + (cls || "muted"); msg.textContent = t || ""; }

  async function refresh() {
    const r = await authed("GET", "/auth/passkey/credentials");
    const list = $("#list"); list.textContent = "";
    ((r.data && r.data.credentials) || []).forEach(function (c) {
      const row = document.createElement("div"); row.className = "kv";
      const name = document.createElement("span"); name.textContent = c.device_name || c.id;
      const del = document.createElement("button"); del.className = "link"; del.textContent = "Remove";
      del.addEventListener("click", async function () {
        const out = await removePasskey(c.credential_id || c.id);
        if (out) { show(out.ok ? "Removed." : (out.detail || "Refused."), out.ok ? "ok" : "err"); refresh(); }
      });
      row.appendChild(name); row.appendChild(del); list.appendChild(row);
    });
  }

  async function refreshJobs() {
    const r = await jobGrants();
    const list = $("#jobs"); list.textContent = "";
    ((r.data && r.data.job_grants) || []).forEach(function (g) {
      const row = document.createElement("div"); row.className = "kv";
      const name = document.createElement("span");
      name.textContent = g.job + " · " + (g.collections.join(", ") || "your key") + " · until " +
                         g.expires_at + " · " + g.state;
      row.appendChild(name);
      if (g.state === "active") {
        const del = document.createElement("button"); del.className = "link"; del.textContent = "Revoke";
        del.addEventListener("click", async function () {
          const out = await revokeJobGrant(g.grant_id);
          if (out) { show(out.ok ? "Revoked." : (out.detail || "Refused."), out.ok ? "ok" : "err"); refreshJobs(); }
        });
        row.appendChild(del);
      }
      list.appendChild(row);
    });
  }

  if (isAuthed()) {
    $("#signin").classList.add("hidden"); $("#manage").classList.remove("hidden"); refresh();
    refreshJobs();
    const q = new URLSearchParams(location.search);
    if (q.get("state") && q.get("code") && q.get("state") === sessionStorage.getItem("link_state")) {
      history.replaceState(null, "", location.pathname);
      confirmLink(q.get("code"), q.get("state"));
    } else if (pendingLink()) {
      /* Back from re-authenticating for a link (a person with no passkey): the code and state
         the sign-in brought were kept here; nothing is linked until the person confirms again. */
      const p = pendingLink();
      confirmLink(p.code, p.state);
    } else if (sessionStorage.getItem("pending_step_up")) {
      show("Confirmed. Choose the action again to finish it.");
    }
  }
  $("#signinBtn").addEventListener("click", async function () {
    try { const r = await passkeySignIn($("#email").value);
          if (!r.ok) show(r.detail || "Passkey sign-in failed.", "err"); }
    catch (e) { show("Passkey sign-in was cancelled.", "err"); }
  });
  $("#addBtn").addEventListener("click", async function () {
    try { const r = await registerPasskey($("#device").value);
          if (r) { show(r.ok ? "Passkey added." : (r.detail || "Refused."), r.ok ? "ok" : "err"); refresh(); } }
    catch (e) { show("Cancelled: " + e.message, "err"); }
  });
  $("#linkBtn").addEventListener("click", function () {
    linkStart().catch(function (e) { show("Refused: " + e.message, "err"); });
  });
  /* The sign-in came back: nothing is linked until the person says so here. */
  function pendingLink() {
    try { return JSON.parse(sessionStorage.getItem("pendingLink") || "null"); }
    catch (e) { return null; }
  }
  function confirmLink(code, state) {
    /* Kept through a re-authentication: the page that comes back offers the same link again. */
    sessionStorage.setItem("pendingLink", JSON.stringify({ code: code, state: state }));
    $("#linkConfirm").classList.remove("hidden");
    $("#linkYes").onclick = function () {
      $("#linkConfirm").classList.add("hidden");
      linkFinish(code, state).then(function (r) {
        if (r) {
          sessionStorage.removeItem("pendingLink");
          show(r.ok ? "Sign-in method linked." : (r.detail || "Refused."), r.ok ? "ok" : "err");
        }
      }).catch(function (e) { show("Cancelled: " + e.message, "err"); });
    };
    $("#linkNo").onclick = function () {
      $("#linkConfirm").classList.add("hidden");
      sessionStorage.removeItem("link_state"); sessionStorage.removeItem("link_verifier");
      sessionStorage.removeItem("pendingLink"); sessionStorage.removeItem("pending_step_up");
      show("Nothing was linked.");
    };
  }
  $("#consoleBtn").addEventListener("click", async function () {
    try { const r = await consoleSignIn();
          show(r.ok ? "Signed in to the operator console in this tab." : (r.detail || "Refused."),
               r.ok ? "ok" : "err"); }
    catch (e) { show("Cancelled.", "err"); }
  });
})();

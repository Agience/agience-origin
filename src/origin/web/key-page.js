/* A grant key, minted or revoked at Origin's own page (John, 2026-11-14).
 *
 * The app opens this page with the key to make (`name`, `members` as `id:read+update,id2:read`,
 * `days` up to 90, `agent`) or the key to revoke (`revoke`), and `back`, its own origin, which
 * Origin checked before serving the page. The key is minted in the person's Origin session. Its
 * token is shown here once and goes nowhere else; only the key's id goes back, to `back` alone. */
(function () {
  const $ = function (s) { return document.querySelector(s); }, msg = $("#msg");
  function show(t, cls) { msg.className = "msg " + (cls || "muted"); msg.textContent = t || ""; }
  const q = new URLSearchParams(location.search);
  const back = (q.get("back") || "").replace(/\/+$/, "");
  const name = (q.get("name") || "").trim(), agent = (q.get("agent") || "").trim();
  const revoke = q.get("revoke") || "";
  const days = Math.max(1, Math.min(90, parseInt(q.get("days") || "30", 10) || 30));
  const members = (q.get("members") || "").split(",").map(function (s) {
    const at = s.lastIndexOf(":");
    if (at <= 0) return null;
    const actions = s.slice(at + 1).split("+").map(function (a) { return a.trim(); })
      .filter(Boolean);
    return actions.length ? { resource_id: s.slice(0, at).trim(), actions: actions } : null;
  }).filter(Boolean);
  const PATH = "/auth/me/keys";

  function answer(message) {
    if (window.opener && back) window.opener.postMessage(message, back);
  }
  function refused(detail) {
    show(detail || "Refused.", "err");
    $("#approveBtn").classList.add("hidden");
    $("#cancelBtn").textContent = "Close";
  }

  /* An hour inside the term, so a clock running a little fast still asks for one Origin takes. */
  const until = new Date(Date.now() + days * 86400000 - 3600000).toISOString();

  function render() {
    $("#grant").classList.remove("hidden");
    const list = $("#members"); list.textContent = "";
    if (revoke) {
      $("#heading").textContent = "Revoke a key";
      $("#what").textContent = "Revoke the key " + revoke + (name ? " (" + name + ")" : "") +
        ". Anything holding it loses access at once.";
      $("#approveBtn").textContent = "Revoke it";
      return;
    }
    $("#what").textContent = "Mint the key “" + name + "”" + (agent ? " for " + agent : "") +
      ". Whoever holds it can do this, and nothing else:";
    $("#until").textContent = "Until " + until + ", or until you revoke it. Mantle still holds " +
      "it to what you yourself may do.";
    members.forEach(function (m) {
      const row = document.createElement("div"); row.className = "kv";
      const id = document.createElement("span"); id.textContent = m.resource_id;
      const what = document.createElement("span"); what.textContent = m.actions.join(", ");
      row.appendChild(id); row.appendChild(what); list.appendChild(row);
    });
  }

  async function approve() {
    if (revoke) {
      const out = await authed("POST", PATH + "/" + encodeURIComponent(revoke) + "/revoke",
                               undefined, {});
      if (!out.ok) { refused(out.detail); return; }
      show("Revoked.", "ok");
      answer({ type: "agience.key-revoked", grant_id: revoke });
      setTimeout(function () { window.close(); }, 600);
      return;
    }
    const body = { name: name, expires_at: until, members: members };
    if (agent) body.agent = agent;
    const out = await authed("POST", PATH, JSON.stringify(body), {});
    if (!out.ok) { refused(out.detail); return; }
    $("#grant").classList.add("hidden");
    $("#minted").classList.remove("hidden");
    $("#token").value = out.data.token;
    show("");
    answer({ type: "agience.key", grant_id: out.data.grant_id, name: name });
  }

  if (!back || (!revoke && (!name || !members.length))) {
    show("This page was opened without a key to mint.", "err");
    return;
  }
  if (!isAuthed()) $("#signin").classList.remove("hidden");
  else render();

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
    answer({ type: revoke ? "agience.key-revoke-declined" : "agience.key-declined" });
    window.close();
  });
  $("#copyBtn").addEventListener("click", function () {
    const t = $("#token");
    t.select();
    (navigator.clipboard ? navigator.clipboard.writeText(t.value) : Promise.reject())
      .then(function () { show("Copied.", "ok"); },
            function () { document.execCommand("copy"); show("Copied.", "ok"); });
  });
  $("#closeBtn").addEventListener("click", function () {
    $("#token").value = "";
    window.close();
  });
})();

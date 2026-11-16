/* The approvals page (/approvals). Every call runs in the viewer's Origin session: a
 * same-origin fetch that sends the cookie and the page's own address as Referer, which is how
 * Origin knows the call comes from this page. Nothing here holds a bearer token. */
(function () {
  "use strict";
  const $ = function (s) { return document.querySelector(s); };
  const TZ = "America/Toronto";
  const CANNOT = "You can't approve this request. Approving needs update access to it.";
  let state = null;      // the last /notes/page/state
  let current = null;    // the request on screen

  async function call(method, path, body) {
    let r;
    try {
      r = await fetch(path, {
        method: method, credentials: "same-origin", referrerPolicy: "same-origin",
        headers: body ? { "Content-Type": "application/json" } : {},
        body: body ? JSON.stringify(body) : undefined, cache: "no-store",
      });
    } catch (e) {
      return { ok: false, status: 0, data: {}, detail: "Network error" };
    }
    let data = {};
    try { data = await r.json(); } catch (e) { /* empty body */ }
    return { ok: r.ok, status: r.status, data: data, detail: (data && data.detail) || null };
  }

  function show(text, kind) {
    const m = $("#msg");
    m.textContent = text || "";
    m.className = "msg" + (kind ? " " + kind : "");
  }
  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }
  function hide(id, yes) { $(id).classList.toggle("hidden", !!yes); }

  /* "today 21:00", "tomorrow 09:30", or "Mon 17 Nov 21:00", always Toronto time. */
  function when(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (isNaN(d)) return String(iso);
    const day = function (x) {
      return new Intl.DateTimeFormat("en-CA", { timeZone: TZ, year: "numeric", month: "2-digit",
                                                day: "2-digit" }).format(x);
    };
    const hm = new Intl.DateTimeFormat("en-CA", { timeZone: TZ, hour: "2-digit", minute: "2-digit",
                                                  hour12: false }).format(d);
    const now = new Date();
    if (day(d) === day(now)) return "today " + hm;
    if (day(d) === day(new Date(now.getTime() + 864e5))) return "tomorrow " + hm;
    if (day(d) === day(new Date(now.getTime() - 864e5))) return "yesterday " + hm;
    return new Intl.DateTimeFormat("en-CA", { timeZone: TZ, weekday: "short", day: "numeric",
                                              month: "short" }).format(d) + " " + hm;
  }
  function firstLine(s) { return String(s || "").split("\n")[0].trim(); }
  function title(req) {
    return firstLine(req.summary) || (req.kind === "question" ? "A question" : req.kind);
  }
  function noun(req) { return req.kind === "question" ? "question" : "request"; }
  /* The level is the filer's own label; it shows only when the filer set one. */
  function levelTag(req) {
    return req.level ? el("span", "level", req.level) : null;
  }
  function metaLine(box, req, rest) {
    const tag = levelTag(req);
    if (tag) { box.appendChild(tag); box.appendChild(document.createTextNode(" · ")); }
    box.appendChild(document.createTextNode(rest));
  }

  /* --- signing in --------------------------------------------------------------------------- */

  function signIn(why) {
    hide("#signin", false); hide("#list", true); hide("#detail", true); hide("#bottom", true);
    hide("#banner", true);
    if (why) $("#signinWhy").textContent = why;
  }
  $("#signinBtn").addEventListener("click", async function () {
    try {
      const o = await post("/auth/passkey/login-options", { email: $("#email").value });
      if (!o.ok) { show(o.detail || "Passkey sign-in failed.", "err"); return; }
      const cred = await navigator.credentials.get(requestOptions(o.data.options));
      const r = await post("/auth/passkey/login-complete",
                           { challenge: o.data.options.challenge, credential: assertionJSON(cred) });
      if (!r.ok) { show(r.detail || "Passkey sign-in failed.", "err"); return; }
      hide("#signin", true); show("");
      await load(current ? current.id : new URLSearchParams(location.search).get("req"));
    } catch (e) { show("Passkey sign-in was cancelled.", "err"); }
  });

  /* --- the list ----------------------------------------------------------------------------- */

  function sorted(pending) {
    return pending.slice().sort(function (a, b) { return new Date(a.expires) - new Date(b.expires); });
  }

  function renderList() {
    const box = $("#list");
    box.textContent = "";
    $("#heading").textContent = "Approvals";
    const pending = sorted(state.pending.filter(function (r) { return r.state === "pending"; }));
    if (!pending.length) {
      box.appendChild(el("p", null, "Nothing waiting for you."));
    } else {
      pending.forEach(function (r) {
        const b = el("button", "row");
        b.type = "button";
        b.appendChild(el("b", null, title(r)));
        const meta = el("span", "muted");
        metaLine(meta, r, "expires " + when(r.expires) + " · " + r.filed_by);
        b.appendChild(meta);
        b.addEventListener("click", function () { openRequest(r.id); });
        box.appendChild(b);
      });
    }
    hide("#list", false); hide("#detail", true);
    renderBottom();
  }

  function renderBottom() {
    const box = $("#bottom");
    box.textContent = "";
    const live = (state.notes || []).length;
    const revokeAll = el("button", "secondary danger",
                         "Revoke all unspent" + (live ? " (" + live + ")" : ""));
    revokeAll.type = "button";
    revokeAll.disabled = !live;
    revokeAll.addEventListener("click", async function () {
      if (!confirm("Revoke every unspent note? Agents holding one can no longer act on it.")) return;
      const r = await call("POST", "/notes/page/revoke-all", { form: state.revoke_all_form });
      if (!r.ok) { show(r.detail || "Revoking failed.", "err"); return; }
      show("Revoked " + r.data.revoked + " note" + (r.data.revoked === 1 ? "" : "s") + ".", "ok");
      await load();
    });
    const signOut = el("button", "secondary danger", "Sign out everywhere");
    signOut.type = "button";
    signOut.addEventListener("click", async function () {
      if (!confirm("Sign out of every device and end every job grant? Notes already approved stay " +
                   "until you revoke them.")) return;
      const r = await call("POST", "/notes/page/sign-out-everywhere", { form: state.sign_out_form });
      if (!r.ok) { show(r.detail || "Signing out failed.", "err"); return; }
      signIn("Signed out everywhere. Sign in again to see what is waiting for you.");
      show("Signed out everywhere.", "ok");
    });
    box.appendChild(revokeAll);
    box.appendChild(signOut);
    hide("#bottom", false);
  }

  /* --- one request -------------------------------------------------------------------------- */

  /* Which evidence agrees with a head: "matches Tester GREEN / CI run", or "differs". */
  function headMark(repo, sha, evidence) {
    const same = [], diff = [];
    (evidence || []).forEach(function (e) {
      if (!e.heads || !(repo in e.heads)) return;
      const other = String(e.heads[repo]);
      const a = String(sha).toLowerCase(), b = other.toLowerCase();
      (a.indexOf(b) === 0 || b.indexOf(a) === 0 ? same : diff).push(e.label || "evidence");
    });
    if (diff.length) return el("span", "mark diff", "differs from " + diff.join(" / "));
    if (same.length) return el("span", "mark same", "matches " + same.join(" / "));
    return el("span", "mark none", "no evidence names this head");
  }

  function shaButton(sha) {
    const full = String(sha);
    const b = el("button", "sha", full.slice(0, 12));
    b.type = "button";
    b.title = "Show the full sha";
    b.addEventListener("click", function () {
      b.textContent = b.textContent.length > 12 ? full.slice(0, 12) : full;
    });
    return b;
  }

  function renderFields(box, fields, evidence) {
    Object.keys(fields || {}).forEach(function (k) {
      const v = fields[k];
      const f = el("div", "field");
      f.appendChild(el("span", "k", k));
      if (k === "heads" && v && typeof v === "object") {
        Object.keys(v).forEach(function (repo) {
          const h = el("div", "head");
          h.appendChild(el("span", null, repo));
          h.appendChild(shaButton(v[repo]));
          h.appendChild(headMark(repo, v[repo], evidence));
          f.appendChild(h);
        });
      } else if (typeof v === "string" && /^[0-9a-f]{40,64}$/i.test(v)) {
        f.appendChild(shaButton(v));
      } else {
        f.appendChild(el("span", null, typeof v === "string" ? v : JSON.stringify(v)));
      }
      box.appendChild(f);
    });
  }

  function renderEvidence(box, evidence) {
    if (!evidence || !evidence.length) return;
    const ev = el("div", "evidence");
    const line = evidence.map(function (e) {
      return (e.label || "evidence") + (e.at ? " " + when(e.at).replace(/^today /, "") : "");
    }).join(" · ");
    ev.appendChild(el("div", null, line));
    evidence.forEach(function (e) {
      if (!e.url || !/^https:\/\//.test(e.url)) return;
      const a = el("a", null, e.label || e.url);
      a.href = e.url; a.target = "_blank"; a.rel = "noopener noreferrer";
      ev.appendChild(document.createTextNode(" "));
      ev.appendChild(a);
    });
    box.appendChild(ev);
  }

  function renderDigest(box, req) {
    if (!/^sha256:/.test(req.digest || "")) return;
    const hex = req.digest.slice(7);
    const d = el("div", "digest");
    const filer = (req.filer_digest || "").replace(/^sha256:/, "");
    if (filer && filer.slice(0, 12) === hex.slice(0, 12) && ("sha256:" + filer) === req.digest) {
      d.appendChild(el("div", "big", hex.slice(0, 12)));
      d.appendChild(el("div", "muted", "The filer and Origin computed the same digest."));
    } else {
      d.appendChild(el("div", "small", req.digest));
      d.appendChild(el("div", "muted", filer
        ? "The filer's digest differs from Origin's. Approve only if you expected that."
        : "The filer sent no digest to compare."));
    }
    box.appendChild(d);
  }

  function nextPending(afterId) {
    const rest = sorted((state ? state.pending : []).filter(function (r) {
      return r.state === "pending" && r.id !== afterId;
    }));
    return rest[0] || null;
  }

  function nextButton(afterId) {
    const n = nextPending(afterId);
    const b = el("button", "secondary", n ? "Next: 1 " + noun(n) : "Back to the list");
    b.type = "button";
    b.addEventListener("click", function () { n ? openRequest(n.id) : renderList(); });
    return b;
  }

  function noteExpiry(token) {
    try { return new Date(decodeJwt(token).exp * 1000).toISOString(); } catch (e) { return null; }
  }

  /* After Approve: the note's expiry, its revoke button until it is spent, and what comes next. */
  function renderDone(box, req) {
    if (req.note && !req.revoked) {
      box.appendChild(el("p", "ok", "Approved, expires " + when(noteExpiry(req.note)) + "."));
      if (req.revoke_form) {
        const rv = el("button", "secondary danger", "Revoke this note");
        rv.type = "button";
        rv.addEventListener("click", async function () {
          if (!confirm("Revoke this note? The agent can no longer act on it.")) return;
          const r = await call("POST", "/notes/page/revoke", { form: req.revoke_form, jti: req.note_jti });
          if (!r.ok) { show(r.detail || "Revoking failed.", "err"); return; }
          show("Revoked.", "ok");
          await openRequest(req.id, true);
        });
        box.appendChild(rv);
      } else if (req.spent) {
        box.appendChild(el("p", "muted", "The note has been spent."));
      }
    } else if (req.revoked) {
      box.appendChild(el("p", "muted", "Approved; the note is revoked."));
    } else if (req.state === "answered") {
      box.appendChild(el("p", "ok", "Answered: " + req.answer + "."));
    } else if (req.state === "declined") {
      box.appendChild(el("p", "muted", "Declined" + (req.reason ? ": " + req.reason : "") + "."));
    } else if (req.state === "expired") {
      box.appendChild(el("p", "muted", "This " + noun(req) + " expired " + when(req.expires) + "."));
    }
    box.appendChild(nextButton(req.id));
  }

  function renderDecision(box, req) {
    box.appendChild(el("div", "spacer"));
    if (!req.can_decide) {
      box.appendChild(el("p", "banner", CANNOT));
      return;
    }
    if (req.kind === "question") {
      (req.options || []).forEach(function (o) {
        const b = el("button", "primary option", o.label);
        b.type = "button";
        b.addEventListener("click", function () { decide(req, "approve", { option: o.label }); });
        box.appendChild(b);
        box.appendChild(el("div", "spacer"));
      });
    } else {
      const a = el("button", "primary", "Approve");
      a.type = "button";
      a.addEventListener("click", function () { decide(req, "approve", {}); });
      box.appendChild(a);
    }
    if (req.kind === "question" && req.default) {
      box.appendChild(el("p", "muted", "If you do nothing by " + when(req.expires) + ": " + req.default));
    }
    const reason = el("textarea");
    reason.rows = 1; reason.maxLength = 300;
    reason.placeholder = "Reason (optional, one line)";
    reason.addEventListener("keydown", function (e) { if (e.key === "Enter") e.preventDefault(); });
    const d = el("button", "secondary", "Decline");
    d.type = "button";
    d.addEventListener("click", function () {
      decide(req, "decline", { reason: reason.value.replace(/\s+/g, " ").trim() });
    });
    box.appendChild(el("div", "spacer"));
    box.appendChild(reason);
    box.appendChild(d);
  }

  function renderRequest(req, banner) {
    current = req;
    const box = $("#detail");
    box.textContent = "";
    $("#heading").textContent = title(req);
    if (banner) { $("#banner").textContent = banner; hide("#banner", false); } else hide("#banner", true);

    const head = el("p", "muted");
    metaLine(head, req, "Written by " + req.filed_by + " · expires " + when(req.expires));
    box.appendChild(head);
    if (req.summary && req.summary.indexOf("\n") >= 0) box.appendChild(el("div", "summary", req.summary));
    renderEvidence(box, req.evidence);
    if (req.kind !== "question") renderFields(box, req.fields, req.evidence);
    (req.steps || []).forEach(function (s, i) {
      const st = el("div", "step");
      st.appendChild(el("b", null, "Step " + (i + 1) + ": " + s.kind));
      renderFields(st, s.fields, req.evidence);
      box.appendChild(st);
    });
    if (req.kind === "question") {
      (req.options || []).forEach(function (o) {
        if (!o.action) return;
        const st = el("div", "step");
        st.appendChild(el("b", null, o.label + " does: " + o.action.kind));
        renderFields(st, o.action.fields, req.evidence);
        box.appendChild(st);
      });
    }
    renderDigest(box, req);
    if (req.state === "pending") renderDecision(box, req); else renderDone(box, req);

    const back = el("button", "link", "All requests");
    back.type = "button";
    back.addEventListener("click", function () { hide("#banner", true); load(); });
    box.appendChild(back);
    hide("#list", true); hide("#detail", false);
    renderBottom();
    window.scrollTo(0, 0);
  }

  /* A request the viewer cannot see: the refusal names nothing of it, and offers a way back and a
   * way to ask for access. Asking copies the request's link to hand to an admin of its workspace. */
  function renderRefused(id, data) {
    current = null;
    const box = $("#detail");
    box.textContent = "";
    $("#heading").textContent = "Approvals";
    hide("#banner", true); show("");
    box.appendChild(el("p", "refusal", CANNOT));
    const back = el("a", "primary", "Back to Agience");
    back.href = (data && data.app_uri) || (state && state.app_uri) || "/";
    box.appendChild(back);
    box.appendChild(el("div", "spacer"));
    const ask = el("button", "secondary", "Ask for access");
    ask.type = "button";
    ask.addEventListener("click", async function () {
      const link = location.origin + "/approvals?req=" + encodeURIComponent(id);
      try { await navigator.clipboard.writeText(link); } catch (e) { /* shown below either way */ }
      show("Send this link to an admin of the request's workspace and ask them for approve " +
           "access: " + link, "ok");
    });
    box.appendChild(ask);
    hide("#list", true); hide("#detail", false); hide("#bottom", true);
  }

  async function openRequest(id, keepMsg, banner) {
    const r = await call("GET", "/notes/page/requests/" + encodeURIComponent(id));
    if (r.status === 401) { signIn(); return; }
    if (r.status === 403 && r.data && r.data.app_uri !== undefined) { renderRefused(id, r.data); return; }
    if (!r.ok) { show(r.detail || "Could not open the request.", "err"); return; }
    if (!keepMsg) show("");
    history.replaceState(null, "", "/approvals?req=" + encodeURIComponent(id));
    renderRequest(r.data, banner);
  }

  async function decide(req, decision, extra) {
    const body = Object.assign({ req: req.id, decision: decision, digest: req.digest, form: req.form },
                               extra);
    show(decision === "approve" ? "Approving…" : "Declining…");
    const r = await call("POST", "/notes/page/decide", body);
    if (r.status === 412) {
      /* Nothing was minted: the new version opens, and Approve has to be pressed again. */
      show("");
      await openRequest(req.id, false, "This request changed after you opened it. Here is the new version.");
      return;
    }
    if (r.status === 401) { signIn("Sign in to decide."); show(r.detail || "", "err"); return; }
    if (!r.ok) { show(r.detail || "That did not go through.", "err"); return; }
    const s = await call("GET", "/notes/page/state");
    if (s.ok) state = s.data;
    if (decision === "decline" || (r.data.state === "answered" && !r.data.note)) {
      const n = nextPending(req.id);
      show(decision === "decline" ? "Declined." : "Answered.", "ok");
      if (n) { await openRequest(n.id, true); return; }
      renderList();
      return;
    }
    show("");
    renderRequest(r.data);
  }

  async function load(reqId) {
    const r = await call("GET", "/notes/page/state");
    if (r.status === 401) { signIn(); return; }
    if (!r.ok) { hide("#signin", true); show(r.detail || "Approvals are not available.", "err"); return; }
    state = r.data;
    hide("#signin", true);
    if (reqId) { await openRequest(reqId, true); return; }
    history.replaceState(null, "", "/approvals");
    renderList();
  }

  load(new URLSearchParams(location.search).get("req"));
})();

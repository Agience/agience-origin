// `web/job-grant-page.js` under stubbed browser globals: a refused grant leaves only Close
// (BUG-060, 2026-11-11: Approve stayed, and each click took another sign-in and the same 403).
"use strict";
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const SRC = fs.readFileSync(path.join(__dirname, "..", "..", "web", "job-grant-page.js"), "utf8");

function el() {
  const classes = new Set();
  return {
    textContent: "", className: "", handlers: {},
    classList: { add: (c) => classes.add(c), remove: (c) => classes.delete(c), has: (c) => classes.has(c) },
    appendChild() {}, addEventListener(ev, fn) { this.handlers[ev] = fn; },
  };
}

function page(postResult) {
  const els = {};
  const store = new Map();
  const sent = [];
  const ctx = {
    document: { querySelector: (s) => (els[s] = els[s] || el()), createElement: () => el() },
    location: { search: "?back=https%3A%2F%2Fmy.agience.test&job=lumen.run.w1.n1&reach=w1&title=Check" },
    sessionStorage: {
      getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k),
    },
    window: { opener: null, close() {} },
    setTimeout: () => 0, JSON, Date, Math, URLSearchParams, Object, parseInt,
    isAuthed: () => true,
    provenTicket: () => "reauth:t",
    stepUpWithBody: async () => "reauth:t",
    authed: async (m, p, b) => { sent.push([m, p]); return postResult; },
  };
  vm.runInNewContext(SRC, ctx);
  return { els, sent };
}

test("a refused grant shows why and offers only Close", async () => {
  const { els, sent } = page({ ok: false, detail: "custody is held only on isolated production" });
  await els["#approveBtn"].handlers.click();
  await new Promise((r) => setImmediate(r));
  assert.deepStrictEqual(sent, [["POST", "/auth/me/job-grants"]]);
  assert.match(els["#msg"].textContent, /custody is held only on isolated production/);
  assert.ok(els["#approveBtn"].classList.has("hidden"), "Approve is not offered again");
  assert.strictEqual(els["#cancelBtn"].textContent, "Close");
});

test("an approved grant keeps Approve as it was until the window closes", async () => {
  const { els } = page({ ok: true, data: { grant_id: "g1" } });
  await els["#approveBtn"].handlers.click();
  await new Promise((r) => setImmediate(r));
  assert.strictEqual(els["#msg"].textContent, "Approved.");
  assert.ok(!els["#approveBtn"].classList.has("hidden"));
});

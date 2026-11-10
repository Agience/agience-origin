/* A step-up proven at Origin's own sign-in goes back to the Origin page that asked for it, in this
 * tab, where the request is sent with the proven ticket (BUG-037, 2026-11-10: the person was left
 * on "return to Origin's page" with that page gone, and the approval never finished). Only a page
 * of Origin itself is gone back to; anything else stays here with the link below. */
(function () {
  "use strict";
  var back = null;
  try {
    var p = JSON.parse(sessionStorage.getItem("pending_step_up") || "null");
    if (p && typeof p.back === "string") back = new URL(p.back, location.origin);
  } catch (e) { back = null; }
  if (!back || back.origin !== location.origin) return;
  var a = document.getElementById("back");
  if (a) { a.href = back.href; a.hidden = false; }
  location.replace(back.href);
})();

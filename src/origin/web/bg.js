/* Agience Origin — the animated auth background: a rotating
   conic gradient (random start angle, 20-40s) + two blur(5vmin) blobs drifting between randomized
   waypoints (0/100% at waypoint[0], 50% at waypoint[2]) over 20-40s. Regenerated per page load,
   like the original.

   Kept separate from `app.js` deliberately: this is presentation and nothing else — it touches no
   token, reads no storage, calls no endpoint. `app.js` carries the auth helpers, including
   `saveToken`/`finishLogin`, which put an access token in `localStorage` and hand it back through a
   URL fragment. The `/auth/authorize` chooser is an authorization-code + PKCE surface and keeps
   that code out of reach: a page that cannot save a token cannot leak one. Splitting the file lets
   both pages share one background without the new one importing the old flow.

   Attaches to `.bg` and does nothing if that element is absent, so it is safe on any page. */
(function buildBackground() {
  var host = document.querySelector(".bg");
  if (!host) return;
  var B = 50, r = Math.random;
  var wp = [];
  for (var i = 0; i < 5; i++) {
    wp.push({
      x1: -B / 2 + r() * (100 + B / 2), y1: -B / 2 + r() * (100 + B / 2),
      x2: -B / 2 + r() * (100 + B / 2), y2: -B / 2 + r() * (100 + B / 2),
    });
  }
  var d0 = 20 + r() * 20, d1 = 20 + r() * 20, g = 20 + r() * 20, a = r() * 360;
  var kf =
    "@keyframes gradient-rotate{0%{transform:translate(-50%,-50%) rotate(" + a + "deg);}100%{transform:translate(-50%,-50%) rotate(" + (a + 360) + "deg);}}" +
    "@keyframes blob1{0%,100%{left:" + wp[0].x1 + "%;top:" + wp[0].y1 + "%;}50%{left:" + wp[2].x1 + "%;top:" + wp[2].y1 + "%;}}" +
    "@keyframes blob2{0%,100%{left:" + wp[0].x2 + "%;top:" + wp[0].y2 + "%;}50%{left:" + wp[2].x2 + "%;top:" + wp[2].y2 + "%;}}";
  var st = document.createElement("style"); st.textContent = kf; document.head.appendChild(st);
  host.innerHTML =
    '<div style="position:absolute;width:200vmax;height:200vmax;left:50%;top:50%;border-radius:50%;' +
    'background:conic-gradient(from 0deg,#581c87,#1e3a8a,#581c87);animation:gradient-rotate ' + g + 's linear infinite"></div>' +
    '<div style="position:absolute;inset:0;overflow:hidden">' +
    '<div style="position:absolute;border-radius:50%;background:#581c87;width:' + B + 'vmin;height:' + B + 'vmin;filter:blur(5vmin);animation:blob1 ' + d0 + 's infinite ease-in-out"></div>' +
    '<div style="position:absolute;border-radius:50%;background:#1e3a8a;width:' + B + 'vmin;height:' + B + 'vmin;filter:blur(5vmin);animation:blob2 ' + d1 + 's infinite ease-in-out"></div>' +
    "</div>";
})();

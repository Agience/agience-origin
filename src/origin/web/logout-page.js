// The server session was cleared by `/logout` itself; the token this browser holds for Origin goes
// here. Then back to `return` only when Origin lists it (the app, or an exact SSO return URI), so this
// page cannot be used to send someone anywhere else.
(async () => {
  clearToken();
  try { sessionStorage.clear(); } catch (e) {}
  const back = qs("return");
  let to = "/";
  if (back) {
    const r = await get("/auth/providers");
    const d = (r.ok && r.data) || {};
    const listed = (Array.isArray(d.sso_return_uris) ? d.sso_return_uris : []).concat(d.app_uri ? [d.app_uri] : []);
    if (isListedReturn(back, listed)) to = back;
  }
  location.replace(to);
})();

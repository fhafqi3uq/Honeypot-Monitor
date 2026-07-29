// Escapes attacker-controlled strings (username/password/command/ip/etc.
// from the honeypot) before they're interpolated into an innerHTML
// template. Without this, a honeypot session where the attacker used a
// username/password/command containing a script tag would execute that
// script in the logged-in admin's browser the next time the dashboard
// renders it - the JWT cookies are httpOnly, but the CSRF token cookie is
// deliberately not (the double-submit design needs JS to read it), so
// injected script could still forge a valid CSRF-protected request.
function escapeHtml(value) {
  if (value === null || value === undefined) return ''
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

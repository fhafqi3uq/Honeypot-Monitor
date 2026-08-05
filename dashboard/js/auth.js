// Session/CSRF helpers shared by every protected dashboard page.
// Relies on API_URL from data.js, which must be loaded first.

function getCsrfToken() {
  const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]*)/)
  return match ? decodeURIComponent(match[1]) : null
}

// Shared by requireAuth() and authFetch() below: several pages call their
// load function unconditionally at parse time instead of waiting on
// requireAuth() to resolve, and load functions themselves fire multiple
// authFetch() calls concurrently (Promise.all) - an unauthenticated/dead
// session can therefore trigger several independent 401s at once. Without
// this guard each would re-assign window.location.href, and the browser can
// abort an in-flight navigation when a second assignment to the same URL
// lands mid-flight.
let _redirectingToLogin = false

function goToLogin() {
  if (_redirectingToLogin) return
  _redirectingToLogin = true
  window.location.href = 'login.html'
}

// Call at the top of every protected page. The page's <body> starts with
// `style="visibility:hidden"` so nothing renders until this either shows
// it (authenticated) or redirects to the login page.
async function requireAuth() {
  try {
    const res = await fetch(`${API_URL}/auth/me`, { credentials: 'include' })
    if (!res.ok) throw new Error('unauthenticated')
    document.body.style.visibility = 'visible'
  } catch {
    goToLogin()
  }
}

// Drop-in replacement for `fetch(url, { ...options, credentials: 'include' })`
// used by every page's data-loading calls - `options` (method/headers/body)
// is optional and passed straight through, only `credentials` is always
// forced to 'include'. fetch() does NOT reject on an HTTP error status (only
// on network failure), so a 401 from an access token that expired/was
// invalidated mid-session would otherwise be parsed as if it were real data
// (data.js's callers would see `{"detail": "..."}` where they expected
// `{"total": ..., ...}`) and silently render wrong/blank numbers instead of
// sending the admin back to the login page. Callers keep their existing
// try/catch (the thrown error is caught there and falls back to their
// normal empty-state default) - the redirect below is what actually
// matters.
async function authFetch(url, options = {}) {
  const res = await fetch(url, { ...options, credentials: 'include' })
  if (res.status === 401) {
    goToLogin()
    throw new Error('unauthenticated')
  }
  return res
}

async function logout() {
  try {
    await fetch(`${API_URL}/auth/logout`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRF-Token': getCsrfToken() || '' },
    })
  } finally {
    window.location.href = 'login.html'
  }
}

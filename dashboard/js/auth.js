// Session/CSRF helpers shared by every protected dashboard page.
// Relies on API_URL from data.js, which must be loaded first.

function getCsrfToken() {
  const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]*)/)
  return match ? decodeURIComponent(match[1]) : null
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
    window.location.href = 'login.html'
  }
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

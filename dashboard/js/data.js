const API_URL = "http://localhost:8000"

// Shared by index.html (via app.js), attacks.html, and search.html's attack
// tables. Only cowrie.login.failed is an actual failed login attempt -
// session.connect/session.closed are just connection lifecycle events (a
// bot that only port-scans/banner-grabs without ever trying a login closes
// the session too), so labeling them "✗ Failed" the same as a real failed
// login attempt was misleading. Badge CSS class stays 'failed' (neutral
// blue) for all of these non-success cases - only login.success gets the
// 'success' (red/critical) styling.
function eventStatusLabel(event) {
    switch (event) {
        case "cowrie.login.success":  return { status: "success", label: "✓ Success" }
        case "cowrie.login.failed":   return { status: "failed",  label: "✗ Failed" }
        case "cowrie.command.input":  return { status: "failed",  label: "⌨ Command" }
        case "cowrie.session.connect": return { status: "failed", label: "→ Connect" }
        case "cowrie.session.closed":  return { status: "failed", label: "■ Closed" }
        // parser/http_honeypot.py - the fake admin login page, a second
        // honeypot service alongside Cowrie's SSH/Telnet. Every submitted
        // login is always rejected (this service never "lets anyone in"
        // the way Cowrie's AuthRandom sometimes does), so it's styled like
        // cowrie.login.failed, never the 'success' badge.
        case "http.login.attempt": return { status: "failed", label: "🌐 HTTP Login" }
        case "http.request":       return { status: "failed", label: "🌐 HTTP Request" }
        default: return { status: "failed", label: event }
    }
}

async function fetchStats() {
    try {
        const res = await authFetch(`${API_URL}/api/stats`)
        return await res.json()
    } catch { return { total:0, unique_ips:0, failed:0, success:0 } }
}

async function fetchAttacks() {
    try {
        const res  = await authFetch(`${API_URL}/api/attacks?limit=20`)
        const data = await res.json()
        return (data.data || []).map(a => ({
            time:     a.timestamp ? a.timestamp.substring(11,19) : "--:--:--",
            ip:       a.src_ip,
            username: a.username,
            password: a.password,
            command:  a.command,
            event:    a.event,
            country:  a.country || "Unknown",
        }))
    } catch { return [] }
}

async function fetchHours() {
    try {
        const res  = await authFetch(`${API_URL}/api/stats/hourly`)
        const data = await res.json()

        const counts = {}
        for (let h = 0; h < 24; h += 2) {
            counts[String(h).padStart(2,"0") + ":00"] = 0
        }

        // Lấy ngày hôm nay theo UTC (vì DB lưu UTC)
        const todayUTC = new Date().toISOString().substring(0, 10)

        ;(data.data || []).forEach(d => {
            if (!d.time || !d.time.startsWith(todayUTC)) return
            const hour = parseInt(d.time.substring(11, 13))
            const slot = Math.floor(hour / 2) * 2
            const key  = String(slot).padStart(2, "0") + ":00"
            if (counts[key] !== undefined) counts[key] += d.count
        })

        return Object.entries(counts).map(([hour, count]) => ({ hour, count }))
    } catch { return [] }
}

async function fetchTypes() {
    try {
        const res  = await authFetch(`${API_URL}/api/stats`)
        const data = await res.json()
        return {
            labels: ["Brute-force SSH", "Login Success", "Command Input"],
            values: [data.failed || 0, data.success || 0, data.commands || 0]
        }
    } catch { return { labels:[], values:[] } }
}

async function fetchTopIPs() {
    try {
        const res  = await authFetch(`${API_URL}/api/top-ips?limit=10`)
        const data = await res.json()
        return (data.data || []).filter(d => d.ip !== "127.0.0.1")
    } catch { return [] }
}

async function fetchTopPasswords() {
    try {
        const res  = await authFetch(`${API_URL}/api/top-passwords?limit=10`)
        const data = await res.json()
        return (data.data || []).filter(d => !d.password?.startsWith("pass"))
    } catch { return [] }
}

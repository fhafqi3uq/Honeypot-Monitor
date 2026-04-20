const API_URL = "http://localhost:8000"

async function fetchStats() {
    try {
        const res = await fetch(`${API_URL}/api/stats`)
        return await res.json()
    } catch { return { total:0, unique_ips:0, failed:0, success:0 } }
}

async function fetchAttacks() {
    try {
        const res  = await fetch(`${API_URL}/api/attacks?limit=500`)
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
        const res  = await fetch(`${API_URL}/api/stats/hourly`)
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
        const res  = await fetch(`${API_URL}/api/stats`)
        const data = await res.json()
        return {
            labels: ["Brute-force SSH", "Login Success", "Command Input"],
            values: [data.failed || 0, data.success || 0, data.commands || 0]
        }
    } catch { return { labels:[], values:[] } }
}

async function fetchTopIPs() {
    try {
        const res  = await fetch(`${API_URL}/api/top-ips?limit=10`)
        const data = await res.json()
        return (data.data || []).filter(d => d.ip !== "127.0.0.1")
    } catch { return [] }
}

async function fetchTopPasswords() {
    try {
        const res  = await fetch(`${API_URL}/api/top-passwords?limit=10`)
        const data = await res.json()
        return (data.data || []).filter(d => !d.password?.startsWith("pass"))
    } catch { return [] }
}

const API_URL = "http://localhost:8000"

async function fetchStats() {
    try {
        const res = await fetch(`${API_URL}/api/stats`)
        return await res.json()
    } catch {
        return { total:0, unique_ips:0, failed:0, success:0 }
    }
}

async function fetchAttacks() {
    try {
        const res  = await fetch(`${API_URL}/api/attacks?limit=20`)
        const data = await res.json()
        return data.data.map(a => ({
            time:     a.timestamp ? a.timestamp.substring(11,19) : "--:--:--",
            ip:       a.src_ip,
            username: a.username,
            password: a.password,
            command:  a.command,
            event:    a.event,
            country:  a.country || "Unknown",
        }))
    } catch {
        return []
    }
}

async function fetchHours() {
    try {
        const res  = await fetch(`${API_URL}/api/stats/hourly`)
        const data = await res.json()

        const counts = {}
        for (let h = 0; h < 24; h += 2) {
            counts[String(h).padStart(2,"0") + ":00"] = 0
        }

        const today = new Date().toISOString().substring(0, 10)

        ;(data.data || []).forEach(d => {
            if (!d.time.startsWith(today)) return
            const hour = d.time.substring(11, 13)
            const slot = Math.floor(parseInt(hour) / 2) * 2
            const key  = String(slot).padStart(2, "0") + ":00"
            if (counts[key] !== undefined) counts[key] += d.count
        })

        return Object.entries(counts).map(([hour, count]) => ({ hour, count }))
    } catch {
        return []
    }
}

async function fetchTypes() {
    try {
        const res  = await fetch(`${API_URL}/api/stats`)
        const data = await res.json()
        return {
            labels: ["Brute-force SSH", "Login Success", "Command Input"],
            values: [data.failed || 0, data.success || 0, data.commands || 0]
        }
    } catch {
        return { labels:[], values:[] }
    }
}

async function fetchTopIPs() {
    try {
        const today = new Date().toISOString().substring(0, 10)
        const res   = await fetch(`${API_URL}/api/attacks?limit=500&start_date=${today}`)
        const data  = await res.json()

        const counts = {}
        ;(data.data || []).forEach(a => {
            if (!a.src_ip) return
            counts[a.src_ip] = (counts[a.src_ip] || 0) + 1
        })

        return Object.entries(counts)
            .map(([ip, count]) => ({ ip, count }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 10)
    } catch {
        return []
    }
}

async function fetchTopPasswords() {
    try {
        const today = new Date().toISOString().substring(0, 10)
        const res   = await fetch(`${API_URL}/api/attacks?limit=500&start_date=${today}`)
        const data  = await res.json()

        const counts = {}
        ;(data.data || []).forEach(a => {
            if (!a.password) return
            counts[a.password] = (counts[a.password] || 0) + 1
        })

        return Object.entries(counts)
            .map(([password, count]) => ({ password, count }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 10)
    } catch {
        return []
    }
}

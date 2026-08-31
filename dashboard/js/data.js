const API_URL = "http://localhost:8000"

// Mongo stores `timestamp` as UTC (Cowrie's own log line, ISO 8601 with a Z
// or without one dependent on source - both handled here). Displayed in
// Vietnam local time (UTC+7) to match the viewer's own wall clock - a page
// showing raw UTC next to "Cập nhật lúc <VN local time>" looked like the
// data was hours stale even when it wasn't (caught live in production
// 2026-08-06). Shared by index.html/attacks.html via data.js; search.html
// keeps its own inline copy (see that file's own comment on why).
const VN_OFFSET_MS = 7 * 3600 * 1000

function toVnTime(isoTimestamp) {
    if (!isoTimestamp) return "--:--:--"
    const utc = new Date(isoTimestamp.endsWith("Z") ? isoTimestamp : isoTimestamp + "Z")
    const vn  = new Date(utc.getTime() + VN_OFFSET_MS)
    const pad = n => String(n).padStart(2, "0")
    return `${pad(vn.getUTCHours())}:${pad(vn.getUTCMinutes())}:${pad(vn.getUTCSeconds())}`
}

function toVnDateTime(isoTimestamp) {
    if (!isoTimestamp) return "--"
    const utc = new Date(isoTimestamp.endsWith("Z") ? isoTimestamp : isoTimestamp + "Z")
    const vn  = new Date(utc.getTime() + VN_OFFSET_MS)
    const pad = n => String(n).padStart(2, "0")
    return `${vn.getUTCFullYear()}-${pad(vn.getUTCMonth()+1)}-${pad(vn.getUTCDate())} ${pad(vn.getUTCHours())}:${pad(vn.getUTCMinutes())}:${pad(vn.getUTCSeconds())}`
}

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
        // Carries the TTY log hash a session replay (attacks.html/
        // search.html's "▶ Xem lại" button, dashboard/js/replay.js) is
        // built from - see parser/parser.py's comment on the `ttylog` field.
        case "cowrie.log.closed":      return { status: "failed", label: "📼 Log Closed" }
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
            time:     toVnTime(a.timestamp),
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
        // limit=48 (not the default 24): the backend returns the most
        // recent N hour-buckets that actually have data, keyed by UTC hour.
        // Since "today" below is the VIETNAM calendar day (UTC+7), it can
        // span into the tail of the previous UTC day - 24 buckets isn't
        // always enough to cover a full VN day once shifted, so ask for
        // extra headroom.
        const res  = await authFetch(`${API_URL}/api/stats/hourly?limit=48`)
        const data = await res.json()

        // DB lưu UTC (`d.time` là "YYYY-MM-DDTHH:00" theo UTC), nhưng hiển
        // thị theo giờ Việt Nam (UTC+7) để khớp đồng hồ thật của người xem -
        // trước đây so theo ngày UTC nên các cột buổi chiều/tối giờ VN (đã
        // là "ngày mai" theo UTC lúc gần nửa đêm, hoặc ngược lại "giờ tương
        // lai chưa tới" theo UTC vào ban ngày VN) bị lọc mất, nhìn như thiếu
        // dữ liệu dù traffic vẫn đang vào liên tục. Mỗi cột là đúng 1 giờ
        // (0h-23h), không gộp 2 giờ/cột nữa.
        const VN_OFFSET_MS = 7 * 3600 * 1000

        // Chỉ tạo cột tới giờ VN HIỆN TẠI, không cố định đủ 24 cột - một
        // biểu đồ "hôm nay tính đến giờ" mà vẽ sẵn cả những giờ chưa xảy ra
        // luôn để lại một khoảng trống rỗng bên phải (rõ nhất vào buổi
        // sáng). Cột cuối (giờ hiện tại) là dữ liệu CHƯA đầy đủ trong 60
        // phút, không phải số đã chốt.
        const currentHourVN = new Date(Date.now() + VN_OFFSET_MS).getUTCHours()
        const counts = {}
        for (let h = 0; h <= currentHourVN; h++) {
            counts[String(h).padStart(2,"0") + ":00"] = 0
        }
        const todayVN = new Date(Date.now() + VN_OFFSET_MS).toISOString().substring(0, 10)

        ;(data.data || []).forEach(d => {
            if (!d.time) return
            const vnDate = new Date(new Date(d.time + "Z").getTime() + VN_OFFSET_MS)
            if (vnDate.toISOString().substring(0, 10) !== todayVN) return
            const key = String(vnDate.getUTCHours()).padStart(2, "0") + ":00"
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

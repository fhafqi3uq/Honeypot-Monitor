import json
import os
import time
from datetime import datetime
from pymongo import MongoClient
from bot import alert_login_failed, alert_login_success, alert_command

# Đường dẫn log Cowrie

LOG_FILE = os.path.expanduser(
    "~/Honeypot-Monitor/honeypot/cowrie-src/var/log/cowrie/cowrie.json"
)

# Kết nối MongoDB
client     = MongoClient("mongodb://localhost:27017")
db         = client["honeypot"]
collection = db["attacks"]

IMPORTANT_EVENTS = [
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.session.connect",
    "cowrie.session.closed",
]

def get_geo(ip: str) -> dict:
    if ip.startswith(("127.", "192.168.", "10.", "172.")):
        return {"country": "Local", "country_code": "LO", "city": "localhost", "latitude": 0.0, "longitude": 0.0}
    try:
        import geoip2.database
        DB_PATH = os.path.expanduser("~/Honeypot-Monitor/parser/geoip/GeoLite2-City.mmdb")
        with geoip2.database.Reader(DB_PATH) as reader:
            r = reader.city(ip)
            return {
                "country":      r.country.name or "Unknown",
                "country_code": r.country.iso_code or "??",
                "city":         r.city.name or "Unknown",
                "latitude":     float(r.location.latitude or 0),
                "longitude":    float(r.location.longitude or 0),
            }
    except Exception:
        return {"country": "Unknown", "country_code": "??", "city": "Unknown", "latitude": 0.0, "longitude": 0.0}

def process_event(raw: dict):
    eventid = raw.get("eventid", "")
    if eventid not in IMPORTANT_EVENTS:
        return

    ip  = raw.get("src_ip", "")
    geo = get_geo(ip)

    # Lưu vào MongoDB
    doc = {
        "timestamp":    raw.get("timestamp"),
        "src_ip":       ip,
        "event":        eventid,
        "username":     raw.get("username"),
        "password":     raw.get("password"),
        "command":      raw.get("input"),
        "session":      raw.get("session"),
        "sensor":       raw.get("sensor", "honeypot-01"),
        "country":      geo["country"],
        "country_code": geo["country_code"],
        "city":         geo["city"],
        "latitude":     geo["latitude"],
        "longitude":    geo["longitude"],
        "alerted":      True,
        "created_at":   datetime.utcnow()
    }
    collection.insert_one(doc)
    print(f"  ✓ {eventid:35} | {ip:15} | {geo['country']}")

    # Gửi Telegram ngay lập tức
    username = raw.get("username", "?")
    password = raw.get("password", "?")
    command  = raw.get("input", "?")

    if eventid == "cowrie.login.failed":
        alert_login_failed(ip, username, password, 1)
        print(f"  📨 Gửi cảnh báo brute-force: {ip}")

    elif eventid == "cowrie.login.success":
        alert_login_success(ip, username, password)
        print(f"  🚨 Gửi cảnh báo login success: {ip}")

    elif eventid == "cowrie.command.input":
        alert_command(ip, command)
        print(f"  💻 Gửi cảnh báo command: {ip}")

def watch_log():
    print(f"🚀 Realtime Alert đang chạy...")
    print(f"👀 Theo dõi: {LOG_FILE}")
    print(f"📨 Telegram cảnh báo ngay khi có tấn công\n")

    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)  # Nhảy đến cuối file
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                process_event(raw)
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    watch_log()

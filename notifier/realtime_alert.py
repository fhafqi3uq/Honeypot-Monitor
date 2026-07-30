import json
import os
import time
from datetime import datetime, timezone
from pymongo import MongoClient
from bot import alert_login_failed, alert_login_success, alert_command
from notify_log_setup import get_logger

logger = get_logger(__name__)

# Đường dẫn log Cowrie

LOG_FILE = os.path.expanduser(
    "~/Honeypot-Monitor/honeypot/cowrie-src/var/log/cowrie/cowrie.json"
)

# Kết nối MongoDB
client     = MongoClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"))
db         = client[os.getenv("DB_NAME", "honeypot")]
collection = db["attacks"]

IMPORTANT_EVENTS = [
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.session.connect",
    "cowrie.session.closed",
]

# Events that carry no attacker action by themselves but hold forensic
# fields (client SSH fingerprint, ports) tied to a session started by an
# earlier cowrie.session.connect line. Cached by session id and merged into
# the IMPORTANT_EVENTS documents below instead of being stored on their own.
SESSION_CACHE: dict[str, dict] = {}

def update_session_cache(raw: dict):
    eventid = raw.get("eventid", "")
    session = raw.get("session")
    if not session:
        return
    if eventid == "cowrie.session.connect":
        cache = SESSION_CACHE.setdefault(session, {})
        cache["src_port"] = raw.get("src_port")
        cache["dst_port"] = raw.get("dst_port")
    elif eventid == "cowrie.client.version":
        SESSION_CACHE.setdefault(session, {})["client_version"] = raw.get("version")
    elif eventid == "cowrie.client.kex":
        cache = SESSION_CACHE.setdefault(session, {})
        cache["hassh"] = raw.get("hassh")
        cache["hasshAlgorithms"] = raw.get("hasshAlgorithms")

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
    update_session_cache(raw)
    if eventid not in IMPORTANT_EVENTS:
        return

    ip  = raw.get("src_ip", "")
    geo = get_geo(ip)
    session = raw.get("session")
    cached = SESSION_CACHE.get(session, {})

    # Lưu vào MongoDB
    doc = {
        "timestamp":       raw.get("timestamp"),
        "src_ip":          ip,
        "src_port":        cached.get("src_port"),
        "dst_port":        cached.get("dst_port"),
        "event":           eventid,
        "username":        raw.get("username"),
        "password":        raw.get("password"),
        "command":         raw.get("input"),
        "session":         session,
        "client_version":  cached.get("client_version"),
        "hassh":           cached.get("hassh"),
        "hasshAlgorithms": cached.get("hasshAlgorithms"),
        "duration":        raw.get("duration") if eventid == "cowrie.session.closed" else None,
        "sensor":          raw.get("sensor", "honeypot-01"),
        "country":         geo["country"],
        "country_code":    geo["country_code"],
        "city":            geo["city"],
        "latitude":        geo["latitude"],
        "longitude":       geo["longitude"],
        "alerted":         True,
        "created_at":      datetime.now(timezone.utc)
    }
    collection.insert_one(doc)
    logger.info(
        "%s from %s (%s)", eventid, ip, geo["country"],
        extra={"event": eventid, "ip": ip, "session": session},
    )

    # session closed -> nothing else will reference this session's cache
    if eventid == "cowrie.session.closed":
        SESSION_CACHE.pop(session, None)

    # Gửi Telegram ngay lập tức
    username = raw.get("username", "?")
    password = raw.get("password", "?")
    command  = raw.get("input", "?")

    if eventid == "cowrie.login.failed":
        alert_login_failed(ip, username, password, 1)
        logger.info("Sent brute-force Telegram alert", extra={"ip": ip, "event": eventid})

    elif eventid == "cowrie.login.success":
        alert_login_success(ip, username, password)
        logger.info("Sent login-success Telegram alert", extra={"ip": ip, "event": eventid})

    elif eventid == "cowrie.command.input":
        alert_command(ip, command)
        logger.info("Sent command-input Telegram alert", extra={"ip": ip, "event": eventid})

def watch_log():
    logger.info("Realtime alert watcher starting, watching %s", LOG_FILE)

    import os
    current_inode = os.stat(LOG_FILE).st_ino
    f = open(LOG_FILE, "r")
    f.seek(0, 2)
    while True:
        try:
            stat = os.stat(LOG_FILE)
            if stat.st_ino != current_inode:
                logger.warning("Cowrie log file was rotated - reopening")
                f.close()
                f = open(LOG_FILE, "r")
                current_inode = stat.st_ino
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
        except Exception:
            logger.error("Unexpected error in watch_log loop", exc_info=True)
            time.sleep(5)

if __name__ == "__main__":
    watch_log()

import json
import os
import time
from datetime import datetime, timezone
from pymongo import MongoClient
from prometheus_client import start_http_server
from bot import alert_login_failed, alert_login_success, alert_command
from notify_log_setup import get_logger
from notify_mitre_mapping import map_mitre_techniques
import notify_metrics

logger = get_logger(__name__)

METRICS_PORT = 9101


def _read_secret(env_name: str):
    """Reads a secret from <env_name>_FILE (a file path) if set - the
    Docker Compose `secrets:` convention (see docker-compose.yml) - else
    falls back to the plain env var, which is what the native venv
    workflow uses. Duplicated per-file rather than shared, same as the
    other `_read_secret()`s in this project (see CLAUDE.md)."""
    file_path = os.getenv(f"{env_name}_FILE")
    if file_path:
        with open(file_path) as f:
            return f.read().strip()
    return os.getenv(env_name)


def _mongo_auth_kwargs() -> dict:
    """Adds MongoDB username/password auth if MONGO_USERNAME is set - the
    native venv workflow (mongod with no --auth) never sets it, so this
    returns {} and pymongo connects exactly as before."""
    username = _read_secret("MONGO_USERNAME")
    if not username:
        return {}
    return {
        "username": username,
        "password": _read_secret("MONGO_PASSWORD"),
        "authSource": os.getenv("MONGO_AUTH_SOURCE", "admin"),
    }

# Đường dẫn log Cowrie

LOG_FILE = os.getenv(
    "COWRIE_LOG_FILE",
    os.path.expanduser("~/Honeypot-Monitor/honeypot/cowrie-src/var/log/cowrie/cowrie.json"),
)

# Saved read position - see _load_offset()/_save_offset() below. Lands in
# the same directory notify_log_setup.py already writes logs/notifier.log
# to (two levels above this file), which docker-compose.yml already mounts
# as a persistent volume, so this survives a container recreation, not
# just an in-process restart.
OFFSET_FILE = os.getenv(
    "REALTIME_ALERT_OFFSET_FILE",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "realtime_alert.offset.json"),
)

# Kết nối MongoDB
client     = MongoClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"), **_mongo_auth_kwargs())
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
        DB_PATH = os.getenv(
            "GEOIP_DB_PATH",
            os.path.expanduser("~/Honeypot-Monitor/parser/geoip/GeoLite2-City.mmdb"),
        )
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
        "mitre_techniques": map_mitre_techniques(eventid, raw.get("input")),
        "sensor":          raw.get("sensor", "honeypot-01"),
        "country":         geo["country"],
        "country_code":    geo["country_code"],
        "city":            geo["city"],
        "latitude":        geo["latitude"],
        "longitude":       geo["longitude"],
        "alerted":         True,
        "created_at":      datetime.now(timezone.utc)
    }
    try:
        collection.insert_one(doc)
    except Exception:
        logger.error(
            "Failed to insert attack document into MongoDB",
            exc_info=True, extra={"event": eventid, "ip": ip},
        )
        notify_metrics.REALTIME_ALERT_INSERT_ERRORS.inc()
        return
    logger.info(
        "%s from %s (%s)", eventid, ip, geo["country"],
        extra={"event": eventid, "ip": ip, "session": session},
    )
    notify_metrics.REALTIME_ALERT_EVENTS_PROCESSED.labels(eventid).inc()
    notify_metrics.REALTIME_ALERT_LAST_EVENT_TIMESTAMP.set(time.time())

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
        notify_metrics.TELEGRAM_ALERTS_SENT.labels(eventid).inc()

    elif eventid == "cowrie.login.success":
        alert_login_success(ip, username, password)
        logger.info("Sent login-success Telegram alert", extra={"ip": ip, "event": eventid})
        notify_metrics.TELEGRAM_ALERTS_SENT.labels(eventid).inc()

    elif eventid == "cowrie.command.input":
        alert_command(ip, command)
        logger.info("Sent command-input Telegram alert", extra={"ip": ip, "event": eventid})
        notify_metrics.TELEGRAM_ALERTS_SENT.labels(eventid).inc()

def _load_offset(current_inode):
    """Returns a saved byte position to resume from, or None if there's no
    usable one - either no offset was ever saved, the file is corrupt, or
    the saved inode doesn't match the log file's CURRENT inode (a rotation
    happened while nothing was watching, so the saved position refers to a
    now-renamed-away file - falling back to "start from the end" is safer
    than seeking to an arbitrary offset in a different file)."""
    try:
        with open(OFFSET_FILE) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    if data.get("inode") != current_inode:
        return None
    return data.get("position")


def _save_offset(inode, position):
    # Write-to-temp-then-rename is atomic on POSIX - a crash mid-write
    # never leaves a half-written, unparseable offset file behind.
    tmp_path = OFFSET_FILE + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump({"inode": inode, "position": position}, f)
    os.replace(tmp_path, OFFSET_FILE)


def watch_log():
    logger.info("Realtime alert watcher starting, watching %s", LOG_FILE)

    import os
    current_inode = os.stat(LOG_FILE).st_ino
    f = open(LOG_FILE, "r")
    saved_position = _load_offset(current_inode)
    if saved_position is not None:
        f.seek(saved_position)
        logger.info("Resuming realtime_alert from saved offset %d", saved_position)
    else:
        f.seek(0, 2)
        logger.info("No usable saved offset - starting from end of file")
    while True:
        try:
            stat = os.stat(LOG_FILE)
            if stat.st_ino != current_inode:
                logger.warning("Cowrie log file was rotated - reopening")
                f.close()
                f = open(LOG_FILE, "r")
                current_inode = stat.st_ino
                notify_metrics.REALTIME_ALERT_LOG_ROTATIONS.inc()
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            line = line.strip()
            if not line:
                _save_offset(current_inode, f.tell())
                continue
            try:
                raw = json.loads(line)
                process_event(raw)
            except json.JSONDecodeError:
                pass
            # Advance regardless of outcome - matches the existing
            # best-effort semantics (failures are logged, not retried)
            # rather than risking an infinite retry loop on one bad line.
            _save_offset(current_inode, f.tell())
        except Exception:
            logger.error("Unexpected error in watch_log loop", exc_info=True)
            time.sleep(5)

if __name__ == "__main__":
    start_http_server(METRICS_PORT)
    watch_log()

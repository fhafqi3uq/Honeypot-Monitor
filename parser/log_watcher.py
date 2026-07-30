import json
import time
import os
from datetime import datetime, timezone
from pymongo import MongoClient
from geoip_lookup import get_geo
from log_setup import get_logger

logger = get_logger(__name__)

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

LOG_FILE = os.getenv(
    "COWRIE_LOG_FILE",
    os.path.expanduser("~/Honeypot-Monitor/honeypot/cowrie-src/var/log/cowrie/cowrie.json"),
)

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

def parse_event(raw: dict):
    eventid = raw.get("eventid", "")
    if eventid not in IMPORTANT_EVENTS:
        return None
    ip  = raw.get("src_ip", "")
    geo = get_geo(ip)
    if geo["country"] == "Unknown" and not ip.startswith(("127.", "192.168.", "10.", "172.")):
        logger.warning("GeoIP lookup returned Unknown for %s", ip, extra={"ip": ip})
    session = raw.get("session")
    cached = SESSION_CACHE.get(session, {})
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
        "alerted":         False,
        "created_at":      datetime.now(timezone.utc)
    }
    # session closed -> nothing else will reference this session's cache
    if eventid == "cowrie.session.closed":
        SESSION_CACHE.pop(session, None)
    return doc

def watch_log():
    logger.info("Watching Cowrie log: %s", LOG_FILE)
    # Cowrie's logtype=rotating renames the current file away and starts a
    # new one at the same path (typically at midnight) - the inode changes
    # even though the path doesn't, so comparing inodes is how we notice a
    # rotation happened under our open file descriptor.
    current_inode = os.stat(LOG_FILE).st_ino
    f = open(LOG_FILE, "r")
    f.seek(0, 2)  # nhảy đến cuối file
    while True:
        try:
            stat = os.stat(LOG_FILE)
        except FileNotFoundError:
            time.sleep(1)
            continue
        if stat.st_ino != current_inode:
            logger.warning("Cowrie log file was rotated - reopening %s", LOG_FILE)
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
            update_session_cache(raw)
            doc = parse_event(raw)
            if doc:
                try:
                    collection.insert_one(doc)
                    logger.info(
                        "%s from %s (%s)", doc["event"], doc["src_ip"], doc["country"],
                        extra={"event": doc["event"], "ip": doc["src_ip"], "session": doc["session"]},
                    )
                except Exception:
                    logger.error(
                        "Failed to insert attack document into MongoDB",
                        exc_info=True, extra={"event": doc["event"], "ip": doc["src_ip"]},
                    )
        except json.JSONDecodeError:
            continue

if __name__ == "__main__":
    watch_log()

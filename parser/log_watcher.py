import json
import time
import os
from datetime import datetime, timezone
from pymongo import MongoClient
from geoip_lookup import get_geo

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

LOG_FILE = os.path.expanduser(
    "~/Honeypot-Monitor/honeypot/cowrie-src/var/log/cowrie/cowrie.json"
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
        "created_at":      datetime.utcnow()
    }
    # session closed -> nothing else will reference this session's cache
    if eventid == "cowrie.session.closed":
        SESSION_CACHE.pop(session, None)
    return doc

def watch_log():
    print(f"👀 Đang theo dõi: {LOG_FILE}")
    print("   Ctrl+C để dừng\n")
    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)  # nhảy đến cuối file
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
                update_session_cache(raw)
                doc = parse_event(raw)
                if doc:
                    collection.insert_one(doc)
                    print(f"  ✓ {doc['event']:35} | {doc['src_ip']:15} | {doc['country']}")
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    watch_log()

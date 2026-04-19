import json
import time
import os
from datetime import datetime, timezone
from pymongo import MongoClient
from geoip_lookup import get_geo

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

LOG_FILE = os.path.expanduser(
    "~/Honeypot-Monitor/honeypot/cowrie-src/var/log/cowrie/cowrie.json"
)

def parse_event(raw: dict):
    eventid = raw.get("eventid", "")
    if eventid not in IMPORTANT_EVENTS:
        return None
    ip  = raw.get("src_ip", "")
    geo = get_geo(ip)
    return {
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
        "alerted":      False,
        "created_at":   datetime.utcnow()
    }

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
                doc = parse_event(raw)
                if doc:
                    collection.insert_one(doc)
                    print(f"  ✓ {doc['event']:35} | {doc['src_ip']:15} | {doc['country']}")
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    watch_log()

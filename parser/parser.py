import json
from datetime import datetime
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

def parse_event(raw: dict) -> dict | None:
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

def import_log_file(filepath: str):
    inserted = 0
    skipped  = 0
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                doc = parse_event(raw)
                if doc:
                    collection.insert_one(doc)
                    inserted += 1
                    print(f"  ✓ {doc['event']:35} | {doc['src_ip']:15} | {doc['country']}")
                else:
                    skipped += 1
            except json.JSONDecodeError:
                continue

    print(f"\n✅ Inserted: {inserted} documents")
    print(f"⏭️  Skipped:  {skipped} events")
    print(f"📦 Total DB: {collection.count_documents({})}")

if __name__ == "__main__":
    collection.drop()
    import_log_file("../honeypot/sample_log.json")

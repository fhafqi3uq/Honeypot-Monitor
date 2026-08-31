import json
import time
import os
from datetime import datetime, timezone
from pymongo import MongoClient
from prometheus_client import start_http_server
from geoip_lookup import get_geo
from log_setup import get_logger
from mitre_mapping import map_mitre_techniques
from severity import classify_severity
import metrics

logger = get_logger(__name__)

METRICS_PORT = 9100


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


client     = MongoClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"), **_mongo_auth_kwargs())
db         = client[os.getenv("DB_NAME", "honeypot")]
collection = db["attacks"]

IMPORTANT_EVENTS = [
    "cowrie.login.failed",
    "cowrie.login.success",
    "cowrie.command.input",
    "cowrie.session.connect",
    "cowrie.session.closed",
    # Carries the TTY log filename (a sha256 hash, not the raw path Cowrie
    # writes - see main.py's /api/sessions/{id}/replay, which reads that
    # hash back out of this field to find the file on disk) for a session's
    # binary keystroke/output recording - what session replay is built on.
    "cowrie.log.closed",
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

# Saved read position - see _load_offset()/_save_offset() below. Lands in
# the same directory log_setup.py already writes logs/parser.log to (two
# levels above this file - /logs in the Docker image, <repo_root>/logs
# natively), which docker-compose.yml already mounts as a persistent
# volume, so this survives a container recreation, not just an in-process
# restart.
OFFSET_FILE = os.getenv(
    "LOG_WATCHER_OFFSET_FILE",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "log_watcher.offset.json"),
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
    mitre_techniques = map_mitre_techniques(eventid, raw.get("input"))
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
        # Only cowrie.log.closed carries this field; stored as just the
        # basename (the sha256 hash Cowrie renames the file to on close),
        # never the full path, since that's a host filesystem detail the
        # replay endpoint re-derives from its own TTYLOG_DIR.
        "ttylog":          os.path.basename(raw["ttylog"]) if raw.get("ttylog") else None,
        "mitre_techniques": mitre_techniques,
        "severity":        classify_severity(mitre_techniques),
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

def _load_offset(current_inode):
    """Returns a saved byte position to resume from, or None if there's no
    usable one - either no offset was ever saved, the file is corrupt, or
    (critically) the saved inode doesn't match the log file's CURRENT
    inode, meaning a rotation happened while nothing was watching and the
    saved byte position refers to a now-renamed-away file. In that last
    case None is correct: falling back to "start from the end" is safer
    than seeking to some arbitrary byte offset in a completely different
    file."""
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
    logger.info("Watching Cowrie log: %s", LOG_FILE)
    # Cowrie's logtype=rotating renames the current file away and starts a
    # new one at the same path (typically at midnight) - the inode changes
    # even though the path doesn't, so comparing inodes is how we notice a
    # rotation happened under our open file descriptor.
    current_inode = os.stat(LOG_FILE).st_ino
    f = open(LOG_FILE, "r")
    saved_position = _load_offset(current_inode)
    if saved_position is not None:
        f.seek(saved_position)
        logger.info("Resuming log_watcher from saved offset %d", saved_position)
    else:
        f.seek(0, 2)  # no usable saved offset - nhảy đến cuối file (previous, pre-persistent-offset behavior)
        logger.info("No usable saved offset - starting from end of file")
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
            metrics.LOG_WATCHER_LOG_ROTATIONS.inc()
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
            update_session_cache(raw)
            doc = parse_event(raw)
            if doc:
                try:
                    collection.insert_one(doc)
                    logger.info(
                        "%s from %s (%s)", doc["event"], doc["src_ip"], doc["country"],
                        extra={"event": doc["event"], "ip": doc["src_ip"], "session": doc["session"]},
                    )
                    metrics.LOG_WATCHER_EVENTS_PROCESSED.labels(doc["event"]).inc()
                    metrics.LOG_WATCHER_LAST_EVENT_TIMESTAMP.set(time.time())
                except Exception:
                    logger.error(
                        "Failed to insert attack document into MongoDB",
                        exc_info=True, extra={"event": doc["event"], "ip": doc["src_ip"]},
                    )
                    metrics.LOG_WATCHER_INSERT_ERRORS.inc()
        except json.JSONDecodeError:
            pass
        # Advance the saved offset past this line regardless of outcome
        # (inserted, insert failed, or malformed JSON) - matches the
        # existing best-effort semantics (failures are logged, not
        # retried) rather than risking an infinite retry loop on a single
        # poisoned line.
        _save_offset(current_inode, f.tell())

if __name__ == "__main__":
    start_http_server(METRICS_PORT)
    watch_log()

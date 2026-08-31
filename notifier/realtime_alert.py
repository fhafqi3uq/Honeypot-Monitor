import json
import os
import time
from datetime import datetime, timezone
from pymongo import MongoClient
from prometheus_client import start_http_server
from bot import alert_login_failed, alert_login_success, alert_session_commands, send_message
from correlation import CorrelationState, evaluate_event
from notify_log_setup import get_logger
from notify_mitre_mapping import map_mitre_techniques
from notify_severity import classify_severity
import notify_metrics

logger = get_logger(__name__)

METRICS_PORT = 9101

# Rate-limit Telegram alerts per (source IP, alert type) - a bot that loops
# (connect, login, run commands, disconnect, repeat every few seconds - real
# IoT botnet behavior, not a bug) would otherwise fire a fresh Telegram push
# every single cycle. Cooldown is tracked PER ALERT TYPE, not shared across
# login_failed/login_success/session_commands - a shared cooldown used to
# mean whichever fired first for an IP "used up" the window entirely, so a
# login-success alert routinely swallowed the session-commands alert for the
# very same session (a bot's login->commands->close cycle usually completes
# in well under 5 minutes, so the commands alert kept landing inside the
# window the login alert had just opened). Caught live in production
# (2026-08-06): a captured Mirai-style command sequence never reached
# Telegram because its session closed 2 minutes after a login-success alert
# for the same IP. Mongo storage is never affected either way - every event
# is always stored regardless of whether a Telegram push fires.
ALERT_COOLDOWN_SECONDS = 5 * 60
_LAST_ALERT_TIME: dict[tuple[str, str], float] = {}


def _should_alert(ip: str, alert_type: str) -> bool:
    now = time.time()
    key = (ip, alert_type)
    last = _LAST_ALERT_TIME.get(key)
    if last is not None and now - last < ALERT_COOLDOWN_SECONDS:
        return False
    _LAST_ALERT_TIME[key] = now
    return True


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
# Separate collection from "attacks" - a correlation alert isn't a single
# Cowrie event, it's a rule firing across several of them (see
# CorrelationAlert.matched_events), so it doesn't fit the attacks schema.
# Mirrors the siem-dashboard reference's Alert.create_from_rule() persisting
# before it notifies, adapted to this project's Telegram-push model instead
# of an SSE stream.
correlation_alerts_collection = db["correlation_alerts"]

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

# Cross-event correlation (brute-force bursts, login->command compromise
# chains, credential scans - see correlation.py) - one process-wide state
# since watch_log() runs a single loop in this process.
_CORRELATION_STATE = CorrelationState()

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
    elif eventid == "cowrie.command.input":
        # Buffered here, not alerted on immediately - see alert_session_commands().
        cache = SESSION_CACHE.setdefault(session, {})
        cache.setdefault("commands", []).append(raw.get("input"))

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
        # Always None here: cowrie.log.closed (the only event that carries
        # this field - see parser/log_watcher.py's matching comment) isn't
        # in this file's IMPORTANT_EVENTS, it's not alert-worthy on its own.
        # Key kept present anyway to match log_watcher.py's document shape -
        # see AL-11 in tests/test_alerting.py.
        "ttylog":          os.path.basename(raw["ttylog"]) if raw.get("ttylog") else None,
        "mitre_techniques": mitre_techniques,
        "severity":        classify_severity(mitre_techniques),
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

    # Gửi Telegram. Lệnh (cowrie.command.input) KHÔNG alert ngay từng dòng
    # nữa - chỉ gom vào SESSION_CACHE (xem update_session_cache) và gửi 1
    # alert tóm tắt khi session đóng, tránh dội hàng chục tin Telegram cho
    # 1 phiên tấn công chạy nhiều lệnh recon liên tiếp.
    username = raw.get("username", "?")
    password = raw.get("password", "?")

    if eventid == "cowrie.login.failed":
        if _should_alert(ip, "login_failed"):
            alert_login_failed(ip, username, password, 1, geo=geo)
            logger.info("Sent brute-force Telegram alert", extra={"ip": ip, "event": eventid})
            notify_metrics.TELEGRAM_ALERTS_SENT.labels(eventid).inc()

    elif eventid == "cowrie.login.success":
        if _should_alert(ip, "login_success"):
            alert_login_success(ip, username, password, geo=geo)
            logger.info("Sent login-success Telegram alert", extra={"ip": ip, "event": eventid})
            notify_metrics.TELEGRAM_ALERTS_SENT.labels(eventid).inc()

    elif eventid == "cowrie.session.closed":
        commands = cached.get("commands", [])
        if commands and _should_alert(ip, "session_commands"):
            alert_session_commands(ip, commands, geo=geo)
            logger.info(
                "Sent session-commands Telegram alert",
                extra={"ip": ip, "event": eventid, "session": session},
            )
            notify_metrics.TELEGRAM_ALERTS_SENT.labels("cowrie.session.commands").inc()

    # Cross-event correlation - separate from the per-event alerts above
    # and gated by its own cooldown (see CorrelationState), not
    # _should_alert(), so it isn't silenced by an unrelated login_failed/
    # login_success alert firing for the same IP moments earlier.
    for calert in evaluate_event(raw, _CORRELATION_STATE):
        # Save-then-notify, same order as the siem-dashboard reference's
        # Alert.create_from_rule() - the alert exists in Mongo (for
        # /correlation_alerts history/dashboard use later) even if the
        # Telegram send that follows fails or is rate-limited.
        try:
            correlation_alerts_collection.insert_one({
                "rule_id":        calert.rule_id,
                "group_key":      calert.group_key,
                "severity":       calert.severity,
                "message":        calert.message,
                "matched_event_count": len(calert.matched_events),
                "sensor":         raw.get("sensor", "honeypot-01"),
                "created_at":     datetime.now(timezone.utc),
            })
        except Exception:
            logger.error(
                "Failed to insert correlation alert into MongoDB",
                exc_info=True, extra={"rule_id": calert.rule_id, "ip": ip},
            )
            notify_metrics.CORRELATION_ALERT_INSERT_ERRORS.inc()
            # Same all-or-nothing choice as the main attacks insert above -
            # skip the Telegram push too rather than notify about an alert
            # that has no durable record to back it (nothing for a
            # dashboard/history view to show if someone clicks through).
            continue

        send_message(f"[correlation:{calert.severity}] {calert.message}")
        logger.info(
            "Sent correlation Telegram alert",
            extra={"rule_id": calert.rule_id, "ip": ip, "event": eventid, "severity": calert.severity},
        )
        notify_metrics.TELEGRAM_ALERTS_SENT.labels(f"correlation.{calert.rule_id}").inc()

    # session closed -> nothing else will reference this session's cache
    if eventid == "cowrie.session.closed":
        SESSION_CACHE.pop(session, None)

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

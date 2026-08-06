"""
Watches MongoDB for source IPs that have crossed an abuse threshold within
the last 24h and firewalls them off automatically via `ufw insert 1 deny`,
so a flood from a single IP no longer needs a human to notice and block it
by hand (see GO_LIVE.md's kill-switch section for the manual equivalent of
what this does automatically).

Runs as its own process (like http_honeypot_alert.py) rather than folding
this into an existing script, since it needs `sudo` access to run `ufw` -
keeping that privileged action isolated to one small, auditable file.
"""

import ipaddress
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone

from prometheus_client import start_http_server
from pymongo import MongoClient

from bot import send_message
from notify_log_setup import get_logger
import notify_metrics

logger = get_logger(__name__)

METRICS_PORT = 9109
POLL_INTERVAL_SECONDS = 60

# 24h rolling window, not calendar day - avoids UTC/VN day-boundary edge
# cases (see the timezone bug fixed 2026-08-06) and doesn't reset a bot's
# count to zero right at midnight.
WINDOW_HOURS = int(os.getenv("AUTO_BLOCK_WINDOW_HOURS", "24"))
THRESHOLD = int(os.getenv("AUTO_BLOCK_THRESHOLD", "2000"))

UFW_PATH = os.getenv("UFW_PATH", "/usr/sbin/ufw")


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


client       = MongoClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"), **_mongo_auth_kwargs())
db           = client[os.getenv("DB_NAME", "honeypot")]
collection   = db["attacks"]
blocked_col  = db["blocked_ips"]


def _is_blockable(ip: str) -> bool:
    """Never auto-block private/local ranges - real attacker traffic never
    legitimately originates from these, so seeing one here would mean
    something is wrong upstream (misconfigured sensor, test traffic), not
    that we found a genuine attacker."""
    if ip.startswith(("127.", "192.168.", "10.", "172.")):
        return False
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return True


def find_ips_over_threshold():
    """Returns [(ip, count), ...] for every source IP with >= THRESHOLD
    events in the last WINDOW_HOURS, not already recorded as blocked."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=WINDOW_HOURS)).strftime("%Y-%m-%dT%H:%M:%S")
    already_blocked = {d["_id"] for d in blocked_col.find({}, {"_id": 1})}
    pipeline = [
        {"$match": {"timestamp": {"$gte": cutoff}}},
        {"$group": {"_id": "$src_ip", "count": {"$sum": 1}}},
        {"$match": {"count": {"$gte": THRESHOLD}}},
    ]
    return [
        (doc["_id"], doc["count"])
        for doc in collection.aggregate(pipeline)
        if doc["_id"] not in already_blocked and _is_blockable(doc["_id"])
    ]


def block_ip(ip: str, count: int) -> bool:
    """Inserts a ufw deny rule ahead of the existing allow/limit rules -
    same command an admin would run by hand (see GO_LIVE.md section 8).
    Returns True if the rule was applied successfully."""
    try:
        subprocess.run(
            ["sudo", UFW_PATH, "insert", "1", "deny", "from", ip, "to", "any"],
            check=True, capture_output=True, timeout=10, text=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.error(
            "Failed to auto-block %s via ufw", ip, exc_info=True, extra={"ip": ip}
        )
        notify_metrics.AUTO_BLOCK_FAILURES.inc()
        return False
    return True


def process_over_threshold_ips():
    """Split out from the poll loop below for testability."""
    for ip, count in find_ips_over_threshold():
        if not block_ip(ip, count):
            continue
        blocked_col.insert_one({
            "_id": ip,
            "count_at_block": count,
            "window_hours": WINDOW_HOURS,
            "blocked_at": datetime.now(timezone.utc),
        })
        logger.info(
            "Auto-blocked %s via ufw (%d events in %dh)", ip, count, WINDOW_HOURS,
            extra={"ip": ip},
        )
        notify_metrics.AUTO_BLOCK_TOTAL.inc()
        send_message(
            "🛑 <b>TỰ ĐỘNG CHẶN IP</b>\n━━━━━━━━━━━━━━━\n"
            f"🌐 IP: <code>{ip}</code>\n"
            f"🔢 Số lượt trong {WINDOW_HOURS}h qua: <b>{count}</b>\n"
            f"✅ Đã thêm rule <code>ufw deny</code>"
        )


def poll_forever():
    logger.info(
        "Auto-block watcher starting (threshold=%d events/%dh, poll every %ds)",
        THRESHOLD, WINDOW_HOURS, POLL_INTERVAL_SECONDS,
    )
    while True:
        try:
            process_over_threshold_ips()
        except Exception:
            logger.error("Unexpected error in auto-block poll loop", exc_info=True)
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    start_http_server(METRICS_PORT)
    poll_forever()
